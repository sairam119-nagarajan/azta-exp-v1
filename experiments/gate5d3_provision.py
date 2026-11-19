"""Gate 5D.3B operator-only provisioning of the ten-device deployment: inspect, provision, verify, rollback.

Additive tooling: the historical a3_policy / a3_mqtt are only imported (their Dynamic Security Admin client is reused),
never modified. It adds exactly what the reviewed Gate 5D.3 plan describes (eight publish-only device principals and the
dedicated receive-only `azta-observer`) and nothing else, one verified operation at a time, with a precise rollback of only
what it created.

Safety properties:
* `inspect` and `verify` are read-only (every command passes the binding-audit read-only allowlist).
* `provision` and `rollback` mutate and refuse to run without --confirm-live-mutation, the exact plan digest and the exact
  frozen registry v2 digest. They refuse to start unless the live policy still equals the documented historical baseline
  and no planned name or credential file already exists.
* Credentials are generated exclusively (O_EXCL), written only to the Git-ignored credential directory with mode 0600, and never
  appear in logs, evidence, plans, output or exceptions. Errors are short codes; broker responses never enter error text.
* On any failure only the entities this run created are removed (reverse order) and the pre-image is verified; a restoration
  that cannot be verified is reported as restoration_failed_STOP and nothing else is touched.
"""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import sys

from experiments import binding_audit
from experiments import gate5d3_provisioning_plan as gp
from observation.registry import DeviceRegistry
from observation.schema import canonical, sha256_text

RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
MIN_SECRET_CHARS = 32


class ProvisionError(Exception):
    """Carries a short code only; no broker response value ever enters the message."""


# ---------------------------------------------------------------- read helpers (admin.call only)
def client_meta(admin, username, optional=False):
    result = admin.call("getClient", optional=optional, username=username)
    if result is None:
        return None
    c = result["client"]
    return dict(username=c["username"], clientid=c.get("clientid"), disabled=bool(c.get("disabled", False)),
                roles=sorted((dict(rolename=r["rolename"], priority=r.get("priority", -1)) for r in c.get("roles", [])),
                             key=lambda r: r["rolename"]),
                groups=sorted(g["groupname"] for g in c.get("groups", [])))


def role_acls(admin, name, optional=False):
    result = admin.call("getRole", optional=optional, rolename=name)
    if result is None:
        return None
    return gp.sorted_acls(result["role"].get("acls", []))


def capture_state(admin):
    """Read-only: whole-policy snapshot plus full records (with role-membership priority) of the historical principals."""
    snapshot = binding_audit.collect_snapshot(binding_audit.ReadOnlyAdmin(admin))
    legacy = {}
    for name in gp.legacy_principals():
        meta = client_meta(admin, name, optional=True)
        legacy[name] = dict(client=meta, roles={r["rolename"]: role_acls(admin, r["rolename"], optional=True)
                                                for r in (meta or {}).get("roles", [])})
    return dict(snapshot=snapshot, legacy=legacy, policy_sha256=binding_audit.policy_digest(snapshot))


# ---------------------------------------------------------------- baseline
def inspect_baseline(state, plan, registry_v1):
    """Compare live state with the documented historical baseline. Returns dict(acceptable, reasons, informational)."""
    documented = gp.documented_legacy_snapshot()
    snap, reasons, info = state["snapshot"], [], {}
    if snap["defaults"] != documented["defaults"]:
        reasons.append("default ACLs are not the four documented denies")
    # Mosquitto's built-in anonymous group ("unauthenticated") exists with no roles and no clients in the historical baseline
    # (policy digest 4578bda2...f3db); any group that carries a role or a member is unexpected.
    for name, group in snap["groups"].items():
        if group["roles"] or group["clients"]:
            reasons.append(f"group {name} has roles or members")
    if snap["anonymous_group"] is not None and snap["anonymous_group"] not in snap["groups"]:
        reasons.append("anonymous group is not an enumerated group")
    admin_roles = (snap["clients"].get("admin") or {}).get("roles")
    if admin_roles != ["dynsec-admin"]:
        reasons.append("the administration identity does not hold exactly dynsec-admin")
    allowed_clients = {"admin", *gp.legacy_principals()}
    extra = sorted(set(snap["clients"]) - allowed_clients)
    if extra:
        reasons.append(f"unexpected clients present: {extra}")
    for name in gp.legacy_principals():
        record = state["legacy"][name]
        meta = record["client"]
        want = documented["clients"][name]
        if meta is None:
            reasons.append(f"{name}: missing")
            continue
        if (meta["clientid"], meta["disabled"], meta["groups"]) != (want["clientid"], False, []):
            reasons.append(f"{name}: client record differs from the documented baseline")
        if [r["rolename"] for r in meta["roles"]] != want["roles"] or any(r["priority"] != gp.PRIORITY for r in meta["roles"]):
            reasons.append(f"{name}: roles or role-membership priority differ from the documented baseline")
        for role, acls in record["roles"].items():
            if acls != documented["roles"].get(role):
                reasons.append(f"{role}: ACLs differ from the documented baseline")
    documented_roles = set(documented["roles"]) - {"dynsec-admin"}
    info["roles_not_in_documented_baseline"] = sorted(set(snap["roles"]) - set(documented["roles"]))
    info["documented_roles_missing"] = sorted(documented_roles - set(snap["roles"]))
    if info["documented_roles_missing"]:
        reasons.append("documented roles missing")
    present = sorted((set(plan["added_principals"]) & set(snap["clients"])) | (set(plan["added_roles"]) & set(snap["roles"])))
    if present:
        reasons.append(f"planned names already exist: {present}")
    audit = binding_audit.analyze(snap, registry_v1)
    if audit["verdict"] != "PASS":
        reasons.append("binding audit under registry v1 is not PASS")
    return dict(acceptable=not reasons, reasons=reasons, informational=info, binding_audit_v1=audit["verdict"],
                policy_sha256=state["policy_sha256"])


# ---------------------------------------------------------------- evidence sink
class Evidence:
    """Thin sink over RunRecords (or any object with write_json/event); never receives secrets."""
    def __init__(self, records):
        self.records = records

    def write(self, name, value):
        self.records.write_json(name, value)

    def event(self, kind, **fields):
        self.records.event("admin", kind, **fields)


# ---------------------------------------------------------------- credentials
def _create_credential(path, token):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(token + "\n")


def _expected_client(item):
    return dict(username=item["username"], clientid=item["clientid"], disabled=False,
                roles=sorted(item["roles"], key=lambda r: r["rolename"]), groups=[])


def _planned_items(plan):
    return plan["device_principals"] + [plan["observer"]]


# ---------------------------------------------------------------- provision
def provision(admin, evidence, plan, registry_v1, registry_v2, credential_root, *, token=lambda: secrets.token_urlsafe(32)):
    """Live mutation. Returns a summary dict; raises ProvisionError after a verified rollback (or restoration_failed_STOP)."""
    gp.verify_plan(plan, registry_v2)
    root = Path(credential_root)
    before = capture_state(admin)
    baseline = inspect_baseline(before, plan, registry_v1)
    evidence.write("pre_image_state.json", before)
    evidence.write("baseline_check.json", baseline)
    if not baseline["acceptable"]:
        raise ProvisionError("baseline_unacceptable_STOP")
    paths = {item["username"]: root / item["credential_file"] for item in _planned_items(plan)}
    if any(p.exists() for p in paths.values()):
        raise ProvisionError("credential_file_exists_STOP")
    created_files, rollback, steps = [], [], []
    state = dict(status="IN_PROGRESS", created_credentials=[], steps=steps, plan_sha256=plan["plan_sha256"])
    evidence.write("provision_state.json", state)

    def checkpoint(step):
        steps.append(step)
        state["created_credentials"] = [p.name for p in created_files]
        evidence.write("provision_state.json", state)
        evidence.event("STEP_VERIFIED", **step)

    try:
        passwords = {}
        for item in _planned_items(plan):
            passwords[item["username"]] = token()
            if len(passwords[item["username"]]) < MIN_SECRET_CHARS:
                raise ProvisionError("generated_credential_too_short")
            path = paths[item["username"]]
            created_files.append(path)  # tracked before creation: removal on rollback is limited to files this run made
            _create_credential(path, passwords[item["username"]])
            checkpoint(dict(step="credential_file", principal=item["username"]))
        for item in _planned_items(plan):
            (role, acls), = item["role_acls"].items()
            rollback.append(("deleteRole", dict(rolename=role)))
            admin.call("createRole", rolename=role, acls=acls)
            if role_acls(admin, role) != gp.sorted_acls(acls):
                raise ProvisionError("role_postcondition_mismatch")
            checkpoint(dict(step="role", rolename=role))
        for item in _planned_items(plan):
            rollback.append(("deleteClient", dict(username=item["username"])))
            admin.call("createClient", username=item["username"], clientid=item["clientid"],
                       password=passwords[item["username"]], roles=item["roles"])
            if client_meta(admin, item["username"]) != _expected_client(item):
                raise ProvisionError("client_postcondition_mismatch")
            checkpoint(dict(step="client", principal=item["username"], role_membership_priority=gp.PRIORITY))
        passwords.clear()
        after = capture_state(admin)
        reasons = gp.compare_preserved(before["snapshot"], after["snapshot"], plan)
        reasons += gp.original_semantics_preserved(before["snapshot"], after["snapshot"])
        if after["legacy"] != before["legacy"]:
            reasons.append("historical principals' full records (including role-membership priority) changed")
        verdict = gp.verify_expanded_snapshot(after["snapshot"], plan, registry_v2)
        if verdict["verdict"] != "PASS":
            reasons += verdict["reasons"]
        evidence.write("post_state.json", after)
        if reasons:
            evidence.write("postcondition_failures.json", dict(reasons=reasons))
            raise ProvisionError("postcondition_failed")
        state["status"] = "COMPLETE"
        evidence.write("provision_state.json", state)
        return dict(status="COMPLETE", pre_policy_sha256=before["policy_sha256"], post_policy_sha256=after["policy_sha256"],
                    created_principals=plan["added_principals"], created_roles=plan["added_roles"],
                    binding_audit_v2=verdict["binding_audit"])
    except Exception as exc:
        code = str(exc) if isinstance(exc, ProvisionError) else "provision_error"
        restored = _rollback(admin, evidence, before, rollback, created_files)
        state["status"] = "ROLLED_BACK_VERIFIED" if restored else "RESTORATION_FAILED"
        state["failure_code"] = code
        evidence.write("provision_state.json", state)
        if not restored:
            raise ProvisionError("restoration_failed_STOP") from None
        raise ProvisionError(code) from None


def _rollback(admin, evidence, before, rollback, created_files):
    failures = 0
    for command, parameters in reversed(rollback):
        try:
            evidence.event("ROLLBACK_STEP", command=command, created_by_this_run=True, **parameters)
            admin.call(command, optional=True, **parameters)
        except Exception:
            failures += 1
    for path in created_files:
        try:
            Path(path).unlink(missing_ok=True)
        except OSError:
            failures += 1
    try:
        after = capture_state(admin)
        equal = after["snapshot"] == before["snapshot"] and after["legacy"] == before["legacy"]
    except Exception:
        equal = False
    evidence.event("ROLLBACK_VERIFIED", pre_image_equal=equal, step_failures=failures)
    return equal and failures == 0


# ---------------------------------------------------------------- verify (read-only)
def verify_live(admin, plan, registry_v1, registry_v2, pre_image=None):
    state = capture_state(admin)
    reasons = []
    for item in _planned_items(plan):
        if client_meta(admin, item["username"], optional=True) != _expected_client(item):
            reasons.append(f"{item['username']}: client (including role-membership priority) differs from the plan")
        for role, acls in item["role_acls"].items():
            if role_acls(admin, role, optional=True) != gp.sorted_acls(acls):
                reasons.append(f"{role}: ACLs differ from the plan")
    expanded = gp.verify_expanded_snapshot(state["snapshot"], plan, registry_v2)
    reasons += expanded["reasons"]
    audit_v1 = binding_audit.analyze(state["snapshot"], registry_v1)
    audit_v2 = binding_audit.analyze(state["snapshot"], registry_v2)
    if audit_v1["verdict"] != "PASS":
        reasons.append("binding audit under registry v1 is not PASS")
    if audit_v2["verdict"] != "PASS":
        reasons.append("binding audit under registry v2 is not PASS")
    if pre_image is not None:
        legacy_unchanged = state["legacy"] == pre_image["legacy"]
        if not legacy_unchanged:
            reasons.append("historical principals differ from the recorded pre-image")
        for name in ("defaults", "groups", "anonymous_group"):
            if state["snapshot"][name] != pre_image["snapshot"][name]:
                reasons.append(f"{name} differs from the recorded pre-image")
    else:
        legacy_unchanged = not inspect_baseline_legacy_reasons(state)
        if not legacy_unchanged:
            reasons.append("historical principals differ from the documented baseline")
    return dict(verdict="PASS" if not reasons else "FAIL", reasons=reasons, binding_audit_v1=audit_v1["verdict"],
                binding_audit_v2=audit_v2["verdict"], legacy_unchanged=legacy_unchanged, policy_sha256=state["policy_sha256"])


def inspect_baseline_legacy_reasons(state):
    documented = gp.documented_legacy_snapshot()
    reasons = []
    for name in gp.legacy_principals():
        record, want = state["legacy"][name], documented["clients"][name]
        meta = record["client"]
        if meta is None or (meta["clientid"], meta["disabled"], meta["groups"]) != (want["clientid"], False, []) \
                or [r["rolename"] for r in meta["roles"]] != want["roles"] or any(r["priority"] != gp.PRIORITY for r in meta["roles"]) \
                or any(acls != documented["roles"].get(role) for role, acls in record["roles"].items()):
            reasons.append(name)
    return reasons


# ---------------------------------------------------------------- rollback command (explicit, scoped)
def rollback_planned(admin, evidence, plan, credential_root, created_credentials=(), pre_image=None):
    """Remove ONLY planned entities that exist exactly as planned; anything else with a planned name stops the run."""
    removed = []
    for item in reversed(_planned_items(plan)):
        meta = client_meta(admin, item["username"], optional=True)
        if meta is None:
            continue
        if meta != _expected_client(item):
            raise ProvisionError("planned_client_differs_STOP")
    for item in reversed(_planned_items(plan)):
        (role, acls), = item["role_acls"].items()
        found = role_acls(admin, role, optional=True)
        if found is not None and found != gp.sorted_acls(acls):
            raise ProvisionError("planned_role_differs_STOP")
    for item in reversed(_planned_items(plan)):
        if client_meta(admin, item["username"], optional=True) is not None:
            evidence.event("ROLLBACK_STEP", command="deleteClient", username=item["username"])
            admin.call("deleteClient", username=item["username"])
            removed.append(item["username"])
    for item in reversed(_planned_items(plan)):
        (role, _), = item["role_acls"].items()
        if role_acls(admin, role, optional=True) is not None:
            evidence.event("ROLLBACK_STEP", command="deleteRole", rolename=role)
            admin.call("deleteRole", rolename=role)
            removed.append(role)
    allowed = {item["credential_file"] for item in _planned_items(plan)}
    for name in created_credentials:
        if name in allowed:  # only files this plan names, only those the provisioning run recorded as its own
            Path(credential_root, name).unlink(missing_ok=True)
    state = capture_state(admin)
    leftover = (set(plan["added_principals"]) & set(state["snapshot"]["clients"])) | (set(plan["added_roles"]) & set(state["snapshot"]["roles"]))
    equal = None if pre_image is None else (state["snapshot"] == pre_image["snapshot"] and state["legacy"] == pre_image["legacy"])
    if leftover or equal is False:
        raise ProvisionError("restoration_failed_STOP")
    return dict(removed=removed, pre_image_equal=equal)


# ---------------------------------------------------------------- command line
def _load(args):
    registry_v1 = DeviceRegistry.load(args.registry_v1)
    registry_v2 = DeviceRegistry.load(args.registry_v2)
    spec = json.loads(Path(args.identity_spec).read_text(encoding="utf-8"))
    return registry_v1, registry_v2, gp.build_plan(registry_v1, registry_v2, spec)


def _read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("inspect", "verify", "provision", "rollback"))
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--registry-v1", default="/app/configs/observation/device_registry.json")
    parser.add_argument("--registry-v2", default="/app/configs/observation/device_registry_v2.json")
    parser.add_argument("--identity-spec", default="/app/configs/gate5d3/identity_spec.json")
    parser.add_argument("--credentials-dir", default="/credentials")
    parser.add_argument("--evidence-root", default="/results/gate5d3_provision")
    parser.add_argument("--pre-image-run", help="evidence run whose pre_image_state.json is the comparison baseline (verify/rollback)")
    parser.add_argument("--state-run", help="evidence run whose provision_state.json lists credential files to remove (rollback)")
    parser.add_argument("--plan-sha256", help="exact plan digest (mutating commands)")
    parser.add_argument("--registry-v2-sha256", help="exact frozen registry v2 digest (mutating commands)")
    parser.add_argument("--confirm-live-mutation", action="store_true")
    args = parser.parse_args(argv)
    mutating = args.action in ("provision", "rollback")
    records = admin = None
    try:
        if not RUN_ID.fullmatch(args.run_id):
            raise ProvisionError("invalid_run_id")
        registry_v1, registry_v2, plan = _load(args)
        if mutating and not (args.confirm_live_mutation and args.plan_sha256 == plan["plan_sha256"]
                             and args.registry_v2_sha256 == registry_v2.sha256):
            raise ProvisionError("authorization_missing_or_stale")
        from experiments.a3_policy import Admin
        from experiments.research_records import RunConfig, RunRecords
        import importlib.metadata
        import platform
        runtime = dict(python=platform.python_version(), paho_mqtt=importlib.metadata.version("paho-mqtt"),
                       git_commit=os.getenv("AZTA_GIT_COMMIT", "unknown"), git_state=os.getenv("AZTA_GIT_STATE", "unknown"),
                       container_image=os.getenv("AZTA_RUNTIME_IMAGE", "unknown"))
        records = RunRecords(args.evidence_root, RunConfig(run_id=args.run_id, scenario="gate5d3-" + args.action), runtime,
                             streams=("admin",))
        evidence = Evidence(records)
        admin = Admin(records)
        pre_image = _read_json(Path(args.evidence_root) / args.pre_image_run / "pre_image_state.json") if args.pre_image_run else None
        if args.action == "inspect":
            state = capture_state(admin)
            result = dict(baseline=inspect_baseline(state, plan, registry_v1), plan_sha256=plan["plan_sha256"],
                          registry_v2_sha256=registry_v2.sha256)
            evidence.write("inspect_state.json", state)
            ok = result["baseline"]["acceptable"]
        elif args.action == "verify":
            result = verify_live(admin, plan, registry_v1, registry_v2, pre_image)
            ok = result["verdict"] == "PASS"
        elif args.action == "provision":
            result = provision(admin, evidence, plan, registry_v1, registry_v2, args.credentials_dir)
            ok = True
        else:
            created = []
            if args.state_run:
                created = _read_json(Path(args.evidence_root) / args.state_run / "provision_state.json").get("created_credentials", [])
            result = rollback_planned(admin, evidence, plan, args.credentials_dir, created, pre_image)
            ok = True
        records.finish(dict(state="COMPLETE", result=result))
        print(f"GATE5D3_PROVISION {args.action} {'PASS' if ok else 'FAIL'} run_id={args.run_id} plan_sha256={plan['plan_sha256']}")
        return 0 if ok else 1
    except Exception as exc:
        code = str(exc) if isinstance(exc, ProvisionError) else type(exc).__name__
        if records is not None:
            records.finish(dict(state="INCOMPLETE", failure_code=code))
        print(f"GATE5D3_PROVISION {args.action} FAILED {code}", file=sys.stderr)
        return 1
    finally:
        if admin is not None:
            admin.close()
        if records is not None:
            records.close()


if __name__ == "__main__":
    raise SystemExit(main())
