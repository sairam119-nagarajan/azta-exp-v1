"""Gate 5D.3B-0 offline provisioning PLAN and verification layer. It plans and verifies; it never mutates.

Builds a deterministic, human-reviewable description of the policy additions that a later, separately authorized
provisioning task would have to make (eight publish-only device principals and one dedicated receive-only observer),
plus pure functions that compare policy snapshots (the dict produced by experiments.binding_audit.collect_snapshot).

This module imports no MQTT client, Dynamic Security administrator, secret or network code. It generates no credential,
sends no command and is not an executable provisioning workflow: the `proposed_steps` it emits are data for review only.
Historical a3_policy / a3_mqtt are neither imported nor modified; the A3 conventions (docs/FOUNDATION_A3.md) are restated.
"""
import argparse
import copy
import json
from pathlib import Path
import re
import sys

from experiments import binding_audit
from observation.registry import DeviceRegistry
from observation.schema import canonical, sha256_text

PLAN_SCHEMA = "azta.gate5d3.provisioning_plan"
PRIORITY = 10  # ACL and role-membership priority of every accepted A3 role (docs/FOUNDATION_A3.md)
OBSERVER_IDENTITY = "azta-observer"
OBSERVER_ROLE = "azta-observer-telemetry-read"
OBSERVER_CREDENTIAL = "azta-observer-password"
OBSERVER_NAME = re.compile(r"azta-observer(-[a-z0-9][a-z0-9-]{0,30})?\Z")
RECEIVER = "azta-operations-receiver"
PDP = "azta-pdp"
PDP_ROLE = "azta-pdp-telemetry-read"
RECEIVER_ROLE = "azta-operations-read"
DEFAULT_ACLTYPES = ("publishClientReceive", "publishClientSend", "subscribe", "unsubscribe")
PUBLISH_DENIED, SUBSCRIBE_DENIED, CONNECT_DENIED = 135, 135, 135  # MQTT v5 "not authorized" (Gate 2 / 5B evidence)
ROOT = Path(__file__).resolve().parents[1]
FREEZE_PATH = ROOT / "configs" / "gate5d3" / "registry_v2_freeze.json"
FREEZE_STATUS = "FROZEN_FOR_FUNCTIONAL_USE"


def acl(kind, topic):
    return dict(acltype=kind, topic=topic, allow=True, priority=PRIORITY)


def _sorted_acls(acls):
    return sorted(({k: a[k] for k in ("acltype", "topic", "allow", "priority")} for a in acls),
                  key=lambda a: (a["acltype"], str(a["topic"]), a["priority"], a["allow"]))


sorted_acls = _sorted_acls  # public alias for the Gate 5D.3 operator tools


def operations_topic(device):
    return f"azta/devices/{device}/operations"


def _problem_free(problems):
    if problems:
        raise ValueError("provisioning plan invariant violated: " + "; ".join(problems))


# ---------------------------------------------------------------- the documented historical policy (A3 / Gate 2)
def documented_legacy_snapshot():
    """The two-device policy as DOCUMENTED (docs/FOUNDATION_A3.md, GATE_2_AUTHORIZATION.md): VERIFIED FROM
    DOCUMENTATION, not a live read. Synthetic stand-in for the shape of binding_audit.collect_snapshot()."""
    d1, d2 = (f"azta/devices/device0{n}/telemetry" for n in (1, 2))
    read = lambda topic: [acl("subscribeLiteral", topic), acl("publishClientReceive", topic)]
    roles = {
        "azta-device01-telemetry-publish": [acl("publishClientSend", d1)],
        "azta-device01-operation-publish": [acl("publishClientSend", operations_topic("device01"))],
        "azta-device02-telemetry-publish": [acl("publishClientSend", d2)],
        "azta-device02-operation-publish": [acl("publishClientSend", operations_topic("device02"))],
        PDP_ROLE: read(d1) + [acl("unsubscribeLiteral", d1)] + read(d2),
        RECEIVER_ROLE: read(operations_topic("device01")) + read(operations_topic("device02")),
        "dynsec-admin": [acl("publishClientSend", "$CONTROL/dynamic-security/#")],
    }
    clients = {
        "admin": ("dynsec-admin",), "azta-device-01": ("azta-device01-telemetry-publish", "azta-device01-operation-publish"),
        "azta-device-02": ("azta-device02-telemetry-publish", "azta-device02-operation-publish"),
        PDP: (PDP_ROLE,), RECEIVER: (RECEIVER_ROLE,)}
    return dict(
        defaults=sorted((dict(acltype=kind, allow=False) for kind in DEFAULT_ACLTYPES), key=lambda a: a["acltype"]),
        clients={name: dict(clientid=None if name == "admin" else name, disabled=False, roles=sorted(names), groups=[])
                 for name, names in clients.items()},
        groups={}, roles={name: _sorted_acls(acls) for name, acls in roles.items()}, anonymous_group=None)


def legacy_principals():
    return ("azta-device-01", "azta-device-02", PDP, RECEIVER)


# ---------------------------------------------------------------- the plan
def _device_principal(entry):
    role = entry.publish_role
    return dict(username=entry.username, clientid=entry.client_id, disabled=False, groups=[],
                roles=[dict(rolename=role, priority=PRIORITY)],
                role_acls={role: [acl("publishClientSend", entry.telemetry_topic)]},
                credential_file=f"{entry.username}-password")


def _expected_denials(added, observer_topics, preserved_topics):
    probes = []
    all_topics = {e["username"]: e["topic"] for e in added}
    names = sorted(all_topics)
    for index, name in enumerate(names):
        other = names[(index + 1) % len(names)]
        device = all_topics[name].split("/")[2]
        probes += [
            dict(actor=name, action="publish", target=all_topics[other], expected=dict(kind="PUBACK", code=PUBLISH_DENIED),
                 why="no publish entitlement on another device's telemetry topic"),
            dict(actor=name, action="publish", target=operations_topic(device), expected=dict(kind="PUBACK", code=PUBLISH_DENIED),
                 why="added devices receive no operations entitlement"),
            dict(actor=name, action="subscribe", target=all_topics[name], expected=dict(kind="SUBACK", code=SUBSCRIBE_DENIED),
                 why="devices hold no subscribe entitlement"),
            dict(actor=name, action="subscribe", target="azta/devices/#", expected=dict(kind="SUBACK", code=SUBSCRIBE_DENIED),
                 why="no wildcard entitlement"),
            dict(actor=name, action="connect_with_foreign_client_id", target=other,
                 expected=dict(kind="CONNACK", code=CONNECT_DENIED), why="client ID is bound to the username"),
        ]
    probes += [
        dict(actor="azta-device-01", action="publish", target=all_topics[names[0]], expected=dict(kind="PUBACK", code=PUBLISH_DENIED),
             why="historical device01 gains no entitlement on an added topic"),
        dict(actor="azta-device-02", action="publish", target=all_topics[names[0]], expected=dict(kind="PUBACK", code=PUBLISH_DENIED),
             why="historical device02 gains no entitlement on an added topic"),
        dict(actor=PDP, action="subscribe", target=all_topics[names[0]], expected=dict(kind="SUBACK", code=SUBSCRIBE_DENIED),
             why="the historical PDP ACL is not widened"),
        dict(actor=OBSERVER_IDENTITY, action="publish", target=observer_topics[0], expected=dict(kind="PUBACK", code=PUBLISH_DENIED),
             why="the observer is receive-only"),
        dict(actor=OBSERVER_IDENTITY, action="subscribe", target="azta/devices/#", expected=dict(kind="SUBACK", code=SUBSCRIBE_DENIED),
             why="exact literal subscriptions only"),
        dict(actor=OBSERVER_IDENTITY, action="subscribe", target=operations_topic("device01"),
             expected=dict(kind="SUBACK", code=SUBSCRIBE_DENIED), why="operations traffic is out of the observer's scope"),
        dict(actor=OBSERVER_IDENTITY, action="subscribe", target="$CONTROL/dynamic-security/#",
             expected=dict(kind="SUBACK", code=SUBSCRIBE_DENIED), why="no control-topic access"),
        dict(actor=OBSERVER_IDENTITY, action="connect_with_foreign_client_id", target=PDP,
             expected=dict(kind="CONNACK", code=CONNECT_DENIED), why="client ID is bound to the username"),
    ]
    return probes


def load_freeze(path=None):
    return json.loads(Path(path or FREEZE_PATH).read_text(encoding="utf-8"))


def build_plan(registry_v1, registry_v2, identity_spec, freeze=None):
    """Deterministic provisioning plan from the committed v1/v2 registries, the identity spec and the registry freeze record."""
    freeze = freeze if freeze is not None else load_freeze()
    if (freeze.get("status"), freeze.get("registry_sha256"), freeze.get("v1_registry_sha256"))             != (FREEZE_STATUS, registry_v2.sha256, registry_v1.sha256):
        raise ValueError("registry v2 digest differs from its freeze record (or the registry is not frozen)")
    v1 = {e.device: e for e in registry_v1.devices}
    entries = {e.device: e for e in registry_v2.devices}
    if set(v1) - set(entries) or any(entries[d] != v1[d] for d in v1):
        raise ValueError("registry v2 must contain the original entries unchanged")
    added_entries = [entries[d] for d in sorted(set(entries) - set(v1))]
    spec = {item["device"]: item for item in identity_spec["additional_devices"]}
    if sorted(spec) != [e.device for e in added_entries]:
        raise ValueError("identity spec and registry v2 disagree on the added devices")
    for entry in added_entries:
        item = spec[entry.device]
        if (item["username"], item["client_id"], item["role"]) != (entry.username, entry.client_id, entry.publish_role):
            raise ValueError(f"identity spec disagrees with registry v2 for {entry.device}")
    proposal = identity_spec.get("observer_principal_proposal") or {}
    if (proposal.get("identity"), proposal.get("client_id"), proposal.get("role"), proposal.get("provisioned"))             != (OBSERVER_IDENTITY, OBSERVER_IDENTITY, OBSERVER_ROLE, False):
        raise ValueError("identity spec observer proposal differs from the accepted dedicated observer")
    devices = [_device_principal(e) for e in added_entries]
    topics = [e.telemetry_topic for e in registry_v2.devices]
    observer = dict(
        username=OBSERVER_IDENTITY, clientid=OBSERVER_IDENTITY, disabled=False, groups=[],
        roles=[dict(rolename=OBSERVER_ROLE, priority=PRIORITY)],
        role_acls={OBSERVER_ROLE: _sorted_acls([a for t in topics for a in (acl("subscribeLiteral", t), acl("publishClientReceive", t))])},
        subscriptions=[dict(topic=t, qos=1) for t in topics], credential_file=OBSERVER_CREDENTIAL)
    added_names = [d["username"] for d in devices] + [OBSERVER_IDENTITY]
    steps = []
    for item in devices + [observer]:
        (role, acls), = item["role_acls"].items()
        steps.append(dict(command="createRole", rolename=role, acls=acls))
    for item in devices + [observer]:
        steps.append(dict(command="createClient", username=item["username"], clientid=item["clientid"],
                          roles=item["roles"], password="<generated at execution; never stored in the plan>"))
    rollback = ([dict(command="deleteClient", username=n) for n in reversed(added_names)]
                + [dict(command="deleteRole", rolename=next(iter(i["role_acls"]))) for i in reversed(devices + [observer])])
    body = dict(
        schema=PLAN_SCHEMA, schema_version=1, status="PROPOSED_NOT_EXECUTED", executable=False, mutation_performed=False,
        registry=dict(v1_sha256=registry_v1.sha256, v2_sha256=registry_v2.sha256, v2_status=FREEZE_STATUS,
                      v2_note="digest frozen for functional use by configs/gate5d3/registry_v2_freeze.json; not approved for scientific use",
                      freeze_record_sha256=sha256_text(canonical(freeze))),
        conventions=dict(acl_priority=PRIORITY, role_membership_priority=PRIORITY, default_acls="deny (unchanged)",
                         source="docs/FOUNDATION_A3.md"),
        device_principals=devices, observer=observer,
        preserved=dict(principals=list(legacy_principals()), rule="every pre-existing client, role, group, default ACL "
                       "and the anonymous group must be identical before and after; the only differences are the planned additions",
                       not_widened=[PDP]),
        added_principals=added_names, added_roles=[next(iter(i["role_acls"])) for i in devices + [observer]],
        expected_denials=_expected_denials(
            [dict(username=e.username, topic=e.telemetry_topic) for e in added_entries], topics, topics),
        proposed_steps=steps,
        restoration=dict(kind="semantic", rollback_steps=rollback,
                         verify="re-read the policy; compare every pre-existing principal, role and default with the pre-image; "
                                "the added names must be absent after a rollback or exactly as planned after acceptance",
                         credentials="delete only credential files created by that execution; never overwrite or delete a pre-existing one"),
        preconditions=[
            "separate explicit authorization for live provisioning", "clean committed repository at a recorded HEAD",
            "read-only baseline snapshot captured and its digest recorded; baseline verdict PASS under registry v1",
            "no other session with any of the bound client IDs (including azta-pdp, azta-device-01/02, azta-observer)",
            "Docker Desktop inventory (running containers, networks, volumes) captured before and compared after; "
            "start only the existing broker without dependencies; never prune, remove volumes or touch other projects",
            "registry v2 frozen by review (its digest is provisional)"],
        stop_conditions=[
            "any pre-existing principal, role, group or default ACL differs from the baseline",
            "any planned name already exists", "partial provisioning detected", "credential file already exists with other content",
            "a read-only audit under registry v2 does not PASS", "any expected denial is observed as allowed",
            "an unexpected container or volume change in the shared Docker engine"],
        not_authorized_by_this_plan=["credential generation", "client or role creation", "ACL change", "MQTT connection",
                                     "Docker or Compose use", "model scoring", "trust integration"])
    plan = dict(body, plan_sha256=sha256_text(canonical(body)))
    verify_plan(plan, registry_v2)
    return plan


def verify_plan(plan, registry_v2):
    """Raise ValueError unless the plan contains only approved, least-privilege permissions."""
    problems = []
    body = {k: v for k, v in plan.items() if k != "plan_sha256"}
    if plan.get("plan_sha256") != sha256_text(canonical(body)):
        problems.append("plan digest mismatch")
    if plan.get("executable") is not False or plan.get("mutation_performed") is not False:
        problems.append("a plan is never executable or already executed")
    telemetry = {e.device: e.telemetry_topic for e in registry_v2.devices}
    registry_names = {e.username: e for e in registry_v2.devices}
    devices, observer = plan["device_principals"], plan["observer"]
    names = [d["username"] for d in devices] + [observer["username"]]
    clientids = [d["clientid"] for d in devices] + [observer["clientid"]]
    if len(set(names)) != len(names) or len(set(clientids)) != len(clientids):
        problems.append("duplicate principal or client ID")
    if any(n != c for n, c in zip(names, clientids)):
        problems.append("client ID must equal the username")
    if set(names) & set(legacy_principals()):
        problems.append("a historical principal is being re-created")
    if not OBSERVER_NAME.fullmatch(observer["username"]):
        problems.append("observer name is not a dedicated azta-observer principal")
    for item in devices + [observer]:
        if item["disabled"] or item["groups"]:
            problems.append(f"{item['username']}: must be enabled with no groups")
        if [r["priority"] for r in item["roles"]] != [PRIORITY] or len(item["roles"]) != 1:
            problems.append(f"{item['username']}: exactly one role at priority {PRIORITY}")
        for role, acls in item["role_acls"].items():
            if [r["rolename"] for r in item["roles"]] != [role]:
                problems.append(f"{item['username']}: role/ACL mismatch")
            if any(a["priority"] != PRIORITY or a["allow"] is not True for a in acls):
                problems.append(f"{role}: ACL priority/allow")
            if any(not re.fullmatch(r"azta/devices/device\d\d/telemetry", a["topic"]) for a in acls):
                problems.append(f"{role}: topic is not an exact device telemetry topic")
    for item in devices:
        entry = registry_names.get(item["username"])
        (role, acls), = item["role_acls"].items()
        if entry is None or role != entry.publish_role or acls != [acl("publishClientSend", entry.telemetry_topic)]:
            problems.append(f"{item['username']}: must hold exactly publishClientSend on its own registry topic")
    (obs_role, obs_acls), = observer["role_acls"].items()
    expected = _sorted_acls([a for t in telemetry.values() for a in (acl("subscribeLiteral", t), acl("publishClientReceive", t))])
    if obs_role != OBSERVER_ROLE or _sorted_acls(obs_acls) != expected:
        problems.append("observer ACLs must be exactly subscribe+receive on the ten approved telemetry topics")
    if any(a["acltype"] == "publishClientSend" for a in obs_acls):
        problems.append("observer must be receive-only")
    if sorted(s["topic"] for s in observer["subscriptions"]) != sorted(telemetry.values()):
        problems.append("observer subscriptions must be the exact approved topics")
    if any(c in a["topic"] for item in devices + [observer] for acls in item["role_acls"].values() for a in acls for c in "+#%"):
        problems.append("wildcard or substitution in a granted topic")
    for probe in plan["expected_denials"]:
        if probe["expected"]["code"] != 135:
            problems.append("an expected denial must be a not-authorized outcome")
    grants = {item["username"]: {(a["acltype"], a["topic"]) for acls in item["role_acls"].values() for a in acls}
              for item in devices + [observer]}
    needed = {"publish": "publishClientSend", "subscribe": "subscribeLiteral"}
    for probe in plan["expected_denials"]:
        kind = needed.get(probe["action"])
        if kind and (kind, probe["target"]) in grants.get(probe["actor"], set()):
            problems.append(f"expected denial is actually granted: {probe['actor']} {probe['action']} {probe['target']}")
    _problem_free(problems)
    return True


# ---------------------------------------------------------------- snapshot operations (pure)
def apply_plan(snapshot, plan):
    """What the policy snapshot WOULD look like after the plan (pure; used to prepare the expected post-state)."""
    after = copy.deepcopy(snapshot)
    for item in plan["device_principals"] + [plan["observer"]]:
        after["clients"][item["username"]] = dict(clientid=item["clientid"], disabled=item["disabled"],
                                                  roles=sorted(r["rolename"] for r in item["roles"]), groups=[])
        for role, acls in item["role_acls"].items():
            after["roles"][role] = _sorted_acls(acls)
    return after


def compare_preserved(before, after, plan):
    """Reasons (empty = preserved): pre-existing policy identical; the only differences are the planned additions."""
    reasons = []
    for section in ("clients", "groups", "roles"):
        for name, value in before[section].items():
            if name not in after[section]:
                reasons.append(f"{section[:-1]} {name} was removed")
            elif after[section][name] != value:
                reasons.append(f"{section[:-1]} {name} was modified")
    if after["defaults"] != before["defaults"]:
        reasons.append("default ACLs changed")
    if after["anonymous_group"] != before["anonymous_group"]:
        reasons.append("anonymous group changed")
    if set(after["clients"]) - set(before["clients"]) - set(plan["added_principals"]):
        reasons.append("unplanned client added")
    if set(after["roles"]) - set(before["roles"]) - set(plan["added_roles"]):
        reasons.append("unplanned role added")
    if set(after["groups"]) != set(before["groups"]):
        reasons.append("groups changed")
    return reasons


def verify_expanded_snapshot(snapshot, plan, registry_v2):
    """Check a (read-only) snapshot against the plan: exact additions and a PASS binding audit under registry v2."""
    reasons = []
    for item in plan["device_principals"] + [plan["observer"]]:
        client = snapshot["clients"].get(item["username"])
        want = dict(clientid=item["clientid"], disabled=False, roles=sorted(r["rolename"] for r in item["roles"]), groups=[])
        if client != want:
            reasons.append(f"{item['username']}: client differs from the plan")
        for role, acls in item["role_acls"].items():
            if snapshot["roles"].get(role) != _sorted_acls(acls):
                reasons.append(f"{role}: ACLs differ from the plan")
    audit = binding_audit.analyze(snapshot, registry_v2)
    if audit["verdict"] != "PASS":
        reasons.append("binding audit under registry v2 is not PASS")
    pdp = snapshot["clients"].get(PDP)
    if pdp is None or snapshot["roles"].get(PDP_ROLE) is None:
        reasons.append("historical PDP principal missing")
    return dict(verdict="PASS" if not reasons else "FAIL", reasons=reasons, binding_audit=audit["verdict"],
                policy_sha256=audit["policy_sha256"])


def original_semantics_preserved(before, after):
    """The four historical principals keep the same client record and role ACLs (the semantic-preservation check)."""
    reasons = []
    for name in legacy_principals():
        if after["clients"].get(name) != before["clients"].get(name):
            reasons.append(f"{name}: client record changed")
        for role in (before["clients"].get(name) or {}).get("roles", []):
            if after["roles"].get(role) != before["roles"].get(role):
                reasons.append(f"{role}: ACLs changed")
    return reasons


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry-v1", default=str(ROOT / "configs/observation/device_registry.json"))
    parser.add_argument("--registry-v2", default=str(ROOT / "configs/observation/device_registry_v2.json"))
    parser.add_argument("--identity-spec", default=str(ROOT / "configs/gate5d3/identity_spec.json"))
    parser.add_argument("--output", required=True, help="new file; an existing file is never overwritten")
    args = parser.parse_args(argv)
    try:
        spec = json.loads(Path(args.identity_spec).read_text(encoding="utf-8"))
        plan = build_plan(DeviceRegistry.load(args.registry_v1), DeviceRegistry.load(args.registry_v2), spec)
        with Path(args.output).open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(plan, indent=2, sort_keys=True) + "\n")
    except (ValueError, OSError, KeyError) as exc:
        print(f"GATE5D3_PLAN_REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(f"GATE5D3_PROVISIONING_PLAN plan_sha256={plan['plan_sha256']} executable=False")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
