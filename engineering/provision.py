"""Operator-only provisioning and verification of the ISOLATED engineering broker (`azta-eng`): the accepted policy, rebuilt from its own specifications.

    python -m engineering.provision inspect                         read-only: names, roles, defaults (no ACL contents beyond counts, no secrets)
    python -m engineering.provision provision --run-id ID           build the ten-device policy on a FRESH engineering broker (refuses anything else)
    python -m engineering.provision verify    --run-id ID           read-only: the broker equals the expected policy exactly
    python -m engineering.provision drift --device D --drift-action A   engineering fault injection: one out-of-band operations-role change (isolated broker only)

The expected policy is not invented here: it is the documented historical two-device policy (`gate5d3_provisioning_plan.documented_legacy_snapshot`: device01/02 with telemetry and
operations roles, the PDP and the operations receiver) plus the reviewed, digest-pinned Gate 5D.3 plan (eight publish-only devices and the dedicated observer), plus ONE
engineering-only principal, the isolation sentinel (disabled, no roles) that lets the PEP attest it is on the isolated broker. Defaults are set to deny for all four ACL types. The
administrative principal keeps only the Dynamic Security control entitlement. Credentials are read from the mounted engineering credential directory and appear in no log, record or
message; broker responses never enter error text. The tool refuses to run on a broker that already has any non-bootstrap principal unless that policy equals the expected one.
"""
import argparse
import json
from pathlib import Path
import sys

from enforcement.channel import MqttControlChannel
from enforcement.errors import ControlUnavailable
from enforcement.model import ROLE_PRIORITY, Catalogue
from experiments import binding_audit
from experiments import gate5d3_provisioning_plan as gp
from observation.registry import DeviceRegistry

CREDENTIALS = Path("/credentials")
ADMIN_CREDENTIAL = Path("/run/secrets/dynsec_admin_password")
CONFIGS = Path("/app/configs")
SENTINEL = "azta-eng-isolation-sentinel"
PILOT_SENTINEL = "azta-pilot-isolation-sentinel"      # selected by --sentinel pilot: marks the dedicated PILOT broker instead of the engineering one
DEFAULT_TYPES = ("publishClientSend", "publishClientReceive", "subscribe", "unsubscribe")
DYNSEC_ROLE = "dynsec-admin"
BUILT_IN_ROLES = ("broker-admin", "client", "dynsec-admin", "super-admin", "sys-notify", "sys-observe", "topic-observe")   # created by Mosquitto itself; never assigned to a principal here


class ProvisionError(Exception):
    """A short code only; broker responses never enter the message."""


class Admin:
    """The read/write interface the shared snapshot code expects (`call`), over the engineering control channel."""

    def __init__(self, channel):
        self.channel = channel

    def call(self, command, optional=False, **fields):
        response = self.channel.command(command, **fields)
        if not response["success"]:
            if optional and "not found" in (response["error"] or "").lower():
                return None
            raise ProvisionError(f"command_failed:{command}")
        return response["data"]


def expected_policy(configs=CONFIGS):
    """(roles {name: acls}, clients {username: dict(clientid, roles)}) of the whole engineering policy, from the documented sources."""
    registry_v1 = DeviceRegistry.load(configs / "observation" / "device_registry.json")
    registry_v2 = DeviceRegistry.load(configs / "observation" / "device_registry_v2.json")
    spec = json.loads((configs / "gate5d3" / "identity_spec.json").read_text(encoding="utf-8"))
    freeze = json.loads((configs / "gate5d3" / "registry_v2_freeze.json").read_text(encoding="utf-8"))
    plan = gp.build_plan(registry_v1, registry_v2, spec, freeze)
    legacy = gp.documented_legacy_snapshot()
    roles = {name: acls for name, acls in legacy["roles"].items() if name != DYNSEC_ROLE}
    clients = {name: dict(clientid=data["clientid"], roles=list(data["roles"])) for name, data in legacy["clients"].items() if name != "admin"}
    for item in plan["device_principals"] + [plan["observer"]]:
        (role, acls), = item["role_acls"].items()
        roles[role] = gp.sorted_acls(acls)
        clients[item["username"]] = dict(clientid=item["clientid"], roles=[role])
    return roles, clients, dict(plan_sha256=plan["plan_sha256"], registry_v2_sha256=registry_v2.sha256)


def credential(principal):
    path = CREDENTIALS / ("admin-password" if principal == "admin" else f"{principal}-password")
    text = path.read_text(encoding="utf-8").strip()
    if len(text) < 32:
        raise ProvisionError("credential_too_short")
    return text


def summary(admin):
    snapshot = binding_audit.collect_snapshot(binding_audit.ReadOnlyAdmin(_Reader(admin)))
    return snapshot


class _Reader:
    """Adapts `Admin` to the read-only wrapper (which calls `.call` and `.close`)."""

    def __init__(self, admin):
        self.admin = admin

    def call(self, command, optional=False, **fields):
        return self.admin.call(command, optional=optional, **fields)

    def close(self):
        pass


def inspect(admin):
    snap = summary(admin)
    return dict(defaults=snap["defaults"], clients={k: dict(clientid=v["clientid"], disabled=v["disabled"], roles=v["roles"], groups=v["groups"]) for k, v in snap["clients"].items()},
                roles={k: len(v) for k, v in snap["roles"].items()}, groups=sorted(snap["groups"]), anonymous_group=snap["anonymous_group"])


def expected_snapshot(roles, clients):
    snap = dict(defaults=sorted((dict(acltype=t, allow=False) for t in DEFAULT_TYPES), key=lambda a: a["acltype"]),
                clients={name: dict(clientid=data["clientid"], disabled=False, roles=sorted(data["roles"]), groups=[]) for name, data in clients.items()},
                groups={}, roles={name: gp.sorted_acls(acls) for name, acls in roles.items()}, anonymous_group=None)
    snap["clients"][SENTINEL] = dict(clientid=SENTINEL, disabled=True, roles=[], groups=[])
    return snap


def differences(actual, expected):
    """Reasons (empty = equal) comparing the broker's policy with the expected one, ignoring only the administrative principal and its role."""
    reasons = []
    if actual["defaults"] != expected["defaults"]:
        reasons.append("default ACLs differ")
    for section in ("clients", "roles"):
        a = {k: v for k, v in actual[section].items() if k != "admin" and k not in BUILT_IN_ROLES}
        e = expected[section]
        for name in sorted(set(a) | set(e)):
            if a.get(name) != e.get(name):
                reasons.append(f"{section[:-1]} {name} differs or is unexpected")
    for name, group in actual["groups"].items():      # the default anonymous group is untouched (as on the research broker); no principal may belong to any group
        if group["clients"]:
            reasons.append(f"group {name} has members")
    return reasons


def provision(admin, channel):
    roles, clients, plan_info = expected_policy()
    before = summary(admin)
    non_bootstrap = [c for c in before["clients"] if c != "admin"]
    if non_bootstrap:
        if differences(before, expected_snapshot(roles, clients)):
            raise ProvisionError("existing_policy_differs_STOP")
        return dict(result="ALREADY_PROVISIONED", **plan_info)
    # 1. default ACL decisions: all four deny
    channel.command("setDefaultACLAccess", acls=[dict(acltype=t, allow=False) for t in DEFAULT_TYPES])
    # 2. the administrative principal keeps only the Dynamic Security control entitlement
    admin_roles = {r["rolename"] for r in admin.call("getClient", username="admin")["client"].get("roles", [])}
    if DYNSEC_ROLE not in admin_roles:
        if admin.call("getRole", optional=True, rolename=DYNSEC_ROLE) is None:
            channel.command("createRole", rolename=DYNSEC_ROLE, acls=[dict(acltype="publishClientSend", topic="$CONTROL/dynamic-security/#", allow=True, priority=10),
                                                                        dict(acltype="subscribePattern", topic="$CONTROL/dynamic-security/#", allow=True, priority=10),
                                                                        dict(acltype="publishClientReceive", topic="$CONTROL/dynamic-security/#", allow=True, priority=10)])
        channel.command("addClientRole", username="admin", rolename=DYNSEC_ROLE, priority=10)
        channel.connect()                # the broker disconnects a client whose roles change
    for name in sorted(admin_roles - {DYNSEC_ROLE}):
        try:
            channel.command("removeClientRole", username="admin", rolename=name)
        except ControlUnavailable:
            pass                         # changing the administrative principal's own roles disconnects it: the effect is settled by reading on a new session
        channel.connect()
        if name in {r["rolename"] for r in admin.call("getClient", username="admin")["client"].get("roles", [])}:
            raise ProvisionError(f"admin_role_not_removed:{name}")
    # 3. roles, then clients (never a client before its roles exist)
    for name, acls in sorted(roles.items()):
        channel.command("createRole", rolename=name, acls=acls)
    for username, data in sorted(clients.items()):
        channel.command("createClient", username=username, clientid=data["clientid"], password=credential(username),
                        roles=[dict(rolename=r, priority=10) for r in sorted(data["roles"])])
    channel.command("createClient", username=SENTINEL, clientid=SENTINEL, password=credential(SENTINEL), roles=[])
    channel.command("disableClient", username=SENTINEL)
    after = summary(admin)
    problems = differences(after, expected_snapshot(roles, clients))
    if problems:
        raise ProvisionError("postcondition_mismatch:" + ";".join(problems)[:300])
    return dict(result="PROVISIONED", policy_sha256=binding_audit.policy_digest(after), **plan_info)


DRIFT_ACTIONS = ("add-operation-role", "remove-operation-role")


def drift(admin, channel, device, action, configs=CONFIGS):
    """Engineering fault injection (operator only): one out-of-band role change on a device principal, as an operator mistake would make it, so the PEP's drift detection
    can be exercised. It acts only on a broker that carries the isolation sentinel and only on a device that has an operations entitlement."""
    sentinel = admin.call("getClient", optional=True, username=SENTINEL)
    if not sentinel or not sentinel["client"].get("disabled"):
        raise ProvisionError("not_the_isolated_engineering_broker_STOP")
    registry = DeviceRegistry.load(configs / "observation" / "device_registry_v2.json")
    entry = Catalogue.from_registry(registry, ["device01", "device02"]).get(device)
    if not entry.operation_role:
        raise ProvisionError("device_has_no_operations_entitlement")
    before = {r["rolename"] for r in admin.call("getClient", username=entry.username)["client"].get("roles", [])}
    channel.command("addClientRole" if action == "add-operation-role" else "removeClientRole", username=entry.username, rolename=entry.operation_role,
                    **(dict(priority=ROLE_PRIORITY) if action == "add-operation-role" else {}))
    return dict(result="DRIFT_INJECTED", device=device, action=action, roles_before=len(before))


def operator_client(admin, channel, device, enable, configs=CONFIGS):
    """Engineering fault injection (operator only): the operator ENABLES or DISABLES a device principal, as a revocation (or its reversal) would. It acts only on a broker that
    carries the isolation sentinel and only on the two operations devices. The binding audit then reports the identity as REVOKED (disabled) or valid again; nothing here is the PEP."""
    sentinel = admin.call("getClient", optional=True, username=SENTINEL)
    if not sentinel or not sentinel["client"].get("disabled"):
        raise ProvisionError("not_the_isolated_broker_STOP")
    registry = DeviceRegistry.load(configs / "observation" / "device_registry_v2.json")
    entry = Catalogue.from_registry(registry, ["device01", "device02"]).get(device)
    before = bool(admin.call("getClient", username=entry.username)["client"].get("disabled"))
    channel.command("enableClient" if enable else "disableClient", username=entry.username)
    return dict(result="OPERATOR_ENABLED" if enable else "OPERATOR_DISABLED", device=device, disabled_before=before)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=("inspect", "provision", "verify", "drift", "operator-disable", "operator-enable"))
    parser.add_argument("--run-id")
    parser.add_argument("--host", default="broker")
    parser.add_argument("--device")
    parser.add_argument("--drift-action", choices=DRIFT_ACTIONS)
    parser.add_argument("--sentinel", choices=("engineering", "pilot"), default="engineering")
    args = parser.parse_args(argv)
    global SENTINEL
    SENTINEL = PILOT_SENTINEL if args.sentinel == "pilot" else SENTINEL
    channel = MqttControlChannel(args.host, ADMIN_CREDENTIAL)
    try:
        admin = Admin(channel)
        if args.action == "inspect":
            result = inspect(admin)
        elif args.action == "provision":
            result = provision(admin, channel)
        elif args.action == "drift":
            if not args.device or not args.drift_action:
                raise ProvisionError("drift_needs_device_and_drift_action")
            result = drift(admin, channel, args.device, args.drift_action)
        elif args.action in ("operator-disable", "operator-enable"):
            if not args.device:
                raise ProvisionError("operator_action_needs_device")
            result = operator_client(admin, channel, args.device, args.action == "operator-enable")
        else:
            roles, clients, plan_info = expected_policy()
            problems = differences(summary(admin), expected_snapshot(roles, clients))
            result = dict(verdict="PASS" if not problems else "FAIL", problems=problems, **plan_info)
        if args.run_id:
            Path("/results", f"provision_{args.action}_{args.run_id}.json").write_text(json.dumps(result, sort_keys=True, indent=1) + "\n", encoding="utf-8")
        print("ENGINEERING_PROVISION " + args.action.upper() + " " + json.dumps(result, sort_keys=True))
        return 0 if result.get("verdict", "PASS") == "PASS" else 1
    except (ProvisionError, ControlUnavailable, OSError, KeyError, ValueError) as exc:
        print(f"ENGINEERING_PROVISION_REFUSED {getattr(exc, 'code', type(exc).__name__)}: {str(exc)[:200]}", file=sys.stderr)
        return 2
    finally:
        channel.close()


if __name__ == "__main__":
    sys.exit(main())
