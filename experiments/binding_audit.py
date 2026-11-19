"""Operator-only READ-ONLY Dynamic Security audit for the Gate 5B namespace identity binding.

Establishes, for one policy snapshot, whether each registry telemetry topic can be published by
exactly its bound principal. Every command passes an explicit read-only allowlist BEFORE it can
be sent; any mutation command fails locally. A mismatch is a failed validation, never repaired.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from observation.registry import DeviceRegistry
from observation.schema import canonical

READ_ONLY_COMMANDS = frozenset({"getDefaultACLAccess", "listClients", "getClient", "listGroups", "getGroup",
                                "listRoles", "getRole", "getAnonymousGroup"})
AUDIT_SCHEMA = "azta.observation.binding_audit"


class ReadOnlyViolation(Exception):
    pass


class AuditError(Exception):
    pass


class ReadOnlyAdmin:
    """Exposes only call(); the wrapped A3 Admin's mutation helpers are unreachable through it."""
    def __init__(self, inner):
        self._inner = inner

    def call(self, command, optional=False, **fields):
        if command not in READ_ONLY_COMMANDS:
            raise ReadOnlyViolation(f"command {command!r} is not in the read-only allowlist")
        return self._inner.call(command, optional=optional, **fields)

    def close(self):
        self._inner.close()


def _names(listing, key, field):
    items = listing.get(key, []) if isinstance(listing, dict) else []
    names = [item if isinstance(item, str) else item.get(field) for item in items]
    if any(not isinstance(name, str) for name in names):
        raise AuditError(f"unparseable {key} listing")
    total = listing.get("totalCount", len(names))
    if total != len(names):
        raise AuditError(f"incomplete {key} enumeration ({len(names)} of {total})")
    return sorted(names)


def _acl(item):
    return dict(acltype=item["acltype"], topic=item.get("topic"), allow=bool(item["allow"]),
                priority=item.get("priority", -1))


def collect_snapshot(admin):
    """Read-only enumeration of every client, group, role, the anonymous group and default access."""
    defaults = sorted((dict(acltype=a["acltype"], allow=bool(a["allow"]))
                       for a in admin.call("getDefaultACLAccess")["acls"]), key=lambda a: a["acltype"])
    clients = {}
    for name in _names(admin.call("listClients", verbose=False, count=-1, offset=0), "clients", "username"):
        data = admin.call("getClient", username=name)["client"]
        clients[name] = dict(clientid=data.get("clientid"), disabled=bool(data.get("disabled", False)),
                             roles=sorted(r["rolename"] for r in data.get("roles", [])),
                             groups=sorted(g["groupname"] for g in data.get("groups", [])))
    groups = {}
    for name in _names(admin.call("listGroups", verbose=False, count=-1, offset=0), "groups", "groupname"):
        data = admin.call("getGroup", groupname=name)["group"]
        groups[name] = dict(roles=sorted(r["rolename"] for r in data.get("roles", [])),
                            clients=sorted(c["username"] for c in data.get("clients", [])))
    roles = {}
    for name in _names(admin.call("listRoles", verbose=False, count=-1, offset=0), "roles", "rolename"):
        data = admin.call("getRole", rolename=name)["role"]
        roles[name] = sorted((_acl(a) for a in data.get("acls", [])),
                             key=lambda a: (a["acltype"], str(a["topic"]), a["priority"], a["allow"]))
    anonymous = admin.call("getAnonymousGroup", optional=True)
    anonymous_group = (anonymous or {}).get("group", {}).get("groupname") if anonymous else None
    return dict(defaults=defaults, clients=clients, groups=groups, roles=roles, anonymous_group=anonymous_group)


def policy_digest(snapshot):
    return hashlib.sha256(canonical(snapshot).encode()).hexdigest()


def topic_matches(acl_filter, topic):
    """MQTT topic-filter matching (+ one level, # remaining levels incl. parent)."""
    if not isinstance(acl_filter, str) or not acl_filter:
        return False
    if topic.startswith("$") and acl_filter[0] in "+#":
        return False
    pattern, levels = acl_filter.split("/"), topic.split("/")
    for i, part in enumerate(pattern):
        if part == "#":
            return True
        if i >= len(levels) or (part != "+" and part != levels[i]):
            return False
    return len(pattern) == len(levels)


def acl_matches(acl_topic, topic, username, clientid):
    """Substitute %u/%c per principal; an unresolvable substitution is conservatively a match."""
    if not isinstance(acl_topic, str):
        return False
    if ("%u" in acl_topic and username is None) or ("%c" in acl_topic and clientid is None):
        return True
    return topic_matches(acl_topic.replace("%u", username or "").replace("%c", clientid or ""), topic)


def principals(snapshot):
    members = {}
    for group, data in snapshot["groups"].items():
        for user in data["clients"]:
            members.setdefault(user, set()).add(group)
    for username, data in sorted(snapshot["clients"].items()):
        groups = set(data["groups"]) | members.get(username, set())
        roles = set(data["roles"])
        for group in groups:
            roles |= set(snapshot["groups"].get(group, {}).get("roles", []))
        yield f"client:{username}", username, data["clientid"], roles
    anonymous = snapshot.get("anonymous_group")
    if anonymous:
        yield "anonymous", None, None, set(snapshot["groups"].get(anonymous, {}).get("roles", []))


def analyze(snapshot, registry, anonymous_listener_disabled=None):
    """Conservative: any allow publishClientSend ACL reachable from a principal makes it a holder."""
    reasons = []
    default_publish = [d for d in snapshot["defaults"] if d["acltype"] == "publishClientSend"]
    default_allow = not default_publish or any(d["allow"] for d in default_publish)
    if default_allow:
        reasons.append("default publishClientSend is not deny")
    missing_roles = sorted({role for _, _, _, roles in principals(snapshot) for role in roles} - set(snapshot["roles"]))
    if missing_roles:
        reasons.append(f"referenced roles missing from snapshot: {missing_roles}")
    devices = {}
    for entry in registry.devices:
        holders = set()
        for label, username, clientid, roles in principals(snapshot):
            for role in roles:
                if any(a["acltype"] == "publishClientSend" and a["allow"]
                       and acl_matches(a["topic"], entry.telemetry_topic, username, clientid)
                       for a in snapshot["roles"].get(role, [])):
                    holders.add(label)
        expected = f"client:{entry.username}"
        client = snapshot["clients"].get(entry.username)
        checks = dict(
            sole_holder=holders == {expected},
            bound_client_present=client is not None,
            client_id_bound=bool(client) and client["clientid"] == entry.client_id,
            expected_role_assigned=bool(client) and entry.publish_role in client["roles"],
        )
        device_reasons = [name for name, ok in checks.items() if not ok]
        extra = sorted(holders - {expected})
        if extra:
            device_reasons.append(f"other principals can publish this topic: {extra}")
        if default_allow:
            device_reasons.append("default allow makes every principal a potential publisher")
        devices[entry.device] = dict(
            telemetry_topic=entry.telemetry_topic, expected_principal=expected, holders=sorted(holders),
            bound_client_enabled=bool(client) and not client["disabled"], checks=checks,
            verdict="PASS" if not device_reasons else "FAIL", reasons=device_reasons)
    admin_publish = sorted(device for device, data in devices.items()
                           if any(h == "client:admin" for h in data["holders"]))
    if admin_publish:
        reasons.append(f"admin can publish application telemetry: {admin_publish}")
    verdict = "PASS" if not reasons and all(d["verdict"] == "PASS" for d in devices.values()) else "FAIL"
    return dict(schema=AUDIT_SCHEMA, schema_version=1, verdict=verdict, reasons=reasons,
                registry_sha256=registry.sha256, policy_sha256=policy_digest(snapshot),
                default_publish_allow=default_allow, anonymous_group=snapshot.get("anonymous_group"),
                anonymous_listener_disabled_in_config=anonymous_listener_disabled, devices=devices,
                read_only_commands=sorted(READ_ONLY_COMMANDS), mutation_performed=False)


def anonymous_disabled(config_path):
    """Static reading of the mounted broker config (configured state, not a live broker query)."""
    if not config_path or not Path(config_path).is_file():
        return None
    lines = [line.split("#", 1)[0].split() for line in Path(config_path).read_text(encoding="utf-8").splitlines()]
    values = [parts[1] for parts in lines if len(parts) == 2 and parts[0] == "listener_allow_anonymous"]
    return bool(values) and all(value == "false" for value in values)


def main(argv=None):
    from experiments.a3_policy import Admin
    from experiments.foundation_run import FoundationConfig, runtime
    from experiments.research_records import RunRecords
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--registry", default="/app/configs/observation/device_registry.json")
    parser.add_argument("--broker-config", default="/app/broker-config/mosquitto.conf")
    parser.add_argument("--output-dir", default="/results")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", args.run_id):
        print("BINDING_AUDIT_CONFIG_ERROR invalid run id", file=sys.stderr)
        return 2
    registry = DeviceRegistry.load(args.registry)
    records = RunRecords(args.output_dir, FoundationConfig(args.run_id, scenario="gate5b-binding-audit"),
                         runtime(), streams=("admin",))
    admin = None
    try:
        admin = ReadOnlyAdmin(Admin(records))
        result = analyze(collect_snapshot(admin), registry, anonymous_disabled(args.broker_config))
        result["run_id"] = args.run_id
        records.write_json("binding_audit.json", result)
        records.finish(dict(state="COMPLETE", verdict=result["verdict"], policy_sha256=result["policy_sha256"],
                            mutation_performed=False))
        print(f'BINDING_AUDIT {result["verdict"]} run_id={args.run_id} policy_sha256={result["policy_sha256"]}')
        return 0 if result["verdict"] == "PASS" else 1
    except Exception as exc:
        code = type(exc).__name__ if isinstance(exc, (AuditError, ReadOnlyViolation)) else "audit_error"
        records.finish(dict(state="INCOMPLETE", failure_code=code, mutation_performed=False))
        print(f"BINDING_AUDIT FAILED {code}", file=sys.stderr)
        return 1
    finally:
        if admin:
            admin.close()
        records.close()


if __name__ == "__main__":
    raise SystemExit(main())
