"""Policy states, the maximum-entitlement catalogue, the documented MQTT permission mapping and the minimal command plan.

States (journal section 4; docs/GATE_4_MANUAL_ENFORCEMENT.md for the broker mapping):

    FULL_ACCESS  client enabled; roles = the device's maximum entitlement (telemetry publish, plus operations publish where the device has one)
    RESTRICT     client enabled; roles = telemetry publish only (operations publication denied by the default-deny ACLs)
    QUARANTINE   client DISABLED (active session ended by the broker, reconnection rejected); roles reduced to telemetry publish

The catalogue is the ceiling: a device is never given a role that is not in its catalogue entry, a role is only (re)added after the broker's own copy of that
role was read back and equals the catalogue's exact ACL, and nothing here creates a role, edits an ACL, changes a default or touches another principal.
Devices without an operations entitlement (devices 03 to 10 of the ten-device registry) have no operations permission to remove: for them FULL_ACCESS and
RESTRICT have the same broker permissions, which is reported honestly (`permission_equivalent`), never as a restriction that was applied.

`plan()` turns a verified current state and a desired state into the smallest ordered command list: disable FIRST when quarantining (a failure after it
leaves the device quarantined, the safe side), enable LAST when un-quarantining (the device never runs with a half-restored role set), role changes between.
"""
from dataclasses import dataclass

from enforcement.errors import PepRefused

FULL_ACCESS, RESTRICT, QUARANTINE = "FULL_ACCESS", "RESTRICT", "QUARANTINE"
STATES = (FULL_ACCESS, RESTRICT, QUARANTINE)
SEVERITY = {FULL_ACCESS: 0, RESTRICT: 1, QUARANTINE: 2}
ROLE_PRIORITY = 10          # priority of every accepted A3 role membership and ACL (docs/FOUNDATION_A3.md)
ALLOWED_MUTATIONS = ("addClientRole", "removeClientRole", "enableClient", "disableClient")
ALLOWED_READS = ("getClient", "getRole", "getDefaultACLAccess")
DEFAULT_ACL_TYPES = ("publishClientSend", "publishClientReceive", "subscribe", "unsubscribe")


def _acl(kind, topic):
    return dict(acltype=kind, topic=topic, allow=True, priority=ROLE_PRIORITY)


@dataclass(frozen=True)
class Entitlement:
    device: str
    username: str
    client_id: str
    telemetry_role: str
    telemetry_topic: str
    operation_role: object = None
    operations_topic: object = None

    @property
    def max_roles(self):
        return frozenset(r for r in (self.telemetry_role, self.operation_role) if r)

    def expected_acl(self, role):
        if role == self.telemetry_role:
            return [_acl("publishClientSend", self.telemetry_topic)]
        if role == self.operation_role:
            return [_acl("publishClientSend", self.operations_topic)]
        raise PepRefused("ROLE_NOT_IN_CATALOGUE", f"{role!r} is not an entitlement of {self.device}")

    def target(self, state):
        """(role set, disabled) the broker must show for `state`."""
        if state == FULL_ACCESS:
            return self.max_roles, False
        if state == RESTRICT:
            return frozenset({self.telemetry_role}), False
        if state == QUARANTINE:
            return frozenset({self.telemetry_role}), True
        raise PepRefused("UNKNOWN_STATE", repr(state))

    @property
    def restrict_is_permission_noop(self):
        return self.operation_role is None


class Catalogue:
    def __init__(self, entries):
        entries = list(entries)
        names = [e.device for e in entries] + [e.username for e in entries]
        if len(set(names)) != len(names) or not entries:
            raise ValueError("catalogue: duplicate or empty")
        self.by_device = {e.device: e for e in entries}

    def get(self, device):
        entry = self.by_device.get(device) if isinstance(device, str) else None
        if entry is None:
            raise PepRefused("UNKNOWN_DEVICE", "the device is not in the entitlement catalogue; nothing was sent")
        return entry

    @property
    def devices(self):
        return tuple(sorted(self.by_device))

    @classmethod
    def from_registry(cls, registry, operations_devices):
        """From an observation `DeviceRegistry` (device, username, client id, telemetry topic and role) plus the explicit list of devices that hold an
        operations entitlement (`azta-<device>-operation-publish`; only device01 and device02 in the accepted policy)."""
        ops = set(operations_devices)
        entries = []
        for e in registry.devices:
            has = e.device in ops
            entries.append(Entitlement(e.device, e.username, e.client_id, e.publish_role, e.telemetry_topic,
                                       f"azta-{e.device}-operation-publish" if has else None,
                                       f"azta/devices/{e.device}/operations" if has else None))
        unknown = ops - {e.device for e in registry.devices}
        if unknown:
            raise ValueError(f"operations devices not in the registry: {sorted(unknown)}")
        return cls(entries)


@dataclass(frozen=True)
class Observed:
    """The broker's own record of one device principal (never a belief)."""
    username: str
    client_id: object
    disabled: bool
    roles: tuple          # ((rolename, priority), ...) sorted
    groups: tuple

    @property
    def role_names(self):
        return frozenset(name for name, _ in self.roles)

    def digest(self):
        return dict(username=self.username, client_id=self.client_id, disabled=self.disabled, roles=[list(r) for r in self.roles], groups=list(self.groups))


@dataclass(frozen=True)
class Classification:
    consistent: bool                 # the record is within the catalogue's ceiling and a recognised shape
    states: frozenset                # policy states whose broker permissions this record has (two for permission-equivalent devices)
    kind: str                        # EXACT | PARTIAL_QUARANTINE | INCONSISTENT
    problems: tuple = ()


def classify(observed, entitlement):
    problems = []
    if observed.client_id != entitlement.client_id:
        problems.append("CLIENT_ID_NOT_BOUND_TO_THE_CATALOGUE")
    if observed.groups:
        problems.append("GROUP_MEMBERSHIP_PRESENT")
    if not observed.role_names <= entitlement.max_roles:
        problems.append("ROLE_ABOVE_THE_MAXIMUM_ENTITLEMENT")
    if entitlement.telemetry_role not in observed.role_names:
        problems.append("TELEMETRY_ROLE_ABSENT")
    if any(priority != ROLE_PRIORITY for _, priority in observed.roles):
        problems.append("UNEXPECTED_ROLE_PRIORITY")
    if problems:
        return Classification(False, frozenset(), "INCONSISTENT", tuple(problems))
    matching = frozenset(s for s in STATES if entitlement.target(s) == (observed.role_names, observed.disabled))
    if matching:
        return Classification(True, matching, "EXACT")
    if observed.disabled:   # disabled but an operations role is still attached: contained, but not the canonical quarantine shape
        return Classification(True, frozenset(), "PARTIAL_QUARANTINE", ("DISABLED_WITH_OPERATIONS_ROLE",))
    return Classification(False, frozenset(), "INCONSISTENT", ("UNRECOGNISED_ROLE_SET",))


def plan(observed, desired, entitlement):
    """Ordered minimal command list [(command, fields)] from the verified current record to `desired`. Raises PepRefused if the record is not plannable."""
    cls = classify(observed, entitlement)
    if not cls.consistent:
        raise PepRefused("STATE_INCONSISTENT_STOP", ",".join(cls.problems))
    roles, disabled = entitlement.target(desired)
    current = observed.role_names
    commands = []
    if disabled and not observed.disabled:
        commands.append(("disableClient", dict(username=entitlement.username)))
    for role in sorted(current - roles):
        commands.append(("removeClientRole", dict(username=entitlement.username, rolename=role)))
    for role in sorted(roles - current):
        commands.append(("addClientRole", dict(username=entitlement.username, rolename=role, priority=ROLE_PRIORITY)))
    if not disabled and observed.disabled:
        commands.append(("enableClient", dict(username=entitlement.username)))
    return commands


def effect_present(command, fields, observed):
    """Has the broker already got the effect of `command`? Used to settle an UNKNOWN outcome by reading state, never by assuming."""
    if command == "disableClient":
        return observed.disabled
    if command == "enableClient":
        return not observed.disabled
    if command == "addClientRole":
        return fields["rolename"] in observed.role_names
    if command == "removeClientRole":
        return fields["rolename"] not in observed.role_names
    raise PepRefused("COMMAND_NOT_ALLOWED", command)
