"""PEP adapter: applies one authorized state change to ONE device principal through Mosquitto Dynamic Security, and verifies what the broker actually shows.

What it does for every request (`apply`):
  1. accepts only an `AuthorizedRequest` minted by a guard, checks its origin against the environment it attested (TEST_ONLY needs the isolated engineering broker),
     refuses an unknown device, an unauthorized de-escalation and a re-used request id with different content; a repeated identical request returns the recorded outcome;
  2. READS the device's real broker record (getClient) and the exact ACLs of its catalogue roles (getRole); anything outside the catalogue's ceiling (extra role, group,
     other client id, changed ACL, changed default) stops the request as STATE_INCONSISTENT_STOP: nothing is "fixed" and nothing is sent;
  3. plans the minimal ordered commands (`model.plan`) from only four verbs (addClientRole, removeClientRole, enableClient, disableClient), always naming that one catalogue
     principal and only catalogue roles; no role, ACL, default, password or other client can be touched (a hard allow-list inside `_send`);
  4. sends each command, treating a transport failure or a missing response as UNKNOWN and settling it by reading the broker's state (retry only if the effect is
     absent, bounded), and re-reads the broker after the last command;
  5. records request, plan, every command with its correlation id and result, the before and after broker records and the outcome in the hash-chained audit log.

Outcomes are honest: APPLIED_VERIFIED only when the final broker record has the target permissions; NOOP_ALREADY_IN_STATE when the broker already showed them (nothing sent);
PARTIAL_UNVERIFIED when some commands took effect and the final record is an intermediate one (the device is flagged for reconciliation); FAILED_UNCHANGED_VERIFIED when
commands failed and the broker record is verifiably unchanged; UNVERIFIED_UNKNOWN when the broker could not be read to settle it. It never reports success it did not observe.
`restrict_is_permission_noop` devices (no operations entitlement) report RESTRICT as `permission_equivalent` to FULL_ACCESS: no restriction was applied, and it says so.
"""
import json

from enforcement import model
from enforcement.audit import StateTable
from enforcement.errors import ControlUnavailable, PepRefused
from enforcement.guard import AuthorizedRequest, digest_of
from enforcement.model import ALLOWED_MUTATIONS, ALLOWED_READS, FULL_ACCESS, QUARANTINE, RESTRICT, SEVERITY, Observed

PEP_VERSION = "enforcement-pep-1"
SENTINEL = "azta-eng-isolation-sentinel"      # a disabled, role-less principal that exists ONLY on the isolated engineering broker
PILOT_SENTINEL = "azta-pilot-isolation-sentinel"   # a disabled, role-less principal that exists ONLY on the dedicated isolated PILOT broker (the one target an operational pilot may enforce on)
ENV_ISOLATED, ENV_UNMARKED, ENV_PILOT = "ENGINEERING_ISOLATED", "UNMARKED", "PILOT_ISOLATED"
APPLIED, NOOP, PARTIAL, FAILED_UNCHANGED, UNKNOWN = ("APPLIED_VERIFIED", "NOOP_ALREADY_IN_STATE", "PARTIAL_UNVERIFIED", "FAILED_UNCHANGED_VERIFIED",
                                                     "UNVERIFIED_UNKNOWN")


class DynSecPEP:
    def __init__(self, channel, catalogue, table, *, clock, max_attempts):
        if type(max_attempts) is not int or not 1 <= max_attempts <= 5:
            raise ValueError("max_attempts must be an explicit integer between 1 and 5")
        self.channel, self.catalogue, self.table, self.clock, self.max_attempts = channel, catalogue, table, clock, max_attempts
        self.environment = None
        self.needs_reconcile = set()

    # ------------------------------------------------------------------------------------------------------------- transport
    def _send(self, command, **fields):
        if command not in ALLOWED_MUTATIONS and command not in ALLOWED_READS:
            raise PepRefused("COMMAND_NOT_ALLOWED", command)
        return self.channel.command(command, **fields)

    def _read(self, command, **fields):
        if command not in ALLOWED_READS:
            raise PepRefused("COMMAND_NOT_ALLOWED", command)
        return self.channel.command(command, **fields)

    # ----------------------------------------------------------------------------------------------------------- observation
    def observe(self, device):
        """The broker's own record of the device principal (raises ControlUnavailable when it cannot be read)."""
        entry = self.catalogue.get(device)
        response = self._read("getClient", username=entry.username)
        if not response["success"]:
            raise PepRefused("PRINCIPAL_NOT_FOUND", entry.username)
        client = response["data"]["client"]
        roles = tuple(sorted((r["rolename"], r.get("priority", -1)) for r in client.get("roles", [])))
        return Observed(client["username"], client.get("clientid"), bool(client.get("disabled", False)), roles, tuple(sorted(g["groupname"] for g in client.get("groups", []))))

    def verify_role(self, entitlement, role):
        response = self._read("getRole", rolename=role)
        if not response["success"]:
            raise PepRefused("ROLE_NOT_FOUND", role)
        acls = sorted(({k: a[k] for k in ("acltype", "topic", "allow", "priority")} for a in response["data"]["role"].get("acls", [])),
                      key=lambda a: (a["acltype"], a["topic"], a["priority"], a["allow"]))
        if acls != entitlement.expected_acl(role):
            raise PepRefused("ROLE_ACL_DIFFERS_FROM_THE_CATALOGUE", f"{role}: not re-attached and not modified")

    def verify_defaults(self):
        response = self._read("getDefaultACLAccess")
        acls = response["data"].get("acls", []) if response["success"] else []
        if {a["acltype"] for a in acls} != set(model.DEFAULT_ACL_TYPES) or any(a["allow"] for a in acls):
            raise PepRefused("DEFAULT_ACL_NOT_ALL_DENY", "the broker's default ACL decisions are not all deny; nothing is enforced on this broker")

    def attest_environment(self):
        """Read the isolation sentinel. TEST_ONLY requests are acted on only when it is present, disabled and role-less."""
        def marker(name):
            response = self._read("getClient", username=name)
            client = response["data"].get("client", {}) if response["success"] else None
            return bool(client) and client.get("disabled") is True and not client.get("roles") and not client.get("groups")
        eng, pilot = marker(SENTINEL), marker(PILOT_SENTINEL)
        if eng and pilot:
            raise PepRefused("ENVIRONMENT_AMBIGUOUS", "the broker carries both the engineering and the pilot marker")
        self.environment = ENV_ISOLATED if eng else ENV_PILOT if pilot else ENV_UNMARKED
        self.table.record("ENVIRONMENT_ATTESTED", environment=self.environment, pep_version=PEP_VERSION)
        return self.environment

    def establish_baseline(self):
        """Observe every catalogued device and the defaults; record them. Does not mutate."""
        self.verify_defaults()
        out = {}
        for device in self.catalogue.devices:
            entry = self.catalogue.get(device)
            observed = self.observe(device)
            cls = model.classify(observed, entry)
            for role in observed.role_names & entry.max_roles:
                self.verify_role(entry, role)
            self.table.record("BASELINE_OBSERVED", device=device, observed=observed.digest(), shape=cls.kind, states=sorted(cls.states), problems=list(cls.problems))
            out[device] = (observed, cls)
        return out

    def reconcile(self, device):
        """Compare the broker with what the layer believes. Never mutates; a mismatch is recorded as drift (the belief is dropped)."""
        entry = self.catalogue.get(device)
        observed = self.observe(device)
        cls = model.classify(observed, entry)
        believed = self.table.believed.get(device)
        drift = believed is not None and believed not in cls.states
        self.table.record("RECONCILIATION", device=device, observed=observed.digest(), shape=cls.kind, states=sorted(cls.states), believed=believed, drift=drift)
        if drift:
            self.needs_reconcile.add(device)
        return dict(device=device, shape=cls.kind, states=sorted(cls.states), believed=believed, drift=drift)

    def refresh(self, device):
        """Read-only: the broker's state NOW, recorded as an OBSERVED entry (phase `refresh`), so a long-running service judges a request against the broker and not against a belief that an
        out-of-band administrative RESTORE (another process, its own audit file) has made stale. A belief the broker contradicts is dropped, exactly as `reconcile` does. Never mutates."""
        entry = self.catalogue.get(device)
        observed = self.observe(device)
        cls = model.classify(observed, entry)
        self.table.record("OBSERVED", device=device, phase="refresh", request_id=None, observed=observed.digest(), shape=cls.kind, states=sorted(cls.states))
        believed = self.table.believed.get(device)
        if believed is not None and believed not in cls.states:
            self.table.record("RECONCILIATION", device=device, observed=observed.digest(), shape=cls.kind, states=sorted(cls.states), believed=believed, drift=True)
            self.needs_reconcile.add(device)
        return cls

    # ---------------------------------------------------------------------------------------------------------------- apply
    def _check_request(self, request):
        if type(request) is not AuthorizedRequest:
            raise PepRefused("REQUEST_NOT_AUTHORIZED", "only an AuthorizedRequest minted by a guard is acted on")
        if request.origin == "TEST_ONLY" and self.environment != ENV_ISOLATED:
            raise PepRefused("TEST_ONLY_REQUIRES_THE_ISOLATED_BROKER", "the environment was not attested as the isolated engineering broker")
        if request.origin == "OPERATIONAL" and self.environment == ENV_ISOLATED:
            raise PepRefused("OPERATIONAL_REQUEST_ON_THE_ENGINEERING_BROKER", "operational requests are not accepted by the isolated engineering broker")
        if self.environment is None:
            raise PepRefused("ENVIRONMENT_NOT_ATTESTED", "attest_environment() must run first")
        self.catalogue.get(request.device)

    def apply(self, request):
        self._check_request(request)
        entry = self.catalogue.get(request.device)
        digest = request.content_digest()
        previous = self.table.requests.get(request.request_id)
        if previous is not None:
            if previous != digest:
                raise PepRefused("REQUEST_ID_REUSED_WITH_DIFFERENT_CONTENT", request.request_id)
            stored = self.table.outcomes.get(request.request_id)
            if stored is not None:
                return dict(stored, duplicate=True)
        else:
            self.table.record("REQUEST_RECEIVED", request_id=request.request_id, request_digest=digest, device=request.device, desired_state=request.desired_state,
                              request_kind=request.kind, origin=request.origin, evidence_ref=request.evidence_ref, authorization=request.authorization)
        started = self.clock.monotonic_ns()
        try:
            outcome = self._apply(request, entry)
        except PepRefused as exc:
            outcome = self._outcome(request, "REFUSED", reason=exc.code, detail=str(exc)[:200])
        except ControlUnavailable as exc:
            outcome = self._outcome(request, UNKNOWN, reason=exc.code, detail="the broker could not be read or reached")
        outcome["pep_processing_ns"] = self.clock.monotonic_ns() - started
        self.table.record("OUTCOME", **outcome)
        return outcome

    def _outcome(self, request, status, **fields):
        return dict(request_id=request.request_id, device=request.device, desired_state=request.desired_state, origin=request.origin, request_kind=request.kind, status=status, **fields)

    def _apply(self, request, entry):
        self.verify_defaults()
        before = self.observe(request.device)
        cls = model.classify(before, entry)
        if not cls.consistent:
            raise PepRefused("STATE_INCONSISTENT_STOP", ",".join(cls.problems))
        self.table.record("OBSERVED", device=request.device, phase="before", request_id=request.request_id, observed=before.digest(), shape=cls.kind, states=sorted(cls.states))
        current = min(cls.states, key=SEVERITY.get) if cls.states else None
        if current is not None and request.desired_state in cls.states:
            return self._outcome(request, NOOP, current_states=sorted(cls.states), permission_equivalent=self._equivalence(entry, request.desired_state, cls),
                                 commands=0)
        self._check_transition(request, cls, current)
        commands = model.plan(before, request.desired_state, entry)
        self.table.record("PLAN", request_id=request.request_id, device=request.device, commands=[c for c, _ in commands])
        for role in sorted((before.role_names & entry.max_roles) | {f["rolename"] for c, f in commands if c == "addClientRole"}):
            self.verify_role(entry, role)           # attached roles and any role about to be re-attached must still equal the catalogue's exact ACL
        executed, failures = [], []
        for command, fields in commands:
            result = self._execute(request, entry, command, fields)
            executed.append(result)
            if result["settled"] != "EFFECT_PRESENT":
                failures.append(result)
                break
        try:
            after = self.observe(request.device)
        except (ControlUnavailable, PepRefused):
            return self._outcome(request, UNKNOWN, reason="POST_STATE_UNREADABLE", commands=executed)
        after_cls = model.classify(after, entry)
        self.table.record("OBSERVED", device=request.device, phase="after", request_id=request.request_id, observed=after.digest(), shape=after_cls.kind,
                          states=sorted(after_cls.states))
        equivalence = self._equivalence(entry, request.desired_state, after_cls)
        if after_cls.consistent and request.desired_state in after_cls.states:
            self.needs_reconcile.discard(request.device)
            return self._outcome(request, APPLIED, final_states=sorted(after_cls.states), permission_equivalent=equivalence, commands=executed)
        self.needs_reconcile.add(request.device)
        if after == before:
            return self._outcome(request, FAILED_UNCHANGED, reason="COMMAND_FAILED", commands=executed, final_states=sorted(after_cls.states))
        return self._outcome(request, PARTIAL, reason="INTERMEDIATE_STATE", commands=executed, final_kind=after_cls.kind, final_states=sorted(after_cls.states))

    @staticmethod
    def _equivalence(entry, desired, cls):
        return bool(desired == RESTRICT and entry.restrict_is_permission_noop and FULL_ACCESS in cls.states)

    def _check_transition(self, request, cls, current):
        if current is None:        # a partially contained device (disabled with an operations role): only a move toward quarantine or an explicit restore is plannable
            if request.desired_state != QUARANTINE and request.kind != "RESTORE":
                raise PepRefused("PARTIAL_STATE_NEEDS_RESTORE_OR_QUARANTINE", "reconcile first; only QUARANTINE or an explicit RESTORE is accepted from this state")
            return
        less = SEVERITY[request.desired_state] < SEVERITY[current]
        if request.kind == "RESTORE":
            return
        if less and not request.deescalation_authorized:
            raise PepRefused("DEESCALATION_NOT_AUTHORIZED", f"{current} -> {request.desired_state} needs explicit authorization or an administrative RESTORE")
        if current == QUARANTINE and request.desired_state == FULL_ACCESS:
            raise PepRefused("QUARANTINE_TO_FULL_ACCESS_NEEDS_RESTORE", "leaving quarantine for full access is the administrative RESTORE, never a decision")

    def _execute(self, request, entry, command, fields):
        correlation = f"{request.request_id}:{command}"
        record = dict(command=command, rolename=fields.get("rolename"), attempts=0, settled=None, last=None)
        for attempt in range(1, self.max_attempts + 1):
            record["attempts"] = attempt
            self.table.record("COMMAND_SENT", request_id=request.request_id, device=request.device, command=command, rolename=fields.get("rolename"), attempt=attempt,
                              correlation=correlation)
            try:
                response = self._send(command, **fields)
                self.table.record("COMMAND_RESULT", request_id=request.request_id, device=request.device, command=command, attempt=attempt, success=response["success"],
                                  error=(response["error"] or "")[:80] if not response["success"] else None)
                record["last"] = "SUCCESS" if response["success"] else "ERROR_RESPONSE"
            except ControlUnavailable as exc:
                self.table.record("COMMAND_RESULT", request_id=request.request_id, device=request.device, command=command, attempt=attempt, success=None, error=exc.code)
                record["last"] = "UNKNOWN_" + exc.code
                response = None
            # settle by reading the broker: success is claimed only from what it shows
            try:
                observed = self.observe(request.device)
            except (ControlUnavailable, PepRefused):
                record["settled"] = "UNREADABLE"
                continue
            if model.effect_present(command, fields, observed):
                record["settled"] = "EFFECT_PRESENT"
                return record
            record["settled"] = "EFFECT_ABSENT"
            if response is not None:       # a clean rejection from the broker is not retried blindly
                return record
        return record
