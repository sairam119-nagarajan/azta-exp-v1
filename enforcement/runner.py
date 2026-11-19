"""Persistent enforcement runner: consumes decision records in order, one device stream at a time, and hands authorized changes to the PEP exactly once.

    decision JSONL (append-only, e.g. the Shadow pipeline's `decisions.jsonl`, or a TEST_ONLY scenario file)
      -> complete lines only, in file order (so per-device order is preserved), the byte cursor and a rolling SHA-256 of the consumed prefix are recorded in the audit log
      -> staleness check against an explicit maximum age, duplicate check by evidence id (survives restarts)
      -> the guard for the record's schema (operational guard for real decisions, TEST_ONLY guard for synthetic engineering records; a record is never offered to the other)
      -> persistence filter (explicit confirmation windows; missing or stale evidence holds and resets)
      -> PEP `apply` (verified outcome) -> audit entries with every processing timestamp.

Restart: a new runner over the same audit log resumes at the recorded cursor after verifying the consumed prefix byte for byte, skips evidence ids already handled, and reconciles the
broker with the recorded belief before processing anything new. Shutdown: `stop()` finishes the record in flight; a crash between the PEP outcome and the `RECORD_HANDLED` entry
is safe because the PEP's request id is deterministic and a repeated request returns the recorded outcome or re-plans from the broker's real state (no duplicate mutation).
A real (operational) record is refused today with OPERATIONAL_APPROVALS_MISSING for every record; that refusal is counted and logged, and the broker is never touched.
"""
import hashlib
import json
from pathlib import Path

from enforcement.audit import StateTable
from enforcement.errors import AuditIntegrityError, ControlUnavailable, EnforcementError, GuardRefused, PepRefused
from enforcement.guard import REAL_DECISION_SCHEMA, TEST_ONLY_SCHEMA
from enforcement.model import FULL_ACCESS, STATES
from enforcement.pep import APPLIED, NOOP
from enforcement.policy import DecisionFilter

RUNNER_VERSION = "enforcement-runner-1"


class JsonlSource:
    """Complete lines of an append-only file from a byte offset; a shrunken file or a changed consumed prefix is an integrity failure."""

    def __init__(self, path):
        self.path = Path(path)

    def read_from(self, offset, expected_prefix_sha256):
        blob = self.path.read_bytes()
        if len(blob) < offset or hashlib.sha256(blob[:offset]).hexdigest() != expected_prefix_sha256:
            raise AuditIntegrityError("SOURCE_PREFIX_CHANGED", "the consumed part of the decision file is not what the audit log recorded")
        end = blob.rfind(b"\n") + 1                        # only complete lines
        lines, position = [], offset
        while position < end:
            nxt = blob.index(b"\n", position)
            lines.append((blob[position:nxt], nxt + 1))
            position = nxt + 1
        return lines, blob


class EnforcementRunner:
    def __init__(self, *, source, pep, table, filter_, guards, clock, max_decision_age_ns, policy_changes=None, policy_change_tolerance_ns=None):
        """guards: {schema: guard} - the operational guard for REAL_DECISION_SCHEMA, the TEST_ONLY guard for TEST_ONLY_SCHEMA (either may be absent).

        policy_changes (Gate 6B, F1; optional, both arguments or neither): a read-only feed of the instants at which a PEP log shows a verified change of one device's policy (`poll()`,
        `last_change_ns(device)`; OSError = unreadable now, ValueError = broken chain). A decision made before the latest such change of ITS device describes an earlier policy
        generation and is HELD, whatever it proposes (`DECISION_PREDATES_POLICY_CHANGE`, with the confirmation run reset). `policy_change_tolerance_ns` is the explicit
        cross-clock allowance between the decision's stamp and the PEP's stamp. Absent (the default) = the baseline behaviour."""
        if type(max_decision_age_ns) is not int or max_decision_age_ns <= 0:
            raise ValueError("max_decision_age_ns must be an explicit positive integer")
        if set(guards) - {REAL_DECISION_SCHEMA, TEST_ONLY_SCHEMA}:
            raise ValueError("unknown guard schema")
        self.source, self.pep, self.table, self.filter, self.guards, self.clock = source, pep, table, filter_, dict(guards), clock
        self.max_age = max_decision_age_ns
        if (policy_changes is None) != (policy_change_tolerance_ns is None):
            raise ValueError("policy_changes and policy_change_tolerance_ns are given together or not at all")
        if policy_changes is not None and (type(policy_change_tolerance_ns) is not int or policy_change_tolerance_ns < 0):
            raise ValueError("policy_change_tolerance_ns must be an explicit non-negative integer")
        self.policy_changes, self.policy_change_tolerance_ns = policy_changes, policy_change_tolerance_ns
        self.counts = {}
        self._stop = False

    def stop(self):
        self._stop = True

    def _count(self, key):
        self.counts[key] = self.counts.get(key, 0) + 1

    def start(self):
        """Attest the environment, observe the baseline, and reconcile every device against the recorded belief."""
        if self.pep.environment is None:
            self.pep.attest_environment()
        self.pep.establish_baseline()
        for device in self.pep.catalogue.devices:
            if device in self.table.believed:
                self.pep.reconcile(device)
        self.table.record("RUNNER_STARTED", runner_version=RUNNER_VERSION, environment=self.pep.environment, cursor=self.table.cursor)

    def _current_label(self, device):
        """The device's current policy label from the broker record of the last observation; None when unknown or ambiguous."""
        last = self.table.verified.get(device)
        if last is None:
            return None
        states = last.get("states") or []
        if not states:
            return None
        entry = self.pep.catalogue.get(device)
        belief = self.table.believed.get(device)
        if belief in states:
            return belief
        return min(states, key=lambda s: STATES.index(s)) if len(states) == 1 or entry.restrict_is_permission_noop else None

    def _refresh_if_held_as_already_enforced(self, request):
        """A restrictive request for a state the layer BELIEVES is already enforced would be held as ALREADY_IN_STATE. An administrative RESTORE made by another process (its own audit file,
        so this log keeps a single writer) leaves that belief stale and a continuing anomaly would never be contained again, so the broker is read first (read-only). An unreadable broker
        changes nothing: the request is judged on the belief as before."""
        if request.desired_state == FULL_ACCESS or self._current_label(request.device) != request.desired_state:
            return
        try:
            self.pep.refresh(request.device)
        except (ControlUnavailable, PepRefused):
            self._count("refresh_unavailable")

    def _predates_policy_change(self, device, decision_ns):
        """None, or (reason, detail) when this decision cannot be acted on because the device's policy changed after it was made (or the feed cannot say right now)."""
        try:
            self.policy_changes.poll()
        except OSError:
            return "POLICY_CHANGE_FEED_UNREADABLE", {}
        except ValueError as exc:
            raise AuditIntegrityError("PEP_LOG_CHAIN_BROKEN", str(exc)[:160]) from None
        last = self.policy_changes.last_change_ns(device)
        if last is not None and decision_ns < last + self.policy_change_tolerance_ns:
            return "DECISION_PREDATES_POLICY_CHANGE", dict(policy_change_ns=last, tolerance_ns=self.policy_change_tolerance_ns)
        return None

    def process_available(self):
        lines, blob = self.source.read_from(self.table.cursor["offset"], self.table.cursor["prefix_sha256"])
        handled = 0
        for raw, end in lines:
            if self._stop:
                break
            self._handle(raw)
            prefix = hashlib.sha256(blob[:end]).hexdigest()
            self.table.record("CURSOR", offset=end, prefix_sha256=prefix)
            handled += 1
        return handled

    def _handle(self, raw):
        seen_ns, seen_mono = self.clock.utc_ns(), self.clock.monotonic_ns()
        timing = dict(record_seen_utc_ns=seen_ns)
        try:
            record = json.loads(raw.decode("utf-8"), parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
            evidence_id = record["evidence_id"] if isinstance(record, dict) else None
        except (ValueError, UnicodeDecodeError, KeyError):
            record, evidence_id = None, None
        if not isinstance(evidence_id, str):
            self._finish("MALFORMED_RECORD", None, None, timing, reason="the line is not a decision record")
            return
        if evidence_id in self.table.decided:
            self._count("duplicate_skipped")
            self.table.record("RECORD_SKIPPED", evidence_id=evidence_id, reason="DUPLICATE_EVIDENCE_ID")
            return
        schema = record.get("schema")
        device = record.get("device") or ((record.get("behavior") or {}).get("window_ref") or {}).get("device")
        decision_ns = record.get("decision_ns")
        timing["decision_ns"] = decision_ns
        guard = self.guards.get(schema)
        if guard is None:
            self._finish("REFUSED", evidence_id, device, timing, reason="NO_GUARD_FOR_THIS_RECORD_TYPE" if schema in (REAL_DECISION_SCHEMA, TEST_ONLY_SCHEMA) else
                         "UNKNOWN_RECORD_SCHEMA", schema=schema)
            return
        if schema == TEST_ONLY_SCHEMA and not isinstance(decision_ns, int):
            self._finish("REFUSED", evidence_id, device, timing, reason="DECISION_INSTANT_MISSING")
            return
        if isinstance(decision_ns, int) and seen_ns - decision_ns > self.max_age:
            self.filter.observe_missing(device)
            self._finish("HELD", evidence_id, device, timing, reason="STALE_DECISION", age_ns=seen_ns - decision_ns)
            return
        if isinstance(decision_ns, int) and decision_ns - seen_ns > self.max_age:
            self.filter.observe_missing(device)
            self._finish("HELD", evidence_id, device, timing, reason="DECISION_FROM_THE_FUTURE")
            return
        try:
            request = guard.authorize(record)
        except GuardRefused as exc:
            self.filter.observe_missing(device) if isinstance(device, str) else None
            claimed = (((record.get("annotations") or {}).get("decision_pipeline") or {}).get("route") or {}).get("device")
            self._finish("REFUSED", evidence_id, device, timing, reason=exc.code, detail=str(exc)[:160],
                         **(dict(claimed_device=claimed[:128]) if isinstance(claimed, str) else {}))     # a claim recorded for audit only; it is never used to act
            return
        device = request.device         # from here on the audit names the device the GUARD confirmed (a hard identity-gate record carries no device field of its own)
        timing["guard_done_utc_ns"] = self.clock.utc_ns()
        if self.policy_changes is not None and isinstance(decision_ns, int):
            held = self._predates_policy_change(device, decision_ns)
            if held is not None:
                self.filter.observe_missing(device)
                self._finish("HELD", evidence_id, device, timing, reason=held[0], **held[1])
                return
        recorded = self.table.outcomes.get(request.request_id)
        if recorded is not None:        # the PEP already acted on this exact request before a crash or restart: its recorded outcome stands and nothing is repeated
            self._finish(recorded["status"], evidence_id, device, timing, request_id=request.request_id, origin=request.origin, desired_state=request.desired_state,
                         reason="OUTCOME_RECOVERED_AFTER_RESTART")
            return
        self._refresh_if_held_as_already_enforced(request)
        verdict = self.filter.observe(request.device, request.desired_state, self._current_label(request.device))
        if verdict["action"] != "REQUEST":
            self._finish("HELD" if verdict["action"] == "HOLD" else "CONFIRMING", evidence_id, device, timing, reason=verdict.get("reason"),
                         confirmations=verdict.get("confirmations"), needed=verdict.get("needed"))
            return
        self._deliver(request, evidence_id, device, timing, decision_ns, record)

    def _deliver(self, request, evidence_id, device, timing, decision_ns, record):
        """Hand one confirmed request to the PEP. `enforcement.authority.AuthorityRunner` puts its authority gate in front of this."""
        timing["pep_start_mono_ns"] = self.clock.monotonic_ns()
        try:
            outcome = self.pep.apply(request)
        except (PepRefused, EnforcementError) as exc:
            timing["pep_end_mono_ns"] = self.clock.monotonic_ns()
            self._finish("PEP_REFUSED", evidence_id, device, timing, reason=exc.code)
            return
        timing["pep_end_mono_ns"] = self.clock.monotonic_ns()
        timing["decision_to_pep_end_ns"] = (self.clock.utc_ns() - decision_ns) if isinstance(decision_ns, int) else None
        self._finish(outcome["status"], evidence_id, device, timing, request_id=request.request_id, origin=request.origin, desired_state=request.desired_state,
                     reason=outcome.get("reason"))

    def _finish(self, disposition, evidence_id, device, timing, **fields):
        self._count(disposition)
        self.table.record("RECORD_HANDLED", evidence_id=evidence_id if evidence_id else f"unidentified-{len(self.table.log.entries) + 1}", device=device,
                          disposition=disposition, timing=timing, **fields)
