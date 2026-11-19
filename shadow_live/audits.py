"""Live read-only broker-policy audits: the identity evidence of a live session, read as the audit runs produce them.

The audits are the ONLY source of identity evidence (a publisher's or payload's claim never is). They are produced by the separately authorized
read-only audit tool as `<run>-audit-<stage>/{binding_audit.json,run_summary.json}` (stage `pre`, periodic `p01`, `p02`, ..., `post`); this module
holds no broker credential and runs no audit, it only follows their output. Stages are probed by EXACT name in order (the raw root is never listed).

An audit becomes usable evidence only if (each is tested):
  * the run summary (the audit tool writes it LAST, atomically) exists and is COMPLETE with pinned capture instants (`utc_start`/`utc_end`), and the
    record parses: until the summary exists an audit is simply not available yet, never guessed at; an audit that ended INCOMPLETE is refused
    permanently so that it cannot block the later stages;
  * the summary names exactly this run and stage, and the record is the read-only binding-audit schema that performed no mutation for the pinned
    registry; anything else is refused permanently and visibly (the session continues on the previous evidence until it ages out, which the unchanged
    engine bounds by its freshness rule: nothing is ever extended);
  * its nominal capture end is not in the future of this host's clock (even inside tolerance, it waits until no longer nominally in the future)
    and it does not overlap or precede the previous accepted audit;
  * a record whose policy digest differs from the declared baseline is STILL used (it states the broker's current authorization, and a FAIL verdict
    must never be ignored) but is flagged, because a changed policy during a Shadow session is itself a finding.
Freshness itself is not decided here: the unchanged engine measures the age of the latest completed audit from its capture START at every decision.
Once accepted, the two files are re-hashed at every poll; any change is a fatal integrity failure.
"""
from dataclasses import dataclass
import hashlib
import json

from shadow_feed import reader
from shadow_live.errors import LiveIntegrityFailure, LiveRefused
from trust.errors import ProducerRefused
from trust.identity import AUDIT_SCHEMA
from trust.producer import audit_snapshot_from_artifacts
from trust.timeline import capture_interval_ns

PROVENANCE = "BROKER_POLICY_AUDIT"
MAX_PERIODIC = 99


def _sha(blob):
    return hashlib.sha256(blob).hexdigest()


class _AuditUnreadable(Exception):
    """An audit file exists but cannot be read RIGHT NOW (a sharing violation, an antivirus lock). It is never mistaken for a missing or changed file:
    the poll records it (once per distinct failure) and the next poll retries."""

    def __init__(self, stage, name, error):
        super().__init__(f"{stage}/{name}: {error}")
        self.stage, self.name, self.error = stage, name, error


@dataclass(frozen=True)
class AcceptedAudit:
    stage: str
    ref: str
    snapshot: object
    record_sha256: str
    summary_sha256: str
    policy_sha256: object
    policy_matches_baseline: bool


class LiveAuditSource:
    def __init__(self, plan, *, clock, barrier=None):
        """`barrier` (Gate 6B, F1) is an optional read-only feed of the instants at which the PEP verified a change of one device's broker policy: `poll()` returns new change
        dicts (device, instant_ns, status, desired_state, request_kind, log, seq, entry_sha256), raising an OSError when a log cannot be read now and a ValueError when its hash
        chain is broken. With it, identity evidence for a device is admissible only if its audit capture STARTED at or after that device's latest policy change plus the declared
        clock tolerance (see `snapshots_for`). Without it (None) nothing changes: every accepted audit is usable for every device, exactly as before."""
        self.plan, self.clock, self.barrier = plan, clock, barrier
        self._accepted, self._decided, self._flagged_future = [], set(), set()
        self._paths = {}
        self._notes, self._last_errors = [], {}
        self._change_ns, self._seen_changes, self._feed_error = {}, set(), None

    # ---------------------------------------------------------------------------------------------------------------- files
    def ref(self, stage):
        return f"{self.plan.run_id}-audit-{stage}"

    def _stage_paths(self, stage):
        if stage not in self._paths:
            base = self.ref(stage)
            self._paths[stage] = tuple(reader.safe_path(self.plan.evidence_root, f"{base}/{name}") for name in ("binding_audit.json", "run_summary.json"))
        return self._paths[stage]

    def _read(self, stage, path):
        """The file's bytes, None when it does not exist, or `_AuditUnreadable` when it exists but cannot be read now."""
        try:
            blob = path.read_bytes()
        except FileNotFoundError:
            blob = None
        except OSError as exc:
            code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
            raise _AuditUnreadable(stage, path.name, f"{exc.__class__.__name__}:{code}" if code else exc.__class__.__name__) from None
        self._last_errors.pop((stage, path.name), None)
        return blob

    def _note_error(self, exc):
        """One AUDIT_READ_ERROR event per distinct failure: the same failure repeating at every poll is recorded once."""
        if self._last_errors.get((exc.stage, exc.name)) != exc.error:
            self._notes.append(dict(kind="AUDIT_READ_ERROR", stage=exc.stage, ref=self.ref(exc.stage), file=exc.name, error=exc.error))
        self._last_errors[(exc.stage, exc.name)] = exc.error

    def snapshots(self):
        return tuple(a.snapshot for a in self._accepted)

    def accepted(self):
        return tuple(self._accepted)

    # ----------------------------------------------------------------------------------------------------- policy generations
    def _floor_ns(self, device):
        change = self._change_ns.get(device)
        return None if change is None else change + self.plan.declaration.clock_tolerance_ns

    def snapshots_for(self, device):
        """The accepted audits admissible as identity evidence for THIS device. An audit that started before the device's latest PEP-verified policy change describes an earlier
        policy generation and is excluded in both directions (never a current REVOKED after a RESTORE, never a current VALID after a QUARANTINE); a genuine later revocation is read
        by the first audit that starts afterwards. While the policy-change feed cannot be read the set of changes is unknown, so NO audit is admissible (identity MISSING: no AZTA
        proposal, the broker's own authorization stays authoritative) until a later read succeeds."""
        if self.barrier is None:
            return self.snapshots()
        if self._feed_error is not None:
            return ()
        floor = self._floor_ns(device)
        return self.snapshots() if floor is None else tuple(s for s in self.snapshots() if s.observed_ns >= floor)

    def barrier_info(self, device):
        """What the barrier did for this device (None when no barrier feed is configured): recorded in the bundle so the exclusion is auditable."""
        if self.barrier is None:
            return None
        floor = self._floor_ns(device)
        return dict(feed_readable=self._feed_error is None, policy_change_ns=self._change_ns.get(device), admissible_from_capture_start_ns=floor,
                    tolerance_ns=self.plan.declaration.clock_tolerance_ns,
                    excluded_audits=[a.ref for a in self._accepted if floor is not None and a.snapshot.observed_ns < floor])

    def _poll_barrier(self, now):
        try:
            changes = self.barrier.poll()
        except OSError as exc:                       # unreadable right now: fail closed (see snapshots_for), recorded once per distinct failure
            error = f"{exc.__class__.__name__}:{exc}"[:160]
            event = [] if self._feed_error == error else [dict(kind="POLICY_FEED_UNREADABLE", error=error)]
            self._feed_error = error
            return event
        except ValueError as exc:                    # a broken chain, a vanished or shortened PEP log: nothing about this session can be trusted any further
            raise LiveIntegrityFailure("POLICY_FEED_INTEGRITY", str(exc)[:200]) from None
        events = []
        if self._feed_error is not None:
            events.append(dict(kind="POLICY_FEED_RECOVERED"))
            self._feed_error = None
        for change in changes:
            key = (change["log"], change["seq"])
            if key in self._seen_changes:
                continue
            self._seen_changes.add(key)
            self._change_ns[change["device"]] = max(change["instant_ns"], self._change_ns.get(change["device"], 0))
            events.append(dict(kind="POLICY_CHANGE_OBSERVED", first_seen_utc_ns=now, **change))
        return events

    # ----------------------------------------------------------------------------------------------------------------- polls
    def _pending(self):
        stages = [] if "pre" in self._decided else ["pre"]
        number = next((n for n in range(1, MAX_PERIODIC + 1) if f"p{n:02d}" not in self._decided), None)
        if number is not None:
            stages.append(f"p{number:02d}")
        if "post" not in self._decided:
            stages.append("post")
        return stages

    def _verify_accepted(self):
        for audit in self._accepted:
            record_path, summary_path = self._stage_paths(audit.stage)
            try:
                record, summary = self._read(audit.stage, record_path), self._read(audit.stage, summary_path)
            except _AuditUnreadable as exc:                  # not a change: verified again at the next poll
                self._note_error(exc)
                continue
            if record is None or summary is None or _sha(record) != audit.record_sha256 or _sha(summary) != audit.summary_sha256:
                raise LiveIntegrityFailure("AUDIT_REWRITTEN", f"the accepted audit {audit.ref} changed or disappeared after it was used as evidence")

    def poll(self):
        """Ledger-ready events, in the order they happened. Raises LiveIntegrityFailure if an accepted audit changed."""
        self._verify_accepted()
        events, now = [], self.clock.utc_ns()
        if self.barrier is not None:                 # first: a policy change seen in this poll is known before any window of this poll is decided
            events.extend(self._poll_barrier(now))
        progressed = True
        while progressed:
            progressed = False
            for stage in self._pending():
                new = self._try_stage(stage, now)
                if new:
                    events.extend(new)
                    progressed = True
        events.extend(self._notes)                          # transient read failures: recorded, but they never count as progress (no retry loop)
        self._notes.clear()
        return events

    def _refuse(self, stage, code, reason):
        self._decided.add(stage)
        return [dict(kind="AUDIT_REFUSED", stage=stage, ref=self.ref(stage), code=code, reason=reason)]

    def _try_stage(self, stage, now):
        record_path, summary_path = self._stage_paths(stage)
        try:
            return self._evaluate(stage, now, record_path, summary_path)
        except _AuditUnreadable as exc:
            self._note_error(exc)
            return None

    def _evaluate(self, stage, now, record_path, summary_path):
        summary_blob = self._read(stage, summary_path)
        if summary_blob is None:
            return None                                            # the audit tool writes its record first and the run summary LAST: no summary, no audit yet
        try:
            summary = json.loads(summary_blob.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None                                            # half-written: retried at the next poll
        if not isinstance(summary, dict):
            return self._refuse(stage, "AUDIT_MALFORMED", "the audit run summary is not an object")
        if summary.get("state") != "COMPLETE":                      # a failed audit has a summary and no record: refused, it must not block later stages
            return self._refuse(stage, "AUDIT_INCOMPLETE", f"the audit run did not complete (failure_code {summary.get('failure_code')!r})")
        interval = capture_interval_ns(summary)
        if interval is None:
            return self._refuse(stage, "AUDIT_NO_CAPTURE_INSTANTS", "the audit run summary has no pinned capture instants")
        if summary.get("run_id") != self.ref(stage):
            return self._refuse(stage, "AUDIT_PROVENANCE", "the audit run summary names another run or stage")
        record_blob = self._read(stage, record_path)
        if record_blob is None:
            return self._refuse(stage, "AUDIT_RECORD_MISSING", "a COMPLETE audit has no binding_audit.json")
        try:
            record = json.loads(record_blob.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return self._refuse(stage, "AUDIT_MALFORMED", "binding_audit.json is not valid JSON")
        if not (isinstance(record, dict) and record.get("schema") == AUDIT_SCHEMA and record.get("schema_version") == 1
                and record.get("mutation_performed") is False and record.get("registry_sha256") == self.plan.registry_sha256):
            return self._refuse(stage, "AUDIT_NOT_READ_ONLY_RECORD", "not the read-only binding-audit record for the pinned registry")
        if interval[1] > now:                        # even bounded clock uncertainty cannot make an unfinished capture authoritative now
            if stage in self._flagged_future:
                return None
            self._flagged_future.add(stage)
            return [dict(kind="AUDIT_FROM_FUTURE", stage=stage, ref=self.ref(stage), ahead_ns=interval[1] - now)]
        if self._accepted and interval[0] < self._accepted[-1].snapshot.completed_ns:
            return self._refuse(stage, "AUDIT_OUT_OF_ORDER", "the capture overlaps or precedes the previous accepted audit")
        try:
            snapshot = audit_snapshot_from_artifacts(record, summary, PROVENANCE)
        except ProducerRefused as exc:
            return self._refuse(stage, "AUDIT_NO_CAPTURE_INSTANTS", str(exc)[:200])
        policy = record.get("policy_sha256")
        audit = AcceptedAudit(stage, self.ref(stage), snapshot, _sha(record_blob), _sha(summary_blob), policy, policy == self.plan.declaration.baseline_policy_sha256)
        self._accepted.append(audit)
        self._decided.add(stage)
        events = [dict(kind="AUDIT_ACCEPTED", stage=stage, ref=audit.ref, record_sha256=audit.record_sha256, summary_sha256=audit.summary_sha256,
                       capture_start_ns=snapshot.observed_ns, capture_end_ns=snapshot.completed_ns, policy_sha256=policy,
                       policy_matches_baseline=audit.policy_matches_baseline, verdict=record.get("verdict"), first_seen_utc_ns=now)]
        if not audit.policy_matches_baseline:
            events.append(dict(kind="POLICY_DIGEST_CHANGED", stage=stage, observed=policy, baseline=self.plan.declaration.baseline_policy_sha256))
        return events

    # ----------------------------------------------------------------------------------------------------------- resumption
    def rebuild(self, events):
        """Rebuild from the recorded events (all of them, in order), proving that every accepted audit file is still exactly what was accepted."""
        for event in events:
            if event["kind"] == "POLICY_CHANGE_OBSERVED":      # replayed so that a restart keeps the generations it had already seen (the feed re-reads its logs from the start)
                self._seen_changes.add((event["log"], event["seq"]))
                self._change_ns[event["device"]] = max(event["instant_ns"], self._change_ns.get(event["device"], 0))
            elif event["kind"] == "AUDIT_REFUSED":
                self._decided.add(event["stage"])
            elif event["kind"] == "AUDIT_FROM_FUTURE":
                self._flagged_future.add(event["stage"])
            elif event["kind"] == "AUDIT_ACCEPTED":
                stage = event["stage"]
                record_path, summary_path = self._stage_paths(stage)
                try:
                    record, summary = self._read(stage, record_path), self._read(stage, summary_path)
                except _AuditUnreadable as exc:
                    raise LiveRefused("AUDIT_UNREADABLE", f"{exc.stage}/{exc.name} cannot be read right now ({exc.error}); the resume is refused and may be retried") from None
                if record is None or summary is None or _sha(record) != event["record_sha256"] or _sha(summary) != event["summary_sha256"]:
                    raise LiveIntegrityFailure("AUDIT_REWRITTEN", f"the accepted audit {event['ref']} changed or disappeared while the adapter was down")
                snapshot = audit_snapshot_from_artifacts(json.loads(record.decode("utf-8")), json.loads(summary.decode("utf-8")), PROVENANCE)
                self._accepted.append(AcceptedAudit(stage, event["ref"], snapshot, event["record_sha256"], event["summary_sha256"], event["policy_sha256"],
                                                    event["policy_matches_baseline"]))
                self._decided.add(stage)
