"""The live Shadow session driver: attach -> poll (audits, windows, decisions) -> ONE atomic ledger entry per poll -> end / halt / finish -> export.

    LiveShadowSession.start(plan, session_id, ...)     a new live id: the ledger directory is created exclusively and never reused
    session.poll()                                      one iteration; raises LiveIntegrityFailure AFTER recording the halt (fail closed)
    session.finish(reason)                              the adapter stops before the observer does: every missing window is one explicit refusal
    LiveShadowSession.resume(plan, session_id, ...)     continue from the last complete poll after proving every consumed byte is unchanged

Order inside a poll is fixed: audit events first (they can only add identity evidence, never alter a window), then the window source, then submission to
the streaming pipeline in file order, then processing of the whole queue, then the single ledger append. A decision is therefore durable only
together with the lines it came from and the stream state after it; a crash before the append loses nothing that was ever claimed.

The hand-off is the pipeline's exact `ShadowNullSink`: this class holds no broker handle, no credential and no enforcement object, and has no
parameter through which one could be given. Whatever it records is a counterfactual proposal.
"""
from collections import Counter
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import time

from shadow_feed import feed, stream
from shadow_feed.stream import ShadowNullSink
from shadow_live.audits import LiveAuditSource
from shadow_live.declaration import ADAPTER_VERSION, EVIDENCE_CLASS
from shadow_live.errors import LiveIntegrityFailure, LiveRefused
from shadow_live.ledger import LiveLedger
from shadow_live.pipeline import ENGINE_MODE_NOTE, SCIENTIFIC_STATUS, LiveShadowPipeline
from shadow_live.source import LiveLine, LiveWindowSource
from trust.errors import PathRefused
from trust.shadow import summarize

DEFAULT_OUT_ROOT = "results/gate5f/live_shadow"
MANIFEST_SCHEMA = "azta.gate5f.live_shadow_manifest"
OUTPUT_FILES = ("decisions.jsonl", "timing.jsonl", "summary.json", "live_manifest.json")
PROTECTED_OUTPUTS = feed.PROTECTED_OUTPUTS + ("shadow_live",)
FLAG_EVENTS = ("CLOCK_STEPPED_BACK", "SOURCE_STALLED", "POLICY_DIGEST_CHANGED", "AUDIT_FROM_FUTURE", "AUDIT_REFUSED", "POLICY_FEED_UNREADABLE")
SAFETY = dict(feed.SAFETY, sink=stream.HANDOFF_INTERFACE, sink_applied_changes=0)
CAVEATS = (
    "LIVE_PROVISIONAL: these decisions describe an unfinished observer session. They are never D_shadow evidence; the accepted session is re-scored by the "
    "manifest-verified replay after its reconciliation and acceptance",
    "nothing here is a formal latency, containment or reliability result; timing fields are engineering measurements on one host's clock",
    "epsilon, lambda, the trust weights and the thresholds of a SYNTHETIC_TEST_UNAPPROVED configuration are test values, not operating parameters",
    "the adapter assumes the observer's output directory is written only by the authorized observer process (an isolation property of the deployment, not "
    "cryptographic authentication); divergence from it is detectable afterwards through the digest chain, not prevented")


def _dump(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _output(out):
    return dict(kind=out.kind, sequence=out.sequence, record=out.record, timing=out.timing)


def _received(line):
    return dict(device=line.device, index=line.index, line_number=line.line_number, byte_start=line.byte_start, byte_end=line.byte_end,
                line_sha256=line.line_sha256, prefix_sha256=line.prefix_sha256, arrival_utc_ns=line.arrival.utc_ns, arrival_mono_ns=line.arrival.mono_ns,
                read_after_session_summary=line.read_after_session_summary, window_end_utc_ns=line.window_end_utc_ns)


def _refused(refusal):
    return dict(code=refusal.code, reason=refusal.reason, device=refusal.device, index=refusal.index, line_number=refusal.line_number,
                byte_start=refusal.byte_start, byte_end=refusal.byte_end, line_sha256=refusal.line_sha256, prefix_sha256=refusal.prefix_sha256,
                arrival_utc_ns=refusal.arrival.utc_ns, arrival_mono_ns=refusal.arrival.mono_ns)


def live_directory(plan, out_root, live_id):
    if not feed.FEED_ID.fullmatch(live_id or ""):
        raise LiveRefused("LIVE_ID_INVALID", "the live id must be an identifier")
    out = (Path(out_root) if Path(out_root).is_absolute() else plan.repo / out_root) / live_id
    resolved = out.resolve()
    for relative in PROTECTED_OUTPUTS:
        base = (plan.repo / relative).resolve()
        if resolved == base or base in resolved.parents:
            raise PathRefused(f"refusing to write live output under {relative}")
    if resolved == plan.evidence_root.resolve() or plan.evidence_root.resolve() in resolved.parents:
        raise PathRefused("refusing to write live output inside the evidence root being followed")
    return out


class LiveShadowSession:
    def __init__(self, *, plan, session_id, live_id, clock, ledger, source, audits, pipeline):
        self.plan, self.session_id, self.live_id, self.clock = plan, session_id, live_id, clock
        self.ledger, self.source, self.audits, self.pipeline = ledger, source, audits, pipeline
        self.flag_counts = Counter()
        self.poll_number = 0
        self.ended = self.halted = False

    # ---------------------------------------------------------------------------------------------------------- lifecycle
    @classmethod
    def _assemble(cls, plan, session_id, live_id, *, engine, clock, sink, schedule, ledger, context_source=None, barrier=None):
        audits = LiveAuditSource(plan, clock=clock, barrier=barrier)
        pipeline = LiveShadowPipeline(plan=plan, session_id=session_id, engine=engine, audit_source=audits, clock=clock, sink=sink or ShadowNullSink(),
                                      stream_id=live_id, schedule=schedule, context_source=context_source)
        return cls(plan=plan, session_id=session_id, live_id=live_id, clock=clock, ledger=ledger, source=LiveWindowSource(plan, session_id, clock=clock),
                   audits=audits, pipeline=pipeline)

    @classmethod
    def start(cls, plan, session_id, *, engine, clock, out_root, live_id, schedule=None, sink=None, context_source=None, barrier=None):
        plan.require_valid_at(clock.utc_ns())
        out = live_directory(plan, out_root, live_id)
        session = cls._assemble(plan, session_id, live_id, engine=engine, clock=clock, sink=sink, schedule=schedule, ledger=None,
                                context_source=context_source, barrier=barrier)   # validates before anything is created
        session.ledger = ledger = LiveLedger.create(out)
        ledger.append("SESSION_DECLARED", dict(
            adapter_version=ADAPTER_VERSION, evidence_class=EVIDENCE_CLASS, live_id=live_id, session_id=session_id, declaration=plan.describe(),
            declaration_data=plan.declaration.data, started_utc_ns=clock.utc_ns(), clock_kind=clock.kind, engine=engine.describe(),
            schedule_sha256=None if schedule is None else hashlib.sha256(_dump(schedule).encode()).hexdigest(), sink=stream.HANDOFF_INTERFACE,
            **({} if context_source is None else dict(context_source=context_source.describe())),
            **({} if barrier is None else dict(policy_change_feed=barrier.describe()))))
        return session

    @classmethod
    def resume(cls, plan, session_id, *, engine, clock, out_root, live_id, schedule=None, sink=None, context_source=None, barrier=None):
        out = live_directory(plan, out_root, live_id)
        ledger = LiveLedger.open_existing(out)
        declared = ledger.entries[0] if ledger.entries else None
        if declared is None or declared["kind"] != "SESSION_DECLARED":
            raise LiveIntegrityFailure("LEDGER_INVALID", "the ledger does not start with the session declaration")
        body = declared["body"]
        if body["adapter_version"] != ADAPTER_VERSION:
            raise LiveRefused("RESUME_VERSION_MISMATCH", "timing semantics changed; start a new prospective live id, never reinterpret an older ledger")
        if (body["declaration"]["declaration_file_sha256"] != plan.declaration_file_sha256 or body["session_id"] != session_id
                or body["live_id"] != live_id):
            raise LiveRefused("RESUME_MISMATCH", "the ledger belongs to another declaration, session or live id")
        if ledger.of_kind("SESSION_ENDED"):
            raise LiveRefused("SESSION_CLOSED", "this live session already ended and is never resumed")
        plan.require_valid_at(clock.utc_ns())
        session = cls._assemble(plan, session_id, live_id, engine=engine, clock=clock, sink=sink, schedule=schedule, ledger=ledger,
                                context_source=context_source, barrier=barrier)
        point, attached = ledger.resume_point(), ledger.of_kind("SESSION_ATTACHED")
        if point:                                                                      # the stream is restored FIRST, so that a halt below can account every window
            session.pipeline.restore_state(point["pipeline"])
            session.poll_number = point["poll"]
            session.flag_counts = Counter(ledger.polls()[-1]["body"]["integrity_flags"])
        session.pipeline.sequence_base = sum(len(e["body"]["outputs"]) for e in ledger.entries if e["kind"] == "POLL")
        try:
            session.audits.rebuild(ledger.audit_events())
            if attached:
                facts = attached[0]["body"]["facts"]
                progress = point["source"] if point else dict(offset=0, prefix_sha256=hashlib.sha256(b"").hexdigest(), line_number=0, coverage_start_offset_ns=None,
                                                              metadata_sha256=facts["metadata_sha256"], last_read_utc_ns=None, last_read_mono_ns=None)
                session.source.resume(progress)
                if session.source.coverage_start_offset_ns is not None:
                    session.pipeline.set_coverage(session.source.facts.origin_utc_ns, session.source.coverage_start_offset_ns)
        except LiveIntegrityFailure as exc:                                            # tampering found on the way back up: recorded durably, then fail closed
            session._end("HALTED_INTEGRITY_FAILURE", halt=dict(code=exc.code, detail=str(exc), found_during="RESUME"),
                         source_progress=point["source"] if point else None)
            raise
        ledger.append("RESUMED", dict(resumed_utc_ns=clock.utc_ns(), from_poll=session.poll_number, ledger_entries=len(ledger.entries),
                                      source_offset=session.source.offset, source_prefix_sha256=session.source.progress()["prefix_sha256"]))
        return session

    # ------------------------------------------------------------------------------------------------------------- polling
    def poll(self):
        if self.ended or self.halted:
            raise LiveRefused("SESSION_CLOSED", "the live session already ended")
        declaration = self.plan.declaration
        if not declaration.valid_from_ns <= self.clock.utc_ns() <= declaration.valid_until_ns:        # an expired authorization does not keep a session going
            self._end("AUTHORIZATION_EXPIRED")
            return dict(poll=self.poll_number, waiting=False, attached=False, lines=0, refused=0, audit_events=0, outputs=0, ended=True)
        try:
            return self._poll()
        except LiveRefused as exc:                  # a LiveIntegrityFailure is one too: either way this session cannot be followed any further
            if not self.ended:                      # a failure while ending must not be ended a second time
                self._end("HALTED_INTEGRITY_FAILURE" if isinstance(exc, LiveIntegrityFailure) else "HALTED_REFUSED",
                          halt=dict(code=exc.code, detail=str(exc)))
            raise

    def _poll(self):
        self.poll_number += 1
        audit_events = self.audits.poll()
        result = self.source.poll()
        if result.attached_now:
            self.ledger.append("SESSION_ATTACHED", dict(facts=asdict(result.facts), attached_utc_ns=result.read.utc_ns))
        if self.source.coverage_start_offset_ns is not None and result.facts is not None:
            self.pipeline.set_coverage(result.facts.origin_utc_ns, self.source.coverage_start_offset_ns)
        received, refused = [], []
        for item in result.items:
            if isinstance(item, LiveLine):
                self.pipeline.submit_line(item)
                received.append(_received(item))
            else:
                self.pipeline.submit_refusal(item)
                refused.append(_refused(item))
                self.flag_counts[item.code] += 1
        outputs = [_output(o) for o in self.pipeline.process_all()]
        for event in (*audit_events, *result.events):
            if event["kind"] in FLAG_EVENTS:
                self.flag_counts[event.get("code") or event["kind"]] += 1
        if audit_events or result.events or result.items or outputs or result.summary is not None:
            self.ledger.append("POLL", dict(
                poll=self.poll_number, read=dict(utc_ns=result.read.utc_ns, mono_ns=result.read.mono_ns),
                previous_read_utc_ns=result.previous_read.utc_ns if result.previous_read else None, clock_delta=result.clock_delta,
                audit_events=audit_events, source_events=result.events,
                received=received, refused=refused, outputs=outputs, source=self.source.progress(), pipeline=self.pipeline.state_snapshot(),
                integrity_flags=dict(self.flag_counts), observer_summary=asdict(result.summary) if result.summary else None))
        if result.summary is not None:
            self._end(f"OBSERVER_SESSION_ENDED_{result.summary.state}", observer_summary=asdict(result.summary))
        return dict(poll=self.poll_number, waiting=result.waiting, attached=result.attached_now, lines=len(received), refused=len(refused),
                    audit_events=len(audit_events), outputs=len(outputs), ended=self.ended)

    def finish(self, reason="ADAPTER_STOPPED"):
        """The adapter stops BEFORE the observer session ended. Every eligible window that was not observed is one explicit refusal."""
        if self.ended or self.halted:
            raise LiveRefused("SESSION_CLOSED", "the live session already ended")
        self._end(reason)

    def _end(self, reason, *, observer_summary=None, halt=None, source_progress=None):
        if observer_summary is not None:
            code, why = "WINDOW_NOT_DELIVERED", "the observer's session ended without delivering this planned window"
        elif halt is not None:
            code, why = "WINDOW_NOT_DECIDED_SESSION_HALTED", "the live session was halted by an integrity failure before this window could be decided"
        else:
            code, why = "WINDOW_NOT_OBSERVED_ADAPTER_STOPPED", "the adapter stopped before the observer session ended, so this window was never observed"
        outputs = [] if self.pipeline.finished else [_output(o) for o in self.pipeline.finish(missing_code=code, missing_reason=why)]
        self.ledger.append("SESSION_ENDED", dict(
            reason=reason, observer_summary=observer_summary, halt=halt, outputs=outputs, source=source_progress or self.source.progress(),
            pipeline=self.pipeline.state_snapshot(),
            accounting=self.pipeline.accounting(), integrity_flags=dict(self.flag_counts)))
        self.ended, self.halted = True, halt is not None
        export_ledger(self.ledger)

    def run(self, *, poll_interval_s, max_duration_s, sleep=time.sleep):
        """A blocking loop for the command line. Both numbers are explicit: the adapter owns no default cadence or deadline."""
        deadline = self.clock.monotonic_ns() + int(max_duration_s * 1_000_000_000)
        while not self.ended:
            self.poll()
            if self.ended:
                break
            if self.clock.monotonic_ns() >= deadline:
                self.finish("ADAPTER_DEADLINE_REACHED")
                break
            sleep(poll_interval_s)
        return self


# ------------------------------------------------------------------------------------------------------------------- export
def _blob(entries_outputs, key):
    return "".join(_dump(item[key]) + "\n" for item in entries_outputs).encode("utf-8")


def export_ledger(ledger):
    """decisions.jsonl, timing.jsonl, summary.json and live_manifest.json, created exclusively, derived from an ENDED ledger only."""
    ended = ledger.of_kind("SESSION_ENDED")
    if not ended:
        raise LiveRefused("SESSION_NOT_ENDED", "only an ended live session is exported")
    directory = ledger.directory
    if any((directory / name).exists() for name in OUTPUT_FILES):
        raise LiveRefused("EXPORT_EXISTS", "the exported files already exist and are never overwritten")
    declared = ledger.entries[0]["body"]
    end = ended[0]["body"]
    outputs = [item for entry in ledger.entries if entry["kind"] in ("POLL", "SESSION_ENDED") for item in entry["body"]["outputs"]]
    records, timings = [o["record"] for o in outputs], [o["timing"] for o in outputs]

    def distribution(values):
        return stream._distribution([v for v in values if v is not None])
    polls = ledger.polls()
    audit_events = ledger.audit_events()
    source_events = Counter(e["kind"] for entry in polls for e in entry["body"]["source_events"])
    summary = dict(
        live=dict(adapter_version=declared["adapter_version"], live_id=declared["live_id"], run_id=declared["declaration"]["run_id"], session_id=declared["session_id"],
                  partition_role=declared["declaration"]["partition_role"], evidence_class=EVIDENCE_CLASS, scope=stream.SCOPE_ARRIVAL
                  if declared["clock_kind"] == "SYSTEM" else stream.SCOPE_SYNTHETIC, clock_kind=declared["clock_kind"], end_reason=end["reason"],
                  polls_recorded=len(polls), restarts=len(ledger.of_kind("RESUMED")), accepted_scientific_session=False),
        accounting=end["accounting"], decisions=summarize(records),
        timing=dict(processing_ns=distribution(t["decision"]["processing_ns"] for t in timings if t["decision"]),
                    feature_ready_to_decision_start_ns=distribution(t["derived"]["feature_ready_to_decision_start_ns"] for t in timings if t["derived"]),
                    window_end_to_feature_ready_ns=distribution(t["derived"]["window_end_to_feature_ready_ns"] for t in timings if t["derived"]),
                    note="live arrival: measured on one host's clock; window-end placement is an upper bound (see window_end_basis); not a formal latency"),
        source=dict(lines_received=sum(len(p["body"]["received"]) for p in polls), lines_refused=sum(len(p["body"]["refused"]) for p in polls),
                    final_offset=end["source"]["offset"], final_prefix_sha256=end["source"]["prefix_sha256"], events=dict(source_events)),
        audits=dict(accepted=sum(e["kind"] == "AUDIT_ACCEPTED" for e in audit_events), events=dict(Counter(e["kind"] for e in audit_events)),
                    refused=[dict(stage=e["stage"], code=e["code"]) for e in audit_events if e["kind"] == "AUDIT_REFUSED"]),
        integrity=dict(flags=end["integrity_flags"], halt=end["halt"]), observer_summary=end["observer_summary"],
        claims=dict(stream.CLAIMS, accepted_scientific_session=False, note="LIVE_PROVISIONAL; see caveats"), safety=SAFETY)
    blobs = dict([("decisions.jsonl", _blob(outputs, "record")), ("timing.jsonl", _blob(outputs, "timing")),
                  ("summary.json", (json.dumps(summary, sort_keys=True, indent=1, allow_nan=False) + "\n").encode("utf-8"))])
    for name, blob in blobs.items():
        with open(directory / name, "xb") as stream_file:
            stream_file.write(blob)
    manifest = dict(
        schema=MANIFEST_SCHEMA, schema_version=1, adapter_version=declared["adapter_version"], live_id=declared["live_id"], evidence_class=EVIDENCE_CLASS,
        scientific_status=SCIENTIFIC_STATUS, engine_evidence_mode_note=ENGINE_MODE_NOTE, declaration=declared["declaration"],
        session_id=declared["session_id"], engine=declared["engine"],
        ledger=dict(entries=len(ledger.entries), head_sha256=ledger.head_sha256, file_sha256=hashlib.sha256((directory / "ledger.jsonl").read_bytes()).hexdigest()),
        outputs={name: dict(sha256=hashlib.sha256(blob).hexdigest(), bytes=len(blob)) for name, blob in blobs.items()}, record_count=len(outputs),
        end=dict(reason=end["reason"], halted=end["halt"] is not None), final_source=dict(offset=end["source"]["offset"], prefix_sha256=end["source"]["prefix_sha256"]),
        claims=summary["claims"], safety=SAFETY, caveats=list(CAVEATS),
        next_step="finalize-check against the finished observer files; acceptance needs the existing reconciliation and a manifest RUN_COLLECTED entry")
    with open(directory / "live_manifest.json", "xb") as stream_file:
        stream_file.write((json.dumps(manifest, sort_keys=True, indent=1, allow_nan=False) + "\n").encode("utf-8"))
    return manifest
