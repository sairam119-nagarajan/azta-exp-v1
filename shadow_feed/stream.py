"""Streaming-readiness pipeline: incremental window arrival -> evidence bundle -> the UNCHANGED trust engine -> a null enforcement hand-off.

An ENGINEERING interface. It makes the decision path incremental and timestamps every stage, so that a later, separately authorized live stage
has a defined contract; it does not make this a live system. The same pipeline serves two bases, and the basis decides what a timestamp means:

  REPLAY    the windows come from a COMPLETED, digest-pinned session. The feature-ready instant is DERIVED from the window end (the observer's own
            clock mapped to UTC); it was never measured by this pipeline, so no latency is derived from it. Only the processing time is measured
            (offline processing on this host). Every timing record says `REPLAY_NOT_LIVE` and that no live latency is demonstrated.
  ARRIVAL   the windows arrive one by one and the arrival instant is read from the injected clock. Feature-ready to decision, queueing and processing
            are then measured on that clock; the scope is `INCREMENTAL_ARRIVAL_MEASURED` for a system clock and `SYNTHETIC_CLOCK_TEST_ONLY` for a
            synthetic one. Even then it is an engineering measurement, never a formal latency result.

Rules that keep evidence honest (each is tested):
  * queueing is explicit: `submit` records the arrival, `process_next` decides later; the decision instant is read when processing STARTS, so a
    backlog makes behavioural evidence stale and the engine refuses it (NOT_EVALUABLE). Nothing is dropped silently and no fresh score is invented;
  * windows are never reordered or repaired: a gap becomes an explicit WINDOW_NOT_DELIVERED refusal, a late, repeated, foreign or malformed window an
    explicit refusal, and `finish()` accounts every planned eligible window exactly once;
  * a wall-clock step backwards between arrival and decision makes the evidence "from the future", which the engine refuses;
  * the only hand-off sink is the exact `ShadowNullSink` type: it records that a proposal was offered, applies nothing and has no other method.
    The pipeline has no parameter for a broker, credential or enforcement object, and refuses any other sink (subclasses included);
  * the engine is stateless and the pipeline holds no trust state: no smoothing, hysteresis, decay or automatic recovery exist here.

One honest limit: the pinned evidence producer has no provenance class for windows of a live, not yet completed (hence not digest-pinned) session.
So real live evidence cannot be fed here; this module is exercised with completed manifest-verified sessions and synthetic arrival. Adding such a
class would change a frozen contract and needs a controller decision. (The separately versioned `shadow_live` adapter supplies that provenance
OUTSIDE the pinned producer, through the three seams below; what this module itself accepts is unchanged.)

Seams for a prospective adapter (all optional, behaviour-identical when unused): `submit(window, arrival=...)` takes an arrival measured by the caller,
`_build_bundle` is the one place an arrived window becomes a bundle, `finish(missing_code=...)` names why planned windows never arrived, and
`state_snapshot()` / `restore_state()` make a stream resumable between whole polls.
"""
from collections import Counter, deque, namedtuple
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import statistics
import time

from observation.schema import validate_window
from shadow_feed import feed
from shadow_feed.errors import StreamRefused
from trust.engine import DECISION_SCHEMA, DECISION_SCHEMA_VERSION
from trust.errors import PathRefused, ProducerRefused
from trust.evidence import parse_bundle
from trust.producer import RunProvenance, profile_assignment_from_plan
from trust.shadow import summarize
from trust.timeline import window_end_utc_ns

STREAM_VERSION = "gate5f-stream-1"
TIMING_SCHEMA = "azta.gate5f.stream_timing"
REPLAY_MANIFEST_SCHEMA = "azta.gate5f.stream_replay_manifest"
BASES = ("REPLAY", "ARRIVAL")
SCOPE_REPLAY, SCOPE_ARRIVAL, SCOPE_SYNTHETIC = "REPLAY_NOT_LIVE", "INCREMENTAL_ARRIVAL_MEASURED", "SYNTHETIC_CLOCK_TEST_ONLY"
CLAIMS = dict(live_decision_latency_demonstrated=False, formal_latency_result=False,
              note="an engineering timestamp record: replay of a completed session never demonstrates live decision latency, and no value here is a "
                   "formal latency, containment or reliability result")
REPLAY_NOT_MEASURABLE = "REPLAY_FEATURE_READY_IS_DERIVED_FROM_THE_WINDOW_END_AND_WAS_NEVER_MEASURED"
HANDOFF_INTERFACE = "SHADOW_NULL_SINK"
OUTPUT_FILES = ("decisions.jsonl", "timing.jsonl", "summary.json")
Arrival = namedtuple("Arrival", "utc_ns mono_ns")
StreamOutput = namedtuple("StreamOutput", "sequence kind record timing")


def _dump(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def scope_for(basis, clock_kind):
    if basis == "REPLAY":
        return SCOPE_REPLAY
    return SCOPE_SYNTHETIC if clock_kind == "SYNTHETIC" else SCOPE_ARRIVAL


class SystemClock:
    """Monotonic and UTC wall time of this host. Used for processing durations and for real arrival measurement.

    The monotonic reading is `time.perf_counter_ns` (QueryPerformanceCounter on Windows, 100 ns): there `time.monotonic_ns` is GetTickCount64 with 15.6 ms
    steps, which would quantize every measured queue wait and processing time into 0 or 15.6 ms. Only DIFFERENCES of this clock are meaningful (its origin is
    arbitrary). The wall reading is `time.time_ns`, the adjustable system clock: on Windows with CPython 3.12 it only advances at the system timer tick
    (0.3 to 15.6 ms, measured 0.34 to 1 ms on the development workstation), so a UTC arrival stamp, and anything derived from it (the window-end to arrival
    lag), carries that granularity. A finer wall reading needs `ctypes`, which the package boundary forbids; the rehearsal tools outside the package read it."""
    kind = "SYSTEM"

    def monotonic_ns(self):
        return time.perf_counter_ns()

    def utc_ns(self):
        return time.time_ns()


class SyntheticClock:
    """A deterministic clock for tests. Monotonic time never goes backwards; the UTC wall clock can be stepped (to model a clock step)."""
    kind = "SYNTHETIC"

    def __init__(self, utc_ns, monotonic_ns=0):
        self._utc, self._mono = int(utc_ns), int(monotonic_ns)

    def advance(self, ns):
        if type(ns) is not int or ns < 0:
            raise StreamRefused("CLOCK_INVALID", "a synthetic clock only advances by a non-negative integer")
        self._utc += ns
        self._mono += ns

    def step_utc(self, ns):
        self._utc += int(ns)                   # a wall-clock step (positive or negative); the monotonic clock is unaffected

    def monotonic_ns(self):
        return self._mono

    def utc_ns(self):
        return self._utc


class ShadowNullSink:
    """The ONLY enforcement hand-off this milestone allows. It records that a proposal was offered and applies nothing; it has no other method."""
    interface = HANDOFF_INTERFACE

    def __init__(self):
        self.offered = 0

    def offer(self, proposal):
        self.offered += 1
        return dict(interface=HANDOFF_INTERFACE, applied=False, broker_mutations=0)


class StaticAuditSource:
    """The read-only audit snapshots already known (a completed session's pinned audits)."""

    def __init__(self, snapshots):
        self._snapshots = tuple(snapshots)

    def snapshots(self):
        return self._snapshots


class AppendableAuditSource:
    """Audit snapshots that become known over time. Only what is known at a decision can be used for it."""

    def __init__(self):
        self._snapshots = []

    def add(self, snapshot):
        self._snapshots.append(snapshot)

    def snapshots(self):
        return tuple(self._snapshots)


@dataclass(frozen=True)
class StreamContext:
    """The run a pipeline decides for. `run` is the producer's provenance record; the rest describes the window grid and the evidence class."""
    run: RunProvenance
    evidence_mode: str
    clock_basis: str
    coverage_start_utc: object
    coverage_start_offset_ns: int
    planned_window_count: int
    devices: tuple
    allowed_partitions: tuple


def context_from_session(session, plan, *, manifest_sha256):
    """The context of a manifest-verified scientific session (D_shadow, MANIFEST_ARTIFACT provenance)."""
    return StreamContext(feed.run_provenance(session, plan, manifest_sha256=manifest_sha256), "TRUSTED_OFFLINE_REPLAY", feed.CLOCK_BASIS,
                         session.coverage_start_utc, session.coverage_start_offset_ns, session.planned_window_count,
                         tuple(sorted(plan["runs"][session.run_id]["devices"])), feed.FEED_PARTITIONS)


class StreamingDecisionPipeline:
    def __init__(self, *, engine, context, assignment, audit_source, clock, sink, basis, stream_id, schedule=None, reserved_tokens=frozenset()):
        if type(sink) is not ShadowNullSink:
            raise StreamRefused("SINK_NOT_AUTHORIZED", "only the exact ShadowNullSink is allowed: an active enforcement sink is a later, separately "
                                                       "authorized milestone and no subclass or other object can stand in for it")
        if basis not in BASES:
            raise StreamRefused("BASIS_INVALID", f"basis must be one of {BASES}")
        if getattr(clock, "kind", None) not in ("SYSTEM", "SYNTHETIC") or not all(callable(getattr(clock, n, None)) for n in ("monotonic_ns", "utc_ns")):
            raise StreamRefused("CLOCK_INVALID", "a clock with kind SYSTEM or SYNTHETIC and monotonic_ns/utc_ns is required")
        if not isinstance(context, StreamContext) or not callable(getattr(engine, "decide", None)):
            raise StreamRefused("CONTEXT_INVALID", "a StreamContext and a decision engine are required")
        if not callable(getattr(audit_source, "snapshots", None)) or not callable(getattr(assignment, "lookup", None)):
            raise StreamRefused("CONTEXT_INVALID", "an audit source (snapshots) and a profile assignment (lookup) are required")
        if basis == "REPLAY" and not isinstance(context.coverage_start_utc, str):
            raise StreamRefused("CONTEXT_INVALID", "REPLAY derives each decision instant from the pinned coverage start (UTC)")
        if not feed.FEED_ID.fullmatch(stream_id or ""):
            raise StreamRefused("CONTEXT_INVALID", "stream id must be an identifier")
        self.engine, self.context, self.assignment, self.audits = engine, context, assignment, audit_source
        self.clock, self.sink, self.basis, self.stream_id, self.schedule = clock, sink, basis, stream_id, schedule
        self.reserved = frozenset(reserved_tokens)
        self.scope = scope_for(basis, clock.kind)
        self.low, self.high = context.run.eligible_window_indices
        self.queue, self.outputs = deque(), []
        self.next_expected = {device: 0 for device in context.devices}
        self.seen, self.accounted = set(), set()
        self.counts = Counter()
        self.max_queue = 0
        self.arrivals = 0
        self.finished = False

    # ------------------------------------------------------------------------------------------------------------- arrival
    def _eligible(self, index):
        return self.low <= index <= self.high

    def _evidence_id(self, device, index):
        return feed.evidence_id_for(self.stream_id, self.context.run.collection_run_id, device, index)

    def _refuse(self, code, reason, *, evidence_id, pair=None, arrival=None):
        self.queue.append(("refusal", dict(code=code, reason=reason, evidence_id=evidence_id, pair=pair),
                           self._arrival() if arrival is None else arrival))

    def _arrival(self):
        return Arrival(self.clock.utc_ns(), self.clock.monotonic_ns())

    def submit(self, window, arrival=None):
        """Record the arrival of one window record. Ordering, duplicate and foreign-window rules are applied here, in arrival order.

        `arrival` (optional) is an `Arrival` the caller measured when it first saw the record; without it the pipeline's own clock is read."""
        if self.finished:
            raise StreamRefused("STREAM_FINISHED", "the stream was finished; no further window can be submitted")
        self.arrivals += 1
        self.counts["submitted"] += 1
        anonymous = f"{self.stream_id}-{self.context.run.collection_run_id}-arrival{self.arrivals:06d}"
        try:
            validate_window(window)
            device, index = window["device"], window["window"]["index"]
        except (ValueError, TypeError, KeyError, AttributeError):
            self._refuse("WINDOW_MALFORMED", "the arriving record is not a valid observation window", evidence_id=anonymous, arrival=arrival)
            return
        run = self.context.run
        if (window["collection_run_id"] != run.collection_run_id or window["observer_session_id"] != run.observer_session_id
                or device not in self.next_expected or not 0 <= index < self.context.planned_window_count):
            self._refuse("WINDOW_FOREIGN", "the window belongs to another run, session or device, or lies outside the planned grid", evidence_id=anonymous,
                         arrival=arrival)
            return
        evidence_id = self._evidence_id(device, index)
        if (device, index) in self.seen:
            self._refuse("WINDOW_DUPLICATE", "this device window was already received", evidence_id=evidence_id, arrival=arrival)
            return
        expected = self.next_expected[device]
        if index < expected:
            self._refuse("WINDOW_OUT_OF_ORDER", "a later window of this device was already received; windows are never reordered or repaired",
                         evidence_id=evidence_id, arrival=arrival)
            return
        for missing in range(expected, index):               # a gap: every missing eligible window is an explicit refusal, never imputed
            if self._eligible(missing):
                self._refuse("WINDOW_NOT_DELIVERED", "the observer delivered no record for this window before a later one arrived",
                             evidence_id=self._evidence_id(device, missing), pair=(device, missing), arrival=arrival)
            else:
                self.counts["design_excluded_not_delivered"] += 1
        self.seen.add((device, index))
        self.next_expected[device] = index + 1
        if not self._eligible(index):
            self.counts["design_excluded"] += 1               # lead-in and post-roll windows are counted and never decided
            return
        self.queue.append(("window", window, self._arrival() if arrival is None else arrival))
        self.max_queue = max(self.max_queue, len(self.queue))

    # ---------------------------------------------------------------------------------------------------------- processing
    def process_next(self):
        if not self.queue:
            return None
        kind, payload, arrival = self.queue.popleft()
        output = self._refusal_output(payload, arrival) if kind == "refusal" else self._decision_output(payload, arrival)
        self.outputs.append(output)
        return output

    def process_all(self):
        done = []
        while self.queue:
            done.append(self.process_next())
        return done

    def on_window(self, window):
        """Submit and process immediately (no queueing)."""
        self.submit(window)
        return self.process_all()

    def finish(self, *, missing_code="WINDOW_NOT_DELIVERED", missing_reason="the planned window never arrived before the stream was finished"):
        """Account every planned eligible window that never arrived, process everything still queued, and close the stream.

        `missing_code` / `missing_reason` say WHY those windows are missing (the observer never delivered them, the caller stopped early, the stream was
        halted); the accounting is the same either way: each missing eligible window becomes exactly one explicit refusal."""
        if self.finished:
            raise StreamRefused("STREAM_FINISHED", "the stream was already finished")
        for device in self.context.devices:
            for index in range(self.next_expected[device], self.context.planned_window_count):
                if self._eligible(index):
                    self._refuse(missing_code, missing_reason, evidence_id=self._evidence_id(device, index), pair=(device, index))
                else:
                    self.counts["design_excluded_not_delivered"] += 1
            self.next_expected[device] = self.context.planned_window_count
        done = self.process_all()
        self.finished = True
        return done

    def state_snapshot(self):
        """The resumable part of the stream between whole polls (the queue must be empty): JSON-ready, no window content."""
        if self.queue:
            raise StreamRefused("STATE_NOT_QUIESCENT", "a snapshot is only defined when nothing is queued")
        return dict(counts=dict(self.counts), seen=sorted([d, i] for d, i in self.seen), accounted=sorted([d, i] for d, i in self.accounted),
                    next_expected=dict(self.next_expected), max_queue=self.max_queue, arrivals=self.arrivals, finished=self.finished)

    def restore_state(self, snapshot):
        """Seed a fresh stream from `state_snapshot()` (before anything was submitted). Outputs are not restored: they live in the caller's record."""
        if self.arrivals or self.outputs or self.queue or self.finished:
            raise StreamRefused("STATE_NOT_FRESH", "a stream can only be restored before anything was submitted")
        if (not isinstance(snapshot, dict) or set(snapshot) != {"counts", "seen", "accounted", "next_expected", "max_queue", "arrivals", "finished"}
                or set(snapshot["next_expected"]) != set(self.next_expected) or snapshot["finished"] is not False):
            raise StreamRefused("STATE_INVALID", "the snapshot does not describe this stream")
        self.counts = Counter(snapshot["counts"])
        self.seen = {(d, i) for d, i in snapshot["seen"]}
        self.accounted = {(d, i) for d, i in snapshot["accounted"]}
        self.next_expected = dict(snapshot["next_expected"])
        self.max_queue, self.arrivals = snapshot["max_queue"], snapshot["arrivals"]

    def _sequence(self):
        return len(self.outputs) + 1

    def _timing_base(self, evidence_id, device, index, window_end):
        return dict(schema=TIMING_SCHEMA, schema_version=1, stream_version=STREAM_VERSION, sequence=self._sequence(), evidence_id=evidence_id,
                    run_id=self.context.run.collection_run_id, device=device, window_index=index, basis=self.basis, scope=self.scope,
                    clock_kind=self.clock.kind, window_end_utc_ns=window_end, claims=dict(CLAIMS))

    def _refusal_output(self, item, arrival):
        record = dict(schema=DECISION_SCHEMA, schema_version=DECISION_SCHEMA_VERSION, record_kind="BUNDLE_REFUSED", line_number=None,
                      evidence_id=item["evidence_id"], reason=f"{item['code']}: {item['reason']}", refusal_code=item["code"], status="NOT_EVALUABLE",
                      proposed_state=None, counterfactual=True, enforcement="NONE", broker_policy_changes=0)
        if item["pair"] is not None:
            self.accounted.add(item["pair"])
        self.counts["refusal:" + item["code"]] += 1
        device, index = item["pair"] if item["pair"] else (None, None)
        timing = self._timing_base(item["evidence_id"], device, index, None)
        timing.update(feature_ready=None, decision=None, enforcement_handoff=dict(interface=HANDOFF_INTERFACE, offered=False,
                      reason="REFUSED_BEFORE_ANY_DECISION", applied=False, broker_mutations=0), derived=None)
        return StreamOutput(timing["sequence"], "REFUSAL", record, timing)

    def _build_bundle(self, *, evidence_id, window, arrival, decision_ns, available):
        """The one place a pipeline turns an arrived window into an evidence bundle (the file feed's builder). A prospective adapter overrides
        this seam to state its own provenance; the engine and everything after it are shared."""
        ctx = self.context
        return feed.window_bundle(
            evidence_id=evidence_id, evidence_mode=ctx.evidence_mode, clock_basis=ctx.clock_basis, decision_ns=decision_ns, available_ns=available,
            window=window, run=ctx.run, snapshots=self.audits.snapshots(), assignment=self.assignment, schedule=self.schedule,
            coverage_start_offset_ns=ctx.coverage_start_offset_ns, allowed_partitions=ctx.allowed_partitions, reserved_tokens=self.reserved)

    def _decision_output(self, window, arrival):
        ctx, index, device = self.context, window["window"]["index"], window["device"]
        evidence_id = self._evidence_id(device, index)
        window_end = window_end_utc_ns(ctx.coverage_start_utc, ctx.coverage_start_offset_ns, window) if ctx.coverage_start_utc is not None else None
        if self.basis == "REPLAY":
            available = decision_ns = window_end                   # derived, not measured: zero lag by construction, labelled so
        else:
            available, decision_ns = arrival.utc_ns, self.clock.utc_ns()
        start = self.clock.monotonic_ns()
        try:
            bundle, report = self._build_bundle(evidence_id=evidence_id, window=window, arrival=arrival, decision_ns=decision_ns, available=available)
            bundle["annotations"]["stream"] = dict(version=STREAM_VERSION, stream_id=self.stream_id, basis=self.basis,
                                                   decision_instant="window end (UTC)" if self.basis == "REPLAY" else "decision start on the pipeline clock",
                                                   missing_inputs=report["missing_inputs"])
            record = self.engine.decide(parse_bundle(json.loads(_dump(bundle))))     # the same canonical JSON round trip the file feed goes through
            refused = None
        except ProducerRefused as exc:
            record, refused = None, str(exc)
        end = self.clock.monotonic_ns()
        self.accounted.add((device, index))
        if refused is not None:
            self.counts["refusal:PRODUCER_REFUSED"] += 1
            record = dict(schema=DECISION_SCHEMA, schema_version=DECISION_SCHEMA_VERSION, record_kind="BUNDLE_REFUSED", line_number=None,
                          evidence_id=evidence_id, reason=f"PRODUCER_REFUSED: {refused}", refusal_code="PRODUCER_REFUSED", status="NOT_EVALUABLE",
                          proposed_state=None, counterfactual=True, enforcement="NONE", broker_policy_changes=0)
        else:
            self.counts["decisions"] += 1
            self.counts["status:" + record["status"]] += 1
        offered_at = completed_at = None
        if record["proposed_state"] is not None:
            offered_at = self.clock.monotonic_ns()
            self.sink.offer(dict(evidence_id=evidence_id, device=device, proposed_state=record["proposed_state"], status=record["status"]))
            completed_at = self.clock.monotonic_ns()
            self.counts["proposals_offered"] += 1
        timing = self._timing_base(evidence_id, device, index, window_end)
        handoff = dict(interface=HANDOFF_INTERFACE, offered=offered_at is not None, applied=False, broker_mutations=0,
                       offered_monotonic_ns=offered_at, completed_monotonic_ns=completed_at, reason=None if offered_at is not None else "NO_PROPOSAL")
        measured = self.basis == "ARRIVAL"
        timing.update(
            feature_ready=dict(utc_ns=available, monotonic_ns=arrival.mono_ns if measured else None,
                               basis="PIPELINE_ARRIVAL_ON_THE_CLOCK" if measured else "WINDOW_END_DERIVED_NOT_MEASURED"),
            decision=dict(instant_utc_ns=decision_ns, instant_basis="DECISION_START_ON_THE_CLOCK" if measured else "WINDOW_END_REPLAY",
                          start_monotonic_ns=start, end_monotonic_ns=end, processing_ns=end - start,
                          processing_basis="OFFLINE_PROCESSING_TIME_ON_THIS_HOST" if not measured else "MEASURED_ON_THE_CLOCK"),
            enforcement_handoff=handoff,
            derived=dict(
                window_end_to_feature_ready_ns=(available - window_end) if measured and window_end is not None else None,
                feature_ready_to_decision_start_ns=(start - arrival.mono_ns) if measured else None,
                feature_ready_to_decision_end_ns=(end - arrival.mono_ns) if measured else None,
                feature_ready_to_handoff_offered_ns=(offered_at - arrival.mono_ns) if measured and offered_at is not None else None,
                not_measurable_reason=None if measured else REPLAY_NOT_MEASURABLE))
        return StreamOutput(timing["sequence"], "DECISION" if refused is None else "REFUSAL", record, timing)

    # ------------------------------------------------------------------------------------------------------------ reporting
    def accounting(self):
        expected = {(d, i) for d in self.context.devices for i in range(self.low, self.high + 1)}
        refusals = {key[len("refusal:"):]: n for key, n in self.counts.items() if key.startswith("refusal:")}
        return dict(
            submitted=self.counts["submitted"], design_excluded=self.counts["design_excluded"],
            design_excluded_not_delivered=self.counts["design_excluded_not_delivered"], decisions=self.counts["decisions"],
            evaluated=self.counts["status:EVALUATED"], not_evaluable=self.counts["status:NOT_EVALUABLE"], refusals=dict(sorted(refusals.items())),
            proposals_offered=self.counts["proposals_offered"], max_queue_depth=self.max_queue, queue_depth=len(self.queue), finished=self.finished,
            expected_eligible_windows=len(expected), eligible_windows_accounted=len(self.accounted & expected),
            every_eligible_window_accounted=self.accounted >= expected and self.finished)

    def summary(self):
        decisions = [o.record for o in self.outputs]
        processing = [o.timing["decision"]["processing_ns"] for o in self.outputs if o.timing["decision"] is not None]
        measured = self.basis == "ARRIVAL"
        queueing = [o.timing["derived"]["feature_ready_to_decision_start_ns"] for o in self.outputs
                    if measured and o.timing["derived"] is not None and o.timing["derived"]["feature_ready_to_decision_start_ns"] is not None]
        return dict(stream=dict(version=STREAM_VERSION, stream_id=self.stream_id, basis=self.basis, scope=self.scope, clock_kind=self.clock.kind,
                                run_id=self.context.run.collection_run_id), accounting=self.accounting(), decisions=summarize(decisions),
                    timing=dict(processing_ns=_distribution(processing), feature_ready_to_decision_start_ns=_distribution(queueing),
                                note="replay: only processing_ns is measured (offline, on this host); queueing exists only for incremental arrival"),
                    claims=dict(CLAIMS), safety=dict(enforcement="NONE", broker_policy_changes=0, sink=HANDOFF_INTERFACE, sink_applied_changes=0))


def _distribution(values):
    if not values:
        return None
    return dict(n=len(values), min=min(values), median=statistics.median(values), mean=math.fsum(values) / len(values), max=max(values))


def replay_session(pipeline, session):
    """Drive a pipeline over a completed session in the observer's emission order (no queueing), then account everything."""
    for window in session.windows:
        pipeline.on_window(window)
    pipeline.finish()
    return pipeline


def session_pipeline(session, campaign, *, basis, engine, clock, sink, stream_id, schedule=None):
    """A pipeline for one manifest-verified session. basis REPLAY (decide at the window end) or ARRIVAL (decide on the clock; used to exercise the
    incremental path with a completed session's windows)."""
    context = context_from_session(session, campaign.plan, manifest_sha256=campaign.manifest_sha256)
    return StreamingDecisionPipeline(engine=engine, context=context, assignment=profile_assignment_from_plan(campaign.plan),
                                     audit_source=StaticAuditSource(session.snapshots), clock=clock, sink=sink, basis=basis, stream_id=stream_id,
                                     schedule=schedule, reserved_tokens=campaign.reserved_tokens)


class WindowFileTail:
    """Polls ONE window file of a session that is still being written and returns the records that have become complete since the last poll.

    A half-written final line is kept for the next poll; a complete line that is not a valid observation window, or a file that shrank, is a hard
    refusal (a corrupt or replaced observer file is an integrity failure, not something to skip). It refuses any path under the raw evidence root:
    tailing live raw evidence is a separately authorized live stage that is not implemented, so this class cannot be pointed at historical evidence.
    """

    def __init__(self, path, *, repo_root):
        resolved = Path(path).resolve()
        raw = (Path(repo_root) / "results" / "raw").resolve()
        if resolved == raw or raw in resolved.parents:
            raise StreamRefused("TAIL_PATH_NOT_AUTHORIZED", "tailing under the raw evidence root needs a separate live authorization (not implemented)")
        self.path, self._offset, self._pending = resolved, 0, b""

    def poll(self):
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            return []
        if size < self._offset:
            raise StreamRefused("TAIL_FILE_TRUNCATED", "the window file is shorter than what was already consumed")
        if size == self._offset:
            return []
        with open(self.path, "rb") as stream:
            stream.seek(self._offset)
            data = stream.read(size - self._offset)
        self._offset += len(data)
        self._pending += data
        *lines, self._pending = self._pending.split(b"\n")
        windows = []
        for line in lines:
            if not line.strip():
                continue
            try:
                window = json.loads(line.decode("utf-8"))
                validate_window(window)
            except (ValueError, UnicodeDecodeError) as exc:
                raise StreamRefused("TAIL_RECORD_INVALID", f"a complete line is not a valid observation window ({str(exc)[:120]})") from None
            windows.append(window)
        return windows


def _protected(out_dir, repo_root):
    resolved = Path(out_dir).resolve()
    for relative in feed.PROTECTED_OUTPUTS:
        base = (Path(repo_root) / relative).resolve()
        if resolved == base or base in resolved.parents:
            raise PathRefused(f"refusing to write replay output under {relative}")


def write_replay(campaign, pipelines, access, *, replay_id, out_root, engine, schedule=None, allow_legacy_observer=False):
    """Create decisions.jsonl, timing.jsonl, summary.json and replay_manifest.json exclusively under out_root/replay_id."""
    if not feed.FEED_ID.fullmatch(replay_id or ""):
        raise StreamRefused("CONTEXT_INVALID", "replay id must be an identifier")
    out = Path(out_root) / replay_id
    _protected(out, campaign.repo)
    outputs = [o for p in pipelines for o in p.outputs]
    decisions = "".join(_dump(o.record) + "\n" for o in outputs).encode("utf-8")
    timing = "".join(_dump(o.timing) + "\n" for o in outputs).encode("utf-8")
    summaries = [p.summary() for p in pipelines]
    summary = (json.dumps(dict(runs=summaries), sort_keys=True, indent=1, allow_nan=False) + "\n").encode("utf-8")
    out.mkdir(parents=True, exist_ok=False)
    files = {}
    for name, blob in (("decisions.jsonl", decisions), ("timing.jsonl", timing), ("summary.json", summary)):
        with open(out / name, "xb") as stream:
            stream.write(blob)
        files[name] = dict(sha256=hashlib.sha256(blob).hexdigest(), bytes=len(blob))
    manifest = dict(
        schema=REPLAY_MANIFEST_SCHEMA, schema_version=1, stream_version=STREAM_VERSION, replay_id=replay_id, partition=campaign.authorization.partition,
        basis="REPLAY", scope=SCOPE_REPLAY, authorization=dict(reference=campaign.authorization.reference, manifest_sha256=campaign.manifest_sha256),
        plan=dict(plan_id=campaign.plan["plan_id"], plan_sha256=campaign.plan_sha256), engine=engine.describe(), legacy_observer_allowed=bool(allow_legacy_observer),
        runs=[dict(run_id=p.context.run.collection_run_id, observer_session_id=p.context.run.observer_session_id,
                   windows_sha256=p.context.run.windows_artifact_sha256, accounting=p.accounting()) for p in pipelines],
        context=dict(operating_schedule=None if schedule is None else dict(version=schedule.get("version"), sha256=feed.sha256_bytes(_dump(schedule).encode()))),
        reserved_protection=dict(reserved_token_count=len(campaign.reserved_tokens)), access=access, outputs=files, record_count=len(outputs),
        claims=dict(CLAIMS), safety=dict(feed.SAFETY, sink=HANDOFF_INTERFACE),
        caveats=["descriptive only: windows within a run share their environment and are not independent",
                 "timing.jsonl holds processing durations measured on this host (not deterministic); decisions.jsonl is deterministic for a replay",
                 "epsilon, lambda, the trust weights and the thresholds of a SYNTHETIC_TEST_UNAPPROVED configuration are test values, not operating parameters"])
    with open(out / "replay_manifest.json", "xb") as stream:
        stream.write((json.dumps(manifest, sort_keys=True, indent=1, allow_nan=False) + "\n").encode("utf-8"))
    return manifest
