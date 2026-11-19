"""The EXISTING streaming pipeline, specialised only where a LIVE session must say something different from a replay.

Everything that makes a decision is reused unchanged: the queue and its ordering rules (duplicate, out-of-order, gap, foreign, design-excluded), the
stage timestamps, the null enforcement hand-off, the pinned evidence producer, the trust engine. What this subclass adds is exactly three things:

  * per-window run provenance: the window's `LiveRunProvenance` carries the digest of the file prefix it was read from, so the unchanged producer
    records it as the window artifact digest, and `annotations.live_provenance` states in plain fields that this is an UNFINISHED prefix;
  * the nominal observed instant of behavioural evidence is the observer-derived window end. The source holds a complete window whose nominal end is still
    ahead of the host read (inside the declared tolerance) and refuses one beyond it, so none reaches this point; the guard below refuses, never clamps,
    anything that still would. This UTC placement is a mixed-domain estimate, not a validated clock mapping or an exact evidence age;
  * the live block of the timing record: the feature-ready instant is the poll that first read the line (bracketed by the previous poll), measured on the
    pipeline clock; nothing here is a replay timestamp and nothing is a formal latency result.

The engine-level evidence mode of a live bundle is `TRUSTED_OFFLINE_REPLAY`: it is the only non-synthetic mode of the frozen evidence vocabulary, so the
decision record's `evidence_scope` says so. The live nature is carried by `annotations.live_provenance.evidence_class = LIVE_PROVISIONAL` and by the
timing scope. (A dedicated live mode in the frozen vocabulary would make that label exact; it is reported as a recommendation, not required here.)
"""
from dataclasses import replace

from shadow_feed import feed
from shadow_feed.stream import StreamContext, StreamingDecisionPipeline
from shadow_live import producer
from shadow_live.declaration import ADAPTER_VERSION, EVIDENCE_CLASS
from shadow_live.errors import LiveRefused
from shadow_live.source import WINDOW_END_BASIS
from shadow_live.timebase import utc_text
from trust.producer import profile_assignment_from_plan

ENGINE_MODE_NOTE = ("TRUSTED_OFFLINE_REPLAY is the only non-synthetic mode of the frozen evidence vocabulary; this record is LIVE_PROVISIONAL evidence of an "
                    "unfinished session, not an offline replay of an accepted one")
SCIENTIFIC_STATUS = ("UNFINISHED_SESSION_NOT_ACCEPTED: never D_shadow evidence; the accepted session is re-scored by the manifest-verified replay "
                     "after reconciliation and acceptance")
FEATURE_READY_BASIS = "LIVE_SOURCE_POLL_READ"


class LiveShadowPipeline(StreamingDecisionPipeline):
    def __init__(self, *, plan, session_id, engine, audit_source, clock, sink, stream_id, schedule=None, context_source=None):
        if schedule is not None and context_source is not None:
            raise LiveRefused("CONTEXT_SOURCE_AMBIGUOUS", "an operating schedule and a broker context source would both supply operating_time")
        self.context_source = context_source
        context = StreamContext(
            run=producer.base_provenance(plan, session_id), evidence_mode="TRUSTED_OFFLINE_REPLAY", clock_basis=feed.CLOCK_BASIS, coverage_start_utc=None,
            coverage_start_offset_ns=0, planned_window_count=plan.planned_window_count, devices=tuple(sorted(plan.devices)),
            allowed_partitions=(plan.partition,))
        super().__init__(engine=engine, context=context, assignment=profile_assignment_from_plan(plan.plan), audit_source=audit_source, clock=clock,
                         sink=sink, basis="ARRIVAL", stream_id=stream_id, schedule=schedule, reserved_tokens=plan.reserved_tokens)
        self.plan, self.session_id = plan, session_id
        self._lines = {}
        self._coverage = None
        self.sequence_base = 0           # outputs already recorded before a restart: sequence numbers stay monotonic across restarts

    def _sequence(self):
        return self.sequence_base + len(self.outputs) + 1

    # ----------------------------------------------------------------------------------------------------------------- feed
    def set_coverage(self, origin_utc_ns, coverage_start_offset_ns):
        """The session's coverage start, derived from the windows' own grid (a constant), placed in UTC through the session start. Set once."""
        placed = (origin_utc_ns, coverage_start_offset_ns)
        if self._coverage is not None:
            if self._coverage != placed:
                raise LiveRefused("COVERAGE_CHANGED", "the coverage start of a session is a constant and cannot change")
            return
        self._coverage = placed
        self.context = replace(self.context, coverage_start_utc=utc_text(origin_utc_ns + coverage_start_offset_ns),
                               coverage_start_offset_ns=coverage_start_offset_ns)

    def submit_line(self, line):
        self._lines.setdefault((line.device, line.index), line)       # the first line of a window keeps its provenance if a duplicate follows
        if line.read_after_session_summary:
            self.counts["live:read_after_session_summary"] += 1
        self.submit(line.window, arrival=line.arrival)

    def submit_refusal(self, refusal):
        """A line the SOURCE refused (malformed, foreign, off-grid, from the future): one explicit refusal, never a decision, never a silent drop."""
        self.arrivals += 1
        self.counts["submitted"] += 1
        self.counts["live:source_refused"] += 1
        known = refusal.device in self.next_expected and type(refusal.index) is int and 0 <= refusal.index < self.context.planned_window_count
        base = self._evidence_id(refusal.device, refusal.index) if known else f"{self.stream_id}-{self.context.run.collection_run_id}-line{refusal.line_number:06d}"
        self._refuse(refusal.code, refusal.reason, evidence_id=f"{base}-l{refusal.line_number:06d}" if known else base, arrival=refusal.arrival)

    # ------------------------------------------------------------------------------------------------------------- bundles
    def _build_bundle(self, *, evidence_id, window, arrival, decision_ns, available):
        ctx, device, index = self.context, window["device"], window["window"]["index"]
        line = self._lines[(device, index)]
        observed = line.window_end_utc_ns
        placeholder = line.read_after_session_summary and window["coverage"]["state"] != "COMPLETE"
        if observed > available:
            if not placeholder:
                raise LiveRefused("WINDOW_TIME_UNCERTAIN", "a future observation cannot be made valid by clamping its timestamp")
            observed = available                    # uncovered shutdown placeholders are not behavioral observations and cannot yield valid features
        run = producer.for_window(ctx.run, line.prefix_sha256)
        extra = ()
        if self.context_source is not None and self._coverage is not None and not placeholder:
            origin_utc_ns, coverage_offset_ns = self._coverage
            extra = self.context_source.facts(device=device, window=window, coverage_start_utc_ns=origin_utc_ns + coverage_offset_ns,
                                              coverage_start_offset_ns=coverage_offset_ns, window_end_utc_ns=line.window_end_utc_ns, decision_ns=decision_ns)
        bundle, report = feed.window_bundle(
            evidence_id=evidence_id, evidence_mode=ctx.evidence_mode, clock_basis=ctx.clock_basis, decision_ns=decision_ns, available_ns=observed,
            window=window, run=run, snapshots=self.audits.snapshots_for(device), assignment=self.assignment, schedule=self.schedule,
            coverage_start_offset_ns=ctx.coverage_start_offset_ns, allowed_partitions=ctx.allowed_partitions, reserved_tokens=self.reserved,
            extra_context_facts=extra)
        barrier = self.audits.barrier_info(device)
        if barrier is not None:                    # a policy-change feed is configured: what it did for this device is part of the evidence
            bundle["annotations"]["identity_barrier"] = barrier
        declaration = self.plan.declaration
        bundle["annotations"]["live_provenance"] = dict(
            adapter_version=ADAPTER_VERSION, evidence_class=EVIDENCE_CLASS, scientific_status=SCIENTIFIC_STATUS, engine_evidence_mode_note=ENGINE_MODE_NOTE,
            partition_role=run.partition, run_id=run.collection_run_id, observer_session_id=run.observer_session_id,
            declaration=dict(id=declaration.declaration_id, file_sha256=self.plan.declaration_file_sha256, authorization_ref=declaration.authorization_ref),
            windows_artifact=dict(file="windows.jsonl", state="UNFINISHED_PREFIX", line_number=line.line_number, byte_start=line.byte_start,
                                  byte_end=line.byte_end, line_sha256=line.line_sha256, prefix_sha256=line.prefix_sha256,
                                  meaning="windows_artifact_sha256 above is the digest of the file prefix this window was read from, not of a finished artifact"),
            timing=dict(window_end_utc_ns=line.window_end_utc_ns, window_end_basis=WINDOW_END_BASIS, arrival_utc_ns=line.arrival.utc_ns,
                        previous_read_utc_ns=line.previous_read_utc_ns, behavior_observed_ns=observed, observed_clamped_to_read_instant=False,
                        observation_time_basis="UNCOVERED_SHUTDOWN_PLACEHOLDER_READ" if placeholder else "NOMINAL_OBSERVER_UTC_UNMAPPED",
                        cross_domain_mapping_validated=False, declared_clock_tolerance_ns=declaration.clock_tolerance_ns,
                        read_after_session_summary=line.read_after_session_summary))
        return bundle, report

    # -------------------------------------------------------------------------------------------------------------- timing
    def _live_timing(self, output, line):
        live = dict(adapter_version=ADAPTER_VERSION, evidence_class=EVIDENCE_CLASS, mode="LIVE_ARRIVAL")
        if line is not None:
            live.update(feature_ready_basis=FEATURE_READY_BASIS, read_interval_utc_ns=[line.previous_read_utc_ns, line.arrival.utc_ns],
                        window_end_to_feature_ready_clock_basis="HOST_WALL_MINUS_OBSERVER_ANCHORED_MONOTONIC",
                        cross_domain_mapping_validated=False, window_end_to_feature_ready_uncertainty_ns=None,
                        window_end_utc_ns=line.window_end_utc_ns, window_end_basis=WINDOW_END_BASIS, read_after_session_summary=line.read_after_session_summary,
                        line=dict(line_number=line.line_number, byte_end=line.byte_end, prefix_sha256=line.prefix_sha256))
            if output.timing.get("feature_ready") is not None:
                output.timing["feature_ready"]["basis"] = FEATURE_READY_BASIS
        output.timing["live"] = live
        return output

    def _decision_output(self, window, arrival):
        return self._live_timing(super()._decision_output(window, arrival), self._lines.get((window["device"], window["window"]["index"])))

    def _refusal_output(self, item, arrival):
        return self._live_timing(super()._refusal_output(item, arrival), None)

    def accounting(self):
        accounting = super().accounting()
        accounting["live"] = dict(mode="LIVE_ARRIVAL", source_refused=self.counts["live:source_refused"],
                                  read_after_session_summary=self.counts["live:read_after_session_summary"])
        return accounting
