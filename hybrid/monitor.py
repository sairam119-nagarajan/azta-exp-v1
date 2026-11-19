"""The per-device behavioural monitor of the pre-live hybrid (Gate 6C pre-live campaign): ONE implementation shared by the live evaluator and every offline study.

A `DeviceMonitor` consumes the ordinary 10 s observer window records of ONE device, in order, one per decision tick, and returns the HBE fusion record of that tick. Its evidence streams:

  TIMING_TICK / TIMING_MSG   TM-1 on the 10 s window (`hybrid.timing`): rate and silence at every tick; payload, short gap and variability in the window that holds the messages
  BLOCK                      BM-1 + DR-1 on a block of K consecutive windows (`hybrid.blocks`): moderate rate changes, partial drops, robust jitter, slow drift; ONE item per block
  AE_FAST                    the autoencoder of the 10 s window (the six frozen measures; device05's PE3 family)
  AE_SLOW                    the autoencoder of a long window composed EXACTLY from K consecutive 10 s records (`hybrid.compose`): devices 06 to 09

Each stream is ACTIVE (counted) or ADVISORY (recorded in every fusion record, never counted, never confirming); a stream a device has no model or contract for is simply absent (UNSUPPORTED in the
register). Fusion is `hybrid.evidence.DeviceFusion`: A_B = max over admissible items, S_B = 100 exp(-lambda A_B); missing evidence is never healthy and never malicious; a slow item is fresh once and
then carried; a carried item counts only while CONFIRMED. `distinct="INTERVALS"` (HBE-2) additionally requires the confirming observations to cover pairwise disjoint time intervals, so two
indicators of the same window, or a long window and a 10 s window inside it, are ONE observation: a single abnormal window can never reach the enforcement layer's N = 2 by itself. Declared
maintenance intervals suppress silence evidence (not other evidence) and the end of one restarts the silence clock like a restored policy generation. Nothing here reads a clock, a file or a network.
"""
from dataclasses import dataclass, field, replace
import math

from observation.schema import PREDICTOR_CANDIDATES

from hybrid import blocks as hb, compose as hc, evidence as he, timing as tm
from hybrid.scaler import mask_vector

NS = 1_000_000_000
WINDOW_NS = 10 * NS
REASON_PRECEDENCE = ("OBSERVER_UNAVAILABLE", "NO_MESSAGES", "INSUFFICIENT_MESSAGES", "NEVER_OBSERVED_IN_SESSION")
_UNSET = object()
STREAMS = ("TIMING_TICK", "TIMING_MSG", "BLOCK", "AE_FAST", "AE_SLOW")


@dataclass(frozen=True)
class AeStream:
    """An autoencoder stream: `model.loss_for_vector(vector)`, its calibration constants (sample SD, journal eq. 10) and the width of the window it scores."""
    name: str
    model: object
    mu_l: float
    sigma_l: float
    width_s: int
    epsilon: float = 1e-6
    masked: tuple = ()               # features held at 0.0 before scoring (pre-live amendment 1: the phase-nuisance age of a strictly periodic device)

    def __post_init__(self):
        if self.name not in ("AE_FAST", "AE_SLOW") or self.width_s < 10 or self.width_s % 10 or (self.name == "AE_FAST") != (self.width_s == 10):
            raise ValueError("invalid autoencoder stream")
        if not (math.isfinite(self.mu_l) and self.mu_l >= 0 and math.isfinite(self.sigma_l) and self.sigma_l > 0 and self.epsilon > 0):
            raise ValueError("an autoencoder stream needs a finite calibration (degenerate calibration is refused, not repaired)")

    def magnitude(self, measures):
        """(A, None) or (None, reason): the six measures are all required; nothing is imputed."""
        statuses = {measures[name]["status"] for name in PREDICTOR_CANDIDATES}
        for reason in REASON_PRECEDENCE:
            if reason in statuses:
                return None, reason
        if any(measures[name]["status"] != "VALUE" for name in PREDICTOR_CANDIDATES):
            return None, "SCHEMA_MISMATCH"
        vector = mask_vector(tuple(float(measures[name]["value"]) for name in PREDICTOR_CANDIDATES), self.masked)
        try:
            loss = float(self.model.loss_for_vector(vector))
        except ValueError as exc:
            return None, f"SCORING_REFUSED:{exc}"
        if not math.isfinite(loss) or loss < 0:
            return None, "NON_FINITE_LOSS"
        return max(0.0, (loss - self.mu_l) / (self.sigma_l + self.epsilon)), None


@dataclass(frozen=True)
class MonitorSpec:
    device: str
    tm: object                          # hybrid.timing.TimingContract (10 s; carries rho, tolerance and the silence policy)
    block: object = None                # hybrid.blocks.BlockContract
    ae_fast: object = None              # AeStream
    ae_slow: object = None              # AeStream
    advisory: tuple = ()
    distinct: str = "INTERVALS"
    maintenance: tuple = ()             # ((start_ns, end_ns), ...) declared maintenance / sleep intervals on the decision-tick clock

    def __post_init__(self):
        if any(s not in STREAMS for s in self.advisory):
            raise ValueError("unknown stream in advisory")
        if self.ae_slow is not None and self.ae_slow.name != "AE_SLOW" or self.ae_fast is not None and self.ae_fast.name != "AE_FAST":
            raise ValueError("stream slot mismatch")

    def horizon_ns(self):
        spans = [he.confirm_horizon_ns(self.tm)]
        for width in (self.block.width_s if self.block else 0, self.ae_slow.width_s if self.ae_slow else 0):
            if width:
                spans.append(2 * width * NS + 20 * NS)
        return max(spans)


class DeviceMonitor:
    def __init__(self, spec):
        self.spec = spec
        self.fusion = he.DeviceFusion(advisory=spec.advisory, confirm_horizon_ns=spec.horizon_ns(), distinct=spec.distinct)
        self.alive = []
        self.blocks = hb.BlockMonitor(spec.block) if spec.block else None
        self.ae_stretch = hb.Stretch(spec.ae_slow.width_s // 10) if spec.ae_slow else None
        self.ae_blocks_done = 0
        self.generation = _UNSET

    def _silence_origin(self, tick_ns, generation_start_ns):
        """The instant silence is measured from: the later of the policy-generation start and the end of the latest declared maintenance interval that has begun; inside one, the tick itself."""
        origin = generation_start_ns
        for start, end in self.spec.maintenance:
            if start <= tick_ns < end:
                return tick_ns
            if end <= tick_ns and (origin is None or end > origin):
                origin = end
        return origin

    def tick(self, record, *, tick_ns, generation_start_ns=None):
        spec, index = self.spec, record["window"]["index"]
        measures, complete = record["measures"], record["coverage"]["state"] == "COMPLETE"
        changed = self.generation is not _UNSET and generation_start_ns != self.generation
        self.generation = generation_start_ns
        if changed:
            # a PEP-verified policy change of THIS device (a quarantine or a restore) starts a new generation: behavioural evidence from before it is not admissible after it, in exactly the
            # sense the identity barrier (EG-1) applies to identity evidence. Without this an anomaly cached before the device was contained could re-contain it right after a manual RESTORE.
            self.alive, self.fusion.anomalous = [], {}
        status, _, tdetail = tm.evaluate(spec.tm, measures, coverage_complete=complete, window_end_ns=tick_ns, generation_start_ns=self._silence_origin(tick_ns, generation_start_ns))
        fresh = [replace(i, start_ns=tick_ns - WINDOW_NS) for i in he.timing_items(spec.tm, tdetail, status, tick_ns, index)]
        detail = dict(timing=tdetail, block=None, ae_fast=None, ae_slow=None)
        if spec.ae_fast is not None:
            a, reason = spec.ae_fast.magnitude(measures) if complete else (None, "OBSERVER_UNAVAILABLE")
            fresh.append(he.Item("AE_FAST", index, tick_ns, tick_ns, a, reason, False, tick_ns - WINDOW_NS))
            detail["ae_fast"] = dict(a=a, reason=reason)
        if self.blocks is not None:
            done = self.blocks.push(record, generation_changed=changed)
            if done is not None:
                bi, bstatus, a_block, a_drift, bdetail = done
                width = spec.block.width_s * NS
                a = max(a_block, a_drift) if bstatus == "EVALUATED" else None
                fresh.append(he.Item("BLOCK", bi, tick_ns, tick_ns + 2 * width, a, bdetail.get("reason"), True, tick_ns - width))
                detail["block"] = dict(status=bstatus, a_block=a_block, a_drift=a_drift, **bdetail)
        if self.ae_stretch is not None:
            if changed:
                self.ae_stretch.restart()
            records, interrupted = self.ae_stretch.push(record)
            width = spec.ae_slow.width_s * NS
            if records is not None:
                try:
                    composed, _ = hc.compose(records)
                    a, reason = spec.ae_slow.magnitude(composed)
                except hc.NotComposable as exc:
                    a, reason = None, f"COMPOSE_REFUSED:{exc}"
                fresh.append(he.Item("AE_SLOW", self.ae_blocks_done, tick_ns, tick_ns + 2 * width, a, reason, True, tick_ns - width))
                detail["ae_slow"] = dict(a=a, reason=reason, index=self.ae_blocks_done)
                self.ae_blocks_done += 1
            elif interrupted:
                fresh.append(he.Item("AE_SLOW", self.ae_blocks_done, tick_ns, tick_ns + 2 * width, None, "OBSERVER_UNAVAILABLE", True, tick_ns - width))
                detail["ae_slow"] = dict(a=None, reason="OBSERVER_UNAVAILABLE", index=self.ae_blocks_done)
        self.alive = [i for i in self.alive if i.expires_ns >= tick_ns] + fresh
        result = self.fusion.tick(tick_ns, self.alive)
        result["detail"] = detail
        return result


def record_of(window, *, complete=True):
    """A 10 s window record from a `hybrid.windows.Window` (offline studies); an outage is `complete=False` with every measure OBSERVER_UNAVAILABLE."""
    measures = window.measures if complete else {k: dict(value=None, status="OBSERVER_UNAVAILABLE") for k in window.measures}
    return dict(window=dict(index=window.index, duration_ns=WINDOW_NS), coverage=dict(state="COMPLETE" if complete else "PARTIAL"), measures=measures)


def run_stream(spec, windows, *, outages=()):
    """The fusion records of a window sequence of one device (`outages` = indices of windows the observer did not cover)."""
    monitor = DeviceMonitor(spec)
    return [monitor.tick(record_of(w, complete=w.index not in outages), tick_ns=w.end_ns) for w in windows]
