"""Versioned cross-domain clock certificate (CLOCK-MAP-1): what may be claimed about one measured clock relation, and for how long.

Two contracts stay separate. The pilot's 100 ms cross-domain budget governs PEP and decision timing and gave the recorded span of about 1,290 s on this host; RC-1's 1 s tolerance is its own contract and is not touched here.
Neither is widened. A certificate holds a measurement from `rehearsal_tools/clock_probe.py evaluate` (never a default): the uncertainty of the offset at the anchor and a bound on the relative clock rate. The defensible span is

    span = (budget - anchor_uncertainty) / rate_bound

`CertificateChain` allows bounded re-anchoring: each anchor is a NEW measurement, must start after the previous one started, must not lie in the future, and must lie in one monotonic clock domain. It refuses a wall-clock step, a suspected
suspend or reboot, a stale anchor and any instant that the current certificate cannot cover, instead of mapping it. Equality with the budget or span is inside (the same non-strict rule the existing clock gate uses). Segments are a
scope statement: `plan_segments` never resets a confirmation counter or turns segments into independent trials, it only says where a session must stop and re-anchor. A session whose required span cannot be covered is BLOCKED.
"""
from dataclasses import dataclass
import math

VERSION = "CLOCK-MAP-1"
NS = 1_000_000_000
SCHEMA = "azta.core.clock_certificate"


class ClockRefused(ValueError):
    def __init__(self, code, text=""):
        super().__init__(f"{code}: {text}")
        self.code = code


@dataclass(frozen=True)
class Anchor:
    """One measured relation. `anchor_utc_ns` and `anchor_mono_ns` are readings on the certifying host; `domain` identifies the monotonic clock (boot id of the host and of the VM)."""
    anchor_utc_ns: int
    anchor_mono_ns: int
    domain: str
    uncertainty_ns: int
    rate_bound_ppm: float
    budget_ns: int
    max_age_ns: int

    def __post_init__(self):
        if type(self.budget_ns) is not int or self.budget_ns <= 0 or type(self.uncertainty_ns) is not int or self.uncertainty_ns < 0:
            raise ClockRefused("CERTIFICATE_MALFORMED", "explicit budget and uncertainty are required")
        if not (isinstance(self.rate_bound_ppm, (int, float)) and math.isfinite(self.rate_bound_ppm) and self.rate_bound_ppm > 0):
            raise ClockRefused("CERTIFICATE_MALFORMED", "a positive finite rate bound is required")
        if type(self.max_age_ns) is not int or self.max_age_ns <= 0 or not self.domain:
            raise ClockRefused("CERTIFICATE_MALFORMED", "a maximum age and a clock domain are required")

    @property
    def span_ns(self):
        margin = self.budget_ns - self.uncertainty_ns
        if margin <= 0:
            raise ClockRefused("BUDGET_EXHAUSTED_AT_THE_ANCHOR", "the anchor uncertainty alone uses the whole budget")
        return int(margin / (self.rate_bound_ppm * 1e-6))

    def error_bound_ns(self, elapsed_ns):
        return self.uncertainty_ns + abs(elapsed_ns) * self.rate_bound_ppm * 1e-6


class CertificateChain:
    """The anchors of one session in order. `check(utc_ns, mono_ns)` returns the error bound of a reading or refuses it."""

    def __init__(self, *, max_step_ns):
        if type(max_step_ns) is not int or max_step_ns <= 0:
            raise ClockRefused("CERTIFICATE_MALFORMED", "the wall/monotonic disagreement limit is explicit")
        self.max_step_ns, self.anchors = max_step_ns, []

    def add(self, anchor):
        if self.anchors:
            last = self.anchors[-1]
            if anchor.domain != last.domain:
                raise ClockRefused("CLOCK_DOMAIN_CHANGED", "a reboot or a new VM starts a new session, not a new anchor")
            if anchor.anchor_mono_ns <= last.anchor_mono_ns or anchor.anchor_utc_ns <= last.anchor_utc_ns:
                raise ClockRefused("ANCHOR_NOT_CAUSAL", "a new anchor must follow the previous one on both clocks")
            if anchor.budget_ns != last.budget_ns:
                raise ClockRefused("BUDGET_CHANGED", "the budget is fixed for a session")
        anchor.span_ns           # refuses an exhausted anchor
        self.anchors.append(anchor)

    def check(self, utc_ns, mono_ns, *, domain):
        if not self.anchors:
            raise ClockRefused("NO_CERTIFICATE", "no measured anchor")
        anchor = self.anchors[-1]
        if domain != anchor.domain:
            raise ClockRefused("CLOCK_DOMAIN_CHANGED", "the reading is from another monotonic domain")
        elapsed = mono_ns - anchor.anchor_mono_ns
        if elapsed < 0:
            raise ClockRefused("READING_BEFORE_THE_ANCHOR", "a reading older than the current anchor is ambiguous")
        if abs((utc_ns - anchor.anchor_utc_ns) - elapsed) > self.max_step_ns:
            raise ClockRefused("WALL_CLOCK_STEP_OR_SUSPEND", "wall and monotonic time disagree beyond the stated limit")
        if elapsed > anchor.max_age_ns:
            raise ClockRefused("CERTIFICATE_STALE", "the anchor is older than its maximum age")
        if elapsed > anchor.span_ns:
            raise ClockRefused("BEYOND_THE_CERTIFIED_SPAN", "the reading lies beyond what this certificate can bound")
        return anchor.error_bound_ns(elapsed)


def plan_segments(required_ns, anchor, *, overhead_ns):
    """The certified segments a session of `required_ns` (warm-up, slowest AE window twice, N = 2, drain and restore included by the caller) would need, with `overhead_ns` to re-anchor between them.
    One segment means the session fits. A slow case longer than one span can only be claimed verified across segments if the caller says so; the plan reports `slowest_window_fits`."""
    if type(required_ns) is not int or required_ns <= 0 or type(overhead_ns) is not int or overhead_ns < 0:
        raise ClockRefused("PLAN_MALFORMED", "explicit positive durations are required")
    span = anchor.span_ns
    usable = span - overhead_ns
    if usable <= 0:
        return dict(status="BLOCKED", reason="RE_ANCHORING_DOES_NOT_FIT_THE_SPAN", span_ns=span)
    segments = max(1, math.ceil(required_ns / usable))
    return dict(status="SINGLE_SPAN" if segments == 1 else "SEGMENTED", version=VERSION, span_ns=span, segments=segments, usable_per_segment_ns=usable, required_ns=required_ns,
                scope_note="segments are one session re-anchored; they do not reset confirmations and are not independent trials")


def required_session_ns(*, slowest_window_s, warmup_s, drain_s, restore_s, n=2, extra_windows=1):
    """The span a session needs so a slow device can complete N disjoint windows after an onset placed in the middle of a window."""
    return int((warmup_s + (n + extra_windows) * slowest_window_s + 10 + drain_s + restore_s) * NS)
