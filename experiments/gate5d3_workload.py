"""Gate 5D.3A ten-slot workload schedules: pure, offline, deterministic. ENGINEERING scaffold only.

Implements the ten-slot specification of docs/gate5d/CICIoMT2024_INSPIRED_MQTT_WORKLOAD_SPEC.md (§4.2, §5) as
pure functions of (run id, slot, window geometry). It never imports an MQTT client, opens a socket or reads
a secret. Gate 5C's PROFILES, plans and schedule generator are not touched; slots 01-04 deliberately reuse
the accepted steady-profile law so that equivalence is testable. Every value below is a controlled synthetic
research-design parameter (not a physical device model, not a measured IoT rate). Rules that the draft left
unspecified are flagged ENGINEERING_CONVENTIONS and are not frozen scientific parameters.
"""
import hashlib
import random

from experiments.collection_workload import payload as _payload
from observation.schema import canonical

SPEC_VERSION = "gate5d3-workload-1"
SEED_PREFIX = "azta-workload-spec-v1"
NS = 1_000_000_000
SLOTS = tuple(range(1, 11))
FIXED = dict(kind="fixed", bytes=128)
VARIABLE = dict(kind="uniform_int", low=128, high=256)
STREAMS = ("jitter", "jitter_slow", "jitter_fast", "size", "phase", "event_gap", "mode_phase")

PROFILES = {
    1: dict(slot=1, shape="steady_jitter", nominal_gap_ns=1 * NS, jitter_fraction=0.1, payload=FIXED),
    2: dict(slot=2, shape="steady_jitter", nominal_gap_ns=NS // 5, jitter_fraction=0.1, payload=VARIABLE),
    3: dict(slot=3, shape="steady_jitter", nominal_gap_ns=NS // 5, jitter_fraction=0.1, payload=FIXED),
    4: dict(slot=4, shape="steady_jitter", nominal_gap_ns=1 * NS, jitter_fraction=0.1, payload=VARIABLE),
    5: dict(slot=5, shape="periodic", period_ns=3 * NS, payload=FIXED),
    6: dict(slot=6, shape="periodic", period_ns=4 * NS, payload=VARIABLE),
    7: dict(slot=7, shape="periodic", period_ns=5 * NS, payload=FIXED),
    8: dict(slot=8, shape="periodic", period_ns=30 * NS, payload=FIXED),
    9: dict(slot=9, shape="event_gap", gap_low_s=20, gap_high_s=60, payload=FIXED),
    10: dict(slot=10, shape="switching", slow_gap_ns=1 * NS, fast_gap_ns=NS // 5, jitter_fraction=0.1,
             block_ns=60 * NS, payload=FIXED),
}

# Rules the draft left open, fixed here ONLY so the offline tests are well defined. Not scientific parameters.
ENGINEERING_CONVENTIONS = dict(
    slot_label_in_seed='"slot" + two-digit slot, e.g. "slot03" (the draft writes only "<slot>")',
    time_basis="t0 = lead_in_windows*W and t1 = (lead_in_windows+eligible_windows)*W after observer coverage start "
               "(the draft leaves t0/t1 and lead-in/out OPEN; the Gate 5C 1+60+1 shape is reused as a default)",
    steady_end_rule="Gate 5C rule: first target t0+gap//2, emit while offset <= t1-gap//2",
    periodic_end_rule="targets t0+phase+k*T emitted while < t1",
    event_end_rule="targets emitted while < t1 (the draft gives no end rule for truncated phases)",
    draw_consumption="one jitter draw per EMITTED target in slots 01-04 and per emitted target in slot 10; one "
                     "event_gap draw per target generated (the first included); one size draw per emitted target "
                     "(variable slots only); one phase draw per run/slot. The draw that produces a target beyond "
                     "the end or beyond a block boundary is consumed",
    slot10_streams="per-mode jitter streams jitter_slow / jitter_fast (the draft says 'that mode's jitter stream'); "
                   "the half-period first target uses no draw",
    slot10_block_geometry="elapsed e = t-t0; cycle position (e+phase) mod 120 s; position <60 s is slow, else fast; "
                          "the first block is the remainder of the current 60 s block (a full 60 s when the phase is "
                          "on a boundary)",
    slot10_cancellation="a generated target at/after the block end is cancelled and recorded; the new block's first "
                        "target is boundary + half its nominal period; a target exactly on the boundary is cancelled",
    late_execution="not modelled: schedules are absolute targets; lateness/abort policy stays OPEN",
)


class CountingRandom:
    """random.Random that counts draws, so draw consumption is documented and testable."""
    def __init__(self, seed):
        self._rng, self.draws = random.Random(seed), 0

    def uniform(self, a, b):
        self.draws += 1
        return self._rng.uniform(a, b)

    def randint(self, a, b):
        self.draws += 1
        return self._rng.randint(a, b)

    def randrange(self, n):
        self.draws += 1
        return self._rng.randrange(n)


def device_for(slot):
    return f"device{slot:02d}"


def stream_seed(run_id, slot, stream):
    if stream not in STREAMS:
        raise ValueError(f"unknown stream {stream!r}")
    text = f"{SEED_PREFIX}|{run_id}|slot{slot:02d}|{stream}"
    return int(hashlib.sha256(text.encode("utf-8")).hexdigest()[:16], 16)


def _size(profile_payload, rng):
    return profile_payload["bytes"] if profile_payload["kind"] == "fixed" else rng.randint(
        profile_payload["low"], profile_payload["high"])


def _steady(profile, t0, t1, rngs):
    gap, fraction = profile["nominal_gap_ns"], profile["jitter_fraction"]
    offset, last, items = t0 + gap // 2, t1 - gap // 2, []
    while offset <= last:
        items.append((len(items) + 1, offset, _size(profile["payload"], rngs.get("size"))))
        offset += round(gap * (1 + rngs["jitter"].uniform(-fraction, fraction)))
    return items, {}


def _periodic(profile, t0, t1, rngs):
    period = profile["period_ns"]
    phase = rngs["phase"].randrange(period)
    items, k = [], 0
    while t0 + phase + k * period < t1:
        items.append((k + 1, t0 + phase + k * period, _size(profile["payload"], rngs.get("size"))))
        k += 1
    return items, dict(phase_ns=phase)


def _event(profile, t0, t1, rngs):
    items, offset = [], t0 + rngs["event_gap"].randint(profile["gap_low_s"], profile["gap_high_s"]) * NS
    while offset < t1:
        items.append((len(items) + 1, offset, _size(profile["payload"], rngs.get("size"))))
        offset += rngs["event_gap"].randint(profile["gap_low_s"], profile["gap_high_s"]) * NS
    return items, {}


def _switching(profile, t0, t1, rngs):
    block, end = profile["block_ns"], t1 - t0
    phase = rngs["mode_phase"].randrange(2 * block)
    position = phase % (2 * block)
    mode = "slow" if position < block else "fast"
    start, length = 0, block - (phase % block)
    items, blocks, canceled = [], [], []
    while start < end:
        nominal = profile["slow_gap_ns"] if mode == "slow" else profile["fast_gap_ns"]
        jitter = rngs["jitter_slow" if mode == "slow" else "jitter_fast"]
        block_end = start + length
        blocks.append(dict(index=len(blocks), mode=mode, start_offset_ns=t0 + start, end_offset_ns=t0 + block_end))
        target = start + nominal // 2
        while True:
            if target >= end:
                break
            if target >= block_end:
                canceled.append(dict(block=len(blocks) - 1, mode=mode, target_offset_ns=t0 + target))
                break
            items.append((len(items) + 1, t0 + target, _size(profile["payload"], rngs.get("size"))))
            target += round(nominal * (1 + jitter.uniform(-profile["jitter_fraction"], profile["jitter_fraction"])))
        start, length, mode = block_end, block, "fast" if mode == "slow" else "slow"
    return items, dict(phase_ns=phase, blocks=blocks, canceled_targets=canceled)


_SHAPES = dict(steady_jitter=_steady, periodic=_periodic, event_gap=_event, switching=_switching)
_STREAMS_USED = dict(steady_jitter=("jitter",), periodic=("phase",), event_gap=("event_gap",),
                     switching=("mode_phase", "jitter_slow", "jitter_fast"))


def schedule(run_id, slot, *, window_ns, lead_in_windows, eligible_windows):
    """Return dict(items=[(sequence, offset_ns_from_coverage_start, payload_bytes)], meta=...). Pure."""
    if slot not in PROFILES:
        raise ValueError(f"unsupported slot {slot!r}")
    if type(window_ns) is not int or window_ns <= 0 or type(lead_in_windows) is not int or lead_in_windows < 0 \
            or type(eligible_windows) is not int or eligible_windows < 1:
        raise ValueError("window geometry must be explicit positive integers")
    profile = PROFILES[slot]
    t0, t1 = lead_in_windows * window_ns, (lead_in_windows + eligible_windows) * window_ns
    names = _STREAMS_USED[profile["shape"]] + (("size",) if profile["payload"]["kind"] != "fixed" else ())
    rngs = {name: CountingRandom(stream_seed(run_id, slot, name)) for name in names}
    items, extra = _SHAPES[profile["shape"]](profile, t0, t1, rngs)
    meta = dict(spec_version=SPEC_VERSION, run_id=run_id, slot=slot, device=device_for(slot), shape=profile["shape"],
                t0_offset_ns=t0, t1_offset_ns=t1,
                seeds={name: stream_seed(run_id, slot, name) for name in names},
                draws={name: rng.draws for name, rng in rngs.items()}, **extra)
    return dict(items=items, meta=meta)


def schedule_sha256(items):
    return hashlib.sha256(canonical([list(item) for item in items]).encode("utf-8")).hexdigest()


def payload_bytes(run_id, slot, sequence, size):
    """Exact serialized application bytes (full JSON object), reusing the accepted Gate 5C serializer."""
    return _payload(run_id, device_for(slot), sequence, size)
