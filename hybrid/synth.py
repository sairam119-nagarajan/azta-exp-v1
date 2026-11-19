"""SYNTHETIC development streams for the hybrid studies: a device's own committed law, with a catalogue anomaly applied from an onset, as per-message receive events.

DEVELOPMENT_ONLY and SYNTHETIC: ideal delivery (the schedule instants) plus an independent Gaussian displacement of `noise_sd_ms` per message, which stands for the scheduling and delivery noise
of the observation chain (0.3 ms is the per-process regime of the collection runs; a few ms is the shared-loop regime of the Gate 6B pilot). The anomaly is derived from the device's OWN law
(`fleet.laws`, the same functions as the live fleet workload), so a rate anomaly of a 30 s sensor stays a 30 s sensor sped up. Anything computed from it is a development screen, not a
detection-accuracy claim, and not live evidence. A horizon of any length can be generated, so the slow contracts (several 180 s windows) can be exercised without new collection.
"""
from collections import namedtuple
import random

from engineering import attack_control as control
from fleet import laws

NS = 1_000_000_000
SynthRun = namedtuple("SynthRun", "run role start_ns width_ns usable_first_ns usable_last_ns events recorded_windows session")
LEAD_IN, POST_ROLL = 1, 5


def params_for(kind, **given):
    """The explicit parameters of a catalogue anomaly (`engineering.attack_control.normalize`, so a synthetic anomaly is exactly what the live control channel would start)."""
    return control.normalize(kind, given)[1]


def synth_run(run_id, device, *, horizon_s, kind=None, params=None, onset_s=None, noise_sd_ms=0.3, seed=0):
    window_ns = 10 * NS
    eligible = int(horizon_s // 10)
    items = laws.benign_items(run_id, device, window_ns=window_ns, lead_in_windows=LEAD_IN, eligible_windows=eligible, post_roll_windows=POST_ROLL)
    pairs = [(o, s) for _, o, s in items]
    first, last = LEAD_IN * window_ns, (LEAD_IN + eligible) * window_ns
    if kind is not None:
        params = control.normalize(kind, params)[1]            # exactly what the live control channel would hand to the workload
        pairs = laws.apply_segment(run_id, device, pairs, kind, params, LEAD_IN * window_ns + int(onset_s * NS), last + POST_ROLL * window_ns, f"synth-{kind}-{seed}")
    rng = random.Random(f"{run_id}|{device}|{kind}|{seed}")
    rows = sorted((max(0, o + int(rng.gauss(0.0, noise_sd_ms) * 1e6)), s) for o, s in pairs)
    return SynthRun(f"{run_id}-{kind or 'benign'}-s{seed}", "SYNTHETIC", 0, window_ns, first, last, {device: rows}, {}, "synthetic"), first + int((onset_s or 0) * NS)
