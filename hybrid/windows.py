"""Multi-timescale windows: the six Gate 5B measures over a window of ANY declared duration, computed by the FROZEN `observation.windowing.measures` function.

A candidate observation contract changes only the window duration W (and therefore a different feature distribution, a different scaler, a different model and a different calibration;
nothing fitted at W = 10 s is reused). Window k of a contract covers [first + k*W, first + (k+1)*W) inside the usable span; a trailing partial window is dropped. `ready` follows the frozen
six-feature rule (every measure must be present: at least three messages for the inter-arrival SD, history for the last-delivery age); nothing is imputed.
"""
from collections import namedtuple

from observation.schema import PREDICTOR_CANDIDATES
from observation.windowing import measures

from fleet.dataset import REASON_PRECEDENCE

Window = namedtuple("Window", "run role device index start_ns end_ns count ready reason vector measures")


def classify(m):
    statuses = {m[name]["status"] for name in PREDICTOR_CANDIDATES}
    for reason in REASON_PRECEDENCE[1:]:
        if reason in statuses:
            return False, reason, None
    if any(m[name]["status"] != "VALUE" for name in PREDICTOR_CANDIDATES):
        return False, "SCHEMA_MISMATCH", None
    return True, None, tuple(float(m[name]["value"]) for name in PREDICTOR_CANDIDATES)


def rewindow(events, device, run, width_ns, *, displaced=None):
    """All windows of `device` in one run (a `hybrid.events.Run`) at duration `width_ns`. `displaced` replaces the receive instants (a list of (offset, size)) for studies that perturb timing."""
    rows = displaced if displaced is not None else run.events.get(device, [])
    first, last = run.usable_first_ns, run.usable_last_ns
    count = (last - first) // width_ns
    buckets, history = {}, None
    for offset, size in rows:
        if offset < first:
            history = offset if history is None or offset > history else history       # the latest delivery before the usable span is the starting "last delivery"
        elif offset < first + count * width_ns:
            buckets.setdefault((offset - first) // width_ns, []).append((offset, size))
    out = []
    for k in range(count):
        counted = sorted(buckets.get(k, []))
        end = first + (k + 1) * width_ns
        if counted:
            history = counted[-1][0]
        m = measures(counted, end, history, True)
        ready, reason, vector = classify(m)
        out.append(Window(run.run, run.role, device, k, end - width_ns, end, len(counted), ready, reason, vector, m))
    return out


def windows_of_role(role, device, width_ns, assignment=None):
    from hybrid import events as ev
    out = []
    for run in ev.runs_of_role(role, assignment):
        out.extend(rewindow(None, device, ev.load_run(run, assignment), width_ns))
    return out
