"""Exact composition of a LONG observation window from consecutive ordinary 10 s observer windows (Gate 6C pre-live campaign).

Why: the live observer (and the broker identity it needs) produces only 10 s windows. The long-window autoencoders of the sparse devices (06 and 07 at 20 s, 08 at 90 s, 09 at 180 s) need the six
Gate 5B measures over a longer window. Those measures are recoverable from the 10 s records without any new observer output, because each 10 s record carries, for its n messages, the count, the
payload mean and sample SD, the inter-arrival mean and sample SD of its n - 1 intra-window gaps, and the age of its last delivery at its end:

    last_k  = e_k - age_k                          (n_k >= 1; e_k = the end of window k, ages are measured from the window end)
    first_k = last_k - (n_k - 1) x mean_gap_k      (the n_k - 1 intra-window gaps sum to last_k - first_k)
    the gap between two consecutive non-empty windows j < k is  first_k - last_j  (an exact individual gap, also across empty windows)

The long window's gaps are the union of the intra-window gap groups and these boundary gaps; their mean and sample SD are merged with the numerically stable pairwise update of Chan et al.
(groups of (count, mean, M2)), and the payload statistics the same way. Everything is relative to the block's own grid (window k ends at (k + 1) x 10 s), so absolute clock values never enter
the arithmetic. The result has the layout of `observation.windowing.measures` and the statuses of `observation.schema.expected_status`, so the frozen vector reader and the frozen feature
order apply unchanged. A block is composable only when every window of it has COMPLETE observer coverage; anything else is reported as the observer-outage reason, never filled in.

`tests/test_hybrid_compose.py` pins the equivalence against the frozen `measures` function on thousands of random event streams; `rehearsal_tools/prelive_compose_parity.py` repeats it on the
recorded TRAIN / VAL runs. Nothing here fits, calibrates or decides anything.
"""
import math

from observation.schema import MEASURES, expected_status

MEASURE_NAMES = tuple(spec["name"] for spec in MEASURES)


class NotComposable(ValueError):
    pass


def _merge(a, b):
    """Chan's pairwise update of two groups (count, mean, M2)."""
    (na, ma, sa), (nb, mb, sb) = a, b
    if na == 0:
        return b
    if nb == 0:
        return a
    n = na + nb
    delta = mb - ma
    return n, ma + delta * nb / n, sa + sb + delta * delta * na * nb / n


def _value(measures, name):
    item = measures[name]
    return item["value"] if item["status"] == "VALUE" else None


def compose(records, *, width_ms=10_000.0):
    """The six measures of the block formed by `records` (consecutive 10 s window records of ONE device, oldest first, indices consecutive). Raises NotComposable on any inconsistency."""
    if not records:
        raise NotComposable("no records")
    first_index = records[0]["window"]["index"]
    for position, record in enumerate(records):
        if record["window"]["index"] != first_index + position:
            raise NotComposable("window indices are not consecutive")
        if abs(record["window"]["duration_ns"] / 1e6 - width_ms) > 1e-6:
            raise NotComposable("not a 10 s window")
    complete = all(record["coverage"]["state"] == "COMPLETE" for record in records)
    if not complete:
        return {name: dict(value=None, status="OBSERVER_UNAVAILABLE") for name in MEASURE_NAMES}, False
    n_total, payload, gaps = 0, (0, 0.0, 0.0), (0, 0.0, 0.0)
    last_seen = None                                  # end-relative instant of the previous non-empty window's last delivery
    for position, record in enumerate(records):
        m = record["measures"]
        end = (position + 1) * width_ms
        n = _value(m, "delivered_count")
        if n is None:
            raise NotComposable("a complete window has no delivered_count")
        if n == 0:
            continue
        age = _value(m, "last_delivery_age_ms")
        mean_payload = _value(m, "payload_bytes_mean")
        if age is None or mean_payload is None:
            raise NotComposable("a non-empty window lacks its last-delivery age or payload mean")
        last = end - age
        gap_mean = _value(m, "interarrival_mean_ms")
        gap_sd = _value(m, "interarrival_sd_ms")
        payload_sd = _value(m, "payload_bytes_sd")
        if n >= 2 and (gap_mean is None or payload_sd is None):
            raise NotComposable("a window with two or more messages lacks its gap mean or payload SD")
        if n >= 3 and gap_sd is None:
            raise NotComposable("a window with three or more messages lacks its gap SD")
        first = last - (n - 1) * gap_mean if n >= 2 else last
        if last_seen is not None:
            gaps = _merge(gaps, (1, first - last_seen, 0.0))
        if n >= 2:
            c = n - 1
            gaps = _merge(gaps, (c, gap_mean, (c - 1) * gap_sd * gap_sd if c >= 2 else 0.0))
            payload = _merge(payload, (n, mean_payload, (n - 1) * payload_sd * payload_sd))
        else:
            payload = _merge(payload, (1, mean_payload, 0.0))
        last_seen = last
        n_total += n
    if n_total >= 1 and gaps[0] != n_total - 1:
        raise NotComposable(f"gap bookkeeping: {gaps[0]} gaps for {n_total} messages")
    final_age = _value(records[-1]["measures"], "last_delivery_age_ms")
    values = dict(
        delivered_count=n_total,
        payload_bytes_mean=float(payload[1]) if n_total >= 1 else None,
        payload_bytes_sd=math.sqrt(payload[2] / (n_total - 1)) if n_total >= 2 else None,
        interarrival_mean_ms=float(gaps[1]) if n_total >= 2 else None,
        interarrival_sd_ms=math.sqrt(gaps[2] / (n_total - 2)) if n_total >= 3 else None,
        last_delivery_age_ms=final_age,
    )
    has_history = final_age is not None
    out = {}
    for name in MEASURE_NAMES:
        status = expected_status(name, n_total, complete, has_history)
        out[name] = dict(value=values[name] if status == "VALUE" else None, status=status)
    return out, complete


def agree(composed, direct, *, relative=1e-9, absolute=1e-6):
    """True when two measure dictionaries have the same statuses and values within a numerical tolerance (used by the parity checks)."""
    for name in MEASURE_NAMES:
        a, b = composed[name], direct[name]
        if a["status"] != b["status"]:
            return False
        if a["status"] == "VALUE" and abs(a["value"] - b["value"]) > absolute + relative * max(abs(a["value"]), abs(b["value"])):
            return False
    return True
