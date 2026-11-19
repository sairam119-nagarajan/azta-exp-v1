"""Legitimate traffic laws of the fleet devices and the synthetic development anomalies, as pure deterministic functions of (run id, device, parameters).

BENIGN. A device's legitimate schedule is the committed ten-slot law of `experiments.gate5d3_workload` (the same function that generated the development collection), generated over
lead-in + eligible + post-roll windows so that no eligible window is cut short by the generator's end rule (the workload-v2 idea). Nothing here changes a device's law.

ANOMALIES. The five DEVELOPMENT_ONLY kinds of the existing catalogue (`engineering.attack_control`): rate, payload, burst, jitter, drop. Each is derived from the device's OWN law by
changing exactly one parameter of that law over an arbitrary run interval [start, end): rate divides every gap (or the period) by `factor`; payload replaces the payload rule; burst
groups `group` messages 20 ms apart at the unchanged mean rate; jitter replaces the jitter fraction (a periodic law has none, so it is refused for it, never emulated); drop removes a
seeded share of the benign messages. The anomaly streams use their own seeded streams (never the benign ones). Pure: no clock, no network, no MQTT client.
"""
import copy
import hashlib
import random

from experiments import gate5d3_workload as g

BURST_SPACING_NS = 20_000_000
NS = g.NS
SUPPORTED = ("rate", "payload", "burst", "jitter", "drop")


class AnomalyNotApplicable(ValueError):
    pass


def slot_of(device):
    return int(device[-2:])


def profile_of(device):
    return copy.deepcopy(g.PROFILES[slot_of(device)])


def benign_items(run_id, device, *, window_ns, lead_in_windows, eligible_windows, post_roll_windows):
    """[(sequence, offset_ns, payload_bytes)] of the device's legitimate schedule over lead-in + eligible + post-roll windows."""
    return g.schedule(run_id, slot_of(device), window_ns=window_ns, lead_in_windows=lead_in_windows, eligible_windows=eligible_windows + post_roll_windows)["items"]


TIMING_VARIATION_KEYS = {"first_window", "last_window", "sigma_ms", "hiccup_rate", "hiccup_ms"}


def validate_timing_variation(segments):
    """Gate 6C pre-live: the declared BENIGN delivery-variation segments of a collection run (`first_window`..`last_window` are 1-based eligible window indices)."""
    if not isinstance(segments, list):
        raise ValueError("timing_variation must be a list of segments")
    last = 0
    for s in segments:
        number = lambda v: isinstance(v, (int, float)) and not isinstance(v, bool)
        ok = isinstance(s, dict) and set(s) == TIMING_VARIATION_KEYS and type(s["first_window"]) is int and type(s["last_window"]) is int and last < s["first_window"] <= s["last_window"]
        ok = ok and number(s["sigma_ms"]) and number(s["hiccup_rate"]) and isinstance(s["hiccup_ms"], list) and len(s["hiccup_ms"]) == 2 and all(number(v) for v in s["hiccup_ms"])
        ok = ok and 0 <= s["sigma_ms"] <= 20 and 0 <= s["hiccup_rate"] <= 0.05 and 0 <= s["hiccup_ms"][0] <= s["hiccup_ms"][1] <= 500
        if not ok:
            raise ValueError(f"invalid timing_variation segment: {s!r}")
        last = s["last_window"]
    return segments


def vary_timing(items, segments, run_id, device, *, window_ns, lead_in_windows):
    """BENIGN delivery variation (Gate 6C pre-live collection): the device's legitimate schedule with each message of a declared segment moved by a Gaussian displacement (SD `sigma_ms`,
    truncated at 4 SD) and, with probability `hiccup_rate`, delayed by a further uniform `hiccup_ms` stall. It emulates the clock, scheduling and network variability a real device has and the
    clean simulator does not; it is a declared COLLECTION CONDITION (recorded in the run's perturbation specification), never an attack. Pure and deterministic in (run id, device, segments):
    three draws per message in a fixed order so that two segments never shift each other's stream. Order is preserved (FIFO, at least 1 ms apart); sequences, payload sizes and the number of
    messages are unchanged."""
    if not segments:
        return list(items)
    rng = random.Random(int(hashlib.sha256(f"fleet-timing-variation|{run_id}|{device}".encode("utf-8")).hexdigest()[:16], 16))
    out, previous = [], None
    for sequence, offset, size in items:
        gauss, flip, span = rng.gauss(0.0, 1.0), rng.random(), rng.random()
        index = offset // window_ns - lead_in_windows + 1
        segment = next((s for s in segments if s["first_window"] <= index <= s["last_window"]), None)
        shifted = offset
        if segment is not None:
            delta_ms = max(-4.0, min(4.0, gauss)) * segment["sigma_ms"]
            if flip < segment["hiccup_rate"]:
                delta_ms += segment["hiccup_ms"][0] + span * (segment["hiccup_ms"][1] - segment["hiccup_ms"][0])
            shifted = max(0, offset + round(delta_ms * 1e6))
        if previous is not None and shifted <= previous:
            shifted = previous + 1_000_000
        previous = shifted
        out.append((sequence, shifted, size))
    return out


RECONNECTION_KEYS = {"window", "phase_ms", "gap_ms", "mode"}
RECONNECTION_MODES = ("clean", "takeover")
RECONNECTION_GAP_MS = (1000, 20000)       # a takeover gap must stay below the broker keep-alive timeout of the A3 client (1.5 x 15 s), or the broker would log a timeout instead
RECONNECTION_SPACING_S = 60


def validate_reconnections(reconnections, devices, *, window_ns):
    """Gate 6C Phase 2: the declared BENIGN reconnections of a collection run, {device: [{window, phase_ms, gap_ms, mode}]} (`window` = 1-based eligible window index, `phase_ms` = start of
    the offline interval inside that window). `clean`: the device sends DISCONNECT, stays offline for `gap_ms` and opens a new authenticated connection; `takeover`: the device goes silent
    without closing its connection (the way a device that lost its network behaves) and its new connection makes the broker close the old one. Messages scheduled while the device is offline
    are lost (no buffering, as in the synthetic reconnection model of Gate 6C). A declared COLLECTION CONDITION, never an attack; absent = the unchanged workload."""
    if not isinstance(reconnections, dict) or not set(reconnections) <= set(devices):
        raise ValueError("reconnections must map devices of the run to lists")
    for device, items in reconnections.items():
        if not isinstance(items, list):
            raise ValueError(f"{device}: reconnections must be a list")
        previous_end = None
        for r in items:
            ok = isinstance(r, dict) and set(r) == RECONNECTION_KEYS and all(type(r[k]) is int for k in ("window", "phase_ms", "gap_ms")) and r["mode"] in RECONNECTION_MODES
            ok = ok and r["window"] >= 1 and 0 <= r["phase_ms"] * 1_000_000 < window_ns and RECONNECTION_GAP_MS[0] <= r["gap_ms"] <= RECONNECTION_GAP_MS[1]
            if not ok:
                raise ValueError(f"invalid reconnection of {device}: {r!r}")
            start = (r["window"] - 1) * window_ns + r["phase_ms"] * 1_000_000
            if previous_end is not None and start < previous_end + RECONNECTION_SPACING_S * 1_000_000_000:
                raise ValueError(f"{device}: reconnections must be in order and at least {RECONNECTION_SPACING_S} s apart")
            previous_end = start + r["gap_ms"] * 1_000_000
    return reconnections


def reconnection_intervals(items, *, window_ns, lead_in_windows):
    """[(offline_start_offset_ns, offline_end_offset_ns, mode)] of one device's declared reconnections, on the run's offset clock."""
    out = []
    for r in items:
        start = (lead_in_windows + r["window"] - 1) * window_ns + r["phase_ms"] * 1_000_000
        out.append((start, start + r["gap_ms"] * 1_000_000, r["mode"]))
    return out


def drop_offline(items, intervals):
    """The schedule without the messages that fall while the device is offline (they are never sent)."""
    return [(q, o, s) for q, o, s in items if not any(a <= o < b for a, b, _ in intervals)]


def _scaled(profile, factor):
    out = copy.deepcopy(profile)
    for key in ("nominal_gap_ns", "period_ns", "slow_gap_ns", "fast_gap_ns"):
        if key in out:
            out[key] = max(1, round(out[key] / factor))
    for key in ("gap_low_s", "gap_high_s"):       # the event-gap law draws whole seconds; without this a rate anomaly on it would be a silent no-op
        if key in out:
            out[key] = max(1, round(out[key] / factor))
    return out


def _grouped(profile, group):
    out = copy.deepcopy(profile)
    for key in ("nominal_gap_ns", "period_ns", "slow_gap_ns", "fast_gap_ns", "gap_low_s", "gap_high_s"):
        if key in out:
            out[key] = out[key] * group
    return out


def _generate(profile, slot, run_id, tag, start, end):
    shape = profile["shape"]
    names = g._STREAMS_USED[shape] + (("size",) if profile["payload"]["kind"] != "fixed" else ())
    rngs = {name: g.CountingRandom(g.stream_seed(f"{run_id}|anomaly|{tag}", slot, name)) for name in names}
    items, _ = g._SHAPES[shape](profile, start, end, rngs)
    return [(offset, size) for _, offset, size in items]


def anomaly_items(run_id, device, kind, params, start, end, tag):
    """The anomalous [(offset_ns, payload_bytes)] of `kind` over [start, end) for this device (not including the benign messages outside the interval)."""
    slot, profile = slot_of(device), profile_of(device)
    if kind == "rate":
        return _generate(_scaled(profile, params["factor"]), slot, run_id, tag, start, end)
    if kind == "payload":
        changed = copy.deepcopy(profile)
        changed["payload"] = params["definition"]
        return _generate(changed, slot, run_id, tag, start, end)
    if kind == "jitter":
        if "jitter_fraction" not in profile:
            raise AnomalyNotApplicable(f"{device}: a {profile['shape']} law has no jitter to change")
        changed = copy.deepcopy(profile)
        changed["jitter_fraction"] = params["fraction"]
        return _generate(changed, slot, run_id, tag, start, end)
    if kind == "burst":
        group = params["group"]
        heads = _generate(_grouped(profile, group), slot, run_id, tag, start, end)
        return [(offset + k * BURST_SPACING_NS, size) for offset, size in heads for k in range(group)]
    if kind == "silence":                                    # every law can fall silent: nothing is generated inside the interval
        return []
    raise AnomalyNotApplicable(f"unsupported anomaly kind {kind!r}")


def apply_segment(run_id, device, pairs, kind, params, start, end, tag):
    """The offset-ordered [(offset, size)] with [start, end) replaced by the anomaly. `drop` filters the messages already in `pairs`."""
    keep = [(o, s) for o, s in pairs if o < start or o >= end]
    if kind == "silence":                                    # complete suppression (stabilization R1): the device stays connected and publishes nothing
        return sorted(keep)
    if kind == "drop":
        import hashlib
        import random
        rng = random.Random(int(hashlib.sha256(f"fleet-drop|{run_id}|{device}|{tag}".encode("utf-8")).hexdigest()[:16], 16))
        inside = [(o, s) for o, s in pairs if start <= o < end and rng.random() >= params["probability"]]
    else:
        inside = anomaly_items(run_id, device, kind, params, start, end, tag)
    return sorted(keep + inside)


def device_pairs(run_id, device, base, segments):
    """The device's complete schedule under the given anomaly segments (each {kind, params, start, end, command_id}); without any it is the benign schedule."""
    pairs = [(o, s) for _, o, s in base]
    for index, segment in enumerate(segments):
        pairs = apply_segment(run_id, device, pairs, segment["kind"], segment["params"], segment["start"], segment["end"], f"{index}-{segment.get('command_id')}")
    return pairs
