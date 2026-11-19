"""Gate 5C workload v2 CANDIDATE: a publishing schedule with an excluded post-roll, so no evaluated window is cut short.

STATUS: engineering candidate only. NOT adopted, NOT frozen and used by NO collected run. It does not edit, replace or re-run the frozen
Gate 5C generator (experiments/collection_workload.py, plan gate5c_workload_v1.json), whose behaviour stays the accepted historical record.
Using this module for a scientific collection needs a separate prospective protocol freeze and authorization (see
docs/gate5e/WORKLOAD_V2_CANDIDATE_SPEC.md). It collects nothing, trains nothing and touches no broker.

Why: the v1 stop rule (publish only while offset <= (lead_in+eligible)*W - nominal_gap/2) removes the messages that the same jitter stream
would have placed in the last half-gap of the LAST ELIGIBLE window, so that window shows a later last message (larger last_delivery_age_ms)
and more 9-message counts than any interior window (docs/gate5e/GATE_5E_S_ARTIFACT_ADDENDUM.md).

Rule: normal publishing continues through every eligible window and through POST_ROLL further windows that are explicitly excluded from
scoring. The same half-gap end rule as v1 is applied only at the end of the post-roll, where nothing is scored. The gap law, profiles,
payloads, seed-to-stream rule, W and the six-feature contract are unchanged, so with the same seeds the v1 schedule is an exact prefix of
the v2 schedule. Scheduled offsets are PLANNED values: whether the publisher kept them is a separate, recorded observation (termination_report).
"""
import copy
import hashlib
import random

from experiments import collection_plan as plans
from observation.schema import IDENTIFIER, PREDICTOR_CANDIDATES
from observation.windowing import measures

GENERATOR_VERSION = "gate5c-workload-2-candidate"
RUN_CONFIG_SCHEMA = "azta.collection.run_config_candidate"
SCHEMA_VERSION = 1
SEED_PREFIX = "g5c-v2c"  # independent of the accepted v1 campaign seeds (g5c-v1)
LEAD_IN_WINDOWS, ELIGIBLE_WINDOWS, POST_ROLL_WINDOWS = 1, 60, 1
ROLES = ("LEAD_IN", "ELIGIBLE", "POST_ROLL")
VERDICTS = ("TERMINATION_OK", "POST_ROLL_INCOMPLETE", "ELIGIBLE_WINDOWS_TRUNCATED", "SCHEDULE_DEVIATION")
SCHEDULE_RULE = dict(
    clock="publisher-process monotonic, absolutely scheduled from the observer COVERAGE_START UTC",
    first_offset="lead_in_windows*W + nominal_gap/2 after coverage start",
    gap="nominal_gap*(1+u), u ~ U(-jitter_fraction, +jitter_fraction) from the jitter stream, per gap",
    end_rule=("publish only while scheduled offset <= (lead_in_windows+eligible_windows+post_roll_windows)*W - nominal_gap/2; "
              "the cut is made only at the end of the excluded post-roll, never inside an eligible window"),
    completeness=("every offset the stream places below the end of the last eligible window is published: the stop boundary lies at least "
                  "one maximum gap beyond that end, so the train must cross it before stopping"),
    pacing="never waits for PUBACK before the next scheduled publish",
)
SEED_RULE = dict(
    device_seed='int(sha256("g5c-v2c|<run_id>|<device>").hexdigest()[:8], 16)',
    stream_seed='int(sha256("<device_seed>|<stream>").hexdigest()[:16], 16), streams "jitter" and "size"',
    generator="Python random.Random(stream_seed): uniform() for jitter, randint() for payload size",
)


def device_seed(run_id, device):
    return int(hashlib.sha256(f"{SEED_PREFIX}|{run_id}|{device}".encode("utf-8")).hexdigest()[:8], 16)


def window_ns(config):
    return config["window_duration_ms"] * 1_000_000


def eligible_end_ns(config):
    return (config["lead_in_windows"] + config["eligible_windows"]) * window_ns(config)


def publishing_end_ns(config):
    return eligible_end_ns(config) + config["post_roll_windows"] * window_ns(config)


def max_gap_ns(profile):
    return round(profile["nominal_gap_ns"] * (1 + profile["jitter_fraction"]))


def stop_boundary_ns(config, profile):
    return publishing_end_ns(config) - profile["nominal_gap_ns"] // 2


def window_roles(config):
    """{window index: role} for every window of the run."""
    lead_in, eligible = config["lead_in_windows"], config["eligible_windows"]
    return {index: "LEAD_IN" if index < lead_in else "ELIGIBLE" if index < lead_in + eligible else "POST_ROLL"
            for index in range(config["planned_window_count"])}


def scoring_eligible_indices(config):
    return [index for index, role in window_roles(config).items() if role == "ELIGIBLE"]


def config_problems(config):
    """Structural problems of a v2 run config (empty when sound)."""
    problems = []
    geometry = [config.get(k) for k in ("lead_in_windows", "eligible_windows", "post_roll_windows")]
    if not all(type(v) is int and v >= 1 for v in geometry):
        return ["lead-in, eligible and post-roll window counts must be integers >= 1"]
    lead_in, eligible, post_roll = geometry
    if config.get("planned_window_count") != lead_in + eligible + post_roll:
        problems.append("planned_window_count must equal lead_in + eligible + post_roll")
    if config.get("eligible_window_indices") != [lead_in, lead_in + eligible - 1]:
        problems.append("eligible_window_indices must span exactly the eligible windows")
    if not (type(config.get("window_duration_ms")) is int and config["window_duration_ms"] > 0):
        return problems + ["window_duration_ms must be a positive integer"]
    for device, spec in config.get("devices", {}).items():
        profile = spec["profile_definition"]
        margin = stop_boundary_ns(config, profile) - eligible_end_ns(config)
        if margin < max_gap_ns(profile):
            problems.append(f"{device}: the post-roll leaves {margin} ns beyond the last eligible window, less than one maximum gap "
                            f"({max_gap_ns(profile)} ns), so the end rule could still shorten an eligible window")
    return problems


def run_config(run_id, plan, *, kind, window_duration_ms, registry, eligible_windows=ELIGIBLE_WINDOWS,
               lead_in_windows=LEAD_IN_WINDOWS, post_roll_windows=POST_ROLL_WINDOWS):
    if kind not in plans.KINDS or plan not in plans.PLANS or not IDENTIFIER.fullmatch(run_id):
        raise ValueError("invalid run config request")
    devices = {}
    entries = {entry.device: entry for entry in registry.devices}
    for device, profile in plans.PLANS[plan].items():
        entry = entries[device]
        seed = device_seed(run_id, device)
        devices[device] = dict(
            profile=profile, profile_definition=copy.deepcopy(plans.PROFILES[profile]),
            username=entry.username, client_id=entry.client_id, telemetry_topic=entry.telemetry_topic,
            device_seed=seed, jitter_seed=plans.stream_seed(seed, "jitter"),
            size_seed=plans.stream_seed(seed, "size") if plans.PROFILES[profile]["payload"]["kind"] != "fixed" else None)
    total = lead_in_windows + eligible_windows + post_roll_windows
    config = dict(
        schema=RUN_CONFIG_SCHEMA, schema_version=SCHEMA_VERSION, generator_version=GENERATOR_VERSION, kind=kind,
        run_id=run_id, plan=plan, window_duration_ms=window_duration_ms, planned_window_count=total,
        lead_in_windows=lead_in_windows, eligible_windows=eligible_windows, post_roll_windows=post_roll_windows,
        eligible_window_indices=[lead_in_windows, lead_in_windows + eligible_windows - 1],
        window_roles=dict(lead_in=[0, lead_in_windows - 1], eligible=[lead_in_windows, lead_in_windows + eligible_windows - 1],
                          post_roll=[lead_in_windows + eligible_windows, total - 1]),  # inclusive [first, last] window indices
        qos=1, retain=False, registry_sha256=registry.sha256, schedule_rule=SCHEDULE_RULE, seed_rule=SEED_RULE, devices=devices)
    problems = config_problems(config)
    if problems:
        raise ValueError("; ".join(problems))
    return config


def counterfactual_config(v1_config, post_roll_windows=POST_ROLL_WINDOWS):
    """ANALYSIS ONLY: the v2 rule applied to an existing v1 run config with its OWN seeds (a paired comparison on the same jitter streams).
    Real v2 runs use run_config() with v2 seeds; this never creates or changes a plan."""
    config = copy.deepcopy(v1_config)
    config.pop("lead_out_windows", None)
    config.update(generator_version=GENERATOR_VERSION, post_roll_windows=post_roll_windows,
                  planned_window_count=config["lead_in_windows"] + config["eligible_windows"] + post_roll_windows)
    return config


def schedule(config, device):
    """Deterministic [(sequence, offset_ns_from_coverage_start, payload_bytes)] under the v2 rule."""
    spec = config["devices"][device]
    profile = spec["profile_definition"]
    gap, fraction, size_rule = profile["nominal_gap_ns"], profile["jitter_fraction"], profile["payload"]
    offset = config["lead_in_windows"] * window_ns(config) + gap // 2
    last_allowed = stop_boundary_ns(config, profile)
    jitter = random.Random(spec["jitter_seed"])
    sizes = random.Random(spec["size_seed"]) if spec["size_seed"] is not None else None
    items, sequence = [], 0
    while offset <= last_allowed:
        sequence += 1
        size = size_rule["bytes"] if size_rule["kind"] == "fixed" else sizes.randint(size_rule["low"], size_rule["high"])
        items.append((sequence, offset, size))
        offset += round(gap * (1 + jitter.uniform(-fraction, fraction)))
    return items


def verify_schedule(config, device):
    """Re-check a schedule against the declared law WITHOUT reusing schedule()'s loop. Returns a list of problems (empty when sound)."""
    spec = config["devices"][device]
    profile = spec["profile_definition"]
    gap, fraction, size_rule = profile["nominal_gap_ns"], profile["jitter_fraction"], profile["payload"]
    items = schedule(config, device)
    problems = []
    if not items:
        return ["empty schedule"]
    if [s for s, _, _ in items] != list(range(1, len(items) + 1)):
        problems.append("sequence numbers are not 1..n")
    offsets = [o for _, o, _ in items]
    if offsets[0] != config["lead_in_windows"] * window_ns(config) + gap // 2:
        problems.append("first offset differs from lead_in*W + gap/2")
    if any(o < config["lead_in_windows"] * window_ns(config) for o in offsets):
        problems.append("a message lies inside the lead-in")
    low, high = gap * (1 - fraction) - 1, gap * (1 + fraction) + 1
    if any(not low <= b - a <= high for a, b in zip(offsets, offsets[1:])):
        problems.append("a gap lies outside nominal*(1 +/- jitter_fraction)")
    boundary = stop_boundary_ns(config, profile)
    if offsets[-1] > boundary:
        problems.append("a message lies beyond the stop boundary")
    jitter = random.Random(spec["jitter_seed"])  # maximality: one more draw must overshoot the boundary
    next_gaps = [round(gap * (1 + jitter.uniform(-fraction, fraction))) for _ in range(len(items))]
    if offsets[-1] + next_gaps[-1] <= boundary:
        problems.append("the schedule stopped before the stop boundary")
    if offsets[-1] < eligible_end_ns(config):
        problems.append("the train does not cross the end of the last eligible window")
    if size_rule["kind"] == "fixed":
        if {s for _, _, s in items} != {size_rule["bytes"]}:
            problems.append("fixed payload size violated")
    elif not all(type(s) is int and size_rule["low"] <= s <= size_rule["high"] for _, _, s in items):
        problems.append("payload size outside the declared range")
    return problems


def planned_window_features(offsets_ns, sizes, window_count, window_duration_ns):
    """PLANNED (not observed) per-window Gate 5B measures from receive offsets, using the frozen observation.windowing.measures and the
    same bookkeeping as WindowEngine (windows close in order; last_delivery_age looks only backwards). Coverage is taken as COMPLETE."""
    buckets = {k: [] for k in range(window_count)}
    for offset, size in zip(offsets_ns, sizes):
        index = offset // window_duration_ns
        if 0 <= index < window_count:
            buckets[index].append((offset, size))
    out, last = {}, None
    for k in range(window_count):
        counted = sorted(buckets[k])
        if counted:
            last = counted[-1][0]
        out[k] = measures(counted, (k + 1) * window_duration_ns, last, True)
    return out


def planned_vector(entry):
    """The six-feature vector of one planned window, or None when any measure is not VALUE (never filled in)."""
    if any(entry[name]["status"] != "VALUE" for name in PREDICTOR_CANDIDATES):
        return None
    return [float(entry[name]["value"]) for name in PREDICTOR_CANDIDATES]


def planned_features(config, device, shift_ns=0):
    """Planned window features of one device's v2 schedule, optionally shifted by a constant receive delay."""
    items = schedule(config, device)
    return planned_window_features([o + shift_ns for _, o, _ in items], [s for _, _, s in items],
                                    config["planned_window_count"], window_ns(config))


def termination_report(config, device, attempts):
    """Experimental COMPLETION (did the publisher run its plan through the eligible windows and the post-roll?) kept apart from actual
    MQTT TIMING (lateness of the attempts). attempts: ledger ATTEMPT-like dicts with sequence, scheduled_offset_ns, attempt_offset_ns."""
    planned = schedule(config, device)
    by_sequence = {a["sequence"]: a for a in attempts}
    planned_sequences = {s for s, _, _ in planned}
    deviating = [s for s, offset, _ in planned if s in by_sequence and by_sequence[s]["scheduled_offset_ns"] != offset]
    unplanned = sorted(set(by_sequence) - planned_sequences)
    missing = [s for s, _, _ in planned if s not in by_sequence]
    boundary = eligible_end_ns(config)
    missing_in_eligible = [s for s, offset, _ in planned if s not in by_sequence and offset < boundary]
    crossed = any(offset >= boundary and s in by_sequence for s, offset, _ in planned)
    verdict = ("SCHEDULE_DEVIATION" if deviating or unplanned
               else "ELIGIBLE_WINDOWS_TRUNCATED" if missing_in_eligible or not crossed
               else "POST_ROLL_INCOMPLETE" if missing else "TERMINATION_OK")
    lateness = [a["attempt_offset_ns"] - a["scheduled_offset_ns"] for a in attempts if a["sequence"] in planned_sequences]
    return dict(
        verdict=verdict,
        experiment_completion=dict(planned_messages=len(planned), attempted_messages=len(attempts) - len(unplanned),
                                   missing_sequences=len(missing), missing_before_eligible_end=len(missing_in_eligible),
                                   train_crossed_eligible_end=crossed, deviating_sequences=len(deviating),
                                   unplanned_sequences=len(unplanned)),
        actual_timing=dict(attempts_with_lateness=len(lateness), max_lateness_ns=max(lateness) if lateness else None,
                           mean_lateness_ns=(sum(lateness) / len(lateness)) if lateness else None,
                           note="lateness describes MQTT/host timing; it does not decide completion"))
