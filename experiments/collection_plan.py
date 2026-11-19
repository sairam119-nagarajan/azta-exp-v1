"""Gate 5C deterministic collection plan builder/validator (controller decisions C1-C6, 17 October 2026).

Builds frozen workload plans and the matching azta.collection.manifest v1 planning entries. It
collects nothing, trains nothing and touches no broker. All values below are controller-ratified
SYNTHETIC research-design parameters, not measured real-world IoT reporting rates. W = 10,000 ms is
a pre-registered design window (slowest profile nominally ~10 observations per window), not an
empirically optimal W, and no latency SLA is claimed.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import random
import re
import sys

from observation import manifest as manifest_module
from observation.registry import DeviceRegistry
from observation.schema import IDENTIFIER, SCHEMA_FINGERPRINT, canonical, observation_config_sha256, sha256_text

PLAN_SCHEMA = "azta.collection.plan"
RUN_CONFIG_SCHEMA = "azta.collection.run_config"
SCHEMA_VERSION = 1
GENERATOR_VERSION = "gate5c-workload-1"
SEED_PREFIX = "g5c-v1"
SUBSCRIPTION_QOS = 1
KINDS = ("SCIENTIFIC", "WRAPPER_VALIDATION_NOT_DATA", "FUNCTIONAL_TEST")
DESIGN_W_MS = 10_000
SCIENTIFIC_WINDOW_COUNT = 62  # window 0 lead-in, 1-60 eligible, 61 lead-out
PROFILES = {
    "S": dict(profile="S", nominal_gap_ns=1_000_000_000, jitter_fraction=0.1,
              payload=dict(kind="fixed", bytes=128)),
    "V": dict(profile="V", nominal_gap_ns=200_000_000, jitter_fraction=0.1,
              payload=dict(kind="uniform_int", low=128, high=256)),
}
PLANS = {"A": {"device01": "S", "device02": "V"}, "B": {"device01": "V", "device02": "S"}}
ALLOCATION = {"B_train": {"A": 5, "B": 5}, "B_val": {"A": 3, "B": 3}, "B_cal": {"A": 4, "B": 4}}
SUBSTITUTES = {"B_train": {"A": 1, "B": 1}, "B_val": {"A": 1, "B": 1}, "B_cal": {"A": 1, "B": 1}}
SCHEDULE_RULE = dict(
    clock="publisher-process monotonic, absolutely scheduled from the observer COVERAGE_START UTC",
    first_offset="lead_in_windows*W + nominal_gap/2 after coverage start",
    gap="nominal_gap*(1+u), u ~ U(-jitter_fraction, +jitter_fraction) from the jitter stream, per gap",
    end_rule="publish only while scheduled offset <= (lead_in_windows+eligible_windows)*W - nominal_gap/2",
    pacing="never waits for PUBACK before the next scheduled publish",
)
SEED_RULE = dict(
    device_seed='int(sha256("g5c-v1|<run_id>|<device>").hexdigest()[:8], 16)',
    stream_seed='int(sha256("<device_seed>|<stream>").hexdigest()[:16], 16), streams "jitter" and "size"',
    generator="Python random.Random(stream_seed): uniform() for jitter, randint() for payload size",
)
ORDER_SEED_RULE = ('int(sha256("g5c-v1|run-order").hexdigest()[:8], 16); one random.Random(seed) stream: draw 1 = '
                   'shuffle(scientific canonical list); draw 2 = shuffle(substitutes canonical list); draws 3.. = further '
                   'shuffles of the scientific canonical list. The first scientific draw satisfying ORDER_CONSTRAINTS is the '
                   'run order (constrained randomization; amended before any collection, seed unchanged)')
BLOCK_SIZE = 6
MAX_PARTITION_STREAK = 2
MAX_ORDER_ATTEMPTS = 1_000_000
ORDER_CONSTRAINTS = dict(
    block_size=BLOCK_SIZE, max_consecutive_same_partition=MAX_PARTITION_STREAK,
    each_block_contains_every_partition=True, each_block_plan_balance="3 A / 3 B (the exact feasible optimum)",
    canonical_list="partitions in ALLOCATION order (B_train, B_val, B_cal), plan A before plan B within each, one entry per run",
    max_attempts=MAX_ORDER_ATTEMPTS)


def _h32(text):
    return int(hashlib.sha256(text.encode("utf-8")).hexdigest()[:8], 16)


def device_seed(run_id, device):
    return _h32(f"{SEED_PREFIX}|{run_id}|{device}")


def stream_seed(seed, stream):
    return int(hashlib.sha256(f"{seed}|{stream}".encode("utf-8")).hexdigest()[:16], 16)


def order_seed():
    return _h32(f"{SEED_PREFIX}|run-order")


def order_violations(sequence):
    """Constraint violations of a scientific run order; sequence = [(partition, plan)] in execution order."""
    problems = []
    streak = 0
    for index, (part, _plan) in enumerate(sequence):
        streak = streak + 1 if index and sequence[index - 1][0] == part else 1
        if streak > MAX_PARTITION_STREAK:
            problems.append(f"run {index + 1}: more than {MAX_PARTITION_STREAK} consecutive {part} runs")
    for start in range(0, len(sequence), BLOCK_SIZE):
        block = sequence[start:start + BLOCK_SIZE]
        label = f"runs {start + 1}-{start + len(block)}"
        if {part for part, _ in block} != set(ALLOCATION):
            problems.append(f"{label}: block lacks a partition")
        if abs(sum(plan == "A" for _, plan in block) - sum(plan == "B" for _, plan in block)) > len(block) % 2:
            problems.append(f"{label}: block plan A/B not balanced")
    return problems


def constrained_order(seed):
    """Deterministic constrained randomization of the scientific order and the (unchanged) substitute order.

    Returns (scientific, substitutes, attempt): attempt is the 1-based scientific draw that was accepted.
    """
    rng = random.Random(seed)
    canonical_list = [(part, plan) for part, counts in ALLOCATION.items() for plan, n in counts.items() for _ in range(n)]
    substitutes = [(part, plan) for part, counts in SUBSTITUTES.items() for plan, n in counts.items() for _ in range(n)]
    candidate = list(canonical_list)
    rng.shuffle(candidate)  # draw 1 = the original unconstrained v1 order
    rng.shuffle(substitutes)  # draw 2 = the original v1 substitute order, preserved exactly
    attempt = 1
    while order_violations(candidate):
        if attempt >= MAX_ORDER_ATTEMPTS:
            raise ValueError("no constrained run order found within the attempt limit")
        candidate = list(canonical_list)
        rng.shuffle(candidate)
        attempt += 1
    return candidate, substitutes, attempt


def digest(value):
    """Canonical-JSON SHA-256 (line-ending independent)."""
    return sha256_text(canonical(value))


def run_config(run_id, plan, *, kind, window_duration_ms, window_count, registry):
    if kind not in KINDS or plan not in PLANS or not IDENTIFIER.fullmatch(run_id):
        raise ValueError("invalid run config request")
    if window_count < 3:
        raise ValueError("a run needs a lead-in, at least one eligible and a lead-out window")
    devices = {}
    entries = {entry.device: entry for entry in registry.devices}
    for device, profile in PLANS[plan].items():
        entry = entries[device]
        seed = device_seed(run_id, device)
        devices[device] = dict(
            profile=profile, profile_definition=copy.deepcopy(PROFILES[profile]),
            username=entry.username, client_id=entry.client_id, telemetry_topic=entry.telemetry_topic,
            device_seed=seed, jitter_seed=stream_seed(seed, "jitter"),
            size_seed=stream_seed(seed, "size") if PROFILES[profile]["payload"]["kind"] != "fixed" else None)
    return dict(
        schema=RUN_CONFIG_SCHEMA, schema_version=SCHEMA_VERSION, generator_version=GENERATOR_VERSION, kind=kind,
        run_id=run_id, plan=plan, window_duration_ms=window_duration_ms, planned_window_count=window_count,
        lead_in_windows=1, eligible_windows=window_count - 2, lead_out_windows=1,
        eligible_window_indices=[1, window_count - 2], qos=1, retain=False, registry_sha256=registry.sha256,
        schedule_rule=SCHEDULE_RULE, seed_rule=SEED_RULE, devices=devices)


def build_plan(*, kind, plan_id, registry, planning_base_commit, window_duration_ms=DESIGN_W_MS,
               window_count=SCIENTIFIC_WINDOW_COUNT, cells=None):
    """cells: for non-scientific kinds, explicit [(run_id, plan, partition_or_None)]."""
    if kind not in KINDS or not IDENTIFIER.fullmatch(plan_id):
        raise ValueError("invalid plan kind/id")
    if not (isinstance(planning_base_commit, str) and manifest_module.COMMIT.fullmatch(planning_base_commit)):
        raise ValueError("planning_base_commit must be a full commit hash")
    seed = None
    attempt = None
    table = []
    if kind == "SCIENTIFIC":
        if cells is not None:
            raise ValueError("scientific cells are generated, never supplied")
        seed = order_seed()
        scientific, substitutes, attempt = constrained_order(seed)
        table = ([(f"g5c-r{i:02d}", "SCIENTIFIC", part, plan) for i, (part, plan) in enumerate(scientific, 1)]
                 + [(f"g5c-s{i:02d}", "SUBSTITUTE", part, plan) for i, (part, plan) in enumerate(substitutes, 1)])
    else:
        if not cells:
            raise ValueError("non-scientific plans need explicit cells")
        table = [(run, kind, part, plan) for run, plan, part in cells]
    runs, rows = {}, []
    for order, (run, role, part, plan) in enumerate(table, 1):
        config = run_config(run, plan, kind=kind, window_duration_ms=window_duration_ms,
                            window_count=window_count, registry=registry)
        runs[run] = config
        rows.append(dict(order=order, run_id=run, role=role, intended_partition=part, plan=plan,
                         workload_config_sha256=digest(config)))
    result = dict(
        schema=PLAN_SCHEMA, schema_version=SCHEMA_VERSION, plan_id=plan_id, kind=kind,
        generator_version=GENERATOR_VERSION,
        design_basis=("controller decisions C1-C6 (17 October 2026): synthetic benign profiles; W is a "
                      "pre-registered design window, not an empirically optimal W; no latency SLA"),
        window_duration_ms=window_duration_ms, planned_window_count=window_count,
        window_roles=dict(lead_in=[0], eligible=[1, window_count - 2], lead_out=[window_count - 1]),
        profiles=copy.deepcopy(PROFILES), plans=copy.deepcopy(PLANS),
        allocation=copy.deepcopy(ALLOCATION) if kind == "SCIENTIFIC" else None,
        substitutes=copy.deepcopy(SUBSTITUTES) if kind == "SCIENTIFIC" else None,
        seed_rule=SEED_RULE, order_seed_rule=ORDER_SEED_RULE if kind == "SCIENTIFIC" else None,
        order_seed=seed, schedule_rule=SCHEDULE_RULE, registry_sha256=registry.sha256,
        schema_fingerprint=SCHEMA_FINGERPRINT, subscription_qos=SUBSCRIPTION_QOS,
        observation_config_sha256=observation_config_sha256(window_duration_ms * 1_000_000, registry.sha256,
                                                             SUBSCRIPTION_QOS),
        planning_base_commit=planning_base_commit, cells=rows, runs=runs)
    if kind == "SCIENTIFIC":  # added only here: committed non-scientific plans keep their digests
        result["order_constraints"] = copy.deepcopy(ORDER_CONSTRAINTS)
        result["order_accepted_attempt"] = attempt
    return result


def validate_plan(plan, registry):
    """Raise ValueError on any structural, balance, seed or digest inconsistency."""
    errors = []

    def req(ok, message):
        if not ok:
            errors.append(message)
    req(plan.get("schema") == PLAN_SCHEMA and plan.get("schema_version") == SCHEMA_VERSION, "plan schema")
    req(plan.get("kind") in KINDS, "plan kind")
    req(plan.get("registry_sha256") == registry.sha256, "registry digest differs")
    req(plan.get("schema_fingerprint") == SCHEMA_FINGERPRINT, "schema fingerprint differs")
    w, count = plan.get("window_duration_ms"), plan.get("planned_window_count")
    req(type(w) is int and w > 0 and type(count) is int and count >= 3, "window parameters")
    if errors:
        raise ValueError("; ".join(errors))
    req(plan["observation_config_sha256"] == observation_config_sha256(w * 1_000_000, registry.sha256, SUBSCRIPTION_QOS),
        "observation config digest")
    cells, runs = plan["cells"], plan["runs"]
    ids = [c["run_id"] for c in cells]
    req(len(ids) == len(set(ids)) and set(ids) == set(runs), "run ids unique and matching run configs")
    req([c["order"] for c in cells] == list(range(1, len(cells) + 1)), "execution order contiguous")
    seeds = []
    for cell in cells:
        config = runs.get(cell["run_id"], {})
        req(cell["workload_config_sha256"] == digest(config), f'{cell["run_id"]}: workload digest')
        expected = run_config(cell["run_id"], cell["plan"], kind=plan["kind"], window_duration_ms=w,
                              window_count=count, registry=registry)
        req(config == expected, f'{cell["run_id"]}: run config differs from the deterministic rule')
        seeds += [d["device_seed"] for d in config.get("devices", {}).values()]
        for device, spec in config.get("devices", {}).items():
            bound = registry.bind(spec["telemetry_topic"])
            req(spec["telemetry_topic"].endswith("/telemetry") and bound is not None and bound.device == device,
                f'{cell["run_id"]}: topic/device mapping')
    req(len(seeds) == len(set(seeds)), "device seeds must be unique")
    if plan["kind"] == "SCIENTIFIC":
        rebuilt = build_plan(kind="SCIENTIFIC", plan_id=plan["plan_id"], registry=registry,
                             planning_base_commit=plan["planning_base_commit"])
        req(plan == rebuilt, "scientific plan differs from deterministic regeneration")
        for role, table in (("SCIENTIFIC", ALLOCATION), ("SUBSTITUTE", SUBSTITUTES)):
            counts = {}
            for cell in cells:
                if cell["role"] == role:
                    counts.setdefault(cell["intended_partition"], {}).setdefault(cell["plan"], 0)
                    counts[cell["intended_partition"]][cell["plan"]] += 1
            req(counts == table, f"{role} allocation/balance")
        req(all(c["intended_partition"] in manifest_module.BENIGN_PARTITIONS for c in cells), "benign partitions only")
        req(all((c["role"] == "SCIENTIFIC") == c["run_id"].startswith("g5c-r") for c in cells), "neutral run ids")
        req(w == DESIGN_W_MS and count == SCIENTIFIC_WINDOW_COUNT, "frozen W / window count")
        sequence = [(c["intended_partition"], c["plan"]) for c in cells if c["role"] == "SCIENTIFIC"]
        req(not order_violations(sequence), f"scientific run order violates the interleaving constraints: {order_violations(sequence)}")
    else:
        req(all(c["role"] == plan["kind"] for c in cells), "non-scientific roles")
        req(not any(re.fullmatch(r"g5c-[rs]\d\d", c["run_id"]) for c in cells), "non-scientific runs never use g5c-rNN/g5c-sNN ids")
    if errors:
        raise ValueError("; ".join(errors))
    return plan


def manifest_entries(plan, *, manifest_id, plan_path, created_utc):
    """Header, one RUN_PLANNED per cell (execution order) and PARTITIONS_FROZEN."""
    if plan["kind"] == "FUNCTIONAL_TEST":
        raise ValueError("FUNCTIONAL_TEST plans never get a collection manifest")
    purpose = ("GATE5C_SCIENTIFIC_BENIGN_COLLECTION" if plan["kind"] == "SCIENTIFIC" else "WRAPPER_VALIDATION_NOT_DATA")
    purpose += f" plan={plan_path} plan_sha256={digest(plan)} planning_base_commit={plan['planning_base_commit']}"
    entries = []
    entries.append(manifest_module.make_entry(entries, "MANIFEST_HEADER", dict(
        manifest_id=manifest_id, created_utc=created_utc, purpose=purpose, assignment_unit="collection_run",
        allowed_partitions=list(manifest_module.PARTITIONS), observation_schema_fingerprint=SCHEMA_FINGERPRINT,
        observation_config_sha256=plan["observation_config_sha256"],
        window_duration_ns=plan["window_duration_ms"] * 1_000_000, registry_sha256=plan["registry_sha256"])))
    for cell in plan["cells"]:
        entries.append(manifest_module.make_entry(entries, "RUN_PLANNED", dict(
            collection_run_id=cell["run_id"], devices=sorted(plan["runs"][cell["run_id"]]["devices"]),
            workload_profile_id=f'gate5c-v1-plan{cell["plan"]}', scenario_designation="BENIGN", attack_informed=False,
            intended_partition=cell["intended_partition"], planned_window_count=plan["planned_window_count"],
            workload_config_sha256=cell["workload_config_sha256"], planned_utc=created_utc)))
    assignments = {cell["run_id"]: cell["intended_partition"] for cell in plan["cells"]}
    entries.append(manifest_module.make_entry(entries, "PARTITIONS_FROZEN", dict(
        frozen_utc=created_utc, assignments=assignments,
        assignments_sha256=manifest_module.assignments_digest(assignments))))
    manifest_module.validate(entries)
    return entries


def write_json_exclusive(path, value):
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def write_manifest_exclusive(path, entries):
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        for entry in entries:
            stream.write(canonical(entry) + "\n")


def load_plan(path):
    with Path(path).open(encoding="utf-8") as stream:
        return json.load(stream)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    build = sub.add_parser("build")
    build.add_argument("--kind", required=True, choices=KINDS)
    build.add_argument("--plan-id", required=True)
    build.add_argument("--plan-out", required=True)
    build.add_argument("--planning-base-commit", required=True)
    build.add_argument("--window-count", type=int)
    build.add_argument("--cell", action="append", default=[], help="run_id:plan[:partition] (non-scientific)")
    build.add_argument("--manifest-out")
    build.add_argument("--manifest-id")
    build.add_argument("--plan-path-label", help="repository-relative plan path recorded in the manifest header")
    build.add_argument("--created-utc")
    check = sub.add_parser("validate")
    check.add_argument("--plan", required=True)
    check.add_argument("--manifest")
    for item in (build, check):
        item.add_argument("--registry", default="/app/configs/observation/device_registry.json")
    args = parser.parse_args(argv)
    try:
        registry = DeviceRegistry.load(args.registry)
        if args.action == "build":
            cells = None
            if args.kind != "SCIENTIFIC":
                cells = []
                for text in args.cell:
                    parts = text.split(":")
                    cells.append((parts[0], parts[1], parts[2] if len(parts) > 2 else None))
            plan = build_plan(kind=args.kind, plan_id=args.plan_id, registry=registry,
                              planning_base_commit=args.planning_base_commit, cells=cells,
                              window_count=args.window_count or SCIENTIFIC_WINDOW_COUNT)
            validate_plan(plan, registry)
            entries = None
            if args.manifest_out:
                entries = manifest_entries(plan, manifest_id=args.manifest_id, plan_path=args.plan_path_label,
                                           created_utc=args.created_utc)
            write_json_exclusive(args.plan_out, plan)
            if entries is not None:
                write_manifest_exclusive(args.manifest_out, entries)
            print(f"PLAN_BUILT {plan['plan_id']} kind={plan['kind']} cells={len(plan['cells'])} "
                  f"plan_sha256={digest(plan)}" + (f" manifest_entries={len(entries)}" if entries else ""))
        else:
            plan = validate_plan(load_plan(args.plan), registry)
            message = f"PLAN_VALID {plan['plan_id']} kind={plan['kind']} cells={len(plan['cells'])} plan_sha256={digest(plan)}"
            if args.manifest:
                state = manifest_module.validate(manifest_module.read_entries(args.manifest))
                check_manifest_against_plan(state, plan)
                message += f" manifest_runs={len(state['planned'])} collected={len(state['collected'])} voided={len(state['voided'])}"
            print(message)
        return 0
    except (ValueError, OSError, KeyError) as exc:
        print(f"PLAN_INVALID {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def check_manifest_against_plan(state, plan):
    header = state["header"]
    if header["observation_config_sha256"] != plan["observation_config_sha256"] or \
            header["window_duration_ns"] != plan["window_duration_ms"] * 1_000_000 or \
            header["registry_sha256"] != plan["registry_sha256"] or f"plan_sha256={digest(plan)}" not in header["purpose"]:
        raise ValueError("manifest header does not match the plan")
    cells = {c["run_id"]: c for c in plan["cells"]}
    if set(state["planned"]) != set(cells):
        raise ValueError("manifest RUN_PLANNED set differs from the plan cells")
    for run, entry in state["planned"].items():
        cell = cells[run]
        if (entry["intended_partition"] != cell["intended_partition"]
                or entry["workload_config_sha256"] != cell["workload_config_sha256"]
                or entry["planned_window_count"] != plan["planned_window_count"]
                or entry["devices"] != sorted(plan["runs"][run]["devices"])):
            raise ValueError(f"manifest entry {run} differs from the plan")
    if not state["frozen"]:
        raise ValueError("manifest partitions are not frozen")
    return True


if __name__ == "__main__":
    raise SystemExit(main())
