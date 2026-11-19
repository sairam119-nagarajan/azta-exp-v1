"""Gate 5F.2 offline plan builder/validator for a PROSPECTIVE workload-v2 D_shadow / D_test campaign. ENGINEERING CANDIDATE.

STATUS: nothing here is approved, frozen or used by any collected run. It collects nothing, trains nothing and touches no broker. The
frozen Gate 5C plan, generator and manifest (experiments/collection_plan.py, collection_workload.py, gate5c_workload_v1.json) are not
edited and their tools refuse these plans (a different schema name), so a v2 plan can never be mistaken for, or merged into, the
accepted v1 campaign. A plan built here is `UNAPPROVED_CANDIDATE` until the Main Controller supplies an approval reference; the v2
runner refuses a COLLECTION run for an unapproved plan.

What the plan guarantees by construction and re-checks on validation:
  * Independent partitions (Gate 5F.3): whole runs are assigned to CAL_V2 (a NEW benign calibration of the frozen models for workload v2,
    separate from the consumed historical B_cal), D_shadow (development of operating parameters) or D_test (held-out final test) before
    any collection, in a versioned (schema 2) manifest whose vocabulary excludes B_train, B_val and B_cal; neutral run identifiers
    (g5f-rNN / g5f-sNN) do not reveal the partition; run IDs and device seeds are pairwise unique, never shared between partitions, and
    disjoint from the accepted v1 plan when it is supplied.
  * Counterbalancing: each partition has equal plan A and plan B counts (device01/device02 swap the S and V profiles).
  * No hidden numbers: the allocation and substitute counts are explicit arguments; this module chooses none.
  * Benign scenarios only: attack workloads are not defined, so ATTACK_* cells are refused until they are separately specified.
  * Model scorability is stated, not assumed: the plan records whether the registry, observation configuration and device profiles are
    ones the frozen S/V autoencoders can score, and why not otherwise (it never makes an incompatible device score-ready).
"""
import argparse
import copy
import hashlib
import json
import math
from pathlib import Path
import random
import re
import sys

from experiments import collection_plan as plans
from experiments import collection_workload_v2 as v2
from observation import manifest as manifest_module
from observation import manifest_v2
from observation.registry import DeviceRegistry
from observation.schema import IDENTIFIER, SCHEMA_FINGERPRINT, observation_config_sha256
from preprocessing.gate5d_data import PIN as FROZEN_PIN

PLAN_SCHEMA_V2 = "azta.collection.plan_candidate"
SCHEMA_VERSION = 1
PARTITIONS_V2 = manifest_v2.PARTITIONS          # ("CAL_V2", "D_shadow", "D_test")
FROZEN_MODEL_ROUTES = {"S": "A-S-k3-seed0", "V": "A-V-k3-seed0"}
FROZEN_W_MS = plans.DESIGN_W_MS
FROZEN_ELIGIBLE = v2.ELIGIBLE_WINDOWS
FROZEN_WINDOW_COUNT = v2.LEAD_IN_WINDOWS + v2.ELIGIBLE_WINDOWS + v2.POST_ROLL_WINDOWS
RUN_PATTERN = re.compile(r"g5f-[rs]\d\d\Z")
BLOCK_SIZE = 6
MAX_ORDER_ATTEMPTS = 1_000_000
ORDER_SEED_RULE = ('int(sha256("g5f-v2|run-order|<plan_id>").hexdigest()[:8], 16); one random.Random(seed) stream: draw 1 = shuffle of the '
                   'scientific canonical list (partitions in allocation order, plan A before B); draw 2 = shuffle of the substitute '
                   'list; further shuffles of the scientific list until the interleaving constraints hold')
DESIGN_BASIS = ("ENGINEERING CANDIDATE (Gate 5F.2): prospective D_shadow/D_test design on the unadopted workload v2 (post-roll). Not "
                "approved, not frozen, not collected. Synthetic benign profiles only; W is the pre-registered design window.")


def order_seed(plan_id):
    return int(hashlib.sha256(f"g5f-v2|run-order|{plan_id}".encode("utf-8")).hexdigest()[:8], 16)


def streak_limit(allocation):
    totals = sorted(sum(counts.values()) for counts in allocation.values())
    return max(2, math.ceil(totals[-1] / (totals[0] + 1)))


def order_violations(sequence, max_streak):
    problems, streak = [], 0
    for index, (part, _plan) in enumerate(sequence):
        streak = streak + 1 if index and sequence[index - 1][0] == part else 1
        if streak > max_streak:
            problems.append(f"run {index + 1}: more than {max_streak} consecutive {part} runs")
    for start in range(0, len(sequence), BLOCK_SIZE):
        block = sequence[start:start + BLOCK_SIZE]
        if abs(sum(p == "A" for _, p in block) - sum(p == "B" for _, p in block)) > len(block) % 2:
            problems.append(f"runs {start + 1}-{start + len(block)}: block plan A/B not balanced")
    return problems


def _canonical(table):
    return [(part, plan) for part, counts in table.items() for plan, n in counts.items() for _ in range(n)]


def constrained_order(seed, allocation, substitutes):
    rng = random.Random(seed)
    canonical_list, substitute_list = _canonical(allocation), _canonical(substitutes)
    limit = streak_limit(allocation)
    candidate = list(canonical_list)
    rng.shuffle(candidate)
    rng.shuffle(substitute_list)
    attempt = 1
    while order_violations(candidate, limit):
        if attempt >= MAX_ORDER_ATTEMPTS:
            raise ValueError("no constrained run order found within the attempt limit")
        candidate = list(canonical_list)
        rng.shuffle(candidate)
        attempt += 1
    return candidate, substitute_list, attempt, limit


def _check_table(table, name, *, minimum):
    if not isinstance(table, dict) or set(table) != set(PARTITIONS_V2):
        raise ValueError(f"{name} must name exactly the partitions {PARTITIONS_V2}")
    for part, counts in table.items():
        if not isinstance(counts, dict) or set(counts) != {"A", "B"} or any(type(n) is not int or n < minimum for n in counts.values()):
            raise ValueError(f"{name}[{part}] needs integer counts for plans A and B (minimum {minimum})")
        if counts["A"] != counts["B"]:
            raise ValueError(f"{name}[{part}]: plan A and plan B counts must be equal (counterbalancing)")


def model_compatibility(registry, window_duration_ms, runs):
    """Whether the frozen S/V autoencoders can score windows of this plan, and exactly why not. Descriptive; it changes nothing."""
    config_sha = observation_config_sha256(window_duration_ms * 1_000_000, registry.sha256, plans.SUBSCRIPTION_QOS)
    profiles = {}
    for run, config in runs.items():
        for device, spec in config["devices"].items():
            profiles.setdefault(device, set()).add(spec["profile"])
    reasons = []
    if registry.sha256 != FROZEN_PIN["registry_sha256"]:
        reasons.append("REGISTRY_DIGEST_DIFFERS_FROM_THE_MODEL_PIN")
    if config_sha != FROZEN_PIN["observation_config_sha256"]:
        reasons.append("OBSERVATION_CONFIG_DIGEST_DIFFERS_FROM_THE_MODEL_PIN")
    unrouted = sorted(f"{d}:{p}" for d, ps in profiles.items() for p in ps if p not in FROZEN_MODEL_ROUTES)
    if unrouted:
        reasons.append("PROFILE_WITHOUT_A_FROZEN_MODEL:" + ",".join(unrouted))
    return dict(frozen_models=dict(FROZEN_MODEL_ROUTES), registry_sha256=registry.sha256,
                pinned_registry_sha256=FROZEN_PIN["registry_sha256"], observation_config_sha256=config_sha,
                pinned_observation_config_sha256=FROZEN_PIN["observation_config_sha256"],
                device_profiles={d: sorted(ps) for d, ps in sorted(profiles.items())}, scorable_by_frozen_models=not reasons,
                reasons=reasons, note="a False value means the engine refuses these windows (SCHEMA_MISMATCH / NO_APPROVED_PROFILE_ROUTE); "
                                      "nothing in this plan changes the models, the pins or the refusal")


def build_plan_v2(*, plan_id, registry, planning_base_commit, kind="SCIENTIFIC", allocation=None, substitutes=None, cells=None,
                  eligible_windows=FROZEN_ELIGIBLE, window_duration_ms=FROZEN_W_MS, approval_ref=None):
    if kind not in plans.KINDS or not IDENTIFIER.fullmatch(plan_id):
        raise ValueError("invalid plan kind/id")
    if not (isinstance(planning_base_commit, str) and manifest_module.COMMIT.fullmatch(planning_base_commit)):
        raise ValueError("planning_base_commit must be a full commit hash")
    if approval_ref is not None and not (isinstance(approval_ref, str) and IDENTIFIER.fullmatch(approval_ref)):
        raise ValueError("approval_ref must be an identifier or null")
    seed = attempt = limit = None
    if kind == "SCIENTIFIC":
        if cells is not None:
            raise ValueError("scientific cells are generated, never supplied")
        _check_table(allocation, "allocation", minimum=1)
        _check_table(substitutes, "substitutes", minimum=0)
        seed = order_seed(plan_id)
        scientific, substitute_list, attempt, limit = constrained_order(seed, allocation, substitutes)
        table = ([(f"g5f-r{i:02d}", "SCIENTIFIC", part, plan) for i, (part, plan) in enumerate(scientific, 1)]
                 + [(f"g5f-s{i:02d}", "SUBSTITUTE", part, plan) for i, (part, plan) in enumerate(substitute_list, 1)])
    else:
        if not cells or allocation is not None or substitutes is not None:
            raise ValueError("non-scientific plans need explicit cells and no allocation")
        if any(partition not in PARTITIONS_V2 for _, _, partition in cells):
            raise ValueError(f"cell partitions must be one of {PARTITIONS_V2}")
        table = [(run, kind, part, plan) for run, plan, part in cells]
    runs, rows = {}, []
    for order, (run, role, part, plan) in enumerate(table, 1):
        config = v2.run_config(run, plan, kind=kind, window_duration_ms=window_duration_ms, registry=registry,
                               eligible_windows=eligible_windows)
        runs[run] = config
        rows.append(dict(order=order, run_id=run, role=role, intended_partition=part, plan=plan, scenario_designation="BENIGN",
                         workload_config_sha256=plans.digest(config)))
    any_config = next(iter(runs.values()))
    plan = dict(
        schema=PLAN_SCHEMA_V2, schema_version=SCHEMA_VERSION, plan_id=plan_id, kind=kind, generator_version=v2.GENERATOR_VERSION,
        design_basis=DESIGN_BASIS, approval_status="APPROVED" if approval_ref else "UNAPPROVED_CANDIDATE", approval_ref=approval_ref,
        window_duration_ms=window_duration_ms, planned_window_count=any_config["planned_window_count"],
        eligible_windows=eligible_windows, post_roll_windows=v2.POST_ROLL_WINDOWS, lead_in_windows=v2.LEAD_IN_WINDOWS,
        window_roles=copy.deepcopy(any_config["window_roles"]), profiles=copy.deepcopy(plans.PROFILES), plans=copy.deepcopy(plans.PLANS),
        allocation=copy.deepcopy(allocation) if kind == "SCIENTIFIC" else None,
        substitutes=copy.deepcopy(substitutes) if kind == "SCIENTIFIC" else None,
        partition_policy=dict(partitions=list(PARTITIONS_V2), assignment_unit="collection_run", manifest_schema_version=manifest_v2.SCHEMA_VERSION,
                              rule="whole runs are assigned before collection; CAL_V2 is a new benign calibration partition for the frozen models "
                                   "(its statistics are separately versioned; the historical B_cal and its Gate 5E calibration stay baselines); "
                                   "D_shadow develops operating parameters; D_test is held out and never used for any selection; neutral run ids; "
                                   "no run or seed is shared across partitions"),
        seed_rule=v2.SEED_RULE, order_seed_rule=ORDER_SEED_RULE if kind == "SCIENTIFIC" else None, order_seed=seed,
        order_constraints=dict(block_size=BLOCK_SIZE, max_consecutive_same_partition=limit, max_attempts=MAX_ORDER_ATTEMPTS)
        if kind == "SCIENTIFIC" else None, order_accepted_attempt=attempt, schedule_rule=v2.SCHEDULE_RULE,
        registry_sha256=registry.sha256, schema_fingerprint=SCHEMA_FINGERPRINT, subscription_qos=plans.SUBSCRIPTION_QOS,
        observation_config_sha256=observation_config_sha256(window_duration_ms * 1_000_000, registry.sha256, plans.SUBSCRIPTION_QOS),
        planning_base_commit=planning_base_commit, frozen_model_compatibility=model_compatibility(registry, window_duration_ms, runs),
        cells=rows, runs=runs)
    return plan


def validate_plan_v2(plan, registry, *, v1_plan=None):
    """Raise ValueError on any structural, independence, seed, geometry or digest inconsistency."""
    errors = []

    def req(ok, message):
        if not ok:
            errors.append(message)
    req(plan.get("schema") == PLAN_SCHEMA_V2 and plan.get("schema_version") == SCHEMA_VERSION, "plan schema (v1 plans are refused here)")
    req(plan.get("kind") in plans.KINDS, "plan kind")
    req(plan.get("generator_version") == v2.GENERATOR_VERSION, "generator version")
    req(plan.get("registry_sha256") == registry.sha256, "registry digest differs")
    req(plan.get("schema_fingerprint") == SCHEMA_FINGERPRINT, "schema fingerprint differs")
    req((plan.get("approval_status"), bool(plan.get("approval_ref"))) in (("APPROVED", True), ("UNAPPROVED_CANDIDATE", False)),
        "approval status and reference disagree")
    w, count = plan.get("window_duration_ms"), plan.get("planned_window_count")
    req(type(w) is int and w > 0 and type(count) is int and count >= 4, "window parameters")
    if errors:
        raise ValueError("; ".join(errors))
    req(plan["observation_config_sha256"] == observation_config_sha256(w * 1_000_000, registry.sha256, plans.SUBSCRIPTION_QOS),
        "observation config digest")
    cells, runs = plan["cells"], plan["runs"]
    ids = [c["run_id"] for c in cells]
    req(len(ids) == len(set(ids)) and set(ids) == set(runs), "run ids unique and matching run configs")
    req([c["order"] for c in cells] == list(range(1, len(cells) + 1)), "execution order contiguous")
    req(all(c["scenario_designation"] == "BENIGN" for c in cells), "only benign scenarios are defined; attack workloads are not specified")
    seeds = []
    for cell in cells:
        config = runs.get(cell["run_id"], {})
        req(cell["workload_config_sha256"] == plans.digest(config), f'{cell["run_id"]}: workload digest')
        expected = v2.run_config(cell["run_id"], cell["plan"], kind=plan["kind"], window_duration_ms=w, registry=registry,
                                 eligible_windows=plan["eligible_windows"])
        req(config == expected, f'{cell["run_id"]}: run config differs from the deterministic v2 rule')
        req(not v2.config_problems(config), f'{cell["run_id"]}: {v2.config_problems(config)}')
        seeds += [d["device_seed"] for d in config.get("devices", {}).values()]
        for device, spec in config.get("devices", {}).items():
            bound = registry.bind(spec["telemetry_topic"])
            req(bound is not None and bound.device == device, f'{cell["run_id"]}: topic/device mapping')
    req(len(seeds) == len(set(seeds)), "device seeds must be unique across the whole plan (hence across partitions)")
    req(plan.get("frozen_model_compatibility") == model_compatibility(registry, w, runs), "frozen-model compatibility statement")
    if v1_plan is not None:
        req(not set(ids) & set(v1_plan.get("runs", {})), "run ids overlap the accepted v1 plan")
        v1_seeds = {d["device_seed"] for r in v1_plan.get("runs", {}).values() for d in r["devices"].values()}
        req(not v1_seeds & set(seeds), "device seeds overlap the accepted v1 plan")
    if plan["kind"] == "SCIENTIFIC":
        rebuilt = build_plan_v2(plan_id=plan["plan_id"], registry=registry, planning_base_commit=plan["planning_base_commit"],
                                allocation=plan["allocation"], substitutes=plan["substitutes"], eligible_windows=plan["eligible_windows"],
                                window_duration_ms=w, approval_ref=plan["approval_ref"])
        req(plan == rebuilt, "scientific plan differs from deterministic regeneration")
        for role, table in (("SCIENTIFIC", plan["allocation"]), ("SUBSTITUTE", plan["substitutes"])):
            counts = {part: {"A": 0, "B": 0} for part in PARTITIONS_V2}
            for cell in cells:
                if cell["role"] == role:
                    counts[cell["intended_partition"]][cell["plan"]] += 1
            req(counts == table, f"{role} allocation/balance")
        req(all(c["intended_partition"] in PARTITIONS_V2 for c in cells), "CAL_V2, D_shadow and D_test partitions only")
        partition_of = {c["run_id"]: c["intended_partition"] for c in cells}
        req(all(RUN_PATTERN.fullmatch(r) for r in ids) and all((c["role"] == "SCIENTIFIC") == c["run_id"].startswith("g5f-r") for c in cells),
            "neutral run ids")
        by_partition = {p: {r for r, q in partition_of.items() if q == p} for p in PARTITIONS_V2}
        parts = list(by_partition.values())
        req(all(parts) and all(not a & b for i, a in enumerate(parts) for b in parts[i + 1:]),
            "CAL_V2, D_shadow and D_test must all exist and be pairwise disjoint")
        req(w == FROZEN_W_MS and plan["eligible_windows"] == FROZEN_ELIGIBLE and count == FROZEN_WINDOW_COUNT,
            "frozen W / window geometry (1 lead-in + 60 eligible + 1 post-roll)")
        sequence = [(c["intended_partition"], c["plan"]) for c in cells if c["role"] == "SCIENTIFIC"]
        req(not order_violations(sequence, plan["order_constraints"]["max_consecutive_same_partition"]),
            "scientific run order violates the interleaving constraints")
    else:
        req(all(c["role"] == plan["kind"] for c in cells), "non-scientific roles")
        req(not any(RUN_PATTERN.fullmatch(c["run_id"]) or re.fullmatch(r"g5c-[rs]\d\d", c["run_id"]) for c in cells),
            "non-scientific runs never use g5f-rNN/g5f-sNN or g5c-rNN/g5c-sNN ids")
    if errors:
        raise ValueError("; ".join(errors))
    return plan


def manifest_entries_v2(plan, *, manifest_id, plan_path, created_utc):
    """Header, one RUN_PLANNED per cell (execution order) and PARTITIONS_FROZEN, in the existing hash-chained manifest format."""
    if plan["kind"] == "FUNCTIONAL_TEST":
        raise ValueError("FUNCTIONAL_TEST plans never get a collection manifest")
    purpose = ("GATE5F2_DSHADOW_DTEST_BENIGN_COLLECTION" if plan["kind"] == "SCIENTIFIC" else "WRAPPER_VALIDATION_NOT_DATA")
    purpose += (f" approval={plan['approval_status']} plan={plan_path} plan_sha256={plans.digest(plan)} "
                f"planning_base_commit={plan['planning_base_commit']}")
    entries = []
    entries.append(manifest_v2.make_entry(entries, "MANIFEST_HEADER", dict(
        manifest_id=manifest_id, created_utc=created_utc, purpose=purpose, assignment_unit="collection_run",
        allowed_partitions=list(manifest_v2.PARTITIONS), observation_schema_fingerprint=SCHEMA_FINGERPRINT,
        observation_config_sha256=plan["observation_config_sha256"], window_duration_ns=plan["window_duration_ms"] * 1_000_000,
        registry_sha256=plan["registry_sha256"])))
    for cell in plan["cells"]:
        entries.append(manifest_v2.make_entry(entries, "RUN_PLANNED", dict(
            collection_run_id=cell["run_id"], devices=sorted(plan["runs"][cell["run_id"]]["devices"]),
            workload_profile_id=f'gate5f2-v2c-plan{cell["plan"]}', scenario_designation=cell["scenario_designation"],
            attack_informed=False, intended_partition=cell["intended_partition"], planned_window_count=plan["planned_window_count"],
            workload_config_sha256=cell["workload_config_sha256"], planned_utc=created_utc)))
    assignments = {cell["run_id"]: cell["intended_partition"] for cell in plan["cells"]}
    entries.append(manifest_v2.make_entry(entries, "PARTITIONS_FROZEN", dict(
        frozen_utc=created_utc, assignments=assignments, assignments_sha256=manifest_module.assignments_digest(assignments))))
    manifest_v2.validate(entries)
    return entries


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    build = sub.add_parser("build")
    build.add_argument("--plan-id", required=True)
    build.add_argument("--plan-out", required=True)
    build.add_argument("--planning-base-commit", required=True)
    build.add_argument("--kind", choices=("SCIENTIFIC", "FUNCTIONAL_TEST"), default="SCIENTIFIC")
    build.add_argument("--allocation-json", help='SCIENTIFIC only; explicit, naming every partition, e.g. {"CAL_V2":{"A":k,"B":k},"D_shadow":{"A":n,"B":n},"D_test":{"A":m,"B":m}} (counts are decided by the controller, not here)')
    build.add_argument("--substitutes-json", help="SCIENTIFIC only; explicit, same shape as the allocation")
    build.add_argument("--cells-json", help='FUNCTIONAL_TEST only; [["g5f-f01","A","D_shadow"], ...] (the partition label is a placeholder: a functional run joins no partition and has no manifest)')
    build.add_argument("--approval-ref")
    build.add_argument("--manifest-out")
    build.add_argument("--manifest-id")
    build.add_argument("--plan-path-label")
    build.add_argument("--created-utc")
    check = sub.add_parser("validate")
    check.add_argument("--plan", required=True)
    check.add_argument("--v1-plan")
    for item in (build, check):
        item.add_argument("--registry", default="/app/configs/observation/device_registry.json")
    args = parser.parse_args(argv)
    try:
        registry = DeviceRegistry.load(args.registry)
        if args.action == "build":
            if args.kind == "SCIENTIFIC":
                if args.cells_json or args.allocation_json is None or args.substitutes_json is None:
                    raise ValueError("a SCIENTIFIC plan needs --allocation-json and --substitutes-json and takes no --cells-json")
                extra = dict(allocation=json.loads(args.allocation_json), substitutes=json.loads(args.substitutes_json))
            else:
                if args.allocation_json or args.substitutes_json or not args.cells_json or args.manifest_out or args.approval_ref:
                    raise ValueError("a FUNCTIONAL_TEST plan needs --cells-json only (no allocation, substitutes, approval or manifest)")
                extra = dict(cells=[tuple(cell) for cell in json.loads(args.cells_json)])
            plan = build_plan_v2(plan_id=args.plan_id, registry=registry, planning_base_commit=args.planning_base_commit, kind=args.kind,
                                 approval_ref=args.approval_ref, **extra)
            validate_plan_v2(plan, registry)
            entries = manifest_entries_v2(plan, manifest_id=args.manifest_id, plan_path=args.plan_path_label,
                                          created_utc=args.created_utc) if args.manifest_out else None
            plans.write_json_exclusive(args.plan_out, plan)
            if entries is not None:
                plans.write_manifest_exclusive(args.manifest_out, entries)
            print(f"PLAN_V2_BUILT {plan['plan_id']} status={plan['approval_status']} cells={len(plan['cells'])} "
                  f"scorable_by_frozen_models={plan['frozen_model_compatibility']['scorable_by_frozen_models']} "
                  f"plan_sha256={plans.digest(plan)}")
        else:
            v1_plan = plans.load_plan(args.v1_plan) if args.v1_plan else None
            plan = validate_plan_v2(plans.load_plan(args.plan), registry, v1_plan=v1_plan)
            print(f"PLAN_V2_VALID {plan['plan_id']} status={plan['approval_status']} cells={len(plan['cells'])} "
                  f"plan_sha256={plans.digest(plan)}")
        return 0
    except (ValueError, OSError, KeyError) as exc:
        print(f"PLAN_V2_INVALID {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
