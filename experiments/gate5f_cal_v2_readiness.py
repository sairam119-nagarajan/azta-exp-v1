"""Offline readiness check of a PROSPECTIVE scientific workload-v2 plan (CAL_V2 / D_shadow / D_test). Reads the plan and committed configuration only.

It opens no evidence, loads no model, scores nothing and chooses nothing: it verifies, with numbers, the properties the CAL_V2 collection
depends on, so that a controller can approve a plan knowing what it contains.

  * structure     the plan validates under the original two-device registry and the frozen observation pins; kind SCIENTIFIC; A/B counts balanced
                  in every partition; substitutes pre-planned per partition; whole-run partition assignment; run ids neutral
  * independence  device seeds pairwise unique across the plan and disjoint from the accepted v1 campaign's runs and seeds; CAL_V2, D_shadow and
                  D_test run sets pairwise disjoint
  * design        for every planned run, from the seeded schedules alone (no observation): all 60 eligible windows are score-ready by construction,
                  the lead-in is empty, the post-roll carries traffic, and the LAST eligible window is compared with the interior ones (the Gate 5E
                  end-of-run artifact came from a stop rule that truncated that window; v2 continues through a post-roll). Descriptive only.
  * profile       every run supplies one S and one V device-run, each profile on each device equally often
  * budget        collection time from the measured rehearsal run (10 min 30 s per run) and the number of runs

The numeric statistics here describe PLANNED schedules, not measurements; they are a design check, never calibration.

    python -m experiments.gate5f_cal_v2_readiness --plan configs/collection_plans/PLAN.json --out results/gate5f/readiness_PLAN.json
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import statistics
import sys

from experiments import collection_plan as plans
from experiments import collection_plan_v2 as plans_v2
from experiments import collection_workload_v2 as v2
from observation.registry import DeviceRegistry
from preprocessing.gate5d_data import PIN

ROOT = Path(__file__).resolve().parents[1]
MEASURED_RUN_MINUTES = 10.5     # g5f-f01: 20:59:42 to 21:10:12 UTC including pre/post audits and reconciliation (VERIFIED FROM FILES)
W_NS = 10_000_000_000


def design_check(config):
    """Planned-window facts of one run (both devices): readiness, lead-in/post-roll roles and last-window vs interior."""
    first, last = config["eligible_window_indices"]
    out = {}
    for device in sorted(config["devices"]):
        features = v2.planned_features(config, device)
        eligible = list(range(first, last + 1))
        ready = [i for i in eligible if v2.planned_vector(features[i]) is not None]
        counts = {i: features[i]["delivered_count"]["value"] for i in range(config["planned_window_count"])}
        ages = {i: features[i]["last_delivery_age_ms"]["value"] for i in eligible if features[i]["last_delivery_age_ms"]["value"] is not None}
        interior = [i for i in eligible if i not in (first, last)]
        out[device] = dict(
            profile=config["devices"][device]["profile"], eligible=len(eligible), ready=len(ready), lead_in_count=counts[0],
            post_roll_count=counts[config["planned_window_count"] - 1], last_window_count=counts[last],
            last_window_age_ms=ages.get(last), interior_ages_ms=[ages[i] for i in interior if i in ages],
            interior_counts=[counts[i] for i in interior])
    return out


def last_window_diagnostic(designs, profile):
    """Pooled over all planned device-runs of one profile: is the LAST eligible window distributed like the interior ones? Welch z of the mean
    last-delivery age and the share of lowest-count windows. A DESCRIPTIVE diagnostic of the planned schedules (not an acceptance threshold):
    the v1 stop rule shifted this window by up to half a gap; |z| near 0 shows the v2 schedule does not."""
    last = [d["last_window_age_ms"] for per in designs.values() for d in per.values() if d["profile"] == profile and d["last_window_age_ms"] is not None]
    interior = [a for per in designs.values() for d in per.values() if d["profile"] == profile for a in d["interior_ages_ms"]]
    se = (statistics.variance(last) / len(last) + statistics.variance(interior) / len(interior)) ** 0.5
    low = min(c for per in designs.values() for d in per.values() if d["profile"] == profile for c in d["interior_counts"])
    last_counts = [d["last_window_count"] for per in designs.values() for d in per.values() if d["profile"] == profile]
    interior_counts = [c for per in designs.values() for d in per.values() if d["profile"] == profile for c in d["interior_counts"]]
    return dict(n_last=len(last), n_interior=len(interior), mean_age_last_ms=statistics.fmean(last), mean_age_interior_ms=statistics.fmean(interior),
                welch_z=(statistics.fmean(last) - statistics.fmean(interior)) / se if se else None,
                share_lowest_count_last=sum(c == low for c in last_counts) / len(last_counts),
                share_lowest_count_interior=sum(c == low for c in interior_counts) / len(interior_counts), lowest_count=low)


def check(plan, registry, v1_plan):
    problems = []
    plans_v2.validate_plan_v2(plan, registry, v1_plan=v1_plan)
    pins_ok = (plan["registry_sha256"] == PIN["registry_sha256"] and plan["observation_config_sha256"] == PIN["observation_config_sha256"]
               and plan["schema_fingerprint"] == PIN["schema_fingerprint"] and plan["generator_version"] == v2.GENERATOR_VERSION)
    if plan["kind"] != "SCIENTIFIC" or not pins_ok:
        problems.append("plan is not a scientific plan under the frozen pins")
    cells = plan["cells"]
    scientific = [c for c in cells if c["role"] == "SCIENTIFIC"]
    allocation = {part: dict(Counter(c["plan"] for c in scientific if c["intended_partition"] == part)) for part in plans_v2.PARTITIONS_V2}
    substitutes = {part: dict(Counter(c["plan"] for c in cells if c["role"] == "SUBSTITUTE" and c["intended_partition"] == part))
                   for part in plans_v2.PARTITIONS_V2}
    for part, table in allocation.items():
        if table.get("A") != table.get("B") or not table:
            problems.append(f"{part}: plan A/B counts are not balanced")
    sets = {part: {c["run_id"] for c in cells if c["intended_partition"] == part} for part in plans_v2.PARTITIONS_V2}
    parts = list(sets.values())
    if any(a & b for i, a in enumerate(parts) for b in parts[i + 1:]):
        problems.append("partitions share runs")
    seeds = [d["device_seed"] for run in plan["runs"].values() for d in run["devices"].values()]
    v1_seeds = {d.get("device_seed") for run in v1_plan["runs"].values() for d in run["devices"].values()}
    if len(seeds) != len(set(seeds)) or set(seeds) & v1_seeds or set(plan["runs"]) & set(v1_plan["runs"]):
        problems.append("seeds or run ids are not independent")
    designs = {run: design_check(config) for run, config in plan["runs"].items()}
    flat = [(run, dev, d) for run, per in designs.items() for dev, d in per.items()]
    if any(d["ready"] != d["eligible"] or d["lead_in_count"] != 0 or d["post_roll_count"] < 1 for _, _, d in flat):
        problems.append("a planned run has a non-score-ready eligible window, a non-empty lead-in or an empty post-roll")
    diagnostics = {profile: last_window_diagnostic(designs, profile) for profile in ("S", "V")}
    coverage = {part: dict(S=Counter(), V=Counter()) for part in plans_v2.PARTITIONS_V2}
    for cell in scientific:
        for device, spec in plan["runs"][cell["run_id"]]["devices"].items():
            coverage[cell["intended_partition"]][spec["profile"]][device] += 1
    runs_total = len(scientific)
    cal = len(sets["CAL_V2"] & {c["run_id"] for c in scientific})
    return dict(
        schema="azta.gate5f.cal_v2_readiness", schema_version=1, plan_id=plan["plan_id"], approval_status=plan["approval_status"],
        plan_sha256=plans.digest(plan), ok=not problems, problems=problems, pins_ok=pins_ok,
        allocation=allocation, substitutes=substitutes, run_ids_neutral=all(c["run_id"].startswith(("g5f-r", "g5f-s")) for c in cells),
        profile_device_coverage={part: {p: dict(c) for p, c in per.items()} for part, per in coverage.items()},
        seeds=dict(device_seeds=len(seeds), unique=len(set(seeds)) == len(seeds), disjoint_from_v1=not (set(seeds) & v1_seeds)),
        design=dict(runs=len(designs), eligible_windows_per_device=60, all_planned_score_ready=all(d["ready"] == d["eligible"] for _, _, d in flat),
                    lead_in_empty=all(d["lead_in_count"] == 0 for _, _, d in flat), post_roll_has_traffic=all(d["post_roll_count"] >= 1 for _, _, d in flat),
                    last_window_vs_interior_planned_diagnostic=diagnostics),
        budget=dict(scientific_runs=runs_total, cal_v2_runs=cal, minutes_per_run_measured=MEASURED_RUN_MINUTES,
                    cal_v2_hours=round(cal * MEASURED_RUN_MINUTES / 60, 2), cal_v2_with_all_substitutes_hours=round(
                        (cal + sum(substitutes["CAL_V2"].values())) * MEASURED_RUN_MINUTES / 60, 2),
                    total_scientific_hours=round(runs_total * MEASURED_RUN_MINUTES / 60, 2)),
        note="design facts of PLANNED schedules, not measurements; no evidence opened; nothing calibrated or selected")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--out", help="new JSON file (never overwritten); omit to print")
    parser.add_argument("--repo-root", default=str(ROOT))
    args = parser.parse_args(argv)
    try:
        root = Path(args.repo_root)
        registry = DeviceRegistry.load(root / "configs" / "observation" / "device_registry.json")
        v1_plan = json.loads((root / "configs" / "collection_plans" / "gate5c_workload_v1.json").read_text(encoding="utf-8"))
        report = check(plans.load_plan(args.plan), registry, v1_plan)
        text = json.dumps(report, indent=1, sort_keys=True, allow_nan=False) + "\n"
        if args.out:
            with Path(args.out).open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(text)
        else:
            sys.stdout.write(text)
    except (OSError, ValueError, KeyError) as exc:
        print(f"CAL_V2_READINESS_REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(f"CAL_V2_READINESS ok={report['ok']} plan_sha256={report['plan_sha256']} problems={len(report['problems'])}", file=sys.stderr if not args.out else sys.stdout)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
