"""Build the ten-device model-coverage record (ENGINEERING CANDIDATE, UNAPPROVED) from committed configuration and the planned schedules.

Pure and offline: it reuses the Gate 5F.2 compatibility analysis (planned synthetic schedules of the ten functional slots, the frozen
profile laws, both registries) and writes what a controller must decide, as a record the trust package can validate. It opens no evidence,
loads no model, approves no route and trains nothing.

    python -m experiments.gate5f_ten_device_coverage build  --out configs/gate5f/ten_device_model_coverage.json
    python -m experiments.gate5f_ten_device_coverage verify --coverage configs/gate5f/ten_device_model_coverage.json
"""
import argparse
import json
from pathlib import Path
import sys

from experiments import gate5d3_workload as slots
from experiments import gate5f2_ten_device_compat as compat
from preprocessing.gate5d_data import PIN
from trust import coverage as cov
from trust.errors import ArtifactRefused

MODEL_PINS = {p: {"registry_sha256": PIN["registry_sha256"], "observation_config_sha256": PIN["observation_config_sha256"]} for p in ("S", "V")}


def law_class(profile):
    payload = profile["payload"]
    size = f"fixed{payload['bytes']}B" if payload["kind"] == "fixed" else f"uniform{payload['low']}-{payload['high']}B"
    shape = profile["shape"]
    if shape == "steady_jitter":
        return f"steady|gap={profile['nominal_gap_ns'] / 1e9:g}s|jitter={profile['jitter_fraction']:g}|{size}"
    if shape == "periodic":
        return f"periodic|period={profile['period_ns'] / 1e9:g}s|{size}"
    if shape == "event_gap":
        return f"event_gap|{profile['gap_low_s']}-{profile['gap_high_s']}s|{size}"
    return f"switching|slow={profile['slow_gap_ns'] / 1e9:g}s|fast={profile['fast_gap_ns'] / 1e9:g}s|block={profile['block_ns'] / 1e9:g}s|{size}"


def build():
    report = compat.analyze()
    rows = []
    for row in report["slots"]:
        slot = row["slot"]
        score = cov.scorability_of(row["eligible_windows"], row["planned_score_ready_windows"])
        blockers = ["PIN_MISMATCH_REGISTRY_V2: the models were fitted and calibrated under registry v1 and its observation configuration",
                    "NO_CALIBRATION_FOR_THIS_REGISTRY_AND_WORKLOAD: no controller-accepted calibration exists", "NO_APPROVED_ROUTE"]
        if row["law_equivalent_to_frozen_profile"] is None:
            blockers.append("NO_FROZEN_MODEL_FOR_TRAFFIC_LAW: needs benign training evidence for this law or a validated shared model")
        if score != "SCORABLE":
            blockers.append(f"SPARSE_AT_10S_SIX_FEATURE_DEFINITION: {row['planned_score_ready_windows']}/{row['eligible_windows']} planned windows "
                            f"are score-ready ({row['planned_not_ready_by_reason']}); never imputed")
        rows.append(dict(device=row["device"], law_class=law_class(slots.PROFILES[slot]),
                         frozen_model_law_equivalent=row["law_equivalent_to_frozen_profile"], eligible_windows=row["eligible_windows"],
                         planned_score_ready_windows=row["planned_score_ready_windows"], scorability=score,
                         route=dict(profile=None, status="NOT_APPROVED", approval_ref=None), blockers=blockers))
    return dict(schema=cov.COVERAGE_SCHEMA, schema_version=cov.COVERAGE_SCHEMA_VERSION, status="ENGINEERING_CANDIDATE_UNAPPROVED",
                registry_sha256=report["registries"]["v2_sha256"], observation_config_sha256=report["observation_config"]["v2_sha256"],
                frozen_models=["S", "V"], devices=rows,
                basis="planned synthetic schedules of the ten functional slots (Gate 5F.2 analysis) and committed configuration; no evidence, model or broker")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("build").add_argument("--out", required=True)
    sub.add_parser("verify").add_argument("--coverage", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            with Path(args.out).open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(json.dumps(build(), indent=1, sort_keys=True, allow_nan=False) + "\n")
            print(f"COVERAGE_WRITTEN {args.out}")
            return 0
        coverage = cov.parse_coverage(json.loads(Path(args.coverage).read_text(encoding="utf-8")), model_pins=MODEL_PINS)
        print("COVERAGE_VERIFIED " + json.dumps(cov.summarize(coverage), sort_keys=True))
        return 0
    except (OSError, ValueError, ArtifactRefused) as exc:
        print(f"COVERAGE_REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
