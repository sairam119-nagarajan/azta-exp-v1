"""Path A, offline middle of the chain: observer windows of ONE engineering functional run -> evidence bundles -> real frozen S/V models -> shadow decisions (Master Implementation 2).

    python -m engineering.path_a_decide --run-dir DIR --run-id ID --session-id obs-... --plan configs/collection_plans/PLAN.json

Two existing, unchanged tools run with fixed engineering arguments and nothing else:
  1. `experiments.gate5f_session_feed build`  - the observer's windows + the run's read-only broker-policy audits + the labelled functional schedule -> bundles (the legacy `azta-pdp` observer
     is accepted by the explicit flag; B_cal, CAL_V2, D_shadow and D_test are reserved from the committed manifests, so none of their evidence can be fed);
  2. `decision_pipeline run`                  - the functional engineering device-profile registry (device01 -> S, device02 -> V, FUNCTIONAL_TEST windows only), the historical calibration
     (which does not describe workload v2, so behaviour stays NOT_EVALUABLE and the model's loss is only INFERRED_UNCALIBRATED telemetry) and the SYNTHETIC_TEST_UNAPPROVED trust configuration.
No calibration, registry, parameter or approval is chosen here beyond those named committed files; nothing connects to a broker; enforcement is NONE. The decisions file it prints is the input
of the persistent enforcement runner, which refuses every one of them.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SCHEDULE = "configs/gate5f_live/functional_demo_schedule.json"
TRUST_CONFIG = "configs/gate5f_live/trust_config_functional_unapproved.json"
PROFILE_REGISTRY = "configs/decision_pipeline/device_profile_registry_v1_functional_engineering_unapproved.json"
# one v2 manifest: the named partitions must exist in every manifest given (the v1 manifest has none of them); the engine refuses the consumed B_cal unconditionally
RESERVE_MANIFESTS = ("configs/collection_manifests/g5f_scientific_v2_approved.jsonl",)
RESERVE_PARTITIONS = ("CAL_V2", "D_shadow", "D_test")


def feed_command(run_dir, run_id, session_id, plan, feed_id):
    command = [sys.executable, "-B", "-m", "experiments.gate5f_session_feed", "build", "--run-root", str(run_dir), "--run-id", run_id, "--session-id", session_id, "--plan", plan,
               "--feed-id", feed_id, "--schedule", SCHEDULE, "--allow-legacy-observer"]
    for manifest in RESERVE_MANIFESTS:
        command += ["--reserve-manifest", manifest]
    for partition in RESERVE_PARTITIONS:
        command += ["--reserve-partition", partition]
    return command


def pipeline_command(feed_id, decisions_id):
    sha = hashlib.sha256((ROOT / PROFILE_REGISTRY).read_bytes()).hexdigest()
    command = [sys.executable, "-B", "-m", "decision_pipeline", "run", "--config", TRUST_CONFIG, "--bundles", f"results/gate5f/feeds/{feed_id}/bundles.jsonl", "--run-id", decisions_id,
               "--calibration", "gate5e-v1", "--device-profile-registry", PROFILE_REGISTRY, "--device-profile-registry-sha256", sha]
    for manifest in RESERVE_MANIFESTS:
        command += ["--reserve-manifest", manifest]
    for partition in RESERVE_PARTITIONS:
        command += ["--reserve-partition", partition]
    return command


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--plan", required=True)
    args = parser.parse_args(argv)
    feed_id, decisions_id = f"{args.run_id}-feed", f"{args.run_id}-decisions"
    for label, command in (("FEED", feed_command(args.run_dir, args.run_id, args.session_id, args.plan, feed_id)), ("DECISIONS", pipeline_command(feed_id, decisions_id))):
        done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=1800)
        print(f"{label} exit={done.returncode} {(done.stdout.strip() or done.stderr.strip())[-400:]}")
        if done.returncode != 0:
            return 2
    summary = json.loads((ROOT / "results" / "gate5f" / decisions_id / "summary.json").read_text(encoding="utf-8"))
    print(f"PATH_A_DECISIONS file=results/gate5f/{decisions_id}/decisions.jsonl")
    print(json.dumps(summary, sort_keys=True)[:1200])
    return 0


if __name__ == "__main__":
    sys.exit(main())
