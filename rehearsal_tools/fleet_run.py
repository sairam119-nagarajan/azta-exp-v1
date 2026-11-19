"""Launcher of ONE supervised FLEET run on the dedicated PILOT broker (project `azta-pilot`), Gate 6B: keep-awake, a fresh clock-probe certificate, a versioned fleet context policy, then
`engineering.fleet_continuous` with the pilot environment. It starts nothing else, touches no research resource and decides nothing: every artifact is an explicit command-line path.

    python -I -B rehearsal_tools/fleet_run.py --label NAME --run-id ID --plan configs/collection_plans/PLAN.json --baseline-policy-sha256 H --dev-perturbation configs/dev_perturbations/ID.json
        --trust-config C.json --profile-registry R.json --cal-v2 CAL.json --models-record M.json --compat-record K.json
        [--approval A.json --approval-sha256 H --calibration-record F.json]   (enforcement; absent = shadow evidence only, every decision refused by the PEP)
        [--time-cut-device deviceNN --time-cut-after-s N]

The context policy permits every device of the plan to operate all day (a window of the PLAN's devices only) except an optional `--time-cut-device`, which is permitted only until N seconds after
the launch instant. Output: results/engineering/pilot/NAME/. The run evidence is written by the orchestrator under results/engineering/runs/ID. Exit code: the orchestrator's.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
PY = ROOT / ".venv" / "Scripts" / "python.exe"
IMAGE = "azta-journal-runtime:gate3"
PROJECT, OVERLAY = "azta-pilot", "compose.pilot.yaml"


def iso(ns):
    return datetime.fromtimestamp(ns / 1e9, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "000Z"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_policy(path, devices, cut_device, cut_after_s, *, now_ns):
    day = 24 * 3600 * 10**9
    full = [[iso(now_ns - day), iso(now_ns + 30 * day)]]
    cut = [[iso(now_ns - day), iso(now_ns + int(cut_after_s * 1e9))]]
    body = {name: dict(client_id=client, permitted_utc_intervals=cut if name == cut_device else full, permitted_topics=[f"azta/devices/{name}/telemetry"]) for name, client in devices.items()}
    path.write_text(json.dumps(dict(schema="azta.pilot_context_policy", version=1, policy_id=f"fleet-{path.parent.name}", status="ENGINEERING_PILOT_UNAPPROVED", devices=body),
                               sort_keys=True, indent=1), encoding="utf-8")


def criteria_with_session(criteria, session_s):
    """The saved clock criteria with ONLY `session_s` replaced (the span the certificate must cover). Every error budget, tolerance, sample minimum and rate cap is copied unchanged; a value that is not a
    positive number of seconds is refused. The result is the text written next to the probe BEFORE the measurement, so the decision is fixed in advance."""
    if isinstance(session_s, bool) or not isinstance(session_s, (int, float)) or session_s <= 0:
        raise ValueError("session_s must be a positive number of seconds")
    out = dict(criteria)
    out["session_s"] = int(session_s)
    return json.dumps(out, sort_keys=True, indent=1) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for key in ("label", "run-id", "plan", "baseline-policy-sha256", "dev-perturbation", "trust-config", "profile-registry", "cal-v2", "models-record", "compat-record"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--authorization-ref", default="USER-FLEET-PILOT-UNSET")
    parser.add_argument("--approval")
    parser.add_argument("--approval-sha256")
    parser.add_argument("--calibration-record")
    parser.add_argument("--probe-duration-s", type=int, default=180)
    parser.add_argument("--clock-session-s", type=int, default=None, help="the session length the clock certificate must cover (criteria field session_s, 800 s in the saved example); covers the time from the end of the probe to the launch, the warm-up and the planned session. "
                        "Declared before the measurement; the error budgets are unchanged and the evaluation still decides PASS or FAIL")
    parser.add_argument("--time-cut-device")
    parser.add_argument("--time-cut-after-s", type=float)
    parser.add_argument("--continuous-arg", action="append", default=[])
    args = parser.parse_args(argv)
    plan = json.loads((ROOT / args.plan).read_text(encoding="utf-8"))
    devices = {d: item["client_id"] for d, item in plan["runs"][args.run_id]["devices"].items()}
    out = ROOT / "results" / "engineering" / "pilot" / args.label
    out.mkdir(parents=True, exist_ok=False)
    log = open(out / "launcher.log", "a", encoding="utf-8")

    def say(text):
        line = f"{datetime.now(timezone.utc).strftime('%H:%M:%S')} {text}"
        log.write(line + "\n")
        log.flush()
        print(line, flush=True)

    env = dict(os.environ, AZTA_ENG_PROJECT=PROJECT, AZTA_ENG_COMPOSE_OVERLAY=OVERLAY, PYTHONDONTWRITEBYTECODE="1")
    awake = subprocess.Popen([str(PY), "-I", "-B", "rehearsal_tools/keep_awake.py", "2400"], cwd=ROOT, creationflags=subprocess.CREATE_NO_WINDOW, stdout=log, stderr=subprocess.STDOUT)
    try:
        for attempt in range(1, 9):               # a FAIL is a fresh-measurement outcome against criteria saved BEFORE it; the criteria are never changed
            probe = out / ("probe" if attempt == 1 else f"probe{attempt}")
            probe.mkdir()
            shutil.copyfile(ROOT / "rehearsal_tools/clock_criteria.example.json", probe / "criteria.json")
            if args.clock_session_s:                  # declared BEFORE the measurement; only the certified span changes, never an error budget
                (probe / "criteria.json").write_text(criteria_with_session(json.loads((probe / "criteria.json").read_text(encoding="utf-8")), args.clock_session_s), encoding="utf-8")
            shutil.copyfile(ROOT / "rehearsal_tools/clock_probe.py", probe / "clock_probe.py")
            name = f"fleet-clock-{args.run_id}-{attempt}"
            subprocess.run(["docker", "run", "--rm", "-d", "--name", name, "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--mount",
                            f"type=bind,src={probe},dst=/probe", IMAGE, "python", "-I", "-B", "/probe/clock_probe.py", "container", "--directory", "/probe", "--duration-s",
                            str(args.probe_duration_s), "--interval-ms", "100"], cwd=ROOT, check=True, capture_output=True)
            subprocess.run([str(PY), "-I", "-B", "rehearsal_tools/clock_probe.py", "host", "--directory", str(probe), "--duration-s", str(args.probe_duration_s), "--interval-ms", "100"],
                           cwd=ROOT, check=True)
            subprocess.run([str(PY), "-I", "-B", "rehearsal_tools/clock_probe.py", "evaluate", "--result", str(probe / "probe_result.json"), "--criteria", str(probe / "criteria.json"),
                            "--out", str(probe / "evaluation.json")], cwd=ROOT)
            verdict = json.loads((probe / "evaluation.json").read_text(encoding="utf-8"))
            say(f"clock probe attempt {attempt} status={verdict.get('status')} reasons={verdict.get('reasons')}")
            if verdict.get("status") == "PASS":
                break
        else:
            say("no clock probe passed in eight fresh measurements; nothing was started")
            return 4
        policy = out / "context_policy.json"
        write_policy(policy, devices, args.time_cut_device, args.time_cut_after_s or 0, now_ns=time.time_ns())
        command = [str(PY), "-B", "-m", "engineering.fleet_continuous", "--run-id", args.run_id, "--plan", args.plan, "--baseline-policy-sha256", args.baseline_policy_sha256,
                   "--authorization-ref", args.authorization_ref, "--audit-interval-s", "30", "--audit-edge-margin-s", "5", "--clock-tolerance-ns", "250000000", "--stall-timeout-ns",
                   "30000000000", "--restart-limit", "5", "--max-attempts", "2", "--escalate-after", "2", "--deescalate-after", "1", "--poll-interval-s", "0.25", "--max-duration-s", "760",
                   "--retry-delay-s", "1", "--shutdown-timeout-s", "45", "--max-decision-age-s", "120", "--clock-evaluation", str(probe / "evaluation.json"),
                   "--clock-evaluation-max-age-s", "120", "--dev-perturbation", args.dev_perturbation, "--context-policy", str(policy), "--shadow-config", args.trust_config,
                   "--shadow-registry", args.profile_registry, "--fleet-cal-v2", args.cal_v2, "--fleet-cal-v2-sha256", sha(args.cal_v2), "--fleet-models-record", args.models_record,
                   "--fleet-models-record-sha256", sha(args.models_record), "--fleet-compat-record", args.compat_record, "--fleet-compat-record-sha256", sha(args.compat_record)]
        if args.approval:
            if not (args.approval_sha256 and args.calibration_record):
                parser.error("--approval needs --approval-sha256 and --calibration-record")
            command += ["--pep-target", "PILOT_FLEET_BROKER", "--operational-approval", args.approval, "--operational-approval-sha256", args.approval_sha256, "--approved-registry",
                        args.profile_registry, "--approved-config", args.trust_config, "--approved-calibration-record", args.calibration_record]
        command += args.continuous_arg
        (out / "launch.json").write_text(json.dumps(dict(command=command, project=PROJECT, started_utc=iso(time.time_ns())), indent=1), encoding="utf-8")
        say("launching engineering.fleet_continuous")
        launched = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        process = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        say(f"engineering.fleet_continuous exit={process.returncode}")
        try:                                    # the broker's own record of client lifecycle events: the independent containment instant
            raw = subprocess.run(["docker", "logs", "--timestamps", "--since", launched, "azta-pilot-broker-1"], capture_output=True, text=True, encoding="utf-8", errors="replace",
                                 timeout=120)
            skip = ("PUBLISH", "PUBACK", "PINGREQ", "PINGRESP")
            kept = [line for line in (raw.stdout + raw.stderr).splitlines() if "azta-device-" in line and not any(word in line for word in skip)]
            (out / "broker_client_events.log").write_text(chr(10).join(kept) + chr(10), encoding="utf-8")
            say(f"broker client events saved: {len(kept)} lines")
        except (OSError, subprocess.SubprocessError) as exc:
            say(f"broker client events not saved: {type(exc).__name__}")
        return process.returncode
    finally:
        awake.terminate()
        log.close()


if __name__ == "__main__":
    sys.exit(main())
