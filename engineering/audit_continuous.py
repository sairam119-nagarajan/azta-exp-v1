"""Pre-push audit harness for the supervised continuous service (isolated engineering broker only): fresh clock preflight, launch, injected faults, result file.

    python -m engineering.audit_continuous --run-id audit-fNN --plan configs/collection_plans/PLAN.json --baseline-policy-sha256 H --out-dir DIR

Sequence, serial, with explicit fixtures (none is an operating value): (1) the unchanged two-way clock probe (host role plus ONE isolated container role) and its evaluation against criteria
saved BEFORE the measurement; (2) the supervised service `engineering.continuous` exactly as its runbook shows; (3) three real faults at fixed offsets from the observer's coverage start:
the adapter process is killed, the enforcement container is killed, and the enforcement container is cut from its network (the transport-loss path); after each fault the harness waits for the
supervisor's own restart event and records it; (4) the process exit and the supervisor events are written to `audit-live-result.json`. It verifies nothing itself: `engineering.audit_verify` does,
from the raw files. It touches only the containers of this run and the engineering network; the research broker is never addressed.
"""
import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

from engineering import env

ROOT = env.ROOT
PY = ROOT / ".venv" / "Scripts" / "python.exe"
IMAGE = "azta-journal-runtime:gate3"
NETWORK = "azta-eng_default"
FAULT_OFFSETS_S = dict(adapter_kill=100, pep_kill=230, pep_network_cut=360)       # engineering fixtures: seconds after the observer's coverage start
PROBE_HOST_S, PROBE_CONTAINER_S, PROBE_INTERVAL_MS = 75, 65, 100


def utc_ns():
    return time.time_ns()


def probe_command(directory, run_id):
    mount = str(Path(directory).resolve()).replace("\\", "/")
    return ["docker", "run", "--rm", "--name", f"clockprobe-{run_id}", "--label", "com.docker.compose.project=clock-witness-sidecar", "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pull", "never", "-v", f"{mount}:/probe", "--entrypoint", "python", IMAGE, "-B", "/probe/clock_probe.py", "container",
            "--directory", "/probe", "--duration-s", str(PROBE_CONTAINER_S), "--interval-ms", str(PROBE_INTERVAL_MS)]


def clock_preflight(out_dir, run_id):
    probe = out_dir / "probe"
    probe.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(ROOT / "rehearsal_tools" / "clock_criteria.example.json", probe / "criteria.json")          # criteria fixed before the measurement
    host = subprocess.Popen([str(PY), "-B", str(ROOT / "rehearsal_tools" / "clock_probe.py"), "host", "--directory", str(probe), "--duration-s", str(PROBE_HOST_S), "--interval-ms",
                             str(PROBE_INTERVAL_MS)], cwd=ROOT, stdout=open(out_dir / "probe.host.out", "wb"), stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    deadline = time.monotonic() + 15
    while not (probe / "clock_probe.py").exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    if not (probe / "clock_probe.py").exists():
        host.kill()
        raise RuntimeError("the host probe never created its directory")
    container = subprocess.Popen(probe_command(probe, run_id), cwd=ROOT, stdout=open(out_dir / "probe.container.out", "wb"), stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    container.wait()
    host.wait()
    done = subprocess.run([str(PY), "-B", str(ROOT / "rehearsal_tools" / "clock_probe.py"), "evaluate", "--result", str(probe / "probe_result.json"), "--criteria", str(probe / "criteria.json"),
                           "--out", str(probe / "evaluation.json")], cwd=ROOT, capture_output=True, text=True)
    evaluation = json.loads((probe / "evaluation.json").read_text(encoding="utf-8")) if (probe / "evaluation.json").exists() else {}
    return probe / "evaluation.json", evaluation.get("status"), done.returncode


def supervisor_events(run_dir):
    path = run_dir / "service" / "supervisor.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()] if path.exists() else []


def worker_starts(run_dir, worker):
    return [e for e in supervisor_events(run_dir) if e["kind"] == "WORKER_STARTED" and e["worker"] == worker]


def wait_for(predicate, seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.5)
    return False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--baseline-policy-sha256", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--no-faults", action="store_true", help="run the service without injected faults")
    parser.add_argument("--stop-after-s", type=float, help="instead of faults, request the operator's early stop this many seconds after the observer's coverage start")
    args = parser.parse_args(argv)
    run_id = args.run_id
    out_dir = Path(args.out_dir).resolve() / run_id
    out_dir.mkdir(parents=True, exist_ok=False)
    run_dir = ROOT / "results" / "engineering" / "runs" / run_id
    pep_container = f"azta-eng-continuous-{run_id}"
    result = dict(run_id=run_id, started_utc_ns=utc_ns(), faults=[], notes=[])
    keep = subprocess.Popen([str(PY), "-I", "-B", str(ROOT / "rehearsal_tools" / "keep_awake.py"), "1700"], cwd=ROOT)
    try:
        running = subprocess.run(["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True, timeout=60).stdout.split()
        if running != ["azta-eng-broker-1"]:
            raise RuntimeError(f"unexpected running containers: {running}")
        evaluation, status, code = clock_preflight(out_dir, run_id)
        result["clock_preflight"] = dict(status=status, evaluate_exit=code, evaluation=str(evaluation))
        if status != "PASS":
            raise RuntimeError(f"the clock preflight is {status}: nothing is started")
        command = [str(PY), "-B", "-m", "engineering.continuous", "--run-id", run_id, "--plan", args.plan, "--baseline-policy-sha256", args.baseline_policy_sha256,
                   "--authorization-ref", "AUDIT-PREPUSH-20261024", "--audit-interval-s", "30", "--audit-edge-margin-s", "5", "--clock-tolerance-ns", "250000000",
                   "--stall-timeout-ns", "30000000000", "--restart-limit", "5", "--max-attempts", "2", "--escalate-after", "1", "--deescalate-after", "1",
                   "--poll-interval-s", "0.25", "--max-duration-s", "760", "--retry-delay-s", "1", "--shutdown-timeout-s", "45", "--max-decision-age-s", "120",
                   "--clock-evaluation", str(evaluation), "--clock-evaluation-max-age-s", "120"]
        log = open(out_dir / "continuous.log", "wb")
        service = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        result["service_pid"] = service.pid
        result["launched_utc_ns"] = utc_ns()
        coverage = wait_for(lambda: service.poll() is not None or b"coverage start observed" in (out_dir / "continuous.log").read_bytes(), 180)
        if service.poll() is not None or not coverage:
            raise RuntimeError(f"the service did not reach observer coverage (exit {service.poll()})")
        t0 = time.monotonic()
        result["coverage_seen_utc_ns"] = utc_ns()
        if args.stop_after_s is not None:
            time.sleep(args.stop_after_s)
            (run_dir / "service" / "REQUEST_STOP").touch()
            result["early_stop_requested_utc_ns"] = utc_ns()
        elif not args.no_faults:
            def at(seconds):
                time.sleep(max(0.0, t0 + seconds - time.monotonic()))
            at(FAULT_OFFSETS_S["adapter_kill"])
            before = len(worker_starts(run_dir, "adapter"))
            pid = worker_starts(run_dir, "adapter")[-1]["pid"]
            killed = subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, text=True)
            restarted = wait_for(lambda: len(worker_starts(run_dir, "adapter")) > before, 60)
            result["faults"].append(dict(kind="ADAPTER_PROCESS_KILL", pid=pid, taskkill_exit=killed.returncode, utc_ns=utc_ns(), supervisor_restarted_it=restarted))
            at(FAULT_OFFSETS_S["pep_kill"])
            before = len(worker_starts(run_dir, "pep"))
            killed = subprocess.run(["docker", "kill", pep_container], capture_output=True, text=True)
            restarted = wait_for(lambda: len(worker_starts(run_dir, "pep")) > before, 60)
            result["faults"].append(dict(kind="PEP_CONTAINER_KILL", docker_exit=killed.returncode, utc_ns=utc_ns(), supervisor_restarted_it=restarted))
            at(FAULT_OFFSETS_S["pep_network_cut"])
            before = len(worker_starts(run_dir, "pep"))
            cut = subprocess.run(["docker", "network", "disconnect", NETWORK, pep_container], capture_output=True, text=True)
            restarted = wait_for(lambda: len(worker_starts(run_dir, "pep")) > before, 90)
            result["faults"].append(dict(kind="PEP_NETWORK_CUT", docker_exit=cut.returncode, utc_ns=utc_ns(), supervisor_restarted_it=restarted))
        try:
            result["service_exit"] = service.wait(timeout=1100)
        except subprocess.TimeoutExpired:
            result["notes"].append("service did not finish in time; requesting stop")
            (run_dir / "service" / "REQUEST_STOP").touch()
            result["service_exit"] = service.wait(timeout=120)
    except Exception as exc:                                    # the failure is recorded, never hidden
        result["harness_error"] = f"{type(exc).__name__}: {exc}"
    finally:
        keep.terminate()
        result["finished_utc_ns"] = utc_ns()
        result["supervisor_events"] = [dict(kind=e["kind"], worker=e.get("worker"), restart=e.get("restart"), exit=e.get("exit")) for e in supervisor_events(run_dir)]
        (out_dir / "audit-live-result.json").write_text(json.dumps(result, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "supervisor_events"}, sort_keys=True))
    expected_exit = 3 if args.stop_after_s is not None else 0          # an early stop is a supervised STOP (exit 3), not a completed observation
    return 0 if result.get("service_exit") == expected_exit and "harness_error" not in result else 1


if __name__ == "__main__":
    sys.exit(main())
