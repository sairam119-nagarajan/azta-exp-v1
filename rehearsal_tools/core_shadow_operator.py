"""Core completion: the scripted operator of an approved shadow session: ONE allowlisted anomaly on ONE device for a bounded time, after a benign settling period, through the run's control channel. It acts on nothing else. Found by `core-s01`: a PowerShell script launched in a fresh process was blocked by the execution policy and sent nothing, so this is a Python tool that logs from its first line.

    python -I -B rehearsal_tools/core_shadow_operator.py --run-id core-s02 --device device02 --anomaly payload --settle-s 150 --duration-s 60 --wait-s 720 --log results/engineering/core_final/s02_operator.log

Exit codes: 0 start and stop were accepted; 2 the run never reported RUNNING (nothing was sent); 3 a command was refused.
"""
import argparse
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from engineering import attack_control as ac      # noqa: E402

MAX_DURATION_S = 120


def main(argv=None, *, sleep=time.sleep, now=time.monotonic):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--device", required=True)
    parser.add_argument("--anomaly", required=True, choices=sorted(ac.CATALOGUE))
    parser.add_argument("--settle-s", type=float, required=True)
    parser.add_argument("--duration-s", type=float, required=True)
    parser.add_argument("--wait-s", type=float, required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--stop-worker-after-s", type=float, default=None, help="after the anomaly, wait this long and stop the fleet.live_worker process of this run once; the supervisor restarts it (the G4 restart exercise, shadow sessions only)")
    parser.add_argument("--root", default=str(ROOT), help="tests only")
    args = parser.parse_args(argv)
    if not 0 < args.duration_s <= MAX_DURATION_S:
        parser.error(f"--duration-s must be in (0, {MAX_DURATION_S}]")
    log = Path(args.log)
    log.parent.mkdir(parents=True, exist_ok=True)

    def say(text):
        with log.open("a", encoding="utf-8") as stream:
            stream.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {text}\n")
    say(f"operator started: run {args.run_id}, {args.anomaly} on {args.device}, settle {args.settle_s} s, duration {args.duration_s} s")
    directory = ac.control_dir(args.run_id, Path(args.root))
    deadline = now() + args.wait_s
    while True:
        status = ac.read_status(directory) if directory.exists() else None
        if isinstance(status, dict) and status.get("phase") == "RUNNING":
            break
        if now() >= deadline:
            say("the run never reported RUNNING; no anomaly was sent")
            return 2
        sleep(2)
    say("RUNNING seen; settling on benign traffic")
    sleep(args.settle_s)
    ok, message = ac.perform(directory, "start", args.device, args.anomaly, None, "core-shadow-operator")
    say(f"START ok={ok}: {str(message)[:300]}")
    if not ok:
        return 3
    sleep(args.duration_s)
    ok, message = ac.perform(directory, "stop", args.device, None, None, "core-shadow-operator")
    say(f"STOP ok={ok}: {str(message)[:300]}")
    if not ok:
        return 3
    if args.stop_worker_after_s is not None:
        sleep(args.stop_worker_after_s)
        say(stop_worker(args.run_id))
    return 0


def stop_worker(run_id):
    """One forced stop of this run's adapter worker (its command line names the run's service spec). Windows only; nothing else is touched."""
    query = f"Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | Where-Object {{ $_.CommandLine -match 'fleet.live_worker' -and $_.CommandLine -match '{run_id}' }} | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force; $_.ProcessId }}"
    out = subprocess.run(["powershell.exe", "-NoProfile", "-Command", query], capture_output=True, text=True, timeout=60).stdout.split()
    return f"WORKER_STOPPED pid={out[0]}" if out else "WORKER_NOT_FOUND"


if __name__ == "__main__":
    sys.exit(main())
