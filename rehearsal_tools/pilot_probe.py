"""Independent data-plane probes of the PILOT broker (what it actually ALLOWS), for the closed-loop demonstration.

    python -I -B rehearsal_tools/pilot_probe.py --dir NAME --phase PHASE [--device device01 --device device02]

Runs `engineering.probe matrix` for each device in the operator profile (the probe controller holds the device credentials itself; it is neither a PDP nor the PEP). The probe connects
AS the device, so it must never run while that device's publisher is connected (same client id). Results are written to results/engineering/runs/NAME/probes/ and summarised on stdout:
the CONNACK outcome, the PUBACK/SUBACK codes (0 success, 16 accepted without matching subscribers, 135 not authorized) and what the observer and operations receiver actually received.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("AZTA_ENG_PROJECT", "azta-pilot")
os.environ.setdefault("AZTA_ENG_COMPOSE_OVERLAY", "compose.pilot.yaml")
from engineering import env  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", required=True)
    parser.add_argument("--phase", required=True)
    parser.add_argument("--device", action="append", required=True, choices=tuple(f"device{n:02d}" for n in range(1, 11)))
    args = parser.parse_args(argv)
    base = ROOT / "results/engineering/runs" / args.dir
    run_dir = base if base.exists() else env.make_run_dir(args.dir)
    environment = dict(os.environ, ENG_RUN_DIR="./" + run_dir.relative_to(ROOT).as_posix(), MSYS_NO_PATHCONV="1")
    for device in args.device:
        name = f"{args.phase}-{device}.json"
        result = subprocess.run(env.compose_prefix() + ["--profile", "operator", "run", "--rm", "--no-deps", "-T", "eng-probe", "matrix", "--device", device, "--phase", args.phase,
                                                          "--out", f"/results/probes/{name}"], cwd=ROOT, env=environment, capture_output=True, text=True, timeout=300)
        path = run_dir / "probes" / name
        if result.returncode != 0 or not path.exists():
            print(f"{device} probe failed exit={result.returncode} {(result.stderr or result.stdout)[-300:]}")
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        print(f"== {device} {args.phase}")
        print(json.dumps(data, sort_keys=True)[:1800])
    return 0


if __name__ == "__main__":
    sys.exit(main())
