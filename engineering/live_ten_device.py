"""Ten-device functional run on the isolated engineering broker (Master Implementation 2): connectivity, namespace isolation, honest eligibility.

    python -m engineering.live_ten_device --run-id g5d3a-fx-ID --baseline-policy-sha256 H --eligible-windows N

One invocation, serial, on the `azta-eng` broker only. Order: (1) the engineering fixture of the ten functional slots (offline, deterministic); (2) the data-plane isolation probe of EVERY
device, before any session exists; (3) the read-only binding audit `pre` under the ten-device registry; (4) the dedicated receive-only observer `azta-observer` (registry v2) and ten
publisher containers, each holding ONLY its own credential; (5) the `post` audit; (6) the per-device reconciliation (planned = attempted = accepted = uniquely observed, bound by exact
topic); (7) the readiness report (`engineering.ten_device_report`): isolation, communication, score-ready windows, the route resolution of the committed candidate registry and the named
reasons adaptive scoring is not available. It creates no manifest entry, joins no partition, approves nothing and mutates no policy.

Exit: 0 reconciliation CONSISTENT and every isolation check holds, 4 deviations, 3 STOP, 2 refused.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

from engineering import env
from engineering import ten_device_report as report
from experiments import gate5d3_plan

ROOT = env.ROOT
COMPOSE = env.compose_prefix()
IMAGE = "azta-journal-runtime:gate3"
BROKER_CONTAINER = "azta-eng-broker-1"
DEVICES = [f"device{n:02d}" for n in range(1, 11)]
REGISTRY_V2 = "/app/configs/observation/device_registry_v2.json"
WINDOW_MS = 10_000
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class Stop(Exception):
    pass


def utc():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def names(*args):
    out = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=60)
    return [line for line in out.stdout.split() if line]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--baseline-policy-sha256", required=True)
    parser.add_argument("--eligible-windows", required=True, type=int)
    args = parser.parse_args(argv)
    run_id = args.run_id
    if not run_id.startswith(gate5d3_plan.RUN_ID_PREFIX) or not SHA256.fullmatch(args.baseline_policy_sha256) or not (4 <= args.eligible_windows <= 120):
        print("REFUSED invalid argument", file=sys.stderr)
        return 2
    try:
        run_dir = env.make_run_dir(run_id)
    except (ValueError, OSError) as exc:
        print(f"REFUSED run directory: {type(exc).__name__}", file=sys.stderr)
        return 2
    lead_in, window_count = 1, args.eligible_windows + 2
    lines = []

    def log(line):
        lines.append(f"{utc()} {line}")
        (run_dir / "logs" / "orchestrator.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(line, flush=True)

    def compose(extra, timeout=900):
        environment = dict(os.environ, ENG_RUN_DIR="./" + run_dir.relative_to(ROOT).as_posix(), MSYS_NO_PATHCONV="1")
        return subprocess.run(COMPOSE + extra, cwd=ROOT, capture_output=True, text=True, timeout=timeout, env=environment)

    def audit(stage):
        ref = f"{run_id}-audit-{stage}"
        out = compose(["--profile", "operator", "run", "--rm", "--no-deps", "-T", "binding-audit", "--run-id", ref, "--registry", REGISTRY_V2])
        log(f"audit-{stage} exit={out.returncode} {out.stdout.strip()[:140]}")
        path = run_dir / ref / "binding_audit.json"
        result = json.loads(path.read_text(encoding="utf-8")) if out.returncode == 0 and path.exists() else None
        return None if result is None or result.get("verdict") != "PASS" or result.get("policy_sha256") != args.baseline_policy_sha256 else result

    observer, publishers = f"azta-eng-ob-{run_id}", {d: f"azta-eng-pub{d[-2:]}-{run_id}" for d in DEVICES}
    try:
        image = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE], capture_output=True, text=True, timeout=60)
        if image.returncode != 0:
            raise Stop("accepted runtime image missing (no build performed)")
        image_id = image.stdout.strip()
        running = names("ps", "--filter", "label=com.docker.compose.project=azta-eng", "--format", "{{.Names}}")
        if running != [BROKER_CONTAINER]:
            raise Stop(f"unexpected engineering containers: {running}")
        # 1. fixture (offline)
        fixture_path = run_dir / "gate5d3_fixtures" / f"{run_id}.json"
        rc = gate5d3_plan.main(["--run-id", run_id, "--output", str(fixture_path), "--eligible-windows", str(args.eligible_windows)])
        if rc != 0:
            raise Stop("fixture builder refused")
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        log(f"fixture {run_id}: fixture_sha256={fixture['fixture_sha256'][:16]} devices={len(fixture['devices'])} eligible_windows={args.eligible_windows} window_count={window_count}")
        # 2. isolation probes (before any observer or publisher exists: the probe uses the observer and receiver principals)
        for i, device in enumerate(DEVICES, 1):
            out = compose(["--profile", "operator", "run", "--rm", "--no-deps", "-T", "eng-probe", "matrix", "--device", device, "--phase", "ten", "--out",
                           f"/results/probes/{i:03d}-ten-{device}.json"])
            log(f"probe {device} exit={out.returncode} {out.stdout.strip()[:120]}")
        # 3. pre audit under the ten-device registry
        if audit("pre") is None:
            raise Stop("pre-run binding audit failed or the policy digest differs from the baseline; nothing started")
        # 4. observer and ten publishers
        env_args = ["-e", f"AZTA_RUNTIME_IMAGE={image_id}"]
        out = compose(["--profile", "observer", "run", "-d", "--no-deps", "-T", "--name", observer, *env_args, "eng-observer-v2", "--purpose", "FUNCTIONAL_TEST", "--collection-run-id",
                       run_id, "--window-duration-ms", str(WINDOW_MS), "--window-count", str(window_count), "--binding-audit-ref", f"{run_id}-audit-pre"])
        if out.returncode != 0:
            raise Stop(f"observer did not start: {out.stderr[-200:]}")
        for device, name in publishers.items():
            out = compose(["--profile", "devices", "run", "-d", "--no-deps", "-T", "--name", name, *env_args, f"eng-publisher-{device}", "--fixture",
                           f"/results/gate5d3_fixtures/{run_id}.json", "--expected-run-id", run_id, "--expected-fixture-sha256", fixture["fixture_sha256"]])
            if out.returncode != 0:
                raise Stop(f"publisher {device} did not start: {out.stderr[-200:]}")
        log("observer and ten publishers started")
        exits = {}
        for name in [observer, *publishers.values()]:
            exits[name] = subprocess.run(["docker", "wait", name], capture_output=True, text=True, timeout=3600).stdout.strip()
            text = subprocess.run(["docker", "logs", name], capture_output=True, text=True, timeout=120)
            (run_dir / "logs" / f"{name}.log").write_text(text.stdout + text.stderr, encoding="utf-8")
            subprocess.run(["docker", "rm", name], capture_output=True, text=True, timeout=60)
        bad = {n: c for n, c in exits.items() if c != "0"}
        log(f"container exits: {'all 0' if not bad else bad}")
        post = audit("post")
        sessions = sorted(p.name for p in (run_dir / "observation").iterdir() if p.is_dir())
        if len(sessions) != 1:
            raise Stop(f"expected exactly one observer session, found {len(sessions)}")
        session = sessions[0]
        # 6. reconciliation (offline container: no network, no secret)
        out = compose(["--profile", "operator", "run", "--rm", "--no-deps", "-T", "eng-v2-tools", "experiments.gate5d3_reconcile", "--fixture", f"/results/gate5d3_fixtures/{run_id}.json",
                       "--workload-run-dir", f"/results/gate5d3_workload/{run_id}", "--observation-root", "/results/observation", "--output", f"/results/gate5d3_reconcile_{run_id}.json"])
        log(f"reconcile exit={out.returncode} {out.stdout.strip()[:200]}")
        reconciliation = run_dir / f"gate5d3_reconcile_{run_id}.json"
        if not reconciliation.exists():
            raise Stop("reconciliation produced no report")
        # 7. readiness report (offline, host)
        rc = report.main(["--run-dir", str(run_dir), "--run-id", run_id, "--session-id", session, "--reconciliation", str(reconciliation), "--lead-in-windows", str(lead_in),
                          "--eligible-windows", str(args.eligible_windows), "--out", str(run_dir / "ten_device_readiness.json")])
        verdict = json.loads(reconciliation.read_text(encoding="utf-8"))["verdict"]
        ready = json.loads((run_dir / "ten_device_readiness.json").read_text(encoding="utf-8")) if rc == 0 else None
        isolation_ok = bool(ready) and ready["summary"]["isolation_ok"] == 10
        print(f"TEN_DEVICE_RESULT run_id={run_id} reconciliation={verdict} isolation_ok={isolation_ok} post_audit={'PASS' if post else 'FAIL'} observer_session={session}")
        if not post or bad:
            raise Stop("a container failed or the post-run audit drifted")
        return 0 if verdict == "CONSISTENT" and isolation_ok else 4
    except Stop as exc:
        print(f"CAMPAIGN_STOP {run_id} {exc}")
        return 3


if __name__ == "__main__":
    sys.exit(main())
