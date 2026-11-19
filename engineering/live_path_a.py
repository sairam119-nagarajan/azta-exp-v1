"""Path A on the isolated engineering broker: GENUINE live MQTT telemetry, observed and audited, for the real frozen S/V models (Master Implementation 2).

    python -m engineering.live_path_a --run-id ID --plan configs/collection_plans/PLAN.json --baseline-policy-sha256 H --audit-interval-s N --audit-edge-margin-s M

One invocation is one FUNCTIONAL_TEST run, serial, on the `azta-eng` broker only: read-only binding audit `pre`, the publisher-only workload-v2 container (device credentials only; it waits
for the observer's coverage start), the receive-only observer (the legacy two-device `azta-pdp` principal, registry v1), read-only audits at a declared cadence anchored at the observer's
own COVERAGE_START, a `post` audit, and the offline reconciliation (no network, no secret). It is the FUNCTIONAL_TEST branch of `experiments/collection_run_v2.ps1` re-targeted to the
engineering project; it creates no manifest entry, joins no scientific partition, mutates no broker policy and never touches the research broker. The windows it produces are engineering
evidence: they exercise the real observer and the real frozen models; they are not calibration, not detection evidence and not a scientific run.

Optional `--dev-perturbation configs/dev_perturbations/NAME.json` swaps the workload service for the DEVELOPMENT_ONLY perturbed publisher (`engineering.dev_workload`); everything else, including the
audits, is unchanged. Such a run is development evidence only and its reconciliation against the unperturbed plan is expected to flag the deliberate differences.

Exit: 0 the reconciliation verdict is ACCEPT, 4 another verdict, 3 STOP (inspect before anything else runs), 2 refused.
"""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

from engineering import env, policy_changes

ROOT = env.ROOT
COMPOSE = env.compose_prefix()
IMAGE = "azta-journal-runtime:gate3"
BROKER_CONTAINER = f"{env.PROJECT}-broker-1"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
PLAN_PATH = re.compile(r"configs/collection_plans/[A-Za-z0-9_-]+\.json\Z")
PERTURBATION_PATH = re.compile(r"configs/dev_perturbations/[A-Za-z0-9_-]+\.json\Z")


class Stop(Exception):
    pass


def utc():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


COMPLETION_MARGIN_S = 1800      # Gate 6C pre-live: the wait for the observer and workload containers to finish is the planned coverage PLUS this margin (it was a flat 1800 s, which silently limited a run to about 80 minutes)


def run_cmd(args, *, run_dir, timeout=900, check=False):
    environment = dict(os.environ, ENG_RUN_DIR="./" + run_dir.relative_to(ROOT).as_posix(), MSYS_NO_PATHCONV="1")
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=timeout, env=environment)
    if check and result.returncode != 0:
        raise Stop(f"command failed: {' '.join(args[:6])}...: {(result.stderr or result.stdout)[-300:]}")
    return result


def docker_names(*args):
    out = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=60)
    return [line for line in out.stdout.split() if line]


def snapshot(observation_dir):
    names = sorted(p.name for p in observation_dir.iterdir() if p.is_dir()) if observation_dir.exists() else []
    text = "".join(f"{n}\n" for n in names)
    return names, "v1:" + ",".join(names), hashlib.sha256(text.encode("ascii")).hexdigest()


FLEET_PROFILE = dict(
    plan_schema="azta.gate6b.fleet_plan", workload_service="fleet-workload", observer_service="eng-observer-v2", workload_registry_args=[],
    audit_args=["--registry", "/app/configs/observation/device_registry_v2.json"])


def main(argv=None, *, service=None, profile=None):
    """`profile` (Gate 6B): None keeps the two-device behaviour exactly. FLEET_PROFILE runs a fleet plan on the registry-v2 observer (azta-observer): the fleet interactive workload, the
    ten-device registry in every binding audit, and no plan-bound reconciliation (a fleet run is dynamic and enforcement changes the policy: it would be VOID by design)."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--baseline-policy-sha256", required=True)
    parser.add_argument("--audit-interval-s", required=True, type=int)
    parser.add_argument("--audit-edge-margin-s", required=True, type=int)
    parser.add_argument("--dev-perturbation")
    parser.add_argument("--revalidate-after-policy-change", action="store_true", help="Gate 6B (F1): follow the run's PEP audit logs and take one extra read-only binding audit as soon as the PEP has verified a change of any device's policy, so that identity evidence which postdates the change exists within seconds (the periodic cadence is unchanged)")
    parser.add_argument("--expect-policy-change", action="store_true", help="the run hosts an approved PEP on the pilot broker: a changed policy digest is then EXPECTED and recorded, not a drift; a failed audit still stops the periodic audits")
    args = parser.parse_args(argv)
    run_id, plan_rel = args.run_id, args.plan.replace("\\", "/")
    if not SHA256.fullmatch(args.baseline_policy_sha256) or not PLAN_PATH.fullmatch(plan_rel) or not (0 < args.audit_interval_s <= 3600) or not (1 <= args.audit_edge_margin_s <= args.audit_interval_s):
        print("REFUSED invalid argument", file=sys.stderr)
        return 2
    perturbation = args.dev_perturbation.replace("\\", "/") if args.dev_perturbation else None
    if perturbation and (not PERTURBATION_PATH.fullmatch(perturbation) or not (ROOT / perturbation).is_file()):
        print("REFUSED invalid or missing development perturbation specification", file=sys.stderr)
        return 2
    plan = json.loads((ROOT / plan_rel).read_text(encoding="utf-8"))
    if plan.get("schema") != (profile["plan_schema"] if profile else "azta.collection.plan_candidate") or plan.get("kind") != "FUNCTIONAL_TEST" or run_id not in plan.get("runs", {}):
        print("REFUSED the plan is not a FUNCTIONAL_TEST plan naming this run", file=sys.stderr)
        return 2
    config = plan["runs"][run_id]
    window_ms, window_count = int(config["window_duration_ms"]), int(config["planned_window_count"])
    coverage_s = window_ms * window_count / 1000.0
    try:
        run_dir = env.make_run_dir(run_id)
    except (ValueError, OSError) as exc:
        print(f"REFUSED run directory: {type(exc).__name__}", file=sys.stderr)
        return 2
    logs = run_dir / "logs"
    log_lines = []

    def log(line):
        log_lines.append(f"{utc()} {line}")
        (logs / "orchestrator.log").write_text("\n".join(log_lines) + "\n", encoding="utf-8")
        print(line, flush=True)

    workload, observer = f"{env.PROJECT}-wl-{run_id}", f"{env.PROJECT}-ob-{run_id}"
    try:
        image = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE], capture_output=True, text=True, timeout=60)
        if image.returncode != 0:
            raise Stop("accepted runtime image missing (no build performed)")
        image_id = image.stdout.strip()
        running = docker_names("ps", "--filter", f"label=com.docker.compose.project={env.PROJECT}", "--format", "{{.Names}}")
        if running != [BROKER_CONTAINER]:
            raise Stop(f"unexpected engineering containers: {running}")
        if [n for n in docker_names("ps", "-a", "--format", "{{.Names}}") if n in (workload, observer)]:
            raise Stop("leftover container of an earlier attempt of this run")
        log(f"pre: image={image_id[:19]} containers={running} purpose=FUNCTIONAL_TEST cadence={args.audit_interval_s}s margin={args.audit_edge_margin_s}s coverage={coverage_s:.0f}s")

        def audit(stage):
            ref = f"{run_id}-audit-{stage}"
            out = run_cmd(COMPOSE + ["--profile", "operator", "run", "--rm", "--no-deps", "-T", "binding-audit", "--run-id", ref, *(profile["audit_args"] if profile else [])], run_dir=run_dir)
            log(f"audit-{stage} exit={out.returncode} {out.stdout.strip()[:140]}")
            path = run_dir / ref / "binding_audit.json"
            if out.returncode != 0 or not path.exists():
                return None
            return json.loads(path.read_text(encoding="utf-8"))

        def drifted(result):
            return result is None or result.get("verdict") != "PASS" or (not args.expect_policy_change and result.get("policy_sha256") != args.baseline_policy_sha256)

        if drifted(audit("pre")):
            raise Stop("pre-run binding audit failed or the policy digest differs from the baseline; no workload started")
        if service:
            service.start(run_dir)
        names, value, digest = snapshot(run_dir / "observation")
        log(f"pre-existing observer sessions: {len(names)} sha256={digest[:16]}")
        env_args = ["-e", f"AZTA_RUNTIME_IMAGE={image_id}"]
        service_name, extra = ("dev-workload", ["--perturbation", f"/app/{perturbation}"]) if perturbation else ("v2-workload", [])
        extra = extra + list(profile.get("workload_args", [])) if profile else extra       # e.g. --isolation per-device (Gate 6B F2)
        if profile:
            if not perturbation:
                print("REFUSED a fleet run needs the interactive perturbation specification", file=sys.stderr)
                return 2
            service_name = profile["workload_service"]
        out = run_cmd(COMPOSE + ["--profile", "devices", "run", "-d", "--no-deps", "-T", "--name", workload, *env_args, "-e", f"AZTA_PREEXISTING_SESSIONS={value}", "-e",
                                 f"AZTA_PREEXISTING_SESSIONS_SHA256={digest}", service_name, "--purpose", "FUNCTIONAL_TEST", "--plan", f"/app/{plan_rel}", "--run-id", run_id, *extra], run_dir=run_dir)
        if out.returncode != 0:
            raise Stop(f"workload container did not start: {out.stderr[-200:]}")
        observer_failed = False
        out = run_cmd(COMPOSE + ["--profile", "observer", "run", "-d", "--no-deps", "-T", "--name", observer, *env_args, profile["observer_service"] if profile else "eng-v2-observer", "--purpose", "FUNCTIONAL_TEST",
                                 "--collection-run-id", run_id, "--window-duration-ms", str(window_ms), "--window-count", str(window_count), "--binding-audit-ref",
                                 f"{run_id}-audit-pre"], run_dir=run_dir)
        if out.returncode != 0:
            observer_failed = True
            log(f"observer did not start: {out.stderr[-200:]}")

        def observer_running():
            result = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", observer], capture_output=True, text=True, timeout=60)
            return result.stdout.strip() == "true"

        session = None

        def find_session():
            nonlocal session
            if session:
                return session
            base = run_dir / "observation"
            if not base.exists():
                return None
            found = []
            for d in base.iterdir():
                meta = d / "session_metadata.json"
                if d.is_dir() and d.name not in names and meta.exists():
                    try:
                        if json.loads(meta.read_text(encoding="utf-8")).get("collection_run_id") == run_id:
                            found.append(d.name)
                    except ValueError:
                        continue
            if len(found) > 1:
                raise Stop("more than one NEW observer session names this run")
            session = found[0] if found else None
            if session and service:
                service.attached(session)
            return session

        def coverage_start():
            name = find_session()
            health = run_dir / "observation" / name / "health.jsonl" if name else None
            if not health or not health.exists():
                return None
            for line in health.read_text(encoding="utf-8").splitlines():
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if record.get("kind") == "COVERAGE_START":
                    return datetime.fromisoformat(record["utc"].replace("Z", "+00:00")).timestamp()
            return None

        if not observer_failed:
            start = None
            while start is None and observer_running():
                if service:
                    service.tick()
                start = coverage_start()
                if start is None:
                    time.sleep(0.5)
            if start is not None:
                log(f"coverage start observed (UTC epoch {start:.3f}); periodic audits every {args.audit_interval_s}s")
                follower = policy_changes.PolicyChangeFollower(run_dir / "pep") if args.revalidate_after_policy_change else None
                taken = 0                                           # audits taken so far: stage names follow the order of execution (the live audit source requires capture order)

                def revalidation_due():
                    """True when the PEP has verified a policy change that no audit has started after yet. An unreadable log is retried at the next tick; a broken chain stops the campaign."""
                    if follower is None or taken >= 98:
                        return False
                    try:
                        return bool(follower.poll())
                    except policy_changes.PolicyChangesUnreadable:
                        return False
                    except policy_changes.PolicyChangesIntegrityError as exc:
                        raise Stop(f"PEP audit log integrity failure: {exc}") from None

                for k in range(1, 100):
                    due = start + k * args.audit_interval_s
                    if due + args.audit_edge_margin_s > start + coverage_s:
                        break
                    wait = due - time.time()
                    while wait > 0 and not observer_failed:
                        if service:
                            service.tick()
                        if revalidation_due() and observer_running():
                            taken += 1
                            log(f"policy change verified by the PEP: immediate revalidation audit p{taken:02d}")
                            if drifted(audit(f"p{taken:02d}")):
                                log(f"revalidation audit {taken} failed or drifted")
                                observer_failed = True
                                break
                        time.sleep(min(wait, 0.5))
                        wait = due - time.time()
                    if observer_failed:
                        break
                    if not observer_running():
                        log(f"observer stopped before periodic audit {k}")
                        break
                    taken += 1
                    if drifted(audit(f"p{taken:02d}")):
                        log(f"periodic audit {k} failed or drifted")
                        observer_failed = True
                        break
            else:
                log("observer coverage start was never observed; no periodic audit taken")
        exits = {}
        for name in (observer, workload):
            if service:
                deadline = time.monotonic() + coverage_s + COMPLETION_MARGIN_S
                while name in docker_names("ps", "--format", "{{.Names}}"):
                    service.tick()
                    if time.monotonic() >= deadline:
                        raise Stop("container completion deadline reached")
                    time.sleep(0.5)
            exits[name] = subprocess.run(["docker", "wait", name], capture_output=True, text=True, timeout=coverage_s + COMPLETION_MARGIN_S).stdout.strip()
            text = subprocess.run(["docker", "logs", name], capture_output=True, text=True, timeout=120)
            (logs / f"{name}.log").write_text(text.stdout + text.stderr, encoding="utf-8")
            subprocess.run(["docker", "rm", name], capture_output=True, text=True, timeout=60)
        if exits[observer] != "0":
            observer_failed = True
        log(f"observer_failed={observer_failed} observer_exit={exits[observer]} workload_exit={exits[workload]}")
        post_drift = drifted(audit("post"))
        if service:
            service.finish()
        find_session()
        if not session:
            raise Stop("no NEW observer session was created for this run; nothing is reconciled by scanning")
        if profile:
            print(f"RUN_RESULT {run_id} purpose=FUNCTIONAL_TEST fleet=1 verdict=NOT_RECONCILED_BY_DESIGN observer_session={session} post_audit_drift={post_drift}")
            return 3 if post_drift else 0
        reconcile = run_cmd(COMPOSE + ["--profile", "operator", "run", "--rm", "--no-deps", "-T", "eng-v2-tools", "experiments.collection_reconcile_v2", "--run-id", run_id, "--plan",
                                       f"/app/{plan_rel}", "--purpose", "FUNCTIONAL_TEST", "--baseline-policy-sha256", args.baseline_policy_sha256, "--audit-interval-s",
                                       str(args.audit_interval_s), "--observer-session-id", session], run_dir=run_dir)
        log(f"reconcile exit={reconcile.returncode} {reconcile.stdout.strip()[:300]}")
        if reconcile.returncode == 2:
            raise Stop("reconciliation could not run")
        report = json.loads((run_dir / "collection" / run_id / "reconciliation.json").read_text(encoding="utf-8"))
        verdict = report.get("verdict")
        print(f"RUN_RESULT {run_id} purpose=FUNCTIONAL_TEST verdict={verdict} campaign_stop={report.get('campaign_stop')} review_flags={len(report.get('review_flags') or [])} "
              f"observer_session={session} post_audit_drift={post_drift}")
        if verdict == "NOT_STARTED":
            raise Stop("the run did not start")
        if report.get("campaign_stop") or post_drift:
            raise Stop("campaign STOP condition (see the reconciliation report)")
        return 0 if verdict == "ACCEPT" else 4
    except Stop as exc:
        print(f"CAMPAIGN_STOP {run_id} {exc}")
        return 3
    finally:
        if service:
            service.close()
        env.stop_run_containers(run_id, logs)


if __name__ == "__main__":
    sys.exit(main())
