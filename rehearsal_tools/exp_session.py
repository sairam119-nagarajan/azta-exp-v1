"""Formal Experimental Validation (AZTA-EXP-v1, addendum 1): one formal session on the isolated pilot broker, the same four steps as the frozen `stb_live_session.py`, whose helpers
(probes, binding audit, enforced-state read-back, protected fingerprints, compose project) it reuses unchanged. Nothing here authors an approval or clicks for the owner.

    python -I -B rehearsal_tools/exp_session.py --run exp-s01 verify --source-commit C     # the recorded authorization and the release against the repository; leaves the broker up
    python -I -B rehearsal_tools/exp_session.py --run exp-s01 run [--as exp-sNN]           # pre probes, core_runtime run (shadow or active-authorized), the scenario driver
    python -I -B rehearsal_tools/exp_session.py --run exp-s01 finish [--restore device02]  # restores only what the answer names, post probes, final audit, fingerprints, down WITHOUT -v

Shadow sessions take no owner and must change nothing: a device that is not at FULL_ACCESS after a shadow session is a stop condition (finish keeps the stack up and restores nothing).
Active sessions are device02 only, with the owner signed in at the console (presence file fresh within 30 s), exactly as STABILIZATION_LIVE_4/5.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "rehearsal_tools")]

import stb_live_session as sls                    # noqa: E402  (frozen helpers; only their module-level run binding is set here)

PY = sls.PY
MATRIX = "configs/formal/exp_matrix_v1.json"
PROTOCOL = "docs/final/AZTA_FORMAL_EXPERIMENT_PROTOCOL.md"
APPROVALS = "configs/formal/approvals"
SESSIONS = "configs/formal/sessions"
FORMAL_OUT = ROOT / "results/engineering/formal"
REQUESTS = {"shadow": ("FORMAL_SHADOW_S1", "FORMAL_SHADOW_S2"), "active-authorized": ("FORMAL_ACTIVE",)}
ACTIVE_SCOPE = {"device02": ["RESTRICT", "QUARANTINE", "RESTORE"]}
APPROVAL_MARGIN_S = 1800


def matrix():
    return json.loads((ROOT / MATRIX).read_text(encoding="utf-8"))


def mode_of(run_id):
    return matrix()["runs"][run_id]["mode"]


def approval_path(run_id):
    found = sorted((ROOT / APPROVALS).glob(f"*/{run_id}/session_approval_{run_id}.json"))
    if len(found) != 1:
        return None
    return found[0].relative_to(ROOT).as_posix()


def bind(run_id):
    """Point the frozen helpers at this run (they read module globals: RUN, OUT, SIDE)."""
    sls.RUN = run_id
    sls.OUT = ROOT / "results/engineering/pilot" / run_id
    sls.SIDE = ROOT / "results/engineering/pilot" / f"{run_id}-session"
    sls.PRESENCE = ROOT / "results/engineering/core_final" / f"console_presence_{run_id}.json"
    sls.OPERATOR_REF = f"OPERATOR-{run_id.upper()}"


def say(text):
    sls.say(text)


def allowed_after_answer(path):
    """Between the answered (addendum) commit and HEAD only the recorded authorization may change: approval records and the active session files that pin them."""
    return path.startswith(APPROVALS + "/") or (path.startswith(SESSIONS + "/exp-a") and path.endswith(".json"))


def release_problems():
    import exp_addendum
    return exp_addendum.verify_all()["problems"]


def verify(args):
    from core_runtime import cli
    from decision_pipeline.registry import canonical, record_sha256
    from engineering import approvals
    from trust.config import TrustConfig
    run_id, mode = args.run, mode_of(args.run)
    session_rel = f"{SESSIONS}/{run_id}.json"
    approval_rel = approval_path(run_id)
    now = time.time_ns()
    checks = dict(approval_record_found=approval_rel is not None, session_file_exists=(ROOT / session_rel).exists())
    session = json.loads((ROOT / session_rel).read_text(encoding="utf-8")) if checks["session_file_exists"] else {}
    approval = json.loads((ROOT / approval_rel).read_text(encoding="utf-8")) if approval_rel else {}
    changed = sorted(sls.run(["git", "diff", "--name-only", args.source_commit, "HEAD"]).stdout.split())
    plan = json.loads((ROOT / session["plan"]).read_text(encoding="utf-8")) if session.get("plan") and (ROOT / session["plan"]).exists() else {}
    problems = release_problems()
    checks.update(
        release_verified_freeze_and_addendum=not problems,
        tree_clean=not sls.run(["git", "status", "--porcelain"]).stdout.strip(),
        source_unchanged_since_the_answered_commit=bool(changed is not None) and all(allowed_after_answer(p) for p in changed),
        approval_names_this_session=bool(approval) and approval.get("purpose") in REQUESTS[mode] and approval.get("mode") == mode and approval.get("run_id") == run_id and bool(approval.get("approved_by")),
        approval_valid_for_the_session=bool(approval) and approval["approved_utc_ns"] <= now and now + APPROVAL_MARGIN_S * 10**9 < approval["expires_utc_ns"],
        approval_names_the_current_artifacts=bool(approval) and approval.get("protocol_sha256") == sls.sha(PROTOCOL) and approval.get("route_sha256") == sls.sha(cli.ROUTE) and approval.get("authority_map_sha256") == sls.sha(cli.AUTHORITY),
        session_file_is_the_run=session.get("run_id") == run_id and session.get("baseline_policy_sha256") == sls.BASELINE,
        device_identities_exact=bool(plan) and {d: i["client_id"] for d, i in plan["runs"][run_id]["devices"].items()} == {d: f"azta-device-{d[-2:]}" for d in sls.DEVICES},
        run_id_is_fresh=not (ROOT / "results/engineering/runs" / run_id).exists() and not (ROOT / "results/engineering/pilot" / run_id).exists() and not (ROOT / "results/engineering/pilot" / f"{run_id}-session").exists()
                        and not (ROOT / "results/engineering" / f"pilot_{run_id}_launch.out").exists(),
        docker_context=sls.run(["docker", "context", "show"]).stdout.strip() == "desktop-linux",
        images_exact=sls.run(["docker", "image", "inspect", "--format", "{{.Id}}", "eclipse-mosquitto:2.1.2-alpine"]).stdout.strip() == sls.BROKER_IMAGE
                     and sls.run(["docker", "image", "inspect", "--format", "{{.Id}}", "azta-journal-runtime:gate3"]).stdout.strip() == sls.RUNTIME_IMAGE,
        no_other_azta_container_running=sls.all_azta_running() == [],
        volume_exists=sls.VOLUME in sls.run(["docker", "volume", "ls", "--format", "{{.Name}}"]).stdout.split(),
        protected_fingerprints_unchanged=sls.fingerprints())
    if mode == "shadow":
        checks["shadow_session_takes_no_approval_or_scope"] = not any(session.get(k) for k in ("operational_approval", "authority_scope", "approved_registry"))
    else:
        directory = (ROOT / approval_rel).parent if approval_rel else ROOT / APPROVALS / "missing"
        try:
            scope = json.loads((directory / "authority_scope.json").read_text(encoding="utf-8"))
            registry_text = (directory / "registry_approved.json").read_text(encoding="utf-8")
            registry = json.loads(registry_text)
            config = TrustConfig.from_dict(json.loads((ROOT / cli.CONFIG).read_text(encoding="utf-8")))
            loaded = approvals.load_approvals(directory / "operational_approval.json", authorized_approval_sha256=session["operational_approval_sha256"], registry_path=directory / "registry_approved.json",
                                              config_path=ROOT / cli.CONFIG, calibration_path=directory / "calibration_bundle.json", now_ns=now)
            rel = directory.relative_to(ROOT)
            checks.update(
                session_file_pins_the_records=session["operational_approval_sha256"] == sls.sha(rel / "operational_approval.json") and session["authority_scope_sha256"] == sls.sha(rel / "authority_scope.json"),
                operational_approval_loads=loaded.missing() == [] and approvals.scope_of(directory / "operational_approval.json", authorized_approval_sha256=session["operational_approval_sha256"], now_ns=now) == approvals.PILOT_CORE_SCOPE,
                registry_canonical_and_approved=canonical(registry) == registry_text and record_sha256(registry) == loaded.registry_sha256 and registry["status"] == "CONTROLLER_APPROVED",
                scope_is_exact={d: x["actions"] for d, x in scope["devices"].items()} == ACTIVE_SCOPE and {d for d, x in scope["devices"].items() if x["automatic"]} == {"device02"}
                              and scope["session_run_id"] == run_id and scope["environment"] == "PILOT_ISOLATED" and scope["mode"] == "active-authorized",
                scope_names_the_current_artifacts=scope["artifacts"] == dict(registry_sha256=loaded.registry_sha256, config_sha256=config.sha256(), route_sha256=sls.sha(cli.ROUTE), authority_map_sha256=sls.sha(cli.AUTHORITY)),
                console_login_exists=bool(json.loads((ROOT / "results/engineering/core_final/operator.json").read_text(encoding="utf-8")).get("operator_ref")))
        except (OSError, KeyError, ValueError, TypeError) as exc:
            checks["active_records_load"] = False
            checks["active_records_error"] = False
            say(f"active records did not load: {type(exc).__name__}: {exc}")
    broker = dict(started=False)
    if all(v is True for v in checks.values()):
        sls.run(sls.COMPOSE + ["up", "-d", "--no-build", "--pull", "never", "broker"], timeout=180)
        time.sleep(5)
        inspect = sls.run(["docker", "inspect", "--format", "{{.Id}} {{.Image}} {{json .HostConfig.PortBindings}}", sls.BROKER]).stdout.split()
        audit = sls.binding_audit(f"{run_id}-verify-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
        broker = dict(started=True, container_id=inspect[0] if inspect else None, image=inspect[1] if len(inspect) > 1 else None, host_ports=inspect[2] if len(inspect) > 2 else None, audit=audit)
        checks.update(only_the_pilot_broker_up=sls.containers() == [sls.BROKER], broker_image_exact=broker["image"] == sls.BROKER_IMAGE, no_host_port=broker["host_ports"] in ("{}", "null"),
                      baseline_policy_digest=audit["passed"] and audit["policy_sha256"] == sls.BASELINE)
    document = dict(schema="azta.formal.session_preconditions", run_id=run_id, mode=mode, approval=approval_rel, approval_sha256=sls.sha(approval_rel) if approval_rel else None,
                    answered_source_commit=args.source_commit, head=sls.run(["git", "rev-parse", "HEAD"]).stdout.strip(), changed_since_the_answered_commit=changed, release_problems=problems[:20],
                    verified_utc_ns=time.time_ns(), all_pass=all(v is True for v in checks.values()), checks=checks, broker=broker)
    if not document["all_pass"] and broker["started"]:
        sls.run(sls.COMPOSE + ["down"], timeout=180)
    FORMAL_OUT.mkdir(parents=True, exist_ok=True)
    path = FORMAL_OUT / f"preconditions_{run_id}.json"
    if path.exists():
        path.rename(path.with_name(f"preconditions_{run_id}_superseded_{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.json"))
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(document, stream, indent=1, sort_keys=True)
    print(json.dumps(dict(run_id=run_id, all_pass=document["all_pass"], failed=[k for k, v in checks.items() if v is not True]), indent=1))
    return 0 if document["all_pass"] else 3


def session_run(args):
    run_id, mode = args.run, mode_of(args.run)
    verified = FORMAL_OUT / f"preconditions_{run_id}.json"
    pre = json.loads(verified.read_text(encoding="utf-8")) if verified.exists() else {}
    if pre.get("all_pass") is not True:
        say("STOP: the session's preconditions were not verified; nothing was started")
        return 2
    approval_rel = pre["approval"]
    if sls.sha(approval_rel) != pre["approval_sha256"]:
        say("STOP: the approval changed after verification")
        return 2
    if mode == "active-authorized":
        try:
            seen_s = (time.time_ns() - json.loads(sls.PRESENCE.read_text(encoding="utf-8"))["utc_ns"]) / 1e9
        except (OSError, ValueError, KeyError):
            seen_s = None
        if seen_s is None or seen_s > sls.PRESENCE_FRESH_S:
            say(f"STOP: no signed-in console page in the last {sls.PRESENCE_FRESH_S} s (last seen: {seen_s}); nothing was started")
            return 2
    if sls.containers() != [sls.BROKER]:
        say(f"STOP: expected exactly {sls.BROKER} up: {sls.containers()}")
        return 2
    session_rel = f"{SESSIONS}/{run_id}.json"
    session = json.loads((ROOT / session_rel).read_text(encoding="utf-8"))
    if not sls.probe("pre", sls.DEVICES):
        say("STOP: the PRE probes did not all succeed; nothing was started")
        return 3
    (sls.SIDE / "pre_state.json").write_text(json.dumps(dict(pre_containers=sls.containers()), indent=1), encoding="utf-8")
    launch_out = (ROOT / "results/engineering" / f"pilot_{run_id}_launch.out").open("x", encoding="utf-8")
    launcher = subprocess.Popen([PY, "-B", "-m", "core_runtime", "run", "--mode", mode, "--session-file", session_rel, "--approval", approval_rel, "--approval-sha256", pre["approval_sha256"]],
                                cwd=ROOT, stdout=launch_out, stderr=subprocess.STDOUT, env=sls.ENV)
    say(f"core_runtime started (pid {launcher.pid}, mode {mode}); the clock probe takes about 3 minutes per attempt")
    log = ROOT / "results/engineering/runs" / run_id / "logs/orchestrator.log"
    driver = None
    deadline = time.time() + 2400
    while launcher.poll() is None and time.time() < deadline:
        if driver is None and log.exists() and "coverage start observed" in log.read_text(encoding="utf-8", errors="replace"):
            command = [PY, "-I", "-B", "rehearsal_tools/exp_operator.py", "--run-id", run_id, "--mode", "shadow" if mode == "shadow" else "active"]
            if session.get("time_cut_after_s"):
                launch = json.loads((sls.OUT / "launch.json").read_text(encoding="utf-8"))
                command += ["--time-cut-utc-ns", str(int(sls.launch_started_ns(launch["started_utc"]) + session["time_cut_after_s"] * 1e9))]
            if mode != "shadow":
                command += ["--presence-file", str(sls.PRESENCE)]
            if args.as_run:
                command += ["--as", args.as_run]
            driver = subprocess.Popen(command, cwd=ROOT, env=sls.ENV)
            say(f"scenario driver started (pid {driver.pid})")
        time.sleep(2)
    if launcher.poll() is None:
        launcher.kill()
        say("the launcher exceeded 40 minutes and was stopped")
    code = launcher.wait()
    driver_code = driver.wait() if driver else None
    say(f"launcher exit {code}; scenario driver exit {driver_code}")
    states = sls.enforced_states()
    (sls.SIDE / "states_after_session.json").write_text(json.dumps(states, indent=1, sort_keys=True), encoding="utf-8")
    not_full = [d for d, v in states.items() if "FULL_ACCESS" not in (v.get("states") or [])]
    restricted = [d for d, v in states.items() if v.get("states") == ["RESTRICT"]]
    if restricted and mode != "shadow":
        sls.probe("restricted", restricted)
    summary = dict(run_id=run_id, mode=mode, as_run=args.as_run, launcher_exit=code, driver_exit=driver_code, coverage_reached=driver is not None, states_read=bool(states),
                   not_at_full_access=not_full, restricted_probed=restricted if mode != "shadow" else [], policy_changed_in_shadow=mode == "shadow" and bool(not_full))
    (sls.SIDE / "session_run.json").write_text(json.dumps(summary, indent=1, sort_keys=True), encoding="utf-8")
    print(json.dumps(summary, indent=1, sort_keys=True))
    if summary["policy_changed_in_shadow"]:
        say(f"STOP CONDITION: a shadow session left {not_full} not at FULL_ACCESS")
        return 4
    return 0 if code == 0 and driver_code == 0 else 1


def finish(args):
    run_id, mode = args.run, mode_of(args.run)
    target = sls.OUT if sls.OUT.exists() else sls.SIDE
    target.mkdir(parents=True, exist_ok=True)
    if mode == "shadow" and args.restore:
        say("REFUSED: a shadow session restores nothing; a changed policy is a stop condition")
        return 2
    restored, failed = [], []
    for device in args.restore or ():
        out = sls.run([PY, "-I", "-B", "rehearsal_tools/pilot_restore.py", "--run-id", run_id, "restore", "--device", device, "--operator-ref", sls.OPERATOR_REF], timeout=300)
        ok = "APPLIED_VERIFIED" in out.stdout
        with (target / "final_restores.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(dict(device=device, answer_ref=args.answer_ref, ok=ok, utc_ns=time.time_ns(), stdout=out.stdout.strip()[-300:]), sort_keys=True) + "\n")
        (restored if ok else failed).append(device)
        say(f"post-session RESTORE of {device}: {'APPLIED_VERIFIED' if ok else 'NOT VERIFIED'}")
    up = sls.containers() == [sls.BROKER]
    states = sls.enforced_states() if up else {}
    still = [d for d, v in states.items() if "FULL_ACCESS" not in (v.get("states") or [])]
    if up and (failed or still or not states):
        say(f"restoration_failed_STOP: failed {failed}, not at FULL_ACCESS {still}. The stack stays up; no further mutation.")
        with (target / "restoration_failed_STOP.json").open("x", encoding="utf-8") as stream:
            json.dump(dict(failed=failed, not_at_full_access=still, states=states), stream, indent=1, sort_keys=True)
        return 3
    probed = sls.probe("post", sls.DEVICES) if up else None
    audit = sls.binding_audit(f"{run_id}-audit-final") if up else dict(passed=None, policy_sha256=None)
    protected = sls.fingerprints()
    down = sls.run(sls.COMPOSE + ["down"], timeout=180)
    document = dict(run_id=run_id, mode=mode, broker_was_up=up, post_probes_ok=probed, final_audit_policy_sha256=audit["policy_sha256"], final_audit_pass=audit["passed"],
                    baseline_restored=audit["policy_sha256"] == sls.BASELINE if up else None, restored_after_session=restored, down_exit=down.returncode, down_used_v=False,
                    containers_after_down=sls.containers(), volume_kept=sls.VOLUME in sls.run(["docker", "volume", "ls", "--format", "{{.Name}}"]).stdout.split(), protected_fingerprints_unchanged=protected)
    with (target / "post_state.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(document, stream, indent=1, sort_keys=True)
    print(json.dumps(document, indent=1, sort_keys=True))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    w = sub.add_parser("verify")
    w.add_argument("--source-commit", required=True)
    r = sub.add_parser("run")
    r.add_argument("--as", dest="as_run", default=None)
    f = sub.add_parser("finish")
    f.add_argument("--answer-ref", default="FORMAL-CLEANUP")
    f.add_argument("--restore", action="append", choices=sls.DEVICES)
    args = parser.parse_args(argv)
    if args.run not in matrix()["runs"]:
        parser.error(f"{args.run} is not a run of the experiment matrix")
    bind(args.run)
    return dict(verify=verify, run=session_run, finish=finish)[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
