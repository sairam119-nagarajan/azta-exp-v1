"""Stabilization (AZTA-EXP-v1): the supervised policy-changing session STABILIZATION_LIVE_1 (`stb-l01`), the same four steps as `core_pilot_session.py` (cloned, constants changed). Nothing here authors an approval.

    python -I -B rehearsal_tools/stb_live_session.py preflight --out FILE.json     # read-only; no publisher, no PEP, no policy change; stack down afterwards
    python -I -B rehearsal_tools/stb_live_session.py verify --source-commit C      # the owner's conditions against the recorded answer; on success it leaves the pilot broker up for `run`
    python -I -B rehearsal_tools/stb_live_session.py run --approval-sha256 H       # needs a passing `verify`, the owner's recorded answer and the owner present
    python -I -B rehearsal_tools/stb_live_session.py finish --answer-ref REF [--restore device02 ...]   # after the owner names the post-session RESTOREs

`run`: inventory, PRE probes of the ten devices, `core_runtime run`, the scenario driver and the owner's guide; after the session, the enforced state and the RESTRICT probe of whatever is restricted. It restores nothing.
`finish`: the RESTORE of exactly the devices the owner named, POST probes, a read-only final binding audit, the protected-fingerprint check, `down` WITHOUT `-v`, and `post_state.json`. A partial or unknown restoration stops with restoration_failed_STOP and keeps the stack up.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
PY = str(ROOT / ".venv" / "Scripts" / "python.exe")
RUN = "stb-l01"
PROJECT = "azta-pilot"
BROKER = "azta-pilot-broker-1"
VOLUME = "azta-pilot_mosquitto_data"
BASELINE = "3e6c25881bc1846036fa27445001f0a69f39e6dd85bc5e137048a78c03179c7b"
DEVICES = [f"device{n:02d}" for n in range(1, 11)]
SESSION = "configs/stabilization/sessions/stb-l01.json"
APPROVAL = "configs/stabilization/approvals/STABILIZATION_LIVE_1/session_approval_stb-l01.json"
APPROVALS_DIR = "configs/stabilization/approvals/STABILIZATION_LIVE_1"
PROTOCOL = "docs/stabilization/STB_LIVE_SESSION_PROTOCOL.md"
SCOPE_ACTIONS = {"device01": ["RESTRICT", "QUARANTINE", "RESTORE"], "device02": ["RESTRICT", "QUARANTINE", "RESTORE"]}
AUTOMATIC = "device02"
COMPOSE = ["docker", "compose", "-p", PROJECT, "-f", "compose.engineering.yaml", "-f", "compose.pilot.yaml"]
ENV = dict(os.environ, AZTA_ENG_PROJECT=PROJECT, AZTA_ENG_COMPOSE_OVERLAY="compose.pilot.yaml", ENG_RUN_DIR="./results/engineering", PYTHONDONTWRITEBYTECODE="1", MSYS_NO_PATHCONV="1")
OUT = ROOT / "results/engineering/pilot" / RUN
SIDE = ROOT / "results/engineering/pilot" / f"{RUN}-session"
PRESENCE = ROOT / "results/engineering/core_final" / f"console_presence_{RUN}.json"
PRESENCE_FRESH_S = 30
OPERATOR_REF = "OPERATOR-STB-L01"
BROKER_IMAGE = "sha256:38c0da4f2ef84284d47b3b3eeea1cb3bdeabe81ee10caf0cd5c5ff61ee3ea408"
RUNTIME_IMAGE = "sha256:02fdaf88ea83fd61383c12c7333160fb54afcf8845816740ae37c3dab4fec21c"
ALLOWED_AFTER_ANSWER = ("rehearsal_tools/stb_live_session.py", "rehearsal_tools/stb_live_verdict.py", "configs/stabilization/sessions/stb-l01.json")     # the verification gate, a stricter checker and the answer's records; nothing the session executes
REQUEST = "STABILIZATION_LIVE_1"
# The retest after the stb-l01 workload crash (status.json rename race, corrected in engineering/attack_control.replace_status) is the SAME protocol under a
# fresh run id and its own request; stb-l01 stays selectable exactly as it ran. Nothing else differs between the two.
SESSIONS = {"stb-l01": "STABILIZATION_LIVE_1", "stb-l02": "STABILIZATION_LIVE_2", "stb-l03": "STABILIZATION_LIVE_3", "stb-l04": "STABILIZATION_LIVE_4", "stb-l05": "STABILIZATION_LIVE_5"}
# Amendment 4 (`stb-l04`): the supervisor-directed AZTA-EXP-v1 verification (tau_Q 65) is device02 ONLY; the earlier sessions keep their two-device scope.
SCOPES = {"stb-l04": {"device02": ["RESTRICT", "QUARANTINE", "RESTORE"]}, "stb-l05": {"device02": ["RESTRICT", "QUARANTINE", "RESTORE"]}}


def select(run_id):
    global RUN, REQUEST, SESSION, APPROVAL, APPROVALS_DIR, OUT, SIDE, PRESENCE, OPERATOR_REF, ALLOWED_AFTER_ANSWER, SCOPE_ACTIONS
    RUN, REQUEST = run_id, SESSIONS[run_id]
    SCOPE_ACTIONS = SCOPES.get(run_id, SCOPE_ACTIONS)
    SESSION = f"configs/stabilization/sessions/{RUN}.json"
    APPROVALS_DIR = f"configs/stabilization/approvals/{REQUEST}"
    APPROVAL = f"{APPROVALS_DIR}/session_approval_{RUN}.json"
    OUT = ROOT / "results/engineering/pilot" / RUN
    SIDE = ROOT / "results/engineering/pilot" / f"{RUN}-session"
    PRESENCE = ROOT / "results/engineering/core_final" / f"console_presence_{RUN}.json"
    OPERATOR_REF = f"OPERATOR-{RUN.upper()}"
    ALLOWED_AFTER_ANSWER = ("rehearsal_tools/stb_live_session.py", "rehearsal_tools/stb_live_verdict.py", SESSION)


def run(command, **kw):
    return subprocess.run(command, cwd=ROOT, env=kw.pop("env", ENV), capture_output=True, text=True, encoding="utf-8", errors="replace", **kw)


def sha(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def say(text):
    print(time.strftime("%H:%M:%SZ", time.gmtime()) + " " + text, flush=True)


def containers():
    return sorted(run(["docker", "ps", "--format", "{{.Names}}", "--filter", f"label=com.docker.compose.project={PROJECT}"]).stdout.split())


def all_azta_running():
    return sorted(x for x in run(["docker", "ps", "--format", "{{.Names}}"]).stdout.split() if "azta" in x)


def binding_audit(reference):
    environment = dict(ENV, ENG_RUN_DIR="./results/engineering/runs/" + RUN) if (ROOT / "results/engineering/runs" / RUN).is_dir() else dict(ENV, ENG_RUN_DIR="./results/engineering/core_final/preflight_audit")
    (ROOT / environment["ENG_RUN_DIR"]).mkdir(parents=True, exist_ok=True)
    out = run(COMPOSE + ["--profile", "operator", "run", "--rm", "--no-deps", "-T", "binding-audit", "--run-id", reference, "--registry", "/app/configs/observation/device_registry_v2.json"], env=environment, timeout=180)
    text = out.stdout + out.stderr
    found = re.search(r"policy_sha256=([0-9a-f]{64})", text)
    return dict(exit=out.returncode, passed="BINDING_AUDIT PASS" in text, policy_sha256=found.group(1) if found else None)


def probe(phase, devices):
    command = [PY, "-I", "-B", "rehearsal_tools/pilot_probe.py", "--dir", f"{RUN}-probes", "--phase", phase]
    for device in devices:
        command += ["--device", device]
    result = run(command, timeout=1500)
    SIDE.mkdir(parents=True, exist_ok=True)       # never OUT: the launcher requires its own directory to be new, and refuses otherwise (found by the first launch attempt, which started nothing)
    (SIDE / f"probe_{phase}.txt").write_text(result.stdout + result.stderr, encoding="utf-8")
    failed = [line for line in result.stdout.splitlines() if "probe failed" in line]
    say(f"{phase} probes of {len(devices)} devices: exit {result.returncode}, {len(failed)} failed")
    return result.returncode == 0 and not failed


def enforced_states():
    out = run([PY, "-I", "-B", "rehearsal_tools/pilot_restore.py", "--run-id", RUN, "observe"], timeout=300).stdout
    return json.JSONDecoder().raw_decode(out[out.index("{"):])[0].get("devices", {}) if "{" in out else {}


def fingerprints():
    return "PROTECTED_ARTIFACTS_UNCHANGED" in run([PY, "-B", "-I", "rehearsal_tools/prelive_fingerprints.py", "verify", "--baseline", "results/engineering/gate6c/prelive/fingerprints_after_collection.json"]).stdout


def preflight(args):
    """Read-only, with the pilot broker up only for the length of one audit: nothing publishes and nothing can change policy. A failed item is a recorded answer; nothing is repaired."""
    report = {}
    report["head"] = run(["git", "rev-parse", "HEAD"]).stdout.strip()
    report["tree_clean"] = not run(["git", "status", "--porcelain"]).stdout.strip()
    report["docker_context"] = run(["docker", "context", "show"]).stdout.strip()
    report["other_azta_containers_running"] = all_azta_running()
    report["volume_exists"] = VOLUME in run(["docker", "volume", "ls", "--format", "{{.Name}}"]).stdout.split()
    report["run_id_is_fresh"] = not (ROOT / "results/engineering/runs" / RUN).exists() and not OUT.exists()
    report["approval_absent"] = not (ROOT / APPROVAL).exists()
    report["images"] = {name: run(["docker", "image", "inspect", "--format", "{{.Id}}", name]).stdout.strip() for name in ("eclipse-mosquitto:2.1.2-alpine", "azta-journal-runtime:gate3")}
    validate = run([PY, "-B", "-m", "core_runtime", "validate"], timeout=300)
    manifest = json.loads(validate.stdout) if validate.returncode == 0 else {}
    report["validate"] = dict(result=manifest.get("result"), route_sha256=manifest.get("route_sha256"), authority_map_sha256=manifest.get("authority_map_sha256"), config_sha256=manifest.get("config_sha256"), registry_file_sha256=manifest.get("registry_file_sha256"), registry_record_sha256=manifest.get("registry_record_sha256"), route_status=manifest.get("route_status"), config_status=manifest.get("config_status"))
    report["model_digests"] = {d: v["model_sha256"] for d, v in manifest.get("devices", {}).items()}
    report["authority_modes"] = {d: v["mode"] for d, v in manifest.get("devices", {}).items()}
    report["protected_fingerprints_unchanged"] = fingerprints()
    session = json.loads((ROOT / SESSION).read_text(encoding="utf-8"))
    report["session"] = {k: session.get(k) for k in ("run_id", "max_duration_s", "clock_session_s", "review_ttl_s", "time_cut_device", "time_cut_after_s", "baseline_policy_sha256")}
    before = containers()
    report["pilot_containers_before"] = before
    if before:
        report["broker"] = dict(error="the pilot project was already running; nothing was started")
    else:
        up = run(COMPOSE + ["up", "-d", "--no-build", "--pull", "never", "broker"], timeout=180)
        time.sleep(5)
        names = containers()
        inspect = run(["docker", "inspect", "--format", "{{.Id}} {{.Image}} {{.State.Status}} {{json .HostConfig.PortBindings}}", BROKER]).stdout.split()
        audit = binding_audit(f"{RUN}-preflight-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
        report["broker"] = dict(up_exit=up.returncode, containers=names, container_id=inspect[0] if inspect else None, image=inspect[1] if len(inspect) > 1 else None, status=inspect[2] if len(inspect) > 2 else None, host_ports=inspect[3] if len(inspect) > 3 else None, audit=audit, baseline_matches=audit["policy_sha256"] == BASELINE)
        down = run(COMPOSE + ["down"], timeout=180)
        report["broker"]["down_exit"] = down.returncode
        report["broker"]["containers_after_down"] = containers()
        report["broker"]["volume_kept"] = VOLUME in run(["docker", "volume", "ls", "--format", "{{.Name}}"]).stdout.split()
    path = ROOT / args.out
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, indent=1, sort_keys=True)
        stream.write("\n")
    print(json.dumps(report, indent=1, sort_keys=True))
    return 0


def verify(args):
    """The owner's conditions, checked BEFORE the session and recorded: approval, source, digests, identities, authority and the isolated broker. It starts the pilot broker (no publisher, no PEP) and leaves it up for `run`. Any false item: the broker is brought down and the session may not start."""
    sys.path[:0] = [str(ROOT), str(ROOT / "rehearsal_tools")]
    from core_runtime import cli
    from decision_pipeline.registry import canonical, record_sha256
    from engineering import approvals
    from trust.config import TrustConfig
    directory = ROOT / APPROVALS_DIR
    approval = json.loads((ROOT / APPROVAL).read_text(encoding="utf-8"))
    session = json.loads((ROOT / SESSION).read_text(encoding="utf-8"))
    scope = json.loads((directory / "authority_scope.json").read_text(encoding="utf-8"))
    registry_text = (directory / "registry_approved.json").read_text(encoding="utf-8")
    registry = json.loads(registry_text)
    plan = json.loads((ROOT / session["plan"]).read_text(encoding="utf-8"))
    now = time.time_ns()
    changed = sorted(run(["git", "diff", "--name-only", args.source_commit, "HEAD"]).stdout.split())
    config = TrustConfig.from_dict(json.loads((ROOT / cli.CONFIG).read_text(encoding="utf-8")))
    loaded = approvals.load_approvals(directory / "operational_approval.json", authorized_approval_sha256=session["operational_approval_sha256"], registry_path=directory / "registry_approved.json", config_path=ROOT / cli.CONFIG, calibration_path=directory / "calibration_bundle.json", now_ns=now)
    checks = dict(
        tree_clean=not run(["git", "status", "--porcelain"]).stdout.strip(),
        runtime_source_unchanged_since_the_answered_commit=all(p in ALLOWED_AFTER_ANSWER or p.startswith(APPROVALS_DIR + "/") for p in changed),
        approval_names_this_session=(approval["purpose"], approval["mode"], approval["run_id"]) == (REQUEST, "active-authorized", RUN) and bool(approval["approved_by"]),
        approval_valid_for_the_session=approval["approved_utc_ns"] <= now and now + 3600 * 10**9 < approval["expires_utc_ns"],
        approval_names_the_current_artifacts=approval["protocol_sha256"] == sha(PROTOCOL) and approval["route_sha256"] == sha(cli.ROUTE) and approval["authority_map_sha256"] == sha(cli.AUTHORITY),
        session_file_pins_the_records=session["operational_approval_sha256"] == sha(directory.relative_to(ROOT) / "operational_approval.json") and session["authority_scope_sha256"] == sha(directory.relative_to(ROOT) / "authority_scope.json"),
        operational_approval_loads=loaded.missing() == [] and approvals.scope_of(directory / "operational_approval.json", authorized_approval_sha256=session["operational_approval_sha256"], now_ns=now) == approvals.PILOT_CORE_SCOPE,
        registry_canonical_and_approved=canonical(registry) == registry_text and record_sha256(registry) == loaded.registry_sha256 and registry["status"] == "CONTROLLER_APPROVED",
        scope_is_exact={d: x["actions"] for d, x in scope["devices"].items()} == SCOPE_ACTIONS and {d for d, x in scope["devices"].items() if x["automatic"]} == {AUTOMATIC} and scope["session_run_id"] == RUN and scope["environment"] == "PILOT_ISOLATED" and scope["mode"] == "active-authorized",
        scope_names_the_current_artifacts=scope["artifacts"] == dict(registry_sha256=loaded.registry_sha256, config_sha256=config.sha256(), route_sha256=sha(cli.ROUTE), authority_map_sha256=sha(cli.AUTHORITY)),
        device_identities_exact={d: i["client_id"] for d, i in plan["runs"][RUN]["devices"].items()} == {d: f"azta-device-{d[-2:]}" for d in DEVICES},
        run_id_is_fresh=not (ROOT / "results/engineering/runs" / RUN).exists() and not OUT.exists() and not SIDE.exists() and not (ROOT / "results/engineering" / f"pilot_{RUN}_launch.out").exists(),
        console_login_exists=bool(json.loads((ROOT / "results/engineering/core_final/operator.json").read_text(encoding="utf-8")).get("operator_ref")),
        docker_context=run(["docker", "context", "show"]).stdout.strip() == "desktop-linux",
        images_exact=run(["docker", "image", "inspect", "--format", "{{.Id}}", "eclipse-mosquitto:2.1.2-alpine"]).stdout.strip() == BROKER_IMAGE and run(["docker", "image", "inspect", "--format", "{{.Id}}", "azta-journal-runtime:gate3"]).stdout.strip() == RUNTIME_IMAGE,
        no_other_azta_container_running=all_azta_running() == [],
        volume_exists=VOLUME in run(["docker", "volume", "ls", "--format", "{{.Name}}"]).stdout.split(),
        protected_fingerprints_unchanged=fingerprints())
    broker = dict(started=False)
    if all(checks.values()):
        run(COMPOSE + ["up", "-d", "--no-build", "--pull", "never", "broker"], timeout=180)
        time.sleep(5)
        inspect = run(["docker", "inspect", "--format", "{{.Id}} {{.Image}} {{json .HostConfig.PortBindings}}", BROKER]).stdout.split()
        audit = binding_audit(f"{RUN}-verify-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
        broker = dict(started=True, container_id=inspect[0], image=inspect[1], host_ports=inspect[2], audit=audit)
        checks.update(only_the_pilot_broker_up=containers() == [BROKER], broker_image_exact=inspect[1] == BROKER_IMAGE, no_host_port=inspect[2] in ("{}", "null"), baseline_policy_digest=audit["passed"] and audit["policy_sha256"] == BASELINE)
    document = dict(schema="azta.core.pilot_preconditions", request=REQUEST, answered_source_commit=args.source_commit, head=run(["git", "rev-parse", "HEAD"]).stdout.strip(), changed_since_the_answered_commit=changed, verified_utc_ns=time.time_ns(), all_pass=all(checks.values()), checks=checks, broker=broker, clock="measured by the launcher immediately before the session, against criteria saved first: session_s 880, budget 100 ms; it refuses to start on a FAIL")
    if not document["all_pass"] and broker["started"]:
        run(COMPOSE + ["down"], timeout=180)
    path = ROOT / f"results/engineering/core_final/pilot_preconditions_{RUN}.json"
    if path.exists():                  # an earlier verification stays on record; the one the session reads is the latest
        path.rename(path.with_name(f"pilot_preconditions_superseded_{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.json"))
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(document, stream, indent=1, sort_keys=True)
    print(json.dumps(document, indent=1, sort_keys=True))
    return 0 if document["all_pass"] else 3


def session_run(args):
    if sha(APPROVAL) != args.approval_sha256:
        say("STOP: the approval is not the pinned file")
        return 2
    verified = ROOT / f"results/engineering/core_final/pilot_preconditions_{RUN}.json"
    if not verified.exists() or json.loads(verified.read_text(encoding="utf-8")).get("all_pass") is not True:
        say("STOP: the owner's conditions were not verified; nothing was started")
        return 2
    try:
        seen_s = (time.time_ns() - json.loads(PRESENCE.read_text(encoding="utf-8"))["utc_ns"]) / 1e9
    except (OSError, ValueError, KeyError):
        seen_s = None
    if seen_s is None or seen_s > PRESENCE_FRESH_S:
        say(f"STOP: no signed-in console page in the last {PRESENCE_FRESH_S} s (last seen: {seen_s}); nothing was started")
        return 2
    session = json.loads((ROOT / SESSION).read_text(encoding="utf-8"))
    if containers() != [BROKER]:
        say(f"STOP: expected exactly {BROKER} up: {containers()}")
        return 2
    OUT.parent.mkdir(parents=True, exist_ok=True)
    if not probe("pre", DEVICES):
        say("STOP: the PRE probes did not all succeed; nothing was started")
        return 3
    pre_containers = containers()
    (SIDE / "pre_state.json").write_text(json.dumps(dict(pre_containers=pre_containers), indent=1), encoding="utf-8")
    launch_out = (ROOT / "results/engineering" / f"pilot_{RUN}_launch.out").open("x", encoding="utf-8")
    launcher = subprocess.Popen([PY, "-B", "-m", "core_runtime", "run", "--mode", "active-authorized", "--session-file", SESSION, "--approval", APPROVAL, "--approval-sha256", args.approval_sha256], cwd=ROOT, stdout=launch_out, stderr=subprocess.STDOUT, env=ENV)
    say(f"core_runtime started (pid {launcher.pid}); the clock probe takes about 3 minutes per attempt")
    log = ROOT / "results/engineering/runs" / RUN / "logs/orchestrator.log"
    operator = None
    deadline = time.time() + 2400
    while launcher.poll() is None and time.time() < deadline:
        if operator is None and log.exists() and "coverage start observed" in log.read_text(encoding="utf-8", errors="replace"):
            launch = json.loads((OUT / "launch.json").read_text(encoding="utf-8"))
            cut_ns = int(launch_started_ns(launch["started_utc"]) + session["time_cut_after_s"] * 1e9)
            operator = subprocess.Popen([PY, "-I", "-B", "rehearsal_tools/stb_live_operator.py", "--run-id", RUN, "--time-cut-utc-ns", str(cut_ns), "--presence-file", str(PRESENCE)], cwd=ROOT, env=ENV)
            say(f"scenario driver started (pid {operator.pid})")
        time.sleep(2)
    code = launcher.wait()
    say(f"launcher exit {code}")
    operator_code = operator.wait() if operator else None
    say(f"scenario driver exit {operator_code}")
    if operator is None:
        say("STOP: the session never reached its coverage start; no publisher ran under this launch and nothing was changed by it")
        return 3
    states = enforced_states()
    (SIDE / "states_after_session.json").write_text(json.dumps(states, indent=1, sort_keys=True), encoding="utf-8")
    restricted = [d for d, v in states.items() if v.get("states") == ["RESTRICT"]]
    if restricted:
        probe("restricted", restricted)
    contained = [d for d, v in states.items() if "FULL_ACCESS" not in (v.get("states") or [])]
    say(f"enforced states after the session; not at FULL_ACCESS: {contained}; RESTRICT probed: {restricted}")
    print(json.dumps(dict(launcher_exit=code, operator_exit=operator_code, not_at_full_access=contained, restricted_probed=restricted), indent=1))
    return 0 if code == 0 and operator_code == 0 else 1


def launch_started_ns(text):
    from datetime import datetime, timezone
    head, _, frac = text.rstrip("Z").partition(".")
    return int(datetime.strptime(head, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()) * 10**9 + int((frac + "000000000")[:9])


def finish(args):
    restored, failed = [], []
    for device in args.restore or ():
        out = run([PY, "-I", "-B", "rehearsal_tools/pilot_restore.py", "--run-id", RUN, "restore", "--device", device, "--operator-ref", OPERATOR_REF], timeout=300)
        ok = "APPLIED_VERIFIED" in out.stdout
        with (OUT / "final_restores.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(dict(device=device, answer_ref=args.answer_ref, ok=ok, utc_ns=time.time_ns(), stdout=out.stdout.strip()[-300:]), sort_keys=True) + "\n")
        (restored if ok else failed).append(device)
        say(f"post-session RESTORE of {device}: {'APPLIED_VERIFIED' if ok else 'NOT VERIFIED'}")
    states = enforced_states()
    still = [d for d, v in states.items() if "FULL_ACCESS" not in (v.get("states") or [])]
    if failed or still or not states:
        say(f"restoration_failed_STOP: failed {failed}, not at FULL_ACCESS {still}. The stack stays up; no further mutation.")
        with (OUT / "restoration_failed_STOP.json").open("x", encoding="utf-8") as stream:
            json.dump(dict(failed=failed, not_at_full_access=still, states=states), stream, indent=1, sort_keys=True)
        return 3
    probed = probe("post", DEVICES)
    audit = binding_audit(f"{RUN}-audit-final")
    protected = fingerprints()
    pre = json.loads((SIDE / "pre_state.json").read_text(encoding="utf-8"))
    down = run(COMPOSE + ["down"], timeout=180)
    document = dict(pre_containers=pre["pre_containers"], post_probes_ok=probed, final_audit_policy_sha256=audit["policy_sha256"], final_audit_pass=audit["passed"], restored_after_session=restored, down_exit=down.returncode, down_used_v=False, containers_after_down=containers(), volume_kept=VOLUME in run(["docker", "volume", "ls", "--format", "{{.Name}}"]).stdout.split(), protected_fingerprints_unchanged=protected)
    with (OUT / "post_state.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(document, stream, indent=1, sort_keys=True)
    print(json.dumps(document, indent=1, sort_keys=True))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--session", choices=sorted(SESSIONS), default="stb-l01", help="stb-l01 (STABILIZATION_LIVE_1, 8 Nov 2026, FAILED), stb-l02 (STABILIZATION_LIVE_2, 9 Nov 2026, FAILED), stb-l03 (STABILIZATION_LIVE_3, amendment 2, FAILED) or stb-l04 (STABILIZATION_LIVE_4, amendment 4: AZTA-EXP-v1 verification, device02 only, FAILED on the missed RESTORE) or stb-l05 (STABILIZATION_LIVE_5, its unchanged repeat)")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("preflight")
    p.add_argument("--out", required=True)
    w = sub.add_parser("verify")
    w.add_argument("--source-commit", required=True)
    r = sub.add_parser("run")
    r.add_argument("--approval-sha256", required=True)
    f = sub.add_parser("finish")
    f.add_argument("--answer-ref", required=True)
    f.add_argument("--restore", action="append", choices=DEVICES)
    args = parser.parse_args(argv)
    select(args.session)
    return dict(preflight=preflight, verify=verify, run=session_run, finish=finish)[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
