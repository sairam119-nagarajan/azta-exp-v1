"""The ONE documented entry point of the AZTA core runtime (the logical PDP/PEP session). `pdp/subscriber.py` is the preserved Gate 3 scaffold and is not part of this path.

    python -B -m core_runtime validate                                                  # offline: every pin, every model, the registry and the authority map; no MQTT, no Docker
    python -B -m core_runtime plan --mode shadow --session-file S.json                  # offline: the exact supervised command this session would run; starts nothing
    python -B -m core_runtime run  --mode shadow --session-file S.json --approval A.json --approval-sha256 H   # live: refuses unless a fresh written session approval names exactly this session
    python -B -m core_runtime console --session-dir DIR --pep-log FILE                  # the local operator console (loopback)

Modes: `shadow` (zero policy changes: no authority block, the PEP service is the refusal boundary), `review` (every action needs an exact operator approval), `active-authorized` (AUTO_ELIGIBLE devices named automatic in the written scope act; all others are reviewed).
A session approval (`azta.core.session_approval`) is written and pinned by the owner or Controller for one request id. This code never authors, renews or extends one: silence, an expired record or another session's record refuses. It carries no secret.
Exit codes: 0 valid or finished, 2 refused, 3 stopped on an integrity failure.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
MODES = ("shadow", "review", "active-authorized")
APPROVAL_SCHEMA = "azta.core.session_approval"
ROUTE = "configs/exp_v1/route_ae_primary_exp_v1.json"          # AZTA-EXP-v1 (stabilization): the CAL5 constants for devices 05-09; v1 route kept unchanged in configs/core_final/
REGISTRY = "configs/exp_v1/registry_ae_primary_exp_v1.json"    # AZTA-EXP-v1: v1 registry + the recalibrated monitor-profile identities (supersedes v1)
AUTHORITY = "configs/core_final/authority_map_v1.json"
CONFIG = "configs/exp_v1/trust_config_exp_v1.json"            # AZTA-EXP-v1: tau_Q 65 (supervisor Option B, 10 Nov 2026; configs/exp_v1/trust_parameters_decision_exp_v1.json); the ctx2 record (tau_Q 70) is kept unchanged
REQUIRED_SESSION = {"label", "run_id", "plan", "dev_perturbation", "baseline_policy_sha256", "authorization_ref", "clock_session_s"}
SESSION_KEYS = REQUIRED_SESSION | {"max_duration_s", "review_ttl_s", "rc1_live", "rc1_container", "operational_approval", "operational_approval_sha256", "approved_registry", "approved_config", "calibration_bundle", "authority_scope", "authority_scope_sha256", "time_cut_device", "time_cut_after_s"}
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


class Refused(Exception):
    pass


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def rel(path):
    return ROOT / path


def validate(root=ROOT):
    """Offline: loads everything through the verifying loaders. Returns the manifest of digests; anything wrong raises."""
    from core_runtime import loader
    from decision_pipeline.registry import record_sha256
    from enforcement.authority import AuthorityMap
    from model import autoencoder as ae
    from trust.config import TrustConfig
    from trust.engine import DecisionEngine
    ae.configure_determinism()
    behavior = loader.load_primary(root, route_path=root / ROUTE, route_sha256=sha(root / ROUTE))
    config = TrustConfig.from_dict(json.loads((root / CONFIG).read_text(encoding="utf-8")))
    engine = loader.wrap(DecisionEngine(config, behavior), repo_root=root, registry_path=root / REGISTRY, registry_sha256=sha(root / REGISTRY))
    authority = AuthorityMap.load(root / AUTHORITY, sha(root / AUTHORITY))
    route = json.loads((root / ROUTE).read_text(encoding="utf-8"))
    registry = json.loads((root / REGISTRY).read_text(encoding="utf-8"))
    return dict(result="VALID", engine=type(engine).__name__, contract=route["contract"], route_status=route["status"], registry_status=registry["status"], config_status=config.config_status, config_sha256=config.sha256(), route_sha256=sha(root / ROUTE),
                registry_file_sha256=sha(root / REGISTRY), registry_record_sha256=record_sha256(registry), authority_map_sha256=sha(root / AUTHORITY), authority_status=authority.data["status"], inputs=route["inputs"],
                devices={d: dict(profile=r["profile"], arm=r["arm"], kind=r["kind"], width_s=r["width_s"], mode=authority.mode(d), model_id=behavior.provenance["models"][r["profile"]]["fit_id"], model_sha256=behavior.provenance["models"][r["profile"]]["weights_sha256"]) for d, r in route["devices"].items()})


def load_session(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    unknown = set(data) - SESSION_KEYS
    if unknown:
        raise Refused(f"unknown session fields: {sorted(unknown)}")
    missing = REQUIRED_SESSION - set(data)
    if missing:
        raise Refused(f"missing session fields: {sorted(missing)}")
    if not IDENTIFIER.fullmatch(str(data["run_id"])):
        raise Refused("the run id is not an identifier")
    return data


def command(mode, session, *, root=ROOT):
    """The exact argument list for `rehearsal_tools/fleet_run.py` (keep-awake, a fresh clock certificate against criteria saved before the measurement, the context policy, then the supervised service). N = 2 and de-escalation `deny` are fixed there, not options."""
    if mode not in MODES:
        raise Refused("unknown mode")
    route = json.loads((root / ROUTE).read_text(encoding="utf-8"))
    inputs = route["inputs"]
    continuous = ["--pep-target", "PILOT_CORE_BROKER", "--core-route", ROUTE, "--core-route-sha256", sha(root / ROUTE), "--core-mode", mode, "--authority-map", AUTHORITY, "--authority-map-sha256", sha(root / AUTHORITY)]
    if session.get("max_duration_s"):
        continuous += ["--max-duration-s", str(session["max_duration_s"])]
    if session.get("rc1_live"):
        continuous += ["--rc1-live", "--rc1-container", session["rc1_container"]]
    a = ["--label", session["label"], "--run-id", session["run_id"], "--plan", session["plan"], "--baseline-policy-sha256", session["baseline_policy_sha256"], "--authorization-ref", session["authorization_ref"], "--dev-perturbation", session["dev_perturbation"], "--clock-session-s", str(session["clock_session_s"]),
         "--trust-config", CONFIG, "--cal-v2", inputs["cal_v2"]["path"], "--models-record", inputs["fleet_models"]["path"], "--compat-record", inputs["compat"]["path"]]
    if session.get("time_cut_device"):        # the declared withdrawal of one device's operating time (context, not behaviour): the launcher writes it into the context policy before the session
        a += ["--time-cut-device", session["time_cut_device"], "--time-cut-after-s", str(session["time_cut_after_s"])]
    if mode == "shadow":
        for key in ("operational_approval", "authority_scope"):
            if session.get(key):
                raise Refused("shadow mode takes no approval and no scope")
        a += ["--profile-registry", REGISTRY]
    else:
        for key in ("operational_approval", "operational_approval_sha256", "approved_registry", "approved_config", "calibration_bundle", "authority_scope", "authority_scope_sha256", "review_ttl_s"):
            if not session.get(key):
                raise Refused(f"mode {mode} needs {key}")
        if session["approved_config"] != CONFIG:
            raise Refused("the operating configuration is the pinned one")
        a += ["--profile-registry", session["approved_registry"], "--approval", session["operational_approval"], "--approval-sha256", session["operational_approval_sha256"], "--calibration-record", session["calibration_bundle"]]
        continuous += ["--authority-scope", session["authority_scope"], "--authority-scope-sha256", session["authority_scope_sha256"], "--review-ttl-s", str(session["review_ttl_s"])]
    return a + [f"--continuous-arg={token}" for token in continuous]

def check_session_approval(path, sha256, *, mode, session, now_ns):
    """The owner's or Controller's written record for THIS session. Everything is compared; nothing is inferred from silence, elapsed time or an earlier campaign."""
    if not sha256 or not path:
        raise Refused("no session approval: live actions stay disabled")
    if sha(path) != sha256:
        raise Refused("the session approval is not the pinned file")
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    expected = {"schema", "request_id", "purpose", "mode", "run_id", "approved_by", "approved_utc_ns", "expires_utc_ns", "protocol_sha256", "route_sha256", "authority_map_sha256"}
    if not isinstance(data, dict) or set(data) != expected or data["schema"] != APPROVAL_SCHEMA:
        raise Refused("not a session approval record")
    if data["mode"] != mode or data["run_id"] != session["run_id"]:
        raise Refused("the approval names another mode or session")
    if not (type(data["approved_utc_ns"]) is int and type(data["expires_utc_ns"]) is int and data["approved_utc_ns"] <= now_ns < data["expires_utc_ns"]):
        raise Refused("the approval is expired or not yet valid")
    if data["route_sha256"] != sha(rel(ROUTE)) or data["authority_map_sha256"] != sha(rel(AUTHORITY)):
        raise Refused("the approval names other artifacts")
    if not (isinstance(data["approved_by"], str) and data["approved_by"]):
        raise Refused("the approval names no approver")
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate")
    for name in ("plan", "run"):
        p = sub.add_parser(name)
        p.add_argument("--mode", choices=MODES, required=True)
        p.add_argument("--session-file", required=True)
        if name == "run":
            p.add_argument("--approval")
            p.add_argument("--approval-sha256")
    console = sub.add_parser("console")
    console.add_argument("--session-dir", required=True)
    console.add_argument("--pep-log", default=None)
    console.add_argument("--port", type=int, default=8765)
    console.add_argument("--operator-file", required=True, help="the local operator credential record (`python -m core_runtime.console.auth create`)")
    console.add_argument("--simulator-control", default=None)
    console.add_argument("--presence-file", default=None, help="written while a signed-in page polls; a policy-changing session reads it")
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            print(json.dumps(validate(), indent=1, sort_keys=True))
            return 0
        if args.command in ("plan", "run"):
            session = load_session(args.session_file)
            arguments = command(args.mode, session)
            if args.command == "plan":
                print(json.dumps(dict(result="PLANNED_NOT_STARTED", mode=args.mode, tool="rehearsal_tools/fleet_run.py", arguments=arguments), indent=1))
                return 0
            check_session_approval(args.approval, args.approval_sha256, mode=args.mode, session=session, now_ns=time.time_ns())
            return subprocess.run([sys.executable, "-I", "-B", str(ROOT / "rehearsal_tools" / "fleet_run.py"), *arguments], cwd=ROOT).returncode
        from core_runtime.console import server
        return server.main(args)
    except Refused as exc:
        print(f"CORE_RUNTIME_REFUSED {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
