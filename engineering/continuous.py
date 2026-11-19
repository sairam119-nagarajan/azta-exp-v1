"""Supervised, bounded continuous FUNCTIONAL observer -> Shadow -> guarded PEP.

Run with --help. Each declaration authorizes one prospective observer session;
new sessions require new run IDs/declarations. Never restart an observer into an
old session, retry integrity refusals, or silently reuse finished evidence.
The original log-only subscriber is replaced in this deployment by the existing
telemetry observer and IntegratedEngine; neither receives PEP credentials.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import time

from engineering import env, live_path_a, path_a_decide
from rehearsal_tools import live_declarations
from shadow_live.declaration import load_declaration
from shadow_live.session import live_directory


class SupervisionFailed(RuntimeError):
    pass


def clock_deadline(path, *, tolerance_ns, max_age_s, required_s, now_ns=None):
    """Same certificate constraints as the established rehearsal driver.

    This gates execution only; it changes no timestamp, offset or clock model.
    """
    now = time.time_ns() if now_ns is None else now_ns
    certificate = json.loads(Path(path).read_text(encoding="utf-8"))
    criteria = certificate["criteria"]
    age = now / 1e9 - Path(path).stat().st_mtime
    end = certificate["probe_interval_host_wall_ns"][1] + int(criteria["session_s"] * 1e9)
    if (certificate.get("schema") != "azta.gate5f.clock_preflight_evaluation" or certificate.get("status") != "PASS"
            or certificate.get("reasons") or criteria["tolerance_ns"] != tolerance_ns or age > max_age_s or age < -60
            or now + int(required_s * 1e9) > end):
        raise SupervisionFailed("clock preflight missing, expired, mismatched or insufficient for this session")
    return end


APPROVAL_OPTIONS = ("operational_approval", "operational_approval_sha256", "approved_registry", "approved_config")


def operational_approval_plan(a, directory, *, now_ns=None):
    """None without approval options (the unchanged functional path: the PEP service builds an EMPTY approval set and refuses every genuine decision).

    With them (all four are required; the accepted calibration record is optional), the approval is verified COMPLETELY on the host before anything is launched, by the same loader
    the command-line helper uses (pin, schema, role, scope, window, registry/configuration/calibration digests re-derived from the artifacts). Any refusal raises `SupervisionFailed`.
    The PEP container cannot import the engine packages, so the verified approval file is copied byte for byte into the service directory and the container receives the host-verified
    form of the specification section (it re-checks the pin, window and sections; the guard re-checks the artifact digests on every decision). The adapter is pointed at the approved
    registry, configuration and (only when separately approved) calibration record, so the decisions carry the digests the approval names. Nothing is approved or defaulted here."""
    given = {key: getattr(a, key, None) for key in APPROVAL_OPTIONS}
    calibration = getattr(a, "approved_calibration_record", None)
    if not any(given.values()) and not calibration:
        return None
    if not all(given.values()):
        raise SupervisionFailed("the operational approval needs --operational-approval, --operational-approval-sha256, --approved-registry and --approved-config together")
    from engineering import approvals
    from enforcement.errors import ApprovalRefused
    try:
        verified = approvals.load_approvals(given["operational_approval"], authorized_approval_sha256=given["operational_approval_sha256"], registry_path=given["approved_registry"],
                                            config_path=given["approved_config"], calibration_path=calibration, now_ns=time.time_ns() if now_ns is None else now_ns)
    except ApprovalRefused as exc:
        raise SupervisionFailed(f"operational approval refused ({exc.code}); nothing was started") from None
    target = getattr(a, "pep_target", None)
    scope = approvals.scope_of(given["operational_approval"], authorized_approval_sha256=given["operational_approval_sha256"], now_ns=time.time_ns() if now_ns is None else now_ns)
    if scope != (approvals.PILOT_SCOPE if target == "PILOT_BROKER" else approvals.SCOPE) or (target == "PILOT_BROKER" and env.PROJECT != "azta-pilot"):
        raise SupervisionFailed("the approval scope, the --pep-target and the targeted project do not agree; nothing was started")
    copy = Path(directory) / "operational_approval.json"
    copy.write_bytes(Path(given["operational_approval"]).read_bytes())
    if hashlib.sha256(copy.read_bytes()).hexdigest() != given["operational_approval_sha256"]:
        raise SupervisionFailed("the copied approval differs from the pinned one; nothing was started")
    adapter = ["--config", str(Path(given["approved_config"]).resolve()), "--device-profile-registry", str(Path(given["approved_registry"]).resolve()),
               "--device-profile-registry-sha256", verified.registry_sha256]
    if calibration:
        adapter += ["--calibration-record", str(Path(calibration).resolve()), "--calibration-record-sha256", hashlib.sha256(Path(calibration).read_bytes()).hexdigest()]
    else:
        adapter += ["--calibration", "gate5e-v1"]
    section = dict(approval="/results/service/operational_approval.json", approval_sha256=given["operational_approval_sha256"], artifact_verification=approvals.HOST_VERIFIED)
    return dict(adapter=adapter, section=section, approval_id=verified.approval_id, behavioural_decisions_enabled=bool(verified.calibration_id))


class Supervisor:
    """One owner per spec; crash retries are bounded and terminal refusals stop.

    The OS lock releases on process death. Workers' own ledgers/cursors are the
    authority across restart; this class never invents progress or proposals.
    """
    def __init__(self, spec_path, *, popen=subprocess.Popen):
        self.path = Path(spec_path).resolve()
        self.spec = json.loads(self.path.read_text(encoding="utf-8"))
        self.directory = self.path.parent
        self.popen = popen
        self.children, self.restarts, self.logs = {}, {"adapter": 0, "pep": 0}, {}
        self.retry_at = {}
        self.lock = None
        self.failed = False
        for key in ("supervisor_poll_s", "retry_delay_s", "shutdown_timeout_s"):
            if not isinstance(self.spec[key], (float, int)) or not math.isfinite(self.spec[key]) or self.spec[key] <= 0:
                raise ValueError(f"{key} must be finite and positive")
        if type(self.spec["restart_limit"]) is not int or self.spec["restart_limit"] < 0:
            raise ValueError("restart_limit must be a non-negative integer")

    def event(self, kind, **fields):
        with open(self.directory / "supervisor.jsonl", "a", encoding="utf-8") as stream:
            stream.write(json.dumps(dict(kind=kind, utc_ns=time.time_ns(), **fields), sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def acquire(self):
        self.lock = open(self.directory / "owner.lock", "a+b")
        self.lock.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.lock.close()
            self.lock = None
            raise SupervisionFailed("another supervisor owns this session") from None

    def command(self, name):
        if name == "adapter":
            return [sys.executable, "-B", "-m", "engineering.live_worker", str(self.path)]
        return env.compose_prefix() + ["--profile", "enforce", "run", "--rm", "--no-deps", "-T", "--name", self.spec["pep_container"],
            "--entrypoint", "python", "eng-pep", "-B", "-m", "engineering.pep_service", "/results/service/spec.json"]

    def launch(self, name):
        log = open(self.directory / f"{name}-{self.restarts[name]}.log", "ab")
        self.logs.setdefault(name, []).append(log)
        options = dict(cwd=env.ROOT, env=dict(os.environ, ENG_RUN_DIR=self.spec["run_dir"], MSYS_NO_PATHCONV="1", PYTHONDONTWRITEBYTECODE="1"),
                       stdout=log, stderr=subprocess.STDOUT)
        if os.name == "nt":
            options["creationflags"] = subprocess.CREATE_NO_WINDOW
        self.children[name] = self.popen(self.command(name), **options)
        self.event("WORKER_STARTED", worker=name, pid=self.children[name].pid, restart=self.restarts[name])

    def start(self):
        self.acquire()
        if any(Path(self.spec[k]).exists() for k in ("stop_file", "pep_stop_host")):
            raise SupervisionFailed("the service was stopped; use a new prospective run")
        self.launch("adapter")
        self.launch("pep")

    def tick(self, *, draining=False):
        for name, child in list(self.children.items()):
            code = child.poll()
            if code is None:
                continue
            if code == 0 and (name == "adapter" or draining):
                continue
            # Exit 2/3 is a durable refusal/integrity halt, never a transient crash.
            if code in (0, 2, 3) or self.restarts[name] >= self.spec["restart_limit"]:
                self.failed = True
                self.event("SERVICE_FAILED", worker=name, exit=code)
                raise SupervisionFailed(f"{name} exit={code}; restart refused or exhausted")
            due = self.retry_at.setdefault(name, time.monotonic() + self.spec["retry_delay_s"])
            if time.monotonic() >= due:
                self.restarts[name] += 1
                self.retry_at.pop(name)
                self.launch(name)

    def finish(self):
        """Observer has ended: wait for ledger export, then drain PEP and stop."""
        deadline = time.monotonic() + self.spec["shutdown_timeout_s"]
        while self.children["adapter"].poll() != 0:
            self.tick()
            if time.monotonic() >= deadline:
                raise SupervisionFailed("adapter did not finish after the observer")
            time.sleep(self.spec["supervisor_poll_s"])
        self.tick()
        Path(self.spec["pep_stop_host"]).touch()
        while self.children["pep"].poll() != 0:
            self.tick(draining=True)
            if time.monotonic() >= deadline:
                raise SupervisionFailed("PEP drain timed out")
            time.sleep(self.spec["supervisor_poll_s"])
        self.tick(draining=True)
        self.event("SERVICE_DRAINED", restarts=self.restarts)

    def close(self):
        if not self.lock:
            return
        try:
            Path(self.spec["stop_file"]).touch()
            deadline = time.monotonic() + self.spec["shutdown_timeout_s"]
            adapter = self.children.get("adapter")
            while adapter and adapter.poll() is None and time.monotonic() < deadline:
                time.sleep(self.spec["supervisor_poll_s"])
            Path(self.spec["pep_stop_host"]).touch()
            for name, child in self.children.items():
                try:
                    child.wait(timeout=max(0.1, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    if name == "pep":
                        subprocess.run(["docker", "stop", "-t", "5", self.spec["pep_container"]], capture_output=True, timeout=30)
                    child.terminate()
                    child.wait(timeout=15)
                    self.event("WORKER_FORCED_STOP", worker=name)
            self.event("SERVICE_STOPPED", failed=self.failed)
        finally:
            for files in self.logs.values():
                for log in files:
                    log.close()
            self.lock.close()
            self.lock = None


class FunctionalService:
    def __init__(self, args):
        self.args, self.supervisor, self.tailer, self.tailer_log, self.tailer_stop = args, None, None, None, None

    def start_broker_feed(self, directory):
        """The trusted denial feed of the PILOT broker (see `engineering.broker_events`): started BEFORE any publisher or observer so that its coverage precedes every window."""
        ledger, self.tailer_stop = directory / "broker_events.jsonl", directory / "broker_events_STOP"
        self.tailer_log = open(directory / "broker_events.log", "ab")
        options = dict(cwd=env.ROOT, stdout=self.tailer_log, stderr=subprocess.STDOUT, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        if os.name == "nt":
            options["creationflags"] = subprocess.CREATE_NO_WINDOW
        self.tailer = subprocess.Popen([sys.executable, "-B", "-m", "engineering.broker_events", "tail", "--container", live_path_a.BROKER_CONTAINER, "--ledger", str(ledger),
                                        "--stop-file", str(self.tailer_stop), "--margin-ms", "500", "--heartbeat-ms", "250"], **options)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.tailer.poll() is not None:
                raise SupervisionFailed("the broker denial feed exited at start")
            if ledger.exists() and b'"COVERAGE"' in ledger.read_bytes():
                return ledger
            time.sleep(0.2)
        raise SupervisionFailed("the broker denial feed produced no coverage heartbeat")

    def stop_broker_feed(self):
        if self.tailer is None:
            return
        try:
            self.tailer_stop.touch()
            try:
                self.tailer.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.tailer.terminate()
                self.tailer.wait(timeout=15)
        finally:
            self.tailer_log.close()
            self.tailer = None

    def start(self, run_dir):
        a = self.args
        directory = run_dir / "service"
        directory.mkdir()
        plan = json.loads((env.ROOT / a.plan).read_text(encoding="utf-8"))
        required_s = plan["planned_window_count"] * plan["window_duration_ms"] / 1000 + a.shutdown_timeout_s + 15
        if a.max_duration_s < required_s:
            raise SupervisionFailed("adapter duration must cover the observer session and shutdown")
        certified_end = clock_deadline(a.clock_evaluation, tolerance_ns=a.clock_tolerance_ns,
            max_age_s=a.clock_evaluation_max_age_s, required_s=required_s)
        live_declarations.configure(dict(run_id=a.run_id, plan=a.plan, evidence_root=run_dir.relative_to(env.ROOT).as_posix(),
            raw_evidence_access=False, live_prefix=a.run_id, authorization_ref=a.authorization_ref))
        now = time.time_ns()
        data = live_declarations.build("continuous", valid_from_ns=now - 60_000_000_000, valid_until_ns=min(certified_end, now + int(a.max_duration_s * 1e9)),
            clock_tolerance_ns=a.clock_tolerance_ns, stall_timeout_ns=a.stall_timeout_ns,
            baseline_policy_sha256=a.baseline_policy_sha256, audit_interval_s=a.audit_interval_s)
        declaration, digest = live_declarations.write(directory, "continuous", data)
        resolved = load_declaration(env.ROOT, declaration, authorized_sha256=digest)
        output_root = env.ENGINEERING / "live"
        live_directory(resolved, output_root, a.run_id)  # validate isolation BEFORE any client or worker starts
        inbox = directory / "inbox.jsonl"
        approved = operational_approval_plan(a, directory)      # verified on the host BEFORE the inbox exists or any worker starts
        inbox.touch(exist_ok=False)
        shadow = (a.shadow_config, a.shadow_registry, a.shadow_calibration_record)
        if any(shadow) and (approved or not all(shadow)):
            raise SupervisionFailed("--shadow-config, --shadow-registry and --shadow-calibration-record are used together and never with an operational approval")
        if approved:
            artifacts = approved["adapter"]
        elif all(shadow):          # scored Shadow evidence for an engineering run WITHOUT enforcement: the PEP service still builds an empty approval set and refuses every decision
            artifacts = ["--config", str(Path(a.shadow_config).resolve()), "--device-profile-registry", str(Path(a.shadow_registry).resolve()),
                         "--device-profile-registry-sha256", hashlib.sha256(Path(a.shadow_registry).read_bytes()).hexdigest(),
                         "--calibration-record", str(Path(a.shadow_calibration_record).resolve()),
                         "--calibration-record-sha256", hashlib.sha256(Path(a.shadow_calibration_record).read_bytes()).hexdigest()]
        else:
            artifacts = ["--config", path_a_decide.TRUST_CONFIG, "--calibration", "gate5e-v1",
                         "--device-profile-registry", path_a_decide.PROFILE_REGISTRY, "--device-profile-registry-sha256",
                         hashlib.sha256((env.ROOT / path_a_decide.PROFILE_REGISTRY).read_bytes()).hexdigest()]
        if a.context_policy:
            context = ["--context-policy", str(Path(a.context_policy).resolve()), "--broker-events", str(self.start_broker_feed(directory))]
        else:
            context = ["--schedule", path_a_decide.SCHEDULE]
        adapter_args = ["run", "--declaration", str(declaration), "--authorized-declaration-sha256", digest, "--session-id-file", str(directory / "session-id"),
            "--confirm-live-session", a.run_id, "--live-id", a.run_id, "--out-root", str(output_root),
            *artifacts, *context,
            "--poll-interval-s", str(a.poll_interval_s), "--max-duration-s", str(a.max_duration_s)]
        pep_args = ["run", "--registry", "/app/configs/observation/device_registry_v2.json", "--operations-devices", "device01,device02",
            "--credential-file", "/run/secrets/azta-pep-admin-credential", "--host", "broker", "--max-attempts", str(a.max_attempts),
            "--audit-log", "/results/pep/continuous.jsonl", "--decisions", "/results/service/inbox.jsonl", "--mode", "operational",
            "--escalate-after", str(a.escalate_after), "--deescalate-after", str(a.deescalate_after), "--max-decision-age-s", str(a.max_decision_age_s),
            "--deescalation-policy", "deny"]
        spec = dict(schema="azta.engineering.continuous", schema_version=1, adapter_args=adapter_args, pep_args=pep_args,
            inbox=str(inbox), stop_file=str(directory / "adapter_STOP"), pep_stop_host=str(directory / "pep_STOP"), pep_stop_file="/results/service/pep_STOP",
            run_dir="./" + run_dir.relative_to(env.ROOT).as_posix(), pep_container=f"{env.PROJECT}-continuous-" + a.run_id,
            supervisor_poll_s=a.poll_interval_s, restart_limit=a.restart_limit, retry_delay_s=a.retry_delay_s, shutdown_timeout_s=a.shutdown_timeout_s)
        if approved:
            spec["operational_approval"] = approved["section"]
        if env.PROJECT == "azta-pilot":      # the PEP must attest the broker it is actually connected to: the pilot broker carries the pilot sentinel
            spec["pep_target"] = "PILOT_BROKER"
        elif getattr(a, "pep_target", None):
            raise SupervisionFailed("--pep-target PILOT_BROKER needs AZTA_ENG_PROJECT=azta-pilot")
        path = directory / "spec.json"
        path.write_text(json.dumps(spec, sort_keys=True, indent=1), encoding="utf-8")
        self.supervisor = Supervisor(path)
        self.supervisor.start()

    def attached(self, session_id):
        path = self.supervisor.directory / "session-id"
        if not path.exists():
            with open(path, "x", encoding="ascii") as stream:
                stream.write(session_id)

    def tick(self):
        if self.supervisor:
            if (self.supervisor.directory / "REQUEST_STOP").exists():
                raise SupervisionFailed("operator stop requested; draining committed work")
            self.supervisor.tick()

    def finish(self):
        self.supervisor.finish()

    def close(self):
        try:
            if self.supervisor:
                self.supervisor.close()
        finally:
            self.stop_broker_feed()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("run-id", "plan", "baseline-policy-sha256", "authorization-ref", "clock-evaluation"):
        parser.add_argument("--" + key, required=True)
    for key in ("audit-interval-s", "audit-edge-margin-s", "clock-tolerance-ns", "stall-timeout-ns", "restart-limit", "max-attempts", "escalate-after", "deescalate-after"):
        parser.add_argument("--" + key, required=True, type=int)
    for key in ("poll-interval-s", "max-duration-s", "retry-delay-s", "shutdown-timeout-s", "max-decision-age-s", "clock-evaluation-max-age-s"):
        parser.add_argument("--" + key, required=True, type=float)
    parser.add_argument("--pep-target", choices=("PILOT_BROKER",), default=None, help="enforce on the dedicated isolated pilot broker (needs a pilot-scope approval and AZTA_ENG_PROJECT=azta-pilot); absent = the engineering refusal boundary")
    for key in ("dev-perturbation", "context-policy", "shadow-config", "shadow-registry", "shadow-calibration-record"):
        parser.add_argument("--" + key, default=None)
    for key in ("operational-approval", "operational-approval-sha256", "approved-registry", "approved-config", "approved-calibration-record"):
        parser.add_argument("--" + key, default=None, help="optional, all-or-nothing operational approval (see docs/gate5f/F3_OPERATIONAL_READINESS_RECORD.md); absent = enforcement stays refused")
    args = parser.parse_args(argv)
    for key, value in vars(args).items():
        if isinstance(value, (int, float)) and (not math.isfinite(value) or value < (0 if key == "restart_limit" else 1e-12)):
            parser.error(f"{key} must be finite and positive (restart limit may be zero)")
    service = FunctionalService(args)
    try:
        return live_path_a.main(["--run-id", args.run_id, "--plan", args.plan, "--baseline-policy-sha256", args.baseline_policy_sha256,
            "--audit-interval-s", str(args.audit_interval_s), "--audit-edge-margin-s", str(args.audit_edge_margin_s),
            *(["--dev-perturbation", args.dev_perturbation] if args.dev_perturbation else []),
            *(["--expect-policy-change"] if args.operational_approval and env.PROJECT == "azta-pilot" else [])], service=service)
    except (SupervisionFailed, ValueError, OSError) as exc:
        print(f"CONTINUOUS_STOP {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3
    finally:
        service.close()


if __name__ == "__main__":
    sys.exit(main())
