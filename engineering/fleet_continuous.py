"""Supervised, bounded continuous FUNCTIONAL fleet run: observer -> Shadow (fleet evaluator) -> guarded PEP, for more than the two frozen S/V devices (Gate 6B).

The two-device `engineering.continuous` is reused unchanged: its `Supervisor` (crash retries, durable refusals), its `FunctionalService` (broker denial feed, session attachment, stop and
drain) and its live path (`engineering.live_path_a`, here with `FLEET_PROFILE`). What differs:

  * the adapter worker is `fleet.live_worker` (fleet plan, fleet evaluator over the frozen S/V models with the unchanged CAL_V2 constants plus provisional profile models);
  * the PEP target is `PILOT_FLEET_BROKER`: the dedicated isolated pilot broker, and the ONLY approval scope it accepts is `PILOT_FLEET_ENFORCEMENT` (the two-device and the operational
    scopes are refused for it, and the fleet scope for them);
  * without an approval the PEP service builds an EMPTY approval set and refuses every genuine decision (shadow evidence only), exactly as before.

Nothing is approved or defaulted here: every artifact (trust configuration, device-profile registry, calibration record, fleet models record, compatibility record, approval) is named on the
command line with its digest and verified before anything starts.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import sys
import time

from engineering import approvals, continuous, env, live_path_a
from rehearsal_tools import live_declarations
from shadow_live.session import live_directory

SupervisionFailed = continuous.SupervisionFailed
TARGET = "PILOT_FLEET_BROKER"
CORE_TARGET = "PILOT_CORE_BROKER"
FLEET_OPTIONS = ("fleet-cal-v2", "fleet-cal-v2-sha256", "fleet-models-record", "fleet-models-record-sha256", "fleet-compat-record", "fleet-compat-record-sha256")


class FleetSupervisor(continuous.Supervisor):
    def command(self, name):
        if name == "adapter":
            return [sys.executable, "-B", "-m", "fleet.live_worker", str(self.path)]
        return super().command(name)


def hybrid_block(a):
    """The `hybrid` block of the worker spec (Gate 6C), or None for the Gate 6B fleet behaviour. Both options or neither; the digest is verified on the host before anything is launched."""
    monitors, monitors_digest = getattr(a, "monitor_profiles", None), getattr(a, "monitor_profiles_sha256", None)       # pre-live campaign: per-device monitor profiles (timing + block + drift + autoencoder streams)
    if monitors or monitors_digest:
        if bool(monitors) != bool(monitors_digest) or getattr(a, "timing_contracts", None) or getattr(a, "timing_contracts_sha256", None):
            raise SupervisionFailed("--monitor-profiles and --monitor-profiles-sha256 are used together and not with --timing-contracts; nothing was started")
        if hashlib.sha256(Path(monitors).read_bytes()).hexdigest() != monitors_digest:
            raise SupervisionFailed("the monitor profiles record differs from the pinned SHA-256; nothing was started")
        return dict(monitors_path=str(Path(monitors).resolve()), monitors_sha256=monitors_digest)
    path, digest = getattr(a, "timing_contracts", None), getattr(a, "timing_contracts_sha256", None)
    if bool(path) != bool(digest):
        raise SupervisionFailed("--timing-contracts and --timing-contracts-sha256 are used together; nothing was started")
    if not path:
        return None
    if hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest:
        raise SupervisionFailed("the timing contracts record differs from the pinned SHA-256; nothing was started")
    return dict(timing_contracts_path=str(Path(path).resolve()), timing_contracts_sha256=digest)


def fleet_approval_plan(a, directory, *, now_ns=None):
    """Counterpart of `continuous.operational_approval_plan` for the fleet scope: every artifact is verified COMPLETELY on the host before anything is launched."""
    given = {key: getattr(a, key, None) for key in continuous.APPROVAL_OPTIONS}
    calibration = getattr(a, "approved_calibration_record", None)
    if not any(given.values()) and not calibration:
        return None
    if not all(given.values()) or not calibration:
        raise SupervisionFailed("the fleet approval needs --operational-approval, --operational-approval-sha256, --approved-registry, --approved-config and --approved-calibration-record")
    from enforcement.errors import ApprovalRefused
    now = time.time_ns() if now_ns is None else now_ns
    try:
        verified = approvals.load_approvals(given["operational_approval"], authorized_approval_sha256=given["operational_approval_sha256"], registry_path=given["approved_registry"],
                                            config_path=given["approved_config"], calibration_path=calibration, now_ns=now)
        scope = approvals.scope_of(given["operational_approval"], authorized_approval_sha256=given["operational_approval_sha256"], now_ns=now)
    except ApprovalRefused as exc:
        raise SupervisionFailed(f"fleet operational approval refused ({exc.code}); nothing was started") from None
    expected_scope, expected_target = (approvals.PILOT_CORE_SCOPE, CORE_TARGET) if getattr(a, "core_route", None) else (approvals.PILOT_FLEET_SCOPE, TARGET)
    if scope != expected_scope or getattr(a, "pep_target", None) != expected_target or env.PROJECT != "azta-pilot":
        raise SupervisionFailed("the approval scope, the --pep-target and the targeted project do not agree; nothing was started")
    copy = Path(directory) / "operational_approval.json"
    copy.write_bytes(Path(given["operational_approval"]).read_bytes())
    if hashlib.sha256(copy.read_bytes()).hexdigest() != given["operational_approval_sha256"]:
        raise SupervisionFailed("the copied approval differs from the pinned one; nothing was started")
    adapter = ["--config", str(Path(given["approved_config"]).resolve()), "--device-profile-registry", str(Path(given["approved_registry"]).resolve()),
               "--device-profile-registry-sha256", verified.registry_sha256,
               "--calibration-record", str(Path(calibration).resolve()), "--calibration-record-sha256", hashlib.sha256(Path(calibration).read_bytes()).hexdigest()]
    section = dict(approval="/results/service/operational_approval.json", approval_sha256=given["operational_approval_sha256"], artifact_verification=approvals.HOST_VERIFIED)
    return dict(adapter=adapter, section=section, approval_id=verified.approval_id)


def core_blocks(a, directory, run_dir):
    """AE_PRIMARY_AUTHORITY_V1: (`core_final` for the worker, `authority` for the PEP service), or (None, None). Every digest is verified on the host and the map and scope are copied byte for byte into the service directory. Shadow mode has no
    authority block at all: the PEP service then holds the unchanged refusal boundary (no approval set) and no review can open."""
    if not getattr(a, "core_route", None):
        return None, None
    for label, path, digest in (("route", a.core_route, a.core_route_sha256), ("authority map", a.authority_map, a.authority_map_sha256)):
        if not path or not digest or hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest:
            raise SupervisionFailed(f"the {label} differs from the pinned SHA-256; nothing was started")
    if a.core_mode not in ("shadow", "review", "active-authorized"):
        raise SupervisionFailed("--core-mode is required with --core-route")
    if a.core_mode == "shadow" and (a.authority_scope or a.operational_approval):
        raise SupervisionFailed("shadow mode takes no authority scope and no operational approval; nothing was started")
    if a.core_mode != "shadow" and not (a.authority_scope and a.authority_scope_sha256 and a.operational_approval):
        raise SupervisionFailed("review and active-authorized need a pinned authority scope and an operational approval; nothing was started")
    (directory / "authority_map.json").write_bytes(Path(a.authority_map).read_bytes())
    core = dict(mode=a.core_mode, route_path=str(Path(a.core_route).resolve()), route_sha256=a.core_route_sha256, authority_map_path=str(directory / "authority_map.json"), authority_map_sha256=a.authority_map_sha256, escalate_after=a.escalate_after)
    if a.rc1_live:
        if not a.rc1_container:
            raise SupervisionFailed("--rc1-live needs --rc1-container")
        core["rc1"] = dict(container=a.rc1_container, observation_dir=str(run_dir / "observation"))
    if a.core_mode == "shadow":
        return core, None
    from enforcement.authority import AuthorityScope
    from enforcement.errors import EnforcementError
    try:
        scope = AuthorityScope.load(a.authority_scope, a.authority_scope_sha256)
    except EnforcementError as exc:
        raise SupervisionFailed(f"authority scope refused ({getattr(exc, 'code', type(exc).__name__)}); nothing was started") from None
    if scope.data["session_run_id"] != a.run_id or scope.data["mode"] != a.core_mode or scope.problem(now_ns=time.time_ns(), environment=scope.data["environment"]):
        raise SupervisionFailed("the authority scope names another session or mode, or is not valid now; nothing was started")
    if scope.data["artifacts"]["authority_map_sha256"] != a.authority_map_sha256 or scope.data["artifacts"]["route_sha256"] != a.core_route_sha256:
        raise SupervisionFailed("the authority scope names other artifacts; nothing was started")
    (directory / "authority_scope.json").write_bytes(Path(a.authority_scope).read_bytes())
    return core, dict(mode=a.core_mode, map_path="/results/service/authority_map.json", map_sha256=a.authority_map_sha256, scope_path="/results/service/authority_scope.json", scope_sha256=a.authority_scope_sha256,
                      review_ttl_s=a.review_ttl_s, intents_path="/results/service/intents.jsonl")


class FleetService(continuous.FunctionalService):
    def start(self, run_dir):
        a = self.args
        directory = run_dir / "service"
        directory.mkdir()
        plan = json.loads((env.ROOT / a.plan).read_text(encoding="utf-8"))
        required_s = plan["planned_window_count"] * plan["window_duration_ms"] / 1000 + a.shutdown_timeout_s + 15
        if a.max_duration_s < required_s:
            raise SupervisionFailed("adapter duration must cover the observer session and shutdown")
        certified_end = continuous.clock_deadline(a.clock_evaluation, tolerance_ns=a.clock_tolerance_ns, max_age_s=a.clock_evaluation_max_age_s, required_s=required_s)
        live_declarations.configure(dict(run_id=a.run_id, plan=a.plan, evidence_root=run_dir.relative_to(env.ROOT).as_posix(), raw_evidence_access=False, live_prefix=a.run_id,
                                         authorization_ref=a.authorization_ref))
        now = time.time_ns()
        data = live_declarations.build("continuous", valid_from_ns=now - 60_000_000_000, valid_until_ns=min(certified_end, now + int(a.max_duration_s * 1e9)),
                                       clock_tolerance_ns=a.clock_tolerance_ns, stall_timeout_ns=a.stall_timeout_ns, baseline_policy_sha256=a.baseline_policy_sha256,
                                       audit_interval_s=a.audit_interval_s)
        data["observer"] = dict(allow_legacy_observer=False)         # the ten-device registry is observed by the dedicated receive-only principal only
        declaration, digest = live_declarations.write(directory, "continuous", data)
        from fleet import plan as fleet_plan
        resolved = fleet_plan.load_declaration(env.ROOT, declaration, authorized_sha256=digest)
        output_root = env.ENGINEERING / "live"
        live_directory(resolved, output_root, a.run_id)
        inbox = directory / "inbox.jsonl"
        approved = fleet_approval_plan(a, directory)
        inbox.touch(exist_ok=False)
        if approved:
            artifacts = approved["adapter"]
        else:
            artifacts = ["--config", str(Path(a.shadow_config).resolve()), "--device-profile-registry", str(Path(a.shadow_registry).resolve()),
                         "--device-profile-registry-sha256", hashlib.sha256(Path(a.shadow_registry).read_bytes()).hexdigest(),
                         "--calibration-record", str(Path(a.fleet_cal_v2).resolve()), "--calibration-record-sha256", a.fleet_cal_v2_sha256]
        if a.context_policy:
            context = ["--context-policy", str(Path(a.context_policy).resolve()), "--broker-events", str(self.start_broker_feed(directory))]
        else:
            raise SupervisionFailed("a fleet run needs --context-policy (the operating-time and topic criteria of every device)")
        adapter_args = ["run", "--declaration", str(declaration), "--authorized-declaration-sha256", digest, "--session-id-file", str(directory / "session-id"),
                        "--confirm-live-session", a.run_id, "--live-id", a.run_id, "--out-root", str(output_root), *artifacts, *context,
                        "--poll-interval-s", str(a.poll_interval_s), "--max-duration-s", str(a.max_duration_s)]
        pep_args = ["run", "--registry", "/app/configs/observation/device_registry_v2.json", "--operations-devices", "device01,device02",
                    "--credential-file", "/run/secrets/azta-pep-admin-credential", "--host", "broker", "--max-attempts", str(a.max_attempts),
                    "--audit-log", "/results/pep/continuous.jsonl", "--decisions", "/results/service/inbox.jsonl", "--mode", "operational",
                    "--escalate-after", str(a.escalate_after), "--deescalate-after", str(a.deescalate_after), "--max-decision-age-s", str(a.max_decision_age_s),
                    "--deescalation-policy", "deny"]
        fleet_artifacts = dict(cal_v2_path=str(Path(a.fleet_cal_v2).resolve()), cal_v2_sha256=a.fleet_cal_v2_sha256, models_record_path=str(Path(a.fleet_models_record).resolve()),
                               models_record_sha256=a.fleet_models_record_sha256, compat_record_path=str(Path(a.fleet_compat_record).resolve()),
                               compat_record_sha256=a.fleet_compat_record_sha256)
        if approved:       # the approved calibration record is the pilot record: ONE calibration id over the constituent calibrations (the guard requires it on every decision)
            fleet_artifacts.update(pilot_record_path=str(Path(a.approved_calibration_record).resolve()),
                                   pilot_record_sha256=hashlib.sha256(Path(a.approved_calibration_record).read_bytes()).hexdigest())
        spec = dict(schema="azta.engineering.continuous", schema_version=1, adapter_args=adapter_args, pep_args=pep_args, fleet=fleet_artifacts,
                    **({} if a.no_identity_barrier else dict(identity_barrier_pep_dir=str(run_dir / "pep"), policy_change_tolerance_ns=a.clock_tolerance_ns)),
                    inbox=str(inbox), stop_file=str(directory / "adapter_STOP"), pep_stop_host=str(directory / "pep_STOP"), pep_stop_file="/results/service/pep_STOP",
                    run_dir="./" + run_dir.relative_to(env.ROOT).as_posix(), pep_container=f"{env.PROJECT}-continuous-" + a.run_id,
                    supervisor_poll_s=a.poll_interval_s, restart_limit=a.restart_limit, retry_delay_s=a.retry_delay_s, shutdown_timeout_s=a.shutdown_timeout_s)
        if hybrid_block(a):
            spec["hybrid"] = hybrid_block(a)
        if approved:
            spec["operational_approval"] = approved["section"]
        if env.PROJECT != "azta-pilot":
            raise SupervisionFailed("a fleet run targets the dedicated pilot project only")
        spec["pep_target"] = TARGET
        core, authority = core_blocks(a, directory, run_dir)
        if core is not None:
            if hybrid_block(a):
                raise SupervisionFailed("--core-route and a hybrid record are exclusive; nothing was started")
            spec["core_final"], spec["pep_target"] = core, CORE_TARGET
            if authority is not None:
                spec["authority"] = authority
        path = directory / "spec.json"
        path.write_text(json.dumps(spec, sort_keys=True, indent=1), encoding="utf-8")
        self.supervisor = FleetSupervisor(path)
        self.supervisor.start()


def check_numeric_arguments(parser, args):
    """Every numeric argument must be finite and positive (the restart limit may be zero). A `bool` is an `int` in Python, so a `store_true` flag left at False would read as 0 and be refused as a number:
    the flags `--shared-publisher-loop` and `--no-identity-barrier` (Gate 6C) made every launch fail with exit 2 until the first live launch found it. Booleans are flags, not numbers."""
    for key, value in vars(args).items():
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)) and (not math.isfinite(value) or value < (0 if key == "restart_limit" else 1e-12)):
            parser.error(f"{key} must be finite and positive (restart limit may be zero)")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("run-id", "plan", "baseline-policy-sha256", "authorization-ref", "clock-evaluation", "dev-perturbation", "context-policy", "shadow-config", "shadow-registry", *FLEET_OPTIONS):
        parser.add_argument("--" + key, required=True)
    for key in ("audit-interval-s", "audit-edge-margin-s", "clock-tolerance-ns", "stall-timeout-ns", "restart-limit", "max-attempts", "escalate-after", "deescalate-after"):
        parser.add_argument("--" + key, required=True, type=int)
    for key in ("poll-interval-s", "max-duration-s", "retry-delay-s", "shutdown-timeout-s", "max-decision-age-s", "clock-evaluation-max-age-s"):
        parser.add_argument("--" + key, required=True, type=float)
    parser.add_argument("--pep-target", choices=(TARGET, CORE_TARGET), default=None)
    for key in ("core-route", "core-route-sha256", "core-mode", "authority-map", "authority-map-sha256", "authority-scope", "authority-scope-sha256", "rc1-container"):
        parser.add_argument("--" + key, default=None, help="AE_PRIMARY_AUTHORITY_V1 (use `python -m core_runtime`); absent = the Gate 6B/6C paths unchanged")
    parser.add_argument("--review-ttl-s", type=float, default=None)
    parser.add_argument("--rc1-live", action="store_true")
    parser.add_argument("--timing-contracts", default=None, help="Gate 6C: the digest-pinned timing-contracts record that turns on the hybrid evaluator (absent = the Gate 6B fleet behaviour)")
    parser.add_argument("--timing-contracts-sha256", default=None)
    parser.add_argument("--monitor-profiles", default=None, help="pre-live campaign: the digest-pinned monitor-profiles record (timing + block + drift + autoencoder streams under HBE-2); exclusive with --timing-contracts")
    parser.add_argument("--monitor-profiles-sha256", default=None)
    parser.add_argument("--shared-publisher-loop", action="store_true",
                        help="rollback to the baseline: all ten publishers in ONE process (Gate 6B defect F2: ms-scale shared-loop timing noise); the default runs one publisher process per device")
    parser.add_argument("--no-identity-barrier", action="store_true",
                        help="rollback to the baseline: identity evidence is NOT held back by the PEP's own policy changes (Gate 6B defect F1 returns); the default follows the PEP audit logs")
    for key in ("operational-approval", "operational-approval-sha256", "approved-registry", "approved-config", "approved-calibration-record"):
        parser.add_argument("--" + key, default=None)
    args = parser.parse_args(argv)
    check_numeric_arguments(parser, args)
    service = FleetService(args)
    try:
        return live_path_a.main(["--run-id", args.run_id, "--plan", args.plan, "--baseline-policy-sha256", args.baseline_policy_sha256, "--audit-interval-s", str(args.audit_interval_s),
                                 "--audit-edge-margin-s", str(args.audit_edge_margin_s), "--dev-perturbation", args.dev_perturbation,
                                 *(["--expect-policy-change"] if args.operational_approval and env.PROJECT == "azta-pilot" else []),
                                 *([] if args.no_identity_barrier else ["--revalidate-after-policy-change"])],
                                service=service, profile=dict(live_path_a.FLEET_PROFILE, workload_args=["--control-io", "inline"] if args.shared_publisher_loop else ["--isolation", "per-device", "--control-io", "thread"]))
    except (SupervisionFailed, ValueError, OSError) as exc:
        print(f"CONTINUOUS_STOP {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3
    finally:
        service.close()


if __name__ == "__main__":
    sys.exit(main())
