"""Credential-free live adapter worker for a FLEET run, supervised by `engineering.fleet_continuous` (counterpart of `engineering.live_worker`).

Same structure, same unchanged pieces: the declaration-gated read-only `LiveShadowSession` over ONE unfinished observer session, the hash-chained ledger with resume, the null Shadow sink and
the byte-preserving projection to the enforcement inbox. What differs: the plan is a fleet plan (`fleet.plan`), the behavioural evaluator is the digest-verified fleet evaluator
(`fleet.loader`: frozen S/V models with the unchanged CAL_V2 constants plus provisional profiles) and the registry-authoritative routing is wrapped with the extended catalog. The artifact
paths and digests come from the supervisor's service specification (`spec["fleet"]`), never from a default.
"""
import json
from pathlib import Path
import sys
import time

from engineering import policy_changes, timing_probe
from engineering.handoff import project
from engineering.ownership import Lease
from fleet import loader, plan as fleet_plan
from shadow_feed import cli as feed_cli, stream
from shadow_live import cli, declaration
from shadow_live.errors import LiveIntegrityFailure, LiveRefused
from shadow_live.ledger import LiveLedger
from shadow_live.session import LiveShadowSession, live_directory
from trust.config import TrustConfig
from trust.engine import DecisionEngine

FLEET_KEYS = {"cal_v2_path", "cal_v2_sha256", "models_record_path", "models_record_sha256", "compat_record_path", "compat_record_sha256"}
PILOT_KEYS = {"pilot_record_path", "pilot_record_sha256"}      # present only for an approved (enforcing) run: the one calibration id the guard requires


def build_engine(args, spec, plan):
    fleet = spec["fleet"]
    if set(fleet) not in (FLEET_KEYS, FLEET_KEYS | PILOT_KEYS):
        raise ValueError("spec.fleet must name exactly the fleet artifact paths and digests (and, for an approved run, the pilot calibration record)")
    config = TrustConfig.from_dict(feed_cli._json_file(args.config))
    arguments = dict(cal_v2_path=fleet["cal_v2_path"], cal_v2_sha256=fleet["cal_v2_sha256"], models_record_path=fleet["models_record_path"],
                     models_record_sha256=fleet["models_record_sha256"], compat_record_path=fleet["compat_record_path"], compat_record_sha256=fleet["compat_record_sha256"],
                     pilot_record_path=fleet.get("pilot_record_path"), pilot_record_sha256=fleet.get("pilot_record_sha256"))
    hybrid = spec.get("hybrid")                      # Gate 6C: absent = the fleet behaviour exactly (the rollback path)
    core = spec.get("core_final")                    # AE_PRIMARY_AUTHORITY_V1: every input comes from the digest-pinned route record; absent = everything below, unchanged
    if core is not None:
        from core_runtime import loader as core_loader
        behavior = core_loader.load_primary(args.repo_root, route_path=core["route_path"], route_sha256=core["route_sha256"], calibration_bundle_path=fleet.get("pilot_record_path"),
                                            calibration_bundle_sha256=fleet.get("pilot_record_sha256")).with_reserved(plan.reserved_tokens)
        if core.get("rc1"):
            from core_runtime.rc1_runtime import LiveConnection
            behavior = behavior.with_connection(LiveConnection())
        engine = DecisionEngine(config, behavior)
        timing_probe.instrument(engine.behavior, Path(spec["inbox"]).parent / "inference_timing.jsonl")
        return core_loader.wrap(engine, repo_root=args.repo_root, registry_path=args.device_profile_registry, registry_sha256=args.device_profile_registry_sha256)
    if hybrid is not None:
        from hybrid import loader as hybrid_loader
        if set(hybrid) == {"monitors_path", "monitors_sha256"}:
            behavior = hybrid_loader.load_monitor_behavior(args.repo_root, monitors_path=hybrid["monitors_path"], monitors_sha256=hybrid["monitors_sha256"], **arguments).with_reserved(plan.reserved_tokens)
        elif set(hybrid) == {"timing_contracts_path", "timing_contracts_sha256"}:
            behavior = hybrid_loader.load_hybrid_behavior(args.repo_root, timing_contracts_path=hybrid["timing_contracts_path"], timing_contracts_sha256=hybrid["timing_contracts_sha256"],
                                                          **arguments).with_reserved(plan.reserved_tokens)
        else:
            raise ValueError("spec.hybrid must name exactly the timing contracts record (or the monitor profiles record) and its digest")
    else:
        behavior = loader.load_fleet_behavior(args.repo_root, **arguments).with_reserved(plan.reserved_tokens)
    engine = DecisionEngine(config, behavior)
    timing_probe.instrument(engine.behavior, Path(spec["inbox"]).parent / "inference_timing.jsonl")
    if hybrid is not None:
        return hybrid_loader.wrap_hybrid_engine(engine, repo_root=args.repo_root, registry_path=args.device_profile_registry, registry_sha256=args.device_profile_registry_sha256)
    return loader.wrap_fleet_engine(engine, repo_root=args.repo_root, registry_path=args.device_profile_registry, registry_sha256=args.device_profile_registry_sha256)


def run(spec):
    args = cli.build_parser().parse_args(spec["adapter_args"])
    if args.command != "run" or not args.device_profile_registry or not args.device_profile_registry_sha256:
        raise ValueError("continuous operation requires run and a digest-pinned profile registry")
    if args.poll_interval_s <= 0 or args.max_duration_s <= 0:
        raise ValueError("explicit positive cadence and duration required")
    plan = fleet_plan.load_declaration(args.repo_root, args.declaration, authorized_sha256=args.authorized_declaration_sha256)
    if plan.declaration.partition != "FUNCTIONAL" or args.confirm_live_session != plan.run_id:
        raise LiveRefused("AUTHORIZATION_INVALID", "the fleet service follows only its declared FUNCTIONAL run")
    clock = stream.SystemClock()
    session_id = cli._session_id(args, clock, time.sleep)
    directory = live_directory(plan, cli._out_root(args), args.live_id)
    ledger = LiveLedger.open_existing(directory) if directory.exists() else None
    if ledger and ledger.of_kind("SESSION_ENDED"):
        end = ledger.of_kind("SESSION_ENDED")[0]["body"]
        project(ledger, spec["inbox"])
        return 3 if end["halt"] else 0
    engine = build_engine(args, spec, plan)
    schedule = feed_cli._json_file(args.schedule) if args.schedule else None
    session = (LiveShadowSession.resume if ledger else LiveShadowSession.start)(
        plan, session_id, engine=engine, clock=clock, out_root=cli._out_root(args), live_id=args.live_id, schedule=schedule, context_source=cli.context_source(args),
        barrier=policy_changes.from_spec(spec))
    project(session.ledger, spec["inbox"])
    recommendations = core_projector(spec, engine)
    if recommendations:
        recommendations.poll()
    follower = core_follower(spec, session_id, engine)
    deadline = time.monotonic() + args.max_duration_s
    try:
        while not session.ended:
            session.poll()
            project(session.ledger, spec["inbox"])
            if recommendations:
                recommendations.poll()
            if not session.ended and (Path(spec["stop_file"]).exists() or time.monotonic() >= deadline):
                session.finish("SUPERVISOR_STOPPED" if Path(spec["stop_file"]).exists() else "ADAPTER_DEADLINE_REACHED")
                project(session.ledger, spec["inbox"])
            if not session.ended:
                time.sleep(args.poll_interval_s)
    except KeyboardInterrupt:
        if not session.ended:
            session.finish("ADAPTER_INTERRUPTED")
        project(session.ledger, spec["inbox"])
    finally:
        if follower:
            follower.stop.set()
    if recommendations:
        recommendations.poll()
    return 3 if session.halted else 0


def core_projector(spec, engine):
    """AE_PRIMARY_AUTHORITY_V1: the recommendations ledger next to the inbox (None without the core block)."""
    core = spec.get("core_final")
    if core is None:
        return None
    from core_runtime.projection import Projector
    from enforcement.authority import AuthorityMap
    return Projector(spec["inbox"], Path(spec["inbox"]).parent / "recommendations.jsonl", runtime_mode=core["mode"], authority_map=AuthorityMap.load(core["authority_map_path"], core["authority_map_sha256"]), escalate_after=core["escalate_after"])


def core_follower(spec, session_id, engine):
    """The read-only RC-1 follower of `--rc1-live` (None otherwise). The provider stays fail-closed until the follower has attached a feed."""
    rc1 = (spec.get("core_final") or {}).get("rc1")
    if not rc1:
        return None
    from core_runtime.rc1_runtime import Follower
    follower = Follower(Path(rc1["observation_dir"]) / session_id, rc1["container"], engine.behavior.connection, status_path=Path(spec["inbox"]).parent / "rc1_status.json")
    follower.start()
    return follower


def main():
    try:
        path = Path(sys.argv[1])
        with Lease(path.parent / "adapter.owner.lock"):
            return run(json.loads(path.read_text(encoding="utf-8")))
    except cli.REFUSALS as exc:
        print(f"FLEET_SERVICE_REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3 if isinstance(exc, LiveIntegrityFailure) else 2
    except (ValueError, KeyError, OSError) as exc:
        print(f"FLEET_SERVICE_REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
