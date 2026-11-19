"""Credential-free live adapter worker, supervised by engineering.continuous.

Uses the existing declaration, model pins, session ledger and null Shadow sink.
An abrupt process exit resumes the ledger; a requested stop accounts missing
windows and drains committed outputs. Integrity/refusal exits are terminal.
"""
import json
from pathlib import Path
import sys
import time

from decision_pipeline.compose import wrap_engine
from engineering import policy_changes, timing_probe
from engineering.handoff import project
from engineering.ownership import Lease
from shadow_feed import cli as feed_cli, stream
from shadow_live import cli, declaration
from shadow_live.errors import LiveIntegrityFailure, LiveRefused
from shadow_live.ledger import LiveLedger
from shadow_live.session import LiveShadowSession, live_directory
from trust.config import TrustConfig
from trust.engine import DecisionEngine


def run(spec):
    args = cli.build_parser().parse_args(spec["adapter_args"])
    if args.command != "run" or not args.device_profile_registry or not args.device_profile_registry_sha256:
        raise ValueError("continuous operation requires run and a digest-pinned profile registry")
    if args.poll_interval_s <= 0 or args.max_duration_s <= 0:
        raise ValueError("explicit positive cadence and duration required")
    plan = cli._plan(args)
    if plan.declaration.partition != "FUNCTIONAL" or args.confirm_live_session != plan.run_id:
        raise LiveRefused("AUTHORIZATION_INVALID", "engineering service follows only its declared FUNCTIONAL run")
    clock = stream.SystemClock()
    session_id = cli._session_id(args, clock, time.sleep)
    directory = live_directory(plan, cli._out_root(args), args.live_id)
    ledger = LiveLedger.open_existing(directory) if directory.exists() else None
    if ledger and ledger.of_kind("SESSION_ENDED"):
        end = ledger.of_kind("SESSION_ENDED")[0]["body"]
        project(ledger, spec["inbox"])
        return 3 if end["halt"] else 0
    choice = args.calibration or dict(record_path=args.calibration_record, record_sha256=args.calibration_record_sha256)
    config = TrustConfig.from_dict(feed_cli._json_file(args.config))
    engine = DecisionEngine(config, feed_cli.load_behavior(args.repo_root, choice, args.cross_workload_experiment).with_reserved(plan.reserved_tokens))
    timing_probe.instrument(engine.behavior, Path(spec["inbox"]).parent / "inference_timing.jsonl")      # times the frozen autoencoder calls; forwards every call and result unchanged
    engine = wrap_engine(engine, repo_root=args.repo_root, registry_path=args.device_profile_registry,
                         registry_sha256=args.device_profile_registry_sha256)
    schedule = feed_cli._json_file(args.schedule) if args.schedule else None
    session = (LiveShadowSession.resume if ledger else LiveShadowSession.start)(
        plan, session_id, engine=engine, clock=clock, out_root=cli._out_root(args), live_id=args.live_id, schedule=schedule,
        context_source=cli.context_source(args), barrier=policy_changes.from_spec(spec))
    project(session.ledger, spec["inbox"])
    deadline = time.monotonic() + args.max_duration_s
    try:
        while not session.ended:
            session.poll()
            project(session.ledger, spec["inbox"])
            if not session.ended and (Path(spec["stop_file"]).exists() or time.monotonic() >= deadline):
                session.finish("SUPERVISOR_STOPPED" if Path(spec["stop_file"]).exists() else "ADAPTER_DEADLINE_REACHED")
                project(session.ledger, spec["inbox"])
            if not session.ended:
                time.sleep(args.poll_interval_s)
    except KeyboardInterrupt:
        if not session.ended:
            session.finish("ADAPTER_INTERRUPTED")
        project(session.ledger, spec["inbox"])
    return 3 if session.halted else 0


def main():
    try:
        path = Path(sys.argv[1])
        with Lease(path.parent / "adapter.owner.lock"):
            return run(json.loads(path.read_text(encoding="utf-8")))
    except cli.REFUSALS as exc:
        print(f"LIVE_SERVICE_REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3 if isinstance(exc, LiveIntegrityFailure) else 2
    except (ValueError, KeyError, OSError) as exc:
        print(f"LIVE_SERVICE_REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
