"""Command line of the live adapter: declaration-digest, check-declaration, run, finalize-check. No broker, credential, Docker or enforcement.

    python -m shadow_live declaration-digest --declaration F
    python -m shadow_live check-declaration  --declaration F --authorized-declaration-sha256 H
    python -m shadow_live run                --declaration F --authorized-declaration-sha256 H (--session-id obs-... | --session-id-file F) --confirm-live-session RUN_ID
                                             --live-id ID --config CFG.json (--calibration gate5e-v1 | --calibration-record R --calibration-record-sha256 H)
                                             --poll-interval-s N --max-duration-s M [--schedule S.json] [--cross-workload-experiment NAME] [--resume]
    python -m shadow_live finalize-check     --declaration F --authorized-declaration-sha256 H --live-id ID [--write-report]

Nothing that selects evidence, an authorization, a calibration, a cadence or a deadline has a default. `check-declaration` and `declaration-digest` open no
evidence. `run` follows ONE named unfinished session read-only and writes only its own new live directory; it can be pointed at the raw evidence root only
by a declaration that carries a raw-evidence authorization reference, and it refuses a run that is already collected (that is replayed, never followed).
The configuration must be SYNTHETIC_TEST_UNAPPROVED (no operating parameter is approved) and every record is a counterfactual: enforcement NONE.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

from shadow_feed import cli as feed_cli
from shadow_feed import stream
from observation.schema import SESSION_ID
from shadow_live import declaration, finalize
from shadow_live.errors import LiveIntegrityFailure, LiveRefused
from shadow_live.session import DEFAULT_OUT_ROOT, LiveShadowSession, live_directory
from trust.config import TrustConfig
from trust.engine import DecisionEngine
from trust.errors import PathRefused

REPO_ROOT = Path(__file__).resolve().parents[1]
REFUSALS = (LiveRefused, *feed_cli.REFUSALS)


def _out_root(args):
    root = Path(args.out_root or DEFAULT_OUT_ROOT)
    return root if root.is_absolute() else Path(args.repo_root) / root


def _plan(args):
    return declaration.load_declaration(args.repo_root, args.declaration, authorized_sha256=args.authorized_declaration_sha256)


def run_declaration_digest(args):
    print("SHADOW_LIVE_DECLARATION_SHA256 " + hashlib.sha256(Path(args.declaration).read_bytes()).hexdigest())
    return 0


def run_check_declaration(args):
    plan = _plan(args)
    print("SHADOW_LIVE_DECLARATION_OK " + json.dumps(plan.describe(), sort_keys=True))
    return 0


def _session_id(args, clock, sleep):
    """The observer session id: given directly, or read from a file the OPERATOR writes once the observer has created its session. Waiting for the file lets
    the adapter be started (and its models loaded) BEFORE the session exists, so that it misses no live window; the id is never discovered by scanning."""
    if args.session_id:
        return args.session_id
    deadline = clock.monotonic_ns() + int(args.max_duration_s * 1_000_000_000)
    while True:
        try:
            text = Path(args.session_id_file).read_text(encoding="ascii").strip()
        except (OSError, UnicodeDecodeError):
            text = ""
        if text:
            if not SESSION_ID.fullmatch(text):
                raise LiveRefused("SESSION_ID_INVALID", "the session id file must hold exactly one observer session id (obs-<32 hex>)")
            return text
        if clock.monotonic_ns() >= deadline:
            raise LiveRefused("SESSION_ID_NOT_PROVIDED", "the session id file did not appear within --max-duration-s; nothing was started")
        sleep(args.poll_interval_s)


def context_source(args):
    """The optional broker-derived context source. Both options or neither; never together with a plain schedule."""
    if bool(args.context_policy) != bool(args.broker_events):
        raise LiveRefused("CONTEXT_OPTIONS_INCOMPLETE", "--context-policy and --broker-events are used together")
    if not args.context_policy:
        return None
    if args.schedule:
        raise LiveRefused("CONTEXT_SOURCE_AMBIGUOUS", "--schedule and --context-policy would both supply operating_time")
    from shadow_live import context_events
    policy, digest = context_events.load_policy(args.context_policy)
    return context_events.BrokerContextSource(policy, digest, args.broker_events)


def run_run(args, *, sleep, behavior_loader, clock):
    plan = _plan(args)
    if args.confirm_live_session != plan.run_id:
        raise LiveRefused("AUTHORIZATION_INVALID", "--confirm-live-session must repeat the run id that is being followed")
    schedule = feed_cli._json_file(args.schedule) if args.schedule else None
    config = TrustConfig.from_dict(feed_cli._json_file(args.config))
    choice = args.calibration or dict(record_path=args.calibration_record, record_sha256=args.calibration_record_sha256)
    engine = DecisionEngine(config, behavior_loader(args.repo_root, choice, args.cross_workload_experiment).with_reserved(plan.reserved_tokens))
    if args.device_profile_registry:      # opt-in: registry-authoritative routing and the uncalibrated inference stage (decision_pipeline)
        from decision_pipeline.compose import wrap_engine
        engine = wrap_engine(engine, repo_root=args.repo_root, registry_path=args.device_profile_registry,
                             registry_sha256=args.device_profile_registry_sha256)
    clock = clock or stream.SystemClock()
    session_id = _session_id(args, clock, sleep)
    arguments = dict(engine=engine, clock=clock, out_root=_out_root(args), live_id=args.live_id, schedule=schedule, context_source=context_source(args))
    session = (LiveShadowSession.resume if args.resume else LiveShadowSession.start)(plan, session_id, **arguments)
    try:
        session.run(poll_interval_s=args.poll_interval_s, max_duration_s=args.max_duration_s, sleep=sleep)
    except KeyboardInterrupt:
        if not session.ended:
            session.finish("ADAPTER_INTERRUPTED")
    ended = session.ledger.of_kind("SESSION_ENDED")[0]["body"]
    print(f"SHADOW_LIVE live_id={args.live_id} run_id={plan.run_id} end={ended['reason']} "
          f"every_eligible_window_accounted={ended['accounting']['every_eligible_window_accounted']} evidence_class={declaration.EVIDENCE_CLASS} enforcement=NONE")
    return 0 if not ended["halt"] else 3


def run_finalize_check(args):
    plan = _plan(args)
    live_dir = live_directory(plan, _out_root(args), args.live_id)
    report = finalize.check_finalization(live_dir, plan)
    if args.write_report:
        finalize.write_report(live_dir, report)
    print(f"SHADOW_LIVE_FINALIZATION status={report['status']} reasons={len(report['reasons'])} accepted_scientific_session=False")
    return 0 if report["status"] in ("FINALIZATION_CHECK_PASSED", "SCIENTIFIC_SESSION_DIGESTS_MATCH") else 4


def build_parser():
    parser = argparse.ArgumentParser(prog="shadow_live", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    digest = sub.add_parser("declaration-digest")
    digest.add_argument("--declaration", required=True)
    for name in ("check-declaration", "run", "finalize-check"):
        command = sub.add_parser(name)
        command.add_argument("--declaration", required=True)
        command.add_argument("--authorized-declaration-sha256", required=True)
        command.add_argument("--repo-root", default=str(REPO_ROOT))
        if name != "check-declaration":
            command.add_argument("--live-id", required=True)
            command.add_argument("--out-root")
        if name == "run":
            which_session = command.add_mutually_exclusive_group(required=True)
            which_session.add_argument("--session-id", help="the observer session id (obs-<32 hex>): sessions are never discovered")
            which_session.add_argument("--session-id-file", help="a file the operator writes with the session id once the observer has created its session")
            command.add_argument("--confirm-live-session", required=True, help="must repeat the run id")
            command.add_argument("--config", required=True, help="trust configuration JSON (SYNTHETIC_TEST_UNAPPROVED only)")
            which = command.add_mutually_exclusive_group(required=True)
            which.add_argument("--calibration", choices=("gate5e-v1",), help="the accepted historical calibration (describes workload v1 only)")
            which.add_argument("--calibration-record", help="a controller-accepted versioned calibration record (needs --calibration-record-sha256)")
            command.add_argument("--calibration-record-sha256")
            command.add_argument("--cross-workload-experiment")
            command.add_argument("--device-profile-registry", help="optional versioned device-profile registry (needs --device-profile-registry-sha256)")
            command.add_argument("--device-profile-registry-sha256")
            command.add_argument("--schedule", help="versioned operating schedule JSON (the only context source)")
            command.add_argument("--context-policy", help="versioned pilot context policy JSON (operating time and topic profile; needs --broker-events, excludes --schedule)")
            command.add_argument("--broker-events", help="hash-chained broker denial ledger written by engineering.broker_events (pilot broker only)")
            command.add_argument("--poll-interval-s", required=True, type=float)
            command.add_argument("--max-duration-s", required=True, type=float)
            command.add_argument("--resume", action="store_true", help="continue an existing live id from its ledger")
        if name == "finalize-check":
            command.add_argument("--write-report", action="store_true")
    return parser


def main(argv=None, *, sleep=time.sleep, behavior_loader=feed_cli.load_behavior, clock=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "run":
        if args.calibration_record and not args.calibration_record_sha256:
            parser.error("--calibration-record needs --calibration-record-sha256")
        if bool(args.device_profile_registry) != bool(args.device_profile_registry_sha256):
            parser.error("--device-profile-registry and --device-profile-registry-sha256 go together")
        if args.poll_interval_s <= 0 or args.max_duration_s <= 0:
            parser.error("--poll-interval-s and --max-duration-s must be positive")
    try:
        if args.command == "declaration-digest":
            return run_declaration_digest(args)
        if args.command == "check-declaration":
            return run_check_declaration(args)
        if args.command == "run":
            return run_run(args, sleep=sleep, behavior_loader=behavior_loader, clock=clock)
        return run_finalize_check(args)
    except LiveIntegrityFailure as exc:
        print(f"SHADOW_LIVE_HALTED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3
    except (*REFUSALS, PathRefused) as exc:
        print(f"SHADOW_LIVE_REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
