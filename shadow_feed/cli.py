"""Command line of the shadow feed: preflight, build-feed, replay. Offline: no broker, credential, Docker or enforcement.

    python -m shadow_feed preflight  <authorization> --plan P --manifest M
    python -m shadow_feed build-feed <authorization> --plan P --manifest M --confirm-partition-access D_shadow --feed-id ID
                                     [--schedule S.json] [--allow-legacy-observer] [--allow-partial]
    python -m shadow_feed replay     <authorization> --plan P --manifest M --confirm-partition-access D_shadow --replay-id ID --config CFG.json
                                     (--calibration gate5e-v1 | --calibration-record R.json --calibration-record-sha256 H)
                                     [--cross-workload-experiment NAME] [--schedule S.json] [--allow-legacy-observer] [--allow-partial]

<authorization> = --partition P --authorized-manifest-sha256 H --authorization-ref REF. Nothing that selects evidence, a partition, a calibration or
an approval has a default. `preflight` opens no evidence. `build-feed` and `replay` open exactly the allowlisted D_shadow files, only after the partition
is confirmed by name, and refuse D_test, CAL_V2 and every B_* partition. `replay` scores nothing the engine does not already score: it runs the
streaming pipeline in REPLAY mode and writes decisions, timing and a manifest that say the timing is not a live latency.
"""
import argparse
import json
from pathlib import Path
import sys

from shadow_feed import feed, reader, stream
from shadow_feed.errors import ScientificReadRefused, StreamRefused
from trust.config import TrustConfig
from trust.engine import DecisionEngine
from trust.errors import ArtifactRefused, ConfigError, PathRefused, ProducerRefused

REPO_ROOT = Path(__file__).resolve().parents[1]
REFUSALS = (ScientificReadRefused, StreamRefused, ProducerRefused, PathRefused, ArtifactRefused, ConfigError, OSError, ValueError, KeyError)


def load_behavior(repo_root, calibration, cross_workload_experiment):
    """The frozen S/V models with one explicitly chosen calibration. The only place the model stack is loaded (a seam for tests)."""
    from trust import artifacts
    behavior = artifacts.load_frozen_behavior(repo_root, calibration=calibration)
    if cross_workload_experiment:
        behavior = behavior.with_cross_workload_baseline(cross_workload_experiment)
    return behavior


def _reject_constant(name):
    raise ValueError(f"non-finite JSON constant {name}")


def _json_file(path):
    return json.loads(Path(path).read_text(encoding="utf-8"), parse_constant=_reject_constant)


def _out_root(args, default):
    root = Path(args.out_root or default)
    return root if root.is_absolute() else Path(args.repo_root) / root


def _authorization(args):
    return reader.ReadAuthorization(args.partition, args.authorized_manifest_sha256, args.authorization_ref)


def _require_confirmation(args):
    if args.confirm_partition_access != args.partition:
        raise ScientificReadRefused("AUTHORIZATION_INVALID", "--confirm-partition-access must name the partition that is being read")


def _campaign(args):
    return reader.load_campaign(args.repo_root, _authorization(args), plan_rel=args.plan, manifest_rel=args.manifest, allow_partial=args.allow_partial)


def run_preflight(args):
    report = reader.preflight(args.repo_root, _authorization(args), plan_rel=args.plan, manifest_rel=args.manifest, allow_partial=args.allow_partial)
    print("SHADOW_FEED_PREFLIGHT_OK " + json.dumps(report, sort_keys=True))
    return 0


def run_build_feed(args):
    _require_confirmation(args)
    campaign = _campaign(args)
    schedule = _json_file(args.schedule) if args.schedule else None
    sessions, access = reader.read_sessions(campaign, allow_legacy_observer=args.allow_legacy_observer)
    manifest = feed.write_feed(campaign, sessions, access, feed_id=args.feed_id, out_root=_out_root(args, feed.DEFAULT_OUT_ROOT), schedule=schedule,
                               allow_legacy_observer=args.allow_legacy_observer)
    print(f"SHADOW_FEED built feed_id={manifest['feed_id']} bundles={manifest['counts']['bundles']} refusals={manifest['counts']['producer_refusals']} "
          f"bundles_sha256={manifest['output']['bundles_sha256']} enforcement=NONE")
    return 0


def run_replay(args):
    _require_confirmation(args)
    campaign = _campaign(args)
    schedule = _json_file(args.schedule) if args.schedule else None
    config = TrustConfig.from_dict(_json_file(args.config))
    choice = args.calibration or dict(record_path=args.calibration_record, record_sha256=args.calibration_record_sha256)
    behavior = load_behavior(args.repo_root, choice, args.cross_workload_experiment).with_reserved(campaign.reserved_tokens)
    engine = DecisionEngine(config, behavior)
    if args.device_profile_registry:      # opt-in: registry-authoritative routing and the uncalibrated inference stage (decision_pipeline)
        from decision_pipeline.compose import wrap_engine
        engine = wrap_engine(engine, repo_root=args.repo_root, registry_path=args.device_profile_registry,
                             registry_sha256=args.device_profile_registry_sha256)
    sessions, access = reader.read_sessions(campaign, allow_legacy_observer=args.allow_legacy_observer)
    clock = stream.SystemClock()
    pipelines = [stream.replay_session(stream.session_pipeline(s, campaign, basis="REPLAY", engine=engine, clock=clock, sink=stream.ShadowNullSink(),
                                                               stream_id=args.replay_id, schedule=schedule), s) for s in sessions]
    manifest = stream.write_replay(campaign, pipelines, access, replay_id=args.replay_id, out_root=_out_root(args, "results/gate5f/scientific_replays"),
                                   engine=engine, schedule=schedule, allow_legacy_observer=args.allow_legacy_observer)
    print(f"SHADOW_FEED_REPLAY replay_id={manifest['replay_id']} records={manifest['record_count']} "
          f"decisions_sha256={manifest['outputs']['decisions.jsonl']['sha256']} scope={manifest['scope']} enforcement=NONE")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="shadow_feed", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("preflight", "build-feed", "replay"):
        command = sub.add_parser(name)
        command.add_argument("--partition", required=True)
        command.add_argument("--authorized-manifest-sha256", required=True)
        command.add_argument("--authorization-ref", required=True)
        command.add_argument("--plan", required=True)
        command.add_argument("--manifest", required=True)
        command.add_argument("--allow-partial", action="store_true", help="engineering use only: read an incomplete allocation (reported in every output)")
        command.add_argument("--repo-root", default=str(REPO_ROOT))
        if name != "preflight":
            command.add_argument("--confirm-partition-access", required=True, help="must repeat the partition name")
            command.add_argument("--allow-legacy-observer", action="store_true", help="accept sessions observed by the legacy two-device azta-pdp principal")
            command.add_argument("--schedule", help="versioned operating schedule JSON (the only context source)")
            command.add_argument("--out-root")
        if name == "build-feed":
            command.add_argument("--feed-id", required=True)
        if name == "replay":
            command.add_argument("--replay-id", required=True)
            command.add_argument("--config", required=True, help="trust configuration JSON (SYNTHETIC_TEST_UNAPPROVED only: no operating parameter is approved)")
            which = command.add_mutually_exclusive_group(required=True)
            which.add_argument("--calibration", choices=("gate5e-v1",), help="the accepted historical calibration (describes workload v1 only)")
            which.add_argument("--calibration-record", help="a controller-accepted versioned calibration record (needs --calibration-record-sha256)")
            command.add_argument("--calibration-record-sha256")
            command.add_argument("--cross-workload-experiment", help="name a comparison experiment that may score a workload the calibration does not describe")
            command.add_argument("--device-profile-registry", help="optional versioned device-profile registry (needs --device-profile-registry-sha256)")
            command.add_argument("--device-profile-registry-sha256")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "replay" and args.calibration_record and not args.calibration_record_sha256:
        parser.error("--calibration-record needs --calibration-record-sha256")
    if args.command == "replay" and bool(args.device_profile_registry) != bool(args.device_profile_registry_sha256):
        parser.error("--device-profile-registry and --device-profile-registry-sha256 go together")
    handlers = dict(preflight=run_preflight, **{"build-feed": run_build_feed}, replay=run_replay)
    try:
        return handlers[args.command](args)
    except REFUSALS as exc:
        print(f"SHADOW_FEED_REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
