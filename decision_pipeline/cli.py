"""Command line of the integrated decision pipeline (offline Shadow over evidence bundles, with registry-authoritative routing).

    python -m decision_pipeline verify-registry --registry R.json --registry-sha256 H [--repo-root DIR]
    python -m decision_pipeline run --config CFG.json --bundles B.jsonl --run-id ID (--calibration gate5e-v1 | --calibration-record R --calibration-record-sha256 H)
                                    --device-profile-registry R.json --device-profile-registry-sha256 H
                                    [--reserve-manifest M.jsonl [--reserve-partition P ...]] [--cross-workload-experiment NAME] [--output-root DIR]

`run` is `trust.shadow run` with the integrated engine: the same exclusive outputs (`decisions.jsonl`, `summary.json`, `shadow_run_manifest.json`), the same
refusal of replay evidence without an explicit reserve protection, the same zero-mutation guarantees, plus the registry's routing, the labelled inference
telemetry and the failure classes inside `annotations.decision_pipeline`. Nothing that selects a calibration, a registry or a parameter has a default; the
trust configuration must be an explicit SYNTHETIC_TEST_UNAPPROVED one (no operating parameter is approved). The command has no broker, credential or network access.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

from decision_pipeline.compose import wrap_engine
from decision_pipeline.errors import RegistryRefused
from trust.config import ConfigError
from trust.errors import ArtifactRefused, PathRefused, ProducerRefused

REFUSALS = (RegistryRefused, ArtifactRefused, PathRefused, ProducerRefused, ConfigError, OSError, ValueError, KeyError)


def _reject_constant(name):
    raise ValueError(f"non-finite JSON constant {name}")


def _parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify-registry")
    run = sub.add_parser("run")
    for command in (verify, run):
        command.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[1]))
    verify.add_argument("--registry", required=True)
    verify.add_argument("--registry-sha256", required=True)
    run.add_argument("--config", required=True)
    run.add_argument("--bundles", required=True)
    run.add_argument("--run-id", required=True)
    run.add_argument("--output-root", default="results/gate5f")
    which = run.add_mutually_exclusive_group(required=True)
    which.add_argument("--calibration", choices=("gate5e-v1",), help="the accepted historical calibration (describes workload v1 only)")
    which.add_argument("--calibration-record", help="a controller-accepted versioned calibration record (needs --calibration-record-sha256)")
    run.add_argument("--calibration-record-sha256")
    run.add_argument("--cross-workload-experiment", help="name a comparison experiment that may score a workload the calibration does not describe")
    run.add_argument("--reserve-manifest", action="append", default=[], help="committed collection manifest whose partitions to reserve")
    run.add_argument("--reserve-partition", action="append", default=[], help="partition to reserve from --reserve-manifest (e.g. D_test)")
    run.add_argument("--device-profile-registry", required=True)
    run.add_argument("--device-profile-registry-sha256", required=True)
    return parser


def _verify_registry(args):
    from preprocessing.gate5d_data import PIN
    from trust import artifacts
    from decision_pipeline.registry import load_registry, model_catalog_from_freeze
    catalog = model_catalog_from_freeze(artifacts.load_freeze(Path(args.repo_root)))
    registry = load_registry(args.registry, authorized_file_sha256=args.registry_sha256, model_catalog=catalog,
                             model_pins={k: PIN[k] for k in ("registry_sha256", "observation_config_sha256")})
    print(json.dumps(registry.describe(), sort_keys=True, indent=1))
    return 0


def _run(args):
    from trust import artifacts, campaign
    from trust.config import TrustConfig
    from trust.engine import DecisionEngine
    from trust.shadow import ShadowRunner
    choice = args.calibration or dict(record_path=args.calibration_record, record_sha256=args.calibration_record_sha256)
    behavior = artifacts.load_frozen_behavior(args.repo_root, calibration=choice)
    if args.cross_workload_experiment:
        behavior = behavior.with_cross_workload_baseline(args.cross_workload_experiment)
    config = TrustConfig.from_dict(json.loads(Path(args.config).read_text(encoding="utf-8"), parse_constant=_reject_constant))
    output_root = Path(args.output_root)
    if not output_root.is_absolute():
        output_root = Path(args.repo_root) / output_root
    protection = None
    if args.reserve_manifest:
        tokens, reserved, described = set(), set(), []
        for path in args.reserve_manifest:
            tokens |= campaign.reserved_tokens_from_manifest(path, partitions=args.reserve_partition)
            reserved |= set(campaign.effective_partitions(path, args.reserve_partition))
            described.append(dict(file_name=Path(path).name, sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest()))
        behavior = behavior.with_reserved(tokens)
        protection = dict(manifests=described, partitions=sorted(reserved), reserved_token_count=len(tokens))
    engine = wrap_engine(DecisionEngine(config, behavior), repo_root=args.repo_root, registry_path=args.device_profile_registry,
                         registry_sha256=args.device_profile_registry_sha256)
    manifest = ShadowRunner(engine, args.repo_root, reserve_protection=protection).run(args.run_id, args.bundles, output_root)
    print(f"DECISION_PIPELINE run_id={manifest['run_id']} records={manifest['record_count']} registry_sha256={engine.registry.sha256} "
          f"decisions_sha256={manifest['outputs']['decisions.jsonl']['sha256']} enforcement=NONE")
    return 0


def main(argv=None):
    args = _parser().parse_args(argv)
    if args.command == "run" and bool(args.calibration_record) != bool(args.calibration_record_sha256):
        _parser().error("--calibration-record and --calibration-record-sha256 go together")
    try:
        return _verify_registry(args) if args.command == "verify-registry" else _run(args)
    except REFUSALS as exc:
        print(f"DECISION_PIPELINE_REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
