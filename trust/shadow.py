"""Offline Shadow Mode: replay validated evidence bundles through the unified trust engine and log what the policy WOULD be.

A Shadow decision is counterfactual. This module reads one bundle file, calls DecisionEngine.decide() for each line, and writes three
new files (decisions, summary, manifest) under results/gate5f/<run_id>/. It needs no broker credential, no MQTT connection and no
container, it has no capability to change broker permissions, and it makes no claim that any proposed state was or could be enforced.
Every input line is accounted for: a malformed line becomes a BUNDLE_REFUSED record, never a silent skip. Outputs are created
exclusively (an existing run directory is refused, so earlier evidence is never overwritten) and contain no wall-clock time, so the same
inputs and artifacts give byte-identical files. Inputs under results/raw (the raw observation evidence, including the consumed
calibration runs) and outputs under any accepted-evidence location are refused.

    python -m trust.shadow run --config CFG.json --bundles BUNDLES.jsonl --run-id ID [--output-root results/gate5f]
    python -m trust.shadow verify-artifacts          (verifies and prints the frozen model and calibration descriptors; scores nothing)
"""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re
import statistics
import sys

from trust.config import TrustConfig
from trust.engine import DECISION_SCHEMA, DECISION_SCHEMA_VERSION, DecisionEngine
from trust.errors import BundleRefused, PathRefused
from trust.evidence import parse_bundle

MANIFEST_SCHEMA = "azta.gate5f.shadow_run_manifest"
RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
PROTECTED_INPUTS = ("results/raw",)
PROTECTED_OUTPUTS = ("results/raw", "results/gate5d", "results/gate5e", "results/gate5e_addendum", "data", "configs", "docs")
SAFETY = dict(enforcement="NONE", broker_policy_changes=0, counterfactual=True, mqtt_connection=False, broker_credentials=False,
              docker=False, note="a Shadow decision is a counterfactual log record, not proof of effective broker enforcement")
CAVEATS = (
    "descriptive only: windows within a run share environment and are not independent; no operating characteristic, detection claim or "
    "parameter selection follows from these records",
    "epsilon, lambda, alpha/beta/gamma, context weights and tau_Q/tau_R in a SYNTHETIC_TEST_UNAPPROVED configuration are test values, "
    "not calibrated or approved operating parameters",
)


def _reject_constant(name):
    raise ValueError(f"non-finite JSON constant {name}")


def dumps(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _inside(path, repo_root, relatives):
    resolved = Path(path).resolve()
    for relative in relatives:
        base = (Path(repo_root) / relative).resolve()
        if resolved == base or base in resolved.parents:
            return relative
    return None


def read_bundles(path, repo_root):
    """Yield (line_number, EvidenceBundle | None, refusal reason | None, evidence_id | None) for every non-blank line, in order."""
    hit = _inside(path, repo_root, PROTECTED_INPUTS)
    if hit:
        raise PathRefused(f"refusing to read evidence bundles from {hit}: raw observation evidence is never a Shadow input")
    seen = set()
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        evidence_id = None
        try:
            data = json.loads(line, parse_constant=_reject_constant)
            evidence_id = data.get("evidence_id") if isinstance(data, dict) else None
            bundle = parse_bundle(data)
            if bundle.evidence_id in seen:
                raise BundleRefused(f"duplicate evidence_id {bundle.evidence_id!r}")
            seen.add(bundle.evidence_id)
            yield number, bundle, None, evidence_id
        except (ValueError, BundleRefused) as exc:
            yield number, None, str(exc), evidence_id if isinstance(evidence_id, str) else None


def _distribution(values):
    if not values:
        return None
    return dict(n=len(values), min=min(values), median=statistics.median(values), mean=math.fsum(values) / len(values), max=max(values))


def _values(records, key):
    return [r["behavior"][key] for r in records if r["behavior"].get(key) is not None]


def summarize(records):
    """Deterministic descriptive summary: state counts, missingness by reason, and per (profile, delivered_count) strata."""
    decisions = [r for r in records if r["record_kind"] == "SHADOW_DECISION"]
    refused = [r for r in records if r["record_kind"] == "BUNDLE_REFUSED"]
    missingness = {c: Counter(reason for r in decisions if r[c]["outcome"] == "MISSING" for reason in r[c]["reasons"])
                   for c in ("identity", "behavior", "context")}
    strata = {}
    for r in decisions:
        scored = r["behavior"]["outcome"] == "EVALUATED"
        key = f"{r['stratum']['profile']}|delivered_count={r['stratum']['delivered_count']}" if scored else "behavior_not_scored"
        entry = strata.setdefault(key, dict(records=[], states=Counter()))
        entry["records"].append(r)
        entry["states"][r["proposed_state"] or "NO_PROPOSAL"] += 1
    return dict(
        records=len(records), decisions=len(decisions), bundle_refused=len(refused),
        evaluated=sum(r["status"] == "EVALUATED" for r in decisions), not_evaluable=sum(r["status"] == "NOT_EVALUABLE" for r in decisions),
        proposed_state_counts=dict(Counter(r["proposed_state"] or "NO_PROPOSAL" for r in decisions)),
        missingness_by_reason={c: dict(counter) for c, counter in missingness.items()},
        refusal_reasons=dict(Counter(r["reason"] for r in refused)),
        strata={key: dict(
            n=len(entry["records"]), proposed_state_counts=dict(entry["states"]),
            reconstruction_loss=_distribution(_values(entry["records"], "loss")),
            anomaly_magnitude=_distribution(_values(entry["records"], "anomaly_magnitude")),
            behavioral_trust=_distribution(_values(entry["records"], "s_b")),
            composite_trust=_distribution([r["fusion"]["trust"] for r in entry["records"]
                                           if r["fusion"] and "trust" in r["fusion"]]))
            for key, entry in sorted(strata.items())},
        caveats=list(CAVEATS))


class ShadowRunner:
    """reserve_protection: None, or a description (manifests and partitions) of the extra run/session reservation that is ALREADY applied
    to the engine's behavioural evaluator. Bundles that claim TRUSTED_OFFLINE_REPLAY evidence are refused without it (fail closed), so a
    real-evidence replay can never run while the held-out partitions are unprotected."""

    def __init__(self, engine, repo_root, *, reserve_protection=None):
        self.engine, self.repo_root, self.reserve_protection = engine, Path(repo_root), reserve_protection

    def run(self, run_id, bundle_path, output_root):
        if not RUN_ID.fullmatch(run_id or ""):
            raise ValueError("run id must be an identifier")
        hit = _inside(bundle_path, self.repo_root, PROTECTED_INPUTS)
        if hit:
            raise PathRefused(f"refusing to read evidence bundles from {hit}: raw observation evidence is never a Shadow input")
        hit = _inside(output_root, self.repo_root, PROTECTED_OUTPUTS)
        if hit:
            raise PathRefused(f"refusing to write Shadow output under {hit}")
        bundle_bytes = Path(bundle_path).read_bytes()
        records = []
        for number, bundle, reason, evidence_id in read_bundles(bundle_path, self.repo_root):
            if bundle is None or (bundle.evidence_mode == "TRUSTED_OFFLINE_REPLAY" and self.reserve_protection is None):
                reason = reason or "REPLAY_REQUIRES_RESERVE_PROTECTION: real-evidence replay needs an explicit reserve manifest and partitions"
                records.append(dict(schema=DECISION_SCHEMA, schema_version=DECISION_SCHEMA_VERSION, record_kind="BUNDLE_REFUSED",
                                    line_number=number, evidence_id=evidence_id or (bundle.evidence_id if bundle else None),
                                    reason=reason, enforcement="NONE"))
            else:
                records.append(self.engine.decide(bundle))
        out_dir = Path(output_root) / run_id
        out_dir.mkdir(parents=True, exist_ok=False)  # an existing run is never reused or overwritten
        decisions = "".join(dumps(r) + "\n" for r in records).encode("utf-8")
        summary = (json.dumps(summarize(records), sort_keys=True, indent=1, allow_nan=False) + "\n").encode("utf-8")
        outputs = {}
        for name, blob in (("decisions.jsonl", decisions), ("summary.json", summary)):
            with open(out_dir / name, "xb") as stream:
                stream.write(blob)
            outputs[name] = dict(sha256=hashlib.sha256(blob).hexdigest(), bytes=len(blob))
        manifest = dict(schema=MANIFEST_SCHEMA, schema_version=1, run_id=run_id, engine=self.engine.describe(),
                        input=dict(file_name=Path(bundle_path).name, sha256=hashlib.sha256(bundle_bytes).hexdigest(),
                                   bytes=len(bundle_bytes)),
                        outputs=outputs, record_count=len(records), safety=SAFETY, caveats=list(CAVEATS),
                        reserve_protection=self.reserve_protection)
        with open(out_dir / "shadow_run_manifest.json", "xb") as stream:
            stream.write((json.dumps(manifest, sort_keys=True, indent=1, allow_nan=False) + "\n").encode("utf-8"))
        return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--config", required=True)
    run.add_argument("--bundles", required=True)
    run.add_argument("--run-id", required=True)
    run.add_argument("--output-root", default="results/gate5f")
    which = run.add_mutually_exclusive_group(required=True)
    which.add_argument("--calibration", choices=("gate5e-v1",), help="the accepted historical calibration (workload v1 only)")
    which.add_argument("--calibration-record", help="a controller-accepted versioned v2 calibration record (needs --calibration-record-sha256)")
    run.add_argument("--calibration-record-sha256")
    run.add_argument("--cross-workload-experiment", help="name a comparison experiment that may score a workload the calibration does not describe")
    run.add_argument("--reserve-manifest", action="append", default=[], help="committed collection manifest whose partitions to reserve")
    run.add_argument("--reserve-partition", action="append", default=[], help="partition to reserve from --reserve-manifest (e.g. D_test)")
    for command in (run, sub.add_parser("verify-artifacts")):
        command.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[1]))
    args = parser.parse_args(argv)
    from trust import artifacts
    if args.command == "verify-artifacts":
        choice = "gate5e-v1"
    elif args.calibration:
        choice = args.calibration
    elif args.calibration_record and args.calibration_record_sha256:
        choice = dict(record_path=args.calibration_record, record_sha256=args.calibration_record_sha256)
    else:
        parser.error("--calibration-record needs --calibration-record-sha256")
    behavior = artifacts.load_frozen_behavior(args.repo_root, calibration=choice)
    if args.command == "run" and args.cross_workload_experiment:
        behavior = behavior.with_cross_workload_baseline(args.cross_workload_experiment)
    if args.command == "verify-artifacts":
        print(json.dumps(behavior.provenance, sort_keys=True, indent=1))
        return 0
    config = TrustConfig.from_dict(json.loads(Path(args.config).read_text(encoding="utf-8"), parse_constant=_reject_constant))
    output_root = Path(args.output_root)
    if not output_root.is_absolute():
        output_root = Path(args.repo_root) / output_root
    protection = None
    if args.reserve_manifest:
        from trust import campaign
        tokens, reserved, described = set(), set(), []
        for path in args.reserve_manifest:
            tokens |= campaign.reserved_tokens_from_manifest(path, partitions=args.reserve_partition)
            reserved |= set(campaign.effective_partitions(path, args.reserve_partition))
            described.append(dict(file_name=Path(path).name, sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest()))
        behavior = behavior.with_reserved(tokens)
        protection = dict(manifests=described, partitions=sorted(reserved), reserved_token_count=len(tokens))
    manifest = ShadowRunner(DecisionEngine(config, behavior), args.repo_root, reserve_protection=protection).run(
        args.run_id, args.bundles, output_root)
    print(f"GATE5F_SHADOW run_id={manifest['run_id']} records={manifest['record_count']} "
          f"decisions_sha256={manifest['outputs']['decisions.jsonl']['sha256']} enforcement=NONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
