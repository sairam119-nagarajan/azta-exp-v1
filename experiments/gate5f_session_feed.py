"""Observer-to-Shadow feed (Gate 5F): turns ONE completed observer session of ONE run into evidence bundles for the unified trust engine.

    azta-observer session  ->  validated 10 s window records  ->  + pinned read-only broker-policy audits (identity)
                           ->  + versioned operating-schedule context  ->  evidence bundles  ->  trust.shadow  ->  proposals (never applied)

This is an OFFLINE adapter over the observer's own output files. It opens no connection, holds no credential, never starts anything and
never recomputes features: the windows are the observer's records, validated by the unchanged Gate 5B schema. What it adds is only
provenance discipline:

  * the session is named EXPLICITLY (no directory discovery, so no neighbouring or reserved session can be found by accident); it must be
    COMPLETE, belong to the stated run and purpose, carry the pinned registry, schema and configuration digests, and its window file must
    match the digest recorded in its own summary;
  * the observer identity is checked: a dedicated `azta-observer...` principal is the intended source; the historical two-device `azta-pdp`
    subscriber is accepted only when the caller says so explicitly AND the registry is within its two devices (a final PDP never silently
    depends on the legacy subscriber);
  * identity evidence comes only from the run's read-only binding audits whose capture instants are pinned in their own run summaries;
    an audit with no usable summary is reported and not used; nothing is imputed;
  * a decision instant is the window's end mapped to UTC through the observer's own COVERAGE_START record (cross-checked against the
    recorded monotonic offset); only eligible windows become bundles, lead-in and post-roll windows are counted and never scored;
  * device-to-profile routes come from the committed plan (FROZEN_PLAN), never from telemetry or payload;
  * evidence of a scientific partition is NOT produced here: only FUNCTIONAL (non-scientific, FUNCTIONAL_TEST) sessions are supported. A
    D_shadow feed needs a manifest-verified artifact reader that has not been written or authorized; B_cal and CAL_V2 are never fed.

Every window yields either a bundle line or an explicit refusal line; none is dropped silently. It lives with the collection tooling, not in the
`trust` package, because it reads observer files and writes a feed: the trust package itself stays free of collection tooling and file output.

    python -m experiments.gate5f_session_feed build --run-root DIR --run-id ID --session-id obs-... --plan PLAN.json --feed-id FEED \
        --reserve-manifest configs/collection_manifests/gate5c_main.jsonl [--schedule SCHEDULE.json] [--allow-legacy-observer]
"""
import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sys

from experiments import collection_audits_v2 as audits_v2
from experiments import collection_plan as plans
from observation.observer import DEDICATED_OBSERVER, LEGACY_OBSERVER_DEVICES, OBSERVER_IDENTITY
from observation.schema import SESSION_ID, validate_window
from trust.errors import PathRefused, ProducerRefused
from trust.producer import (ContextFact, ObservedWindow, RunProvenance, audit_snapshot_from_artifacts, build_bundle,
                            operating_schedule_fact, profile_assignment_from_plan)
from trust.timeline import parse_utc_ns, window_end_utc_ns

FEED_VERSION = "gate5f-1"
FEED_SCHEMA = "azta.gate5f.session_feed_manifest"
FEED_PARTITIONS = ("FUNCTIONAL",)
FEED_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
CLOCK_BASIS = "UTC_EPOCH_NS"
WINDOW_NS = 10_000_000_000
PROTECTED_OUTPUTS = ("results/raw", "results/gate5d", "results/gate5e", "results/gate5e_addendum", "data", "configs", "docs")


def _require(condition, message):
    if not condition:
        raise ProducerRefused(message)


def _sha(blob):
    return hashlib.sha256(blob).hexdigest()


def _json_bytes(blob, what):
    try:
        return json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ProducerRefused(f"{what}: not valid JSON ({exc})") from None


@dataclass(frozen=True)
class LoadedSession:
    run_id: str
    session_id: str
    purpose: str
    observer_identity: str
    coverage_start_utc: str
    coverage_start_offset_ns: int
    windows: tuple
    windows_sha256: str
    snapshots: tuple
    unusable_audit_stages: tuple
    audit_digests: dict


def _read(path):
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        raise ProducerRefused(f"cannot read {Path(path).name}: {exc.strerror or exc}") from None


def coverage_start_from_health(blob, session_id):
    """The observer's own COVERAGE_START record: (utc text, monotonic offset ns). Exactly one must exist."""
    found = []
    for line in blob.decode("utf-8").splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue   # a half-written final line is not evidence
        if record.get("kind") == "COVERAGE_START":
            _require(record.get("observer_session_id") == session_id, "COVERAGE_START belongs to another session")
            found.append((record["utc"], record["offset_ns"]))
    _require(len(found) == 1, f"expected exactly one COVERAGE_START record, found {len(found)}")
    return found[0]


def load_session(run_root, run_id, session_id, plan, *, purpose, allow_legacy_observer=False):
    """Validate and load one completed session. Raises ProducerRefused on any inconsistency; nothing is repaired."""
    _require(isinstance(session_id, str) and SESSION_ID.fullmatch(session_id), "an explicit observer session id (obs-<32 hex>) is required")
    _require(purpose == "FUNCTIONAL_TEST" and plan.get("kind") == "FUNCTIONAL_TEST",
             "only FUNCTIONAL_TEST sessions can be fed; a scientific-partition feed needs a manifest-verified reader that is not authorized")
    config = plan.get("runs", {}).get(run_id)
    _require(config is not None, "the run is not in the plan")
    root = Path(run_root)
    directory = root / "observation" / session_id
    meta_blob = _read(directory / "session_metadata.json")
    meta = _json_bytes(meta_blob, "session_metadata.json")
    summary = _json_bytes(_read(directory / "session_summary.json"), "session_summary.json")
    windows_blob = _read(directory / "windows.jsonl")
    health_blob = _read(directory / "health.jsonl")

    _require(summary.get("state") == "COMPLETE" and summary.get("failure_code") is None
             and summary.get("invariants") and all(summary["invariants"].values()), "the observer session is not COMPLETE with all invariants true")
    _require(meta.get("observer_session_id") == session_id and summary.get("observer_session_id") == session_id, "session id mismatch")
    _require(meta.get("collection_run_id") == run_id and meta.get("purpose") == purpose == summary.get("purpose"),
             "the session belongs to another run or purpose")
    _require(meta.get("registry_sha256") == plan["registry_sha256"] and meta.get("observation_config_sha256") == plan["observation_config_sha256"]
             == summary.get("observation_config_sha256") and meta.get("schema_fingerprint") == plan["schema_fingerprint"]
             == summary.get("schema_fingerprint"), "session registry, configuration or schema digest differs from the plan pins")
    _require(meta.get("window_duration_ns") == WINDOW_NS == summary.get("window_duration_ns"), "window duration is not the pinned 10 s")
    _require(meta.get("window_count") == config["planned_window_count"], "session window count differs from the plan")
    _require(meta.get("enforcement") == "NONE" and summary.get("enforcement") == "NONE", "observer evidence must declare enforcement NONE")
    _require(summary["artifact_sha256"]["windows.jsonl"] == _sha(windows_blob) and summary["artifact_sha256"]["health.jsonl"] == _sha(health_blob)
             and summary["artifact_sha256"]["session_metadata.json"] == _sha(meta_blob),
             "windows.jsonl, health.jsonl or session_metadata.json differs from the digest in the observer's own summary")

    identity = meta.get("observer_identity")
    devices = {entry["device"] for entry in meta["registry"]["devices"]}
    if identity == OBSERVER_IDENTITY:
        _require(allow_legacy_observer, "the session was observed by the legacy azta-pdp subscriber; a final PDP requires the dedicated "
                                        "azta-observer (pass allow_legacy_observer only for the two-device functional evidence)")
        _require(devices <= LEGACY_OBSERVER_DEVICES, "the legacy subscriber cannot have observed a registry wider than device01/device02")
    else:
        _require(isinstance(identity, str) and DEDICATED_OBSERVER.fullmatch(identity), "unknown observer identity")

    utc, offset = coverage_start_from_health(health_blob, session_id)
    _require(offset == summary["coverage_start_offset_ns"], "COVERAGE_START offset differs from the session summary")
    parse_utc_ns(utc)

    windows, seen = [], set()
    for line in windows_blob.decode("utf-8").splitlines():
        window = json.loads(line)
        validate_window(window)
        key = (window["device"], window["window"]["index"])
        _require(window["collection_run_id"] == run_id and window["observer_session_id"] == session_id and window["purpose"] == purpose,
                 "a window belongs to another run, session or purpose")
        _require(window["device"] in config["devices"] and 0 <= key[1] < config["planned_window_count"] and key not in seen,
                 "a window is foreign, out of range or duplicated")
        seen.add(key)
        windows.append(window)
    _require(seen == {(d, i) for d in config["devices"] for i in range(config["planned_window_count"])}, "the session has missing window records")
    windows.sort(key=lambda w: (w["window"]["index"], w["device"]))

    snapshots, unusable, digests = [], [], {}
    for stage in audits_v2.discover_stages(root, run_id):
        item = audits_v2.load_stage(root, run_id, stage)
        try:
            _require(isinstance(item["record"], dict), "no audit record")
            snapshots.append(audit_snapshot_from_artifacts(item["record"], item["summary"], "BROKER_POLICY_AUDIT"))
            for name in ("binding_audit.json", "run_summary.json"):
                digests[f"{stage}/{name}"] = _sha(_read(audits_v2.stage_dir(root, run_id, stage) / name))
        except ProducerRefused:
            unusable.append(stage)   # reported, not used, not repaired
    return LoadedSession(run_id, session_id, purpose, identity, utc, offset, tuple(windows), _sha(windows_blob), tuple(snapshots),
                         tuple(unusable), digests)


def bundles_from_session(session, plan, *, feed_id, schedule=None, reserved_tokens=()):
    """Yield (kind, payload) in decision order: ("bundle", dict) or ("refused", dict). Design-excluded windows are counted, not emitted."""
    _require(FEED_ID.fullmatch(feed_id or ""), "feed id must be an identifier")
    config = plan["runs"][session.run_id]
    low, high = config["eligible_window_indices"]
    assignment = profile_assignment_from_plan(plan)
    run = RunProvenance(session.run_id, session.session_id, "FUNCTIONAL", "FUNCTIONAL_ARTIFACT", (low, high), plan["generator_version"],
                        plan_sha256=plans.digest(plan), windows_artifact_sha256=session.windows_sha256)
    for window in session.windows:
        index, device = window["window"]["index"], window["device"]
        if not low <= index <= high:
            continue
        evidence_id = f"{feed_id}-{device}-w{index:03d}"
        decision_ns = window_end_utc_ns(session.coverage_start_utc, session.coverage_start_offset_ns, window)
        facts = []
        if schedule is not None:
            facts.append(operating_schedule_fact(schedule, window, coverage_start_offset_ns=session.coverage_start_offset_ns, observed_ns=decision_ns))
        try:
            bundle, report = build_bundle(
                evidence_id=evidence_id, evidence_mode="TRUSTED_OFFLINE_REPLAY", clock_basis=CLOCK_BASIS, decision_ns=decision_ns,
                observation=ObservedWindow(window, decision_ns, run), audits=list(session.snapshots), assignment=assignment,
                context_facts=facts, allowed_partitions=FEED_PARTITIONS, reserved_tokens=reserved_tokens)
            bundle["annotations"]["session_feed"] = dict(
                version=FEED_VERSION, feed_id=feed_id, observer_identity=session.observer_identity, decision_instant="window end (UTC)",
                missing_inputs=report["missing_inputs"])
            yield "bundle", bundle
        except ProducerRefused as exc:
            yield "refused", dict(evidence_id=evidence_id, producer_refusal=str(exc))


def _dump(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def write_feed(out_dir, session, plan, rows, *, feed_id, schedule, allow_legacy_observer, repo_root):
    """Create bundles.jsonl and feed_manifest.json exclusively under out_dir (never overwritten, never under protected evidence paths)."""
    out = Path(out_dir)
    resolved = out.resolve()
    for relative in PROTECTED_OUTPUTS:
        base = (Path(repo_root) / relative).resolve()
        if resolved == base or base in resolved.parents:
            raise PathRefused(f"refusing to write a feed under {relative}")
    rows = list(rows)
    out.mkdir(parents=True, exist_ok=False)
    blob = "".join(_dump(payload) + "\n" for _, payload in rows).encode("utf-8")
    with open(out / "bundles.jsonl", "xb") as stream:
        stream.write(blob)
    low, high = plan["runs"][session.run_id]["eligible_window_indices"]
    manifest = dict(
        schema=FEED_SCHEMA, schema_version=1, feed_version=FEED_VERSION, feed_id=feed_id, run_id=session.run_id,
        observer_session_id=session.session_id, observer_identity=session.observer_identity, legacy_observer_allowed=bool(allow_legacy_observer),
        partition="FUNCTIONAL", evidence_scope="functional (non-scientific) observation of a FUNCTIONAL_TEST run",
        plan_id=plan["plan_id"], plan_sha256=plans.digest(plan), workload_version=plan["generator_version"],
        windows_sha256=session.windows_sha256, coverage_start_utc=session.coverage_start_utc,
        counts=dict(windows=len(session.windows), eligible=sum(low <= w["window"]["index"] <= high for w in session.windows),
                    design_excluded=sum(not low <= w["window"]["index"] <= high for w in session.windows),
                    bundles=sum(kind == "bundle" for kind, _ in rows), producer_refusals=sum(kind == "refused" for kind, _ in rows)),
        audits=dict(used=sorted(f"{s.provenance}:{s.observed_ns}" for s in session.snapshots), unusable_stages=list(session.unusable_audit_stages),
                    input_digests=session.audit_digests),
        context=dict(operating_schedule=None if schedule is None else dict(version=schedule.get("version"), sha256=_sha(_dump(schedule).encode()))),
        output=dict(bundles_sha256=_sha(blob), bytes=len(blob)),
        safety=dict(enforcement="NONE", broker_policy_changes=0, mqtt_connection=False, broker_credentials=False, docker=False))
    with open(out / "feed_manifest.json", "xb") as stream:
        stream.write((json.dumps(manifest, sort_keys=True, indent=1, allow_nan=False) + "\n").encode("utf-8"))
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build")
    build.add_argument("--run-root", required=True, help="directory holding observation/<session>/ and <run>-audit-<stage>/ of ONE functional run")
    build.add_argument("--run-id", required=True)
    build.add_argument("--session-id", required=True)
    build.add_argument("--plan", required=True)
    build.add_argument("--feed-id", required=True)
    build.add_argument("--out-root", default="results/gate5f/feeds")
    build.add_argument("--schedule", help="versioned operating schedule JSON (the only context source supported)")
    build.add_argument("--reserve-manifest", action="append", default=[], required=True,
                       help="committed manifest whose B_cal/CAL_V2 (and any named) run and session ids must never be fed")
    build.add_argument("--reserve-partition", action="append", default=[])
    build.add_argument("--allow-legacy-observer", action="store_true")
    build.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[1]))
    args = parser.parse_args(argv)
    from trust import campaign
    try:
        plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
        schedule = json.loads(Path(args.schedule).read_text(encoding="utf-8")) if args.schedule else None
        tokens = set()
        for path in args.reserve_manifest:
            tokens |= campaign.reserved_tokens_from_manifest(path, partitions=args.reserve_partition)
        _require(args.run_id not in tokens and args.session_id not in tokens, "the run or session is reserved evidence")
        session = load_session(args.run_root, args.run_id, args.session_id, plan, purpose="FUNCTIONAL_TEST",
                               allow_legacy_observer=args.allow_legacy_observer)
        rows = list(bundles_from_session(session, plan, feed_id=args.feed_id, schedule=schedule, reserved_tokens=tokens))
        out_root = Path(args.out_root)
        if not out_root.is_absolute():
            out_root = Path(args.repo_root) / out_root
        manifest = write_feed(out_root / args.feed_id, session, plan, rows, feed_id=args.feed_id, schedule=schedule,
                              allow_legacy_observer=args.allow_legacy_observer, repo_root=args.repo_root)
    except (ProducerRefused, PathRefused, OSError, ValueError, KeyError) as exc:
        print(f"SESSION_FEED_REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    c = manifest["counts"]
    print(f"SESSION_FEED {args.feed_id} bundles={c['bundles']} refusals={c['producer_refusals']} design_excluded={c['design_excluded']} "
          f"bundles_sha256={manifest['output']['bundles_sha256']} enforcement=NONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
