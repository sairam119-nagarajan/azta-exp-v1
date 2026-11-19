"""Verified scientific sessions -> evidence bundles for the UNCHANGED trust engine, and the exclusive feed files.

`window_bundle` is the single place where one observer window becomes one evidence bundle. The file feed below and the streaming pipeline
(`shadow_feed.stream`) both call it, so a replay through either path builds identical bundles. It adds only provenance discipline on top of the
existing producer (`trust.producer.build_bundle`), which stays authoritative:

  * the run is declared with the MANIFEST_ARTIFACT source kind and the D_shadow partition, carrying the plan, manifest and window-artifact
    digests, so a bundle can be traced to a committed manifest entry and a verified file;
  * the producer already refuses a bundle whose partition is not allowed, whose run or session is reserved (D_test, CAL_V2, invalidated), or
    whose window lies outside the plan's eligible range; the feed passes the manifest-derived reserved set, so none of those can be fed;
  * device-to-profile routes come from the committed plan (FROZEN_PLAN), identity evidence only from the pinned read-only audits (latest one
    completed not later than the decision), context only from a caller-supplied versioned schedule; payload and publisher claims have no
    parameter anywhere;
  * a decision instant is the window end in UTC (replay): lead-in and post-roll windows are counted and never scored;
  * every window yields a bundle line or an explicit refusal line; none is dropped.

Nothing here scores a window, chooses a parameter, opens a connection or touches policy.
"""
import hashlib
import json
from pathlib import Path
import re

from experiments import collection_plan as plans
from shadow_feed import reader
from shadow_feed.errors import ScientificReadRefused
from trust.errors import PathRefused, ProducerRefused
from trust.producer import ObservedWindow, RunProvenance, build_bundle, operating_schedule_fact, profile_assignment_from_plan
from trust.timeline import window_end_utc_ns

FEED_VERSION = "gate5f-sci-1"
FEED_SCHEMA = "azta.gate5f.scientific_feed_manifest"
CLOCK_BASIS = "UTC_EPOCH_NS"
FEED_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
FEED_PARTITIONS = ("D_shadow",)
DEFAULT_OUT_ROOT = "results/gate5f/scientific_feeds"
PROTECTED_OUTPUTS = ("results/raw", "results/gate5d", "results/gate5e", "results/gate5e_addendum", "results/gate5f4", "data", "configs", "docs",
                     "tests", "calibration", "model", "preprocessing", "observation", "experiments", "trust", "shadow_feed")
SAFETY = dict(enforcement="NONE", broker_policy_changes=0, mqtt_connection=False, broker_credentials=False, docker=False,
              note="counterfactual evidence feed; no enforcement and no broker interaction")


def _dump(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha256_bytes(blob):
    return hashlib.sha256(blob).hexdigest()


def run_provenance(session, plan, *, manifest_sha256):
    """The run as the producer must see it: a manifest artifact of the D_shadow partition with all three digests."""
    return RunProvenance(session.run_id, session.session_id, session.partition, "MANIFEST_ARTIFACT", tuple(session.eligible_window_indices),
                         session.workload_version, plan_sha256=plans.digest(plan), manifest_sha256=manifest_sha256,
                         windows_artifact_sha256=session.windows_sha256)


def decision_instant_ns(session, window):
    """UTC epoch ns of the window's end: the pinned coverage-start UTC plus the monotonic distance from the coverage start."""
    return window_end_utc_ns(session.coverage_start_utc, session.coverage_start_offset_ns, window)


def window_bundle(*, evidence_id, evidence_mode, clock_basis, decision_ns, available_ns, window, run, snapshots, assignment, schedule,
                  coverage_start_offset_ns, allowed_partitions, reserved_tokens, extra_context_facts=()):
    """(bundle dict, producer report) for ONE window. Raises ProducerRefused for anything the producer will not combine.

    `extra_context_facts` are additional, already-built `ContextFact`s from a trusted source (the pilot's broker-derived context); the producer still validates them."""
    facts = []
    if schedule is not None:
        facts.append(operating_schedule_fact(schedule, window, coverage_start_offset_ns=coverage_start_offset_ns, observed_ns=decision_ns))
    facts.extend(extra_context_facts)
    return build_bundle(evidence_id=evidence_id, evidence_mode=evidence_mode, clock_basis=clock_basis, decision_ns=decision_ns,
                        observation=ObservedWindow(window, available_ns, run), audits=list(snapshots), assignment=assignment,
                        context_facts=facts, allowed_partitions=allowed_partitions, reserved_tokens=reserved_tokens)


def evidence_id_for(feed_id, run_id, device, index):
    return f"{feed_id}-{run_id}-{device}-w{index:03d}"


def bundles_from_session(session, plan, *, manifest_sha256, feed_id, reference, schedule=None, reserved_tokens=frozenset()):
    """Yield ("bundle", dict) or ("refused", dict) in decision order for one verified session. Design-excluded windows are not emitted."""
    if not FEED_ID.fullmatch(feed_id or ""):
        raise ProducerRefused("feed id must be an identifier")
    low, high = session.eligible_window_indices
    assignment = profile_assignment_from_plan(plan)
    run = run_provenance(session, plan, manifest_sha256=manifest_sha256)
    for window in session.windows:
        index, device = window["window"]["index"], window["device"]
        if not low <= index <= high:
            continue
        evidence_id = evidence_id_for(feed_id, session.run_id, device, index)
        decision_ns = decision_instant_ns(session, window)
        try:
            bundle, report = window_bundle(
                evidence_id=evidence_id, evidence_mode="TRUSTED_OFFLINE_REPLAY", clock_basis=CLOCK_BASIS, decision_ns=decision_ns,
                available_ns=decision_ns, window=window, run=run, snapshots=session.snapshots, assignment=assignment, schedule=schedule,
                coverage_start_offset_ns=session.coverage_start_offset_ns, allowed_partitions=FEED_PARTITIONS, reserved_tokens=reserved_tokens)
            bundle["annotations"]["scientific_feed"] = dict(
                version=FEED_VERSION, feed_id=feed_id, authorization_reference=reference, observer_identity=session.observer_identity,
                decision_instant="window end (UTC), replay: not a measured feature-ready instant", review_flags=list(session.review_flags),
                missing_inputs=report["missing_inputs"])
            yield "bundle", bundle
        except ProducerRefused as exc:
            yield "refused", dict(evidence_id=evidence_id, producer_refusal=str(exc))


def _protected(out_dir, repo_root):
    resolved = Path(out_dir).resolve()
    for relative in PROTECTED_OUTPUTS:
        base = (Path(repo_root) / relative).resolve()
        if resolved == base or base in resolved.parents:
            raise PathRefused(f"refusing to write a feed under {relative}")


def write_feed(campaign, sessions, access, *, feed_id, out_root, schedule=None, allow_legacy_observer=False):
    """Create bundles.jsonl and feed_manifest.json exclusively under out_root/feed_id (never overwritten, never under protected locations)."""
    if not FEED_ID.fullmatch(feed_id or ""):
        raise ProducerRefused("feed id must be an identifier")
    if campaign.authorization.partition not in FEED_PARTITIONS:
        raise ScientificReadRefused("PARTITION_LOCKED", f"only {FEED_PARTITIONS} can be fed")
    out = Path(out_root) / feed_id
    _protected(out, campaign.repo)
    plan, reference = campaign.plan, campaign.authorization.reference
    rows, runs = [], []
    for session in sessions:
        session_rows = list(bundles_from_session(session, plan, manifest_sha256=campaign.manifest_sha256, feed_id=feed_id, reference=reference,
                                                 schedule=schedule, reserved_tokens=campaign.reserved_tokens))
        rows += session_rows
        low, high = session.eligible_window_indices
        runs.append(dict(
            run_id=session.run_id, observer_session_id=session.session_id, observer_identity=session.observer_identity,
            collected_entry_sha256=session.collected_entry_sha256, windows_sha256=session.windows_sha256,
            coverage_start_utc=session.coverage_start_utc, review_flags=list(session.review_flags),
            counts=dict(windows=len(session.windows), eligible=sum(low <= w["window"]["index"] <= high for w in session.windows),
                        design_excluded=sum(not low <= w["window"]["index"] <= high for w in session.windows),
                        bundles=sum(kind == "bundle" for kind, _ in session_rows), producer_refusals=sum(kind == "refused" for kind, _ in session_rows)),
            audits=dict(stages=len(session.snapshots), input_digests=session.audit_digests)))
    out.mkdir(parents=True, exist_ok=False)                  # an existing feed is never reused or overwritten
    blob = "".join(_dump(payload) + "\n" for _, payload in rows).encode("utf-8")
    with open(out / "bundles.jsonl", "xb") as stream:
        stream.write(blob)
    manifest = dict(
        schema=FEED_SCHEMA, schema_version=1, feed_version=FEED_VERSION, feed_id=feed_id, partition=campaign.authorization.partition,
        authorization=dict(reference=reference, manifest_sha256=campaign.authorization.manifest_sha256),
        evidence_scope="accepted scientific observation, manifest-verified replay; counterfactual only, not a live measurement",
        plan=dict(plan_id=plan["plan_id"], plan_sha256=campaign.plan_sha256, plan_file_sha256=campaign.plan_file_sha256, path=campaign.plan_rel,
                  workload_version=plan["generator_version"], approval_ref=plan["approval_ref"]),
        manifest=dict(path=campaign.manifest_rel, sha256=campaign.manifest_sha256), allocation=campaign.allocation,
        legacy_observer_allowed=bool(allow_legacy_observer), runs=runs,
        reserved_protection=dict(partitions=list(reader.RESERVED_PARTITIONS), reserved_token_count=len(campaign.reserved_tokens)),
        context=dict(operating_schedule=None if schedule is None else dict(version=schedule.get("version"), sha256=sha256_bytes(_dump(schedule).encode()))),
        access=access, counts=dict(bundles=sum(r["counts"]["bundles"] for r in runs), producer_refusals=sum(r["counts"]["producer_refusals"] for r in runs)),
        output=dict(bundles_sha256=sha256_bytes(blob), bytes=len(blob)), safety=SAFETY)
    with open(out / "feed_manifest.json", "xb") as stream:
        stream.write((json.dumps(manifest, sort_keys=True, indent=1, allow_nan=False) + "\n").encode("utf-8"))
    return manifest
