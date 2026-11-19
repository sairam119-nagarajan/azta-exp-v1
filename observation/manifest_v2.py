"""Versioned collection manifest (schema version 2) for the workload-v2 campaign. ENGINEERING CANDIDATE: no manifest of this version exists yet.

The accepted v1 manifest (observation/manifest.py, schema version 1) fixes its partition vocabulary at B_train, B_val, B_cal, D_shadow,
D_test and is pinned by the accepted Gate 5C/5D/5E records, so it is NOT edited. The workload-v2 campaign needs an independent NEW
calibration partition, which that vocabulary cannot express and which must never be confused with the consumed historical B_cal. This
module therefore reuses the v1 hash chain, entry bodies and helpers unchanged and generalises only what depends on the vocabulary:

  * partitions CAL_V2 (benign-only calibration of the frozen models for workload v2), D_shadow and D_test; the historical B_train, B_val
    and B_cal are NOT in the vocabulary, so a v2 manifest can never plan a run into them;
  * schema version 2 in every entry, so a v1 reader refuses a v2 file and the reverse;
  * two additional integrity rules, off in the v1 vocabulary: partitions must be frozen BEFORE any run is collected, and every collected
    run must pin the run summaries of its binding audits (their `utc_start`/`utc_end` are the only pinned capture instants).

Fidelity: with `V1_VOCABULARY` this validator is differentially tested against the v1 validator on the committed v1 manifest and a
battery of mutations (tests/test_gate5f3_manifest_v2.py), so every other rule is the v1 rule.
"""
from dataclasses import dataclass
from pathlib import Path

from observation import manifest as v1
from observation.manifest import BODY, COMMIT, ENVELOPE, EVIDENCE_ROLE, GENESIS, INVALIDATION_AUTHORITY, RELATIVE_PATH, REASON_CODE, \
    ManifestError, assignments_digest, entry_hash, file_sha256, read_entries
from observation.schema import SESSION_ID, SHA256, UTC, canonical, IDENTIFIER

MANIFEST_SCHEMA = v1.MANIFEST_SCHEMA
SCHEMA_VERSION = 2
AUDIT_SUMMARY_ROLES = ("binding_audit_pre_run_summary", "binding_audit_post_run_summary")


@dataclass(frozen=True)
class Vocabulary:
    schema_version: int
    partitions: tuple
    benign_partitions: tuple
    calibration_partition: str
    freeze_before_collection: bool
    require_audit_summaries: bool


V1_VOCABULARY = Vocabulary(1, tuple(v1.PARTITIONS), tuple(v1.BENIGN_PARTITIONS), "B_cal", False, False)
V2_VOCABULARY = Vocabulary(SCHEMA_VERSION, ("CAL_V2", "D_shadow", "D_test"), ("CAL_V2",), "CAL_V2", True, True)
PARTITIONS = V2_VOCABULARY.partitions
BENIGN_PARTITIONS = V2_VOCABULARY.benign_partitions
CALIBRATION_PARTITION = V2_VOCABULARY.calibration_partition


def make_entry(previous, entry_type, body, vocabulary=V2_VOCABULARY):
    if entry_type not in BODY or set(body) != set(BODY[entry_type]):
        raise ManifestError(f"{entry_type}: body fields must be exactly {BODY.get(entry_type)}")
    entry = dict(manifest_schema=MANIFEST_SCHEMA, schema_version=vocabulary.schema_version, seq=len(previous) + 1, entry_type=entry_type,
                 prev_entry_sha256=previous[-1]["entry_sha256"] if previous else GENESIS, **body)
    entry["entry_sha256"] = entry_hash(entry)
    return entry


def append(path, entry_type, body, artifact_root=None, vocabulary=V2_VOCABULARY):
    """Validate the whole chain including the new entry, then append one line. Never rewrites."""
    path = Path(path)
    previous = read_entries(path) if path.exists() else []
    entry = make_entry(previous, entry_type, body, vocabulary)
    validate(previous + [entry], artifact_root, vocabulary)
    with path.open("a" if previous else "x", encoding="utf-8", newline="\n") as stream:
        stream.write(canonical(entry) + "\n")
    return entry


def _req(condition, message, errors):
    if not condition:
        errors.append(message)


def validate(entries, artifact_root=None, vocabulary=V2_VOCABULARY):
    """Raise ManifestError listing every leakage/integrity violation found (the v1 rules over the given vocabulary)."""
    errors = []
    if not entries:
        raise ManifestError("empty manifest")
    header, planned, collected, voided, invalidated, replacements = None, {}, {}, {}, {}, {}
    frozen = superseded = False
    sessions, artifact_hashes = {}, {}
    for position, entry in enumerate(entries, 1):
        kind = entry.get("entry_type") if isinstance(entry, dict) else None
        if kind not in BODY or set(entry) != set(ENVELOPE) | set(BODY[kind]):
            errors.append(f"entry {position}: unknown type or fields")
            continue
        _req(entry["manifest_schema"] == MANIFEST_SCHEMA and entry["schema_version"] == vocabulary.schema_version,
             f"entry {position}: schema", errors)
        _req(entry["seq"] == position, f"entry {position}: sequence gap or reorder", errors)
        expected_prev = entries[position - 2].get("entry_sha256") if position > 1 else GENESIS
        _req(entry["prev_entry_sha256"] == expected_prev, f"entry {position}: broken hash chain", errors)
        _req(entry["entry_sha256"] == entry_hash(entry), f"entry {position}: entry hash mismatch (tampered)", errors)
        _req(not superseded, f"entry {position}: entries after SUPERSEDED_BY", errors)
        if position == 1:
            _req(kind == "MANIFEST_HEADER", "first entry must be MANIFEST_HEADER", errors)
        if kind == "MANIFEST_HEADER":
            _req(position == 1, f"entry {position}: second header", errors)
            header = entry
            _req(isinstance(entry["manifest_id"], str) and IDENTIFIER.fullmatch(entry["manifest_id"]), "header id", errors)
            _req(entry["assignment_unit"] == "collection_run", "assignment unit must be the whole collection run", errors)
            _req(list(entry["allowed_partitions"]) == list(vocabulary.partitions), "allowed partitions", errors)
            for key in ("observation_schema_fingerprint", "observation_config_sha256", "registry_sha256"):
                _req(isinstance(entry[key], str) and SHA256.fullmatch(entry[key]), f"header {key}", errors)
            _req(type(entry["window_duration_ns"]) is int and entry["window_duration_ns"] > 0, "header W", errors)
        elif kind == "RUN_PLANNED":
            run = entry["collection_run_id"]
            _req(isinstance(run, str) and IDENTIFIER.fullmatch(run), f"entry {position}: run id", errors)
            _req(run not in planned, f"entry {position}: duplicate run {run} (one partition per run)", errors)
            _req(not frozen, f"entry {position}: run planned after partitions were frozen", errors)
            scenario, partition = entry["scenario_designation"], entry["intended_partition"]
            _req(isinstance(scenario, str) and v1.SCENARIO.fullmatch(scenario), f"entry {position}: scenario", errors)
            _req(partition in vocabulary.partitions, f"entry {position}: invalid partition", errors)
            _req(entry["attack_informed"] is (scenario != "BENIGN"), f"entry {position}: attack_informed flag", errors)
            _req(partition not in vocabulary.benign_partitions or scenario == "BENIGN",
                 f"entry {position}: non-benign run in benign-only partition {partition}", errors)
            _req(isinstance(entry["devices"], list) and entry["devices"]
                 and all(isinstance(d, str) and IDENTIFIER.fullmatch(d) for d in entry["devices"]),
                 f"entry {position}: devices", errors)
            _req(type(entry["planned_window_count"]) is int and entry["planned_window_count"] > 0,
                 f"entry {position}: planned windows", errors)
            _req(isinstance(entry["workload_config_sha256"], str) and SHA256.fullmatch(entry["workload_config_sha256"]),
                 f"entry {position}: workload config digest", errors)
            planned.setdefault(run, entry)
        elif kind == "RUN_COLLECTED":
            run = entry["collection_run_id"]
            plan = planned.get(run)
            _req(plan is not None, f"entry {position}: collected run {run} was never planned", errors)
            _req(run not in collected, f"entry {position}: run {run} collected twice", errors)
            _req(run not in voided, f"entry {position}: run {run} collected after void", errors)
            if vocabulary.freeze_before_collection:
                _req(frozen, f"entry {position}: run {run} collected before the partitions were frozen", errors)
            if plan is not None:
                _req(entry["planned_entry_sha256"] == plan["entry_sha256"], f"entry {position}: plan reference", errors)
            _req(entry["observation_purpose"] == "COLLECTION", f"entry {position}: functional-test sessions are not data", errors)
            _req(entry["collection_git_state"] == "clean" and isinstance(entry["collection_git_commit"], str)
                 and COMMIT.fullmatch(entry["collection_git_commit"]),
                 f"entry {position}: collection must run from a clean committed checkpoint", errors)
            _req(isinstance(entry["observer_session_id"], str) and SESSION_ID.fullmatch(entry["observer_session_id"]),
                 f"entry {position}: session id", errors)
            if header is not None:
                for key in ("observation_schema_fingerprint", "observation_config_sha256"):
                    _req(entry[key] == header[key], f"entry {position}: {key} differs from manifest header", errors)
            pre, post = entry["binding_audit_pre"], entry["binding_audit_post"]
            _req(isinstance(pre, dict) and isinstance(post, dict) and pre.get("verdict") == "PASS"
                 and post.get("verdict") == "PASS" and pre.get("policy_sha256") == post.get("policy_sha256"),
                 f"entry {position}: pre/post binding audit missing, failed or changed", errors)
            session = entry["observer_session_id"]
            _req(session not in sessions, f"entry {position}: observer session reused by {sessions.get(session)}", errors)
            sessions[session] = run
            artifacts = entry["artifacts"] if isinstance(entry["artifacts"], list) else [None]
            for artifact in artifacts:
                if not (isinstance(artifact, dict) and set(artifact) == {"role", "path", "sha256"}
                        and isinstance(artifact["sha256"], str) and SHA256.fullmatch(artifact["sha256"])):
                    errors.append(f"entry {position}: malformed artifact reference")
                    continue
                owner = artifact_hashes.get(artifact["sha256"])
                _req(owner in (None, run), f"entry {position}: artifact reused from run {owner}", errors)
                artifact_hashes[artifact["sha256"]] = run
                if artifact_root is not None:
                    target = Path(artifact_root) / artifact["path"]
                    _req(target.is_file() and file_sha256(target) == artifact["sha256"],
                         f"entry {position}: artifact {artifact['path']} missing or digest mismatch", errors)
            if vocabulary.require_audit_summaries:
                roles = {a.get("role") for a in artifacts if isinstance(a, dict)}
                _req(set(AUDIT_SUMMARY_ROLES) <= roles,
                     f"entry {position}: the binding-audit run summaries (pinned capture instants) are not pinned", errors)
            collected[run] = entry
        elif kind == "RUN_VOIDED":
            run = entry["collection_run_id"]
            _req(run in planned, f"entry {position}: voided run was never planned", errors)
            _req(run not in voided, f"entry {position}: run voided twice", errors)
            _req(run not in collected, f"entry {position}: run {run} was collected; use RUN_INVALIDATED", errors)
            _req(isinstance(entry["reason"], str) and entry["reason"].strip(), f"entry {position}: void reason", errors)
            voided[run] = dict(entry, after_freeze=frozen)
        elif kind == "RUN_INVALIDATED":
            run = entry["collection_run_id"]
            record = collected.get(run)
            _req(record is not None, f"entry {position}: invalidated run {run} was never collected", errors)
            _req(run not in invalidated, f"entry {position}: run {run} invalidated twice", errors)
            if record is not None:
                _req(entry["collected_entry_sha256"] == record["entry_sha256"], f"entry {position}: collected entry reference", errors)
            _req(entry["decision_authority"] == INVALIDATION_AUTHORITY, f"entry {position}: decision authority", errors)
            _req(isinstance(entry["reason_code"], str) and REASON_CODE.fullmatch(entry["reason_code"]),
                 f"entry {position}: reason code", errors)
            _req(isinstance(entry["reason"], str) and entry["reason"].strip(), f"entry {position}: invalidation reason", errors)
            evidence = entry["evidence"]
            _req(isinstance(evidence, list) and evidence, f"entry {position}: invalidation evidence required", errors)
            for item in evidence if isinstance(evidence, list) else []:
                if not (isinstance(item, dict) and set(item) == {"role", "path", "sha256"}
                        and isinstance(item["role"], str) and EVIDENCE_ROLE.fullmatch(item["role"])
                        and isinstance(item["path"], str) and RELATIVE_PATH.fullmatch(item["path"])
                        and isinstance(item["sha256"], str) and SHA256.fullmatch(item["sha256"])):
                    errors.append(f"entry {position}: malformed evidence reference (relative path, role, sha256)")
                    continue
                if artifact_root is not None:
                    target = Path(artifact_root) / item["path"]
                    _req(target.is_file() and file_sha256(target) == item["sha256"],
                         f"entry {position}: evidence {item['path']} missing or digest mismatch", errors)
            replacement = entry["replacement_run_id"]
            if replacement is not None:
                target = planned.get(replacement) if isinstance(replacement, str) else None
                _req(target is not None and replacement != run, f"entry {position}: replacement must be a different planned run", errors)
                if target is not None and run in planned:
                    original = planned[run]
                    _req(all(target[k] == original[k] for k in ("intended_partition", "workload_profile_id", "devices",
                                                               "scenario_designation", "planned_window_count")),
                         f"entry {position}: replacement {replacement} does not match partition/profile of {run}", errors)
                _req(replacement not in replacements,
                     f"entry {position}: replacement {replacement} already replaces {replacements.get(replacement)}", errors)
                _req(replacement not in voided and replacement not in invalidated,
                     f"entry {position}: replacement {replacement} is voided or invalidated", errors)
                replacements[replacement] = run
            invalidated[run] = entry
        elif kind == "PARTITIONS_FROZEN":
            _req(not frozen, f"entry {position}: partitions frozen twice", errors)
            expected = {run: plan["intended_partition"] for run, plan in planned.items()}
            _req(entry["assignments"] == expected, f"entry {position}: frozen assignments differ from planned", errors)
            _req(entry["assignments_sha256"] == assignments_digest(entry["assignments"]), f"entry {position}: assignments digest", errors)
            frozen = True
        elif kind == "SUPERSEDED_BY":
            _req(isinstance(entry["reason"], str) and entry["reason"].strip(), f"entry {position}: supersede reason", errors)
            superseded = True
        for key in ("created_utc", "planned_utc", "collected_utc", "voided_utc", "frozen_utc", "superseded_utc"):
            if key in entry:
                _req(isinstance(entry[key], str) and UTC.fullmatch(entry[key]), f"entry {position}: {key}", errors)
    if errors:
        raise ManifestError("; ".join(errors))
    return dict(header=header, planned=planned, collected=collected, voided=voided, invalidated=invalidated,
                replacements=replacements, frozen=frozen, superseded=superseded)


def check_collection_allowed(path, run_id, *, expected_manifest_sha256, git_commit, git_state, vocabulary=V2_VOCABULARY):
    """Refuse a real collection unless its RUN_PLANNED exists in a committed, clean, unaltered, frozen manifest (v1 rule plus freeze)."""
    if git_state != "clean" or not isinstance(git_commit, str) or not COMMIT.fullmatch(git_commit):
        raise ManifestError("collection refused: not running from a clean committed checkpoint")
    actual = file_sha256(path)
    if actual != expected_manifest_sha256:
        raise ManifestError("collection refused: manifest differs from the committed planning state")
    state = validate(read_entries(path), None, vocabulary)
    if state["superseded"]:
        raise ManifestError("collection refused: manifest superseded")
    if vocabulary.freeze_before_collection and not state["frozen"]:
        raise ManifestError("collection refused: partitions are not frozen")
    plan = state["planned"].get(run_id)
    if plan is None:
        raise ManifestError("collection refused: run has no committed RUN_PLANNED entry")
    if run_id in state["collected"] or run_id in state["voided"]:
        raise ManifestError("collection refused: run already collected or voided")
    return dict(planned_entry_sha256=plan["entry_sha256"], manifest_sha256=actual, git_commit=git_commit,
                planned_window_count=plan["planned_window_count"], window_duration_ns=state["header"]["window_duration_ns"],
                observation_config_sha256=state["header"]["observation_config_sha256"])

