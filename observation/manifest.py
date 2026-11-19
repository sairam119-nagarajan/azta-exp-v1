"""Append-only, hash-chained collection/partition manifest (azta.collection.manifest v1).

The assignment unit is the whole collection run. A run's intended partition is fixed in its
RUN_PLANNED entry, which must be committed in a clean Git checkpoint BEFORE the run is
collected; collection tooling refuses otherwise. Windows are never assigned individually.
Gate 5B creates no real entries: only temporary synthetic manifests are used in tests.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from observation.records import file_sha256
from observation.schema import IDENTIFIER, SESSION_ID, SHA256, UTC, canonical

MANIFEST_SCHEMA = "azta.collection.manifest"
SCHEMA_VERSION = 1
PARTITIONS = ("B_train", "B_val", "B_cal", "D_shadow", "D_test")
BENIGN_PARTITIONS = ("B_train", "B_val", "B_cal")
SCENARIO = re.compile(r"BENIGN\Z|ATTACK_[A-Z0-9_]{1,48}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
GENESIS = "0" * 64
BODY = {
    "MANIFEST_HEADER": ("manifest_id", "created_utc", "purpose", "assignment_unit", "allowed_partitions",
                        "observation_schema_fingerprint", "observation_config_sha256", "window_duration_ns",
                        "registry_sha256"),
    "RUN_PLANNED": ("collection_run_id", "devices", "workload_profile_id", "scenario_designation",
                    "attack_informed", "intended_partition", "planned_window_count", "workload_config_sha256",
                    "planned_utc"),
    "RUN_COLLECTED": ("collection_run_id", "planned_entry_sha256", "observer_session_id", "observation_purpose",
                      "collection_git_commit", "collection_git_state", "manifest_sha256_at_collection",
                      "observation_schema_fingerprint", "observation_config_sha256", "artifacts",
                      "binding_audit_pre", "binding_audit_post", "session_state", "collected_utc"),
    "RUN_VOIDED": ("collection_run_id", "reason", "voided_utc"),
    # Gate 5C controller decision (17 October 2026): post-collection scientific invalidation of a
    # RUN_COLLECTED run. Append-only; the RUN_COLLECTED entry and its evidence stay unchanged.
    "RUN_INVALIDATED": ("collection_run_id", "collected_entry_sha256", "decision_authority", "reason_code", "reason",
                        "evidence", "replacement_run_id", "invalidated_utc"),
    "PARTITIONS_FROZEN": ("frozen_utc", "assignments", "assignments_sha256"),
    "SUPERSEDED_BY": ("successor_manifest_id", "reason", "superseded_utc"),
}
ENVELOPE = ("manifest_schema", "schema_version", "seq", "entry_type", "prev_entry_sha256", "entry_sha256")
INVALIDATION_AUTHORITY = "CONTROLLER_SCIENTIFIC_VALIDITY_DECISION"
REASON_CODE = re.compile(r"[A-Z][A-Z0-9_]{2,63}\Z")
EVIDENCE_ROLE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
RELATIVE_PATH = re.compile(r"(?!/)(?![A-Za-z]:)(?!.*(?:^|/)\.\.(?:/|\Z))[A-Za-z0-9._/-]{1,256}\Z")


class ManifestError(ValueError):
    pass


def entry_hash(entry):
    return hashlib.sha256(canonical({k: v for k, v in entry.items() if k != "entry_sha256"}).encode()).hexdigest()


def assignments_digest(assignments):
    return hashlib.sha256(canonical(assignments).encode()).hexdigest()


def read_entries(path):
    with Path(path).open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def make_entry(previous, entry_type, body):
    if entry_type not in BODY or set(body) != set(BODY[entry_type]):
        raise ManifestError(f"{entry_type}: body fields must be exactly {BODY.get(entry_type)}")
    entry = dict(manifest_schema=MANIFEST_SCHEMA, schema_version=SCHEMA_VERSION,
                 seq=len(previous) + 1, entry_type=entry_type,
                 prev_entry_sha256=previous[-1]["entry_sha256"] if previous else GENESIS, **body)
    entry["entry_sha256"] = entry_hash(entry)
    return entry


def append(path, entry_type, body, artifact_root=None):
    """Validate the whole chain including the new entry, then append one line. Never rewrites."""
    path = Path(path)
    previous = read_entries(path) if path.exists() else []
    entry = make_entry(previous, entry_type, body)
    validate(previous + [entry], artifact_root)
    with path.open("a" if previous else "x", encoding="utf-8", newline="\n") as stream:
        stream.write(canonical(entry) + "\n")
    return entry


def _req(condition, message, errors):
    if not condition:
        errors.append(message)


def validate(entries, artifact_root=None):
    """Raise ManifestError listing every leakage/integrity violation found."""
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
        _req(entry["manifest_schema"] == MANIFEST_SCHEMA and entry["schema_version"] == SCHEMA_VERSION,
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
            _req(list(entry["allowed_partitions"]) == list(PARTITIONS), "allowed partitions", errors)
            for key in ("observation_schema_fingerprint", "observation_config_sha256", "registry_sha256"):
                _req(isinstance(entry[key], str) and SHA256.fullmatch(entry[key]), f"header {key}", errors)
            _req(type(entry["window_duration_ns"]) is int and entry["window_duration_ns"] > 0, "header W", errors)
        elif kind == "RUN_PLANNED":
            run = entry["collection_run_id"]
            _req(isinstance(run, str) and IDENTIFIER.fullmatch(run), f"entry {position}: run id", errors)
            _req(run not in planned, f"entry {position}: duplicate run {run} (one partition per run)", errors)
            _req(not frozen, f"entry {position}: run planned after partitions were frozen", errors)
            scenario, partition = entry["scenario_designation"], entry["intended_partition"]
            _req(isinstance(scenario, str) and SCENARIO.fullmatch(scenario), f"entry {position}: scenario", errors)
            _req(partition in PARTITIONS, f"entry {position}: invalid partition", errors)
            _req(entry["attack_informed"] is (scenario != "BENIGN"), f"entry {position}: attack_informed flag", errors)
            _req(partition not in BENIGN_PARTITIONS or scenario == "BENIGN",
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
            if plan is not None:
                _req(entry["planned_entry_sha256"] == plan["entry_sha256"], f"entry {position}: plan reference", errors)
            _req(entry["observation_purpose"] == "COLLECTION", f"entry {position}: functional-test sessions are not data",
                 errors)
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
            for artifact in entry["artifacts"] if isinstance(entry["artifacts"], list) else [None]:
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
                _req(entry["collected_entry_sha256"] == record["entry_sha256"],
                     f"entry {position}: collected entry reference", errors)
            _req(entry["decision_authority"] == INVALIDATION_AUTHORITY, f"entry {position}: decision authority", errors)
            _req(isinstance(entry["reason_code"], str) and REASON_CODE.fullmatch(entry["reason_code"]),
                 f"entry {position}: reason code", errors)
            _req(isinstance(entry["reason"], str) and entry["reason"].strip(), f"entry {position}: invalidation reason",
                 errors)
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
                _req(target is not None and replacement != run,
                     f"entry {position}: replacement must be a different planned run", errors)
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
            _req(entry["assignments_sha256"] == assignments_digest(entry["assignments"]),
                 f"entry {position}: assignments digest", errors)
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


def check_collection_allowed(path, run_id, *, expected_manifest_sha256, git_commit, git_state):
    """Refuse a real collection unless its RUN_PLANNED exists in a committed, clean, unaltered manifest.

    The host wrapper (experiments/observation_collect.ps1) verifies with Git that the manifest is
    tracked and unmodified in a clean checkpoint and passes its SHA-256 here.
    """
    if git_state != "clean" or not isinstance(git_commit, str) or not COMMIT.fullmatch(git_commit):
        raise ManifestError("collection refused: not running from a clean committed checkpoint")
    actual = file_sha256(path)
    if actual != expected_manifest_sha256:
        raise ManifestError("collection refused: manifest differs from the committed planning state")
    state = validate(read_entries(path))
    if state["superseded"]:
        raise ManifestError("collection refused: manifest superseded")
    plan = state["planned"].get(run_id)
    if plan is None:
        raise ManifestError("collection refused: run has no committed RUN_PLANNED entry")
    if run_id in state["collected"] or run_id in state["voided"]:
        raise ManifestError("collection refused: run already collected or voided")
    return dict(planned_entry_sha256=plan["entry_sha256"], manifest_sha256=actual, git_commit=git_commit,
                planned_window_count=plan["planned_window_count"],
                window_duration_ns=state["header"]["window_duration_ns"],
                observation_config_sha256=state["header"]["observation_config_sha256"])


def main(argv=None):
    parser = argparse.ArgumentParser(description="Validate a Gate 5B collection manifest.")
    parser.add_argument("action", choices=("validate",))
    parser.add_argument("manifest")
    parser.add_argument("--artifact-root")
    args = parser.parse_args(argv)
    try:
        state = validate(read_entries(args.manifest), args.artifact_root)
    except (ManifestError, OSError, ValueError) as exc:
        print(f"MANIFEST_INVALID {exc}", file=sys.stderr)
        return 1
    print(f"MANIFEST_VALID runs={len(state['planned'])} collected={len(state['collected'])} "
          f"invalidated={len(state['invalidated'])} voided={len(state['voided'])} frozen={state['frozen']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
