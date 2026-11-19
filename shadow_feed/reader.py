"""Manifest-verified reader of ACCEPTED scientific observer sessions: the D_shadow evidence path into the Shadow-mode pipeline.

Nothing here selects a parameter, scores a window or changes policy. It turns committed, hash-chained manifest entries into verified, in-memory
sessions and accounts for every byte it opens. The verification mirrors the single-use CAL_V2 tool (`calibration/gate5f4_calibrate.py`, which this
module deliberately does NOT import: that module loads the model stack, and a differential test keeps the two validators in step), restricted to
what a reader of decision evidence may touch:

  * only `D_shadow` can be read. `D_test` is the locked final-test partition (no unlock mechanism is authorized), `CAL_V2` and the historical `B_*`
    partitions are consumed calibration or training evidence and are never decision evidence;
  * the caller must hold an explicit `ReadAuthorization` (partition, the committed manifest's SHA-256, a controller reference); there is no default;
  * the manifest is validated WITHOUT an artifact root, so merely loading a campaign opens no evidence; the plan must be approved, the partitions
    frozen, the pins equal to the frozen model pins, and the manifest header bound to exactly the supplied plan;
  * the files that may be opened are the exact, digest-pinned allowlist of the accepted runs of the requested partition (windows, observer session
    metadata and summary, workload metadata and summary, reconciliation, and every pinned audit with its capture-instant summary). `events.jsonl`,
    `health.jsonl` and the publisher ledgers are never opened; the window-to-UTC mapping comes from the pinned workload summary, which records the
    observer's own COVERAGE_START instant;
  * while reading, an interpreter-level audit hook refuses ANY other open, directory listing or write under the raw evidence root, in this process;
  * every run must be ACCEPT-reconciled with all six named checks PASS, provenance-consistent with the manifest, plan and attestation, and its audit
    capture timing must re-derive exactly from the pinned summaries; any inconsistency is a refusal, never a repair.

The legacy two-device `azta-pdp` observer is accepted only when the caller says so explicitly (the v2 two-device campaign was observed by it), and
only for a registry inside device01/device02; a dedicated `azta-observer` principal is accepted without the flag.
"""
from collections import Counter, namedtuple
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sys

from experiments import collection_audits_v2 as audits
from experiments import collection_finalize_v2 as finalize
from experiments import collection_plan as plans
from experiments import collection_plan_v2 as plans_v2
from experiments import collection_workload_v2 as workload
from observation import manifest_v2 as manifest
from observation.registry import DeviceRegistry
from observation.schema import IDENTIFIER, SHA256, validate_window
from preprocessing import gate5d_data as data
from shadow_feed.errors import ScientificReadRefused
from trust.errors import ProducerRefused
from trust.producer import audit_snapshot_from_artifacts
from trust.timeline import parse_utc_ns

RAW_REL = "results/raw"
REGISTRY_REL = "configs/observation/device_registry.json"
V1_PLAN_REL = "configs/collection_plans/gate5c_workload_v1.json"
READABLE_PARTITIONS = ("D_shadow",)
LOCKED_PARTITIONS = {
    "D_test": "the final-test partition is locked: no unlock mechanism is authorized (a controller decision and a freeze record come first)",
    "CAL_V2": "the CAL_V2 partition was consumed by the single-use calibration and is never decision evidence",
    "B_cal": "the historical calibration partition was consumed by Gate 5E and is never decision evidence",
    "B_train": "B_train is model-fitting evidence and is never Shadow evidence",
    "B_val": "B_val is validation evidence and is never Shadow evidence",
}
RESERVED_PARTITIONS = tuple(sorted({"D_test", manifest.CALIBRATION_PARTITION}))     # never fed while D_shadow is developed: the held-out and the calibration runs
PINS = {key: data.PIN[key] for key in ("registry_sha256", "observation_config_sha256", "schema_fingerprint")}
WORKLOAD = workload.GENERATOR_VERSION
PROFILES = data.PROFILES
WINDOW_NS = 10_000_000_000
OBSERVER_IDENTITY = "azta-pdp"           # equal to observation.observer.OBSERVER_IDENTITY (a test asserts it; that module imports paho)
DEDICATED_OBSERVER = re.compile(r"azta-observer(-[a-z0-9][a-z0-9-]{0,30})?\Z")
LEGACY_OBSERVER_DEVICES = frozenset({"device01", "device02"})
REQUIRED_CHECKS = frozenset({"windows_complete_and_replayed", "termination_complete", "manifest_plan_matches_run", "binding_audits_pass",
                             "audit_capture_instants_pinned_and_cadence_as_declared", "policy_digest_unchanged"})
REPORT_SCHEMA = "azta.collection.reconciliation_candidate"
GUARDED_EVENTS = ("open", "os.listdir", "os.scandir", "os.remove", "os.rename", "os.mkdir", "os.rmdir")


def _fail(code, message):
    raise ScientificReadRefused(code, message)


def _require(condition, code, message):
    if not condition:
        _fail(code, message)


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def safe_path(root, relative):
    """Exact relative paths only: no traversal, absolute names, alternate streams, links or junctions."""
    _require(isinstance(relative, str) and relative and "\\" not in relative and ":" not in relative, "PATH_UNSAFE", "invalid relative path")
    parts = relative.split("/")
    _require(all(p not in ("", ".", "..") for p in parts) and not Path(relative).is_absolute(), "PATH_UNSAFE", "path traversal")
    root = Path(root).absolute()
    current = root
    for part in parts:
        current /= part
        _require(not current.is_symlink() and not current.is_junction(), "PATH_UNSAFE", "linked evidence/configuration path refused")
    _require(current.resolve().is_relative_to(root.resolve()), "PATH_UNSAFE", "path escapes its root")
    return current


def reserved_tokens(state):
    """Run and session ids that may never be fed while D_shadow is developed: every planned run of the held-out and the calibration partitions and
    every invalidated run, together with the sessions of those that were collected. It is derived from the already validated manifest state, so it
    comes from exactly the authorized bytes (the trust package derives the same set from the file, and a test keeps the two equal)."""
    tokens = set()
    for run, planned in state["planned"].items():
        if planned["intended_partition"] in RESERVED_PARTITIONS or run in state["invalidated"]:
            tokens.add(run)
            if run in state["collected"]:
                tokens.add(state["collected"][run]["observer_session_id"])
    return frozenset(tokens)


@dataclass(frozen=True)
class ReadAuthorization:
    """The explicit, auditable permission to read ONE partition of ONE committed manifest. There is no default and no ambient permission."""
    partition: str
    manifest_sha256: str
    reference: str

    def __post_init__(self):
        _require(isinstance(self.partition, str) and self.partition, "AUTHORIZATION_INVALID", "a partition is required")
        _require(isinstance(self.manifest_sha256, str) and SHA256.fullmatch(self.manifest_sha256), "AUTHORIZATION_INVALID",
                 "the authorized manifest SHA-256 is required")
        _require(isinstance(self.reference, str) and IDENTIFIER.fullmatch(self.reference), "AUTHORIZATION_INVALID",
                 "a controller authorization reference (identifier) is required")


@dataclass(frozen=True)
class Campaign:
    repo: Path
    authorization: ReadAuthorization
    plan: dict
    plan_sha256: str
    plan_file_sha256: str
    plan_rel: str
    manifest_rel: str
    manifest_sha256: str
    state: dict
    runs: tuple
    allocation: dict
    blocked_tokens: frozenset
    reserved_tokens: frozenset


PlanState = namedtuple("PlanState", "repo plan plan_blob manifest_blob manifest_sha256 state historical_tokens")


def check_plan_pins_and_geometry(plan):
    """The workload, registry and schema pins equal the frozen model pins, and the geometry is the frozen 1 + 60 + 1 layout of 10 s windows."""
    _require(plan["generator_version"] == WORKLOAD and plan["registry_sha256"] == PINS["registry_sha256"]
             and plan["observation_config_sha256"] == PINS["observation_config_sha256"]
             and plan["schema_fingerprint"] == PINS["schema_fingerprint"], "PIN_MISMATCH", "plan workload, registry or schema pins differ")
    _require(plan["window_roles"] == dict(lead_in=[0, 0], eligible=[1, 60], post_roll=[61, 61]) and plan["planned_window_count"] == 62
             and plan["window_duration_ms"] == 10_000, "GEOMETRY_MISMATCH", "the window geometry differs from the frozen 1 + 60 + 1 layout")


def load_plan_and_state(repo, *, plan_rel, manifest_rel, expected_manifest_sha256):
    """The committed, approved scientific plan and its frozen, plan-bound manifest, validated WITHOUT an artifact root (no evidence file is opened).

    The single definition of what a usable plan/manifest pair is, shared by the replay reader (`load_campaign`) and the prospective live-session
    declaration (`shadow_live`), so the two can never disagree about it. `expected_manifest_sha256` is the digest the caller was authorized for."""
    repo = Path(repo).resolve()
    _require(isinstance(plan_rel, str) and isinstance(manifest_rel, str) and plan_rel.startswith("configs/collection_plans/")
             and manifest_rel.startswith("configs/collection_manifests/"), "CONFIG_PATH_INVALID",
             "plan and manifest must be explicit repository configurations")
    plan_blob = safe_path(repo, plan_rel).read_bytes()
    manifest_blob = safe_path(repo, manifest_rel).read_bytes()
    manifest_sha = digest(manifest_blob)
    _require(manifest_sha == expected_manifest_sha256, "MANIFEST_DIGEST_MISMATCH", "the authorization names a different manifest")
    try:
        plan = json.loads(plan_blob)
        entries = [json.loads(line) for line in manifest_blob.decode("utf-8").splitlines() if line.strip()]
        state = manifest.validate(entries)
    except ValueError as exc:
        _fail("MANIFEST_INVALID", f"manifest or plan cannot be validated: {str(exc)[:300]}")
    try:
        registry = DeviceRegistry.load(safe_path(repo, REGISTRY_REL))
        v1_plan = json.loads(safe_path(repo, V1_PLAN_REL).read_bytes())
    except (ValueError, KeyError, TypeError, OSError) as exc:
        _fail("CONFIG_INVALID", f"the device registry or the historical plan cannot be loaded ({type(exc).__name__})")
    try:
        plans_v2.validate_plan_v2(plan, registry, v1_plan=v1_plan)
        plans.check_manifest_against_plan(state, plan)
    except (ValueError, KeyError, TypeError) as exc:
        _fail("PLAN_INVALID", f"plan does not validate against the registry or the manifest: {str(exc)[:300]}")
    _require(plan["kind"] == "SCIENTIFIC" and plan["approval_status"] == "APPROVED" and plan["approval_ref"], "PLAN_NOT_APPROVED",
             "an explicitly controller-approved scientific v2 plan is required")
    _require(state["frozen"] and not state["superseded"], "MANIFEST_NOT_FROZEN", "the manifest must be frozen and current")
    header = state["header"]
    _require(header["observation_schema_fingerprint"] == PINS["schema_fingerprint"] and header["registry_sha256"] == PINS["registry_sha256"]
             and header["observation_config_sha256"] == PINS["observation_config_sha256"] and header["window_duration_ns"] == WINDOW_NS,
             "PIN_MISMATCH", "manifest observation pins differ from the frozen model pins")
    check_plan_pins_and_geometry(plan)
    purpose = header["purpose"]
    _require(f"plan={plan_rel} " in purpose and f"plan_sha256={plans.digest(plan)} " in purpose, "MANIFEST_PLAN_UNBOUND",
             "the manifest header is not bound to the supplied plan")
    try:
        historical = data.load_campaign(repo)       # pinned Gate 5C configuration metadata only; no artifact root
    except ValueError as exc:
        _fail("PIN_MISMATCH", f"the historical campaign pins cannot be verified: {str(exc)[:200]}")
    historical_tokens = set(historical.plan["runs"]) | {e["observer_session_id"] for e in historical.entries
                                                         if e["entry_type"] == "RUN_COLLECTED"}
    return PlanState(repo, plan, plan_blob, manifest_blob, manifest_sha, state, frozenset(historical_tokens))


def load_campaign(repo, authorization, *, plan_rel, manifest_rel, allow_partial=False):
    """Metadata only. The manifest is validated WITHOUT an artifact root, so no evidence file is opened or hashed here."""
    _require(isinstance(authorization, ReadAuthorization), "AUTHORIZATION_INVALID", "an explicit ReadAuthorization is required")
    partition = authorization.partition
    if partition in LOCKED_PARTITIONS:
        _fail("PARTITION_LOCKED", f"{partition}: {LOCKED_PARTITIONS[partition]}")
    _require(partition in READABLE_PARTITIONS, "PARTITION_UNKNOWN", f"only {READABLE_PARTITIONS} can be read, not {partition!r}")
    loaded = load_plan_and_state(repo, plan_rel=plan_rel, manifest_rel=manifest_rel, expected_manifest_sha256=authorization.manifest_sha256)
    repo, plan, plan_blob, manifest_sha, state = loaded.repo, loaded.plan, loaded.plan_blob, loaded.manifest_sha256, loaded.state
    historical_tokens = loaded.historical_tokens
    cells = {c["run_id"]: c for c in plan["cells"]}
    excluded = set(state["invalidated"]) | set(state["voided"])
    runs = tuple(sorted(r for r in state["collected"] if r not in excluded and cells[r]["intended_partition"] == partition))
    _require(runs, "NO_COLLECTED_RUNS", f"the manifest has no accepted collected {partition} run: nothing exists to read")
    for run in runs:
        _require(state["collected"][run]["session_state"] == "COMPLETE" and state["planned"][run]["scenario_designation"] == "BENIGN",
                 "RUN_NOT_ACCEPTED", f"{run}: incomplete or non-benign run")
    replacements, assigned = finalize._replacement_map(state, cells)     # pure manifest-only mapping; no inventory call
    originals = {r for r, c in cells.items() if c["role"] == "SCIENTIFIC" and c["intended_partition"] == partition}
    _require(all(cells[r]["role"] == "SCIENTIFIC" or assigned.get(r) in originals for r in runs), "SUBSTITUTE_UNASSIGNED",
             "a collected substitute does not replace a voided or invalidated planned run")
    missing = sorted(r for r in originals if r not in runs and not any(x["original"] == r and x["substitute"] in runs for x in replacements))
    required, counts = plan["allocation"][partition], dict(Counter(cells[r]["plan"] for r in runs))
    complete = counts == required and not missing
    if not allow_partial:
        _require(complete, "ALLOCATION_INCOMPLETE", f"accepted {partition} runs {counts} differ from the approved allocation {required}"
                                                    f" (missing without a replacement: {missing}); pass allow_partial only for engineering use")
    else:
        _require(all(counts.get(letter, 0) <= required.get(letter, 0) for letter in set(counts) | set(required)), "ALLOCATION_INCOMPLETE",
                 f"accepted {partition} runs {counts} exceed the approved allocation {required}")
    blocked = historical_tokens | {r for r in state["planned"] if r not in runs}
    blocked |= {e["observer_session_id"] for r, e in state["collected"].items() if r not in runs}
    return Campaign(repo, authorization, plan, plans.digest(plan), digest(plan_blob), plan_rel, manifest_rel, manifest_sha, state, runs,
                    dict(partition=partition, required=required, accepted=counts, complete=complete, partial_allowed=bool(allow_partial),
                         missing_without_replacement=missing, replacements=[dict(x) for x in replacements]),
                    frozenset(blocked), reserved_tokens(state))


def assert_readable(campaign):
    """Re-assert, at the moment evidence would be opened, what `load_campaign` established: the authorized partition is a readable one and every
    run to be read belongs to it. A Campaign that was built or edited by hand (rather than returned by `load_campaign`) cannot widen the read."""
    partition = campaign.authorization.partition
    if partition in LOCKED_PARTITIONS:
        _fail("PARTITION_LOCKED", f"{partition}: {LOCKED_PARTITIONS[partition]}")
    _require(partition in READABLE_PARTITIONS, "PARTITION_UNKNOWN", f"only {READABLE_PARTITIONS} can be read, not {partition!r}")
    for run in campaign.runs:
        planned = campaign.state["planned"].get(run)
        if planned is None or planned["intended_partition"] != partition:
            _fail("PARTITION_LOCKED", f"{run} does not belong to the authorized partition {partition}")
        if run in campaign.state["invalidated"] or run in campaign.state["voided"] or run not in campaign.state["collected"]:
            _fail("RUN_NOT_ACCEPTED", f"{run} is not an accepted collected run")


def expected_artifacts(run, entry):
    """Only the selected windows and their validation metadata; never events, health or publisher ledgers."""
    session = entry["observer_session_id"]
    paths = {"observer_windows": f"observation/{session}/windows.jsonl",
             "observer_session_metadata": f"observation/{session}/session_metadata.json",
             "observer_session_summary": f"observation/{session}/session_summary.json",
             "workload_metadata": f"collection/{run}/workload_metadata.json",
             "workload_summary": f"collection/{run}/workload_summary.json",
             "reconciliation": f"collection/{run}/reconciliation.json"}
    roles = [a["role"] for a in entry["artifacts"]]
    _require(len(roles) == len(set(roles)), "ARTIFACT_PINS_INVALID", f"{run}: duplicate artifact roles")
    stages = {"pre", "post"}
    for role in roles:
        if role.startswith("binding_audit_"):
            stage = role[len("binding_audit_"):].removesuffix("_run_summary")
            _require(audits.STAGE.fullmatch(stage), "ARTIFACT_PINS_INVALID", f"{run}: invalid audit stage")
            stages.add(stage)
    for stage in stages:
        paths[f"binding_audit_{stage}"] = f"{run}-audit-{stage}/binding_audit.json"
        paths[f"binding_audit_{stage}_run_summary"] = f"{run}-audit-{stage}/run_summary.json"
    found = {a["role"]: a for a in entry["artifacts"]}
    _require(set(paths) <= set(found), "ARTIFACT_PINS_INVALID", f"{run}: missing pinned validation metadata")
    _require(all(found[k]["path"] == p for k, p in paths.items()), "ARTIFACT_PINS_INVALID",
             f"{run}: artifact path does not belong to this run/session")
    return {k: found[k] for k in paths}, ["pre", *sorted(stages - {"pre", "post"}), "post"]


_GUARDS = []
_HOOK = []


def _audit(event, args):
    for guard in tuple(_GUARDS):
        guard.check(event, args)


class AllowlistedEvidenceReader:
    """Digest-verified exact allowlist plus a pre-open interpreter guard over the whole raw evidence tree."""

    def __init__(self, repo, campaign):
        assert_readable(campaign)
        self.root = safe_path(repo, RAW_REL)
        self.by_run, self.stages, self.allowed = {}, {}, {}
        self.reads, self.events, self.cache = [], [], {}
        self.active = False
        for run in campaign.runs:
            items, stages = expected_artifacts(run, campaign.state["collected"][run])
            self.by_run[run], self.stages[run] = items, stages
            for artifact in items.values():
                relative = artifact["path"]
                _require(not any(token in relative for token in campaign.blocked_tokens) and "g5c-" not in relative, "RESERVED_PATH",
                         "reserved scientific evidence path")
                path = safe_path(self.root, relative)
                _require(str(path) not in self.allowed, "ARTIFACT_PINS_INVALID", "duplicate allowlisted path")
                self.allowed[str(path)] = artifact["sha256"]

    def check(self, event, args):
        if not self.active or event not in GUARDED_EVENTS:
            return
        if event == "os.rename":
            for target in args[:2]:
                self.check("os.remove", (target,))      # both source and destination are forbidden under the raw root
            return
        target = args[0]
        if not isinstance(target, (str, bytes, os.PathLike)):
            return
        path = os.path.abspath(os.fsdecode(target))
        try:
            inside = os.path.normcase(os.path.commonpath((self.root, path))) == os.path.normcase(str(self.root))
        except ValueError:                               # another Windows drive
            inside = False
        if not inside:
            return
        self.events.append(dict(event=event, path=path))
        _require(event == "open" and path in self.allowed, "GUARD_VIOLATION", "interpreter guard refused non-allowlisted raw-evidence access")
        mode, flags = args[1:3]
        _require((mode is None or mode in ("r", "rb")) and not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC),
                 "GUARD_VIOLATION", "raw evidence is read-only")

    @contextmanager
    def armed(self):
        if not _HOOK:
            sys.addaudithook(_audit)                    # audit hooks cannot be removed; one module-level hook serves every guard
            _HOOK.append(True)
        _GUARDS.append(self)
        self.active = True
        try:
            yield self
        finally:
            self.active = False
            _GUARDS.remove(self)

    def read(self, artifact):
        path = safe_path(self.root, artifact["path"])
        key = str(path)
        _require(self.allowed.get(key) == artifact["sha256"], "RESERVED_PATH", "outside the D_shadow allowlist")
        _require(key not in self.cache, "GUARD_VIOLATION", "duplicate evidence read")
        try:
            blob = path.read_bytes()
        except OSError as exc:
            _fail("ARTIFACT_MISSING", f"a pinned artifact cannot be read ({exc.__class__.__name__}): {artifact['path']}")
        _require(digest(blob) == artifact["sha256"], "DIGEST_MISMATCH", f"artifact digest differs from its manifest pin: {artifact['path']}")
        self.cache[key] = True
        self.reads.append(dict(path=artifact["path"], sha256=digest(blob), bytes=len(blob)))
        return blob

    def verify_complete(self):
        _require({e["path"] for e in self.events} == set(self.allowed) and len(self.reads) == len(self.allowed),
                 "ALLOWLIST_MISMATCH", "interpreter events and reader allowlist differ")

    def access_report(self):
        return dict(allowlisted_files=len(self.allowed), reads=list(self.reads), interpreter_events=len(self.events),
                    interpreter_events_equal_allowlist={e["path"] for e in self.events} == set(self.allowed))


@dataclass(frozen=True)
class ScientificSession:
    run_id: str
    session_id: str
    partition: str
    purpose: str
    observer_identity: str
    workload_version: str
    eligible_window_indices: tuple
    coverage_start_utc: str
    coverage_start_offset_ns: int
    windows: tuple
    windows_sha256: str
    snapshots: tuple
    audit_digests: dict
    collected_entry_sha256: str
    review_flags: tuple
    planned_window_count: int


def _json(blobs, key, run):
    try:
        return json.loads(blobs[key])
    except (ValueError, KeyError):
        _fail("METADATA_INVALID", f"{run}: {key} is not valid JSON")


def validate_run_artifacts(campaign, run, blobs, stages, *, allow_legacy_observer=False):
    """The per-run provenance, reconciliation and audit-timing checks (mirroring the CAL_V2 tool's `validate_metadata`).
    Returns (meta, summary, workload_summary, report, audit objects)."""
    plan, entry = campaign.plan, campaign.state["collected"][run]
    config = plan["runs"][run]
    objects = {k: _json(blobs, k, run) for k in blobs if k != "observer_windows"}
    report, meta, summary = (objects[k] for k in ("reconciliation", "observer_session_metadata", "observer_session_summary"))
    try:
        accepted = (report["schema"] == REPORT_SCHEMA and report["schema_version"] == 1 and report["verdict"] == "ACCEPT"
                    and report["reasons"] == [] and report["campaign_stop"] is False)
        provenance = (report["run_id"] == run and report["observer_session_id"] == entry["observer_session_id"]
                      and report["purpose"] == "COLLECTION" and report["generator_version"] == WORKLOAD and report["plan_kind"] == "SCIENTIFIC"
                      and report["plan_sha256"] == campaign.plan_sha256 and report["workload_config_sha256"] == plans.digest(config))
        checks = {c["name"]: c["result"] for c in report["checks"]}
    except (KeyError, TypeError):
        _fail("RECONCILIATION_NOT_ACCEPT", f"{run}: the reconciliation report is malformed")
    _require(accepted, "RECONCILIATION_NOT_ACCEPT", f"{run}: reconciliation is not an unflagged ACCEPT")
    _require(provenance, "REPORT_PROVENANCE_MISMATCH", f"{run}: the reconciliation report belongs to another run, plan or workload")
    _require(REQUIRED_CHECKS <= set(checks) and set(checks.values()) == {"PASS"}, "RECONCILIATION_NOT_ACCEPT",
             f"{run}: reconciliation checks failed or are missing")
    try:
        for obj in (meta, summary):
            _require(obj["observer_session_id"] == entry["observer_session_id"] and obj["purpose"] == "COLLECTION"
                     and obj["schema_fingerprint"] == PINS["schema_fingerprint"]
                     and obj["observation_config_sha256"] == PINS["observation_config_sha256"], "OBSERVER_PROVENANCE_MISMATCH",
                     f"{run}: observer provenance mismatch")
        _require(meta["registry_sha256"] == PINS["registry_sha256"] and meta["window_duration_ns"] == WINDOW_NS
                 and meta["window_count"] == config["planned_window_count"] and summary["state"] == "COMPLETE"
                 and summary["failure_code"] is None and summary["invariants"] and all(summary["invariants"].values()),
                 "OBSERVER_INCOMPLETE", f"{run}: observer not complete or not compatible")
        _require(meta["collection_run_id"] == run, "OBSERVER_PROVENANCE_MISMATCH", f"{run}: observer run mismatch")
        _require(summary["artifact_sha256"]["windows.jsonl"] == digest(blobs["observer_windows"]), "DIGEST_MISMATCH",
                 f"{run}: the window file differs from the observer's own summary digest")
        attestation = meta["collection_attestation"]
        _require(attestation["git_commit"] == entry["collection_git_commit"] and meta["runtime"]["git_state"] == "clean"
                 and meta["runtime"]["git_commit"] == entry["collection_git_commit"]
                 and attestation["planned_entry_sha256"] == entry["planned_entry_sha256"]
                 and attestation["manifest_sha256"] == entry["manifest_sha256_at_collection"], "ATTESTATION_MISMATCH",
                 f"{run}: collection attestation mismatch")
        for key in ("workload_metadata", "workload_summary"):
            obj = objects[key]
            _require(obj["generator_version"] == WORKLOAD and obj["workload_config_sha256"] == plans.digest(config)
                     and obj["run_id"] == run and obj["purpose"] == "COLLECTION" and obj["attestation"] == attestation
                     and obj["devices"] == {d: dict(profile=s["profile"], username=s["username"], client_id=s["client_id"],
                                                    telemetry_topic=s["telemetry_topic"], planned_messages=obj["devices"][d]["planned_messages"])
                                            for d, s in config["devices"].items()}, "WORKLOAD_PROVENANCE_MISMATCH",
                     f"{run}: workload provenance mismatch")
        workload_summary = objects["workload_summary"]
        _require(workload_summary["state"] == "COMPLETE" and workload_summary["failure_code"] is None
                 and workload_summary["observer_session_id"] == entry["observer_session_id"], "WORKLOAD_INCOMPLETE",
                 f"{run}: the workload is incomplete or belongs to another session")
        cadence = report["audit_cadence"]
        _require(not cadence["problems"] and [r["stage"] for r in cadence["stages"]] == stages, "AUDIT_TIMING_INVALID",
                 f"{run}: audit cadence problems or stage mismatch")
        items = []
        for stage in stages:
            audit, audit_summary = objects[f"binding_audit_{stage}"], objects[f"binding_audit_{stage}_run_summary"]
            _require(audit["verdict"] == "PASS" and audit["registry_sha256"] == PINS["registry_sha256"]
                     and audit["policy_sha256"] == entry["binding_audit_pre"]["policy_sha256"] and audit.get("mutation_performed") is False,
                     "AUDIT_INVALID", f"{run}: binding audit {stage} failed, differs in policy or performed a mutation")
            _require(audit_summary["run_id"] == f"{run}-audit-{stage}", "AUDIT_INVALID", f"{run}: audit summary provenance")
            items.append(dict(stage=stage, ref=f"{run}-audit-{stage}", summary=audit_summary, record=audit))
        start = parse_utc_ns(workload_summary["coverage_start_utc"])
        end = start + config["planned_window_count"] * WINDOW_NS
        described = audits.describe([dict(stage=i["stage"], ref=i["ref"], summary=i["summary"]) for i in items], start, end,
                                    cadence["declared_interval_s"])
        _require(not described["problems"] and described == cadence, "AUDIT_TIMING_INVALID", f"{run}: audit capture timing does not re-derive")
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, ScientificReadRefused):
            raise
        _fail("METADATA_INVALID", f"{run}: provenance metadata is malformed ({type(exc).__name__})")
    identity = meta.get("observer_identity")
    devices = {d["device"] for d in meta["registry"]["devices"]}
    if identity == OBSERVER_IDENTITY:
        _require(allow_legacy_observer, "OBSERVER_NOT_ALLOWED", f"{run}: observed by the legacy azta-pdp subscriber; pass allow_legacy_observer "
                                                                 "explicitly (a final PDP never silently depends on it)")
        _require(devices <= LEGACY_OBSERVER_DEVICES, "OBSERVER_NOT_ALLOWED", f"{run}: the legacy subscriber cannot serve a wider registry")
    else:
        _require(isinstance(identity, str) and DEDICATED_OBSERVER.fullmatch(identity), "OBSERVER_NOT_ALLOWED", f"{run}: unknown observer identity")
    return meta, summary, objects["workload_summary"], report, items


def parse_windows(campaign, run, blob, summary):
    """Every window record of the session, validated and provenance-checked against the plan and the session. Nothing is scored here."""
    entry, spec = campaign.state["collected"][run], campaign.plan["runs"][run]
    count = spec["planned_window_count"]
    seen, windows = set(), []
    for line in blob.decode("utf-8").splitlines():
        try:
            window = json.loads(line)
            validate_window(window)
        except ValueError as exc:
            _fail("WINDOW_INVALID", f"{run}: a window record is malformed ({str(exc)[:160]})")
        device, index = window["device"], window["window"]["index"]
        _require(device in spec["devices"] and index in range(count) and (device, index) not in seen, "WINDOW_INVALID",
                 f"{run}: duplicate or foreign window")
        seen.add((device, index))
        route = spec["devices"][device]
        _require(route["profile"] in PROFILES and window["collection_run_id"] == run and window["observer_session_id"] == entry["observer_session_id"]
                 and window["purpose"] == "COLLECTION" and window["identity"]["bound_client_id"] == route["client_id"]
                 and window["identity"]["bound_username"] == route["username"] and window["identity"]["registry_sha256"] == PINS["registry_sha256"]
                 and window["identity"]["binding_audit_ref"] == f"{run}-audit-pre"
                 and window["observation_config_sha256"] == PINS["observation_config_sha256"], "WINDOW_INVALID",
                 f"{run}: window provenance differs from the plan route or the session")
        _require(window["window"]["duration_ns"] == WINDOW_NS
                 and window["window"]["start_offset_ns"] == summary["coverage_start_offset_ns"] + index * WINDOW_NS, "WINDOW_INVALID",
                 f"{run}: window geometry differs from the coverage start")
        windows.append(window)
    _require(seen == {(d, i) for d in spec["devices"] for i in range(count)}, "WINDOWS_INCOMPLETE", f"{run}: missing window records")
    windows.sort(key=lambda w: (w["window"]["index"], w["device"]))
    return tuple(windows)


def build_session(campaign, run, blobs, stages, *, allow_legacy_observer=False):
    meta, summary, workload_summary, report, items = validate_run_artifacts(campaign, run, blobs, stages,
                                                                            allow_legacy_observer=allow_legacy_observer)
    entry = campaign.state["collected"][run]
    windows = parse_windows(campaign, run, blobs["observer_windows"], summary)
    snapshots, digests = [], {}
    for item in items:
        try:
            snapshots.append(audit_snapshot_from_artifacts(item["record"], item["summary"], "BROKER_POLICY_AUDIT"))
        except ProducerRefused:
            _fail("AUDIT_INVALID", f"{run}: audit {item['stage']} has no usable pinned capture instants")
        stage = item["stage"]
        digests[f"{stage}/binding_audit.json"] = digest(blobs[f"binding_audit_{stage}"])
        digests[f"{stage}/run_summary.json"] = digest(blobs[f"binding_audit_{stage}_run_summary"])
    low, high = campaign.plan["runs"][run]["eligible_window_indices"]
    return ScientificSession(
        run_id=run, session_id=entry["observer_session_id"], partition=campaign.authorization.partition, purpose="COLLECTION",
        observer_identity=meta["observer_identity"], workload_version=WORKLOAD, eligible_window_indices=(low, high),
        coverage_start_utc=workload_summary["coverage_start_utc"], coverage_start_offset_ns=summary["coverage_start_offset_ns"],
        windows=windows, windows_sha256=digest(blobs["observer_windows"]), snapshots=tuple(snapshots), audit_digests=digests,
        collected_entry_sha256=entry["entry_sha256"], review_flags=tuple(report.get("review_flags") or ()),
        planned_window_count=campaign.plan["runs"][run]["planned_window_count"])


def read_sessions(campaign, *, allow_legacy_observer=False):
    """Read every accepted run of the authorized partition through the guarded allowlist. Returns (sessions, access report)."""
    reader = AllowlistedEvidenceReader(campaign.repo, campaign)
    sessions = []
    with reader.armed():
        for run in campaign.runs:
            blobs = {role: reader.read(item) for role, item in reader.by_run[run].items()}
            sessions.append(build_session(campaign, run, blobs, reader.stages[run], allow_legacy_observer=allow_legacy_observer))
    reader.verify_complete()
    return tuple(sessions), reader.access_report()


def preflight(repo, authorization, *, plan_rel, manifest_rel, allow_partial=False):
    """Everything that can be checked WITHOUT opening one evidence byte: authorization, manifest, plan, allocation, allowlist construction and,
    by `stat` only, that every allowlisted file exists. It reads nothing from the raw evidence root and creates nothing."""
    campaign = load_campaign(repo, authorization, plan_rel=plan_rel, manifest_rel=manifest_rel, allow_partial=allow_partial)
    reader = AllowlistedEvidenceReader(campaign.repo, campaign)
    missing = [Path(p).name for p in reader.allowed if not (Path(p).is_file() and Path(p).stat().st_size > 0)]
    _require(not missing, "ARTIFACT_MISSING", f"allowlisted input files are missing or empty: {missing[:5]}")
    return dict(ready=True, partition=authorization.partition, runs=list(campaign.runs), allowlisted_files=len(reader.allowed),
                allocation=campaign.allocation, manifest_sha256=campaign.manifest_sha256, plan_sha256=campaign.plan_sha256,
                effect="no evidence was opened; reading will open exactly the allowlisted files")
