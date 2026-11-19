"""Offline, single-use CAL_V2 calibration. See docs/gate5f/GATE_5F4_CAL_V2_TOOL.md.

No collection, promotion, fitting, policy selection or historical observation access.
"""
import argparse
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

from calibration import gate5e_calibrate as baseline_tool
from experiments import collection_audits_v2 as audits
from experiments import collection_finalize_v2 as finalize
from experiments import collection_plan as plans
from experiments import collection_plan_v2 as plans_v2
from experiments import collection_workload_v2 as workload
from model import stdlib_check
from observation import manifest_v2 as manifest
from observation.registry import DeviceRegistry
from observation.schema import validate_window
from preprocessing import gate5d_data as data
from trust import artifacts, calibration
from trust.errors import ArtifactRefused
from trust.timeline import parse_utc_ns

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_REL = "docs/gate5f/GATE_5F4_CAL_V2_TOOL.md"
PROTOCOL_REVISION_REL = "docs/gate5f/GATE_5F3_CAL_V2_PROTOCOL_REVISION.md"
FREEZE_REL = "configs/gate5f4/calibration_freeze.json"
OUTPUT_REL = "results/gate5f4/cal_v2"
RAW_REL = "results/raw"
ISSUED_MARKER = "CAL_V2_ISSUED.json"
WORKLOAD = workload.GENERATOR_VERSION
PINS = {k: data.PIN[k] for k in ("registry_sha256", "observation_config_sha256", "schema_fingerprint")}
PROFILES = ("S", "V")
MIN_FREE_BYTES = 256 * 1024 * 1024


class CalibrationRefused(ValueError):
    """A refusal never releases the single-use marker or repairs evidence."""


def require(ok, message):
    if not ok:
        raise CalibrationRefused(message)


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def write_exclusive(path, value):
    """Publish complete fsync'ed bytes atomically, without replacing an existing name.

    Same-directory hard-link publication is exclusive on Windows and POSIX. A crash
    before publication leaves only a temporary file; after publication the final
    name refers to the complete file. No copy/overwrite fallback is permitted.
    """
    path = Path(path)
    blob = encoded(value)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(blob)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)  # exclusive: FileExistsError preserves any previous result/marker
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return digest(blob)


def git(repo, *args):
    result = subprocess.run(["git", *args], cwd=repo, capture_output=True, check=False)
    require(result.returncode == 0, f"Git check failed: {' '.join(args)}")
    return result.stdout


def safe_path(root, relative):
    """Exact relative paths only, no traversal, links/junctions or alternate Windows streams."""
    require(isinstance(relative, str) and relative and "\\" not in relative and ":" not in relative,
            "invalid relative path")
    parts = relative.split("/")
    require(all(p not in ("", ".", "..") for p in parts) and not Path(relative).is_absolute(), "path traversal")
    root = Path(root).absolute()
    current = root
    for part in parts:
        current /= part
        require(not current.is_symlink() and not current.is_junction(), "linked evidence/configuration path refused")
    require(current.resolve().is_relative_to(root.resolve()), "path escapes its root")
    return current


def code_files(repo):
    # Sources only. Never enumerate results, data or a scientific evidence directory.
    files = [PROTOCOL_REL, PROTOCOL_REVISION_REL, "requirements-gate5d.lock.txt"]
    for directory in ("calibration", "model", "preprocessing", "observation", "experiments", "trust"):
        files += [p.relative_to(repo).as_posix() for p in (Path(repo) / directory).rglob("*.py")]
    return sorted(files)


def freeze_content(repo):
    """Prospective tool freeze only; never creates or approves a collection manifest."""
    require(Path(repo).resolve() == ROOT.resolve(), "the executable and frozen repository must be the same checkout")
    freeze = artifacts.load_freeze(repo)  # digest-pinned historical model/scaler definitions, no observations
    return dict(schema="azta.gate5f4.calibration_freeze", schema_version=1, workload_version=WORKLOAD,
                code_sha256={p: digest(safe_path(repo, p).read_bytes()) for p in code_files(repo)},
                models=freeze["candidates"], pins=PINS, environment=baseline_tool.ENV_PIN,
                eligible_window_indices=[1, 60], records_per_device=62, sd_convention=calibration.SD_CONVENTION,
                historical_freeze_sha256=artifacts.FREEZE_SHA256)


def verify_freeze(repo, authorized_sha256):
    require(Path(repo).resolve() == ROOT.resolve(), "the executable and frozen repository must be the same checkout")
    path = safe_path(repo, FREEZE_REL)
    blob = path.read_bytes()
    require(digest(blob) == authorized_sha256, "authorization names a different tool freeze")
    require(json.loads(blob) == freeze_content(repo), "tool/protocol/model freeze differs from current bytes")
    require(not git(repo, "status", "--porcelain=v1", "-uall").strip(), "calibration requires a clean committed tree")
    require(git(repo, "ls-files", "--error-unmatch", FREEZE_REL).decode().strip() == FREEZE_REL, "untracked freeze")
    commit = git(repo, "log", "-1", "--format=%H", "--", FREEZE_REL).decode().strip()
    require(calibration.HEX40.fullmatch(commit), "tool freeze commit is missing")
    require(git(repo, "show", f"{commit}:{FREEZE_REL}") == blob, "freeze bytes are not committed")
    return dict(freeze_commit=commit, freeze_sha256=digest(blob), git_head=git(repo, "rev-parse", "HEAD").decode().strip())


def load_campaign(repo, plan_rel, manifest_rel, authorized_manifest_sha256, freeze_commit):
    """Metadata only: importantly, validate WITHOUT artifact_root (which would open every partition)."""
    require(plan_rel.startswith("configs/collection_plans/") and manifest_rel.startswith("configs/collection_manifests/"),
            "plan and manifest must be explicit repository configurations")
    plan_blob = safe_path(repo, plan_rel).read_bytes()
    manifest_blob = safe_path(repo, manifest_rel).read_bytes()
    require(digest(manifest_blob) == authorized_manifest_sha256, "authorization names a different manifest")
    plan = json.loads(plan_blob)
    entries = [json.loads(line) for line in manifest_blob.decode("utf-8").splitlines()]
    state = manifest.validate(entries)  # no evidence root
    registry = DeviceRegistry.load(safe_path(repo, "configs/observation/device_registry.json"))
    v1 = json.loads(safe_path(repo, "configs/collection_plans/gate5c_workload_v1.json").read_bytes())
    historical = data.load_campaign(repo)  # pinned configuration metadata only, never any artifact root
    historical_tokens = set(historical.plan["runs"])
    historical_tokens |= {e["observer_session_id"] for e in historical.entries if e["entry_type"] == "RUN_COLLECTED"}
    plans_v2.validate_plan_v2(plan, registry, v1_plan=v1)
    plans.check_manifest_against_plan(state, plan)
    require(plan["kind"] == "SCIENTIFIC" and plan["approval_status"] == "APPROVED" and plan["approval_ref"],
            "an explicitly controller-approved scientific v2 plan is required")
    require(state["frozen"] and not state["superseded"], "manifest must be frozen and current")
    header = state["header"]
    require(header["observation_schema_fingerprint"] == PINS["schema_fingerprint"]
            and header["registry_sha256"] == PINS["registry_sha256"]
            and header["observation_config_sha256"] == PINS["observation_config_sha256"]
            and header["window_duration_ns"] == 10_000_000_000, "manifest observation pins differ")
    require(plan["generator_version"] == WORKLOAD and plan["registry_sha256"] == PINS["registry_sha256"]
            and plan["observation_config_sha256"] == PINS["observation_config_sha256"]
            and plan["schema_fingerprint"] == PINS["schema_fingerprint"], "workload/registry/schema pins differ")
    require(plan["window_roles"] == dict(lead_in=[0, 0], eligible=[1, 60], post_roll=[61, 61])
            and plan["planned_window_count"] == 62 and plan["window_duration_ms"] == 10_000, "eligible window geometry differs")
    # Bind the manifest to exactly the supplied plan, including the approved canonical digest.
    purpose = state["header"]["purpose"]
    require(f"plan={plan_rel} " in purpose and f"plan_sha256={plans.digest(plan)} " in purpose,
            "manifest header is not bound to the supplied plan")
    cells = {c["run_id"]: c for c in plan["cells"]}
    excluded = set(state["invalidated"]) | set(state["voided"])
    runs = sorted(r for r in state["collected"] if r not in excluded and cells[r]["intended_partition"] == "CAL_V2")
    counts = Counter(cells[r]["plan"] for r in runs)
    require(dict(counts) == plan["allocation"]["CAL_V2"], "accepted CAL_V2 membership/count/balance differs from approved allocation")
    replacements, assigned = finalize._replacement_map(state, cells)  # pure manifest-only mapping; no inventory call
    originals = {r for r, c in cells.items() if c["role"] == "SCIENTIFIC" and c["intended_partition"] == "CAL_V2"}
    require(all(r in runs or any(x["original"] == r and x["substitute"] in runs for x in replacements) for r in originals),
            "a planned CAL_V2 run is missing without its preplanned replacement")
    require(all(cells[r]["role"] == "SCIENTIFIC" or assigned.get(r) in originals for r in runs), "unassigned substitute")
    for run in runs:
        record = state["collected"][run]
        require(record["session_state"] == "COMPLETE" and state["planned"][run]["scenario_designation"] == "BENIGN",
                f"{run}: incomplete or non-benign run")
        # The tool+protocol must have existed unchanged before this run's collection checkpoint.
        git(repo, "merge-base", "--is-ancestor", freeze_commit, record["collection_git_commit"])
        require(git(repo, "show", f"{record['collection_git_commit']}:{FREEZE_REL}") == safe_path(repo, FREEZE_REL).read_bytes(),
                f"{run}: collection used a different tool freeze")
    return dict(plan=plan, state=state, runs=runs, plan_sha256=plans.digest(plan), plan_file_sha256=digest(plan_blob),
                manifest_sha256=digest(manifest_blob), plan_path=plan_rel, manifest_path=manifest_rel,
                historical_tokens=historical_tokens)


def expected_artifacts(run, entry):
    """Only selected CAL_V2 windows and their validation metadata; never events, health or publisher ledgers."""
    session = entry["observer_session_id"]
    paths = {"observer_windows": f"observation/{session}/windows.jsonl",
             "observer_session_metadata": f"observation/{session}/session_metadata.json",
             "observer_session_summary": f"observation/{session}/session_summary.json",
             "workload_metadata": f"collection/{run}/workload_metadata.json",
             "workload_summary": f"collection/{run}/workload_summary.json",
             "reconciliation": f"collection/{run}/reconciliation.json"}
    roles = [a["role"] for a in entry["artifacts"]]
    require(len(roles) == len(set(roles)), f"{run}: duplicate artifact roles")
    stages = {"pre", "post"}
    for role in roles:
        if role.startswith("binding_audit_"):
            stage = role[len("binding_audit_"):].removesuffix("_run_summary")
            require(audits.STAGE.fullmatch(stage), f"{run}: invalid audit stage")
            stages.add(stage)
    for stage in stages:
        paths[f"binding_audit_{stage}"] = f"{run}-audit-{stage}/binding_audit.json"
        paths[f"binding_audit_{stage}_run_summary"] = f"{run}-audit-{stage}/run_summary.json"
    found = {a["role"]: a for a in entry["artifacts"]}
    require(set(paths) <= set(found), f"{run}: missing pinned validation metadata")
    require(all(found[k]["path"] == p for k, p in paths.items()), f"{run}: artifact path does not belong to this run/session")
    return {k: found[k] for k in paths}, ["pre", *sorted(stages - {"pre", "post"}), "post"]


class EvidenceReader:
    """Digest-verified exact allowlist plus a pre-open interpreter guard over the entire raw evidence tree."""
    def __init__(self, repo, campaign):
        self.root = safe_path(repo, RAW_REL)
        self.by_run, self.stages, self.allowed = {}, {}, {}
        self.reads, self.events, self.cache = [], [], {}
        self.active = False
        reserved = set(campaign["historical_tokens"])
        reserved |= {r for r in campaign["state"]["planned"] if r not in campaign["runs"]}
        reserved |= {e["observer_session_id"] for r, e in campaign["state"]["collected"].items() if r not in campaign["runs"]}
        for run in campaign["runs"]:
            items, stages = expected_artifacts(run, campaign["state"]["collected"][run])
            self.by_run[run], self.stages[run] = items, stages
            for artifact in items.values():
                rel = artifact["path"]
                require(not any(t in rel for t in reserved) and "g5c-" not in rel, "reserved scientific evidence path")
                path = safe_path(self.root, rel)
                require(str(path) not in self.allowed, "duplicate calibration input path")
                self.allowed[str(path)] = artifact["sha256"]

    def guard(self, event, args):
        if not self.active or event not in ("open", "os.listdir", "os.scandir", "os.remove", "os.rename", "os.mkdir", "os.rmdir"):
            return
        if event == "os.rename":
            for target in args[:2]:
                self.guard("os.remove", (target,))  # both source and destination are forbidden under raw
            return
        target = args[0]
        if not isinstance(target, (str, bytes, os.PathLike)):
            return
        path = os.path.abspath(os.fsdecode(target))
        try:
            under_raw = os.path.normcase(os.path.commonpath((self.root, path))) == os.path.normcase(str(self.root))
        except ValueError:  # another Windows drive
            under_raw = False
        if not under_raw:
            return
        self.events.append(dict(event=event, path=path))
        require(event == "open" and path in self.allowed, "interpreter guard refused non-allowlisted raw-evidence access")
        mode, flags = args[1:3]
        require((mode is None or mode in ("r", "rb")) and not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC),
                "raw evidence is read-only")

    def install(self):
        sys.addaudithook(self.guard)
        self.active = True

    def read(self, artifact):
        path = safe_path(self.root, artifact["path"])
        key = str(path)
        require(self.allowed.get(key) == artifact["sha256"], "outside CAL_V2 allowlist")
        require(key not in self.cache, "duplicate calibration input read")
        blob = path.read_bytes()
        require(digest(blob) == artifact["sha256"], f"artifact digest mismatch: {artifact['path']}")
        self.cache[key] = True
        self.reads.append(dict(path=artifact["path"], sha256=digest(blob), bytes=len(blob)))
        return blob


def validate_metadata(campaign, run, blobs, stages):
    plan, entry = campaign["plan"], campaign["state"]["collected"][run]
    config = plan["runs"][run]
    objects = {k: json.loads(v) for k, v in blobs.items() if k != "observer_windows"}
    report, meta, summary = (objects[k] for k in ("reconciliation", "observer_session_metadata", "observer_session_summary"))
    require(report["schema"] == "azta.collection.reconciliation_candidate" and report["schema_version"] == 1
            and report["verdict"] == "ACCEPT" and report["reasons"] == [] and report["campaign_stop"] is False,
            f"{run}: reconciliation not ACCEPT")
    require(report["run_id"] == run and report["observer_session_id"] == entry["observer_session_id"]
            and report["purpose"] == "COLLECTION" and report["generator_version"] == WORKLOAD
            and report["plan_kind"] == "SCIENTIFIC" and report["plan_sha256"] == campaign["plan_sha256"]
            and report["workload_config_sha256"] == plans.digest(config), f"{run}: report provenance mismatch")
    checks = {c["name"]: c["result"] for c in report["checks"]}
    required = {"windows_complete_and_replayed", "termination_complete", "manifest_plan_matches_run", "binding_audits_pass",
                "audit_capture_instants_pinned_and_cadence_as_declared", "policy_digest_unchanged"}
    require(required <= set(checks) and set(checks.values()) == {"PASS"}, f"{run}: reconciliation checks failed or missing")
    for obj in (meta, summary):
        require(obj["observer_session_id"] == entry["observer_session_id"]
                and obj["purpose"] == "COLLECTION" and obj["schema_fingerprint"] == PINS["schema_fingerprint"]
                and obj["observation_config_sha256"] == PINS["observation_config_sha256"], f"{run}: observer provenance mismatch")
    require(meta["registry_sha256"] == PINS["registry_sha256"] and meta["window_duration_ns"] == 10_000_000_000
            and meta["window_count"] == 62 and summary["state"] == "COMPLETE" and summary["failure_code"] is None
            and summary["invariants"] and all(summary["invariants"].values()), f"{run}: observer not complete/compatible")
    require(meta["collection_run_id"] == run, f"{run}: observer run mismatch")
    require(summary["artifact_sha256"]["windows.jsonl"] == digest(blobs["observer_windows"]),
            f"{run}: window digest differs from observer summary")
    att = meta["collection_attestation"]
    require(att["git_commit"] == entry["collection_git_commit"] and meta["runtime"]["git_state"] == "clean"
            and meta["runtime"]["git_commit"] == entry["collection_git_commit"]
            and att["planned_entry_sha256"] == entry["planned_entry_sha256"]
            and att["manifest_sha256"] == entry["manifest_sha256_at_collection"], f"{run}: collection attestation mismatch")
    for key in ("workload_metadata", "workload_summary"):
        obj = objects[key]
        require(obj["generator_version"] == WORKLOAD and obj["workload_config_sha256"] == plans.digest(config)
                and obj["run_id"] == run and obj["purpose"] == "COLLECTION"
                and obj["attestation"] == att
                and obj["devices"] == {d: dict(profile=s["profile"], username=s["username"], client_id=s["client_id"],
                    telemetry_topic=s["telemetry_topic"], planned_messages=obj["devices"][d]["planned_messages"])
                    for d, s in config["devices"].items()},
                f"{run}: workload provenance mismatch")
    require(objects["workload_summary"]["state"] == "COMPLETE" and objects["workload_summary"]["failure_code"] is None
            and objects["workload_summary"]["observer_session_id"] == entry["observer_session_id"],
            f"{run}: workload incomplete")
    cadence = report["audit_cadence"]
    require(not cadence["problems"] and [r["stage"] for r in cadence["stages"]] == stages, f"{run}: cadence/stage mismatch")
    snapshots = []
    for stage in stages:
        audit, audit_summary = objects[f"binding_audit_{stage}"], objects[f"binding_audit_{stage}_run_summary"]
        require(audit["verdict"] == "PASS" and audit["registry_sha256"] == PINS["registry_sha256"]
                and audit["policy_sha256"] == entry["binding_audit_pre"]["policy_sha256"]
                and audit.get("mutation_performed") is False, f"{run}: binding audit mismatch")
        require(audit_summary["run_id"] == f"{run}-audit-{stage}", f"{run}: audit summary provenance")
        snapshots.append(dict(stage=stage, ref=f"{run}-audit-{stage}", summary=audit_summary))
    # Re-evaluate capture timing from pinned summaries, without discovering/opening health or other runs.
    # The accepted reconciliation checked this publisher/observer clock mapping; the summary is digest pinned.
    start = parse_utc_ns(objects["workload_summary"]["coverage_start_utc"])
    end = start + 62 * 10_000_000_000
    described = audits.describe(snapshots, start, end, cadence["declared_interval_s"])
    require(not described["problems"] and described == cadence, f"{run}: audit timing invalid")
    return meta, summary


def score_windows(campaign, run, blob, models, meta, summary):
    entry, spec = campaign["state"]["collected"][run], campaign["plan"]["runs"][run]
    seen, rows, accounting = set(), [], []
    for line in blob.decode("utf-8").splitlines():
        window = json.loads(line)
        validate_window(window)
        device, index = window["device"], window["window"]["index"]
        require(device in spec["devices"] and index in range(62) and (device, index) not in seen, f"{run}: duplicate/foreign window")
        seen.add((device, index))
        route = spec["devices"][device]
        require(route["profile"] in PROFILES and window["collection_run_id"] == run
                and window["observer_session_id"] == entry["observer_session_id"] and window["purpose"] == "COLLECTION"
                and window["identity"]["bound_client_id"] == route["client_id"]
                and window["identity"]["bound_username"] == route["username"]
                and window["identity"]["registry_sha256"] == PINS["registry_sha256"]
                and window["identity"]["binding_audit_ref"] == f"{run}-audit-pre"
                and window["observation_config_sha256"] == PINS["observation_config_sha256"], f"{run}: window provenance mismatch")
        require(window["window"]["duration_ns"] == 10_000_000_000
                and window["window"]["start_offset_ns"] == summary["coverage_start_offset_ns"] + index * 10_000_000_000,
                f"{run}: window geometry mismatch")
        profile = route["profile"]
        category, reason, vector = data.DESIGN_EXCLUDED, None, None
        if 1 <= index <= 60:
            ready, reason, vector = data.classify_window(window, profile)
            require(reason not in ("SCHEMA_MISMATCH", "NO_APPROVED_PROFILE_ROUTE"), f"{run}: incompatible eligible window")
            category = data.SCORE_READY if ready else data.NOT_SCORE_READY
            if ready:
                model, weights, bundle = models[profile]
                loss = model.score_window(window, profile)
                other = stdlib_check.loss(json.loads(weights), bundle["scaler"]["mu"], bundle["scaler"]["s"], vector)
                require(math.isfinite(loss) and loss >= 0 and math.isfinite(other)
                        and abs(loss - other) <= baseline_tool.TOLERANCES["loss_abs_plus_rel"] * max(1.0, abs(other)),
                        f"{run}: reconstruction loss verification failed")
                rows.append(dict(run=run, session_id=entry["observer_session_id"], profile=profile, device=device, index=index,
                                 loss=loss, loss_hex=loss.hex(), delivered_count=window["measures"]["delivered_count"]["value"]))
        accounting.append(dict(run=run, profile=profile, device=device, index=index, category=category, reason=reason))
    require(seen == {(d, i) for d in spec["devices"] for i in range(62)}, f"{run}: missing window records")
    return rows, accounting


def statistics_for(values):
    n = len(values)
    require(all(math.isfinite(v) and v >= 0 for v in values), "nonfinite/negative loss")
    mu = float(statistics.fmean(values)) if n else None
    sigma = float(statistics.stdev(values)) if n >= 2 else None  # journal eq. 10: n-1
    status = "INSUFFICIENT_SUPPORT" if n < 2 else "DEGENERATE_ZERO_SD" if sigma == 0 else "OK"
    require((mu is None or math.isfinite(mu)) and (sigma is None or math.isfinite(sigma)), "nonfinite calibration statistic")
    return dict(n_B=n, mu_L=mu, sigma_L=sigma, status=status)


def sensitivity(rows, runs):
    values = lambda subset: statistics_for([r["loss"] for r in subset])
    full, trimmed = values(rows), values([r for r in rows if r["index"] != 60])
    strata = {}
    for key in ("9", "10", "11", "other"):
        subset = [r["loss"] for r in rows if (str(r["delivered_count"]) if r["delivered_count"] in (9, 10, 11) else "other") == key]
        strata[key] = dict(statistics_for(subset), median_loss=float(statistics.median(subset)) if subset else None)
    return dict(per_run={run: values([r for r in rows if r["run"] == run]) for run in runs},
                leave_one_run_out={run: values([r for r in rows if r["run"] != run]) for run in runs},
                with_last_eligible=full, without_last_eligible=trimmed,
                removed_score_ready_windows=sum(r["index"] == 60 for r in rows),
                sigma_without_over_with=trimmed["sigma_L"] / full["sigma_L"]
                if trimmed["sigma_L"] is not None and full["sigma_L"] not in (None, 0) else None,
                delivered_count_strata=strata)


def preflight(repo, calibration_id, *, plan_rel, manifest_rel, authorized_manifest_sha256, authorized_freeze_sha256):
    """Everything that can be checked WITHOUT issuing the single-use marker or opening one evidence byte.

    The marker is fail-closed: once issued, an interruption consumes the allocation for good. Almost every refusal happens before it, but a
    preventable one after it (a missing or unreadable allowlisted file, an unwritable output root, no disk space) would waste the partition.
    This read-only check runs the same authorization, freeze, campaign, environment and model checks as `calibrate`, then confirms by
    `stat` only (never `open`) that every allowlisted input is a regular, non-empty file and that the output root is writable and unused.
    It creates nothing, issues no marker and offers no way to undo or bypass one.
    """
    repo = Path(repo).resolve()
    require(isinstance(calibration_id, str) and calibration.IDENTIFIER.fullmatch(calibration_id)
            and calibration_id != calibration.HISTORICAL_ID, "a new calibration identifier is required")
    freeze = verify_freeze(repo, authorized_freeze_sha256)
    campaign = load_campaign(repo, plan_rel, manifest_rel, authorized_manifest_sha256, freeze["freeze_commit"])
    environment = baseline_tool.check_environment()
    baseline_tool.load_candidates(repo / "results")
    reader = EvidenceReader(repo, campaign)
    out_root = safe_path(repo, OUTPUT_REL)
    require(not (out_root / ISSUED_MARKER).exists(), "CAL_V2 already issued/consumed; no retry or alternate calibration id is allowed")
    require(not (out_root / calibration_id).exists(), "calibration output already exists")
    ancestor = out_root
    while not ancestor.exists():
        ancestor = ancestor.parent
    require(ancestor.is_dir() and os.access(ancestor, os.W_OK), "the output location is not writable")
    free = shutil.disk_usage(ancestor).free
    require(free >= MIN_FREE_BYTES, "insufficient free disk space for the calibration outputs")
    missing = [Path(p).name for p in reader.allowed if not (Path(p).is_file() and Path(p).stat().st_size > 0)]
    require(not missing, f"allowlisted input files are missing or empty: {missing[:5]}")
    expected_windows = 60 * len(campaign["runs"])
    return dict(ready=True, runs=campaign["runs"], allowlisted_files=len(reader.allowed), eligible_windows_per_profile_before_missingness=expected_windows,
                freeze_commit=freeze["freeze_commit"], environment_ok=bool(environment), free_bytes=free,
                effect="calibrate WILL issue the single-use marker; this preflight issued none and opened no evidence")


def run_calibration(repo, calibration_id, *, plan_rel, manifest_rel, authorized_manifest_sha256, authorized_freeze_sha256):
    repo = Path(repo).resolve()
    require(isinstance(calibration_id, str) and calibration.IDENTIFIER.fullmatch(calibration_id)
            and calibration_id != calibration.HISTORICAL_ID, "a new calibration identifier is required")
    freeze = verify_freeze(repo, authorized_freeze_sha256)
    campaign = load_campaign(repo, plan_rel, manifest_rel, authorized_manifest_sha256, freeze["freeze_commit"])
    environment = baseline_tool.check_environment()
    models, descriptors = baseline_tool.load_candidates(repo / "results")
    reader = EvidenceReader(repo, campaign)
    out_root = safe_path(repo, OUTPUT_REL)
    out_root.mkdir(parents=True, exist_ok=True)
    require(not (out_root / calibration_id).exists(), "calibration output already exists")
    # One fixed marker for this partition, independent of id, manifest digest, output arguments or failure.
    try:
        marker_sha256 = write_exclusive(out_root / ISSUED_MARKER, dict(calibration_id=calibration_id, issued_utc=now(),
            freeze=freeze, manifest_sha256=campaign["manifest_sha256"], runs=campaign["runs"]))
    except FileExistsError:
        raise CalibrationRefused("CAL_V2 already issued/consumed; no retry or alternate calibration id is allowed") from None
    out = out_root / calibration_id
    out.mkdir()
    try:
        reader.install()
        rows, accounting = [], []
        for run in campaign["runs"]:
            blobs = {k: reader.read(a) for k, a in reader.by_run[run].items()}
            meta, summary = validate_metadata(campaign, run, blobs, reader.stages[run])
            scored, accounted = score_windows(campaign, run, blobs["observer_windows"], models, meta, summary)
            rows += scored
            accounting += accounted
        reader.active = False
        require({e["path"] for e in reader.events} == set(reader.allowed) and len(reader.reads) == len(reader.allowed),
                "interpreter/reader allowlist mismatch")
        stats = {p: statistics_for([r["loss"] for r in rows if r["profile"] == p]) for p in PROFILES}
        valid = all(s["status"] == "OK" for s in stats.values())
        # Exact existing engine record schema; acceptance is never written by this tool.
        record = dict(schema=calibration.RECORD_SCHEMA, schema_version=calibration.RECORD_SCHEMA_VERSION,
            calibration_id=calibration_id, status="DRAFT_UNACCEPTED" if valid else "INVALID", workload_versions=[WORKLOAD],
            partition="CAL_V2", manifest_schema_version=2,
            models={p: {k: descriptors[p][k] for k in ("fit_id", "weights_sha256", "bundle_sha256")} for p in PROFILES},
            pins=PINS, plan_sha256=campaign["plan_sha256"], manifest_sha256=campaign["manifest_sha256"],
            freeze_commit=freeze["freeze_commit"], runs=campaign["runs"], statistics=stats,
            sd_convention=calibration.SD_CONVENTION, baseline_for_comparison=calibration.HISTORICAL_ID)
        report = dict(schema="azta.gate5f4.calibration_audit", schema_version=1, calibration_id=calibration_id,
            status=record["status"], calibration_valid=valid, created_utc=now(), workload_version=WORKLOAD, pins=PINS,
            freeze=freeze, marker_sha256=marker_sha256, environment=environment, models=descriptors,
            sources={k: campaign[k] for k in ("plan_path", "manifest_path", "plan_file_sha256", "plan_sha256", "manifest_sha256")},
            source_entries={r: campaign["state"]["collected"][r]["entry_sha256"] for r in campaign["runs"]},
            sensitivity={p: sensitivity([r for r in rows if r["profile"] == p], campaign["runs"]) for p in PROFILES},
            support={p: dict(planned_eligible=60 * len(campaign["runs"]), score_ready=stats[p]["n_B"],
                missing_reasons=dict(Counter(r["reason"] for r in accounting if r["profile"] == p and r["category"] == data.NOT_SCORE_READY)))
                for p in PROFILES}, reads=reader.reads, interpreter_events=reader.events,
            limitations=["Windows within a run, co-located devices and neighbouring runs are dependent; the run is the analysis unit.",
                          "Sensitivity reports are descriptive only; no threshold, anomaly parameter, adequacy verdict or detection claim is selected.",
                          "Missing eligible windows are accounted for, never imputed or replaced by lead-in/post-roll windows."])
        files = {name: write_exclusive(out / name, value) for name, value in (
            ("calibration_record.json", record), ("audit_report.json", report), ("losses.json", rows), ("window_accounting.json", accounting))}
        write_exclusive(out / "record_manifest.json", dict(schema="azta.gate5f4.output_manifest", schema_version=1, files=files))
        return record
    except BaseException as exc:
        reader.active = False
        try:
            write_exclusive(out / "failure_record.json", dict(calibration_id=calibration_id, status="FAILED_CONSUMED", utc=now(),
                error=type(exc).__name__, message=str(exc)[:500], reads=reader.reads, interpreter_events=reader.events,
                note="Single-use marker retained. Evidence cannot be scored again."))
        except OSError as recording_error:
            exc.add_note(f"Failure record could not be published: {recording_error}. Single-use marker retained.")
        raise
    finally:
        reader.active = False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("freeze-record", "preflight", "calibrate"))
    parser.add_argument("--repo-root", default=str(ROOT))
    parser.add_argument("--calibration-id")
    parser.add_argument("--plan", dest="plan_rel")
    parser.add_argument("--manifest", dest="manifest_rel")
    parser.add_argument("--authorized-manifest-sha256")
    parser.add_argument("--authorized-freeze-sha256")
    parser.add_argument("--confirm-cal-v2-access", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.action == "freeze-record":
            path = safe_path(args.repo_root, FREEZE_REL)
            path.parent.mkdir(parents=True, exist_ok=True)
            write_exclusive(path, freeze_content(Path(args.repo_root)))
            print("CAL_V2_TOOL_FREEZE_WRITTEN", FREEZE_REL)
            return 0
        if args.action == "preflight":
            require(all((args.calibration_id, args.plan_rel, args.manifest_rel, args.authorized_manifest_sha256, args.authorized_freeze_sha256)),
                    "preflight needs the same identifier, plan, manifest and both authorized digests as calibrate")
            report = preflight(Path(args.repo_root), args.calibration_id, plan_rel=args.plan_rel, manifest_rel=args.manifest_rel,
                               authorized_manifest_sha256=args.authorized_manifest_sha256, authorized_freeze_sha256=args.authorized_freeze_sha256)
            print("CAL_V2_PREFLIGHT_OK " + json.dumps(report, sort_keys=True))
            return 0
        require(args.confirm_cal_v2_access and all((args.calibration_id, args.plan_rel, args.manifest_rel,
                args.authorized_manifest_sha256, args.authorized_freeze_sha256)), "explicit CAL_V2 access confirmation and both authorized digests required")
        record = run_calibration(Path(args.repo_root), args.calibration_id, plan_rel=args.plan_rel, manifest_rel=args.manifest_rel,
            authorized_manifest_sha256=args.authorized_manifest_sha256, authorized_freeze_sha256=args.authorized_freeze_sha256)
        print(f"CAL_V2 {record['calibration_id']} {record['status']}")
        return 0 if record["status"] == "DRAFT_UNACCEPTED" else 1
    except (ValueError, KeyError, TypeError, OSError, ArtifactRefused, baseline_tool.CalibrationRefused) as exc:
        print(f"CAL_V2_REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
