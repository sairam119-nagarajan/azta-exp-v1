"""Gate 5D.2 data access, trusted profile routing and readiness (freeze document sections 2-4, 6, 10).

Reads only accepted Gate 5C B_train/B_val evidence. Every evidence read goes through EvidenceReader, which
allows only the digest-pinned artifacts of accepted B_train/B_val runs, verifies each digest and logs the read.
B_cal, invalidated and unaccepted evidence is refused and is never opened. Nothing here fits, scores or trains.
"""
from collections import Counter, namedtuple
import hashlib
import json
from pathlib import Path

from observation import manifest as obs_manifest
from observation.schema import PREDICTOR_CANDIDATES, SCHEMA_FINGERPRINT, candidate_vector, validate_window

FEATURES = PREDICTOR_CANDIDATES
PROFILES = ("S", "V")
TRAINING_PARTITIONS = ("B_train", "B_val")
RESERVED_PARTITION = "B_cal"

MANIFEST_REL = "configs/collection_manifests/gate5c_main.jsonl"
PLAN_REL = "configs/collection_plans/gate5c_workload_v1.json"
PIN = dict(
    manifest_sha256="a1c0efd8dd3a3c4ab4414f87f4ae5cb366711f3e9414e01501f26840a9f2f979",
    plan_sha256="f72a61234222e27724eccede375cdc9d08270e021319b836514940ff174ce26d",
    schema_fingerprint="2dede5d8bd97c8ee1ffe0fda5afd78b020f455aad9208f6b4a75bdbca028767c",
    observation_config_sha256="ca2bebaa171c039b98f96a877de83ab8a7c916dbeb7d22901d031eaa73d0aa27",
    registry_sha256="bd3d9308adc0f43bb87a6a51bbad82bf7de4d241fc1ac65371baf25e9e1e0157",
)

# R2 reason precedence (freeze document section 4).
REASON_PRECEDENCE = ("SCHEMA_MISMATCH", "NO_APPROVED_PROFILE_ROUTE", "OBSERVER_UNAVAILABLE", "NO_MESSAGES",
                     "INSUFFICIENT_MESSAGES", "NEVER_OBSERVED_IN_SESSION")
SCORE_READY, NOT_SCORE_READY, DESIGN_EXCLUDED = "SCORE_READY", "NOT_SCORE_READY", "DESIGN_EXCLUDED"

RunInfo = namedtuple("RunInfo", "run plan_letter session_id artifacts planned_entry_sha256 collected_entry_sha256")
Campaign = namedtuple("Campaign", "manifest_sha256 plan_sha256 entries plan accepted invalidated reserved_tokens "
                                  "routes cross_checks")
WindowRecord = namedtuple("WindowRecord", "run partition profile device index category reason vector")


class DataContractError(ValueError):
    """Evidence or configuration violates the accepted contract; stop and report."""


class PartitionRefused(PermissionError):
    """An evidence read or partition outside the Gate 5D training scope was refused (and logged)."""


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _require(condition, message):
    if not condition:
        raise DataContractError(message)


def route_for(campaign, run, device):
    """Trusted profile: the frozen Gate 5C plan only, never payload, ledger or telemetry inference."""
    return campaign.routes[run][device]


def load_campaign(repo_root):
    """Verify the pinned manifest and plan and derive accepted runs and trusted routes. Opens no evidence."""
    root = Path(repo_root)
    manifest_bytes = (root / MANIFEST_REL).read_bytes()
    plan_bytes = (root / PLAN_REL).read_bytes()
    _require(sha256_bytes(manifest_bytes) == PIN["manifest_sha256"], "manifest SHA-256 differs from the frozen pin")
    _require(sha256_bytes(plan_bytes) == PIN["plan_sha256"], "plan SHA-256 differs from the frozen pin")
    _require(SCHEMA_FINGERPRINT == PIN["schema_fingerprint"], "observation schema fingerprint differs from the pin")
    entries = [json.loads(line) for line in manifest_bytes.decode("utf-8").splitlines() if line.strip()]
    try:
        obs_manifest.validate(entries)  # hash chain and rules only; no artifact_root, so no evidence is opened
    except obs_manifest.ManifestError as exc:
        raise DataContractError(f"manifest validation failed: {exc}") from exc
    plan = json.loads(plan_bytes.decode("utf-8"))
    header = entries[0]
    for key, pin in (("observation_schema_fingerprint", "schema_fingerprint"),
                     ("observation_config_sha256", "observation_config_sha256"),
                     ("registry_sha256", "registry_sha256")):
        _require(header[key] == PIN[pin], f"manifest header {key} differs from the pin")
        _require(plan[pin] == PIN[pin], f"plan {pin} differs from the pin")

    planned = {e["collection_run_id"]: e for e in entries if e["entry_type"] == "RUN_PLANNED"}
    collected = {e["collection_run_id"]: e for e in entries if e["entry_type"] == "RUN_COLLECTED"}
    invalidated = {e["collection_run_id"] for e in entries if e["entry_type"] == "RUN_INVALIDATED"}
    frozen = next(e for e in entries if e["entry_type"] == "PARTITIONS_FROZEN")["assignments"]
    cells = {c["run_id"]: c for c in plan["cells"]}

    accepted = {partition: [] for partition in (*TRAINING_PARTITIONS, RESERVED_PARTITION)}
    routes, checks = {}, []
    for run in sorted(set(collected) - invalidated):
        cell, rp, entry = cells[run], planned[run], collected[run]
        letter, partition = cell["plan"], rp["intended_partition"]
        per_device = {device: plan["runs"][run]["devices"][device]["profile"] for device in ("device01", "device02")}
        ok = dict(run=run,
                  partition_matches_plan_and_freeze=(partition == cell["intended_partition"] == frozen[run]),
                  workload_profile_id=(rp["workload_profile_id"] == f"gate5c-v1-plan{letter}"),
                  workload_config_digest=(rp["workload_config_sha256"] == cell["workload_config_sha256"]),
                  routes_match_plans_table=(per_device == plan["plans"][letter]),
                  collected_references_planned=(entry["planned_entry_sha256"] == rp["entry_sha256"]))
        checks.append(ok)
        _require(all(v for k, v in ok.items() if k != "run"), f"routing cross-check failed for {run}: {ok}")
        _require(partition in accepted, f"unexpected partition {partition} for {run}")
        routes[run] = per_device
        accepted[partition].append(RunInfo(run, letter, entry["observer_session_id"], tuple(entry["artifacts"]),
                                           rp["entry_sha256"], entry["entry_sha256"]))
    for partition, runs in accepted.items():
        _require(len(runs) == sum(plan["allocation"][partition].values()),
                 f"accepted {partition} run count differs from the frozen allocation")
    reserved = {run.run for run in accepted[RESERVED_PARTITION]} | {run.session_id for run in accepted[RESERVED_PARTITION]}
    reserved |= invalidated | {collected[run]["observer_session_id"] for run in invalidated}
    return Campaign(sha256_bytes(manifest_bytes), sha256_bytes(plan_bytes), tuple(entries), plan,
                    {p: tuple(r) for p, r in accepted.items()}, tuple(sorted(invalidated)), tuple(sorted(reserved)),
                    routes, tuple(checks))


class EvidenceReader:
    """Allowlisted, digest-verifying, logging access to accepted B_train/B_val evidence only."""

    def __init__(self, results_root, campaign):
        self.root = Path(results_root)
        self.reserved = campaign.reserved_tokens
        self.allowed = {a["path"]: a["sha256"] for p in TRAINING_PARTITIONS
                        for run in campaign.accepted[p] for a in run.artifacts}
        self.reads, self.refusals = [], []

    def refuse(self, message):
        self.refusals.append(message)
        raise PartitionRefused(message)

    def read(self, rel_path):
        if any(token in rel_path for token in self.reserved):
            self.refuse(f"REFUSED reserved or unaccepted evidence (B_cal / invalidated): {rel_path}")
        if rel_path not in self.allowed:
            self.refuse(f"REFUSED path outside the accepted B_train/B_val artifact allowlist: {rel_path}")
        data = (self.root / rel_path).read_bytes()
        digest = sha256_bytes(data)
        _require(digest == self.allowed[rel_path], f"artifact digest mismatch: {rel_path}")
        self.reads.append(dict(path=rel_path, sha256=digest, bytes=len(data)))
        return data


def classify_window(window, profile):
    """R1/R2 for one window record: (ready, reason, six-float vector). Never imputes; never healthy-by-default."""
    try:
        validate_window(window)
        if window["schema_fingerprint"] != PIN["schema_fingerprint"] \
                or window["observation_config_sha256"] != PIN["observation_config_sha256"]:
            raise ValueError("pinned schema or configuration mismatch")
    except (ValueError, TypeError, KeyError, AttributeError):
        return False, "SCHEMA_MISMATCH", None
    if profile not in PROFILES:
        return False, "NO_APPROVED_PROFILE_ROUTE", None
    statuses = {window["measures"][name]["status"] for name in FEATURES}
    if window["coverage"]["state"] != "COMPLETE":
        return False, "OBSERVER_UNAVAILABLE", None
    for reason in REASON_PRECEDENCE[2:]:
        if reason in statuses:
            return False, reason, None
    values, mask = candidate_vector(window)
    if not all(mask):  # pragma: no cover - guarded by the status checks above
        return False, "SCHEMA_MISMATCH", None
    return True, None, tuple(float(v) for v in values)


def load_partition(campaign, reader, partition):
    """Window records of one accepted training partition. B_cal (and anything else) is refused and logged."""
    if partition not in TRAINING_PARTITIONS:
        reader.refuse(f"REFUSED partition {partition}: only {TRAINING_PARTITIONS} are readable in Gate 5D")
    records = []
    for run in campaign.accepted[partition]:
        raw = {a["role"]: reader.read(a["path"]) for a in run.artifacts}  # verifies every digest
        spec = campaign.plan["runs"][run.run]
        low, high = spec["eligible_window_indices"]
        seen = Counter()
        for line in raw["observer_windows"].decode("utf-8").splitlines():
            window = json.loads(line)
            device, index = window["device"], window["window"]["index"]
            _require(window["collection_run_id"] == run.run and window["observer_session_id"] == run.session_id
                     and window["purpose"] == "COLLECTION", f"{run.run}: window header differs from its manifest entry")
            _require(device in spec["devices"] and window["identity"]["bound_client_id"] == spec["devices"][device]["client_id"]
                     and window["identity"]["registry_sha256"] == PIN["registry_sha256"],
                     f"{run.run}: window device binding differs from the plan and registry")
            seen[device] += 1
            profile = route_for(campaign, run.run, device)
            if not low <= index <= high:
                records.append(WindowRecord(run.run, partition, profile, device, index, DESIGN_EXCLUDED, None, None))
                continue
            ready, reason, vector = classify_window(window, profile)
            records.append(WindowRecord(run.run, partition, profile, device, index,
                                        SCORE_READY if ready else NOT_SCORE_READY, reason, vector))
        _require(set(seen.values()) == {spec["planned_window_count"]} and set(seen) == set(spec["devices"]),
                 f"{run.run}: window record count differs from the plan")
    records.sort(key=lambda r: (r.run, r.index, r.device))  # deterministic order
    return records


def account(records):
    """R4: every record counted by partition, run, profile, device and category/reason."""
    counts = Counter((r.partition, r.run, r.profile, r.device, r.category, r.reason or "") for r in records)
    return [dict(partition=p, run=run, profile=pr, device=d, category=c, reason=reason or None, count=n)
            for (p, run, pr, d, c, reason), n in sorted(counts.items())]


def summarize_accounting(records):
    """Per (partition, profile) totals used by the expected-population guard."""
    out = Counter((r.partition, r.profile, r.category) for r in records)
    return {f"{p}|{pr}|{c}": n for (p, pr, c), n in sorted(out.items())}
