"""Gate 5F.2 evidence-bundle producer: assembles ONE decision bundle from separately typed, separately provenanced inputs.

The adapter exists so that the evidence classes the trust engine treats differently can never be confused on the way in:

  trusted observer measurement   an `ObservedWindow` (a validated Gate 5B window record + the instant it became available + run and
                                 session provenance). Features are never recomputed from message contents.
  broker-policy facts            `AuditSnapshot` records (Gate 5B read-only binding audits) with the instant each was taken. The
                                 identity evidence is derived ONLY from these; the latest snapshot not later than the decision is used.
  device / profile assignment    a `ProfileAssignment` bound to a registry and observation-configuration digest and to a trusted source
                                 (a frozen plan or a versioned assignment file). Never inferred from telemetry or payload.
  authoritative context facts    `ContextFact` records with explicit provenance and observation time (and one deterministic derivation
                                 from a versioned operating schedule).
  run / session provenance       `RunProvenance`: run, session, partition, plan and manifest digests, window-artifact digest.
  readiness and missingness      reported in annotations (never read by the engine) and visible as null sections.
  publisher claims               there is NO parameter through which a payload, a `device_id` field or any publisher assertion could
                                 enter; a publisher's claim of identity, context or profile is not representable here.

Mixing is refused early and loudly: a SYNTHETIC_FIXTURE bundle may only carry SYNTHETIC_FIXTURE provenance and a TRUSTED_OFFLINE_REPLAY
bundle may never carry it; evidence of the consumed calibration partition (B_cal) is refused unconditionally; evidence of any partition
the caller has not explicitly allowed, or whose run or session is in the reserved list, is refused. The producer opens no file, holds no
connection and invents no evidence: an input that is absent becomes a null section, which the engine treats as MISSING.
"""
from dataclasses import dataclass
from fractions import Fraction
import hashlib
import json

from observation import manifest as manifest_module
from observation import manifest_v2
from observation.schema import validate_window
from preprocessing.gate5d_data import classify_window
from trust.errors import ProducerRefused
from trust.evidence import BUNDLE_SCHEMA, BUNDLE_SCHEMA_VERSION, SYNTHETIC_PROVENANCE, parse_bundle
from trust.identity import identity_from_binding_audit
from trust.timeline import capture_interval_ns

PRODUCER_VERSION = "gate5f2-1"
ASSIGNMENT_SCHEMA = "azta.gate5f.profile_assignment"
SCHEDULE_SCHEMA = "azta.gate5f.operating_schedule"
ASSIGNMENT_SOURCES = ("FROZEN_PLAN", "VERSIONED_PROFILE_ASSIGNMENT", SYNTHETIC_PROVENANCE)
PARTITION_ROLES = tuple(dict.fromkeys((*manifest_module.PARTITIONS, *manifest_v2.PARTITIONS))) + ("FUNCTIONAL", "SYNTHETIC")
SOURCE_KINDS = ("MANIFEST_ARTIFACT", "FUNCTIONAL_ARTIFACT", "SYNTHETIC")
NEVER_PRODUCED_PARTITIONS = ("B_cal", "CAL_V2")   # calibration windows are never decision evidence
SHA256_HEX = 64


def _require(condition, message):
    if not condition:
        raise ProducerRefused(message)


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RunProvenance:
    collection_run_id: str
    observer_session_id: str
    partition: str
    source_kind: str
    eligible_window_indices: tuple
    workload_version: str
    plan_sha256: object = None
    manifest_sha256: object = None
    windows_artifact_sha256: object = None

    def __post_init__(self):
        _require(self.partition in PARTITION_ROLES, f"unknown partition role {self.partition!r}")
        _require(isinstance(self.eligible_window_indices, tuple) and len(self.eligible_window_indices) == 2
                 and all(type(v) is int and v >= 0 for v in self.eligible_window_indices)
                 and self.eligible_window_indices[0] <= self.eligible_window_indices[1],
                 "eligible_window_indices must be an explicit (first, last) pair from the plan")
        _require(self.source_kind in SOURCE_KINDS, f"unknown source kind {self.source_kind!r}")
        _require(isinstance(self.workload_version, str) and self.workload_version, "workload_version must be stated (from the plan generator)")
        if self.source_kind == "FUNCTIONAL_ARTIFACT":   # real broker observation of a FUNCTIONAL_TEST run: no manifest, no scientific partition
            _require(self.partition == "FUNCTIONAL", "functional evidence can only carry the FUNCTIONAL partition role")
            for name in ("plan_sha256", "windows_artifact_sha256"):
                value = getattr(self, name)
                _require(isinstance(value, str) and len(value) == SHA256_HEX, f"FUNCTIONAL_ARTIFACT provenance needs {name}")
            _require(self.manifest_sha256 is None, "a functional run has no collection manifest")
        elif self.source_kind == "MANIFEST_ARTIFACT":   # real replays must be traceable to a committed manifest and a verified artifact
            _require(self.partition not in ("SYNTHETIC", "FUNCTIONAL"), "a manifest artifact cannot carry the SYNTHETIC or FUNCTIONAL partition role")
            for name in ("plan_sha256", "manifest_sha256", "windows_artifact_sha256"):
                value = getattr(self, name)
                _require(isinstance(value, str) and len(value) == SHA256_HEX, f"MANIFEST_ARTIFACT provenance needs {name}")
        else:
            _require(self.partition == "SYNTHETIC", "a synthetic source can only carry the SYNTHETIC partition role")


@dataclass(frozen=True)
class ObservedWindow:
    window: dict
    available_ns: int
    run: RunProvenance


@dataclass(frozen=True)
class AuditSnapshot:
    """One read-only audit. `observed_ns` is the capture START (age is measured from it: the conservative instant); `completed_ns` is the
    capture END (None for a point-in-time synthetic snapshot). A snapshot is usable for a decision only once it has completed."""
    record: dict
    observed_ns: int
    provenance: str
    completed_ns: object = None


@dataclass(frozen=True)
class ContextFact:
    criterion_id: str
    conformity: object
    provenance: str
    observed_ns: int
    source_ref: object = None


@dataclass(frozen=True)
class ProfileAssignment:
    """Device-to-profile routes bound to one registry/configuration. `runs` maps run id -> {device: profile}; `devices` is the global map."""
    version: int
    registry_sha256: str
    observation_config_sha256: str
    source: str
    devices: dict
    runs: dict

    def lookup(self, run_id, device):
        return self.runs.get(run_id, {}).get(device, self.devices.get(device))

    def sha256(self):
        return _digest(dict(schema=ASSIGNMENT_SCHEMA, version=self.version, registry_sha256=self.registry_sha256,
                            observation_config_sha256=self.observation_config_sha256, source=self.source,
                            devices=self.devices, runs=self.runs))


def parse_profile_assignment(data):
    _require(isinstance(data, dict) and set(data) == {"schema", "version", "registry_sha256", "observation_config_sha256", "source",
                                                      "devices", "runs"}, "assignment: unexpected or missing fields")
    _require(data["schema"] == ASSIGNMENT_SCHEMA and type(data["version"]) is int and data["version"] >= 1, "assignment: schema/version")
    _require(data["source"] in ASSIGNMENT_SOURCES, f"assignment source must be one of {ASSIGNMENT_SOURCES}")
    for key in ("registry_sha256", "observation_config_sha256"):
        _require(isinstance(data[key], str) and len(data[key]) == SHA256_HEX, f"assignment: {key}")
    _require(isinstance(data["devices"], dict) and isinstance(data["runs"], dict), "assignment: devices/runs must be objects")
    for mapping in (data["devices"], *data["runs"].values()):
        _require(isinstance(mapping, dict) and all(isinstance(k, str) and isinstance(v, str) and v for k, v in mapping.items()),
                 "assignment: device -> profile map")
    return ProfileAssignment(data["version"], data["registry_sha256"], data["observation_config_sha256"], data["source"],
                             dict(data["devices"]), {run: dict(m) for run, m in data["runs"].items()})


def profile_assignment_from_plan(plan, *, version=1):
    """Routes read from a committed collection plan (Gate 5C v1 or the v2 candidate plan): trusted source FROZEN_PLAN."""
    _require(isinstance(plan, dict) and "runs" in plan, "not a collection plan")
    runs = {run: {device: spec["profile"] for device, spec in config["devices"].items()} for run, config in plan["runs"].items()}
    return ProfileAssignment(version, plan["registry_sha256"], plan["observation_config_sha256"], "FROZEN_PLAN", {}, runs)


def operating_schedule_fact(schedule, window, *, coverage_start_offset_ns, observed_ns, source_ref=None):
    """Conformity of one window to a versioned operating schedule: the share of the window inside a permitted interval (exact).

    `schedule` = {schema, version, basis "COVERAGE_RELATIVE_NS", permitted_intervals_ns: [[start, end), ...] (non-overlapping)}, with times
    measured from the observer's coverage start. The window's own start and end offsets (observer monotonic clock) less the session's
    `coverage_start_offset_ns` are the only time input: nothing comes from a payload or from the device.
    1 means wholly inside a permitted interval, 0 wholly outside; intermediate values are allowed by the journal for a window that
    straddles a boundary. The result carries provenance VERSIONED_CONFIGURATION.
    """
    _require(isinstance(schedule, dict) and schedule.get("schema") == SCHEDULE_SCHEMA and schedule.get("basis") == "COVERAGE_RELATIVE_NS",
             "operating schedule: schema/basis")
    intervals = schedule.get("permitted_intervals_ns")
    _require(isinstance(intervals, list) and all(type(a) is int and type(b) is int and 0 <= a < b for a, b in intervals)
             and all(x[1] <= y[0] for x, y in zip(sorted(intervals), sorted(intervals)[1:])), "operating schedule: intervals")
    _require(type(coverage_start_offset_ns) is int, "coverage_start_offset_ns must be the session's recorded coverage start")
    start = window["window"]["start_offset_ns"] - coverage_start_offset_ns
    end = window["window"]["end_offset_ns"] - coverage_start_offset_ns
    inside = sum(max(0, min(end, b) - max(start, a)) for a, b in intervals)
    share = Fraction(inside, end - start)
    return ContextFact("operating_time", float(share), "VERSIONED_CONFIGURATION", observed_ns,
                       source_ref or f"operating_schedule:v{schedule.get('version')}:{_digest(schedule)}")


def audit_snapshot_from_artifacts(record, run_summary, provenance):
    """An `AuditSnapshot` whose capture instants come from the audit's own pinned run summary; refused if the summary has none."""
    capture = capture_interval_ns(run_summary)
    _require(capture is not None, "the audit run summary is missing, incomplete or has no capture instants (utc_start/utc_end)")
    return AuditSnapshot(record, capture[0], provenance, capture[1])


def select_audit(audits, decision_ns):
    """The latest authoritative audit snapshot taken NOT LATER than the decision (never one from the future), or None."""
    usable = [a for a in audits if (a.completed_ns if a.completed_ns is not None else a.observed_ns) <= decision_ns]
    return max(usable, key=lambda a: a.observed_ns) if usable else None


def _check_provenance_labels(mode, labels):
    for label in labels:
        if mode == "SYNTHETIC_FIXTURE":
            _require(label == SYNTHETIC_PROVENANCE, f"mixed provenance: {label!r} in a SYNTHETIC_FIXTURE bundle")
        else:
            _require(label != SYNTHETIC_PROVENANCE, "mixed provenance: SYNTHETIC_FIXTURE evidence in a TRUSTED_OFFLINE_REPLAY bundle")


def build_bundle(*, evidence_id, evidence_mode, clock_basis, decision_ns, observation, audits, assignment, context_facts,
                 allowed_partitions, reserved_tokens):
    """One validated evidence bundle (a dict accepted by `parse_bundle`) plus a producer report. Nothing here reads a file or a payload."""
    _require(evidence_mode in ("SYNTHETIC_FIXTURE", "TRUSTED_OFFLINE_REPLAY"), "unknown evidence mode")
    _require(all(p in PARTITION_ROLES for p in allowed_partitions), "allowed_partitions names an unknown partition role")
    _require(not set(allowed_partitions) & set(NEVER_PRODUCED_PARTITIONS),
             "the consumed calibration partition B_cal can never be allowed")
    reserved = frozenset(reserved_tokens)
    missing, labels, sections = [], [], dict(identity=None, behavior=None, context=None)
    annotations = dict(producer=dict(version=PRODUCER_VERSION))
    window = run = None

    # ---- trusted observer measurement, run/session provenance, profile route ---------------------------------------------------
    if observation is None:
        missing.append("OBSERVER_WINDOW_NOT_SUPPLIED")
    else:
        window, run = observation.window, observation.run
        validate_window(window)                     # a malformed record is refused, never repaired
        _require(run.partition not in NEVER_PRODUCED_PARTITIONS, "evidence of the consumed calibration partition B_cal is refused")
        _require(run.partition in allowed_partitions, f"partition {run.partition} is not allowed for this bundle")
        _require(window["collection_run_id"] == run.collection_run_id and window["observer_session_id"] == run.observer_session_id,
                 "window run/session differ from the stated run provenance")
        _require(run.collection_run_id not in reserved and run.observer_session_id not in reserved,
                 "the run or session is in the reserved list for this stage")
        low, high = run.eligible_window_indices
        _require(low <= window["window"]["index"] <= high,
                 f"DESIGN_EXCLUDED_WINDOW: window {window['window']['index']} lies outside the plan's eligible range [{low}, {high}] "
                 "(lead-in and post-roll windows are never scored)")
        annotations["eligible_window_indices"] = [low, high]
        _require((evidence_mode == "SYNTHETIC_FIXTURE") == (run.source_kind == "SYNTHETIC"),
                 "evidence mode and run source kind disagree (synthetic fixtures and manifest artifacts must not be mixed)")
        _require(type(observation.available_ns) is int and observation.available_ns >= 0, "window available_ns")
        if assignment is None:
            missing.append("PROFILE_ASSIGNMENT_NOT_SUPPLIED")
            sections["behavior"] = dict(window=window, bound_profile=None, route_provenance="ABSENT",
                                        observed_ns=observation.available_ns, workload_version=run.workload_version)
        else:
            _require(assignment.registry_sha256 == window["identity"]["registry_sha256"]
                     and assignment.observation_config_sha256 == window["observation_config_sha256"],
                     "ASSIGNMENT_REGISTRY_MISMATCH: the profile assignment was made for a different registry or observation "
                     "configuration than this window; no route is carried across registries")
            labels.append(assignment.source)
            sections["behavior"] = dict(window=window, bound_profile=assignment.lookup(run.collection_run_id, window["device"]),
                                        route_provenance=assignment.source, observed_ns=observation.available_ns,
                                        workload_version=run.workload_version)
        ready, reason, _ = classify_window(window, sections["behavior"]["bound_profile"])
        annotations["producer"].update(run_provenance=dict(
            collection_run_id=run.collection_run_id, observer_session_id=run.observer_session_id, partition=run.partition,
            source_kind=run.source_kind, workload_version=run.workload_version, plan_sha256=run.plan_sha256, manifest_sha256=run.manifest_sha256,
            windows_artifact_sha256=run.windows_artifact_sha256),
            readiness=dict(window_ready=bool(ready), reason=reason, note="informational; the engine decides readiness itself"),
            assignment_sha256=assignment.sha256() if assignment else None)

    # ---- broker-policy facts -> identity evidence ----------------------------------------------------------------------------------
    if window is None:
        missing.append("IDENTITY_NOT_DERIVABLE_WITHOUT_AN_OBSERVER_WINDOW")
    else:
        snapshot = select_audit(audits, decision_ns)
        if snapshot is None:
            missing.append("NO_AUDIT_SNAPSHOT_AT_OR_BEFORE_THE_DECISION")
        else:
            labels.append(snapshot.provenance)
            identity = identity_from_binding_audit(
                snapshot.record, window["device"], bound_client_id=window["identity"]["bound_client_id"],
                observed_ns=snapshot.observed_ns, provenance=snapshot.provenance,
                registry_sha256=window["identity"]["registry_sha256"])
            if identity["bound_username"] is not None:
                _require(identity["bound_username"] == window["identity"]["bound_username"],
                         "IDENTITY_BINDING_DISAGREES: the audited principal differs from the observer-bound principal")
            sections["identity"] = identity
            annotations["producer"]["audit_selected"] = dict(observed_ns=snapshot.observed_ns,
                                                             policy_sha256=snapshot.record.get("policy_sha256"))

    # ---- authoritative context facts ---------------------------------------------------------------------------------------------
    if context_facts:
        seen = set()
        criteria = []
        for fact in context_facts:
            _require(fact.criterion_id not in seen, f"duplicate context fact {fact.criterion_id!r}")
            seen.add(fact.criterion_id)
            labels.append(fact.provenance)
            criteria.append(dict(criterion_id=fact.criterion_id, conformity=fact.conformity, provenance=fact.provenance,
                                 observed_ns=fact.observed_ns, source_ref=fact.source_ref))
        sections["context"] = dict(criteria=criteria)
    else:
        missing.append("NO_CONTEXT_FACTS_SUPPLIED")

    _check_provenance_labels(evidence_mode, labels)
    annotations["producer"]["missing_inputs"] = missing
    bundle = dict(schema=BUNDLE_SCHEMA, schema_version=BUNDLE_SCHEMA_VERSION, evidence_id=evidence_id, evidence_mode=evidence_mode,
                  clock_basis=clock_basis, decision_ns=decision_ns, annotations=annotations, **sections)
    parse_bundle(bundle)   # the produced bundle must satisfy the engine's own structural contract
    return bundle, dict(missing_inputs=missing, labels=sorted(set(labels)))
