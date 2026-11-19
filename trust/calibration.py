"""Separately versioned calibration records of the frozen S/V models (journal eq. 9 and 10: mu_L and the SAMPLE sigma_L, n_B - 1).

Two calibrations can exist side by side, never merged:

  gate5e-v1   the accepted historical calibration, made on the eight consumed B_cal runs of workload v1. It stays the baseline. It
              describes workload `gate5c-workload-1` only, so it is refused for workload-v2 evidence (CALIBRATION_NOT_VALID_FOR_WORKLOAD)
              unless a named cross-workload comparison experiment says otherwise.
  <new id>    a future calibration of the SAME frozen models on the independent CAL_V2 partition of workload v2, recorded in a record of the
              schema below. It does not exist yet. No such record is created here and nothing is recalibrated; this module only defines how a
              record must look and refuses anything that is not controller-accepted, not bound to the frozen model digests and the observation
              pins, not on the CAL_V2 partition, not using the sample SD, or built from runs that are reserved (B_cal, invalidated, or any run
              the caller lists).

Accepting such a record into an engine is model promotion; that remains a controller decision outside this module.
"""
import math
import re

from trust.behavior import Calibration
from trust.errors import ArtifactRefused

RECORD_SCHEMA = "azta.gate5f3.calibration_record"
RECORD_SCHEMA_VERSION = 1
ACCEPTED_STATUSES = ("CONTROLLER_ACCEPTED",)
HISTORICAL_ID = "gate5e-v1"
HISTORICAL_WORKLOADS = ("gate5c-workload-1",)
SD_CONVENTION = "sample (denominator n-1)"
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
HEX64, HEX40 = re.compile(r"[0-9a-f]{64}\Z"), re.compile(r"[0-9a-f]{40}\Z")
_KEYS = {"schema", "schema_version", "calibration_id", "status", "workload_versions", "partition", "manifest_schema_version", "models", "pins",
         "plan_sha256", "manifest_sha256", "freeze_commit", "runs", "statistics", "sd_convention", "baseline_for_comparison"}
_MODEL_KEYS = {"fit_id", "weights_sha256", "bundle_sha256"}
_STAT_KEYS = {"n_B", "mu_L", "sigma_L", "status"}


def _require(condition, message):
    if not condition:
        raise ArtifactRefused(message)


def parse_record(data, *, frozen_models, pins, reserved_tokens):
    """Validate one v2 calibration record and return ({profile: Calibration}, description). Refuses anything that is not fully conformant.

    frozen_models: {profile: {fit_id, weights_sha256, bundle_sha256}} of the frozen candidates; pins: the observation pins;
    reserved_tokens: run and session ids that may never contribute to a calibration (consumed B_cal, invalidated runs, held-out runs).
    """
    _require(isinstance(data, dict) and set(data) == _KEYS, "calibration record: unexpected or missing fields")
    _require(data["schema"] == RECORD_SCHEMA and data["schema_version"] == RECORD_SCHEMA_VERSION, "calibration record: schema")
    cid = data["calibration_id"]
    _require(isinstance(cid, str) and IDENTIFIER.fullmatch(cid) and cid != HISTORICAL_ID, "calibration_id must be a new identifier")
    _require(data["status"] in ACCEPTED_STATUSES, f"CALIBRATION_NOT_ACCEPTED: status {data['status']!r} (a draft record is never used)")
    versions = data["workload_versions"]
    _require(isinstance(versions, list) and versions and all(isinstance(v, str) and v for v in versions)
             and not set(versions) & set(HISTORICAL_WORKLOADS), "workload_versions must name the NEW workload version(s) only")
    _require(data["partition"] == "CAL_V2" and data["manifest_schema_version"] == 2,
             "a v2 calibration must come from the CAL_V2 partition of a schema-2 manifest")
    _require(isinstance(data["models"], dict) and set(data["models"]) == set(frozen_models), "calibration record: model set")
    for profile, spec in frozen_models.items():
        got = data["models"][profile]
        _require(isinstance(got, dict) and set(got) == _MODEL_KEYS and all(got[k] == spec[k] for k in _MODEL_KEYS),
                 f"{profile}: the calibration was made with a model other than the frozen candidate")
    _require(isinstance(data["pins"], dict) and data["pins"] == dict(pins), "calibration record: observation pins differ from the frozen pins")
    for key in ("plan_sha256", "manifest_sha256"):
        _require(isinstance(data[key], str) and HEX64.fullmatch(data[key]), f"calibration record: {key}")
    _require(isinstance(data["freeze_commit"], str) and HEX40.fullmatch(data["freeze_commit"]), "calibration record: freeze_commit")
    runs = data["runs"]
    _require(isinstance(runs, list) and runs and all(isinstance(r, str) and r for r in runs) and len(set(runs)) == len(runs),
             "calibration record: run list")
    _require(not set(runs) & set(reserved_tokens), "calibration record: a reserved run (B_cal, invalidated or held out) contributes")
    _require(data["sd_convention"] == SD_CONVENTION, "the calibration must use the sample standard deviation (n-1), as journal eq. 10")
    _require(data["baseline_for_comparison"] == HISTORICAL_ID, "calibration record: the historical baseline must be named")
    calibrations, described = {}, {}
    _require(isinstance(data["statistics"], dict) and set(data["statistics"]) == set(frozen_models), "calibration record: statistics set")
    for profile, stats in data["statistics"].items():
        _require(isinstance(stats, dict) and set(stats) == _STAT_KEYS and stats["status"] == "OK", f"{profile}: calibration status")
        n, mu, sigma = stats["n_B"], stats["mu_L"], stats["sigma_L"]
        _require(type(n) is int and n >= 2 and isinstance(mu, float) and isinstance(sigma, float)
                 and math.isfinite(mu) and mu >= 0 and math.isfinite(sigma) and sigma > 0,
                 f"{profile}: n_B >= 2, finite mu_L >= 0 and sigma_L > 0 are required (degenerate calibration is refused, not repaired)")
        calibrations[profile] = Calibration(profile, n, mu, sigma, dict(calibration_id=cid, partition="CAL_V2"), calibration_id=cid,
                                            workload_versions=tuple(versions))
        described[profile] = dict(n_B=n, mu_L=mu, sigma_L=sigma, sd_convention=SD_CONVENTION)
    return calibrations, dict(calibration_id=cid, status=data["status"], workload_versions=list(versions), partition="CAL_V2",
                              freeze_commit=data["freeze_commit"], plan_sha256=data["plan_sha256"], manifest_sha256=data["manifest_sha256"],
                              runs=len(runs), statistics=described, baseline_for_comparison=HISTORICAL_ID)
