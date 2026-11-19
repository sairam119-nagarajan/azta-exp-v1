"""Verified, read-only loading of the frozen S/V profile models, their train-fitted scalers and the accepted Gate 5E calibration.

Nothing here fits, retrains, recalibrates or re-scores anything, and no observation evidence is opened: only the hash-pinned model
bundle and weights of the two selected candidates (Gate 5D.2b), the committed Gate 5E freeze record, and the Gate 5E calibration
record (a derived output holding mu_L and the sample sigma_L) are read, and each is verified against a digest pinned in this file or
in the committed freeze record before use. Any mismatch raises ArtifactRefused. The eight reserved calibration runs, the invalidated
run and their sessions are listed from the committed manifest (no evidence is opened) so that their windows can never be scored.

load_calibrations() needs only the standard library. load_frozen_behavior() imports torch and, as an explicit documented step, sets the
float64 / deterministic / single-thread regime the models were fitted and calibrated under, and refuses a different library set.
"""
import hashlib
import json
from pathlib import Path
import sys

from trust import calibration as calibration_records
from trust.behavior import BehaviorEvaluator, Calibration
from trust.errors import ArtifactRefused

FREEZE_REL = "configs/gate5e/calibration_freeze.json"
FREEZE_SHA256 = "a6b971dc3f94ffc14518795bde1e3eb4f6be0418dec8464e82d44bb0c264f542"
CANDIDATE_RUN = "g5d2b-20261019-01"
CALIBRATION_RUN = "g5e-20261020-01"
CALIBRATION_RECORD_REL = f"results/gate5e/{CALIBRATION_RUN}/calibration_record.json"
CALIBRATION_RECORD_SHA256 = "6abb06bced8df7434b9fcc36ef35ee605701bcd24339290a7ee1a626c2567d7d"
PROTOCOL_ID = "gate5e-calibration-protocol-v1"
PROFILES = ("S", "V")
ENV_PIN = dict(python="3.12.10", numpy="2.1.3", torch="2.5.1+cpu")
KNOWN_LIMITATIONS = (
    "S_SIGMA_L_SINGLE_WINDOW_DOMINATED: one window (g5c-r14/device01/index 60) carries 91.4% of the S squared deviation, so the accepted "
    "S sigma_L (0.025239) is about 3.4x larger than without it (Gate 5E record section 2)",
    "S_LAST_ELIGIBLE_WINDOW_ARTIFACT: the original publisher stop rule truncates window 60, raising last_delivery_age_ms and the share of "
    "9-message windows there; the accepted S calibration includes this artifact (Gate 5E addendum sections 2-4)",
    "S_COUNT9_COUNT11_UNDERFIT: Model A/S reconstructs legitimate 9-message (and less so 11-message) windows badly even away from the "
    "run edges and on its own training data (addendum section 5); these are legitimate phase effects, not intrusions",
    "V_LAST_ELIGIBLE_WINDOW_BOUNDARY_EFFECT: V shows the same truncation effect at window 60 in development data, smaller in absolute "
    "terms (addendum E10)",
    "A_SCALES_WITH_INVERSE_SIGMA_L: A divides by sigma_L, so an inflated sigma_L lowers A for every window; a lower or higher "
    "dispersion is not evidence of better or worse detection (A is monotone in L: only the loss-to-trust mapping depends on sigma_L)",
    "CALIBRATION_WINDOWS_NOT_INDEPENDENT: windows within a run share environment; mu_L and sigma_L pool 480 windows from 8 runs",
    "WORKLOAD_SYNTHETIC: S and V are synthetic seeded workloads, not physical-device behaviour; no detection claim exists",
)


def sha256_bytes(blob):
    return hashlib.sha256(blob).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _require(condition, message):
    if not condition:
        raise ArtifactRefused(message)


def _read_verified(path, expected_sha256, label):
    try:
        blob = Path(path).read_bytes()
    except OSError as exc:
        raise ArtifactRefused(f"{label}: cannot read {path} ({exc.__class__.__name__})") from exc
    digest = sha256_bytes(blob)
    _require(digest == expected_sha256, f"{label}: SHA-256 {digest} differs from the pinned {expected_sha256} "
                                        "(for committed files, check line-ending conversion)")
    return blob


def load_freeze(root):
    return json.loads(_read_verified(Path(root) / FREEZE_REL, FREEZE_SHA256, "Gate 5E freeze record").decode("utf-8"))


def load_record(root):
    return json.loads(_read_verified(Path(root) / CALIBRATION_RECORD_REL, CALIBRATION_RECORD_SHA256,
                                     "Gate 5E calibration record").decode("utf-8"))


def load_calibrations(root, record=None):
    """({profile: Calibration}, description) from the digest-pinned accepted Gate 5E calibration record."""
    freeze = load_freeze(root)
    record = record or load_record(root)
    _require(record.get("calibration_valid") is True and record.get("protocol_id") == PROTOCOL_ID
             and record.get("integrity_failures") == [] and record.get("run_id") == CALIBRATION_RUN, "calibration record is not the valid "
             "accepted run")
    _require(record["freeze"]["freeze_record_sha256"] == FREEZE_SHA256, "calibration record names a different freeze record")
    calibrations, described = {}, {}
    for profile in PROFILES:
        spec, stats = freeze["candidates"]["fits"][profile], record["statistics"][profile]
        used = record["candidates"][profile]
        _require(all(used[key] == spec[key] for key in ("fit_id", "weights_sha256", "bundle_sha256", "k", "seed")),
                 f"{profile}: calibration was made with a different candidate than the frozen one")
        _require(stats["status"] == "OK" and record["support"][profile]["score_ready"] == stats["n"], f"{profile}: calibration is not OK")
        calibrations[profile] = Calibration(profile, stats["n"], float(stats["mu_L"]), float(stats["sigma_L"]),
                                            dict(run_id=CALIBRATION_RUN, record_sha256=CALIBRATION_RECORD_SHA256),
                                            calibration_id=calibration_records.HISTORICAL_ID,
                                            workload_versions=calibration_records.HISTORICAL_WORKLOADS)
        described[profile] = dict(n_B=stats["n"], mu_L=stats["mu_L"], sigma_L=stats["sigma_L"], sd_convention="sample (denominator n-1)")
    return calibrations, dict(
        calibration_id=calibration_records.HISTORICAL_ID, workload_versions=list(calibration_records.HISTORICAL_WORKLOADS),
        run_id=CALIBRATION_RUN, record_sha256=CALIBRATION_RECORD_SHA256, protocol_id=PROTOCOL_ID,
        freeze_commit=record["freeze"]["freeze_commit"], freeze_record_sha256=FREEZE_SHA256, statistics=described,
        acceptance="reported accepted by the Main Controller in the Gate 5F assignment; the repository record predates that statement")


def check_environment():
    import numpy
    import torch
    seen = dict(python=sys.version.split()[0], numpy=numpy.__version__, torch=torch.__version__)
    _require(seen == ENV_PIN, f"environment {seen} differs from the frozen pin {ENV_PIN}")
    return seen


def load_frozen_behavior(root, *, calibration):
    """The BehaviorEvaluator over the two frozen models, one explicitly chosen calibration and the reserved-evidence refusal list.

    calibration: "gate5e-v1" (the accepted historical calibration, which describes workload v1 only) or a dict
    {"record_path": ..., "record_sha256": ...} naming a controller-accepted, separately versioned v2 calibration record (none exists yet).
    There is no default: which calibration scores the evidence is always a stated choice and is logged.
    """
    root = Path(root)
    if calibration != calibration_records.HISTORICAL_ID and not (isinstance(calibration, dict) and set(calibration) == {"record_path", "record_sha256"}):
        raise ArtifactRefused("calibration must be 'gate5e-v1' or {'record_path', 'record_sha256'}: there is no default calibration")
    from model import autoencoder as ae
    from model.inference import ProfileModel
    from preprocessing import gate5d_data as data
    ae.configure_determinism()  # float64, deterministic algorithms, one thread: the regime of fitting and calibration
    environment = check_environment()
    freeze = load_freeze(root)
    _require(freeze["candidates"]["run"] == CANDIDATE_RUN, "freeze record names a different candidate run")
    record = load_record(root)
    calibrations, calibration_info = load_calibrations(root, record)
    models, descriptors = {}, {}
    for profile in PROFILES:
        spec = freeze["candidates"]["fits"][profile]
        directory = root / "results" / "gate5d" / CANDIDATE_RUN / "fits" / spec["fit_id"]
        _read_verified(directory / "weights.json", spec["weights_sha256"], f"{profile} weights")
        bundle_bytes = _read_verified(directory / "bundle.json", spec["bundle_sha256"], f"{profile} bundle")
        bundle = json.loads(bundle_bytes.decode("utf-8"))
        _require((bundle["profile"], bundle["fit_id"], bundle["status"], bundle["k"]) == (profile, spec["fit_id"], "COMPLETED", spec["k"]),
                 f"{profile}: bundle identity differs from the frozen candidate")
        scaler_sha = sha256_bytes(canonical(bundle["scaler"]).encode("utf-8"))
        _require(scaler_sha == record["candidates"][profile]["scaler_sha256"],
                 f"{profile}: scaler differs from the one the calibration was made with")
        models[profile] = ProfileModel.load(directory)  # re-verifies weights digest, schema pins and D-ZV-2 zero weights
        _require(models[profile].profile == profile, f"{profile}: loaded model profile differs")
        descriptors[profile] = dict(fit_id=spec["fit_id"], k=spec["k"], seed=spec["seed"], weights_sha256=spec["weights_sha256"],
                                    bundle_sha256=spec["bundle_sha256"], scaler_sha256=scaler_sha, architecture=bundle["architecture"],
                                    zero_variance_features=bundle["scaler"]["zero_variance_features"], scaler_n_fit=bundle["scaler"]["n_fit"])
    campaign = data.load_campaign(root)  # verifies the committed manifest and plan pins; opens no evidence
    if calibration != calibration_records.HISTORICAL_ID:
        blob = _read_verified(calibration["record_path"], calibration["record_sha256"], "versioned calibration record")
        frozen_models = {p: {k: freeze["candidates"]["fits"][p][k] for k in ("fit_id", "weights_sha256", "bundle_sha256")} for p in PROFILES}
        pins = {k: data.PIN[k] for k in ("registry_sha256", "observation_config_sha256", "schema_fingerprint")}
        calibrations, calibration_info = calibration_records.parse_record(json.loads(blob.decode("utf-8")), frozen_models=frozen_models,
                                                                          pins=pins, reserved_tokens=campaign.reserved_tokens)
        calibration_info["record_sha256"] = calibration["record_sha256"]
    provenance = dict(models=descriptors, calibration=calibration_info, schema_pins=dict(data.PIN), environment=environment,
                      known_limitations=list(KNOWN_LIMITATIONS), reserved_token_count=len(campaign.reserved_tokens))
    return BehaviorEvaluator(models, calibrations, reserved_tokens=campaign.reserved_tokens, provenance=provenance)
