"""Digest-verified loading of the fleet behavioural evaluator and its composition with the registry-authoritative pipeline.

Inputs, each named together with its SHA-256 (no default, no discovery):
  * the frozen S/V models and the accepted CAL_V2 record, loaded by the UNCHANGED `trust.artifacts.load_frozen_behavior` (their calibration is not modified);
  * the registry-v2 compatibility record (`fleet.compat`) that lets S/V score ten-device windows, or none (then S/V keep the frozen registry-v1 pins and every v2 window of
    device01/device02 is refused as SCHEMA_MISMATCH);
  * the fleet models record (`configs/gate6b/fleet_models_*.json`): per provisional profile its model digests, its calibration constants and their lineage.

`wrap_fleet_engine` then adds the registry-authoritative routing of `decision_pipeline` unchanged, with the frozen S/V catalog extended by the fleet profiles and the registry-v2 pins.
"""
import dataclasses
import hashlib
import json
from pathlib import Path

from fleet import spec
from fleet.evaluator import FleetBehaviorEvaluator, FleetCalibration
from fleet.models import FleetModelRefused, FleetProfileModel
from preprocessing.gate5d_data import PIN as FROZEN_PIN

MODELS_SCHEMA = "azta.gate6b.fleet_models"
COMPAT_SCHEMA = "azta.gate6b.registry_v2_compat_record"
PILOT_SCHEMA = "azta.gate6b.fleet_pilot_calibration"
FROZEN_PROFILES = ("S", "V")


def read_verified(path, sha256, label):
    blob = Path(path).read_bytes()
    if hashlib.sha256(blob).hexdigest() != sha256:
        raise FleetModelRefused(f"{label}: SHA-256 differs from the pinned {sha256}")
    return json.loads(blob.decode("utf-8"))


def _apply_pilot_record(record, calibrations, descriptors, *, cal_v2_sha256, models_record_sha256, compat_record_sha256):
    """The guard authorizes a decision only if its behaviour block carries the ONE calibration id the approval names. A pilot record (authored only under an explicit authorization) is that
    single id over the constituent calibrations: the frozen S/V constants (CAL_V2, unchanged) and the provisional profile constants. It must name exactly the loaded models and the pinned
    constituent artifacts; the constants themselves are never taken from it, so it can neither alter nor repair a calibration."""
    if record.get("schema") != PILOT_SCHEMA or record.get("status") != "CONTROLLER_ACCEPTED" or not isinstance(record.get("calibration_id"), str) or not record["calibration_id"]:
        raise FleetModelRefused("the pilot calibration record has the wrong schema, status or identifier")
    if not (isinstance(record.get("acceptance_ref"), str) and record["acceptance_ref"]) or record.get("acceptance_scope") != "PILOT_ONLY_PROVISIONAL_PROFILES":
        raise FleetModelRefused("the pilot calibration record must carry its acceptance reference and the PILOT_ONLY_PROVISIONAL_PROFILES scope")
    models = record.get("models")
    expected = {profile: (d["fit_id"], d["weights_sha256"]) for profile, d in descriptors.items()}
    if not isinstance(models, dict) or {p: (m.get("model_id"), m.get("weights_sha256")) for p, m in models.items()} != expected:
        raise FleetModelRefused("the pilot calibration record does not name exactly the loaded models")
    constituents = record.get("constituents")
    if not isinstance(constituents, dict) or constituents.get("cal_v2_sha256") != cal_v2_sha256 or constituents.get("models_record_sha256") != models_record_sha256             or constituents.get("compat_record_sha256") != compat_record_sha256:
        raise FleetModelRefused("the pilot calibration record names other constituent artifacts than the ones loaded")
    unified = {}
    for profile, c in calibrations.items():
        unified[profile] = dataclasses.replace(c, calibration_id=record["calibration_id"], status="CONTROLLER_ACCEPTED",
                                               source=dict(c.source, constituent_calibration_id=c.calibration_id, constituent_status=c.status, pilot_calibration_id=record["calibration_id"]))
    return unified, dict(calibration_id=record["calibration_id"], acceptance_ref=record["acceptance_ref"], acceptance_scope=record["acceptance_scope"])


def load_fleet_behavior(root, *, cal_v2_path, cal_v2_sha256, models_record_path, models_record_sha256, compat_record_path=None, compat_record_sha256=None,
                        pilot_record_path=None, pilot_record_sha256=None):
    from trust import artifacts
    root = Path(root)
    base = artifacts.load_frozen_behavior(root, calibration=dict(record_path=str(cal_v2_path), record_sha256=cal_v2_sha256))
    pins_v2 = spec.v2_pins(root)
    v2_triple = (pins_v2["registry_sha256"], pins_v2["observation_config_sha256"], pins_v2["schema_fingerprint"])
    v1_triple = (FROZEN_PIN["registry_sha256"], FROZEN_PIN["observation_config_sha256"], FROZEN_PIN["schema_fingerprint"])
    record = read_verified(models_record_path, models_record_sha256, "fleet models record")
    if record.get("schema") != MODELS_SCHEMA or record.get("pins") != pins_v2:
        raise FleetModelRefused("the fleet models record is not for the registry-v2 pins")
    compat = None
    if compat_record_path is not None:
        compat = read_verified(compat_record_path, compat_record_sha256, "registry-v2 compatibility record")
        if compat.get("schema") != COMPAT_SCHEMA or compat.get("v2_pins") != pins_v2 or compat.get("v1_pins") != dict(
                registry_sha256=FROZEN_PIN["registry_sha256"], observation_config_sha256=FROZEN_PIN["observation_config_sha256"], schema_fingerprint=FROZEN_PIN["schema_fingerprint"]):
            raise FleetModelRefused("the compatibility record does not describe these pins")
        if compat.get("facts_hold") is not True:
            raise FleetModelRefused("the compatibility record states that its facts do NOT hold")
    models, calibrations, descriptors, pins = dict(base.models), {}, dict(base.provenance["models"]), {}
    for profile in FROZEN_PROFILES:
        frozen = base.calibrations[profile]
        versions = tuple(frozen.workload_versions or ()) + ((spec.FLEET_WORKLOAD_VERSION,) if compat else ())
        calibrations[profile] = FleetCalibration(profile, frozen.n_b, frozen.mu_l, frozen.sigma_l, dict(frozen.source, fleet_compatibility_record=compat_record_sha256),
                                                 calibration_id=frozen.calibration_id, workload_versions=versions, status="CONTROLLER_ACCEPTED")
        pins[profile] = (v1_triple, v2_triple) if compat else (v1_triple,)
    for profile, item in sorted(record["profiles"].items()):
        if profile in FROZEN_PROFILES:
            raise FleetModelRefused(f"{profile}: a frozen profile cannot be redefined by the fleet record")
        model_spec = item["model"]
        directory = root / model_spec["directory"]
        loaded = FleetProfileModel.load(directory, expected_weights_sha256=model_spec["weights_sha256"], expected_bundle_sha256=model_spec["bundle_sha256"], expected_profile=profile)
        if loaded.fit_id != model_spec["fit_id"] or loaded.descriptor["schema_pins"]["observation_config_sha256"] != pins_v2["observation_config_sha256"]:
            raise FleetModelRefused(f"{profile}: model identity or pins differ from the record")
        cal = item["calibration"]
        models[profile] = loaded
        descriptors[profile] = dict(loaded.descriptor, origin=record["status"])
        calibrations[profile] = FleetCalibration(profile, cal["n_B"], float(cal["mu_L"]), float(cal["sigma_L"]), dict(record=record.get("record_id"), runs=cal["runs"]),
                                                 calibration_id=cal["calibration_id"], workload_versions=tuple(cal["workload_versions"]), status=record["status"])
        pins[profile] = (v2_triple,)
    if pilot_record_path is not None:
        calibrations, pilot = _apply_pilot_record(read_verified(pilot_record_path, pilot_record_sha256, "fleet pilot calibration record"), calibrations, descriptors,
                                                  cal_v2_sha256=cal_v2_sha256, models_record_sha256=models_record_sha256, compat_record_sha256=compat_record_sha256)
    else:
        pilot = None
    provenance = dict(base.provenance, models=descriptors, fleet=dict(schema=MODELS_SCHEMA, record_sha256=models_record_sha256, status=record["status"],
                                                                      compatibility_record_sha256=compat_record_sha256, profiles=sorted(record["profiles"]),
                                                                      sv_calibration="UNCHANGED accepted CAL_V2 record " + cal_v2_sha256[:16], pilot_calibration=pilot,
                                                                      note="provisional profiles are engineering candidates until a Controller approval record exists"))
    return FleetBehaviorEvaluator(models, calibrations, accepted_pins=pins, reserved_tokens=base.reserved, provenance=provenance)


def wrap_fleet_engine(engine, *, repo_root, registry_path, registry_sha256):
    """The unchanged registry-authoritative `IntegratedEngine`, with the frozen S/V catalog extended by the fleet profiles and the registry-v2 pins."""
    from decision_pipeline.errors import RegistryRefused
    from decision_pipeline.integrated import IntegratedEngine
    from decision_pipeline.registry import load_registry, model_catalog_from_freeze
    from trust import artifacts
    behavior = engine.behavior
    descriptors = behavior.provenance.get("models")
    if not descriptors or "fleet" not in behavior.provenance:
        raise RegistryRefused("ENGINE_WITHOUT_FLEET_MODELS", "the engine's behaviour evaluator is not a fleet evaluator")
    catalog = model_catalog_from_freeze(artifacts.load_freeze(Path(repo_root)))
    for profile, d in descriptors.items():
        if profile not in catalog:
            catalog[profile] = dict(model_id=d["fit_id"], weights_sha256=d["weights_sha256"])
    pins = spec.v2_pins(repo_root)
    registry = load_registry(registry_path, authorized_file_sha256=registry_sha256, model_catalog=catalog,
                             model_pins={k: pins[k] for k in ("registry_sha256", "observation_config_sha256")})
    return IntegratedEngine(engine, registry, models=behavior.models, descriptors=descriptors)
