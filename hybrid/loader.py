"""Digest-verified loading of the hybrid behaviour evaluator and its composition with the unchanged registry-authoritative pipeline.

Inputs, each named together with its SHA-256 (no default, no discovery): everything `fleet.loader.load_fleet_behavior` takes (frozen S/V models and the accepted CAL_V2 record, the registry-v2
compatibility record, the fleet models record, an optional pilot calibration record), plus ONE timing-contracts record (`configs/gate6c/timing_contracts_*.json`). Each timing profile in it carries
its contract and the SHA-256 of that contract; a record whose digest or pins differ from what is loaded is refused. A timing profile enters the engine's model catalog under the digest of its contract, so
`decision_pipeline` verifies a registry that routes a device to it exactly as it verifies a route to a trained model. The hybrid evaluator is otherwise the fleet evaluator (autoencoder profiles are
scored by the inherited code, unchanged). Rollback: not passing a timing-contracts record yields the fleet behaviour exactly.
"""
import hashlib
import json
from pathlib import Path

from fleet import loader as fleet_loader, spec
from fleet.models import FleetModelRefused
from hybrid import models as hybrid_models
from hybrid.blocks import BlockContract
from hybrid.engine import GenerationAwareEngine, HybridBehaviorEvaluator, MonitorProfileModel, TimingProfileModel
from hybrid.monitor import AeStream, MonitorSpec, STREAMS
from hybrid.timing import TimingContract

TIMING_SCHEMA = "azta.gate6c.timing_contracts"
MONITOR_SCHEMA = "azta.gate6c.monitor_profiles"
STREAM_STATES = ("ACTIVE", "ADVISORY", "ABSENT")


def load_hybrid_behavior(root, *, timing_contracts_path, timing_contracts_sha256, **fleet_arguments):
    base = fleet_loader.load_fleet_behavior(root, **fleet_arguments)
    record = fleet_loader.read_verified(timing_contracts_path, timing_contracts_sha256, "timing contracts record")
    pins_v2 = spec.v2_pins(root)
    if record.get("schema") != TIMING_SCHEMA or record.get("pins") != pins_v2:
        raise FleetModelRefused("the timing contracts record is not for the registry-v2 pins")
    v2_triple = (pins_v2["registry_sha256"], pins_v2["observation_config_sha256"], pins_v2["schema_fingerprint"])
    models, descriptors, pins, timing = dict(base.models), dict(base.provenance["models"]), dict(base.accepted_pins), {}
    pilot = base.provenance["fleet"].get("pilot_calibration")        # an approved run names ONE calibration id for every decision; the timing profiles carry it too (and its status)
    calibration_id, calibration_status = (pilot["calibration_id"], "CONTROLLER_ACCEPTED") if pilot else (record["record_id"], "PROVISIONAL_UNAPPROVED")
    for profile, item in sorted(record["profiles"].items()):
        if profile in models:
            raise FleetModelRefused(f"{profile}: a loaded profile cannot be redefined by the timing contracts record")
        model = TimingProfileModel(profile, TimingContract(**item["contract"]))
        if model.weights_sha256 != item["contract_sha256"]:
            raise FleetModelRefused(f"{profile}: the contract differs from its recorded digest")
        models[profile] = model
        descriptors[profile] = dict(model.descriptor, origin=record["status"])
        pins[profile] = (v2_triple,)
        timing[profile] = dict(model=model, calibration_id=calibration_id, calibration_status=calibration_status, advisory=tuple(item.get("advisory", ())))
    provenance = dict(base.provenance, models=descriptors, hybrid=dict(schema=TIMING_SCHEMA, record_sha256=timing_contracts_sha256, status=record["status"], profiles=sorted(timing),
                                                                      rule="HBE-1", note="timing profiles are PROVISIONAL engineering candidates; no calibration is accepted for them"))
    return HybridBehaviorEvaluator(models, base.calibrations, timing_profiles=timing, accepted_pins=pins, reserved_tokens=base.reserved, provenance=provenance)


def profile_digest(body):
    """The digest of a monitor profile definition (everything except its own `definition_sha256`)."""
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _ae_stream(root, name, item, device=None):
    if "members" in item:               # seed procedure E3 (Gate 6C core campaign): the mean of the member losses, every member digest-verified, the combined digests pinned
        model = hybrid_models.EnsembleModel.load([dict(model_dir=Path(root) / m["model_dir"], weights_sha256=m["weights_sha256"], bundle_sha256=m["bundle_sha256"]) for m in item["members"]],
                                                 expected_weights_sha256=item["weights_sha256"], expected_bundle_sha256=item["bundle_sha256"])
    else:
        directory = Path(root) / item["model_dir"]
        model = hybrid_models.CandidateModel.load(directory, expected_weights_sha256=item["weights_sha256"], expected_bundle_sha256=item["bundle_sha256"])
    if model.descriptor["contract"]["device"] != device or model.descriptor["contract"]["width_s"] != item["width_s"]:
        raise FleetModelRefused(f"{device}: the model {model.fit_id} was fitted for {model.descriptor['contract']['device']} at {model.descriptor['contract']['width_s']} s, not for this profile")
    calibration = item["calibration"]
    return AeStream(name, model, calibration["mu_L"], calibration["sigma_L"], item["width_s"], masked=tuple(item.get("masked_features", ())))


def build_monitor_spec(root, body):
    """A `MonitorSpec` from one profile body of a monitor-profiles record; every constituent model is digest-verified when loaded."""
    states = body["streams"]
    if body["tm"]["device"] != body["device"] or (body.get("block") and body["block"]["device"] != body["device"]):
        raise FleetModelRefused(f"{body['device']}: a contract of the profile belongs to another device")
    if set(states) != set(STREAMS) or any(v not in STREAM_STATES for v in states.values()):
        raise FleetModelRefused("a monitor profile must state every stream as ACTIVE, ADVISORY or ABSENT")
    for stream in ("AE_FAST", "AE_SLOW"):
        if (states[stream] == "ABSENT") != (body.get(stream.lower()) is None):
            raise FleetModelRefused(f"{stream}: the stream state and the model entry disagree")
    if (states["BLOCK"] == "ABSENT") != (body.get("block") is None):
        raise FleetModelRefused("BLOCK: the stream state and the contract entry disagree")
    return MonitorSpec(body["device"], TimingContract(**body["tm"]), BlockContract(**body["block"]) if body.get("block") else None,
                       _ae_stream(root, "AE_FAST", body["ae_fast"], body["device"]) if body.get("ae_fast") else None,
                       _ae_stream(root, "AE_SLOW", body["ae_slow"], body["device"]) if body.get("ae_slow") else None,
                       tuple(sorted(name for name, state in states.items() if state == "ADVISORY")), body.get("distinct", "INTERVALS"), tuple(tuple(x) for x in body.get("maintenance", ())))


def load_monitor_behavior(root, *, monitors_path, monitors_sha256, **fleet_arguments):
    """The pre-live hybrid evaluator: everything `load_hybrid_behavior` verifies, but each listed device is scored by a per-device MONITOR PROFILE (timing + block + drift + autoencoder streams under
    HBE-2). The record names every constituent artifact with its SHA-256; a profile whose body does not hash to its `definition_sha256`, or a model that does not match its digests, is refused."""
    # An approved (enforcing) run names ONE pilot calibration record over EVERY loaded model, the monitor profiles included (the approval parses the registry against that catalog). The fleet loader
    # would require the record to name only the fleet models it loads itself, so the record is applied here, after the monitor profiles exist, against the complete set (found by the first
    # attempt to author a hybrid approval; the fleet-only behaviour is unchanged when no record is given).
    pilot_path, pilot_sha = fleet_arguments.pop("pilot_record_path", None), fleet_arguments.pop("pilot_record_sha256", None)
    base = fleet_loader.load_fleet_behavior(root, **fleet_arguments)
    record = fleet_loader.read_verified(monitors_path, monitors_sha256, "monitor profiles record")
    pins_v2 = spec.v2_pins(root)
    if record.get("schema") != MONITOR_SCHEMA or record.get("pins") != pins_v2:
        raise FleetModelRefused("the monitor profiles record is not for the registry-v2 pins")
    v2_triple = (pins_v2["registry_sha256"], pins_v2["observation_config_sha256"], pins_v2["schema_fingerprint"])
    models, descriptors, pins, profiles = dict(base.models), dict(base.provenance["models"]), dict(base.accepted_pins), {}
    built = {}
    for profile, body in sorted(record["profiles"].items()):
        if profile in models:
            raise FleetModelRefused(f"{profile}: a loaded profile cannot be redefined by the monitor profiles record")
        declared = body.get("definition_sha256")
        content = {k: v for k, v in body.items() if k != "definition_sha256"}
        if declared != profile_digest(content):
            raise FleetModelRefused(f"{profile}: the profile definition differs from its recorded digest")
        monitor_spec = build_monitor_spec(root, content)
        model = MonitorProfileModel(profile, monitor_spec, content)
        models[profile] = model
        descriptors[profile] = dict(model.descriptor, origin=record["status"])
        pins[profile] = (v2_triple,)
        built[profile] = (model, monitor_spec)
    calibrations, pilot = dict(base.calibrations), base.provenance["fleet"].get("pilot_calibration")
    if pilot_path is not None:
        calibrations, pilot = fleet_loader._apply_pilot_record(fleet_loader.read_verified(pilot_path, pilot_sha, "fleet pilot calibration record"), calibrations, descriptors,
                                                               cal_v2_sha256=fleet_arguments["cal_v2_sha256"], models_record_sha256=fleet_arguments["models_record_sha256"],
                                                               compat_record_sha256=fleet_arguments.get("compat_record_sha256"))
    calibration_id, calibration_status = (pilot["calibration_id"], "CONTROLLER_ACCEPTED") if pilot else (record["record_id"], "PROVISIONAL_UNAPPROVED")
    for profile, (model, monitor_spec) in built.items():
        profiles[profile] = dict(model=model, monitor=monitor_spec, calibration_id=calibration_id, calibration_status=calibration_status, advisory=monitor_spec.advisory)
    provenance = dict(base.provenance, models=descriptors, fleet=dict(base.provenance["fleet"], pilot_calibration=pilot),
                      hybrid=dict(schema=MONITOR_SCHEMA, record_sha256=monitors_sha256, status=record["status"], profiles=sorted(profiles), rule="HBE-2",
                                  note="monitor profiles are PROVISIONAL engineering candidates; no calibration is accepted for them"))
    return HybridBehaviorEvaluator(models, calibrations, timing_profiles=profiles, accepted_pins=pins, reserved_tokens=base.reserved, provenance=provenance)


def wrap_hybrid_engine(engine, *, repo_root, registry_path, registry_sha256):
    """`fleet.loader.wrap_fleet_engine` unchanged, then the generation-aware wrapper so the silence of a restored device is never read as a missing report."""
    wrapped = fleet_loader.wrap_fleet_engine(engine, repo_root=repo_root, registry_path=registry_path, registry_sha256=registry_sha256)
    return GenerationAwareEngine(wrapped, engine.behavior)
