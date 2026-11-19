"""Digest-verified composition of the behavioural-family models with the EXISTING hybrid evaluator, behind a versioned family-assignment record.

The record (`azta.gate6c.family_assignment`) names, per device, the arm whose networks the device uses, its stream state (ACTIVE or ADVISORY), the legacy profile it replaces (for rollback) and, for
the devices scored by a pre-live monitor profile, that profile's name. Both it and the candidates record (`azta.gate6c.p1_candidates`) are read together with their pinned SHA-256; every
weights and bundle digest, every normaliser digest and the feature contract are verified before a single model is built. `apply_family` returns a NEW evaluator and never mutates its argument:
not calling it (or discarding its result) leaves the accepted legacy behaviour exactly as it was, which is the rollback. Devices stay independent: each keeps its own normaliser, calibration and
monitor; only the learned networks are shared. A device on the plain autoencoder path (devices 01 to 04 and 10) gets a model and a calibration under the profile name `FAM-<arm>-<device>`
(the registry route must name it; nothing here edits a registry); a device on a monitor profile (05 to 09) keeps its timing, block and drift streams and receives the family stream in its
autoencoder slot, ACTIVE (counted) or ADVISORY (recorded, never counted, never confirming: hybrid rule H7). The trust engine, weights, thresholds, N = 2 and the PDP/PEP are not touched.
"""
import dataclasses
import json
from pathlib import Path

from fleet.evaluator import FleetCalibration
from fleet.loader import read_verified
from fleet.models import FleetModelRefused
from family import devices as dev, record as rec
from hybrid.engine import HybridBehaviorEvaluator, MonitorProfileModel
from hybrid.monitor import AeStream

ASSIGNMENT_SCHEMA = "azta.gate6c.family_assignment"
STATES = ("ACTIVE", "ADVISORY")
FEATURE_CONTRACTS = ("FC-6.1N", "FC-6.2R")
PER_DEVICE = "PER_DEVICE"
CANDIDATE_SCHEMAS = (rec.SCHEMA, "azta.gate6c.p2_candidates")


class FamilyRefused(FleetModelRefused):
    pass


def load_family(root, *, assignment_path, assignment_sha256, candidates_path, candidates_sha256, models_dir):
    """{device: dict(model, calibration, stream, state, arm, legacy_profile, monitor_profile)} for every device of the assignment, plus provenance. Everything is verified; nothing is built on failure."""
    assignment = read_verified(assignment_path, assignment_sha256, "family assignment record")
    candidates = read_verified(candidates_path, candidates_sha256, "family candidates record")
    if assignment.get("schema") != ASSIGNMENT_SCHEMA or candidates.get("schema") not in CANDIDATE_SCHEMAS:
        raise FamilyRefused("not a family assignment record or candidates record")
    per_device = assignment["feature_contract"] == PER_DEVICE          # Phase 2: the frequent and periodic families use different contracts; each device names its own
    if assignment["candidates_sha256"] != candidates_sha256 or not (per_device or assignment["feature_contract"] in FEATURE_CONTRACTS):
        raise FamilyRefused("the assignment names other candidates or an unknown feature contract")
    devices, by_arm = {}, {}
    for device, item in sorted(assignment["devices"].items()):
        if device not in dev.SPECS:
            raise FamilyRefused(f"{device}: not a declared device")
        arm, state = item["arm"], item["stream_state"]
        entry = candidates["arms"].get(arm)
        contract = item.get("feature_contract") if per_device else assignment["feature_contract"]
        if entry is None or contract not in FEATURE_CONTRACTS or entry["contract"] != contract:
            raise FamilyRefused(f"{device}: the arm {arm!r} is unknown or fitted under another feature contract")
        if device not in entry["members"] and device not in entry["held_out"]:
            raise FamilyRefused(f"{device}: not a member of {arm}")
        if state not in STATES or (item.get("monitor_profile") is None and state != "ACTIVE"):
            raise FamilyRefused(f"{device}: the stream state {state!r} is not allowed here (the plain autoencoder path has no advisory state)")
        if arm not in by_arm:
            by_arm[arm] = rec.load_models(root, candidates, models_dir, arm)
        model, calibration = by_arm[arm][device]
        width = dev.SPECS[device].width_s
        stream = AeStream("AE_FAST" if width == 10 else "AE_SLOW", model, calibration["mu_L"], calibration["sigma_L"], width, masked=tuple(entry["masked_features"]))
        devices[device] = dict(model=model, calibration=calibration, stream=stream, state=state, arm=arm, legacy_profile=item.get("legacy_profile"), monitor_profile=item.get("monitor_profile"),
                               calibration_id=candidates["calibration_id"])
    shared = {}
    for device, item in devices.items():
        shared.setdefault(item["arm"], []).append(device)
    for arm, members in shared.items():                  # the checkable meaning of "shared": one set of learned parameters behind several devices
        if len({devices[d]["model"].networks.weights_sha256 for d in members}) != 1 or len({id(devices[d]["model"].networks) for d in members}) != 1:
            raise FamilyRefused(f"{arm}: the devices of a family must hold the same networks")
    provenance = dict(schema=ASSIGNMENT_SCHEMA, version=assignment["version"], assignment_sha256=assignment_sha256, candidates_sha256=candidates_sha256, feature_contract=assignment["feature_contract"],
                      arms={arm: sorted(members) for arm, members in shared.items()}, status=assignment["status"],
                      note="family models are PROVISIONAL engineering candidates; no calibration is accepted for them")
    return devices, provenance


def _monitor_definition(base_definition, item, provenance):
    return dict(base_definition, family=dict(arm=item["arm"], state=item["state"], networks_weights_sha256=item["model"].networks.weights_sha256, normalizer_sha256=item["model"].normalizer.digest,
                                              calibration={k: item["calibration"][k] for k in ("n_B", "mu_L", "sigma_L")}, feature_contract=item["model"].networks.contract,
                                              assignment_sha256=provenance["assignment_sha256"], candidates_sha256=provenance["candidates_sha256"]))


def apply_family(evaluator, devices, provenance, *, plain_pins):
    """A NEW `HybridBehaviorEvaluator` in which the assigned devices use their family models. `plain_pins`: the pin triples the plain-path family profiles are scored under (the registry-v2 triple).
    The argument is never mutated; every dict it shares is copied first."""
    models, calibrations = dict(evaluator.models), dict(evaluator.calibrations)
    pins, profiles = {k: tuple(v) for k, v in evaluator.accepted_pins.items()}, {k: dict(v) for k, v in evaluator.timing_profiles.items()}
    descriptors = dict(evaluator.provenance["models"])
    for device, item in sorted(devices.items()):
        monitor_profile = item["monitor_profile"]
        if monitor_profile is None:
            profile = item["model"].profile
            if profile in models:
                raise FamilyRefused(f"{profile}: a loaded profile cannot be redefined by the family record")
            models[profile] = item["model"]
            calibrations[profile] = FleetCalibration(profile, item["calibration"]["n_B"], item["calibration"]["mu_L"], item["calibration"]["sigma_L"],
                                                     dict(source="family calibration", arm=item["arm"], device=device), calibration_id=item["calibration_id"])
            pins[profile] = tuple(tuple(p) for p in plain_pins)
            descriptors[profile] = dict(item["model"].descriptor, origin=provenance["status"])
            continue
        if monitor_profile not in profiles or "monitor" not in profiles[monitor_profile]:
            raise FamilyRefused(f"{device}: {monitor_profile} is not a monitor profile of the loaded evaluator")
        base = profiles[monitor_profile]
        spec = base["monitor"]
        if spec.device != device:
            raise FamilyRefused(f"{device}: the monitor profile {monitor_profile} belongs to {spec.device}")
        slot = "ae_fast" if item["stream"].name == "AE_FAST" else "ae_slow"
        other = "ae_slow" if slot == "ae_fast" else "ae_fast"
        advisory = tuple(sorted((set(spec.advisory) - {"AE_FAST", "AE_SLOW"}) | ({item["stream"].name} if item["state"] == "ADVISORY" else set())))
        new_spec = dataclasses.replace(spec, **{slot: item["stream"], other: None, "advisory": advisory})
        definition = _monitor_definition(base["model"].descriptor["definition"], item, provenance)
        model = MonitorProfileModel(monitor_profile, new_spec, definition)
        models[monitor_profile] = model
        descriptors[monitor_profile] = dict(model.descriptor, origin=provenance["status"])
        profiles[monitor_profile] = dict(base, model=model, monitor=new_spec, advisory=new_spec.advisory)
    provenance_all = dict(evaluator.provenance, models=descriptors, family=provenance)
    out = HybridBehaviorEvaluator(models, calibrations, timing_profiles=profiles, accepted_pins=pins, reserved_tokens=evaluator.reserved, provenance=provenance_all,
                                  cross_workload_experiment_id=evaluator.cross_workload_experiment_id)
    return out


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))
