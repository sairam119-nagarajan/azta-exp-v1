"""Digest-verified loading of the AE_PRIMARY_AUTHORITY_V1 evaluator from its route record (`configs/core_final/route_ae_primary_v1.json`).

The route record names every input with its SHA-256; each constituent loader then verifies its own model and calibration digests (frozen S/V models and CAL_V2 through `trust.artifacts`, the Campaign 2 records
through `fleet.loader` and `hybrid.loader`, the family candidates through `family.loader`). Any mismatch refuses the whole load; nothing is built on failure and nothing falls back to another route.
`wrap` adds the unchanged registry-authoritative routing and generation awareness. Rollback: do not use this module; the Campaign 2 evaluator (`hybrid.loader.load_monitor_behavior`) is untouched.
"""
import dataclasses
import hashlib
import json
from pathlib import Path

from core_runtime import CONTRACT
from core_runtime.primary import PrimaryAeEvaluator
from family import devices as dev, loader as family_loader
from fleet import loader as fleet_loader, spec
from fleet.models import FleetModelRefused
from hybrid import loader as hybrid_loader

ROUTE_SCHEMA = "azta.core.route"
BUNDLE_SCHEMA = "azta.core.calibration_bundle"
INPUTS = ("cal_v2", "fleet_models", "compat", "monitors", "candidates", "family_assignment")
MODELS_FALLBACK = "results/engineering/gate6c/p1/models/p1-train-01"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_route(root, route_path, route_sha256):
    route = fleet_loader.read_verified(route_path, route_sha256, "route record")
    if route.get("schema") != ROUTE_SCHEMA or route.get("contract") != CONTRACT or set(route.get("devices", {})) != set(dev.DEVICES):
        raise FleetModelRefused("not an AE_PRIMARY_AUTHORITY_V1 route over the ten devices")
    if set(route.get("inputs", {})) != set(INPUTS):
        raise FleetModelRefused("the route record must name exactly its inputs")
    for name, item in route["inputs"].items():
        if sha(Path(root) / item["path"]) != item["sha256"]:
            raise FleetModelRefused(f"route input {name}: SHA-256 differs from the pinned one")
    return route


def apply_calibration_bundle(evaluator, bundle_path, bundle_sha256):
    """An ACCEPTED bundle (status CONTROLLER_ACCEPTED, set only by the owner or Controller) gives the ONE calibration id the guard requires. It names the loaded models and never carries constants."""
    record = fleet_loader.read_verified(bundle_path, bundle_sha256, "calibration bundle")
    if record.get("schema") != BUNDLE_SCHEMA or record.get("status") != "CONTROLLER_ACCEPTED" or not record.get("calibration_id") or not record.get("acceptance_ref"):
        raise FleetModelRefused("the calibration bundle is not an accepted bundle")
    expected = {p: (d["fit_id"], d["weights_sha256"]) for p, d in evaluator.provenance["models"].items()}
    if {p: (m.get("model_id"), m.get("weights_sha256")) for p, m in record.get("models", {}).items()} != expected:
        raise FleetModelRefused("the calibration bundle does not name exactly the loaded models")
    identifier = record["calibration_id"]
    evaluator.calibrations = {p: dataclasses.replace(c, calibration_id=identifier, status="CONTROLLER_ACCEPTED", source=dict(c.source, constituent_calibration_id=c.calibration_id)) for p, c in evaluator.calibrations.items()}
    evaluator.timing_profiles = {p: dict(item, calibration_id=identifier, calibration_status="CONTROLLER_ACCEPTED") for p, item in evaluator.timing_profiles.items()}
    return evaluator


def load_primary(root, *, route_path, route_sha256, calibration_bundle_path=None, calibration_bundle_sha256=None):
    root = Path(root)
    route = read_route(root, route_path, route_sha256)
    inputs = route["inputs"]
    path = lambda name: str(root / inputs[name]["path"])
    base = hybrid_loader.load_monitor_behavior(root, monitors_path=path("monitors"), monitors_sha256=inputs["monitors"]["sha256"], cal_v2_path=path("cal_v2"), cal_v2_sha256=inputs["cal_v2"]["sha256"],
                                               models_record_path=path("fleet_models"), models_record_sha256=inputs["fleet_models"]["sha256"], compat_record_path=path("compat"), compat_record_sha256=inputs["compat"]["sha256"])
    family, provenance = family_loader.load_family(root, assignment_path=path("family_assignment"), assignment_sha256=inputs["family_assignment"]["sha256"], candidates_path=path("candidates"),
                                                   candidates_sha256=inputs["candidates"]["sha256"], models_dir=root / MODELS_FALLBACK)
    v2 = spec.v2_pins(root)
    hybrid = family_loader.apply_family(base, family, provenance, plain_pins=((v2["registry_sha256"], v2["observation_config_sha256"], v2["schema_fingerprint"]),))
    evaluator = PrimaryAeEvaluator.from_hybrid(hybrid, route["devices"])
    if calibration_bundle_path is not None:
        evaluator = apply_calibration_bundle(evaluator, calibration_bundle_path, calibration_bundle_sha256)
    return evaluator


def wrap(engine, *, repo_root, registry_path, registry_sha256):
    return hybrid_loader.wrap_hybrid_engine(engine, repo_root=repo_root, registry_path=registry_path, registry_sha256=registry_sha256)


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))
