"""Fleet constants: the ten-device observation pins, the fleet workload version and the committed profile specification.

The pins are derived, never typed: the registry-v2 digest comes from the committed registry file and the observation-configuration digest from the frozen digest function with the
frozen window duration, so a changed registry cannot carry stale pins. The profile specification is `configs/gate6b/fleet_profiles.json`.
"""
import hashlib
import json
from pathlib import Path

from experiments import collection_plan as plans
from observation.registry import DeviceRegistry
from observation.schema import SCHEMA_FINGERPRINT, observation_config_sha256

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_V2_REL = "configs/observation/device_registry_v2.json"
PROFILES_REL = "configs/gate6b/fleet_profiles.json"
FLEET_WORKLOAD_VERSION = "gate6b-fleet-workload-1"
WINDOW_MS = 10_000
WINDOW_NS = WINDOW_MS * 1_000_000
PLAN_SCHEMA = "azta.gate6b.fleet_plan"
PROFILES_SCHEMA = "azta.gate6b.fleet_profiles"


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def registry_v2(root=ROOT):
    return DeviceRegistry.load(Path(root) / REGISTRY_V2_REL)


def v2_pins(root=ROOT):
    """The (registry, observation configuration, schema fingerprint) a ten-device window carries."""
    registry = registry_v2(root)
    return dict(registry_sha256=registry.sha256, observation_config_sha256=observation_config_sha256(WINDOW_NS, registry.sha256, plans.SUBSCRIPTION_QOS),
                schema_fingerprint=SCHEMA_FINGERPRINT)


def load_profiles(root=ROOT):
    data = json.loads((Path(root) / PROFILES_REL).read_text(encoding="utf-8"))
    if data.get("schema") != PROFILES_SCHEMA or data.get("schema_version") != 1:
        raise ValueError("not a fleet profile specification")
    return data
