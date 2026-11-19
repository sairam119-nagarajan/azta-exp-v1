"""Registry-v1 to registry-v2 compatibility record for the FROZEN S and V models (Gate 6B).

S and V were fitted and calibrated on windows observed under the two-device registry v1; a ten-device observer necessarily carries registry v2, whose digest differs, and so does the
observation-configuration digest (the registry digest is one of its inputs). The frozen evaluator therefore refuses every v2 window (SCHEMA_MISMATCH). This record states, from the committed
artifacts, the facts that make a device01/device02 window under v2 the SAME kind of observation as under v1, so that a hash-pinned, controller-reviewable record (instead of a silent
bypass) lets the S/V models score it:

  1. the v2 rows of device01 and device02 equal their v1 rows (broker username, client id, telemetry topic, publish role): the same identities on the same topics;
  2. the observation-configuration digest is a pure function of (window duration, registry digest, subscription QoS): recomputed for v1 it equals the frozen pin, recomputed for v2 it
     equals the ten-device pin, with the same window duration and QoS, so the registry digest is the ONLY input that differs;
  3. the schema fingerprint and the observer's windowing and schema sources are the same files (their SHA-256 is recorded).

Facts 1 to 3 are STRUCTURAL. They do not show that the benign feature distributions under v2 match the training support; `empirical` holds that comparison when it has been made. Whether
this is sufficient for scientific use is a Controller decision; the record is PROVISIONAL_UNAPPROVED and is used by the engineering pilot only.
"""
import hashlib
import json
from pathlib import Path

from experiments import collection_plan as plans
from fleet import spec
from observation.registry import DeviceRegistry
from observation.schema import OBSERVER_VERSION, SCHEMA_FINGERPRINT, observation_config_sha256
from preprocessing.gate5d_data import PIN as FROZEN_PIN

SCHEMA = "azta.gate6b.registry_v2_compat_record"
V1_REL = "configs/observation/device_registry.json"


def _rows(registry, devices):
    return {e.device: dict(username=e.username, client_id=e.client_id, telemetry_topic=e.telemetry_topic, publish_role=e.publish_role) for e in registry.devices if e.device in devices}


def build(root=spec.ROOT, empirical=None):
    root = Path(root)
    v1, v2 = DeviceRegistry.load(root / V1_REL), spec.registry_v2(root)
    shared = ("device01", "device02")
    rows1, rows2 = _rows(v1, shared), _rows(v2, shared)
    recomputed_v1 = observation_config_sha256(spec.WINDOW_NS, v1.sha256, plans.SUBSCRIPTION_QOS)
    recomputed_v2 = observation_config_sha256(spec.WINDOW_NS, v2.sha256, plans.SUBSCRIPTION_QOS)
    sources = {rel: hashlib.sha256((root / rel).read_bytes()).hexdigest() for rel in ("observation/windowing.py", "observation/schema.py")}
    facts = dict(
        shared_device_rows_equal=rows1 == rows2 and set(rows1) == set(shared),
        v1_registry_matches_frozen_pin=v1.sha256 == FROZEN_PIN["registry_sha256"],
        v1_config_recomputes_to_frozen_pin=recomputed_v1 == FROZEN_PIN["observation_config_sha256"],
        v2_config_recomputes_to_ten_device_pin=recomputed_v2 == spec.v2_pins(root)["observation_config_sha256"],
        registries_differ=v1.sha256 != v2.sha256, same_window_duration_ns=spec.WINDOW_NS, same_subscription_qos=plans.SUBSCRIPTION_QOS,
        same_schema_fingerprint=SCHEMA_FINGERPRINT == FROZEN_PIN["schema_fingerprint"], observer_version=OBSERVER_VERSION)
    holds = all(v for k, v in facts.items() if isinstance(v, bool) and k != "registries_differ") and facts["registries_differ"]
    return dict(
        schema=SCHEMA, schema_version=1, status="PROVISIONAL_UNAPPROVED", facts_hold=holds, facts=facts, shared_device_rows=rows2, observer_source_sha256=sources,
        v1_pins=dict(registry_sha256=FROZEN_PIN["registry_sha256"], observation_config_sha256=FROZEN_PIN["observation_config_sha256"], schema_fingerprint=FROZEN_PIN["schema_fingerprint"]),
        v2_pins=spec.v2_pins(root), empirical=empirical,
        scope=("Lets the frozen S and V models (and the unchanged CAL_V2 constants) score windows of device01 and device02 observed under the ten-device registry v2, "
               "for the engineering pilot only. Structural facts only unless `empirical` is present; not a scientific approval."))


def write(path, record):
    blob = (json.dumps(record, sort_keys=True, indent=1) + "\n").encode("utf-8")
    with Path(path).open("xb") as stream:
        stream.write(blob)
    return hashlib.sha256(blob).hexdigest()
