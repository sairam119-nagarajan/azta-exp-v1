"""Gate 5F.2 offline compatibility analysis: can the intended ten-device workload be scored by the currently frozen S/V autoencoders?

Pure, deterministic and offline. It reads only committed configuration (both registries, the registry-v2 freeze record, the accepted
Gate 5C profile definitions and the ten-slot functional workload specification) and computes PLANNED window features from the seeded
synthetic schedules. It opens no evidence, loads no model, scores nothing and approves no route. Its purpose is to state, with numbers,
which parts of the ten-device experiment the frozen models cannot score and why, so that nothing is silently made score-ready.

Three independent conditions must all hold before a window can be scored by a frozen model:
  1. PIN: the window's registry and observation-configuration digests equal the ones the model was fitted and calibrated under
     (registry v2 differs, so every ten-device window is refused as SCHEMA_MISMATCH today);
  2. ROUTE: its device must have a trusted S or V assignment (no v2 device has an approved route);
  3. LAW: the workload law that generates its traffic must be the law the model was trained on (a steady 1 Hz fixed-128-byte train for S,
     a steady 5 Hz variable 128-256-byte train for V), otherwise a large residual would register legitimate behaviour as anomalous.
Satisfying condition 1 or 2 would need a controller decision; condition 3 is a property of the workload and cannot be decided by pins.

    python -m experiments.gate5f2_ten_device_compat [--out report.json]
"""
import argparse
import json
from pathlib import Path
import statistics
import sys

from experiments import collection_plan as plans
from experiments import collection_workload_v2 as v2
from experiments import gate5d3_workload as slots
from observation.registry import DeviceRegistry
from observation.schema import PREDICTOR_CANDIDATES, SCHEMA_FINGERPRINT, canonical, observation_config_sha256, sha256_text
from preprocessing.gate5d_data import PIN, REASON_PRECEDENCE

ROOT = Path(__file__).resolve().parents[1]
RUN_ID = "g5f2-compat-analysis"
W_NS = plans.DESIGN_W_MS * 1_000_000
LEAD_IN, ELIGIBLE = 1, 60


def _payload_law(payload):
    return tuple(payload.get(k) for k in ("kind", "bytes", "low", "high"))


def frozen_profile_matching(slot_profile):
    """'S' or 'V' when the slot's traffic law equals the frozen profile's law exactly, else None."""
    if slot_profile["shape"] != "steady_jitter":
        return None
    for name, frozen in plans.PROFILES.items():
        if (slot_profile["nominal_gap_ns"], slot_profile["jitter_fraction"], _payload_law(slot_profile["payload"])) == \
                (frozen["nominal_gap_ns"], frozen["jitter_fraction"], _payload_law(frozen["payload"])):
            return name
    return None


def _reason(entry):
    statuses = {entry[name]["status"] for name in PREDICTOR_CANDIDATES}
    for reason in REASON_PRECEDENCE[3:]:
        if reason in statuses:
            return reason
    return None


def analyze_slot(slot):
    built = slots.schedule(RUN_ID, slot, window_ns=W_NS, lead_in_windows=LEAD_IN, eligible_windows=ELIGIBLE)
    items = built["items"]
    count = LEAD_IN + ELIGIBLE + 1
    features = v2.planned_window_features([o for _, o, _ in items], [s for _, _, s in items], count, W_NS)
    eligible = [features[i] for i in range(LEAD_IN, LEAD_IN + ELIGIBLE)]
    reasons = {}
    for entry in eligible:
        reason = _reason(entry)
        if reason:
            reasons[reason] = reasons.get(reason, 0) + 1
    ready = [e for e in eligible if v2.planned_vector(e) is not None]
    counts = [e["delivered_count"]["value"] for e in eligible]
    profile = slots.PROFILES[slot]
    return dict(
        slot=slot, device=slots.device_for(slot), shape=profile["shape"], law_equivalent_to_frozen_profile=frozen_profile_matching(profile),
        planned_messages=len(items), eligible_windows=len(eligible), planned_score_ready_windows=len(ready),
        planned_not_ready_by_reason=reasons,
        delivered_count=dict(min=min(counts), median=statistics.median(counts), max=max(counts)))


def analyze():
    v1_registry = DeviceRegistry.load(ROOT / "configs" / "observation" / "device_registry.json")
    v2_registry = DeviceRegistry.load(ROOT / "configs" / "observation" / "device_registry_v2.json")
    freeze = json.loads((ROOT / "configs" / "gate5d3" / "registry_v2_freeze.json").read_text(encoding="utf-8"))
    v1_config, v2_config = (observation_config_sha256(W_NS, r.sha256, plans.SUBSCRIPTION_QOS) for r in (v1_registry, v2_registry))
    rows = [analyze_slot(slot) for slot in slots.SLOTS]
    for row in rows:
        law = row["law_equivalent_to_frozen_profile"]
        row["condition_pin"] = "FAIL: registry v2 digest differs from the model pin (SCHEMA_MISMATCH)"
        row["condition_route"] = "FAIL: no approved S/V route exists for any registry-v2 device"
        row["condition_law"] = (f"PASS: same traffic law as frozen profile {law}" if law
                                else "FAIL: no frozen model was trained on this traffic law")
        row["scorable_today"] = False
        row["scorable_if_pin_and_route_were_approved"] = bool(law) and row["planned_score_ready_windows"] == row["eligible_windows"]
    return dict(
        schema="azta.gate5f2.ten_device_compatibility", schema_version=1, run_id_for_seeds=RUN_ID,
        basis="planned synthetic schedules and committed configuration only; no evidence, model or broker involved",
        registries=dict(v1_sha256=v1_registry.sha256, v1_pinned=PIN["registry_sha256"], v1_matches_pin=v1_registry.sha256 == PIN["registry_sha256"],
                        v2_sha256=v2_registry.sha256, v2_freeze_record_sha256=freeze["registry_sha256"],
                        v2_matches_its_freeze_record=v2_registry.sha256 == freeze["registry_sha256"],
                        v1_device_count=len(v1_registry.devices), v2_device_count=len(v2_registry.devices)),
        observation_config=dict(
            v1_sha256=v1_config, pinned=PIN["observation_config_sha256"], v1_matches_pin=v1_config == PIN["observation_config_sha256"],
            v2_sha256=v2_config, differs_from_pin=v2_config != PIN["observation_config_sha256"],
            schema_fingerprint=SCHEMA_FINGERPRINT, schema_fingerprint_matches_pin=SCHEMA_FINGERPRINT == PIN["schema_fingerprint"],
            note="the digest inputs are the window duration, QoS, observer version, schema fingerprint and the registry digest; with those "
                 "other inputs equal, the registry digest is the only difference between the v1 and v2 observation configurations"),
        slots=rows, slots_scorable_today=[r["slot"] for r in rows if r["scorable_today"]],
        slots_with_a_frozen_traffic_law=[r["slot"] for r in rows if r["law_equivalent_to_frozen_profile"]],
        slots_without_any_frozen_model=[r["slot"] for r in rows if not r["law_equivalent_to_frozen_profile"]],
        conclusion=("The intended ten-device experiment CANNOT be scored with the currently frozen S/V models. Every registry-v2 window is "
                    "refused on the pin and has no approved route. Even if a controller approved the pin and the routes, only the slots "
                    "listed in slots_with_a_frozen_traffic_law have a traffic law the frozen models were trained on; the other slots need "
                    "their own benign collection, training and calibration (new models, not a relabelling of these)."))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", help="new JSON file (never overwritten); omit to print")
    args = parser.parse_args(argv)
    report = analyze()
    text = json.dumps(report, sort_keys=True, indent=1, allow_nan=False) + "\n"
    if args.out:
        with Path(args.out).open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        print(f"GATE5F2_TEN_DEVICE_COMPAT sha256={sha256_text(canonical(report))} scorable_today={report['slots_scorable_today']}")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
