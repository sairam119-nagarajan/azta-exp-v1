"""Ten-device functional readiness report (Master Implementation 2): what the isolated broker and the real observer show for each device, and exactly what adaptive scoring may and may not do.

    python -m engineering.ten_device_report --run-dir DIR --run-id ID --session-id obs-... --out FILE

Offline and read-only over ONE engineering run directory (observer windows of the named session, the per-device reconciliation, the isolation probes). For every device it states:
  * isolation, from the data-plane probe: the principal connects, its own telemetry is acknowledged AND delivered to the receive-only observer, another device's topic and every
    subscription are denied, and an operations publication is denied unless the device holds the operations entitlement (device01 and device02 only);
  * communication, from the reconciliation: planned = attempted = accepted = uniquely observed, bound to the device only by the exact delivered topic;
  * eligibility, from the observer's own windows: how many eligible windows are SCORE-READY (all six features carry a VALUE) against the committed planning coverage;
  * routing, from the committed ten-device candidate registry: the exact resolution code the integrated engine returns for a window of this device (ROUTE_NOT_APPROVED,
    NO_FROZEN_MODEL_FOR_LAW or UNSCORABLE_AT_WINDOW_DEFINITION; the registry routes nothing), and separately whether the windows carry the registry and observation-configuration
    digests the frozen models were fitted and calibrated under (they do not: the unchanged engine refuses them);
  * adaptive scoring: always NOT AVAILABLE for all ten devices today, with every blocker named. Nothing here bypasses a pin, fabricates a route or approves a model.
It reads the observer's output of an engineering run only (never B_cal, CAL_V2, D_shadow or D_test) and writes nothing but the report.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SIX = ("delivered_count", "payload_bytes_mean", "payload_bytes_sd", "interarrival_mean_ms", "interarrival_sd_ms", "last_delivery_age_ms")
OPERATIONS_DEVICES = ("device01", "device02")
SCHEMA = "azta.engineering.ten_device_readiness"
CANDIDATE_REGISTRY = ROOT / "configs" / "decision_pipeline" / "device_profile_registry_ten_device_candidate.json"
COVERAGE = ROOT / "configs" / "gate5f" / "ten_device_model_coverage.json"
EVIDENCE_MODE = "TRUSTED_OFFLINE_REPLAY"
PURPOSE = "FUNCTIONAL_TEST"


def jsonl(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def score_ready(window):
    return all((window["measures"].get(name) or {}).get("status") == "VALUE" for name in SIX)


def load_candidate_registry(repo_root=ROOT, path=CANDIDATE_REGISTRY):
    """The committed ten-device candidate through the same loader and pin checks the pipeline uses."""
    from decision_pipeline.registry import load_registry, model_catalog_from_freeze
    from preprocessing.gate5d_data import PIN
    from trust import artifacts
    catalog = model_catalog_from_freeze(artifacts.load_freeze(Path(repo_root)))
    return load_registry(path, authorized_file_sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest(), model_catalog=catalog,
                         model_pins={k: PIN[k] for k in ("registry_sha256", "observation_config_sha256")})


def isolation(probe, device):
    """The probe outcome of one device against the data plane its entitlement gives. `ok` is True only if every observation matches."""
    if not probe or probe.get("connack") != 0:
        return dict(ok=False, reason="PROBE_MISSING_OR_NOT_CONNECTED", connack=(probe or {}).get("connack"))
    p, s = probe["publishes"], probe["subscribes"]
    expected_ops = (0, True) if device in OPERATIONS_DEVICES else (135, False)
    observed = dict(own_telemetry=(p["own_telemetry"]["puback"], p["own_telemetry"]["delivered_to_listener"]),
                    other_device_telemetry=(p["other_telemetry"]["puback"], p["other_telemetry"]["delivered_to_listener"]),
                    own_operations=(p["own_operations"]["puback"], p["own_operations"]["delivered_to_listener"]),
                    subscriptions=(s["own_telemetry"]["suback"], s["wildcard"]["suback"]))
    expected = dict(own_telemetry=(0, True), other_device_telemetry=(135, False), own_operations=expected_ops, subscriptions=(135, 135))
    return dict(ok=observed == expected, observed={k: list(v) for k, v in observed.items()}, expected={k: list(v) for k, v in expected.items()})


def window_summary(windows, device, lead_in, eligible):
    own = [w for w in windows if w["device"] == device and lead_in <= w["window"]["index"] < lead_in + eligible]
    counts = {}
    for w in own:
        value = (w["measures"]["delivered_count"] or {}).get("value")
        counts[str(value)] = counts.get(str(value), 0) + 1
    return dict(eligible_windows=len(own), score_ready=sum(1 for w in own if score_ready(w)), delivered_count_histogram=dict(sorted(counts.items(), key=lambda kv: float(kv[0]) if kv[0] != "None" else -1)),
                messages=sum((w["measures"]["delivered_count"] or {}).get("value") or 0 for w in own))


def build_report(*, run_id, session_id, windows, probes, reconciliation, registry, coverage, lead_in, eligible):
    pins = {(w["identity"]["registry_sha256"], w["observation_config_sha256"]) for w in windows}
    if len(pins) != 1:
        raise ValueError("the session carries windows of more than one registry or configuration")
    (registry_sha, config_sha), = pins
    from preprocessing.gate5d_data import PIN
    frozen_pins = (PIN["registry_sha256"], PIN["observation_config_sha256"])
    pins_match = (registry_sha, config_sha) == frozen_pins
    rows = {e["device"]: e for e in coverage["devices"]}
    per_device = {}
    for device in sorted(rows):
        entry, summary = rows[device], window_summary(windows, device, lead_in, eligible)
        rec = (reconciliation.get("per_device") or {}).get(device, {})
        route = registry.resolve(device, window_registry_sha256=registry_sha, window_config_sha256=config_sha, evidence_mode=EVIDENCE_MODE, window_purpose=PURPOSE)
        planned = entry["planned_score_ready_windows"] / entry["eligible_windows"]
        observed = summary["score_ready"] / summary["eligible_windows"] if summary["eligible_windows"] else None
        per_device[device] = dict(
            principal=f"azta-device-{int(device[-2:]):02d}", operations_entitlement=device in OPERATIONS_DEVICES, isolation=isolation(probes.get(device), device),
            communication=dict(planned=rec.get("planned"), attempted=rec.get("attempted"), accepted=rec.get("accepted"), observed_unique=rec.get("observed_unique"),
                               exact=bool(rec) and len({rec.get("planned"), rec.get("attempted"), rec.get("accepted"), rec.get("observed_unique")}) == 1),
            windows=summary, planning=dict(law_class=entry["law_class"], scorability=entry["scorability"], planned_score_ready_fraction=planned,
                                           observed_score_ready_fraction=observed,
                                           observed_matches_plan=observed is not None and (observed == planned if entry["scorability"] != "PARTIAL" else 0 < observed < 1)),
            route=dict(code=route.code, profile=route.profile, blockers=list(route.blockers) or list(entry["blockers"])),
            frozen_model_law_equivalent=entry["frozen_model_law_equivalent"],
            adaptive_scoring_available=False,
            adaptive_scoring_blockers=sorted(set(["NO_CONTROLLER_APPROVED_ROUTE", "NO_ACCEPTED_CALIBRATION_FOR_THIS_REGISTRY_AND_WORKLOAD"]
                                                 + ([] if pins_match else ["REGISTRY_PIN_MISMATCH_FOR_THE_FROZEN_MODELS"])
                                                 + (["NO_FROZEN_MODEL_FOR_THIS_TRAFFIC_LAW"] if entry["frozen_model_law_equivalent"] is None else [])
                                                 + (["UNSCORABLE_AT_THE_10_S_WINDOW_DEFINITION"] if entry["scorability"] == "UNSCORABLE" else [])
                                                 + (["PARTLY_UNSCORABLE_AT_THE_10_S_WINDOW_DEFINITION"] if entry["scorability"] == "PARTIAL" else []))))
    return dict(
        schema=SCHEMA, schema_version=1, run_id=run_id, observer_session_id=session_id, evidence_scope="ENGINEERING FUNCTIONAL run on the isolated broker; not a scientific collection, not calibration",
        window_pins=dict(registry_sha256=registry_sha, observation_config_sha256=config_sha),
        frozen_model_pins=dict(registry_sha256=frozen_pins[0], observation_config_sha256=frozen_pins[1], windows_match=pins_match,
                               engine_outcome_for_these_windows="ACCEPTED_BY_THE_PIN_CHECK" if pins_match else "REFUSED_BY_THE_UNCHANGED_ENGINE: the windows were not observed under the registry and "
                                                                                                         "configuration the frozen models were fitted and calibrated under"),
        candidate_registry=dict(status=registry.status, sha256=registry.sha256,
                                                                                                                  routed_devices=registry.describe()["routed_devices"]),
        reconciliation=dict(verdict=reconciliation.get("verdict"), totals=reconciliation.get("totals")), per_device=per_device,
        summary=dict(devices=len(per_device), isolation_ok=sum(1 for d in per_device.values() if d["isolation"]["ok"]), communication_exact=sum(1 for d in per_device.values()
                                                                                                                                           if d["communication"]["exact"]),
                     observed_matches_plan=sum(1 for d in per_device.values() if d["planning"]["observed_matches_plan"]),
                     adaptive_scoring_available=sum(1 for d in per_device.values() if d["adaptive_scoring_available"]),
                     route_codes=sorted({d["route"]["code"] for d in per_device.values()})),
        restrictions=["No route is approved: the ten-device candidate registry routes nothing.",
                      "The windows carry the ten-device registry and configuration digests; the frozen S/V models were fitted and calibrated under registry v1 (PIN_MISMATCH). The pin is in a "
                      "frozen module; no bypass or fabricated compatibility exists here.",
                      "Only device01 (S law) and device02 (V law) have a frozen model for their traffic law; devices 03 to 10 have none.",
                      "Devices 07 to 09 are unscorable and device06 half-scorable at the 10 s six-feature window definition.",
                      "No calibration exists for this registry and workload; an ENGINEERING_CANDIDATE_UNAPPROVED registry cannot become CONTROLLER_APPROVED here."])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--reconciliation", required=True)
    parser.add_argument("--probe-glob", default="*-ten-*.json")
    parser.add_argument("--lead-in-windows", required=True, type=int)
    parser.add_argument("--eligible-windows", required=True, type=int)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        run_dir = Path(args.run_dir)
        windows = jsonl(run_dir / "observation" / args.session_id / "windows.jsonl")
        probes = {}
        for path in sorted((run_dir / "probes").glob(args.probe_glob)):
            probe = json.loads(path.read_text(encoding="utf-8"))
            probes[probe["device"]] = probe
        report = build_report(run_id=args.run_id, session_id=args.session_id, windows=windows, probes=probes, reconciliation=json.loads(Path(args.reconciliation).read_text(encoding="utf-8")),
                              registry=load_candidate_registry(), coverage=json.loads(COVERAGE.read_text(encoding="utf-8")), lead_in=args.lead_in_windows, eligible=args.eligible_windows)
        with open(args.out, "x", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, indent=1, sort_keys=True)
            stream.write("\n")
    except (OSError, ValueError, KeyError) as exc:
        print(f"TEN_DEVICE_REPORT_REFUSED {type(exc).__name__}: {str(exc)[:200]}", file=sys.stderr)
        return 2
    s = report["summary"]
    print(f"TEN_DEVICE_REPORT devices={s['devices']} isolation_ok={s['isolation_ok']} communication_exact={s['communication_exact']} observed_matches_plan={s['observed_matches_plan']} "
          f"adaptive_scoring_available={s['adaptive_scoring_available']} route_codes={','.join(s['route_codes'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
