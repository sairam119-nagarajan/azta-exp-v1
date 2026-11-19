"""Gate 5D.3B per-device reconciliation of one FUNCTIONAL_TEST ten-instance run (offline analysis of retained evidence).

For every device: planned (fixture) -> attempted -> accepted (PUBACK 0) -> uniquely observed by the dedicated observer (exact payload
SHA-256 correlation, bound by delivered topic) plus missing, extra, duplicate and misattributed messages, window-count consistency,
and candidate-readiness statuses. Timing comes from the per-instance startup/lateness records. Exact equality is expected for a clean
QoS 1 run, so there are no tolerances; every deviation is listed, never absorbed. Nothing here is a scientific result, a latency or
reliability figure, a model input or a threshold.

It reads only the one observer session named by the workload summaries (never a directory listing of the observation root), so no
other evidence is opened.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys

from experiments import gate5d3_runner as runner

CANDIDATE_FEATURES = ("delivered_count", "payload_bytes_mean", "payload_bytes_sd", "interarrival_mean_ms",
                      "interarrival_sd_ms", "last_delivery_age_ms")


def _jsonl(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def _read_instance(directory, device):
    directory = Path(directory)
    summary = json.loads((directory / "workload_summary.json").read_text(encoding="utf-8"))
    ledger = _jsonl(directory / f"ledger_{device}.jsonl")
    return summary, ledger


def reconcile(fixture, workload_run_dir, observation_root, *, expected_devices=None):
    """Pure function over retained files; returns a JSON-serializable report."""
    workload_run_dir, observation_root = Path(workload_run_dir), Path(observation_root)
    devices = sorted(expected_devices or fixture["devices"])
    reasons = []
    instances = {}
    for device in devices:
        directory = workload_run_dir / device
        if not (directory / "workload_summary.json").is_file():
            reasons.append(f"{device}: no instance evidence")
            continue
        instances[device] = _read_instance(directory, device)
    summaries = [s for s, _ in instances.values()]
    structural = runner.reconcile_instances(summaries, expected_devices=devices)
    reasons += structural["reasons"]
    sessions = {s.get("observer_session_id") for s in summaries}
    if len(sessions) != 1 or None in sessions:
        raise ValueError("instances do not name exactly one observer session")
    session_id = next(iter(sessions))
    session_dir = observation_root / session_id
    metadata = json.loads((session_dir / "session_metadata.json").read_text(encoding="utf-8"))
    if metadata.get("collection_run_id") != fixture["run_id"] or metadata.get("purpose") != "FUNCTIONAL_TEST":
        raise ValueError("observer session is not this run's FUNCTIONAL_TEST session")
    observer_summary = json.loads((session_dir / "session_summary.json").read_text(encoding="utf-8"))
    events = _jsonl(session_dir / "events.jsonl")
    windows = _jsonl(session_dir / "windows.jsonl")
    if metadata["registry_sha256"] != fixture["registry_sha256"] or metadata["observation_config_sha256"] != fixture["observation_config_sha256"]:
        reasons.append("observer session registry/configuration digest differs from the fixture")
    if observer_summary["state"] != "COMPLETE" or not all(observer_summary["invariants"].values()):
        reasons.append(f"observer session is {observer_summary['state']} or violates its invariants")
    ledger_hash_owner = {}
    attempts_by_device = {}
    for device, (_, ledger) in instances.items():
        attempts = [r for r in ledger if r["record_type"] == "ATTEMPT"]
        attempts_by_device[device] = attempts
        for record in attempts:
            ledger_hash_owner[record["payload_sha256"]] = device
    per_device = {}
    for device in devices:
        if device not in instances:
            continue
        summary, ledger = instances[device]
        attempts = attempts_by_device[device]
        acks = [r for r in ledger if r["record_type"] == "PUBACK"]
        ack_by_sequence = {k["sequence"]: k["puback_reason"] for k in acks}
        accepted_hashes = {a["payload_sha256"] for a in attempts if ack_by_sequence.get(a["sequence"]) == 0}
        mine = [e for e in events if e["bound_device"] == device]
        counted = [e for e in mine if e["disposition"] == "COUNTED"]
        counted_hashes = Counter(e["payload_sha256"] for e in counted)
        attempted_hashes = {a["payload_sha256"] for a in attempts}
        observed_any = {e["payload_sha256"] for e in mine}
        missing = sorted(accepted_hashes - set(counted_hashes))
        misattributed = [h for h in counted_hashes if h in ledger_hash_owner and ledger_hash_owner[h] != device]
        extra = [h for h in counted_hashes if h not in attempted_hashes and h not in misattributed]
        duplicates = sum(c - 1 for c in counted_hashes.values() if c > 1)
        own_windows = sorted((w for w in windows if w["device"] == device), key=lambda w: w["window"]["index"])
        window_sum = sum(w["measures"]["delivered_count"]["value"] or 0 for w in own_windows)
        reasons_here = []
        planned = fixture["devices"][device]["planned_messages"]
        result = summary["devices_result"][device]
        if not (planned == result["attempted"] == result["accepted"]):
            reasons_here.append("planned, attempted and accepted counts differ")
        if missing:
            reasons_here.append(f"{len(missing)} accepted message(s) not observed")
        if extra or misattributed:
            reasons_here.append("observed messages that are not this device's own")
        if duplicates:
            reasons_here.append("duplicate counted deliveries")
        if window_sum != len(counted):
            reasons_here.append("window delivered_count sum differs from counted events")
        excluded = Counter(e["disposition"] for e in mine if e["disposition"] != "COUNTED")
        if excluded:
            reasons_here.append(f"excluded deliveries: {dict(excluded)}")
        statuses = Counter()
        for window in own_windows:
            for name in CANDIDATE_FEATURES:
                statuses[window["measures"][name]["status"]] += 1
        eligible = [w for w in own_windows if 1 <= w["window"]["index"] <= fixture["eligible_windows"]]
        complete_vectors = sum(all(w["measures"][n]["status"] == "VALUE" for n in CANDIDATE_FEATURES) for w in eligible)
        per_device[device] = dict(
            slot=fixture["devices"][device]["slot"], planned=planned, attempted=len(attempts), queued=result["queued"],
            accepted=result["accepted"], accepted_no_matching_subscribers=result["accepted_no_matching_subscribers"],
            denied=result["denied"], other_ack=result["other"], unacknowledged=result["unacknowledged"],
            observed_any_by_topic=len(observed_any), observed_counted=len(counted), observed_unique=len(counted_hashes),
            missing=len(missing), missing_sequences_head=sorted(a["sequence"] for a in attempts if a["payload_sha256"] in missing)[:20],
            extra=len(extra), misattributed=len(misattributed), duplicates=duplicates, excluded=dict(excluded),
            window_delivered_count_sum=window_sum, windows=len(own_windows),
            coverage_complete_windows=sum(w["coverage"]["state"] == "COMPLETE" for w in own_windows),
            eligible_windows=len(eligible), eligible_windows_with_all_six_values=complete_vectors,
            measure_status_counts=dict(statuses), lateness_ns=result["lateness_ns"],
            startup=summary["startup"], reasons=reasons_here)
        reasons += [f"{device}: {r}" for r in reasons_here]
    outside = Counter(e["bound_device"] for e in events if e["binding_status"] == "BOUND" and e["bound_device"] not in devices)
    if outside:
        reasons.append(f"observer events bound to devices outside this run: {dict(outside)}")
    unbound = [e for e in events if e["binding_status"] != "BOUND"]
    if unbound:
        reasons.append(f"{len(unbound)} observer event(s) with an unbound topic")
    return dict(
        schema="azta.gate5d3.reconciliation", schema_version=1, evidence_label="FUNCTIONAL_TEST", scientific=False,
        run_id=fixture["run_id"], fixture_sha256=fixture["fixture_sha256"], observer_session_id=session_id,
        observer_identity=metadata.get("observer_identity"), observer_state=observer_summary["state"],
        verdict="CONSISTENT" if not reasons else "DEVIATIONS", reasons=reasons, per_device=per_device,
        totals=dict(planned=sum(d["planned"] for d in per_device.values()), attempted=sum(d["attempted"] for d in per_device.values()),
                    accepted=sum(d["accepted"] for d in per_device.values()),
                    observed_unique=sum(d["observed_unique"] for d in per_device.values()),
                    observer_events=len(events), unbound_events=len(unbound)),
        instances=dict(structural=structural["verdict"], startup=structural["startup"], max_lateness_ns=structural["max_lateness_ns"],
                       clock_basis=structural["clock_basis"], late_policy=structural["late_policy"]),
        note="functional communication evidence only; startup offsets and lateness are recorded observations, not established timing "
             "accuracy, synchronization, latency or reliability, and no acceptance threshold is applied")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--workload-run-dir", required=True, help=".../gate5d3_workload/<run id>")
    parser.add_argument("--observation-root", required=True, help=".../observation (only the named session is read)")
    parser.add_argument("--output", required=True, help="new file; never overwritten")
    args = parser.parse_args(argv)
    try:
        fixture = json.loads(Path(args.fixture).read_text(encoding="utf-8"))
        report = reconcile(fixture, args.workload_run_dir, args.observation_root)
        with Path(args.output).open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as exc:
        print(f"GATE5D3_RECONCILE_REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    t = report["totals"]
    print(f"GATE5D3_RECONCILE {report['verdict']} run_id={report['run_id']} planned={t['planned']} attempted={t['attempted']} "
          f"accepted={t['accepted']} observed_unique={t['observed_unique']} deviations={len(report['reasons'])}")
    return 0 if report["verdict"] == "CONSISTENT" else 1


if __name__ == "__main__":
    raise SystemExit(main())
