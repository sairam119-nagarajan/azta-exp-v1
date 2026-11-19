"""Gate 5C deterministic publisher/observer reconciliation and ACCEPT/VOID verdict for one run.

Read-only over evidence files; writes only its own exclusive report. Nothing is repaired. Hard
validity is structural (coverage, subscriptions, observer errors, invariants, receipt
reconciliation, audits/policy, identity binding, plan match). Timing values are descriptive QC; a
timing anomaly at or above the fastest profile's minimum scheduled gap only raises a REVIEW flag
(controller decision C6), never a VOID by itself. The publisher ledger corroborates; the observer's
audit-backed exact-topic binding is authoritative for identity.
"""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import sys

from experiments import collection_plan as plans
from experiments.collection_workload import payload, schedule, utc_to_epoch_ns
from observation import manifest as manifest_module
from observation.records import file_sha256
from observation.registry import DeviceRegistry
from observation.schema import SCHEMA_FINGERPRINT, canonical, validate_event, validate_health, validate_window
from observation.windowing import WindowConfig, replay

REPORT_SCHEMA = "azta.collection.reconciliation"
SCHEMA_VERSION = 1
SESSION_FILES = ("session_metadata.json", "events.jsonl", "windows.jsonl", "health.jsonl")
CLEAN_COUNTERS = ("event_errors", "binding_failures", "excluded_unbound", "excluded_retained",
                  "excluded_pre_coverage", "excluded_post_coverage")


def _jsonl(path):
    with Path(path).open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def _json(path):
    with Path(path).open(encoding="utf-8") as stream:
        return json.load(stream)


def stats(values):
    values = list(values)
    if not values:
        return dict(n=0, mean=None, sd=None, min=None, max=None)
    return dict(n=len(values), mean=statistics.fmean(values), sd=statistics.stdev(values) if len(values) > 1 else None,
                min=min(values), max=max(values))


def find_sessions(root, run_id):
    found = []
    for meta in sorted((Path(root) / "observation").glob("obs-*/session_metadata.json")):
        try:
            if _json(meta).get("collection_run_id") == run_id:
                found.append(meta.parent)
        except (OSError, ValueError):
            found.append(meta.parent)  # unreadable metadata is never silently ignored
    return found


def audit_paths(root, run_id):
    return {stage: Path(root) / f"{run_id}-audit-{stage}" / "binding_audit.json" for stage in ("pre", "post")}


class Checks:
    def __init__(self):
        self.items = []

    def __call__(self, name, ok, stop=False, **observed):
        self.items.append(dict(name=name, result="PASS" if ok else "FAIL", campaign_stop_if_failed=stop,
                               observed=observed))
        return ok


def reconcile(*, root, run_id, plan, registry, purpose, baseline_policy_sha256, manifest_path=None):
    root = Path(root)
    config = plan["runs"][run_id]
    checks = Checks()
    devices = sorted(config["devices"])
    topic_of = {d: config["devices"][d]["telemetry_topic"] for d in devices}
    w_ns = plan["window_duration_ms"] * 1_000_000
    first_eligible, last_eligible = config["eligible_window_indices"]
    review_scale_ns = min(round(p["profile_definition"]["nominal_gap_ns"] * (1 - p["profile_definition"]["jitter_fraction"]))
                          for p in config["devices"].values())
    sessions = find_sessions(root, run_id)
    ledger_dir = root / "collection" / run_id
    ledgers = {d: ledger_dir / f"ledger_{d}.jsonl" for d in devices}
    attempts_present = any(p.exists() and any(r.get("record_type") == "ATTEMPT" for r in _jsonl(p))
                           for p in ledgers.values())
    report = dict(schema=REPORT_SCHEMA, schema_version=SCHEMA_VERSION, run_id=run_id, purpose=purpose,
                  plan_id=plan["plan_id"], plan_kind=plan["kind"], plan_sha256=plans.digest(plan),
                  workload_config_sha256=plans.digest(config), observer_session_id=None,
                  review_scale_ns=review_scale_ns, review_flags=[], timing={}, checks=checks.items)
    if not sessions and not attempts_present:
        report.update(verdict="NOT_STARTED", campaign_stop=True,
                      reasons=["no observer session and no publisher attempt for this run"])
        return report

    # ---- observer session -------------------------------------------------------------
    if not checks("observer_session_unique", len(sessions) == 1, stop=len(sessions) > 1,
                  sessions=[p.name for p in sessions]):
        return _close(report, checks)
    session = sessions[0]
    report["observer_session_id"] = session.name
    try:
        meta, summary = _json(session / "session_metadata.json"), _json(session / "session_summary.json")
        events, windows, health = (_jsonl(session / f"{n}.jsonl") for n in ("events", "windows", "health"))
    except (OSError, ValueError) as exc:
        checks("observer_evidence_readable", False, error=type(exc).__name__)
        return _close(report, checks)
    checks("observer_purpose", meta.get("purpose") == purpose == summary.get("purpose"), observed=meta.get("purpose"))
    invariants = summary.get("invariants") or {}
    checks("observer_session_complete", summary.get("state") == "COMPLETE" and summary.get("failure_code") is None
           and invariants and all(invariants.values()), state=summary.get("state"), failure=summary.get("failure_code"),
           invariants=invariants)
    subacks = {r["details"].get("topic"): r["details"].get("reason_codes") for r in health if r["kind"] == "SUBACK"}
    checks("observer_subscriptions_confirmed",
           all(subacks.get(e.telemetry_topic) == [1] for e in registry.devices)
           and any(r["kind"] == "COVERAGE_START" for r in health), subacks=subacks)
    digests_ok = all((session / name).exists() and file_sha256(session / name) == summary.get("artifact_sha256", {}).get(name)
                     for name in SESSION_FILES)
    checks("observer_artifact_digests", digests_ok)
    checks("observation_fingerprints",
           meta.get("schema_fingerprint") == SCHEMA_FINGERPRINT == summary.get("schema_fingerprint")
           and meta.get("observation_config_sha256") == plan["observation_config_sha256"] == summary.get("observation_config_sha256")
           and meta.get("registry_sha256") == registry.sha256 == plan["registry_sha256"]
           and meta.get("window_duration_ns") == w_ns and meta.get("window_count") == config["planned_window_count"],
           observation_config_sha256=meta.get("observation_config_sha256"), registry_sha256=meta.get("registry_sha256"))
    try:
        for record in events:
            validate_event(record)
        for record in windows:
            validate_window(record)
        for record in health:
            validate_health(record)
        valid = True
    except ValueError as exc:
        valid = False
        checks("observer_records_valid", False, error=str(exc)[:200])
    if valid:
        checks("observer_records_valid", True, events=len(events), windows=len(windows), health=len(health))
    expected_windows = len(registry.devices) * config["planned_window_count"]
    replay_ok = False
    if valid and summary.get("coverage_start_offset_ns") is not None:
        try:
            replayed = replay(events, registry, WindowConfig(w_ns, config["planned_window_count"]),
                              summary["coverage_start_offset_ns"], summary.get("coverage_end_offset_ns"),
                              meta["window_header"])
            replay_ok = [canonical(r) for r in replayed] == [canonical(r) for r in windows]
        except (ValueError, KeyError):
            replay_ok = False
    checks("windows_complete_and_replayed",
           len(windows) == expected_windows and all(r["coverage"]["state"] == "COMPLETE" for r in windows) and replay_ok,
           windows=len(windows), expected=expected_windows, replay_identical=replay_ok)
    counters = summary.get("counters") or {}
    dirty = {name: counters.get(name) for name in CLEAN_COUNTERS if counters.get(name) != 0}
    checks("observer_counters_clean", not dirty,
           stop=any(counters.get(n) for n in ("binding_failures", "excluded_unbound", "excluded_retained")), nonzero=dirty)

    # ---- binding audits / policy ------------------------------------------------------
    audits = {}
    for stage, path in audit_paths(root, run_id).items():
        try:
            audits[stage] = _json(path)
        except (OSError, ValueError):
            audits[stage] = None
    audit_ok = all(a and a.get("verdict") == "PASS" and a.get("mutation_performed") is False
                   and a.get("registry_sha256") == registry.sha256 for a in audits.values())
    checks("binding_audits_pass", audit_ok, stop=True,
           verdicts={k: (a or {}).get("verdict") for k, a in audits.items()})
    digests = {k: (a or {}).get("policy_sha256") for k, a in audits.items()}
    checks("policy_digest_unchanged", digests["pre"] == digests["post"] == baseline_policy_sha256, stop=True,
           pre=digests["pre"], post=digests["post"], baseline=baseline_policy_sha256)
    report["binding_audits"] = {k: dict(ref=f"{run_id}-audit-{k}", verdict=(a or {}).get("verdict"),
                                        policy_sha256=(a or {}).get("policy_sha256")) for k, a in audits.items()}

    # ---- publisher ledger vs plan ------------------------------------------------------
    try:
        workload = _json(ledger_dir / "workload_summary.json")
        ledger = {d: _jsonl(ledgers[d]) for d in devices}
    except (OSError, ValueError) as exc:
        checks("publisher_evidence_readable", False, error=type(exc).__name__)
        return _close(report, checks)
    checks("workload_complete", workload.get("state") == "COMPLETE" and workload.get("failure_code") is None
           and workload.get("run_id") == run_id and workload.get("workload_config_sha256") == plans.digest(config)
           and workload.get("observer_session_id") == session.name and workload.get("purpose") == purpose,
           state=workload.get("state"), failure=workload.get("failure_code"))
    attempts, pubacks, plan_ok, outcomes_ok = {}, {}, True, True
    for device in devices:
        spec = config["devices"][device]
        entry = registry.bind(spec["telemetry_topic"])
        attempts[device] = {r["sequence"]: r for r in ledger[device] if r.get("record_type") == "ATTEMPT"}
        acks = [r for r in ledger[device] if r.get("record_type") == "PUBACK"]
        pubacks[device] = {}
        for record in acks:
            if record.get("sequence") is None or record["sequence"] in pubacks[device]:
                outcomes_ok = False
            pubacks[device][record.get("sequence")] = record
        expected = schedule(config, device)
        if len(ledger[device]) != len(attempts[device]) + len(acks) or len(attempts[device]) != len(expected):
            plan_ok = False
        for sequence, offset, size in expected:
            record = attempts[device].get(sequence)
            data = payload(run_id, device, sequence, size)
            if not (record and record["scheduled_offset_ns"] == offset and record["payload_bytes"] == size
                    and record["payload_sha256"] == hashlib.sha256(data).hexdigest()
                    and record["topic"] == spec["telemetry_topic"] and record["qos"] == 1 and record["retain"] is False
                    and entry is not None and entry.device == device and record["configured_username"] == entry.username
                    and record["configured_client_id"] == entry.client_id):
                plan_ok = False
        for sequence, record in attempts[device].items():
            ack = pubacks[device].get(sequence)
            if not (record["queued"] and ack and ack["puback_reason"] == 0 and ack["mqtt_mid"] == record["mqtt_mid"]):
                outcomes_ok = False
    checks("ledger_matches_frozen_plan", plan_ok, planned={d: len(schedule(config, d)) for d in devices},
           attempted={d: len(attempts[d]) for d in devices})
    denied = sum(1 for d in devices for a in pubacks[d].values() if (a.get("puback_reason") or 0) >= 128)
    checks("publisher_outcomes_accepted", outcomes_ok, stop=denied > 0, denied=denied)

    # ---- receipt correlation -----------------------------------------------------------
    by_hash = {}
    for event in events:
        by_hash.setdefault(event["payload_sha256"], []).append(event)
    ledger_hashes = {a["payload_sha256"]: (d, s) for d in devices for s, a in attempts[d].items()}
    unmatched, misplaced = [], []
    for device in devices:
        for sequence, record in attempts[device].items():
            originals = [e for e in by_hash.get(record["payload_sha256"], []) if not e["dup"]]
            if len(originals) != 1:
                unmatched.append(f"{device}:{sequence}")
                continue
            event = originals[0]
            if not (event["topic"] == topic_of[device] and event["bound_device"] == device
                    and event["disposition"] == "COUNTED" and first_eligible <= event["window_index"] <= last_eligible):
                misplaced.append(f"{device}:{sequence}")
    checks("receipt_reconciled", not unmatched and not misplaced, unmatched=unmatched[:20], misplaced=misplaced[:20],
           unmatched_count=len(unmatched), misplaced_count=len(misplaced))
    foreign = [e["record_seq"] for e in events if e["payload_sha256"] not in ledger_hashes]
    checks("no_foreign_events", not foreign, stop=bool(foreign), foreign_record_seqs=foreign[:20], count=len(foreign))
    dup_events = [e for e in events if e["dup"]]
    dup_only = [e["record_seq"] for e in dup_events
                if not any(not other["dup"] for other in by_hash.get(e["payload_sha256"], []))]
    checks("duplicates_reconciled", not dup_only, dup_flagged=len(dup_events), dup_only_record_seqs=dup_only[:20])
    counted = {d: sum(1 for e in events if e["disposition"] == "COUNTED" and e["bound_device"] == d) for d in devices}
    window_sum = {d: sum(r["measures"]["delivered_count"]["value"] or 0 for r in windows if r["device"] == d)
                  for d in devices}
    designed_empty = [f'{r["device"]}:{r["window"]["index"]}' for r in windows
                      if not first_eligible <= r["window"]["index"] <= last_eligible and r["qc"]["counted_events_raw"]]
    checks("participation_as_planned",
           all(counted[d] == len(attempts[d]) == window_sum[d] > 0 for d in devices) and not designed_empty
           and sorted(e.device for e in registry.devices) == devices, counted=counted, window_sum=window_sum,
           lead_in_out_nonempty=designed_empty)

    # ---- manifest / plan binding (COLLECTION) -----------------------------------------
    if purpose == "COLLECTION":
        try:
            state = manifest_module.validate(manifest_module.read_entries(manifest_path))
            plans.check_manifest_against_plan(state, plan)
            planned = state["planned"][run_id]
            observer_att = meta.get("collection_attestation") or {}
            workload_att = workload.get("attestation") or {}
            ok = (run_id not in state["collected"] and run_id not in state["voided"]
                  and planned["workload_config_sha256"] == plans.digest(config)
                  and observer_att.get("planned_entry_sha256") == planned["entry_sha256"] == workload_att.get("planned_entry_sha256")
                  and observer_att.get("manifest_sha256") == workload_att.get("manifest_sha256")
                  and observer_att.get("git_commit") == workload_att.get("git_commit") == meta["runtime"].get("git_commit")
                  and meta["runtime"].get("git_state") == "clean")
            checks("manifest_plan_matches_run", ok, observer_manifest_sha256=observer_att.get("manifest_sha256"),
                   workload_manifest_sha256=workload_att.get("manifest_sha256"), git_commit=observer_att.get("git_commit"))
        except (manifest_module.ManifestError, ValueError, KeyError, OSError) as exc:
            checks("manifest_plan_matches_run", False, error=str(exc)[:200])

    # ---- descriptive timing QC ---------------------------------------------------------
    timing = {}
    for device in devices:
        rows = [attempts[device][s] for s in sorted(attempts[device])]
        gaps = [(b["attempt_offset_ns"] - a["attempt_offset_ns"]) / 1e6 for a, b in zip(rows, rows[1:])]
        late = [(r["attempt_offset_ns"] - r["scheduled_offset_ns"]) / 1e6 for r in rows]
        ack = [(pubacks[device][s]["puback_offset_ns"] - attempts[device][s]["attempt_offset_ns"]) / 1e6
               for s in attempts[device] if s in pubacks[device]]
        received = sorted(e["receive_offset_ns"] for e in events if e["disposition"] == "COUNTED" and e["bound_device"] == device)
        delivery = []
        for record in rows:
            match = [e for e in by_hash.get(record["payload_sha256"], []) if not e["dup"]]
            if match:
                delivery.append((utc_to_epoch_ns(match[0]["receive_utc"]) - utc_to_epoch_ns(record["attempt_utc"])) / 1e6)
        counts_all = [r["measures"]["delivered_count"]["value"] for r in windows
                      if r["device"] == device and first_eligible <= r["window"]["index"] <= last_eligible]
        counts = [c for c in counts_all if c is not None]  # unavailable (non-COMPLETE) windows carry no count
        timing[device] = dict(
            profile=config["devices"][device]["profile"],
            nominal_gap_ms=config["devices"][device]["profile_definition"]["nominal_gap_ns"] / 1e6,
            publisher_attempt_gap_ms=stats(gaps), schedule_lateness_ms=stats(late), puback_latency_ms=stats(ack),
            observer_interarrival_ms=stats((b - a) / 1e6 for a, b in zip(received, received[1:])),
            delivery_latency_utc_ms=stats(delivery), eligible_window_counts=stats(counts),
            eligible_windows_below_3=sum(1 for c in counts if c < 3),
            eligible_windows_unavailable=len(counts_all) - len(counts),
            count_distribution={str(c): counts.count(c) for c in sorted(set(c for c in counts if c is not None))})
        if late and max(late) * 1e6 >= review_scale_ns:
            report["review_flags"].append(f"{device}: publisher schedule lateness {max(late):.1f} ms >= review scale")
    beats = [r["details"] for r in health if r["kind"] == "HEARTBEAT"]
    timing["observer"] = dict(close_lag_ms=stats(b["close_lag_ns"] / 1e6 for b in beats),
                              max_loop_gap_ms=stats(b["max_loop_gap_ns"] / 1e6 for b in beats), heartbeats=len(beats))
    for key in ("close_lag_ns", "max_loop_gap_ns"):
        worst = max((b[key] for b in beats), default=0)
        if worst >= review_scale_ns:
            report["review_flags"].append(f"observer {key} {worst / 1e6:.1f} ms >= review scale")
    report["timing"] = timing
    return _close(report, checks)


def _close(report, checks):
    failed = [c for c in checks.items if c["result"] == "FAIL"]
    report["verdict"] = "ACCEPT" if not failed else "VOID"
    report["campaign_stop"] = any(c["campaign_stop_if_failed"] for c in failed)
    report["reasons"] = [c["name"] for c in failed]
    return report


def write_report(root, run_id, report):
    path = Path(root) / "collection" / run_id / "reconciliation.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--purpose", required=True, choices=("FUNCTIONAL_TEST", "COLLECTION"))
    parser.add_argument("--baseline-policy-sha256", required=True)
    parser.add_argument("--manifest")
    parser.add_argument("--registry", default="/app/configs/observation/device_registry.json")
    parser.add_argument("--root", default="/results")
    args = parser.parse_args(argv)
    try:
        registry = DeviceRegistry.load(args.registry)
        plan = plans.validate_plan(plans.load_plan(args.plan), registry)
        if args.run_id not in plan["runs"]:
            raise ValueError("run is not in the plan")
        if (args.purpose == "COLLECTION") != bool(args.manifest):
            raise ValueError("COLLECTION reconciliation needs the manifest; FUNCTIONAL_TEST must not use one")
        report = reconcile(root=args.root, run_id=args.run_id, plan=plan, registry=registry, purpose=args.purpose,
                           baseline_policy_sha256=args.baseline_policy_sha256, manifest_path=args.manifest)
        path = write_report(args.root, args.run_id, report)
    except (ValueError, OSError, KeyError) as exc:
        print(f"RECONCILE_ERROR {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(f'RECONCILIATION {args.run_id} verdict={report["verdict"]} campaign_stop={report["campaign_stop"]} '
          f'reasons={",".join(report["reasons"]) or "none"} review_flags={len(report["review_flags"])} report={path}')
    return 0 if report["verdict"] == "ACCEPT" else 3 if report["campaign_stop"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
