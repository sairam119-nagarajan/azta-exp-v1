"""Gate 5F.2 reconciliation and ACCEPT/VOID verdict for ONE workload-v2 run (post-roll rules). ENGINEERING CANDIDATE: not run, not approved.

Read-only over evidence files; writes only its own exclusive report. It follows the frozen v1 reconciliation (experiments/
collection_reconcile.py, which is not edited and keeps judging v1 runs) check for check, using that module's helpers, and differs in
exactly the places where workload v2 deliberately changes the evidence (docs/gate5e/WORKLOAD_V2_CANDIDATE_SPEC.md section 4):

  * the expected publishing schedule is the v2 schedule (a post-roll window carries normal traffic);
  * the lead-out window is replaced by a POST-ROLL window that must be NON-empty for every device, while the lead-in stays empty;
  * observer receipts may fall in the eligible windows or the post-roll, never in the lead-in;
  * `termination_complete`: every device's publisher must have crossed the end of the last eligible window and published its whole plan
    (`collection_workload_v2.termination_report` verdict TERMINATION_OK); POST_ROLL_INCOMPLETE is not accepted automatically and needs a
    controller decision; ELIGIBLE_WINDOWS_TRUNCATED and SCHEDULE_DEVIATION are never acceptable.
The post-roll window is excluded from scoring everywhere downstream; this module only records that it is present and consistent.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

from experiments import collection_plan as plans
from experiments import collection_plan_v2 as plans_v2
from experiments import collection_audits_v2 as audits_v2
from experiments import collection_sessions_v2 as sessions_v2
from experiments import collection_reconcile as v1
from experiments import collection_workload_v2 as v2
from experiments.collection_workload import payload, utc_to_epoch_ns
from trust.timeline import parse_utc_ns
from observation import manifest as manifest_module
from observation import manifest_v2
from observation.records import file_sha256
from observation.registry import DeviceRegistry
from observation.schema import SCHEMA_FINGERPRINT, canonical, validate_event, validate_health, validate_window
from observation.windowing import WindowConfig, replay

REPORT_SCHEMA = "azta.collection.reconciliation_candidate"
SCHEMA_VERSION = 1


def reconcile(*, root, run_id, plan, registry, purpose, baseline_policy_sha256, audit_interval_s, manifest_path=None, observer_session_id=None):
    """observer_session_id: when given, ONLY that session directory is opened (scoped discovery); when None the evidence root is scanned for
    the run's session, which is acceptable only for an isolated functional root (the command line refuses it for COLLECTION)."""
    root = Path(root)
    config = plan["runs"][run_id]
    checks = v1.Checks()
    devices = sorted(config["devices"])
    topic_of = {d: config["devices"][d]["telemetry_topic"] for d in devices}
    w_ns = plan["window_duration_ms"] * 1_000_000
    first_eligible, last_eligible = config["eligible_window_indices"]
    post_first, post_last = config["window_roles"]["post_roll"]
    review_scale_ns = min(round(p["profile_definition"]["nominal_gap_ns"] * (1 - p["profile_definition"]["jitter_fraction"]))
                          for p in config["devices"].values())
    if observer_session_id is None:
        sessions = v1.find_sessions(root, run_id)
    else:
        try:
            sessions = [sessions_v2.explicit_session(root, run_id, observer_session_id)]
        except ValueError:
            sessions = []          # the named session is absent: NOT_STARTED or a failed uniqueness check below, never a scan
    ledger_dir = root / "collection" / run_id
    ledgers = {d: ledger_dir / f"ledger_{d}.jsonl" for d in devices}
    attempts_present = any(p.exists() and any(r.get("record_type") == "ATTEMPT" for r in v1._jsonl(p)) for p in ledgers.values())
    report = dict(schema=REPORT_SCHEMA, schema_version=SCHEMA_VERSION, generator_version=v2.GENERATOR_VERSION, run_id=run_id,
                  purpose=purpose, plan_id=plan["plan_id"], plan_kind=plan["kind"], plan_sha256=plans.digest(plan),
                  workload_config_sha256=plans.digest(config), observer_session_id=None, window_roles=config["window_roles"],
                  review_scale_ns=review_scale_ns, review_flags=[], timing={}, checks=checks.items)
    if not sessions and not attempts_present:
        report.update(verdict="NOT_STARTED", campaign_stop=True, reasons=["no observer session and no publisher attempt for this run"])
        return report

    # ---- observer session (unchanged from v1) ------------------------------------------------------------------------------
    if not checks("observer_session_unique", len(sessions) == 1, stop=len(sessions) > 1, sessions=[p.name for p in sessions]):
        return v1._close(report, checks)
    session = sessions[0]
    report["observer_session_id"] = session.name
    try:
        meta, summary = v1._json(session / "session_metadata.json"), v1._json(session / "session_summary.json")
        events, windows, health = (v1._jsonl(session / f"{n}.jsonl") for n in ("events", "windows", "health"))
    except (OSError, ValueError) as exc:
        checks("observer_evidence_readable", False, error=type(exc).__name__)
        return v1._close(report, checks)
    checks("observer_purpose", meta.get("purpose") == purpose == summary.get("purpose"), observed=meta.get("purpose"))
    if observer_session_id is not None:
        checks("observer_session_names_this_run", meta.get("collection_run_id") == run_id and meta.get("observer_session_id") == observer_session_id,
               stop=True, named=observer_session_id)
    invariants = summary.get("invariants") or {}
    checks("observer_session_complete", summary.get("state") == "COMPLETE" and summary.get("failure_code") is None
           and invariants and all(invariants.values()), state=summary.get("state"), failure=summary.get("failure_code"),
           invariants=invariants)
    subacks = {r["details"].get("topic"): r["details"].get("reason_codes") for r in health if r["kind"] == "SUBACK"}
    checks("observer_subscriptions_confirmed",
           all(subacks.get(e.telemetry_topic) == [1] for e in registry.devices) and any(r["kind"] == "COVERAGE_START" for r in health),
           subacks=subacks)
    digests_ok = all((session / name).exists() and file_sha256(session / name) == summary.get("artifact_sha256", {}).get(name)
                     for name in v1.SESSION_FILES)
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
            replayed = replay(events, registry, WindowConfig(w_ns, config["planned_window_count"]), summary["coverage_start_offset_ns"],
                              summary.get("coverage_end_offset_ns"), meta["window_header"])
            replay_ok = [canonical(r) for r in replayed] == [canonical(r) for r in windows]
        except (ValueError, KeyError):
            replay_ok = False
    checks("windows_complete_and_replayed",
           len(windows) == expected_windows and all(r["coverage"]["state"] == "COMPLETE" for r in windows) and replay_ok,
           windows=len(windows), expected=expected_windows, replay_identical=replay_ok)
    counters = summary.get("counters") or {}
    dirty = {name: counters.get(name) for name in v1.CLEAN_COUNTERS if counters.get(name) != 0}
    checks("observer_counters_clean", not dirty,
           stop=any(counters.get(n) for n in ("binding_failures", "excluded_unbound", "excluded_retained")), nonzero=dirty)

    # ---- binding audits / policy: pre, post and (declared cadence) periodic audits, all pinned with their capture instants -------------
    stages = [audits_v2.load_stage(root, run_id, stage) for stage in audits_v2.discover_stages(root, run_id)]
    have = {item["stage"] for item in stages}
    # Coverage instants in UTC: the observer's own COVERAGE_START record; the end is the planned end (start + window_count*W) for a complete
    # session (the observer records an explicit end only when coverage stops early), otherwise start + the recorded monotonic distance.
    coverage = {r["kind"]: r["utc"] for r in health if r["kind"] == "COVERAGE_START"}
    start_ns = parse_utc_ns(coverage["COVERAGE_START"]) if "COVERAGE_START" in coverage else None
    offsets = (summary.get("coverage_start_offset_ns"), summary.get("coverage_end_offset_ns"))
    if start_ns is None:
        end_ns = None
    elif offsets[1] is None:
        end_ns = start_ns + config["planned_window_count"] * w_ns
    else:
        end_ns = start_ns + (offsets[1] - offsets[0]) if all(type(v) is int for v in offsets) else None
    audit_ok = {"pre", "post"} <= have and all(
        item["record"] and item["record"].get("verdict") == "PASS" and item["record"].get("mutation_performed") is False
        and item["record"].get("registry_sha256") == registry.sha256 for item in stages)
    checks("binding_audits_pass", audit_ok, stop=True,
           verdicts={item["stage"]: (item["record"] or {}).get("verdict") for item in stages}, mandatory_stages_present={"pre", "post"} <= have)
    digests = {item["stage"]: (item["record"] or {}).get("policy_sha256") for item in stages}
    checks("policy_digest_unchanged", bool(digests) and all(d == baseline_policy_sha256 for d in digests.values()), stop=True,
           digests=digests, baseline=baseline_policy_sha256)
    cadence = audits_v2.describe(stages, start_ns, end_ns, audit_interval_s)
    checks("audit_capture_instants_pinned_and_cadence_as_declared", not cadence["problems"], problems=cadence["problems"],
           declared_interval_s=audit_interval_s, periodic_count=cadence["periodic_count"])
    report["audit_cadence"] = cadence
    report["binding_audits"] = {item["stage"]: dict(ref=item["ref"], verdict=(item["record"] or {}).get("verdict"),
                                                    policy_sha256=(item["record"] or {}).get("policy_sha256")) for item in stages}

    # ---- publisher ledger vs the v2 plan -----------------------------------------------------------------------------------
    try:
        workload = v1._json(ledger_dir / "workload_summary.json")
        ledger = {d: v1._jsonl(ledgers[d]) for d in devices}
    except (OSError, ValueError) as exc:
        checks("publisher_evidence_readable", False, error=type(exc).__name__)
        return v1._close(report, checks)
    checks("workload_complete", workload.get("state") == "COMPLETE" and workload.get("failure_code") is None
           and workload.get("run_id") == run_id and workload.get("workload_config_sha256") == plans.digest(config)
           and workload.get("generator_version") == v2.GENERATOR_VERSION and workload.get("observer_session_id") == session.name
           and workload.get("purpose") == purpose, state=workload.get("state"), failure=workload.get("failure_code"))
    attempts, pubacks, plan_ok, outcomes_ok, planned_counts = {}, {}, True, True, {}
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
        expected = v2.schedule(config, device)
        planned_counts[device] = len(expected)
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
    checks("ledger_matches_frozen_plan", plan_ok, planned=planned_counts, attempted={d: len(attempts[d]) for d in devices})
    denied = sum(1 for d in devices for a in pubacks[d].values() if (a.get("puback_reason") or 0) >= 128)
    checks("publisher_outcomes_accepted", outcomes_ok, stop=denied > 0, denied=denied)
    terminations = {d: v2.termination_report(config, d, list(attempts[d].values())) for d in devices}
    verdicts = {d: t["verdict"] for d, t in terminations.items()}
    checks("termination_complete", all(v == "TERMINATION_OK" for v in verdicts.values()), verdicts=verdicts,
           experiment_completion={d: t["experiment_completion"] for d, t in terminations.items()})
    if any(v == "POST_ROLL_INCOMPLETE" for v in verdicts.values()):
        report["review_flags"].append("POST_ROLL_INCOMPLETE: eligible windows are intact but a controller decision is required")

    # ---- receipt correlation ------------------------------------------------------------------------------------------------
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
            if not (event["topic"] == topic_of[device] and event["bound_device"] == device and event["disposition"] == "COUNTED"
                    and first_eligible <= event["window_index"] <= post_last):   # eligible windows or the post-roll, never the lead-in
                misplaced.append(f"{device}:{sequence}")
    checks("receipt_reconciled", not unmatched and not misplaced, unmatched=unmatched[:20], misplaced=misplaced[:20],
           unmatched_count=len(unmatched), misplaced_count=len(misplaced))
    foreign = [e["record_seq"] for e in events if e["payload_sha256"] not in ledger_hashes]
    checks("no_foreign_events", not foreign, stop=bool(foreign), foreign_record_seqs=foreign[:20], count=len(foreign))
    dup_events = [e for e in events if e["dup"]]
    dup_only = [e["record_seq"] for e in dup_events if not any(not other["dup"] for other in by_hash.get(e["payload_sha256"], []))]
    checks("duplicates_reconciled", not dup_only, dup_flagged=len(dup_events), dup_only_record_seqs=dup_only[:20])
    counted = {d: sum(1 for e in events if e["disposition"] == "COUNTED" and e["bound_device"] == d) for d in devices}
    window_sum = {d: sum(r["measures"]["delivered_count"]["value"] or 0 for r in windows if r["device"] == d) for d in devices}
    lead_in_nonempty = [f'{r["device"]}:{r["window"]["index"]}' for r in windows
                        if r["window"]["index"] < first_eligible and r["qc"]["counted_events_raw"]]
    post_roll_counts = {d: sum(r["qc"]["counted_events_raw"] for r in windows if r["device"] == d and post_first <= r["window"]["index"] <= post_last)
                        for d in devices}
    checks("participation_as_planned",
           all(counted[d] == len(attempts[d]) == window_sum[d] > 0 for d in devices) and not lead_in_nonempty
           and all(post_roll_counts[d] > 0 for d in devices) and sorted(e.device for e in registry.devices) == devices,
           counted=counted, window_sum=window_sum, lead_in_nonempty=lead_in_nonempty, post_roll_counts=post_roll_counts)

    # ---- manifest / plan binding (COLLECTION) -------------------------------------------------------------------------------
    if purpose == "COLLECTION":
        try:
            state = manifest_v2.validate(manifest_v2.read_entries(manifest_path))
            plans.check_manifest_against_plan(state, plan)
            planned = state["planned"][run_id]
            observer_att = meta.get("collection_attestation") or {}
            workload_att = workload.get("attestation") or {}
            ok = (run_id not in state["collected"] and run_id not in state["voided"]
                  and planned["workload_config_sha256"] == plans.digest(config)
                  and observer_att.get("planned_entry_sha256") == planned["entry_sha256"] == workload_att.get("planned_entry_sha256")
                  and observer_att.get("manifest_sha256") == workload_att.get("manifest_sha256")
                  and observer_att.get("git_commit") == workload_att.get("git_commit") == meta["runtime"].get("git_commit")
                  and meta["runtime"].get("git_state") == "clean" and plan["approval_status"] == "APPROVED")
            checks("manifest_plan_matches_run", ok, observer_manifest_sha256=observer_att.get("manifest_sha256"),
                   workload_manifest_sha256=workload_att.get("manifest_sha256"), git_commit=observer_att.get("git_commit"),
                   approval_status=plan["approval_status"])
        except (manifest_module.ManifestError, ValueError, KeyError, OSError) as exc:
            checks("manifest_plan_matches_run", False, error=str(exc)[:200])

    # ---- descriptive timing QC (eligible windows; post-roll counts reported separately) ------------------------------------
    timing = {}
    for device in devices:
        rows = [attempts[device][s] for s in sorted(attempts[device])]
        gaps = [(b["attempt_offset_ns"] - a["attempt_offset_ns"]) / 1e6 for a, b in zip(rows, rows[1:])]
        late = [(r["attempt_offset_ns"] - r["scheduled_offset_ns"]) / 1e6 for r in rows]
        ack = [(pubacks[device][s]["puback_offset_ns"] - attempts[device][s]["attempt_offset_ns"]) / 1e6
               for s in attempts[device] if s in pubacks[device]]
        received = sorted(e["receive_offset_ns"] for e in events if e["disposition"] == "COUNTED" and e["bound_device"] == device)
        delivery, delivery_mono = [], []
        stamp_basis = sorted({r.get("attempt_utc_basis", "WALL_CLOCK_AFTER_PUBLISH_LEGACY") for r in rows})
        for record in rows:
            match = [e for e in by_hash.get(record["payload_sha256"], []) if not e["dup"]]
            if match:
                delivery.append((utc_to_epoch_ns(match[0]["receive_utc"]) - utc_to_epoch_ns(record["attempt_utc"])) / 1e6)
                if type(summary.get("coverage_start_offset_ns")) is int:   # same-kernel monotonic domain: no wall-clock stamp involved
                    delivery_mono.append(((match[0]["receive_offset_ns"] - summary["coverage_start_offset_ns"]) - record["attempt_offset_ns"]) / 1e6)
        counts_all = [r["measures"]["delivered_count"]["value"] for r in windows
                      if r["device"] == device and first_eligible <= r["window"]["index"] <= last_eligible]
        counts = [c for c in counts_all if c is not None]
        timing[device] = dict(
            profile=config["devices"][device]["profile"], nominal_gap_ms=config["devices"][device]["profile_definition"]["nominal_gap_ns"] / 1e6,
            publisher_attempt_gap_ms=v1.stats(gaps), schedule_lateness_ms=v1.stats(late), puback_latency_ms=v1.stats(ack),
            observer_interarrival_ms=v1.stats((b - a) / 1e6 for a, b in zip(received, received[1:])),
            delivery_latency_utc_ms=v1.stats(delivery), delivery_latency_monotonic_ms=v1.stats(delivery_mono),
            delivery_latency_negative_wall_count=sum(x < 0 for x in delivery), delivery_latency_negative_monotonic_count=sum(x < 0 for x in delivery_mono),
            attempt_utc_basis=stamp_basis, eligible_window_counts=v1.stats(counts),
            eligible_windows_below_3=sum(1 for c in counts if c < 3), eligible_windows_unavailable=len(counts_all) - len(counts),
            count_distribution={str(c): counts.count(c) for c in sorted(set(counts))}, post_roll_messages=post_roll_counts[device])
        if any(x < 0 for x in delivery_mono):   # never clamped or dropped: a negative monotonic latency means the clocks are inconsistent
            report["review_flags"].append(f"{device}: negative monotonic delivery latency (min {min(delivery_mono):.3f} ms)")
        if stamp_basis == ["WALL_CLOCK_BEFORE_PUBLISH"] and any(x < 0 for x in delivery):
            report["review_flags"].append(f"{device}: negative wall-clock delivery latency despite pre-publish stamps (min {min(delivery):.3f} ms)")
        if late and max(late) * 1e6 >= review_scale_ns:
            report["review_flags"].append(f"{device}: publisher schedule lateness {max(late):.1f} ms >= review scale")
    beats = [r["details"] for r in health if r["kind"] == "HEARTBEAT"]
    timing["observer"] = dict(close_lag_ms=v1.stats(b["close_lag_ns"] / 1e6 for b in beats),
                              max_loop_gap_ms=v1.stats(b["max_loop_gap_ns"] / 1e6 for b in beats), heartbeats=len(beats))
    for key in ("close_lag_ns", "max_loop_gap_ns"):
        worst = max((b[key] for b in beats), default=0)
        if worst >= review_scale_ns:
            report["review_flags"].append(f"observer {key} {worst / 1e6:.1f} ms >= review scale")
    report["timing"] = timing
    return v1._close(report, checks)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--purpose", required=True, choices=("FUNCTIONAL_TEST", "COLLECTION"))
    parser.add_argument("--baseline-policy-sha256", required=True)
    parser.add_argument("--audit-interval-s", required=True, type=int,
                        help="the cadence DECLARED for this run's periodic read-only audits in seconds (0 = pre/post only); no default")
    parser.add_argument("--manifest")
    parser.add_argument("--observer-session-id", help="required for COLLECTION: the ONLY session directory that is opened")
    parser.add_argument("--registry", default="/app/configs/observation/device_registry.json")
    parser.add_argument("--root", default="/results")
    args = parser.parse_args(argv)
    try:
        registry = DeviceRegistry.load(args.registry)
        plan = plans_v2.validate_plan_v2(plans.load_plan(args.plan), registry)
        if args.run_id not in plan["runs"]:
            raise ValueError("run is not in the plan")
        if (args.purpose == "COLLECTION") != bool(args.manifest):
            raise ValueError("COLLECTION reconciliation needs the manifest; FUNCTIONAL_TEST must not use one")
        if args.purpose == "COLLECTION" and not args.observer_session_id:
            raise ValueError("COLLECTION reconciliation needs --observer-session-id: sessions are never discovered by scanning the evidence root")
        report = reconcile(root=args.root, run_id=args.run_id, plan=plan, registry=registry, purpose=args.purpose,
                           baseline_policy_sha256=args.baseline_policy_sha256, audit_interval_s=args.audit_interval_s,
                           manifest_path=args.manifest, observer_session_id=args.observer_session_id)
        path = v1.write_report(args.root, args.run_id, report)
    except (ValueError, OSError, KeyError) as exc:
        print(f"RECONCILE_V2_ERROR {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(f'RECONCILIATION_V2 {args.run_id} verdict={report["verdict"]} campaign_stop={report["campaign_stop"]} '
          f'reasons={",".join(report["reasons"]) or "none"} review_flags={len(report["review_flags"])} report={path}')
    return 0 if report["verdict"] == "ACCEPT" else 3 if report["campaign_stop"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
