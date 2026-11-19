"""Independent verification of FINISHED engineering live evidence (pre-push audit). Read-only; opens only one engineering run's own directories.

    python -m engineering.audit_verify --run-id ID [--live] [--out FILE]

It does not trust the components that produced the evidence; every check recomputes from raw bytes with its own code:
  windows      each emitted window of the observer session is recomputed from the raw event log with the Gate 5B contract's definitions (counted events of the bound device within
               [start, end), payload mean and SAMPLE SD (n-1), inter-arrival mean and sample SD of consecutive gaps, last-delivery age to the window end) and compared with the emitted
               record, including which measures are VALUE; the window grid and each counted event's window index are re-derived as well;
  models       the reconstruction loss of every decision record is recomputed with a numpy forward pass of the digest-pinned frozen weights (6 -> 8 -> k -> 8 -> 6) from the record's
               own feature vector, and that vector must equal the observer window's measures in the frozen feature order, for the device's own profile (device01 S, device02 V);
  identity     every decision's window names the run, session and device that the observer's events bind, and its identity evidence is a fresh positive broker-audit verdict bound to the
               device's own principal (no payload claim is consulted);
  continuous   (with --live) the supervised run: hash chains of the live ledger and the enforcement audit, the inbox as a byte-exact projection of the ledger outputs, the
               enforcement record sequence equal to the inbox sequence (no duplicate, missing or reordered record), every record refused for the missing approvals, no command,
               consumed cursor at the end of the inbox, the supervisor's start/restart/drain events, all binding audits PASS with one policy digest, reconciliation verdict.
Nothing is written except the optional report. Raw scientific evidence (results/raw) is never opened.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import statistics
import subprocess
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
FEATURES = ["delivered_count", "payload_bytes_mean", "payload_bytes_sd", "interarrival_mean_ms", "interarrival_sd_ms", "last_delivery_age_ms"]
PROFILE_OF = {"device01": "S", "device02": "V"}
FITS = ROOT / "results" / "gate5d" / "g5d2b-20261019-01" / "fits"
W_NS = 10_000_000_000


def jsonl(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def close(a, b, rel=1e-9, absolute=1e-9):
    return a is not None and b is not None and math.isclose(a, b, rel_tol=rel, abs_tol=absolute)


# ------------------------------------------------------------------------------------------------------------------ windows from raw events
def expected_measures(counted_offsets, sizes, window_end, earlier_last):
    """The contract's six measures for one device-window: {name: value or None (not a VALUE)}."""
    n = len(counted_offsets)
    out = dict(delivered_count=float(n))
    out["payload_bytes_mean"] = statistics.fmean(sizes) if n >= 1 else None
    out["payload_bytes_sd"] = statistics.stdev(sizes) if n >= 2 else None
    gaps = [(b - a) / 1e6 for a, b in zip(counted_offsets, counted_offsets[1:])]
    out["interarrival_mean_ms"] = statistics.fmean(gaps) if n >= 2 else None
    out["interarrival_sd_ms"] = statistics.stdev(gaps) if n >= 3 else None
    last = counted_offsets[-1] if n else earlier_last
    out["last_delivery_age_ms"] = (window_end - last) / 1e6 if last is not None else None
    return out


def check_windows(session_dir):
    events, windows = jsonl(session_dir / "events.jsonl"), jsonl(session_dir / "windows.jsonl")
    counted = {}
    for event in events:
        if event["disposition"] == "COUNTED":
            counted.setdefault(event["bound_device"], []).append(event)
    for device in counted:
        counted[device].sort(key=lambda e: e["receive_offset_ns"])
    start0 = min(w["window"]["start_offset_ns"] for w in windows)
    result = dict(windows=len(windows), complete=0, compared=0, mismatches=[], grid_errors=0, placement_errors=0, status_errors=0, unavailable_errors=0)
    for w in windows:
        device, k = w["device"], w["window"]["index"]
        s, e = w["window"]["start_offset_ns"], w["window"]["end_offset_ns"]
        if (s, e) != (start0 + k * W_NS, start0 + (k + 1) * W_NS) or w["window"]["duration_ns"] != W_NS:
            result["grid_errors"] += 1
        if w["coverage"]["state"] != "COMPLETE":
            result["unavailable_errors"] += sum(1 for m in FEATURES if w["measures"][m]["status"] != "OBSERVER_UNAVAILABLE")
            continue
        result["complete"] += 1
        mine = [ev for ev in counted.get(device, []) if s <= ev["receive_offset_ns"] < e]
        earlier = [ev["receive_offset_ns"] for ev in counted.get(device, []) if ev["receive_offset_ns"] < s]
        want = expected_measures([ev["receive_offset_ns"] for ev in mine], [ev["payload_bytes"] for ev in mine], e, max(earlier) if earlier else None)
        for ev in mine:
            if ev.get("window_index") != k:
                result["placement_errors"] += 1
        for name in FEATURES:
            got = w["measures"][name]
            is_value = got["status"] == "VALUE"
            if is_value != (want[name] is not None) or (got["value"] is None) == is_value:
                result["status_errors"] += 1
                result["mismatches"].append(dict(device=device, window=k, measure=name, kind="status", got=got["status"], expected_value=want[name]))
            elif is_value and not close(got["value"], want[name], rel=1e-9, absolute=1e-6):
                result["mismatches"].append(dict(device=device, window=k, measure=name, kind="value", got=got["value"], expected=want[name]))
            result["compared"] += 1
    result["ok"] = not (result["mismatches"] or result["grid_errors"] or result["placement_errors"] or result["status_errors"] or result["unavailable_errors"]) and result["complete"] > 0
    result["mismatches"] = result["mismatches"][:10]
    return result, {(w["device"], w["window"]["index"]): w for w in windows}


# ------------------------------------------------------------------------------------------------------------------ models
def load_fits():
    fits = {}
    for profile in ("S", "V"):
        directory = FITS / f"A-{profile}-k3-seed0"
        bundle = json.loads((directory / "bundle.json").read_text(encoding="utf-8"))
        weights = json.loads((directory / bundle["weights_file"]).read_text(encoding="utf-8"))
        assert hashlib.sha256((directory / bundle["weights_file"]).read_bytes()).hexdigest() == bundle["weights_sha256"]
        fits[profile] = (bundle, {n: np.asarray(s["data"], dtype=np.float64) for n, s in weights.items()})
    return fits


def reference_loss(fit, vector):
    bundle, w = fit
    z = (np.asarray(vector, dtype=np.float64) - np.asarray(bundle["scaler"]["mu"])) / np.asarray(bundle["scaler"]["s"])
    h = np.maximum(w["enc1.weight"] @ z + w["enc1.bias"], 0.0)
    d = np.maximum(w["dec1.weight"] @ (w["enc2.weight"] @ h + w["enc2.bias"]) + w["dec1.bias"], 0.0)
    return float(np.mean((w["out.weight"] @ d + w["out.bias"] - z) ** 2))


def check_decisions(records, windows, session_id, run_id):
    fits = load_fits()
    result = dict(decisions=0, losses_checked=0, loss_mismatches=[], feature_mismatches=[], route_errors=0, binding_errors=0, classes={}, routes={}, statuses={}, proposals=0)
    for record in records:
        if record.get("record_kind") != "SHADOW_DECISION":
            continue
        result["decisions"] += 1
        note = record["annotations"]["decision_pipeline"]
        ref = record["behavior"].get("window_ref") or {}
        device = ref.get("device")
        result["classes"][note["evidence"]["class"]] = result["classes"].get(note["evidence"]["class"], 0) + 1
        result["routes"][note["route"]["code"]] = result["routes"].get(note["route"]["code"], 0) + 1
        result["statuses"][record["status"]] = result["statuses"].get(record["status"], 0) + 1
        result["proposals"] += 1 if record["proposed_state"] is not None else 0
        if ref.get("collection_run_id") != run_id or ref.get("observer_session_id") != session_id or (device, ref.get("window_index")) not in windows:
            result["binding_errors"] += 1
            continue
        window = windows[(device, ref["window_index"])]
        if note["route"]["profile"] != PROFILE_OF.get(device) or note["inference"].get("model", {}).get("profile") != PROFILE_OF.get(device):
            result["route_errors"] += 1
        identity = record["identity"]
        principal = f"azta-device-{int(device[-2:]):02d}"       # the device's own principal, from the registry's naming, never from a payload
        if (identity.get("outcome"), identity.get("assessment"), identity.get("provenance")) != ("EVALUATED", "FRESH_AUTHORITATIVE_POSITIVE", "BROKER_POLICY_AUDIT") \
                or identity.get("bound_username") != principal or identity.get("bound_client_id") != principal or identity.get("s_id") != 100.0:
            result["identity_errors"] = result.get("identity_errors", 0) + 1
        vector = [window["measures"][name]["value"] for name in FEATURES]
        inference = note["inference"]
        if inference.get("features") != vector or record["behavior"].get("features") != vector:
            result["feature_mismatches"].append((device, ref["window_index"]))
        if inference.get("loss") is not None:
            expected = reference_loss(fits[PROFILE_OF[device]], vector)
            result["losses_checked"] += 1
            if not close(inference["loss"], expected, rel=1e-9, absolute=1e-12):
                result["loss_mismatches"].append(dict(device=device, window=ref["window_index"], got=inference["loss"], expected=expected))
    result.setdefault("identity_errors", 0)
    result["ok"] = (result["decisions"] > 0 and not (result["loss_mismatches"] or result["feature_mismatches"] or result["route_errors"] or result["binding_errors"]
                                                     or result["identity_errors"]) and result["losses_checked"] > 0)
    result["loss_mismatches"], result["feature_mismatches"] = result["loss_mismatches"][:5], result["feature_mismatches"][:5]
    return result


# ------------------------------------------------------------------------------------------------------------------ the supervised run
def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def check_pep_chain(entries):
    previous, errors = "0" * 64, 0
    for number, entry in enumerate(entries, 1):
        body = {k: v for k, v in entry.items() if k != "sha256"}
        if entry["seq"] != number or entry["prev_sha256"] != previous or hashlib.sha256(canonical(body).encode("utf-8")).hexdigest() != entry["sha256"]:
            errors += 1
        previous = entry["sha256"]
    return errors


def check_continuous(run_id, run_dir, session_id, early_stop=False):
    live_dir = ROOT / "results" / "engineering" / "live" / run_id
    service = run_dir / "service"
    sys.path.insert(0, str(ROOT))
    from rehearsal_tools import verify_ledgers
    from shadow_live.ledger import LiveLedger
    report = dict()
    ledger_report = verify_ledgers.verify(live_dir)
    report["live_ledger"] = dict(chain=ledger_report["chain"], entries=ledger_report.get("entries"), ended=ledger_report.get("ended"), ok=ledger_report.get("ok"))
    ledger = LiveLedger.open_existing(live_dir)
    outputs = [item for entry in ledger.entries if entry["kind"] in ("POLL", "SESSION_ENDED") for item in entry["body"]["outputs"]]
    expected_inbox = b"".join((canonical(o["record"]) + "\n").encode("utf-8") for o in outputs)
    inbox_bytes = (service / "inbox.jsonl").read_bytes()
    inbox = [json.loads(line) for line in inbox_bytes.decode("utf-8").splitlines()]
    end = ledger.of_kind("SESSION_ENDED")
    report["inbox"] = dict(records=len(inbox), byte_exact_projection_of_ledger_outputs=inbox_bytes == expected_inbox, ledger_outputs=len(outputs),
                           session_end_reason=end[0]["body"]["reason"] if end else None, evidence_ids_unique=len({r["evidence_id"] for r in inbox}) == len(inbox))
    pep = jsonl(run_dir / "pep" / "continuous.jsonl")
    handled = [e["body"] for e in pep if e["kind"] == "RECORD_HANDLED"]
    kinds = {}
    for e in pep:
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
    cursors = [e["body"] for e in pep if e["kind"] == "CURSOR"]
    reasons = sorted({str(h.get("reason")) for h in handled})
    report["pep_audit"] = dict(entries=len(pep), chain_errors=check_pep_chain(pep), kinds=kinds, handled=len(handled),
                               sequence_equals_inbox=[h["evidence_id"] for h in handled] == [r["evidence_id"] for r in inbox],
                               all_refused=all(h["disposition"] == "REFUSED" for h in handled), reasons=reasons,
                               no_command_or_outcome=not any(k in kinds for k in ("COMMAND_SENT", "COMMAND_RESULT", "OUTCOME", "REQUEST_RECEIVED", "PLAN")),
                               cursor_at_end=bool(cursors) and cursors[-1]["offset"] == len(inbox_bytes) and cursors[-1]["prefix_sha256"] == hashlib.sha256(inbox_bytes).hexdigest(),
                               runner_starts=kinds.get("RUNNER_STARTED", 0))
    supervisor = jsonl(service / "supervisor.jsonl")
    counts = {}
    for e in supervisor:
        key = e["kind"] + (":" + e["worker"] if "worker" in e else "")
        counts[key] = counts.get(key, 0) + 1
    stopped = [e for e in supervisor if e["kind"] == "SERVICE_STOPPED"]
    report["supervisor"] = dict(events=counts, drained=(counts.get("SERVICE_DRAINED", 0) == 1) or early_stop, stopped_clean=bool(stopped) and stopped[-1]["failed"] is False,
                                failed_events=counts.get("SERVICE_FAILED:adapter", 0) + counts.get("SERVICE_FAILED:pep", 0))
    audits = sorted(p for p in run_dir.glob(f"{run_id}-audit-*"))
    digests, verdicts = set(), []
    for p in audits:
        data = json.loads((p / "binding_audit.json").read_text(encoding="utf-8"))
        digests.add(data["policy_sha256"])
        verdicts.append(data["verdict"])
    report["audits"] = dict(count=len(audits), all_pass=all(v == "PASS" for v in verdicts), distinct_policy_digests=len(digests), digest=sorted(digests)[0][:16] if digests else None)
    if early_stop:       # an operator stop is NOT a completed observation: no reconciliation exists, every eligible window must be accounted, and nothing is claimed as ACCEPT
        reasons_seen = sorted({str(r["reason"]) for r in inbox if "reason" in r} | {str(r.get("reasons")) for r in inbox if r.get("record_kind") != "SHADOW_DECISION"})
        report["early_stop"] = dict(session_end_reason=report["inbox"]["session_end_reason"], total_outputs=len(outputs), accounted_all_120_eligible_windows=len(outputs) == 120,
                                    decisions=sum(1 for r in inbox if r.get("record_kind") == "SHADOW_DECISION"), other_records=sum(1 for r in inbox if r.get("record_kind") != "SHADOW_DECISION"),
                                    stop_requested=(run_dir / "service" / "REQUEST_STOP").exists(), run_containers_left=subprocess.run(
                                        ["docker", "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True, timeout=60).stdout.split())
        report["reconciliation"] = dict(verdict="NOT_APPLICABLE_EARLY_STOP", campaign_stop=False, review_flags=0, reasons=[])
    else:
        reconciliation = json.loads((run_dir / "collection" / run_id / "reconciliation.json").read_text(encoding="utf-8"))
        report["reconciliation"] = dict(verdict=reconciliation["verdict"], campaign_stop=reconciliation["campaign_stop"], review_flags=len(reconciliation["review_flags"]),
                                        reasons=reconciliation["reasons"])
    report["ok"] = bool(report["live_ledger"]["ok"] and report["inbox"]["byte_exact_projection_of_ledger_outputs"] and report["inbox"]["evidence_ids_unique"]
                        and report["pep_audit"]["chain_errors"] == 0 and report["pep_audit"]["sequence_equals_inbox"] and report["pep_audit"]["all_refused"]
                        and report["pep_audit"]["no_command_or_outcome"] and report["pep_audit"]["cursor_at_end"] and report["supervisor"]["drained"]
                        and report["supervisor"]["stopped_clean"] and report["audits"]["all_pass"] and report["audits"]["distinct_policy_digests"] == 1
                        and (early_stop or report["reconciliation"]["verdict"] == "ACCEPT") and not report["reconciliation"]["campaign_stop"])
    return report, inbox


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--live", action="store_true", help="also verify the supervised continuous service of this run")
    parser.add_argument("--early-stop", action="store_true", help="the run was stopped early by the operator: verify accounting and cleanup instead of completion")
    parser.add_argument("--decisions", help="decision file to check instead of the live ledger's (an offline replay of the same session)")
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    run_dir = ROOT / "results" / "engineering" / "runs" / args.run_id
    sessions = sorted(p for p in (run_dir / "observation").iterdir() if p.is_dir())
    if len(sessions) != 1:
        print(f"AUDIT_VERIFY_REFUSED expected exactly one observer session, found {len(sessions)}", file=sys.stderr)
        return 2
    session_id = sessions[0].name
    report = dict(run_id=args.run_id, session_id=session_id)
    report["windows"], windows = check_windows(sessions[0])
    records = None
    if args.live:
        report["continuous"], records = check_continuous(args.run_id, run_dir, session_id, early_stop=args.early_stop)
    elif args.decisions:
        records = jsonl(args.decisions)
    if records is not None:
        report["decisions"] = check_decisions(records, windows, session_id, args.run_id)
    report["ok"] = all(report[k]["ok"] for k in ("windows", "decisions", "continuous") if k in report)
    text = json.dumps(report, indent=1, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
