"""Gate 5C runtime-integrity QC for one finalized run (controller decision after the g5c-r03 standby incident).

Host-side and read-only over evidence: compares the observer session's wall-clock (UTC) elapsed time with
its run-clock (monotonic offset) elapsed time, lists heartbeat/ledger gaps, and checks whether a confirmed
Windows Modern Standby/sleep interval overlapped the session (System log, Kernel-Power /
Power-Troubleshooter events; no administrator rights). It writes only its own exclusive report.

Verdicts (controller rules, 17 October 2026):
  STANDBY_OVERLAP  confirmed standby/sleep overlapped the run: the run is not counted scientifically
  QC_REVIEW        wall_minus_run_elapsed > 5 s without a confirmed standby event, or standby events
                   unavailable: pause before the next run and report; never an automatic invalidation
  CLEAN            otherwise; small clock/scheduling differences stay descriptive
This is an infrastructure-integrity check, not a model or detector criterion; it tunes nothing.
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys

REPORT_SCHEMA = "azta.collection.runtime_integrity"
REVIEW_EXCESS_S = 5.0
GAP_REPORT_S = 1.0
ENTER_EVENTS = {("Microsoft-Windows-Kernel-Power", 506), ("Microsoft-Windows-Kernel-Power", 42)}
EXIT_EVENTS = {("Microsoft-Windows-Kernel-Power", 507), ("Microsoft-Windows-Kernel-Power", 107),
               ("Microsoft-Windows-Power-Troubleshooter", 1)}
LOOKBACK = timedelta(minutes=30)


def parse_utc(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)


def _jsonl(path):
    with Path(path).open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def clock_integrity(health):
    """Wall vs run elapsed from SESSION_START to SESSION_END (or the last health record)."""
    start = next(r for r in health if r["kind"] == "SESSION_START")
    end = next((r for r in health if r["kind"] == "SESSION_END"), health[-1])
    wall = (parse_utc(end["utc"]) - parse_utc(start["utc"])).total_seconds()
    run = (end["offset_ns"] - start["offset_ns"]) / 1e9
    gaps = []
    for a, b in zip(health, health[1:]):
        excess = (parse_utc(b["utc"]) - parse_utc(a["utc"])).total_seconds() - (b["offset_ns"] - a["offset_ns"]) / 1e9
        if excess > GAP_REPORT_S:
            gaps.append(dict(from_utc=a["utc"], to_utc=b["utc"], from_offset_s=a["offset_ns"] / 1e9,
                             to_offset_s=b["offset_ns"] / 1e9, excess_s=round(excess, 3)))
    return dict(start_utc=start["utc"], end_utc=end["utc"], session_end_seen=end["kind"] == "SESSION_END",
                wall_clock_elapsed_s=round(wall, 3), run_clock_elapsed_s=round(run, 3),
                wall_minus_run_elapsed_s=round(wall - run, 3), heartbeat_gaps=gaps)


def ledger_integrity(rows):
    attempts = [r for r in rows if r.get("record_type") == "ATTEMPT"]
    worst = None
    for a, b in zip(attempts, attempts[1:]):
        excess = ((parse_utc(b["attempt_utc"]) - parse_utc(a["attempt_utc"])).total_seconds()
                  - (b["attempt_offset_ns"] - a["attempt_offset_ns"]) / 1e9)
        if worst is None or excess > worst["excess_s"]:
            worst = dict(from_sequence=a["sequence"], to_sequence=b["sequence"], from_utc=a["attempt_utc"],
                         to_utc=b["attempt_utc"], excess_s=round(excess, 3))
    return dict(attempts=len(attempts), max_consecutive_excess=worst)


def standby_overlap(events, start_utc, end_utc):
    """events: [{utc, provider, id, message}] sorted or not. Overlap if an enter event falls inside the
    run, or the last power transition before the run start was an enter (still suspended)."""
    start, end = parse_utc(start_utc), parse_utc(end_utc)
    ordered = sorted(events, key=lambda e: parse_utc(e["utc"]))
    inside = [e for e in ordered if start <= parse_utc(e["utc"]) <= end and (e["provider"], e["id"]) in ENTER_EVENTS]
    before = [e for e in ordered if parse_utc(e["utc"]) < start
              and (e["provider"], e["id"]) in ENTER_EVENTS | EXIT_EVENTS]
    suspended_at_start = bool(before) and (before[-1]["provider"], before[-1]["id"]) in ENTER_EVENTS
    return dict(overlap=bool(inside) or suspended_at_start, enter_events_in_run=inside,
                suspended_at_start=suspended_at_start)


def evaluate(clock, power_events):
    if power_events is None:
        standby = dict(overlap=None, enter_events_in_run=[], suspended_at_start=None)
    else:
        standby = standby_overlap(power_events, clock["start_utc"], clock["end_utc"])
    if standby["overlap"]:
        verdict, reason = "STANDBY_OVERLAP", "confirmed Windows standby/sleep overlapped the run"
    elif power_events is None:
        verdict, reason = "QC_REVIEW", "Windows power events unavailable; standby absence not confirmed"
    elif clock["wall_minus_run_elapsed_s"] > REVIEW_EXCESS_S:
        verdict, reason = "QC_REVIEW", f"wall_minus_run_elapsed > {REVIEW_EXCESS_S} s without a confirmed standby event"
    else:
        verdict, reason = "CLEAN", "no standby overlap; clock difference descriptive only"
    return verdict, reason, standby


def windows_power_events(start_utc, end_utc):
    """Kernel-Power / Power-Troubleshooter System-log events around the run; None if unavailable."""
    start = (parse_utc(start_utc) - LOOKBACK).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = (parse_utc(end_utc) + timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    script = (
        f"$s=[datetime]::Parse('{start}').ToUniversalTime().ToLocalTime(); "
        f"$e=[datetime]::Parse('{end}').ToUniversalTime().ToLocalTime(); "
        "$r=@(Get-WinEvent -FilterHashtable @{LogName='System'; "
        "ProviderName=@('Microsoft-Windows-Kernel-Power','Microsoft-Windows-Power-Troubleshooter'); "
        "Id=@(1,42,107,506,507); StartTime=$s; EndTime=$e} -ErrorAction SilentlyContinue | ForEach-Object { "
        "[pscustomobject]@{utc=$_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.ffffffZ'); "
        "provider=$_.ProviderName; id=$_.Id; message=(($_.Message -split [Environment]::NewLine)[0])} }); "
        "ConvertTo-Json -InputObject $r -Compress")
    try:
        done = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                              capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if done.returncode != 0:
        return None
    text = done.stdout.strip() or "[]"
    try:
        value = json.loads(text)
    except ValueError:
        return None
    return value if isinstance(value, list) else [value]


def find_session(root, run_id):
    found = []
    for meta in sorted((Path(root) / "observation").glob("obs-*/session_metadata.json")):
        with meta.open(encoding="utf-8") as stream:
            if json.load(stream).get("collection_run_id") == run_id:
                found.append(meta.parent)
    if len(found) != 1:
        raise ValueError(f"expected exactly one observer session for {run_id}, found {len(found)}")
    return found[0]


def build_report(root, run_id, power_events_source=windows_power_events):
    root = Path(root)
    session = find_session(root, run_id)
    clock = clock_integrity(_jsonl(session / "health.jsonl"))
    ledgers = {p.stem.replace("ledger_", ""): ledger_integrity(_jsonl(p))
               for p in sorted((root / "collection" / run_id).glob("ledger_*.jsonl"))}
    events = power_events_source(clock["start_utc"], clock["end_utc"])
    verdict, reason, standby = evaluate(clock, events)
    return dict(schema=REPORT_SCHEMA, schema_version=1, run_id=run_id, observer_session_id=session.name,
                verdict=verdict, reason=reason, review_excess_threshold_s=REVIEW_EXCESS_S, clock=clock,
                ledgers=ledgers, standby=standby, power_events_available=events is not None,
                power_events=events if events is not None else [])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--root", default="results/raw")
    args = parser.parse_args(argv)
    try:
        report = build_report(args.root, args.run_id)
        out = Path(args.root) / "collection-runtime-qc" / args.run_id / "runtime_integrity.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
    except (ValueError, OSError, KeyError, StopIteration) as exc:
        print(f"RUNTIME_QC_ERROR {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    clock = report["clock"]
    print(f"RUNTIME_QC {args.run_id} verdict={report['verdict']} wall={clock['wall_clock_elapsed_s']}s "
          f"run={clock['run_clock_elapsed_s']}s wall_minus_run={clock['wall_minus_run_elapsed_s']}s "
          f"standby_events_in_run={len(report['standby']['enter_events_in_run'])} report={out.as_posix()}")
    return {"CLEAN": 0, "QC_REVIEW": 5, "STANDBY_OVERLAP": 6}[report["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
