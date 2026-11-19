"""Gate 5F.3 read-only identity-audit stages of a workload-v2 run: discovery, capture intervals, cadence description. Offline, evidence-reading.

A run has two mandatory read-only binding audits, `pre` (before the workload) and `post` (after it), and, when the run declares a cadence,
periodic audits `p01`, `p02`, ... taken while the observer is covering. Every audit is a separate short-lived audit run `<run_id>-audit-<stage>`
whose `run_summary.json` carries `utc_start` and `utc_end`: those two instants are the ONLY capture times of the snapshot. v2 pins the summary
of every audit in the manifest (role `<audit role>_run_summary`), so identity freshness can be judged from pinned evidence. The snapshot
reads Dynamic Security state at some instant inside [utc_start, utc_end]; the conservative age is therefore measured from `utc_start`, and a
snapshot may be used for a decision only if its `utc_end` is not later than the decision instant.

Nothing here talks to a broker. The cadence is an explicit declaration (seconds, or 0 for pre/post only); no value is defaulted.
"""
import json
from pathlib import Path
import re

from trust.timeline import capture_interval_ns

STAGE = re.compile(r"(pre|post|p\d{2})\Z")
PERIODIC = re.compile(r"p\d{2}\Z")


def audit_ref(run_id, stage):
    return f"{run_id}-audit-{stage}"


def stage_dir(root, run_id, stage):
    if not STAGE.fullmatch(stage):
        raise ValueError(f"invalid audit stage {stage!r}")
    return Path(root) / audit_ref(run_id, stage)


def discover_stages(root, run_id):
    """Existing stages in time order: pre, p01.., post. Only directories of THIS run's own audit prefix are looked at."""
    names = {p.name[len(audit_ref(run_id, "")):] for p in Path(root).glob(audit_ref(run_id, "*")) if p.is_dir()}
    periodic = sorted(n for n in names if PERIODIC.fullmatch(n))
    return [s for s in ("pre", *periodic, "post") if s in names]


def _json(path):
    with Path(path).open(encoding="utf-8") as stream:
        return json.load(stream)


def load_stage(root, run_id, stage):
    directory = stage_dir(root, run_id, stage)
    try:
        record = _json(directory / "binding_audit.json")
    except (OSError, ValueError):
        record = None
    try:
        summary = _json(directory / "run_summary.json")
    except (OSError, ValueError):
        summary = None
    return dict(stage=stage, ref=audit_ref(run_id, stage), record=record, summary=summary)


def minimum_periodic_audits(coverage_ns, interval_s):
    """Fewest periodic audits a declared cadence implies: floor(coverage / interval) - 1 (one may be lost at the edges). 0 when no cadence."""
    if type(interval_s) is not int or interval_s < 0:
        raise ValueError("the audit cadence must be an explicit integer number of seconds (0 = pre/post only)")
    if interval_s == 0:
        return 0
    return max(0, coverage_ns // (interval_s * 1_000_000_000) - 1)


def describe(stages, coverage_start_ns, coverage_end_ns, interval_s):
    """Descriptive cadence report and the hard problems that make an audit set unusable (empty list = usable)."""
    problems, rows = [], []
    for item in stages:
        interval = capture_interval_ns(item["summary"])
        rows.append(dict(stage=item["stage"], ref=item["ref"], start_ns=interval[0] if interval else None,
                         end_ns=interval[1] if interval else None, duration_ms=round((interval[1] - interval[0]) / 1e6, 3) if interval else None))
        if interval is None:
            problems.append(f"{item['stage']}: run summary missing, incomplete or without capture instants")
    if coverage_start_ns is None or coverage_end_ns is None:
        problems.append("observer coverage instants are unavailable, so the audit cadence cannot be verified")
    timed = [r for r in rows if r["start_ns"] is not None]
    for first, second in zip(timed, timed[1:]):
        if second["start_ns"] < first["end_ns"]:
            problems.append(f"{second['stage']}: capture overlaps {first['stage']}")
    if timed and coverage_start_ns is not None and coverage_end_ns is not None:
        pre, post = next((r for r in timed if r["stage"] == "pre"), None), next((r for r in timed if r["stage"] == "post"), None)
        if pre and pre["end_ns"] > coverage_start_ns:
            problems.append("pre audit was not completed before observer coverage started")
        if post and post["start_ns"] < coverage_end_ns:
            problems.append("post audit started before observer coverage ended")
        for row in timed:
            if PERIODIC.fullmatch(row["stage"]) and not (coverage_start_ns <= row["start_ns"] and row["end_ns"] <= coverage_end_ns):
                problems.append(f"{row['stage']}: periodic audit lies outside observer coverage")
    periodic = [r for r in timed if PERIODIC.fullmatch(r["stage"])]
    coverage_ns = (coverage_end_ns - coverage_start_ns) if coverage_start_ns is not None and coverage_end_ns is not None else 0
    need = minimum_periodic_audits(coverage_ns, interval_s)
    if len(periodic) < need:
        problems.append(f"declared cadence {interval_s}s over {coverage_ns / 1e9:.0f}s implies at least {need} periodic audits, found {len(periodic)}")
    if interval_s == 0 and periodic:
        problems.append("periodic audits exist although no cadence was declared")
    gaps = [(b["start_ns"] - a["start_ns"]) / 1e9 for a, b in zip(timed, timed[1:])]
    return dict(declared_interval_s=interval_s, stages=rows, periodic_count=len(periodic), minimum_periodic_implied=need,
                max_gap_between_starts_s=max(gaps) if gaps else None,
                max_capture_duration_ms=max((r["duration_ms"] for r in rows if r["duration_ms"] is not None), default=None),
                problems=problems)
