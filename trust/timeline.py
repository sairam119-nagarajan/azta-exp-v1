"""Pinned-timestamp helpers for authoritative evidence: UTC text to epoch nanoseconds, audit capture intervals, window-end instants.

Pure functions, no clock is read. The bundle clock used with real replays is UTC epoch nanoseconds (`UTC_EPOCH_NS`): an audit snapshot is
placed at its capture START (the conservative instant for age) and is usable only after its capture END; a window's decision instant is its
end, mapped from the observer's monotonic offsets to UTC through the observer's own COVERAGE_START record. The residual error of that
mapping is the wall-versus-run-clock difference, which the runtime-integrity QC already measures for every run; it is carried as an explicit
uncertainty by whoever chooses a freshness bound, never silently ignored.
"""
import calendar
import re

UTC_TEXT = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z\Z")
CLOCK_BASIS = "UTC_EPOCH_NS"


def parse_utc_ns(text):
    """'2026-10-16T21:44:51.964693Z' -> integer nanoseconds since the Unix epoch (UTC). Anything else is a ValueError."""
    match = UTC_TEXT.fullmatch(text) if isinstance(text, str) else None
    if not match:
        raise ValueError(f"not a UTC timestamp: {text!r}")
    year, month, day, hour, minute, second = (int(v) for v in match.groups()[:6])
    seconds = calendar.timegm((year, month, day, hour, minute, second, 0, 0, 0))
    fraction = (match.group(7) or "").ljust(9, "0")
    return seconds * 1_000_000_000 + int(fraction)


def capture_interval_ns(run_summary):
    """(start_ns, end_ns) of an audit capture from its COMPLETE run summary (`utc_start`, `utc_end`), else None. Never invented."""
    if not isinstance(run_summary, dict) or run_summary.get("state") != "COMPLETE":
        return None
    try:
        start, end = parse_utc_ns(run_summary["utc_start"]), parse_utc_ns(run_summary["utc_end"])
    except (KeyError, ValueError, TypeError):
        return None
    return (start, end) if 0 < start <= end else None


def window_end_utc_ns(coverage_start_utc, coverage_start_offset_ns, window):
    """UTC epoch nanoseconds of a Gate 5B window's end: coverage-start UTC plus the monotonic distance from the coverage start."""
    return parse_utc_ns(coverage_start_utc) + (window["window"]["end_offset_ns"] - coverage_start_offset_ns)


def identity_coverage(decision_instants_ns, snapshots, max_age_ns):
    """How many decisions have fresh, completed identity evidence under a candidate freshness bound.

    snapshots: [(capture_start_ns, capture_end_ns)] of read-only audits. For a decision instant t the usable snapshot is the latest one
    that has COMPLETED (end <= t); it is fresh when t - start <= max_age_ns (age is measured from the capture start, the conservative
    instant). Returns (covered, total, uncovered_instants). Pure arithmetic; it chooses no bound and no cadence.
    """
    uncovered = []
    for instant in decision_instants_ns:
        usable = [start for start, end in snapshots if end <= instant]
        if not usable or instant - max(usable) > max_age_ns:
            uncovered.append(instant)
    return len(decision_instants_ns) - len(uncovered), len(decision_instants_ns), uncovered


def minimum_bound_for_full_coverage(decision_instants_ns, snapshots):
    """The smallest freshness bound under which EVERY decision has fresh identity evidence, or None if some decision has no completed audit."""
    worst = 0
    for instant in decision_instants_ns:
        usable = [start for start, end in snapshots if end <= instant]
        if not usable:
            return None
        worst = max(worst, instant - max(usable))
    return worst
