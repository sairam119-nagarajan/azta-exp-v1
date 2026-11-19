"""UTC text for exact integer nanoseconds (the inverse of `trust.timeline.parse_utc_ns`, with nine fractional digits so the round trip is exact)."""
from datetime import datetime, timezone

from trust.timeline import parse_utc_ns


def utc_text(ns):
    if type(ns) is not int or ns < 0:
        raise ValueError("a non-negative integer number of nanoseconds is required")
    seconds, rest = divmod(ns, 1_000_000_000)
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + f".{rest:09d}Z"


def round_trips(ns):
    return parse_utc_ns(utc_text(ns)) == ns
