"""Gate 5F measurement audit: decompose publisher-to-observer delivery latency for ONE functional or collection run directory.

Offline and read-only. It reads the publisher ledgers, the observer's events and session summary and the workload summary of the run root it
is given (an explicit path; no discovery of other runs) and writes a new JSON report. It never edits, clamps or drops an observation: the
original wall-clock figure is reported unchanged next to a monotonic-domain figure and the difference between them.

Definitions (all in milliseconds):
  wall_latency        observer `receive_utc` minus publisher `attempt_utc`            (the original reconciliation metric)
  monotonic_latency   (observer receive offset minus its coverage-start offset) minus publisher `attempt_offset_ns`
                      both stamps come from CLOCK_MONOTONIC of the same kernel (containers share one VM kernel); the publisher stamp is taken
                      before publish(); the observer stamp at callback entry. No wall clock is involved.
  stamp_skew          monotonic_latency minus wall_latency = (publisher wall-stamp lag after its monotonic stamp) minus (observer wall-stamp
                      lag after its monotonic offset), plus any wall-vs-monotonic divergence BETWEEN the two stamps (about 0 for a shared clock)
  wall_drift          how far the wall clock moved relative to the monotonic clock since the coverage start, per process and over the run

A negative wall latency with a positive monotonic latency is a wall-stamp placement/lag artifact, not a physical negative delay. The six
autoencoder features use neither `receive_utc` nor `attempt_utc` (see tests/test_gate5f_timing_instrumentation.py).

    python -m experiments.gate5f_latency_audit --run-root results/raw/functional/g5f-f01 --run-id g5f-f01 --out results/gate5f/latency_audit_g5f-f01.json
"""
import argparse
import json
from pathlib import Path
import statistics
import sys

from experiments.collection_workload import utc_to_epoch_ns

SCHEMA = "azta.gate5f.latency_audit"


def _lines(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def _stats(values):
    values = sorted(values)
    if not values:
        return dict(n=0)
    n = len(values)
    return dict(n=n, min=values[0], p05=values[n // 20], median=statistics.median(values), mean=statistics.fmean(values),
                p95=values[(n * 19) // 20], max=values[-1])


def _trend_ppm(points):
    """Divergence (parts per million) between the first and last tenth of (t_seconds, value_ms) points, or None."""
    points = sorted(points)
    if len(points) < 20:
        return None
    tenth = len(points) // 10
    head, tail = points[:tenth], points[-tenth:]
    dt = statistics.fmean(t for t, _ in tail) - statistics.fmean(t for t, _ in head)
    return None if dt <= 0 else (statistics.fmean(v for _, v in tail) - statistics.fmean(v for _, v in head)) / 1000.0 / dt * 1e6


def _quarters(rows):
    """Median stamp skew in each quarter of the observed time span (None for an empty quarter): a stable value shows no wall/monotonic drift effect."""
    if not rows:
        return [None] * 4
    low, high = min(r["t"] for r in rows), max(r["t"] for r in rows)
    width = (high - low) / 4 or 1.0
    out = []
    for q in range(4):
        part = [r["skew"] for r in rows if low + q * width <= r["t"] < low + (q + 1) * width or (q == 3 and r["t"] == high)]
        out.append(statistics.median(part) if part else None)
    return out


def decompose(run_root, run_id):
    root = Path(run_root)
    sessions = sorted(p for p in (root / "observation").iterdir() if p.is_dir())
    if len(sessions) != 1:
        raise ValueError("the run root must contain exactly one observer session")
    session = sessions[0]
    summary = json.loads((session / "session_summary.json").read_text(encoding="utf-8"))
    workload = json.loads((root / "collection" / run_id / "workload_summary.json").read_text(encoding="utf-8"))
    base = summary["coverage_start_offset_ns"]
    coverage_epoch = utc_to_epoch_ns(workload["coverage_start_utc"])
    by_hash = {}
    for event in _lines(session / "events.jsonl"):
        if not event["dup"]:
            by_hash.setdefault(event["payload_sha256"], event)
    rows, bases = [], set()
    for ledger in sorted((root / "collection" / run_id).glob("ledger_*.jsonl")):
        for record in _lines(ledger):
            if record.get("record_type") != "ATTEMPT":
                continue
            event = by_hash.get(record["payload_sha256"])
            if event is None:
                continue
            bases.add(record.get("attempt_utc_basis", "WALL_CLOCK_AFTER_PUBLISH_LEGACY"))
            wall = (utc_to_epoch_ns(event["receive_utc"]) - utc_to_epoch_ns(record["attempt_utc"])) / 1e6
            mono = ((event["receive_offset_ns"] - base) - record["attempt_offset_ns"]) / 1e6
            t = record["attempt_offset_ns"] / 1e9
            pub_div = (utc_to_epoch_ns(record["attempt_utc"]) - (coverage_epoch + record["attempt_offset_ns"])) / 1e6
            obs_div = (utc_to_epoch_ns(event["receive_utc"]) - (coverage_epoch + (event["receive_offset_ns"] - base))) / 1e6
            rows.append(dict(device=record["device"], t=t, wall=wall, mono=mono, skew=mono - wall, pub_div=pub_div, obs_div=obs_div))
    return dict(
        schema=SCHEMA, schema_version=1, run_id=run_id, observer_session_id=session.name, pairs=len(rows), attempt_stamp_basis=sorted(bases),
        wall_latency_ms=_stats([r["wall"] for r in rows]), monotonic_latency_ms=_stats([r["mono"] for r in rows]),
        stamp_skew_ms=_stats([r["skew"] for r in rows]),
        negative=dict(wall=sum(r["wall"] < 0 for r in rows), monotonic=sum(r["mono"] < 0 for r in rows)),
        negative_wall_pairs=[dict(device=r["device"], t_s=round(r["t"], 3), wall_ms=r["wall"], monotonic_ms=r["mono"], stamp_skew_ms=r["skew"])
                             for r in rows if r["wall"] < 0],
        stamp_skew_median_ms_per_quarter_of_run=_quarters(rows),
        wall_vs_monotonic_divergence=dict(
            publisher_ms=_stats([r["pub_div"] for r in rows]), observer_ms=_stats([r["obs_div"] for r in rows]),
            publisher_ppm=_trend_ppm([(r["t"], r["pub_div"]) for r in rows]), observer_ppm=_trend_ppm([(r["t"], r["obs_div"]) for r in rows])),
        interpretation=[
            "wall_latency is the original reconciliation metric and is reported unchanged; it is not clamped and no pair was removed",
            "monotonic_latency uses one kernel's monotonic clock on both sides and has no wall-clock stamp in it",
            "a negative wall_latency with a positive monotonic_latency means the publisher's wall stamp (taken after publish() in a legacy ledger) "
            "was later than the observer's receipt: a stamp-placement artifact in a sub-millisecond path",
            "the wall clock diverges slowly from the monotonic clock in both processes alike; this bounds the UTC mapping error used for audit ages"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run-root", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--out", required=True, help="new JSON file; never overwritten")
    args = parser.parse_args(argv)
    try:
        report = decompose(args.run_root, args.run_id)
        with Path(args.out).open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(report, indent=1, sort_keys=True, allow_nan=False) + "\n")
    except (OSError, ValueError, KeyError) as exc:
        print(f"LATENCY_AUDIT_REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(f"LATENCY_AUDIT {args.run_id} pairs={report['pairs']} negative_wall={report['negative']['wall']} "
          f"negative_monotonic={report['negative']['monotonic']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
