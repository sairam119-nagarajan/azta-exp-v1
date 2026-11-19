"""Stabilization requirement 5: are the long observation windows of the sparse devices necessary? Read only, on the TRAIN runs g6c-d01..d03 (benign, already used to fit these models).

    python -B -I rehearsal_tools/stb_window_review.py --out results/engineering/stabilization/window_review.json

For devices 06-09: the measured benign reporting interval (inter-delivery gaps at the observer), and, for every candidate width, the share of benign windows that are SCORE-READY under
the unchanged six-feature schema (`hybrid.windows.classify`: every predictor must have a value, which needs enough deliveries inside the window). The deployed width was chosen by the
frozen rule "shortest width with a score-ready share of at least 0.95 on TRAIN, VAL and CAL" (docs/gate6c/GATE_6C_STAGES2_4_HYBRID.md). A shorter width also changes the model input
distribution (counts, gaps and age per window), so the existing weights and calibration would not apply to it: any change needs retraining, which this campaign does not authorize.
No calibration, development-evaluation, TEST or CAL5 run is opened.
"""
import argparse
import json
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from hybrid import events as ev, windows as hw     # noqa: E402

NS = 1_000_000_000
TRAIN = ("g6c-d01", "g6c-d02", "g6c-d03")
DEVICES = {"device06": 20, "device07": 20, "device08": 90, "device09": 180}
WIDTHS = (10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 120, 150, 180)
N_CONFIRM = 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    assignment = ev.load_prelive_assignment()
    runs = [ev.load_run(r, assignment) for r in TRAIN]
    out = {}
    for device, deployed in DEVICES.items():
        gaps = []
        for run in runs:
            rows = [o for o, _ in run.events.get(device, []) if run.usable_first_ns <= o < run.usable_last_ns]
            gaps += [(b - a) / NS for a, b in zip(rows, rows[1:])]
        ordered = sorted(gaps)
        shares, reasons = {}, {}
        for width in WIDTHS:
            windows = [w for run in runs for w in hw.rewindow(None, device, run, width * NS)]
            ready = sum(w.ready for w in windows)
            shares[width] = round(ready / len(windows), 4) if windows else None
            counts = {}
            for w in windows:
                if not w.ready:
                    counts[w.reason] = counts.get(w.reason, 0) + 1
            reasons[width] = counts
        rule = min((w for w in WIDTHS if shares[w] is not None and shares[w] >= 0.95), default=None)
        out[device] = dict(deployed_width_s=deployed, reporting_gap_s=dict(n=len(gaps), median=statistics.median(gaps), mean=statistics.fmean(gaps), p95=ordered[int(0.95 * (len(ordered) - 1))], max=ordered[-1], min=ordered[0]),
                           score_ready_share_by_width_s=shares, not_ready_reasons_by_width_s=reasons, shortest_width_meeting_the_0_95_rule_on_train=rule,
                           deliveries_per_deployed_window=deployed / statistics.fmean(gaps),
                           confirmation_floor_s=dict(observation=N_CONFIRM * deployed, note="N = 2 consecutive anomalous windows: an anomaly starting at a window boundary is confirmed no earlier than two complete windows; one starting inside a window waits for that window to end as well (up to one more window)"))
        print(device, "deployed", deployed, "gap median", round(out[device]["reporting_gap_s"]["median"], 2), "max", round(ordered[-1], 2), "rule ->", rule, "shares", shares)
    record = dict(schema="azta.stabilization.window_review", runs=list(TRAIN), role="TRAIN (read only)", devices=out)
    if args.out:
        path = ROOT / args.out
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(record, stream, indent=1, sort_keys=True)
            stream.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
