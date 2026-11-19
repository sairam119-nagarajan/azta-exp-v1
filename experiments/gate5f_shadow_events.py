"""Shadow decision records -> dashboard events (JSONL). The only I/O around the pure converter in trust/demo_events.py.

    python -m experiments.gate5f_shadow_events convert --decisions results/gate5f/RUN/decisions.jsonl --out results/gate5f/RUN/events.jsonl

The output file is created exclusively (never overwritten), every event is validated before it is written, and nothing is connected or
changed: the events restate counterfactual proposals, marked as not applied, with restoration manual.
"""
import argparse
import json
from pathlib import Path
import sys

from trust.demo_events import decision_to_event, validate_event


def convert(decisions_path, out_path):
    events = []
    for number, line in enumerate(Path(decisions_path).read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue
        event = decision_to_event(json.loads(line), sequence=len(events))
        problems = validate_event(event)
        if problems:
            raise ValueError(f"line {number + 1}: event would be dishonest: {problems}")
        events.append(event)
    blob = "".join(json.dumps(e, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n" for e in events).encode("utf-8")
    with open(out_path, "xb") as stream:
        stream.write(blob)
    return len(events)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    cmd = sub.add_parser("convert")
    cmd.add_argument("--decisions", required=True)
    cmd.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        count = convert(args.decisions, args.out)
    except (OSError, ValueError, KeyError) as exc:
        print(f"SHADOW_EVENTS_REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(f"SHADOW_EVENTS events={count} enforcement=NONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
