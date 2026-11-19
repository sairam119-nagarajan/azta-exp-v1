"""Trusted broker-side denial feed for the PILOT broker: the evidence behind the `topic_profile` context criterion.

    python -m engineering.broker_events tail --container azta-pilot-broker-1 --ledger FILE --stop-file FILE [--margin-ms 1000] [--heartbeat-ms 500]

Why this source: an operation that the broker's ACL denies is invisible to the receive-only observer, and the publisher's own PUBACK code is attacker-controlled. The broker itself, however, logs
every denied operation with the AUTHENTICATED client id (Dynamic Security binds a client id to its credential; a payload field is never read). With `log_type all` the pilot broker writes
`Denied PUBLISH from <client id> (..., '<topic>', ...)` and, for subscriptions, `Received SUBSCRIBE from <client id>` followed by `<topic> (denied)`. This tool follows the broker container's log
read-only (`docker logs --follow`), keeps only those two kinds of line, and appends them to a hash-chained JSONL ledger. Nothing else is stored (no payload, no password), the broker is never
written to, and the original log stays in the container.

Coverage: absence of a denial is evidence only if the feed was actually reading. While the queue of unread log lines is empty the tool appends a COVERAGE record every `--heartbeat-ms` stating
`covered_through_utc_ns` = host time less `--margin-ms` (the declared upper bound on log delivery delay); a consumer treats the criterion as unavailable (never as conforming) when coverage does not
reach the end of the window. Event times are the Docker daemon's receive stamps (the same VM clock as the broker container); their offset to the host clock is bounded by the declared clock
tolerance of the live session, so an event within that tolerance of a window edge may be attributed to the neighbouring window. The ledger is evidence class ENGINEERING pilot telemetry.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading
import time

from shadow_live.context_events import GENESIS, LEDGER_VERSION, LedgerReader, docker_stamp_ns, entry_digest  # noqa: F401  (the pure reader lives with its only consumer; re-exported here)

PUBLISH = re.compile(r"^(\d+): Denied PUBLISH from (\S+) \(d\d+, q\d+, r\d+, m\d+, '([^']*)'")
SUBSCRIBE_HEADER = re.compile(r"^(\d+): Received SUBSCRIBE from (\S+)")
SUBSCRIBE_DENIED = re.compile(r"^(\d+): \t(.+) \(denied\)\s*$")
CLIENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


class LineParser:
    """Stateful: a SUBSCRIBE header applies to the `(denied)` lines that follow it. Returns a list of events for each docker line."""

    def __init__(self):
        self.subscriber = None

    def feed(self, docker_line):
        line = docker_line.rstrip("\r\n")
        stamp, _, rest = line.partition(" ")
        try:
            utc_ns = docker_stamp_ns(stamp)
        except ValueError:
            return []
        match = PUBLISH.match(rest)
        if match and CLIENT_ID.fullmatch(match.group(2)):
            self.subscriber = None
            return [dict(kind="DENIED_PUBLISH", client_id=match.group(2), topic=match.group(3), broker_epoch_s=int(match.group(1)), utc_ns=utc_ns)]
        header = SUBSCRIBE_HEADER.match(rest)
        if header:
            self.subscriber = header.group(2) if CLIENT_ID.fullmatch(header.group(2)) else None
            return []
        denied = SUBSCRIBE_DENIED.match(rest)
        if denied and self.subscriber:
            return [dict(kind="DENIED_SUBSCRIBE", client_id=self.subscriber, topic=denied.group(2), broker_epoch_s=int(denied.group(1)), utc_ns=utc_ns)]
        if not rest.startswith(f"{rest.split(':', 1)[0]}: \t"):
            self.subscriber = None
        return []


class LedgerWriter:
    def __init__(self, path):
        self.path = Path(path)
        self.seq, self.prev = 0, GENESIS
        if self.path.exists():
            raise FileExistsError("a broker-event ledger is never reopened or overwritten")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.stream = open(self.path, "x", encoding="utf-8", newline="\n")

    def append(self, **fields):
        self.seq += 1
        body = dict(v=LEDGER_VERSION, seq=self.seq, prev=self.prev, **fields)
        body["sha256"] = entry_digest(body)
        self.prev = body["sha256"]
        self.stream.write(json.dumps(body, sort_keys=True) + "\n")
        self.stream.flush()
        return body

    def close(self):
        self.stream.close()


def tail(container, ledger, stop_file, *, margin_ms=1000, heartbeat_ms=500, runner=subprocess.Popen, now_ns=time.time_ns):
    writer = LedgerWriter(ledger)
    since = datetime.fromtimestamp(now_ns() / 1e9, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    writer.append(kind="START", container=container, utc_ns=now_ns(), margin_ms=margin_ms, heartbeat_ms=heartbeat_ms, feed="docker logs --follow --timestamps (read-only)")
    process = runner(["docker", "logs", "--follow", "--timestamps", "--since", since, container], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
    lines = queue.Queue()

    def reader():
        for text in process.stdout:
            lines.put(text)
        lines.put(None)
    threading.Thread(target=reader, daemon=True).start()
    parser, last_beat, counts = LineParser(), 0.0, dict(denied_publish=0, denied_subscribe=0, lines=0)
    ended = "STOP_FILE"
    try:
        while not Path(stop_file).exists():
            try:
                text = lines.get(timeout=heartbeat_ms / 2000)
            except queue.Empty:
                text = ""
            if text is None:
                ended = "LOG_STREAM_ENDED"
                break
            if text:
                counts["lines"] += 1
                for event in parser.feed(text):
                    writer.append(**event)
                    counts["denied_publish" if event["kind"] == "DENIED_PUBLISH" else "denied_subscribe"] += 1
            if lines.empty() and time.monotonic() - last_beat >= heartbeat_ms / 1000:       # every line that has arrived has been processed (also while the log is busy)
                current = now_ns()
                writer.append(kind="COVERAGE", utc_ns=current, covered_through_utc_ns=current - margin_ms * 10**6)
                last_beat = time.monotonic()
    finally:
        writer.append(kind="END", utc_ns=now_ns(), reason=ended, counts=counts)
        try:
            process.terminate()
        except OSError:
            pass
        writer.close()
    return counts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    t = sub.add_parser("tail")
    t.add_argument("--container", required=True)
    t.add_argument("--ledger", required=True)
    t.add_argument("--stop-file", required=True)
    t.add_argument("--margin-ms", type=int, default=1000)
    t.add_argument("--heartbeat-ms", type=int, default=500)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"azta-pilot-broker-\d+", args.container):
        print("REFUSED the feed follows only the pilot broker container", file=sys.stderr)
        return 2
    print(json.dumps(tail(args.container, args.ledger, args.stop_file, margin_ms=args.margin_ms, heartbeat_ms=args.heartbeat_ms)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
