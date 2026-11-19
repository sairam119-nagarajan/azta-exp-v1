"""The read-only RC-1 connection provider of the maintained runtime: a `family.connection_live.LiveFeed` filled by a follower thread, behind the provider interface of `HybridBehaviorEvaluator`.

Until the feed exists, or whenever its status is not OK, nothing is explained: the evidence stays plain, never healthy. The monitor path asks about items stamped on the observer's anchored UTC timeline (`window_end_utc_ns`), the plain path about
window offsets; the provider maps the first onto the second through the feed's own health points, so one clock relation serves both. It is off by default: `--rc1-live` turns it on, and a deployment needs the live verification first.
The follower reads the broker's log output and the observer's files; it holds no credential and writes nothing to either.
"""
from dataclasses import replace
import json
from pathlib import Path
import subprocess
import threading
import time

from family import connection as fc, connection_live as cl


class Tail:
    """Complete new lines of a growing file (a partial last line waits for its newline)."""

    def __init__(self, path):
        self.path, self.pos, self.rest = Path(path), 0, b""

    def lines(self):
        if not self.path.exists():
            return []
        with self.path.open("rb") as stream:
            stream.seek(self.pos)
            data = stream.read()
        self.pos += len(data)
        *complete, self.rest = (self.rest + data).split(b"\n")
        return [line.decode("utf-8", errors="replace") for line in complete if line.strip()]


class LiveConnection:
    def __init__(self, now=time.monotonic_ns):
        self.feed, self.now = None, now

    def attach(self, feed):
        self.feed = feed

    def explains(self, device, start_ns, end_ns):
        return bool(self.feed and self.feed.provider(self.now()).explains(device, start_ns, end_ns))

    def filter_items(self, device, items):
        items = list(items)
        feed = self.feed
        if feed is None or not items or not feed.clock.utc:
            return items
        offset = feed.clock.to_offset
        if feed.status(self.now(), max(offset(i.observed_ns) for i in items)) != "OK" or device not in feed.identities:
            return items
        explainer = feed.explainer(device)
        return [replace(i, a=None, reason=fc.REASON) if i.a is not None and explainer.explains(None if i.start_ns is None else offset(i.start_ns), offset(i.observed_ns)) else i for i in items]


class Follower:
    """One thread: `docker logs --follow --timestamps --since <lead-in>` of the named broker container and tails of the observer session's files. A stop request ends it; the feed judges the EOF."""

    def __init__(self, session_directory, container, connection, *, poll_s=1.0, status_path=None):
        self.directory, self.container, self.connection, self.poll_s, self.status_path = Path(session_directory), container, connection, poll_s, status_path
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True, name="rc1-follower")

    def start(self):
        self.thread.start()

    def _run(self):
        meta = json.loads((self.directory / "session_metadata.json").read_text(encoding="utf-8"))
        feed = cl.LiveFeed(meta)
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        instance = subprocess.run(["docker", "inspect", "--format", "{{.Id}}", self.container], capture_output=True, text=True, creationflags=flags).stdout.strip()
        if not instance:
            feed.follower_failed("BROKER_CONTAINER_UNKNOWN")
        feed.follower_started(instance)
        self.connection.attach(feed)
        since = str(cl.utc_text_ns(meta["utc_start"]) // 1_000_000_000 - 30)
        process = subprocess.Popen(["docker", "logs", "--follow", "--timestamps", "--since", since, self.container], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=flags)
        assembler, lock = cl.LineAssembler(), threading.Lock()
        pending = []

        def pump():
            for raw in process.stdout:
                lines = assembler.feed(raw.decode("utf-8", errors="replace").replace("\r\n", "\n"))
                with lock:
                    pending.extend(lines)
            assembler.close()
        threading.Thread(target=pump, daemon=True).start()
        health, events = Tail(self.directory / "health.jsonl"), Tail(self.directory / "events.jsonl")
        try:
            while not self.stop.is_set():
                with lock:
                    batch, pending[:] = list(pending), []
                for line in batch:
                    feed.broker_line(line)
                now = self.connection.now()
                for line in health.lines():
                    feed.health_record(json.loads(line), now)
                for line in events.lines():
                    feed.event_record(json.loads(line))
                if process.poll() is not None and not feed.follower_eof:
                    feed.follower_stopped(f"docker logs exited rc={process.returncode}")
                if self.status_path is not None:
                    self._write_status(feed, now)
                self.stop.wait(self.poll_s)
        except (OSError, ValueError) as exc:
            feed.follower_failed(f"{type(exc).__name__}")
        finally:
            process.terminate()

    def _write_status(self, feed, now):
        body = dict(status=feed.status(now), lifecycle=feed.lifecycle(), anchor_verified=feed.anchor()[0], boundary_discards=feed.boundary_discards(), last_health_offset_ns=feed.clock.last_offset, broker_events=len(feed.events))
        temporary = Path(str(self.status_path) + ".tmp")
        temporary.write_text(json.dumps(body, sort_keys=True), encoding="utf-8")
        temporary.replace(self.status_path)
