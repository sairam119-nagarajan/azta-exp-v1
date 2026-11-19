"""Append-only, hash-chained ledger of one live session: the durable record that makes the adapter restartable and its history tamper-evident.

Atomicity is the design. Every poll that changed anything is recorded as ONE entry (`POLL`) holding, together: the audit events, the window lines
received or refused, every output (decision or refusal) produced from them, the source position with its rolling digest, and a snapshot of the stream's
accounting. A line is appended and fsynced only after all of that exists, so a crash leaves the ledger either with the whole poll or without it. The
restarted adapter resumes from the last complete entry and re-reads the rest from the (verified) source: no window is ever decided twice and none is
lost; windows that were pending at the crash are simply read again, later, and their staleness is measured honestly.

Entries are never rewritten or deleted. Each carries the hash of the previous one; a gap, reorder, edit, a torn final line or a foreign schema is a fatal
integrity failure (fail closed). The ledger is the authority; `decisions.jsonl`, `timing.jsonl` and `summary.json` are exported views of it.
"""
import hashlib
import json
import os
from pathlib import Path

from observation.schema import canonical
from shadow_live.errors import LiveIntegrityFailure, LiveRefused

LEDGER_SCHEMA = "azta.gate5f.live_ledger"
LEDGER_FILE = "ledger.jsonl"
GENESIS = "0" * 64
KINDS = ("SESSION_DECLARED", "SESSION_ATTACHED", "POLL", "RESUMED", "SESSION_ENDED")
_KEYS = {"schema", "schema_version", "seq", "kind", "body", "prev_entry_sha256", "entry_sha256"}


def entry_hash(entry):
    return hashlib.sha256(canonical({k: v for k, v in entry.items() if k != "entry_sha256"}).encode("utf-8")).hexdigest()


class LiveLedger:
    def __init__(self, directory, entries):
        self.directory, self.path = Path(directory), Path(directory) / LEDGER_FILE
        self.entries = list(entries)

    @classmethod
    def create(cls, directory):
        """A new ledger in a new directory. An existing live session is never reused or overwritten."""
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=False)
        with open(directory / LEDGER_FILE, "xb"):
            pass
        return cls(directory, [])

    @classmethod
    def open_existing(cls, directory):
        path = Path(directory) / LEDGER_FILE
        try:
            blob = path.read_bytes()
        except OSError as exc:
            raise LiveRefused("LEDGER_MISSING", f"the live ledger cannot be read ({exc.__class__.__name__})") from None
        if blob and not blob.endswith(b"\n"):
            raise LiveIntegrityFailure("LEDGER_TORN_TAIL", "the final ledger line is incomplete: the ledger is not resumed (start a new live id)")
        entries, previous = [], GENESIS
        for number, line in enumerate(blob.decode("utf-8").splitlines(), 1):
            try:
                entry = json.loads(line)
            except ValueError:
                raise LiveIntegrityFailure("LEDGER_INVALID", f"ledger line {number} is not valid JSON") from None
            if (not isinstance(entry, dict) or set(entry) != _KEYS or entry["schema"] != LEDGER_SCHEMA or entry["schema_version"] != 1
                    or entry["seq"] != number or entry["kind"] not in KINDS or entry["prev_entry_sha256"] != previous
                    or entry["entry_sha256"] != entry_hash(entry)):
                raise LiveIntegrityFailure("LEDGER_INVALID", f"ledger line {number}: broken chain, edited entry, wrong sequence or unknown kind")
            entries.append(entry)
            previous = entry["entry_sha256"]
        return cls(directory, entries)

    @property
    def head_sha256(self):
        return self.entries[-1]["entry_sha256"] if self.entries else GENESIS

    def append(self, kind, body):
        if kind not in KINDS:
            raise LiveRefused("LEDGER_KIND", f"unknown ledger entry kind {kind!r}")
        entry = dict(schema=LEDGER_SCHEMA, schema_version=1, seq=len(self.entries) + 1, kind=kind, body=body, prev_entry_sha256=self.head_sha256)
        entry["entry_sha256"] = entry_hash(entry)
        line = (canonical(entry) + "\n").encode("utf-8")
        with open(self.path, "ab") as stream:
            stream.write(line)
            stream.flush()
            os.fsync(stream.fileno())
        self.entries.append(entry)
        return entry

    # ------------------------------------------------------------------------------------------------------------- views
    def of_kind(self, kind):
        return [e for e in self.entries if e["kind"] == kind]

    def polls(self):
        return self.of_kind("POLL")

    def audit_events(self):
        return [event for entry in self.polls() for event in entry["body"]["audit_events"]]

    def resume_point(self):
        """What a restarted adapter needs: the last complete poll's source position and stream snapshot (None before the first poll)."""
        polls = self.polls()
        return None if not polls else dict(source=polls[-1]["body"]["source"], pipeline=polls[-1]["body"]["pipeline"], poll=polls[-1]["body"]["poll"])
