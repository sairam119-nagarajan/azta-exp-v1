"""Append-only, hash-chained audit log and the state table derived from it (the auditable state record of the PEP and the runner).

Every entry is one fsynced JSON line {seq, ts_utc, kind, body, prev_sha256, sha256}. Opening an existing log verifies the whole chain and refuses a torn tail,
an edited or reordered entry or a gap, so a restart can only continue from an intact record. The state table is rebuilt by replaying the log: what the layer
BELIEVES (last verified broker state, outcomes by request id, decided evidence ids, the runner's input cursor) is never stored anywhere the chain does not cover.
No secret is ever written: bodies are built from device names, state labels, command names without passwords and correlation ids.
"""
import hashlib
import json
import os
from pathlib import Path

from enforcement.errors import AuditIntegrityError

SCHEMA = "azta.enforcement.audit"
GENESIS = "0" * 64


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _entry_sha(entry):
    return hashlib.sha256(_canonical({k: v for k, v in entry.items() if k != "sha256"}).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path, entries, clock):
        """`path=None` is an in-memory log (read-only commands such as `observe`): nothing is written anywhere."""
        self.path, self.entries, self.clock = (Path(path) if path is not None else None), list(entries), clock

    @classmethod
    def create(cls, path, clock):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "xb"):
            pass                                    # an existing log is never reused or overwritten here
        return cls(path, [], clock)

    @classmethod
    def open_existing(cls, path, clock):
        blob = Path(path).read_bytes()
        if blob and not blob.endswith(b"\n"):
            raise AuditIntegrityError("AUDIT_TORN_TAIL", "the final line is incomplete; the log is not continued")
        entries, previous = [], GENESIS
        for number, line in enumerate(blob.decode("utf-8").splitlines(), 1):
            try:
                entry = json.loads(line)
            except ValueError:
                raise AuditIntegrityError("AUDIT_INVALID", f"line {number} is not JSON") from None
            if (not isinstance(entry, dict) or set(entry) != {"schema", "seq", "ts_utc_ns", "kind", "body", "prev_sha256", "sha256"} or entry["schema"] != SCHEMA
                    or entry["seq"] != number or entry["prev_sha256"] != previous or entry["sha256"] != _entry_sha(entry)):
                raise AuditIntegrityError("AUDIT_INVALID", f"line {number}: broken chain, edited entry or wrong sequence")
            entries.append(entry)
            previous = entry["sha256"]
        return cls(path, entries, clock)

    @classmethod
    def open_or_create(cls, path, clock):
        return cls.open_existing(path, clock) if Path(path).exists() else cls.create(path, clock)

    @property
    def head(self):
        return self.entries[-1]["sha256"] if self.entries else GENESIS

    def append(self, kind, **body):
        entry = dict(schema=SCHEMA, seq=len(self.entries) + 1, ts_utc_ns=self.clock.utc_ns(), kind=kind, body=json.loads(_canonical(body)), prev_sha256=self.head)
        entry["sha256"] = _entry_sha(entry)
        if self.path is not None:
            with open(self.path, "ab") as stream:
                stream.write((_canonical(entry) + "\n").encode("utf-8"))
                stream.flush()
                os.fsync(stream.fileno())
        self.entries.append(entry)
        return entry

    def of_kind(self, kind):
        return [e for e in self.entries if e["kind"] == kind]


class StateTable:
    """What the layer believes, derived from the log. `verified` is the last state the BROKER showed; `believed` is the last outcome the PEP recorded."""

    def __init__(self, log):
        self.log = log
        self.outcomes, self.requests, self.decided = {}, {}, set()
        self.verified, self.believed, self.cursor = {}, {}, dict(offset=0, prefix_sha256=hashlib.sha256(b"").hexdigest())
        for e in log.entries:
            self._apply(e)

    def _apply(self, e):
        kind, body = e["kind"], e["body"]
        if kind == "REQUEST_RECEIVED":
            self.requests[body["request_id"]] = body["request_digest"]
        elif kind == "OUTCOME":
            self.outcomes[body["request_id"]] = body
            if body["status"] in ("APPLIED_VERIFIED", "NOOP_ALREADY_IN_STATE"):
                self.believed[body["device"]] = body["desired_state"]
        elif kind in ("OBSERVED", "BASELINE_OBSERVED"):
            self.verified[body["device"]] = body
        elif kind == "RECORD_HANDLED":
            self.decided.add(body["evidence_id"])
        elif kind == "CURSOR":
            self.cursor = dict(offset=body["offset"], prefix_sha256=body["prefix_sha256"])
        elif kind == "RECONCILIATION" and body.get("drift"):
            self.believed.pop(body["device"], None)

    def record(self, kind, **body):
        entry = self.log.append(kind, **body)
        self._apply(entry)
        return entry
