"""Read-only follower of the PEP's hash-chained audit logs: WHEN the PEP verified a change of one device's broker policy (Gate 6B defect F1).

Identity evidence is a statement about the broker's policy at the instant an audit read it. Once the PEP (the only writer of device policy here) has
applied a change for a device, a binding audit that STARTED before that change no longer describes that device, in either direction: a REVOKED verdict
read while the client was disabled says nothing about the client after an administrative RESTORE, and a VALID verdict read before a QUARANTINE says
nothing about the quarantined client. Gate 6B pilot `g6b-p01` showed the consequence: device01 was restored at 21:24:11.6, the latest audit (captured
21:24:06, client disabled) was still inside the 40 s identity freshness bound, two windows were decided as `FRESH_AUTHORITATIVE_NEGATIVE` (S_ID 0) and the
restored, healthy device was quarantined again.

This module only READS what the PEP wrote. A change is reported when an `OUTCOME` entry of any log directly under the PEP directory (`continuous.jsonl`
and every `restore-*.jsonl`, which keep a single writer each) carries a status for which the broker policy of that device DID or MAY have changed:

    APPLIED_VERIFIED     the broker showed the target permissions after the last command
    PARTIAL_UNVERIFIED   some commands took effect (an intermediate policy)
    UNVERIFIED_UNKNOWN   the final state could not be read (the policy may have changed)

NOOP_ALREADY_IN_STATE, FAILED_UNCHANGED_VERIFIED and REFUSED changed nothing and are not reported. The instant is the entry's own `ts_utc_ns`, written after the
read-back, so it is not earlier than the broker showing the new policy. Every log is read incrementally and its whole chain (sequence, previous digest, entry
digest) is re-verified as it grows: an edited, reordered, shortened or vanished log is an integrity failure, never silently skipped. A file that cannot be read
right now (a sharing violation) raises `PolicyChangesUnreadable`; callers must treat the feed as UNKNOWN until a later read succeeds (fail closed), never as "no change".
"""
import json
import os
from pathlib import Path

from enforcement.audit import GENESIS, SCHEMA, _entry_sha
from enforcement.pep import APPLIED, PARTIAL, UNKNOWN

CHANGE_STATUSES = (APPLIED, PARTIAL, UNKNOWN)
ENTRY_KEYS = {"schema", "seq", "ts_utc_ns", "kind", "body", "prev_sha256", "sha256"}


def from_spec(spec):
    """The follower a supervisor asked for (`spec["identity_barrier_pep_dir"]`), or None: the key is absent for the baseline behaviour and for any run that does not enable the barrier."""
    directory = spec.get("identity_barrier_pep_dir")
    return PolicyChangeFollower(directory) if directory else None


class PolicyChangesUnreadable(OSError):
    """A PEP log exists but cannot be read right now; the next call retries. Until one succeeds the set of changes is not known."""


class PolicyChangesIntegrityError(ValueError):
    """A PEP log is not the append-only hash chain it was: tampering, truncation or a second writer."""

    def __init__(self, code, detail):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


class PolicyChangeFollower:
    def __init__(self, pep_dir):
        self.pep_dir = Path(pep_dir)
        self._files = {}                  # name -> dict(offset, seq, prev)
        self._last = {}                   # device -> latest change instant (ns)

    def last_change_ns(self, device):
        return self._last.get(device)

    def describe(self):
        return dict(kind="PEP_AUDIT_LOG_FOLLOWER", directory=self.pep_dir.name, statuses=list(CHANGE_STATUSES), logs=sorted(self._files))

    def poll(self):
        """New changes since the last successful call, ordered by (instant, log, sequence). An unreadable log raises; nothing is reported twice."""
        try:
            names = sorted(e.name for e in os.scandir(self.pep_dir) if e.is_file() and e.name.endswith(".jsonl"))
        except FileNotFoundError:
            names = []
        except OSError as exc:
            raise PolicyChangesUnreadable(f"{self.pep_dir.name}: {exc.__class__.__name__}") from None
        missing = sorted(set(self._files) - set(names))
        if missing:
            raise PolicyChangesIntegrityError("PEP_LOG_DISAPPEARED", f"{missing[0]} was followed and no longer exists")
        found = []
        staged = {}
        for name in names:
            found.extend(self._read(name, staged))
        for name, state in staged.items():             # state advances only after EVERY log was read: a failure leaves no half-applied position
            self._files[name] = state
        found.sort(key=lambda c: (c["instant_ns"], c["log"], c["seq"]))
        for change in found:
            if change["instant_ns"] > self._last.get(change["device"], -1):
                self._last[change["device"]] = change["instant_ns"]
        return found

    def _read(self, name, staged):
        state = dict(self._files.get(name, dict(offset=0, seq=0, prev=GENESIS)))
        try:
            blob = (self.pep_dir / name).read_bytes()
        except FileNotFoundError:
            raise PolicyChangesIntegrityError("PEP_LOG_DISAPPEARED", f"{name} vanished while it was being read") from None
        except OSError as exc:
            raise PolicyChangesUnreadable(f"{name}: {exc.__class__.__name__}") from None
        if len(blob) < state["offset"]:
            raise PolicyChangesIntegrityError("PEP_LOG_SHRANK", f"{name} is shorter than the part already verified")
        end = blob.rfind(b"\n") + 1                       # a partial last line is still being written: it is read at a later call
        changes, position = [], state["offset"]
        while position < end:
            nxt = blob.index(b"\n", position)
            entry = self._entry(name, blob[position:nxt], state)
            if entry["kind"] == "OUTCOME" and isinstance(entry["body"], dict) and entry["body"].get("status") in CHANGE_STATUSES:
                body = entry["body"]
                changes.append(dict(device=body.get("device"), instant_ns=entry["ts_utc_ns"], status=body["status"], desired_state=body.get("desired_state"),
                                    request_kind=body.get("request_kind"), request_id=body.get("request_id"), log=name, seq=entry["seq"],
                                    entry_sha256=entry["sha256"]))
            position = nxt + 1
        state["offset"] = position
        staged[name] = state
        return changes

    @staticmethod
    def _entry(name, line, state):
        try:
            entry = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise PolicyChangesIntegrityError("PEP_LOG_INVALID", f"{name}: line {state['seq'] + 1} is not JSON") from None
        number = state["seq"] + 1
        if (not isinstance(entry, dict) or set(entry) != ENTRY_KEYS or entry["schema"] != SCHEMA or entry["seq"] != number
                or entry["prev_sha256"] != state["prev"] or entry["sha256"] != _entry_sha(entry)
                or type(entry["ts_utc_ns"]) is not int):
            raise PolicyChangesIntegrityError("PEP_LOG_BROKEN_CHAIN", f"{name}: line {number}: broken chain, edited entry or wrong sequence")
        state["seq"], state["prev"] = number, entry["sha256"]
        return entry
