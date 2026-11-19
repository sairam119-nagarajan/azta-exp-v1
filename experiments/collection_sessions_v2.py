"""Scoped observer-session discovery for workload-v2 runs: never open a session the run did not create.

The v1 tools found "the" observer session of a run by opening `session_metadata.json` of EVERY session directory under the evidence root. For
a scientific run that root also holds the sealed historical sessions, so each discovery re-opened the metadata of evidence it had no business
touching (a read of B_cal session metadata was exposed by the first rehearsal's tooling review). The v2 rule:

  * a name-only snapshot of the existing session directories is taken by the ORCHESTRATOR before it starts either container (`snapshot_names`
    lists names; it opens nothing) and is handed to the workload in two environment variables (`encode_snapshot` / `decode_snapshot`);
    the workload never takes its own snapshot: its start-up work (validating a 68-cell plan takes seconds) races with the observer, which
    creates its session directory almost at once, and a late snapshot would exclude the run's own session (the first CAL_V2 run was voided
    by exactly that);
  * `NewSessionCoverage` (the workload's coverage source) opens metadata only in directories that are NOT in that snapshot;
  * reconciliation is given the session id explicitly and opens only that directory (`explicit_session`); a COLLECTION reconciliation without
    an id is refused (fail closed), and the id must equal the one the workload recorded.

An isolated functional root (one run per root) may still be scanned, because nothing else lives there.
"""
import hashlib
import json
from pathlib import Path
import re

from experiments.collection_workload import WorkloadError

SESSION_NAME = re.compile(r"obs-[0-9a-f]{32}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
ENV_SNAPSHOT, ENV_DIGEST, SNAPSHOT_PREFIX = "AZTA_PREEXISTING_SESSIONS", "AZTA_PREEXISTING_SESSIONS_SHA256", "v1:"
MAX_UNLISTED = 1       # only the run's own observer session may exist outside the snapshot; more means the snapshot is not the orchestrator's


def snapshot_names(root):
    """Names of the session directories that exist now (a directory listing; no file is opened)."""
    directory = Path(root) / "observation"
    return frozenset(p.name for p in directory.iterdir() if p.is_dir()) if directory.is_dir() else frozenset()


def snapshot_digest(names):
    """SHA-256 of the canonical listing: the sorted names, one per line, each followed by a newline."""
    return hashlib.sha256("".join(name + chr(10) for name in sorted(names)).encode("ascii")).hexdigest()


def encode_snapshot(names):
    """(value, digest) for the two environment variables. The value always has the version prefix, so it is never empty."""
    ordered = sorted(names)
    if not all(SESSION_NAME.fullmatch(n) for n in ordered) or len(set(ordered)) != len(ordered):
        raise ValueError("snapshot names must be unique observer session ids")
    return SNAPSHOT_PREFIX + ",".join(ordered), snapshot_digest(ordered)


def decode_snapshot(value, digest, root):
    """The orchestrator's pre-run snapshot as a frozenset, or ValueError. Absent, malformed, non-canonical, digest-mismatching, forged (names
    that are not directories under root/observation) or truncated snapshots (more than MAX_UNLISTED existing directories outside it) are refused."""
    if not isinstance(value, str) or not value.startswith(SNAPSHOT_PREFIX):
        raise ValueError("the pre-run session snapshot is absent or has no version prefix")
    body = value[len(SNAPSHOT_PREFIX):]
    names = body.split(",") if body else []
    if not all(SESSION_NAME.fullmatch(n) for n in names) or len(set(names)) != len(names) or names != sorted(names):
        raise ValueError("the pre-run session snapshot is malformed (names must be unique, canonical, sorted observer session ids)")
    if not (isinstance(digest, str) and HEX64.fullmatch(digest)) or digest != snapshot_digest(names):
        raise ValueError("the pre-run session snapshot digest is absent or does not match its content")
    existing = snapshot_names(root)
    if not set(names) <= existing:
        raise ValueError("the pre-run session snapshot names directories that do not exist")
    if len(existing - set(names)) > MAX_UNLISTED:
        raise ValueError("the pre-run session snapshot omits existing sessions: it is not the orchestrator's snapshot")
    return frozenset(names)


def coverage_from_environment(root, run_id, purpose, environ):
    """The workload's coverage source built from the orchestrator's snapshot; refuses when the snapshot is missing or untrusted."""
    excluded = decode_snapshot(environ.get(ENV_SNAPSHOT), environ.get(ENV_DIGEST), root)
    return NewSessionCoverage(root, run_id, purpose, excluded)


class NewSessionCoverage:
    """Reads (never writes) the coverage start of the observer session THIS run creates; sessions that predate the snapshot are never opened."""

    def __init__(self, root, run_id, purpose, excluded_names):
        self.root, self.run_id, self.purpose = Path(root) / "observation", run_id, purpose
        self.excluded = frozenset(excluded_names)
        self.opened = []                     # directory names whose metadata this source opened (for evidence and tests)

    def __call__(self):
        matches = []
        candidates = sorted(p for p in self.root.iterdir() if p.is_dir() and p.name not in self.excluded) if self.root.is_dir() else []
        if len(candidates) > MAX_UNLISTED:     # checked before ANY file is opened: a truncated or forged snapshot must not widen the search
            raise WorkloadError("untrusted_session_snapshot")
        for directory in candidates:
            if not SESSION_NAME.fullmatch(directory.name):
                continue
            try:
                data = json.loads((directory / "session_metadata.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            self.opened.append(directory.name)
            if data.get("collection_run_id") == self.run_id:
                matches.append((directory, data))
        if len(matches) > 1:
            raise WorkloadError("multiple_observer_sessions_for_run")
        if not matches:
            return None
        directory, data = matches[0]
        if data.get("purpose") != self.purpose:
            raise WorkloadError("observer_purpose_mismatch")
        try:
            lines = (directory / "health.jsonl").read_text(encoding="utf-8").splitlines()
        except OSError:
            return None
        for line in lines:
            try:
                record = json.loads(line)
            except ValueError:
                continue                     # a line still being written
            if record.get("kind") == "COVERAGE_START":
                return dict(observer_session_id=data["observer_session_id"], coverage_start_utc=record["utc"])
            if record.get("kind") == "SESSION_END":
                raise WorkloadError("observer_session_ended_before_coverage")
        return None


def explicit_session(root, run_id, session_id):
    """The one session directory named by the caller; nothing else under observation/ is listed or opened."""
    if not (isinstance(session_id, str) and SESSION_NAME.fullmatch(session_id)):
        raise ValueError("an explicit observer session id (obs-<32 hex>) is required")
    directory = Path(root) / "observation" / session_id
    if not directory.is_dir():
        raise ValueError("the named observer session does not exist")
    return directory
