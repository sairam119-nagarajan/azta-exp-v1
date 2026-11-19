"""Contextual-trust evidence for a LIVE pilot session: authorized operating time and device/topic-profile conformity.

Two criteria, both defined by journal section 4.1 and both fed to the UNCHANGED trust engine as ordinary context facts (S_C = 100 * sum(omega_j * c_j) is computed by `trust.fusion`):

  * `operating_time` (provenance VERSIONED_CONFIGURATION): the share of the window inside a permitted interval of a VERSIONED per-device policy file. The policy states the
    intervals in UTC; they are converted to the coverage-relative form of the existing `trust.producer.operating_schedule_fact`, which then computes the exact share from the
    window's own observer offsets. No device, payload or topic content takes part.
  * `topic_profile` (provenance TRUSTED_INSTRUMENTATION): 1.0 when the broker recorded NO denied operation by the device's authenticated client id inside the window, 0.0 when it
    recorded at least one. The source is the hash-chained ledger of `engineering.broker_events` (the pilot broker's own log). A window is evaluated only when the feed demonstrably
    covered it (started before the window, coverage heartbeat reached its end); otherwise the fact is `conformity: null`, so the criterion is MISSING and the configured
    missing-evidence policy applies. Absence of a feed is never a healthy score. A denial for a topic the device's profile PERMITS is a policy/ACL inconsistency and is also
    reported as unavailable, never as a violation or as conformity.

What this does not claim: the topic criterion is evidence of attempted access outside the broker policy (an ACL denial), observed on the broker; it does not see operations the
broker allowed, and it is not an independent measurement of the profile beyond the ACL. The time criterion is a configured schedule, not a measured fact about the device.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import time

from trust.producer import SCHEDULE_SCHEMA, ContextFact, operating_schedule_fact

LEDGER_VERSION = 1
GENESIS = "0" * 64


def docker_stamp_ns(text):
    """RFC 3339 stamp with up to nanosecond digits -> integer nanoseconds since the epoch."""
    match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z", text)
    if not match:
        raise ValueError("unparseable timestamp")
    seconds = int(datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp())
    return seconds * 10**9 + int((match.group(2) or "0").ljust(9, "0"))


def entry_digest(body):
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


class LedgerReader:
    """Incremental, chain-verifying READER of the broker-event ledger written by `engineering.broker_events` (the writer and the log follower live there; this package only reads a
    file). `refresh()` reads what was appended since the last call; a broken chain raises."""

    def __init__(self, path):
        self.path, self.offset, self.prev, self.seq = Path(path), 0, GENESIS, 0
        self.events, self.coverage_ns, self.ended, self.started, self.start_ns = [], None, False, False, None

    def refresh(self):
        if not self.path.exists():
            return
        data = self.path.read_bytes()[self.offset:]
        end = data.rfind(b"\n")
        if end < 0:
            return
        for raw in data[: end + 1].splitlines():
            body = json.loads(raw.decode("utf-8"))
            claimed = body.pop("sha256")
            if body["prev"] != self.prev or body["seq"] != self.seq + 1 or entry_digest(body) != claimed:
                raise ValueError("broker-event ledger chain broken")
            self.prev, self.seq = claimed, body["seq"]
            if body["kind"] in ("DENIED_PUBLISH", "DENIED_SUBSCRIBE"):
                self.events.append(body)
            elif body["kind"] == "COVERAGE":
                self.coverage_ns = body["covered_through_utc_ns"]
            elif body["kind"] == "START":
                self.started, self.start_ns = True, body["utc_ns"]
            elif body["kind"] == "END":
                self.ended = True
        self.offset += end + 1


POLICY_SCHEMA = "azta.pilot_context_policy"
OPERATING_TIME, TOPIC_PROFILE = "operating_time", "topic_profile"
CLIENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
STAMP = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z\Z")


class ContextPolicyError(ValueError):
    pass


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _need(condition, message):
    if not condition:
        raise ContextPolicyError(message)


def parse_policy(data):
    """Strict validation of a pilot context policy; returns (policy dict with intervals in integer ns, sha256 of the canonical document)."""
    _need(isinstance(data, dict) and set(data) == {"schema", "version", "policy_id", "status", "devices"}, "policy: unexpected or missing fields")
    _need(data["schema"] == POLICY_SCHEMA and type(data["version"]) is int and data["version"] >= 1, "policy: schema/version")
    _need(isinstance(data["policy_id"], str) and re.fullmatch(r"[A-Za-z0-9._-]{1,64}", data["policy_id"]), "policy: policy_id")
    _need(data["status"] in ("ENGINEERING_PILOT_UNAPPROVED", "CONTROLLER_APPROVED_PILOT"), "policy: status")
    _need(isinstance(data["devices"], dict) and data["devices"], "policy: devices")
    parsed, clients = {}, set()
    for device, entry in data["devices"].items():
        _need(isinstance(device, str) and isinstance(entry, dict) and set(entry) == {"client_id", "permitted_utc_intervals", "permitted_topics"},
              f"policy: device {device!r} fields")
        _need(isinstance(entry["client_id"], str) and CLIENT_ID.fullmatch(entry["client_id"]) and entry["client_id"] not in clients, "policy: client_id")
        clients.add(entry["client_id"])
        intervals = []
        for pair in entry["permitted_utc_intervals"]:
            _need(isinstance(pair, list) and len(pair) == 2 and all(isinstance(t, str) and STAMP.fullmatch(t) for t in pair), "policy: interval format")
            start, end = (docker_stamp_ns(t) for t in pair)
            _need(start < end, "policy: interval must have start < end")
            intervals.append((start, end))
        _need(all(a[1] <= b[0] for a, b in zip(intervals, intervals[1:])), "policy: intervals must be sorted and non-overlapping")
        topics = entry["permitted_topics"]
        _need(isinstance(topics, list) and all(isinstance(t, str) and t and "#" not in t and "+" not in t for t in topics), "policy: permitted_topics are exact topics")
        parsed[device] = dict(client_id=entry["client_id"], intervals=intervals, topics=frozenset(topics))
    return dict(policy_id=data["policy_id"], version=data["version"], status=data["status"], devices=parsed), hashlib.sha256(canonical(data)).hexdigest()


def load_policy(path):
    raw = Path(path).read_bytes()
    policy, _ = parse_policy(json.loads(raw.decode("utf-8")))
    return policy, hashlib.sha256(canonical(json.loads(raw.decode("utf-8")))).hexdigest()


class BrokerContextSource:
    """Supplies the two context facts of ONE window of ONE device. Pure with respect to the engine: it only reads the policy and the broker-event ledger."""

    def __init__(self, policy, policy_sha256, ledger_path, *, wait_s=2.0, poll_s=0.1, sleep=time.sleep, monotonic=time.monotonic):
        self.policy, self.policy_sha256 = policy, policy_sha256
        self.reader = LedgerReader(ledger_path)
        self.wait_s, self.poll_s, self._sleep, self._monotonic = wait_s, poll_s, sleep, monotonic
        self.unavailable = 0

    def describe(self):
        return dict(kind="PILOT_BROKER_CONTEXT", policy_id=self.policy["policy_id"], policy_version=self.policy["version"], policy_status=self.policy["status"],
                    policy_sha256=self.policy_sha256, ledger=str(self.reader.path), criteria=[OPERATING_TIME, TOPIC_PROFILE])

    def _covered(self, start_ns, end_ns):
        reader = self.reader
        return (reader.start_ns is not None and reader.start_ns <= start_ns and reader.coverage_ns is not None and reader.coverage_ns >= end_ns)

    def facts(self, *, device, window, coverage_start_utc_ns, coverage_start_offset_ns, window_end_utc_ns, decision_ns):
        entry = self.policy["devices"].get(device)
        if entry is None:
            return []                                   # no policy for this device: the criteria are NOT PROVIDED, so S_C cannot be computed
        base = f"{self.policy['policy_id']}:v{self.policy['version']}:{self.policy_sha256[:16]}"
        duration = window["window"]["end_offset_ns"] - window["window"]["start_offset_ns"]
        start_ns = window_end_utc_ns - duration
        relative = [[max(a - coverage_start_utc_ns, 0), b - coverage_start_utc_ns] for a, b in entry["intervals"] if b > coverage_start_utc_ns]
        schedule = dict(schema=SCHEDULE_SCHEMA, version=self.policy["version"], basis="COVERAGE_RELATIVE_NS", permitted_intervals_ns=relative)
        timed = operating_schedule_fact(schedule, window, coverage_start_offset_ns=coverage_start_offset_ns, observed_ns=decision_ns,
                                        source_ref=f"context_policy:{base}:operating_time:{device}")

        self.reader.refresh()
        deadline = self._monotonic() + self.wait_s
        while not self._covered(start_ns, window_end_utc_ns) and not self.reader.ended and self._monotonic() < deadline:
            self._sleep(self.poll_s)
            self.reader.refresh()
        reason, conformity = None, None
        if not self._covered(start_ns, window_end_utc_ns):
            reason = "BROKER_EVENT_COVERAGE_NOT_DEMONSTRATED"
        else:
            denied = [e for e in self.reader.events if e["client_id"] == entry["client_id"] and start_ns <= e["utc_ns"] < window_end_utc_ns]
            if any(e["topic"] in entry["topics"] for e in denied):
                reason = "DENIAL_FOR_A_PERMITTED_TOPIC_POLICY_INCONSISTENT"
            else:
                conformity = 0.0 if denied else 1.0
        if conformity is None:
            self.unavailable += 1
        observed = min(window_end_utc_ns, decision_ns)
        topic = ContextFact(TOPIC_PROFILE, conformity, "TRUSTED_INSTRUMENTATION", observed,
                            f"broker_log_denials:{base}:{device}:chain={self.reader.prev[:16]}" + (f":{reason}" if reason else ""))
        return [timed, topic]
