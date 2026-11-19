"""Separate research PDP receive logger; the historical subscriber is unchanged."""
import json
import re

from experiments.research_records import IDENTIFIER, digest, is_utc


class ResearchPDP:
    def __init__(self, config, records, session_id, stream="pdp", prefix="PDP"):
        self.config, self.records, self.session_id = config, records, session_id
        self.stream, self.prefix = stream, prefix
        self.observed = 0
        self.duplicates = 0
        self.malformed = 0
        self.unrelated = 0
        self.conflicts = 0
        self.received = {}

    def observe(self, topic, qos, payload, duplicate=False, retained=False):
        base = dict(
            local_session_id=self.session_id, topic=topic, qos=qos,
            payload_length=len(payload), duplicate=bool(duplicate), retained=bool(retained),
            decision="NOT_IMPLEMENTED", authenticated_publisher_identity=None,
        )
        try:
            if len(payload) > 65536:
                raise ValueError()
            data = json.loads(payload)
            if not isinstance(data, dict):
                raise ValueError()
            # An unrelated run is not counted as malformed or attributed to this run.
            if isinstance(data.get("run_id"), str) and data["run_id"] != self.config.run_id:
                self.unrelated += 1
                self.records.event(self.stream, self.prefix + "_UNRELATED", result="ignored", **base)
                return
            if (
                type(data.get("schema_version")) is not int
                or data["schema_version"] != getattr(self.config, "schema_version", 1)
                or data.get("evidence_type") != "LIVE_MQTT"
                or data.get("run_id") != self.config.run_id
                or type(data.get("sequence")) is not int
                or not 1 <= data["sequence"] <= self.config.message_count
                or data.get("event_id") != f'{self.config.run_id}:{data["sequence"]}'
                or not isinstance(data.get("device_id"), str)
                or not IDENTIFIER.fullmatch(data["device_id"])
                or not isinstance(data.get("publisher_session_id"), str)
                or not re.fullmatch(r"pub-[0-9a-f]{32}", data["publisher_session_id"])
                or not is_utc(data.get("timestamp"))
                or type(data.get("sample")) is not int or not 0 <= data["sample"] < 1000
                or topic != self.config.topic or qos != self.config.qos or retained
            ):
                raise ValueError()
        except (ValueError, TypeError, UnicodeError, RecursionError):
            self.malformed += 1
            self.records.event(self.stream, self.prefix + "_MALFORMED",
                               result="invalid_payload_or_metadata", **base)
            return
        seq = data["sequence"]
        fingerprint = digest(payload)
        self.observed += 1
        if seq in self.received:
            self.duplicates += 1
            if self.received[seq] != fingerprint:
                self.conflicts += 1
        else:
            self.received[seq] = fingerprint
        self.records.event(
            self.stream, self.prefix + "_RECEIVED", sequence=seq, event_id=data["event_id"],
            claimed_run_id=data["run_id"], claimed_device_id=data["device_id"],
            claimed_publisher_session_id=data["publisher_session_id"],
            claimed_publish_utc=data["timestamp"], sample=data["sample"],
            payload_sha256=fingerprint, result="observed", **base,
        )
