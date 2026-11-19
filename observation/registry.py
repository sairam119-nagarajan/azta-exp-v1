"""Versioned device registry: exact telemetry topic -> device and its bound broker principal.

The registry is a claim about policy. It becomes an audit-backed binding only together with a
passing read-only Dynamic Security binding audit (experiments/binding_audit.py). The received MQTT
message never carries the publisher username to this subscriber, and payloads are never used.
"""
from dataclasses import dataclass
import json
from pathlib import Path
import re

from observation.schema import IDENTIFIER, canonical, sha256_text

REGISTRY_SCHEMA = "azta.observation.device_registry"
LITERAL_TOPIC = re.compile(r"[A-Za-z0-9_.:-]+(/[A-Za-z0-9_.:-]+)*\Z")
DEVICE_KEYS = ("device", "username", "client_id", "telemetry_topic", "publish_role")


@dataclass(frozen=True)
class DeviceEntry:
    device: str
    username: str
    client_id: str
    telemetry_topic: str
    publish_role: str


class DeviceRegistry:
    def __init__(self, data):
        if not isinstance(data, dict) or set(data) != {"schema", "schema_version", "registry_version", "scope", "devices"}:
            raise ValueError("registry: unexpected or missing fields")
        if data["schema"] != REGISTRY_SCHEMA or data["schema_version"] != 1:
            raise ValueError("registry: schema")
        if type(data["registry_version"]) is not int or data["registry_version"] < 1 or not isinstance(data["scope"], str):
            raise ValueError("registry: version/scope")
        if not isinstance(data["devices"], list) or not data["devices"]:
            raise ValueError("registry: devices required")
        entries = []
        for item in data["devices"]:
            if not isinstance(item, dict) or set(item) != set(DEVICE_KEYS):
                raise ValueError("registry: device fields")
            for key in ("device", "username", "client_id", "publish_role"):
                if not isinstance(item[key], str) or not IDENTIFIER.fullmatch(item[key]):
                    raise ValueError(f"registry: invalid {key}")
            topic = item["telemetry_topic"]
            # Literal topics only: no wildcard, empty level, system topic or non-telemetry path (D4).
            if (not isinstance(topic, str) or not LITERAL_TOPIC.fullmatch(topic)
                    or topic.startswith("$") or not topic.endswith("/telemetry")):
                raise ValueError("registry: telemetry topic must be a literal telemetry topic")
            entries.append(DeviceEntry(**item))
        for key in DEVICE_KEYS:
            values = [getattr(entry, key) for entry in entries]
            if len(set(values)) != len(values):
                raise ValueError(f"registry: duplicate {key}")
        self.data = data
        self.devices = tuple(sorted(entries, key=lambda entry: entry.device))
        self._by_topic = {entry.telemetry_topic: entry for entry in self.devices}
        self.sha256 = sha256_text(canonical(data))

    @classmethod
    def load(cls, path):
        with Path(path).open(encoding="utf-8") as stream:
            return cls(json.load(stream))

    def bind(self, topic):
        """Exact literal match only. Anything else is unbound and never becomes a trusted device."""
        return self._by_topic.get(topic) if isinstance(topic, str) else None
