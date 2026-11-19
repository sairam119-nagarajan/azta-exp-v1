"""A2 record contract. Defaults are functional-test defaults, never calibrated."""
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import time
import uuid

SCHEMA_VERSION = 1
EVIDENCE_TYPES = ("LIVE_MQTT", "FEATURE_REPLAY", "OFFLINE_DATASET")
TOPIC = "azta/devices/device01/telemetry"
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def is_utc(value):
    if not isinstance(value, str) or len(value) > 40:
        return False
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return stamp.utcoffset() is not None and stamp.utcoffset().total_seconds() == 0
    except ValueError:
        return False


def new_run_id():
    return "run-" + uuid.uuid4().hex


@dataclass(frozen=True)
class RunConfig:
    run_id: str
    scenario: str = "functional-test"
    device_identity: str = "azta-device-01"
    claimed_device_id: str = "device01"
    topic: str = TOPIC
    qos: int = 1
    message_count: int = 10
    interval: float = 0.2
    seed: int = 0
    payload_size: int = 512
    timeout: float = 20.0
    evidence_type: str = "LIVE_MQTT"

    def validate(self):
        for value in (self.run_id, self.scenario, self.device_identity, self.claimed_device_id):
            if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
                raise ValueError("Identifiers must be 1-64 ASCII letters/digits/underscore/hyphen")
        if not isinstance(self.topic, str) or not re.fullmatch(r"[A-Za-z0-9_./:-]{1,256}", self.topic):
            raise ValueError("Topic must be a bounded literal MQTT topic, without wildcards")
        if self.evidence_type != "LIVE_MQTT":
            raise ValueError("This runner executes LIVE_MQTT only")
        if type(self.qos) is not int or self.qos != 1:
            raise ValueError("A2 supports QoS 1 only")
        for value, low, high, label in (
            (self.message_count, 1, 100000, "message_count"),
            (self.seed, 0, 2**32 - 1, "seed"),
            (self.payload_size, 512, 65536, "payload_size"),
        ):
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"Invalid {label}")
        for value, low, high, label in (
            (self.interval, 0, 60, "interval"), (self.timeout, 0.1, 3600, "timeout")
        ):
            if type(value) not in (int, float) or not math.isfinite(value) or not low <= value <= high:
                raise ValueError(f"Invalid {label}")
        return self


def encode_payload(config, sequence, publisher_session_id, timestamp):
    """Same parameters/sequence/time/session produce exactly the same bytes."""
    if type(sequence) is not int or not 1 <= sequence <= config.message_count:
        raise ValueError("Invalid sequence")
    if not is_utc(timestamp):
        raise ValueError("Invalid UTC timestamp")
    payload = dict(
        schema_version=getattr(config, "schema_version", SCHEMA_VERSION), evidence_type="LIVE_MQTT",
        run_id=config.run_id, event_id=f"{config.run_id}:{sequence}",
        sequence=sequence, device_id=config.claimed_device_id,
        publisher_session_id=publisher_session_id, timestamp=timestamp,
        sample=(config.seed + sequence * 17) % 1000, padding="",
    )
    encode = lambda: json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    size = len(encode())
    if size > config.payload_size:
        raise ValueError("Payload size too small for correlation metadata")
    payload["padding"] = "x" * (config.payload_size - size)
    return encode()


def digest(payload):
    return hashlib.sha256(payload).hexdigest()


class RunRecords:
    """Exclusive run directory, flushed JSONL, shared process monotonic reference."""
    def __init__(self, root, config, runtime, *, clock=time.monotonic_ns,
                 streams=("publisher", "pdp")):
        self.config = config
        self.schema_version = getattr(config, "schema_version", SCHEMA_VERSION)
        self.clock = clock
        self.start_ns = clock()
        self.start_utc = utc_now()
        self.path = Path(root) / config.run_id
        self.path.mkdir(parents=True, exist_ok=False)
        self.files = {}
        self.index = {stream: 0 for stream in streams}
        try:
            for stream in self.index:
                self.files[stream] = (self.path / f"{stream}_events.jsonl").open("x", encoding="utf-8")
            self.metadata = dict(
                schema_version=self.schema_version, evidence_type=config.evidence_type,
                run_id=config.run_id, scenario=config.scenario, utc_start=self.start_utc,
                utc_end=None, monotonic_start_ns=self.start_ns,
                clock_domain="shared_runner_process_monotonic",
                mqtt_protocol_version=5, configuration=asdict(config),
                parameter_status="user_selected_or_functional_test_defaults",
                runtime=runtime, state="IN_PROGRESS",
            )
            self.write_json("run_metadata.json", self.metadata)
        except BaseException:
            self.close()
            raise

    def elapsed_ms(self):
        return (self.clock() - self.start_ns) / 1_000_000

    def event(self, stream, event_type, **fields):
        self.index[stream] += 1
        record = dict(
            schema_version=self.schema_version, evidence_type=self.config.evidence_type,
            run_id=self.config.run_id, scenario=self.config.scenario,
            record_id=f"{stream}:{self.index[stream]}",
            utc_timestamp=utc_now(), monotonic_elapsed_ms=self.elapsed_ms(),
            event_type=event_type, sequence=None, event_id=None,
            topic=self.config.topic, qos=self.config.qos, payload_length=None,
        )
        record.update(fields)
        self.files[stream].write(json.dumps(record, sort_keys=True, allow_nan=False) + "\n")
        self.files[stream].flush()
        return record

    def write_json(self, name, value):
        # Runtime evidence write, not source editing. Atomic replacement in the run dir.
        temporary = self.path / (name + ".tmp")
        with temporary.open("w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
        temporary.replace(self.path / name)

    def finish(self, summary):
        end = utc_now()
        summary.update(schema_version=self.schema_version, evidence_type=self.config.evidence_type,
                       run_id=self.config.run_id, scenario=self.config.scenario,
                       utc_start=self.start_utc, utc_end=end, duration_ms=self.elapsed_ms())
        self.write_json("run_summary.json", summary)
        self.metadata.update(utc_end=end, state=summary["state"])
        self.write_json("run_metadata.json", self.metadata)

    def close(self):
        for stream in self.files.values():
            stream.close()
