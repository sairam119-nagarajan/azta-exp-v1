"""Gate 5C publisher-only benign workload runner: both registered devices, QoS 1, telemetry topics only.

Uses the existing authenticated MQTT architecture (experiments.a3_mqtt.MQTTClient, unchanged) with
each device's own bound username/client ID. Never subscribes, never retains, never touches the
operations topic, another device's namespace or any policy. Publishes are scheduled at absolute
monotonic times from the frozen plan; PUBACKs are collected asynchronously and never pace the next
publish. The flushed per-device ledger is corroborating experiment evidence only; it is not identity
evidence (the observer's audit-backed topic binding remains authoritative) and holds no credential.
"""
import argparse
import calendar
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import random
import sys
import time

from experiments import collection_plan as plans
from experiments.research_records import utc_now
from observation import manifest as manifest_module
from observation.records import file_sha256
from observation.registry import DeviceRegistry

LEDGER_SCHEMA = "azta.collection.publisher_ledger"
SUMMARY_SCHEMA = "azta.collection.workload_summary"
SCHEMA_VERSION = 1
PURPOSES = ("FUNCTIONAL_TEST", "COLLECTION")
PUBLISH_QOS = 1
LOOP_SLICE_S = 0.002


class WorkloadError(Exception):
    pass


def schedule(config, device):
    """Deterministic [(sequence, offset_ns_from_coverage_start, payload_bytes)] from the frozen plan."""
    spec = config["devices"][device]
    profile = spec["profile_definition"]
    gap, fraction, payload = profile["nominal_gap_ns"], profile["jitter_fraction"], profile["payload"]
    w = config["window_duration_ms"] * 1_000_000
    offset = config["lead_in_windows"] * w + gap // 2
    last_allowed = (config["lead_in_windows"] + config["eligible_windows"]) * w - gap // 2
    jitter = random.Random(spec["jitter_seed"])
    sizes = random.Random(spec["size_seed"]) if spec["size_seed"] is not None else None
    items, sequence = [], 0
    while offset <= last_allowed:
        sequence += 1
        size = payload["bytes"] if payload["kind"] == "fixed" else sizes.randint(payload["low"], payload["high"])
        items.append((sequence, offset, size))
        offset += round(gap * (1 + jitter.uniform(-fraction, fraction)))
    return items


def payload(run_id, device, sequence, size):
    """Correlation fields plus padding to the exact frozen size. Untrusted content for the observer."""
    body = dict(r=run_id, d=device, s=sequence, v=(sequence * 17) % 1000, p="")
    encode = lambda: json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    pad = size - len(encode())
    if pad < 0:
        raise ValueError("payload size too small for correlation fields")
    body["p"] = "x" * pad
    raw = encode()
    if len(raw) != size:
        raise ValueError("payload size mismatch")
    return raw


def utc_to_epoch_ns(text):
    stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return calendar.timegm(stamp.utctimetuple()) * 1_000_000_000 + stamp.microsecond * 1000


def epoch_ns_to_utc(value):
    seconds, rest = divmod(int(value), 1_000_000_000)
    stamp = datetime.fromtimestamp(seconds, timezone.utc).replace(microsecond=rest // 1000)
    return stamp.isoformat(timespec="microseconds").replace("+00:00", "Z")


class ObserverCoverage:
    """Reads (never writes) the observer's own evidence to learn when its coverage started."""
    def __init__(self, root, run_id, purpose):
        self.root, self.run_id, self.purpose = Path(root) / "observation", run_id, purpose

    def __call__(self):
        matches = []
        for meta in sorted(self.root.glob("obs-*/session_metadata.json")):
            try:
                data = json.loads(meta.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if data.get("collection_run_id") == self.run_id:
                matches.append((meta.parent, data))
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
                continue  # a line still being written
            if record.get("kind") == "COVERAGE_START":
                return dict(observer_session_id=data["observer_session_id"], coverage_start_utc=record["utc"])
            if record.get("kind") == "SESSION_END":
                raise WorkloadError("observer_session_ended_before_coverage")
        return None


class DevicePublisher:
    """Thin adapter over the unchanged A3 MQTTClient; PUBACKs are reported from the Paho callback."""
    def __init__(self, username, on_ack, emit, host="broker", credentials="/run/secrets"):
        from experiments.a3_mqtt import MQTTClient, password_for
        self.inner = MQTTClient(username, password_for(username, credentials), emit, host)
        original = self.inner.client.on_publish

        def published(client, userdata, mid, reason, properties):
            original(client, userdata, mid, reason, properties)
            on_ack(mid, reason.value)
        self.inner.client.on_publish = published

    @property
    def connected(self):
        return self.inner.connected

    def connect(self, timeout):
        return self.inner.connect(timeout)

    def publish(self, topic, data):
        from experiments.a3_mqtt import ProbeError
        try:
            return self.inner.publish(topic, data, PUBLISH_QOS).mid  # A3 publish always uses retain=False
        except ProbeError:
            return None

    def loop(self, timeout):
        return self.inner.client.loop(timeout=timeout)

    def close(self):
        self.inner.close()


class WorkloadRunner:
    def __init__(self, *, config, purpose, output_root, publisher_factory, coverage_source, clock=time.monotonic_ns,
                 wall=time.time_ns, utc=utc_now, runtime=None, plan_ref=None, attestation=None,
                 coverage_timeout_ns=120_000_000_000, ack_timeout_ns=10_000_000_000, idle=time.sleep):
        if purpose not in PURPOSES:
            raise ValueError("purpose must be FUNCTIONAL_TEST or COLLECTION")
        if config["qos"] != PUBLISH_QOS or config["retain"] is not False:
            raise ValueError("workload must be QoS 1 without retain")
        self.config, self.purpose, self.clock, self.wall, self.utc, self.idle = config, purpose, clock, wall, utc, idle
        self.run_id = config["run_id"]
        self.coverage_source, self.publisher_factory = coverage_source, publisher_factory
        self.coverage_timeout_ns, self.ack_timeout_ns = coverage_timeout_ns, ack_timeout_ns
        self.path = Path(output_root) / "collection" / self.run_id
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.mkdir(exist_ok=False)  # never overwrite prior evidence
        self.devices = sorted(config["devices"])
        self.files = {}
        self.pending = {device: {} for device in self.devices}
        self.messages = {device: {} for device in self.devices}
        self.lifecycle = []
        self.publishers = {}
        self.failure = None
        self.coverage = None
        self.mono_coverage = None
        self.epoch_coverage = None
        self.schedules = {device: schedule(config, device) for device in self.devices}
        for device in self.devices:
            self.files[device] = (self.path / f"ledger_{device}.jsonl").open("x", encoding="utf-8", newline="\n")
        self.metadata = dict(
            schema=SUMMARY_SCHEMA, schema_version=SCHEMA_VERSION, record="WORKLOAD_METADATA", run_id=self.run_id,
            purpose=purpose, plan_kind=config["kind"], plan_ref=plan_ref, attestation=attestation,
            workload_config_sha256=plans.digest(config), generator_version=config["generator_version"],
            devices={d: dict(profile=config["devices"][d]["profile"], username=config["devices"][d]["username"],
                             client_id=config["devices"][d]["client_id"],
                             telemetry_topic=config["devices"][d]["telemetry_topic"],
                             planned_messages=len(self.schedules[d])) for d in self.devices},
            runtime=runtime or {}, utc_start=utc(),
            identity_note="ledger is corroborating evidence only; observer topic binding is authoritative")
        self._write_json("workload_metadata.json", self.metadata)

    def _write_json(self, name, value):
        with (self.path / name).open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")

    def _ledger(self, device, **fields):
        record = dict(schema=LEDGER_SCHEMA, schema_version=SCHEMA_VERSION, run_id=self.run_id, purpose=self.purpose,
                      device=device, **fields)
        self.files[device].write(json.dumps(record, sort_keys=True, allow_nan=False) + "\n")
        self.files[device].flush()

    def _offset(self, now=None):
        return (self.clock() if now is None else now) - self.mono_coverage

    def _ack(self, device, mid, reason):
        now = self.clock()
        sequence = self.pending[device].pop(mid, None)
        outcome = ("accepted" if reason == 0 else "accepted_no_matching_subscribers" if reason == 16
                   else "denied" if reason >= 128 else "other")
        self._ledger(device, record_type="PUBACK", sequence=sequence, mqtt_mid=mid, puback_reason=reason,
                     puback_offset_ns=self._offset(now), puback_monotonic_ns=now, puback_utc=self.utc(), outcome=outcome)
        if sequence is None:
            self.failure = self.failure or "unexpected_puback"
            return
        self.messages[device][sequence]["puback_reason"] = reason
        if reason != 0:
            self.failure = self.failure or {"denied": "publish_denied", "other": "unexpected_puback_code",
                                            "accepted_no_matching_subscribers": "puback_no_matching_subscribers"}[outcome]

    def _pump(self, until_ns):
        while True:
            now = self.clock()
            if now >= until_ns:
                return
            share = min(LOOP_SLICE_S, (until_ns - now) / 1e9 / len(self.publishers))
            for device, publisher in self.publishers.items():
                if publisher.loop(max(0.0, share)) != 0 or not publisher.connected:
                    raise WorkloadError("publisher_connection_lost")

    def _wait_coverage(self):
        deadline = self.clock() + self.coverage_timeout_ns
        while True:
            found = self.coverage_source()
            if found:
                return found
            if self.clock() >= deadline:
                raise WorkloadError("observer_coverage_not_detected")
            self.idle(0.05)

    def run(self):
        state = "INCOMPLETE"
        try:
            self.coverage = self._wait_coverage()
            self.epoch_coverage = utc_to_epoch_ns(self.coverage["coverage_start_utc"])
            self.mono_coverage = self.clock() - (self.wall() - self.epoch_coverage)
            for device in self.devices:
                spec = self.config["devices"][device]
                if spec["username"] != spec["client_id"]:
                    raise WorkloadError("bound client id must equal the registered username")
                publisher = self.publisher_factory(
                    spec["username"], lambda mid, reason, d=device: self._ack(d, mid, reason),
                    lambda kind, d=device, **fields: self.lifecycle.append(dict(device=d, kind=kind, **{
                        k: v for k, v in fields.items() if k in ("reason_code", "intentional", "server_disconnect_packet")})))
                self.publishers[device] = publisher
                if publisher.connect(3) != 0:
                    raise WorkloadError("publisher_authentication_rejected")
            items = sorted((offset, device, sequence, size) for device in self.devices
                           for sequence, offset, size in self.schedules[device])
            if not items:
                raise WorkloadError("empty_schedule")
            if self._offset() >= items[0][0]:
                raise WorkloadError("coverage_detected_too_late")
            for offset, device, sequence, size in items:
                self._pump(self.mono_coverage + offset)
                if self.failure:
                    break
                spec = self.config["devices"][device]
                data = payload(self.run_id, device, sequence, size)
                attempt = self.clock()
                mid = self.publishers[device].publish(spec["telemetry_topic"], data)
                self.messages[device][sequence] = dict(queued=mid is not None, puback_reason=None)
                if mid is not None:
                    self.pending[device][mid] = sequence
                self._ledger(device, record_type="ATTEMPT", configured_username=spec["username"],
                             configured_client_id=spec["client_id"], topic=spec["telemetry_topic"], qos=PUBLISH_QOS,
                             retain=False, sequence=sequence, scheduled_offset_ns=offset,
                             scheduled_utc=epoch_ns_to_utc(self.epoch_coverage + offset),
                             attempt_offset_ns=self._offset(attempt), attempt_monotonic_ns=attempt, attempt_utc=self.utc(),
                             payload_bytes=len(data), payload_sha256=hashlib.sha256(data).hexdigest(), mqtt_mid=mid,
                             queued=mid is not None, outcome="queued" if mid is not None else "enqueue_failed")
                if mid is None:
                    self.failure = self.failure or "publish_enqueue_failed"
                    break
            deadline = self.clock() + self.ack_timeout_ns
            while any(self.pending.values()) and self.clock() < deadline and not self.failure:
                self._pump(min(deadline, self.clock() + 10_000_000))
            if any(self.pending.values()) and not self.failure:
                self.failure = "puback_timeout"
            planned = all(len(self.messages[d]) == len(self.schedules[d]) for d in self.devices)
            if not self.failure and planned:
                state = "COMPLETE"
            elif not self.failure:
                self.failure = "schedule_not_completed"
        except WorkloadError as exc:
            self.failure = self.failure or str(exc)
        except Exception as exc:  # fail closed, without echoing arbitrary text
            self.failure = self.failure or f"unexpected_{type(exc).__name__}"
        finally:
            for publisher in self.publishers.values():
                try:
                    publisher.close()
                except Exception:
                    self.failure = self.failure or "shutdown_error"
                    state = "INCOMPLETE"
            for stream in self.files.values():
                stream.close()
        return self._finish(state)

    def _finish(self, state):
        devices = {}
        for device in self.devices:
            values = list(self.messages[device].values())
            reasons = [m["puback_reason"] for m in values]
            devices[device] = dict(
                profile=self.config["devices"][device]["profile"], planned_messages=len(self.schedules[device]),
                attempted=len(values), queued=sum(m["queued"] for m in values),
                accepted=reasons.count(0), accepted_no_matching_subscribers=reasons.count(16),
                denied=sum(r is not None and r >= 128 for r in reasons),
                other=sum(r is not None and r not in (0, 16) and r < 128 for r in reasons),
                unacknowledged=sum(m["queued"] and m["puback_reason"] is None for m in values),
                ledger_sha256=file_sha256(self.path / f"ledger_{device}.jsonl"))
        summary = dict(self.metadata, record="WORKLOAD_SUMMARY", state=state, failure_code=self.failure,
                       observer_session_id=(self.coverage or {}).get("observer_session_id"),
                       coverage_start_utc=(self.coverage or {}).get("coverage_start_utc"),
                       devices_result=devices, lifecycle=self.lifecycle, utc_end=self.utc())
        self._write_json("workload_summary.json", summary)
        return summary


def verify_collection(manifest_path, run_id, plan, config):
    """Repeat the committed-plan check inside the container and bind the run config to RUN_PLANNED."""
    attestation = manifest_module.check_collection_allowed(
        manifest_path, run_id, expected_manifest_sha256=os.getenv("AZTA_MANIFEST_SHA256", ""),
        git_commit=os.getenv("AZTA_GIT_COMMIT"), git_state=os.getenv("AZTA_GIT_STATE"))
    state = manifest_module.validate(manifest_module.read_entries(manifest_path))
    plans.check_manifest_against_plan(state, plan)
    if state["planned"][run_id]["workload_config_sha256"] != plans.digest(config):
        raise ValueError("run config differs from the committed RUN_PLANNED digest")
    return attestation


def runtime():
    return dict(python=platform.python_version(), paho_mqtt=importlib.metadata.version("paho-mqtt"),
                git_commit=os.getenv("AZTA_GIT_COMMIT", "unknown"), git_state=os.getenv("AZTA_GIT_STATE", "unknown"),
                container_image=os.getenv("AZTA_RUNTIME_IMAGE", "unknown"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--purpose", required=True, choices=PURPOSES)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--manifest", help="Required for COLLECTION (committed RUN_PLANNED).")
    parser.add_argument("--registry", default="/app/configs/observation/device_registry.json")
    parser.add_argument("--output-dir", default="/results")
    parser.add_argument("--host", default=os.getenv("MQTT_HOST", "broker"))
    parser.add_argument("--credentials", default="/run/secrets")
    parser.add_argument("--coverage-timeout-s", type=float, default=120.0)
    args = parser.parse_args(argv)
    try:
        registry = DeviceRegistry.load(args.registry)
        plan = plans.validate_plan(plans.load_plan(args.plan), registry)
        config = plan["runs"].get(args.run_id)
        if config is None:
            raise ValueError("run is not in the plan")
        attestation = None
        if args.purpose == "COLLECTION":
            if plan["kind"] not in ("SCIENTIFIC", "WRAPPER_VALIDATION_NOT_DATA") or not args.manifest:
                raise ValueError("COLLECTION needs a collection plan and its committed manifest")
            attestation = verify_collection(args.manifest, args.run_id, plan, config)
        elif plan["kind"] != "FUNCTIONAL_TEST" or args.manifest:
            raise ValueError("FUNCTIONAL_TEST uses only a FUNCTIONAL_TEST plan and no manifest")
        runner = WorkloadRunner(
            config=config, purpose=args.purpose, output_root=args.output_dir,
            publisher_factory=lambda username, on_ack, emit: DevicePublisher(username, on_ack, emit, args.host,
                                                                            args.credentials),
            coverage_source=ObserverCoverage(args.output_dir, args.run_id, args.purpose),
            runtime=runtime(), plan_ref=dict(plan_id=plan["plan_id"], plan_sha256=plans.digest(plan)),
            attestation=attestation, coverage_timeout_ns=int(args.coverage_timeout_s * 1e9))
    except (ValueError, OSError, KeyError, manifest_module.ManifestError) as exc:
        print(f"WORKLOAD_REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    summary = runner.run()
    counts = " ".join(f'{d}={r["accepted"]}/{r["planned_messages"]}' for d, r in summary["devices_result"].items())
    print(f'WORKLOAD_RUN {args.run_id} {summary["state"]} failure={summary["failure_code"]} accepted {counts}')
    return 0 if summary["state"] == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
