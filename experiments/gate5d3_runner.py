"""Gate 5D.3 ten-device FUNCTIONAL publisher runner (offline-prepared; no scientific collection).

Consumes the accepted Gate 5D.3A engineering fixture (schedules, exact payload bytes) and identity specification and,
when a later authorized task runs it, publishes QoS 1 / non-retained telemetry as ONE device per process on that device's
own exact topic. It is separately versioned and does not use or alter the Gate 5C collection runner.

Deployment mode (credential isolation). The live mode is SINGLE_DEVICE: `--device deviceNN --credential-file <that device's
file only>`. One process, one MQTT identity/client ID, one topic, one credential file; the code is shared, the instances are
ten. A process refuses an unknown device, a device/identity/topic mismatch, a credential file that is not named for its own
identity, and a credential directory that exposes any other identity's credential. The ALL_DEVICES mode exists only to
validate the shared fixture and to drive offline tests with fake publishers; it never connects (the CLI refuses a live
run, and the real publisher class refuses a credential directory shared with other identities).

Shared-run coordination. All ten instances load the same fixture (one run ID, one digest, one set of deterministic schedules)
and are given the expected run ID and fixture digest, which they must match. Their common time origin is the observer's
recorded COVERAGE_START (UTC), read from the shared evidence the observer writes; every instance converts it to its own
monotonic clock. The planned experiment start is that instant plus lead_in_windows * W. Instances do not start together:
each connects first (so connection latency is off the schedule-critical path), then waits for the observer coverage, and
records its actual startup and scheduling offsets. No clock synchronization is claimed or measured. The late-message
skip/abort policy is UNRESOLVED and is not decided here: an overdue target is published when reached and its lateness is
recorded.

Safety properties: importing this module or validating a configuration opens no connection and reads no credential
(credential files are only stat'ed; contents are read solely by the unchanged A3 MQTTClient at connect time and never
logged); the purpose is FUNCTIONAL_TEST only: nothing here is a Gate 5C scientific run, a manifest entry or a model route.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time

from experiments import gate5d3_plan as plan
from experiments import gate5d3_workload as workload
from experiments.collection_workload import ObserverCoverage, WorkloadError, epoch_ns_to_utc, utc_to_epoch_ns
from experiments.research_records import utc_now
from observation.records import file_sha256
from observation.registry import DeviceRegistry
from observation.schema import canonical, observation_config_sha256, sha256_text

RUNNER_VERSION = "gate5d3-runner-2"
LEDGER_SCHEMA = "azta.gate5d3.publisher_ledger"
SUMMARY_SCHEMA = "azta.gate5d3.workload_summary"
PURPOSE = "FUNCTIONAL_TEST"
PUBLISH_QOS = 1
LOOP_SLICE_S = 0.002
MAX_CREDENTIAL_BYTES = 4096
OBSERVER_CREDENTIAL = "azta-observer-password"
CREDENTIAL_SUFFIX = "-password"
DEVICE_ID = re.compile(r"device\d\d\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MODE_SINGLE = "SINGLE_DEVICE"
MODE_ALL = "ALL_DEVICES_OFFLINE_FIXTURE"
COORDINATION_ANCHOR = "observer_coverage_start"
CLOCK_BASIS = ("host system clock (UTC wall time) sampled against this process's monotonic clock when the shared observer "
               "coverage start is detected; clock synchronization between instances is neither claimed nor measured")
LATE_POLICY = ("UNRESOLVED: no skip, abort or catch-up decision is made here; an overdue target is published when reached "
               "and its lateness is recorded")


class RunnerConfigError(ValueError):
    pass


def _require(condition, message):
    if not condition:
        raise RunnerConfigError(message)


def assert_isolated_credential(path):
    """Refuse a credential directory that exposes any other credential file. Names and contents are never read or reported."""
    path = Path(path)
    try:
        others = [p for p in path.parent.iterdir() if p.name.endswith(CREDENTIAL_SUFFIX) and p.name != path.name]
    except OSError:
        raise RunnerConfigError("credential directory cannot be inspected") from None
    _require(not others, f"credential directory exposes {len(others)} other credential file(s); one credential per instance")


class RunConfig:
    """A fully validated, connection-free runner configuration (SINGLE_DEVICE live mode or ALL_DEVICES offline fixture)."""

    def __init__(self, fixture, registry, identity_spec, *, device=None, credential_file=None, credentials_dir=None,
                 expected_run_id=None, expected_fixture_sha256=None):
        _require(isinstance(fixture, dict) and fixture.get("schema") == plan.FIXTURE_SCHEMA, "not a Gate 5D.3 fixture")
        body = {k: v for k, v in fixture.items() if k != "fixture_sha256"}
        _require(fixture.get("fixture_sha256") == sha256_text(canonical(body)), "fixture digest mismatch")
        _require(fixture["kind"] == "FUNCTIONAL_ENGINEERING_FIXTURE" and fixture["scientific"] is False
                 and fixture["partition"] is None and fixture["split_assignment"] is None,
                 "only an engineering fixture without partition assignment can be run")
        _require(fixture["registry_sha256"] == registry.sha256, "fixture registry digest differs from the registry")
        _require(fixture["observation_config_sha256"] == observation_config_sha256(fixture["window_ns"], registry.sha256, 1),
                 "fixture observation configuration digest is inconsistent")
        by_device = {e.device: e for e in registry.devices}
        spec = {item["device"]: item for item in identity_spec["additional_devices"]}
        preserved = set(identity_spec["preserved_devices"])
        _require(bool(fixture["devices"]), "fixture has no devices")
        self.fixture, self.registry = fixture, registry
        self.run_id = fixture["run_id"]
        schedules, specs = {}, {}
        for dev in sorted(fixture["devices"]):  # the whole shared fixture is validated by every instance
            item = fixture["devices"][dev]
            entry = by_device.get(dev)
            _require(entry is not None, f"{dev} is not in the registry")
            _require(item["slot"] == int(dev[-2:]) and workload.device_for(item["slot"]) == dev, f"{dev}: slot mismatch")
            _require((item["username"], item["client_id"], item["telemetry_topic"])
                     == (entry.username, entry.client_id, entry.telemetry_topic), f"{dev}: identity/topic differs from the registry")
            _require(item["username"] == item["client_id"], f"{dev}: bound client ID must equal the username")
            _require(dev in preserved or (dev in spec and spec[dev]["username"] == entry.username
                                          and spec[dev]["client_id"] == entry.client_id),
                     f"{dev}: not covered by the identity specification")
            built = workload.schedule(self.run_id, item["slot"], window_ns=fixture["window_ns"],
                                      lead_in_windows=fixture["lead_in_windows"], eligible_windows=fixture["eligible_windows"])
            _require(workload.schedule_sha256(built["items"]) == item["schedule_sha256"]
                     and len(built["items"]) == item["planned_messages"], f"{dev}: schedule differs from the fixture")
            _require(item["approved_model_route"] is None, f"{dev}: no model route may be attached")
            schedules[dev], specs[dev] = built["items"], item
        if device is not None:
            self.mode = MODE_SINGLE
            _require(isinstance(device, str) and DEVICE_ID.fullmatch(device), "device must be exactly one device identifier")
            _require(device in specs, f"{device} is not in the fixture")
            _require(credential_file is not None and credentials_dir is None,
                     "single-device mode needs exactly its own --credential-file and no credential directory")
            _require(expected_run_id == self.run_id, "expected run ID differs from the fixture")
            _require(isinstance(expected_fixture_sha256, str) and SHA256.fullmatch(expected_fixture_sha256)
                     and expected_fixture_sha256 == fixture["fixture_sha256"], "expected fixture digest differs from the fixture")
            path = Path(credential_file)
            _require(path.name == f"{specs[device]['username']}{CREDENTIAL_SUFFIX}",
                     f"{device}: credential file is not named for this device's identity")
            _require(path.name != OBSERVER_CREDENTIAL, "a device may not use the observer credential")
            self.devices, self.credentials = [device], {device: path}
        else:
            self.mode = MODE_ALL
            _require(credential_file is None and credentials_dir is not None,
                     "all-devices mode needs a credential directory and no single credential file")
            root = Path(credentials_dir)
            self.devices = sorted(specs)
            self.credentials = {dev: root / f"{specs[dev]['username']}{CREDENTIAL_SUFFIX}" for dev in self.devices}
            _require(root / OBSERVER_CREDENTIAL not in self.credentials.values(), "a device credential may not be the observer credential")
        paths = list(self.credentials.values())
        _require(len(set(paths)) == len(paths), "devices must not share a credential file")
        self.schedules = {d: schedules[d] for d in self.devices}
        self.specs = {d: specs[d] for d in self.devices}
        self.planned_start = dict(
            anchor=COORDINATION_ANCHOR, offset_ns=fixture["lead_in_windows"] * fixture["window_ns"],
            run_id=self.run_id, fixture_sha256=fixture["fixture_sha256"], window_ns=fixture["window_ns"],
            lead_in_windows=fixture["lead_in_windows"], eligible_windows=fixture["eligible_windows"])

    def check_credentials(self):
        """Existence, size and isolation only; contents are never read. Names devices, never paths or secrets."""
        missing = []
        for device, path in self.credentials.items():
            try:
                ok = path.is_file() and 0 < path.stat().st_size <= MAX_CREDENTIAL_BYTES
            except OSError:
                ok = False
            if not ok:
                missing.append(device)
        _require(not missing, f"credential file missing, empty or too large for: {', '.join(missing)}")
        if self.mode == MODE_SINGLE:
            assert_isolated_credential(self.credentials[self.devices[0]])


class DevicePublisher:
    """Thin adapter over the unchanged A3 MQTTClient with an explicit credential path. Connects only on connect()."""
    def __init__(self, username, credential_path, on_ack, emit, host="broker"):
        assert_isolated_credential(credential_path)  # a real connection never starts beside other identities' credentials
        from experiments.a3_mqtt import MQTTClient
        self.inner = MQTTClient(username, credential_path, emit, host)
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


class TenDeviceRunner:
    def __init__(self, *, config, output_root, publisher_factory, coverage_source, clock=time.monotonic_ns,
                 wall=time.time_ns, utc=utc_now, runtime=None, coverage_timeout_ns=120_000_000_000,
                 ack_timeout_ns=10_000_000_000, idle=time.sleep):
        self.config, self.clock, self.wall, self.utc, self.idle = config, clock, wall, utc, idle
        self.coverage_source, self.publisher_factory = coverage_source, publisher_factory
        self.coverage_timeout_ns, self.ack_timeout_ns = coverage_timeout_ns, ack_timeout_ns
        self.run_id, self.devices = config.run_id, config.devices
        instance = self.devices[0] if config.mode == MODE_SINGLE else "all_devices_fixture"
        # never under Gate 5C's collection/ directory; one directory per instance so concurrent instances never collide
        self.path = Path(output_root) / "gate5d3_workload" / self.run_id / instance
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.mkdir(exist_ok=False)  # never overwrite prior evidence
        self.pending = {d: {} for d in self.devices}
        self.messages = {d: {} for d in self.devices}
        self.lifecycle, self.publishers = [], {}
        self.failure = self.coverage = self.mono_coverage = self.epoch_coverage = None
        self.startup = {}
        self.files = {d: (self.path / f"ledger_{d}.jsonl").open("x", encoding="utf-8", newline="\n") for d in self.devices}
        self.metadata = dict(
            schema=SUMMARY_SCHEMA, schema_version=1, record="WORKLOAD_METADATA", runner_version=RUNNER_VERSION,
            mode=config.mode, run_id=self.run_id, purpose=PURPOSE, fixture_sha256=config.fixture["fixture_sha256"],
            registry_sha256=config.registry.sha256, coordination=dict(config.planned_start, clock_basis=CLOCK_BASIS),
            late_policy=LATE_POLICY,
            devices={d: dict(slot=config.specs[d]["slot"], username=config.specs[d]["username"],
                             client_id=config.specs[d]["client_id"], telemetry_topic=config.specs[d]["telemetry_topic"],
                             planned_messages=len(config.schedules[d])) for d in self.devices},
            runtime=runtime or {}, utc_start=utc(),
            identity_note="ledger is corroborating evidence only; observer topic binding is authoritative")
        self._write_json("workload_metadata.json", self.metadata)

    def _write_json(self, name, value):
        with (self.path / name).open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")

    def _ledger(self, device, **fields):
        record = dict(schema=LEDGER_SCHEMA, schema_version=1, run_id=self.run_id, purpose=PURPOSE, device=device, **fields)
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
                     puback_offset_ns=None if self.mono_coverage is None else self._offset(now),
                     puback_utc=self.utc(), outcome=outcome)
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
            for publisher in self.publishers.values():
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
            if self.publishers:
                self._pump(min(deadline, self.clock() + 50_000_000))  # keep the connections alive while waiting
            else:
                self.idle(0.05)

    def run(self):
        state = "INCOMPLETE"
        try:
            self.startup["process_start_utc"] = self.utc()
            self.config.check_credentials()
            for device in self.devices:  # connect first: connection latency stays off the schedule-critical path
                spec = self.config.specs[device]
                self.publishers[device] = self.publisher_factory(
                    spec["username"], self.config.credentials[device],
                    lambda mid, reason, d=device: self._ack(d, mid, reason),
                    lambda kind, d=device, **fields: self.lifecycle.append(dict(device=d, kind=kind, **{
                        k: v for k, v in fields.items() if k in ("reason_code", "intentional", "server_disconnect_packet")})))
                if self.publishers[device].connect(3) != 0:
                    raise WorkloadError("publisher_authentication_rejected")
            ready = self.clock()
            self.startup["connected_utc"] = self.utc()
            self.coverage = self._wait_coverage()
            detected = self.clock()
            self.startup["coverage_detected_utc"] = self.utc()
            self.epoch_coverage = utc_to_epoch_ns(self.coverage["coverage_start_utc"])
            sample_mono = self.clock()
            sample_wall = self.wall()
            self.mono_coverage = sample_mono - (sample_wall - self.epoch_coverage)
            items = sorted((offset, device, sequence, size) for device in self.devices
                           for sequence, offset, size in self.config.schedules[device])
            if not items:
                raise WorkloadError("empty_schedule")
            ready_offset, detected_offset = ready - self.mono_coverage, detected - self.mono_coverage
            self.startup.update(
                anchor_sample=dict(monotonic_ns=sample_mono, wall_ns=sample_wall),
                ready_offset_ns=ready_offset, coverage_detected_offset_ns=detected_offset,
                first_scheduled_offset_ns=items[0][0], ready_margin_ns=items[0][0] - max(ready_offset, detected_offset))
            if self._offset() >= items[0][0]:
                raise WorkloadError("coverage_detected_too_late")
            for offset, device, sequence, size in items:
                self._pump(self.mono_coverage + offset)
                if self.failure:
                    break
                spec = self.config.specs[device]
                data = workload.payload_bytes(self.run_id, spec["slot"], sequence, size)
                attempt = self.clock()
                mid = self.publishers[device].publish(spec["telemetry_topic"], data)  # only this device's own topic
                self.messages[device][sequence] = dict(queued=mid is not None, puback_reason=None,
                                                      late_ns=self._offset(attempt) - offset)
                if mid is not None:
                    self.pending[device][mid] = sequence
                self._ledger(device, record_type="ATTEMPT", slot=spec["slot"], configured_username=spec["username"],
                             configured_client_id=spec["client_id"], topic=spec["telemetry_topic"], qos=PUBLISH_QOS,
                             retain=False, sequence=sequence, scheduled_offset_ns=offset,
                             scheduled_utc=epoch_ns_to_utc(self.epoch_coverage + offset),
                             attempt_offset_ns=self._offset(attempt), lateness_ns=self._offset(attempt) - offset,
                             attempt_utc=self.utc(), payload_bytes=len(data),
                             payload_sha256=hashlib.sha256(data).hexdigest(), mqtt_mid=mid, queued=mid is not None,
                             outcome="queued" if mid is not None else "enqueue_failed")
                if mid is None:
                    self.failure = self.failure or "publish_enqueue_failed"
                    break
            deadline = self.clock() + self.ack_timeout_ns
            while any(self.pending.values()) and self.clock() < deadline and not self.failure:
                self._pump(min(deadline, self.clock() + 10_000_000))
            if any(self.pending.values()) and not self.failure:
                self.failure = "puback_timeout"
            planned = all(len(self.messages[d]) == len(self.config.schedules[d]) for d in self.devices)
            if not self.failure and planned:
                state = "COMPLETE"
            elif not self.failure:
                self.failure = "schedule_not_completed"
        except (WorkloadError, RunnerConfigError) as exc:
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
            late = [m["late_ns"] for m in values]
            devices[device] = dict(
                slot=self.config.specs[device]["slot"], planned_messages=len(self.config.schedules[device]),
                attempted=len(values), queued=sum(m["queued"] for m in values), accepted=reasons.count(0),
                accepted_no_matching_subscribers=reasons.count(16),
                denied=sum(r is not None and r >= 128 for r in reasons),
                other=sum(r is not None and r not in (0, 16) and r < 128 for r in reasons),
                unacknowledged=sum(m["queued"] and m["puback_reason"] is None for m in values),
                lateness_ns=(dict(count=len(late), min=min(late), max=max(late), mean=sum(late) / len(late))
                             if late else None),
                ledger_sha256=file_sha256(self.path / f"ledger_{device}.jsonl"))
        summary = dict(self.metadata, record="WORKLOAD_SUMMARY", state=state, failure_code=self.failure,
                       observer_session_id=(self.coverage or {}).get("observer_session_id"),
                       coverage_start_utc=(self.coverage or {}).get("coverage_start_utc"),
                       startup=self.startup, devices_result=devices, lifecycle=self.lifecycle, utc_end=self.utc())
        self._write_json("workload_summary.json", summary)
        return summary


def reconcile_instances(summaries, expected_devices=None):
    """Structural consistency of the independent per-device instance summaries of ONE shared run (pure, offline).

    Checks that every instance belongs to the same run, fixture, registry and observer coverage, that each device appears
    once and completed, and reports (without any pass/fail threshold) the startup and lateness spread. The verdict is
    structural only; it neither decides the late-message policy nor claims clock synchronization."""
    reasons = []
    summaries = list(summaries)
    if not summaries:
        return dict(verdict="INCONSISTENT", reasons=["no instance summaries"])
    keys = ("run_id", "fixture_sha256", "registry_sha256", "runner_version", "observer_session_id", "coverage_start_utc")
    for key in keys:
        if len({s.get(key) for s in summaries}) != 1 or summaries[0].get(key) is None:
            reasons.append(f"instances disagree on, or lack, {key}")
    if len({json.dumps(s.get("coordination"), sort_keys=True) for s in summaries}) != 1:
        reasons.append("instances disagree on the coordination descriptor")
    devices = [next(iter(s["devices"])) if len(s.get("devices", {})) == 1 else None for s in summaries]
    if any(s.get("mode") != MODE_SINGLE for s in summaries) or None in devices:
        reasons.append("every summary must be a single-device instance")
    if len(set(devices)) != len(devices):
        reasons.append("a device appears in more than one instance")
    if expected_devices is not None and set(devices) != set(expected_devices):
        reasons.append("instance devices differ from the expected set")
    for s, device in zip(summaries, devices):
        if s.get("state") != "COMPLETE":
            reasons.append(f"{device}: instance is {s.get('state')} ({s.get('failure_code')})")
    startups = [s.get("startup") or {} for s in summaries]
    detected = [u["coverage_detected_offset_ns"] for u in startups if "coverage_detected_offset_ns" in u]
    margins = [u["ready_margin_ns"] for u in startups if "ready_margin_ns" in u]
    lateness = [r["lateness_ns"]["max"] for s in summaries for r in s.get("devices_result", {}).values() if r.get("lateness_ns")]
    return dict(
        verdict="CONSISTENT" if not reasons else "INCONSISTENT", reasons=reasons, devices=sorted(d for d in devices if d),
        startup=dict(coverage_detected_offset_spread_ns=(max(detected) - min(detected)) if detected else None,
                     min_ready_margin_ns=min(margins) if margins else None),
        max_lateness_ns=max(lateness) if lateness else None, clock_basis=CLOCK_BASIS, late_policy=LATE_POLICY)


def load_config(fixture_path, registry_path, identity_spec_path, **options):
    fixture = json.loads(Path(fixture_path).read_text(encoding="utf-8"))
    spec = json.loads(Path(identity_spec_path).read_text(encoding="utf-8"))
    return RunConfig(fixture, DeviceRegistry.load(registry_path), spec, **options)


def runtime():
    import importlib.metadata
    import platform
    return dict(python=platform.python_version(), paho_mqtt=importlib.metadata.version("paho-mqtt"),
                git_commit=os.getenv("AZTA_GIT_COMMIT", "unknown"), git_state=os.getenv("AZTA_GIT_STATE", "unknown"),
                container_image=os.getenv("AZTA_RUNTIME_IMAGE", "unknown"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True, help="engineering fixture JSON from experiments.gate5d3_plan (shared by all instances)")
    parser.add_argument("--registry", default="/app/configs/observation/device_registry_v2.json")
    parser.add_argument("--identity-spec", default="/app/configs/gate5d3/identity_spec.json")
    parser.add_argument("--device", action="append", help="the ONE device this instance simulates (live mode); repeating it is refused")
    parser.add_argument("--credential-file", help="that device's own credential file (live mode)")
    parser.add_argument("--expected-run-id", help="shared run ID; must equal the fixture's (live mode)")
    parser.add_argument("--expected-fixture-sha256", help="shared fixture digest; must equal the fixture's (live mode)")
    parser.add_argument("--all-devices", action="store_true",
                        help="offline fixture validation only; requires --validate-only and --credentials-dir")
    parser.add_argument("--credentials-dir", help="all-devices offline validation only")
    parser.add_argument("--output-dir", default="/results")
    parser.add_argument("--host", default=os.getenv("MQTT_HOST", "broker"))
    parser.add_argument("--coverage-timeout-s", type=float, default=120.0)
    parser.add_argument("--validate-only", action="store_true", help="validate configuration and credential files; no connection")
    args = parser.parse_args(argv)
    try:
        _require(args.device is None or len(args.device) == 1, "exactly one --device per instance")
        device = args.device[0] if args.device else None
        if args.all_devices:
            _require(args.validate_only and device is None and args.credential_file is None,
                     "all-devices mode is an offline fixture check: use --validate-only, no --device, no --credential-file")
            options = dict(credentials_dir=args.credentials_dir)
        else:
            _require(device is not None and args.credentials_dir is None,
                     "a live instance needs exactly one --device and its own --credential-file")
            options = dict(device=device, credential_file=args.credential_file,
                           expected_run_id=args.expected_run_id, expected_fixture_sha256=args.expected_fixture_sha256)
        config = load_config(args.fixture, args.registry, args.identity_spec, **options)
        config.check_credentials()
        if args.validate_only:
            print(f"GATE5D3_RUNNER_CONFIG_OK mode={config.mode} run_id={config.run_id} devices={len(config.devices)} "
                  "(no connection made)")
            return 0
        runner = TenDeviceRunner(
            config=config, output_root=args.output_dir,
            publisher_factory=lambda username, path, on_ack, emit: DevicePublisher(username, path, on_ack, emit, args.host),
            coverage_source=ObserverCoverage(args.output_dir, config.run_id, PURPOSE), runtime=runtime(),
            coverage_timeout_ns=int(args.coverage_timeout_s * 1e9))
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as exc:
        print(f"GATE5D3_RUNNER_REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    summary = runner.run()
    counts = " ".join(f'{d}={r["accepted"]}/{r["planned_messages"]}' for d, r in summary["devices_result"].items())
    print(f'GATE5D3_WORKLOAD_RUN {config.run_id} {summary["state"]} failure={summary["failure_code"]} accepted {counts}')
    return 0 if summary["state"] == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
