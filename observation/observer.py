"""Gate 5B live observer: the existing receive-only azta-pdp principal, literal telemetry subscriptions.

Observational only. It never parses payloads, never publishes, never touches the Dynamic Security control topic, holds no
administration credential and writes files only. Device binding is derived from the exact
delivered topic through the versioned registry, backed by a separate read-only Dynamic Security
audit; the delivered MQTT message does not carry the publisher username to this subscriber.
No reconnect within a session: an unexpected disconnect ends complete coverage (D5).
Gate 5D.3B-0: optionally a dedicated azta-observer principal with an explicit credential file
(--observer-identity/--credential-file, given together); the historical azta-pdp default is unchanged.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import sys
import time
import uuid

from experiments.a3_mqtt import MQTTClient, ProbeError, password_for
from experiments.research_records import utc_now
from observation import manifest as manifest_module
from observation.records import ObservationRecords
from observation.registry import DeviceRegistry
from observation.schema import BINDING_BASIS, EVENT_SCHEMA, HEALTH_SCHEMA, IDENTIFIER, OBSERVER_VERSION, \
    PURPOSES, SCHEMA_FINGERPRINT, SCHEMA_VERSION, observation_config_sha256
from observation.windowing import WindowConfig, WindowEngine, classify

OBSERVER_IDENTITY = "azta-pdp"  # historical two-device default (v1); unchanged
SUBSCRIPTION_QOS = 1
# Gate 5D.3B-0: an explicitly configured dedicated receive-only observer. It must be a stable `azta-observer` name
# (optionally with a lowercase shard suffix), so the historical PDP, receiver, device and administration identities can
# never be selected through the configuration path, and the historical principal never serves a wider registry.
DEDICATED_OBSERVER = re.compile(r"azta-observer(-[a-z0-9][a-z0-9-]{0,30})?\Z")
LEGACY_OBSERVER_DEVICES = frozenset({"device01", "device02"})
MAX_CREDENTIAL_BYTES = 4096
DEFAULT_REGISTRY = "/app/configs/observation/device_registry.json"
DISPOSITION_COUNTERS = ("COUNTED", "EXCLUDED_UNBOUND", "EXCLUDED_PRE_COVERAGE", "EXCLUDED_POST_COVERAGE",
                        "EXCLUDED_RETAINED", "EXCLUDED_DUPLICATE")


class ObserverError(Exception):
    pass


def resolve_observer(registry, identity=None, credential_file=None):
    """Return (observer identity, credential path or None) or raise ValueError before any connection.

    Neither option -> the historical azta-pdp principal, accepted only for a registry within the two original devices.
    Both options -> a dedicated `azta-observer` principal with an explicit credential file. Anything else is refused,
    so a wider registry can never silently fall back to the historical identity. The credential is never read here.
    """
    if (identity is None) != (credential_file is None):
        raise ValueError("--observer-identity and --credential-file must be given together")
    devices = {entry.device for entry in registry.devices}
    if identity is None:
        if not devices <= LEGACY_OBSERVER_DEVICES:
            raise ValueError("this registry needs an explicit dedicated observer identity; "
                             "the historical principal serves only the original two-device registry")
        return OBSERVER_IDENTITY, None
    if not isinstance(identity, str) or not DEDICATED_OBSERVER.fullmatch(identity):
        raise ValueError("observer identity must be a dedicated azta-observer principal")
    path = Path(credential_file)
    try:
        size = path.stat().st_size if path.is_file() else 0
    except OSError:
        size = 0
    if not 0 < size <= MAX_CREDENTIAL_BYTES:
        raise ValueError("observer credential file is missing, empty or too large")
    return identity, path


class PahoAdapter:
    """Wraps the existing A3 MQTTClient without modifying it; timestamps happen in the callback."""
    def __init__(self, emit, host="broker", credentials="/run/secrets", identity=OBSERVER_IDENTITY,
                 credential_file=None):
        if credential_file is None:
            if identity != OBSERVER_IDENTITY:
                raise ObserverError("a dedicated observer identity requires an explicit credential file")
            credential_file = password_for(identity, credentials)
        self.inner = MQTTClient(identity, credential_file, emit, host)

    def set_message_handler(self, handler):
        self.inner.client.on_message = lambda client, userdata, message: handler(message)

    @property
    def connected(self):
        return self.inner.connected

    def connect(self, timeout):
        return self.inner.connect(timeout)

    def subscribe(self, topic, qos, timeout):
        return self.inner.subscribe(topic, qos, timeout)

    def loop(self):
        return self.inner.loop()

    def close(self):
        self.inner.close()


class ObserverSession:
    def __init__(self, *, registry, duration_ns, window_count, purpose, collection_run_id, output_root,
                 binding_audit_ref=None, client_factory=None, clock=time.monotonic_ns, runtime=None,
                 collection_attestation=None, observer_identity=OBSERVER_IDENTITY):
        if purpose not in PURPOSES:
            raise ValueError("purpose must be FUNCTIONAL_TEST or COLLECTION")
        if observer_identity == OBSERVER_IDENTITY:
            resolve_observer(registry)  # the historical principal never serves a registry beyond the original devices
        elif not DEDICATED_OBSERVER.fullmatch(str(observer_identity)):
            raise ValueError("observer identity must be a dedicated azta-observer principal")
        elif client_factory is None:
            raise ValueError("a dedicated observer identity needs an explicit client factory with its credential")
        if not isinstance(collection_run_id, str) or not IDENTIFIER.fullmatch(collection_run_id):
            raise ValueError("invalid collection run id")
        if purpose == "COLLECTION" and (binding_audit_ref is None or collection_attestation is None):
            raise ValueError("COLLECTION requires a binding audit reference and a committed-plan attestation")
        self.registry, self.purpose, self.clock = registry, purpose, clock
        self.config = WindowConfig(duration_ns, window_count)
        self.session_id = "obs-" + uuid.uuid4().hex
        self.config_sha256 = observation_config_sha256(duration_ns, registry.sha256, SUBSCRIPTION_QOS)
        self.header = dict(observation_config_sha256=self.config_sha256, purpose=purpose,
                           observer_session_id=self.session_id, collection_run_id=collection_run_id,
                           binding_audit_ref=binding_audit_ref)
        self.records = ObservationRecords(output_root, self.session_id)
        self.origin = clock()
        self.seq = {"events": 0, "health": 0}
        self.counters = dict(received_total=0, event_errors=0, binding_failures=0, dup_flagged_total=0,
                             windows_emitted=0, **{name.lower(): 0 for name in DISPOSITION_COUNTERS})
        self.coverage_start = None
        self.coverage_end = None
        self.engine = None
        self.failure = None
        self.intentional_disconnect = False
        self.disconnect_offset = None
        self.done = False
        self.max_loop_gap = 0
        self.last_poll = None
        factory = client_factory or (lambda emit: PahoAdapter(emit))
        self.client = factory(self._client_event)
        self.client.set_message_handler(self._receive)
        self.metadata = dict(
            observer_session_id=self.session_id, observer_version=OBSERVER_VERSION, purpose=purpose,
            purpose_note=("FUNCTIONAL_TEST: parameters have no scientific or experimental significance"
                          if purpose == "FUNCTIONAL_TEST" else "COLLECTION: committed RUN_PLANNED required"),
            collection_run_id=collection_run_id, observer_identity=observer_identity,
            subscription_qos=SUBSCRIPTION_QOS, window_duration_ns=duration_ns, window_count=window_count,
            schema_fingerprint=SCHEMA_FINGERPRINT, observation_config_sha256=self.config_sha256,
            registry_sha256=registry.sha256, registry=registry.data, binding_basis=BINDING_BASIS,
            binding_audit_ref=binding_audit_ref, collection_attestation=collection_attestation,
            runtime=runtime or {}, clock_domain="observer_process_monotonic_ns", utc_start=utc_now(),
            enforcement="NONE", payload_policy="payload never parsed; only length and SHA-256 retained",
            window_header=self.header,
        )
        self.records.write_json("session_metadata.json", self.metadata)

    def offset(self):
        return self.clock() - self.origin

    def health(self, kind, offset=None, **details):
        self.seq["health"] += 1
        self.records.write("health", dict(
            schema=HEALTH_SCHEMA, schema_version=SCHEMA_VERSION, schema_fingerprint=SCHEMA_FINGERPRINT,
            observer_session_id=self.session_id, record_seq=self.seq["health"],
            offset_ns=self.offset() if offset is None else offset, utc=utc_now(), kind=kind, details=details))

    def _client_event(self, kind, **fields):
        # A3 MQTTClient lifecycle events (CONNACK, SUBACK, DISCONNECT): no secrets are present.
        if kind == "DISCONNECT" and self.disconnect_offset is None:
            self.disconnect_offset = self.offset()
        self.health(kind if kind in ("CONNACK", "SUBACK", "DISCONNECT") else "EVENT_ERROR", **fields)

    def _receive(self, message):
        offset = self.offset()  # first: scientific placement uses this callback-time monotonic offset
        self.counters["received_total"] += 1
        try:
            topic, payload = message.topic, bytes(message.payload)
            qos, dup, retain = int(message.qos), bool(message.dup), bool(message.retain)
            entry = self.registry.bind(topic)
            disposition, index = classify(entry, retain, dup, offset, self.coverage_start, self.config,
                                          coverage_open=self.coverage_end is None and not self.done)
            self.seq["events"] += 1
            event = dict(
                schema=EVENT_SCHEMA, schema_version=SCHEMA_VERSION, schema_fingerprint=SCHEMA_FINGERPRINT,
                observer_session_id=self.session_id, record_seq=self.seq["events"], receive_offset_ns=offset,
                receive_utc=utc_now(), topic=topic, binding_status="BOUND" if entry else "UNBOUND_TOPIC",
                bound_device=entry.device if entry else None, bound_username=entry.username if entry else None,
                bound_client_id=entry.client_id if entry else None, binding_basis=BINDING_BASIS if entry else None,
                binding_audit_ref=self.header["binding_audit_ref"], registry_sha256=self.registry.sha256,
                qos=qos, dup=dup, retain=retain, payload_bytes=len(payload),
                payload_sha256=hashlib.sha256(payload).hexdigest(), window_index=index, disposition=disposition)
            self.records.write("events", event)
        except Exception as exc:
            self.counters["event_errors"] += 1
            self.health("EVENT_ERROR", offset=offset, error_type=type(exc).__name__)
            return
        self.counters[disposition.lower()] += 1
        self.counters["dup_flagged_total"] += int(dup)
        self.counters["binding_failures"] += int(entry is None)
        if self.engine is not None:
            self.engine.add(event)

    def start(self):
        self.health("SESSION_START", purpose=self.purpose, window_duration_ns=self.config.duration_ns,
                    window_count=self.config.window_count, registry_sha256=self.registry.sha256)
        try:
            if self.client.connect(3) != 0:
                raise ObserverError("observer_authentication_rejected")
            for entry in self.registry.devices:
                if self.client.subscribe(entry.telemetry_topic, SUBSCRIPTION_QOS, 3) != [SUBSCRIPTION_QOS]:
                    raise ObserverError("subscription_not_granted")
        except (ObserverError, ProbeError) as exc:
            self.failure = str(exc)
            self.done = True
            return False
        self.coverage_start = self.offset()
        self.engine = WindowEngine(self.registry, self.config, self.coverage_start, self.header)
        self.health("COVERAGE_START", offset=self.coverage_start,
                    topics=[entry.telemetry_topic for entry in self.registry.devices])
        self.last_poll = self.coverage_start
        return True

    def _end_coverage(self, offset, reason):
        if self.coverage_end is None:
            self.coverage_end = offset
            self.engine.end_coverage(offset)
            self.health("COVERAGE_END", offset=offset, reason=reason)

    def _close_due(self, now):
        while self.engine.next_index < self.config.window_count and now >= self.engine.bounds(self.engine.next_index)[1]:
            index = self.engine.next_index
            for record in self.engine.close(index):
                self.records.write("windows", record)
                self.counters["windows_emitted"] += 1
            self.health("HEARTBEAT", window_index=index, close_lag_ns=now - self.engine.bounds(index)[1],
                        max_loop_gap_ns=self.max_loop_gap, counters=dict(self.counters))
            self.max_loop_gap = 0

    def poll(self):
        """One loop iteration plus due window closures. Returns True while the session is active."""
        if self.done:
            return False
        before = self.offset()
        self.max_loop_gap = max(self.max_loop_gap, before - self.last_poll)
        rc = self.client.loop()
        now = self.offset()
        self.last_poll = now
        if rc != 0 or not self.client.connected:
            offset = self.disconnect_offset if self.disconnect_offset is not None else now
            self._end_coverage(offset, "intentional_test_disconnect" if self.intentional_disconnect else "unexpected_disconnect")
            self.failure = self.failure or ("observer_disconnected_intentionally" if self.intentional_disconnect
                                            else "observer_disconnected")
            self.done = True
            return False
        self._close_due(now)
        if self.engine.next_index >= self.config.window_count:
            self.done = True
        return not self.done

    def disconnect_for_test(self):
        """Probe-only failure injection: ends coverage now, then closes the observer connection."""
        self.intentional_disconnect = True
        if self.coverage_start is not None:
            self._end_coverage(self.offset(), "intentional_test_disconnect")
        self.client.close()

    def finish(self):
        self.done = True
        if self.engine is not None:
            if self.engine.next_index < self.config.window_count:
                self._end_coverage(self.offset(), "session_ended_before_last_window")
                while self.engine.next_index < self.config.window_count:
                    index = self.engine.next_index
                    for record in self.engine.close(index):
                        self.records.write("windows", record)
                        self.counters["windows_emitted"] += 1
        try:
            if self.client.connected:
                self.intentional_disconnect = True
                self.client.close()
        except Exception:
            self.failure = self.failure or "shutdown_error"
        dispositions = sum(self.counters[name.lower()] for name in DISPOSITION_COUNTERS)
        expected_windows = len(self.registry.devices) * self.config.window_count if self.engine else 0
        invariants = dict(
            received_equals_dispositions_plus_errors=self.counters["received_total"]
            == dispositions + self.counters["event_errors"],
            windows_emitted_equals_devices_times_windows=self.counters["windows_emitted"] == expected_windows,
        )
        if not all(invariants.values()):
            self.failure = self.failure or "counter_invariant_failed"
        state = "COMPLETE" if self.failure is None and self.coverage_end is None and self.engine else "INCOMPLETE"
        self.health("SESSION_END", state=state, failure_code=self.failure, counters=dict(self.counters),
                    invariants=invariants)
        digests = self.records.digests()
        summary = dict(
            observer_session_id=self.session_id, purpose=self.purpose, state=state, failure_code=self.failure,
            coverage_start_offset_ns=self.coverage_start, coverage_end_offset_ns=self.coverage_end,
            window_duration_ns=self.config.duration_ns, window_count=self.config.window_count,
            counters=self.counters, invariants=invariants, artifact_sha256=digests, utc_end=utc_now(),
            schema_fingerprint=SCHEMA_FINGERPRINT, observation_config_sha256=self.config_sha256,
            enforcement="NONE", decision="NOT_IMPLEMENTED")
        self.records.write_json("session_summary.json", summary)
        return summary

    def run(self):
        if self.start():
            while self.poll():
                pass
        return self.finish()


def runtime():
    return dict(git_commit=os.getenv("AZTA_GIT_COMMIT", "unknown"), git_state=os.getenv("AZTA_GIT_STATE", "unknown"),
                container_image=os.getenv("AZTA_RUNTIME_IMAGE", "unknown"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--purpose", required=True, choices=PURPOSES)
    parser.add_argument("--collection-run-id", required=True)
    parser.add_argument("--window-duration-ms", required=True, type=int,
                        help="Required. No scientific W is selected in Gate 5B; there is no default.")
    parser.add_argument("--window-count", required=True, type=int)
    parser.add_argument("--registry", default=DEFAULT_REGISTRY)
    parser.add_argument("--binding-audit-ref")
    parser.add_argument("--manifest", help="Required for COLLECTION (committed RUN_PLANNED).")
    parser.add_argument("--output-dir", default="/results")
    parser.add_argument("--host", default=os.getenv("MQTT_HOST", "broker"))
    parser.add_argument("--observer-identity",
                        help="Dedicated receive-only observer principal (azta-observer...); default: historical azta-pdp.")
    parser.add_argument("--credential-file",
                        help="Credential file of the dedicated observer; required with --observer-identity.")
    args = parser.parse_args(argv)
    try:
        if args.window_duration_ms <= 0:
            raise ValueError("window duration must be positive")
        registry = DeviceRegistry.load(args.registry)
        identity, credential_file = resolve_observer(registry, args.observer_identity, args.credential_file)
        attestation = None
        if args.purpose == "COLLECTION":
            if not args.manifest or not args.binding_audit_ref:
                raise ValueError("COLLECTION requires --manifest and --binding-audit-ref")
            attestation = manifest_module.check_collection_allowed(
                args.manifest, args.collection_run_id,
                expected_manifest_sha256=os.getenv("AZTA_MANIFEST_SHA256", ""),
                git_commit=os.getenv("AZTA_GIT_COMMIT"), git_state=os.getenv("AZTA_GIT_STATE"))
            if (attestation["window_duration_ns"] != args.window_duration_ms * 1_000_000
                    or attestation["planned_window_count"] != args.window_count
                    or attestation["observation_config_sha256"]
                    != observation_config_sha256(args.window_duration_ms * 1_000_000, registry.sha256, SUBSCRIPTION_QOS)):
                raise ValueError("collection parameters differ from the committed plan")
        session = ObserverSession(
            registry=registry, duration_ns=args.window_duration_ms * 1_000_000, window_count=args.window_count,
            purpose=args.purpose, collection_run_id=args.collection_run_id, output_root=args.output_dir,
            binding_audit_ref=args.binding_audit_ref, runtime=runtime(), collection_attestation=attestation,
            observer_identity=identity,
            client_factory=lambda emit: PahoAdapter(emit, args.host, identity=identity, credential_file=credential_file))
    except (ValueError, OSError, manifest_module.ManifestError, ProbeError) as exc:
        print(f"OBSERVATION_REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    summary = session.run()
    print(f'OBSERVATION_SESSION {summary["observer_session_id"]} {summary["state"]} failure={summary["failure_code"]}')
    return 0 if summary["state"] == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
