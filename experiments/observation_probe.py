"""Gate 5B bounded serial live functional probe (operator-invoked). FUNCTIONAL_TEST only.

Its window duration has NO scientific or experimental significance. It uses the receive-only
azta-pdp observer and the azta-device-01 publisher only; it never publishes as device02, never
administers policy and never mutates anything. Read-only binding audits run as a separate
process before and after (experiments/binding_audit.py); this probe records their reference.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time

import paho.mqtt.client as mqtt
from experiments.a3_mqtt import MQTTClient, ProbeError, password_for, topic
from observation.observer import ObserverSession, PahoAdapter, runtime
from observation.registry import DeviceRegistry
from observation.schema import IDENTIFIER, canonical
from observation.windowing import WindowConfig, replay

PUBLISHER = "azta-device-01"
# Offsets in units of W after coverage start, and exact payload sizes (bytes) for hand checks.
HEALTHY_PLAN = (("publish", 1.20, 100), ("publish", 1.40, 150), ("publish", 1.60, 200),
                ("cross_namespace", 2.50, 120), ("publish", 3.30, 120), ("publish", 3.70, 120),
                ("wrong_client_id", 4.40, None))
HEALTHY_WINDOWS = 6
FAILURE_WINDOWS = 4


def payload(sequence, size):
    """Deliberately carries a FORGED identity claim; the observer must ignore payload content."""
    body = dict(p="g5b", s=sequence, claimed_device_id="device02", pad="")
    raw = json.dumps(body, separators=(",", ":")).encode()
    if len(raw) > size:
        raise ValueError("payload size too small")
    body["pad"] = "x" * (size - len(raw))
    raw = json.dumps(body, separators=(",", ":")).encode()
    assert len(raw) == size
    return raw


class Probe:
    def __init__(self, args, registry):
        self.args, self.registry = args, registry
        self.duration_ns = args.window_duration_ms * 1_000_000
        self.ledger, self.checks, self.events = [], [], []

    def check(self, name, ok, **observed):
        self.checks.append(dict(name=name, result="PASS" if ok else "FAIL", observed=observed))
        return ok

    def pump(self, session, clients, until_ns):
        while session.offset() < until_ns:
            if not session.poll():
                return False
            for client in clients:
                if client.connected and client.loop() != 0:
                    raise ProbeError("publisher_connection_lost")
        return True

    def wait_ack(self, session, publisher, info, timeout_s=3.0):
        deadline = time.monotonic() + timeout_s
        while info.mid not in publisher.acks:
            if time.monotonic() > deadline:
                raise ProbeError("puback_timeout")
            session.poll()
            if publisher.loop() != 0:
                raise ProbeError("publisher_connection_lost")
        return publisher.acks.pop(info.mid)

    def wrong_client_id(self, session):
        """Valid device credential with a non-bound client ID: Dynamic Security must refuse it."""
        result = dict(reason_code=None)
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=PUBLISHER + "-probe-unbound-id",
                             protocol=mqtt.MQTTv5, reconnect_on_failure=False)
        client.username_pw_set(PUBLISHER, Path(password_for(PUBLISHER)).read_text(encoding="utf-8").strip())
        client.on_connect = lambda c, u, f, reason, p: result.update(reason_code=reason.value)
        client.connect(self.args.host, 1883, keepalive=15, clean_start=True)
        deadline = time.monotonic() + 3
        while result["reason_code"] is None and time.monotonic() < deadline:
            session.poll()
            if client.loop(timeout=0.005) != 0:
                break
        client.disconnect()
        return result["reason_code"]

    def publisher(self):
        client = MQTTClient(PUBLISHER, password_for(PUBLISHER), lambda kind, **f: None, self.args.host)
        if client.connect(3) != 0:
            raise ProbeError("publisher_authentication_rejected")
        return client

    def new_session(self, suffix, windows):
        return ObserverSession(
            registry=self.registry, duration_ns=self.duration_ns, window_count=windows, purpose="FUNCTIONAL_TEST",
            collection_run_id=f"{self.args.run_id}-{suffix}", output_root=self.args.output_dir,
            binding_audit_ref=self.args.binding_audit_ref, runtime=runtime(),
            client_factory=lambda emit: PahoAdapter(emit, self.args.host))

    def healthy(self):
        publisher = self.publisher()
        session = self.new_session("healthy", HEALTHY_WINDOWS)
        try:
            if not self.check("observer_started_with_all_literal_subscriptions", session.start(),
                              failure=session.failure):
                return session.finish()
            sequence = 0
            for action, at, size in HEALTHY_PLAN:
                if not self.pump(session, [publisher], session.coverage_start + int(at * self.duration_ns)):
                    break
                if action == "publish":
                    sequence += 1
                    data = payload(sequence, size)
                    info = publisher.publish(topic("device01", "telemetry"), data, 1)
                    ack = self.wait_ack(session, publisher, info)
                    self.ledger.append(dict(kind="valid", sequence=sequence, topic=topic("device01", "telemetry"),
                                            payload_sha256=hashlib.sha256(data).hexdigest(), bytes=size, puback=ack))
                elif action == "cross_namespace":
                    data = payload(99, size)
                    info = publisher.publish(topic("device02", "telemetry"), data, 1)
                    ack = self.wait_ack(session, publisher, info)
                    self.ledger.append(dict(kind="cross_namespace", topic=topic("device02", "telemetry"),
                                            payload_sha256=hashlib.sha256(data).hexdigest(), bytes=size, puback=ack))
                    if not self.check("cross_namespace_publish_denied", ack == 135, puback=ack):
                        raise ProbeError("STOP_cross_namespace_publish_not_denied")
                else:
                    code = self.wrong_client_id(session)
                    self.check("wrong_client_id_connection_denied", code is not None and code >= 128, connack=code)
            while session.poll():
                publisher.loop()
        except BaseException:
            session.failure = session.failure or "probe_error"
            session.finish()  # preserve evidence of the aborted session
            raise
        finally:
            publisher.close()
        return session.finish()

    def failure(self):
        session = self.new_session("disconnect", FAILURE_WINDOWS)
        if not self.check("failure_session_started", session.start(), failure=session.failure):
            return session.finish()
        if self.pump(session, [], session.coverage_start + int(2.5 * self.duration_ns)):
            session.disconnect_for_test()
            deadline = time.monotonic() + 3
            while session.poll() and time.monotonic() < deadline:
                pass
        return session.finish()

    def read(self, summary, name):
        path = Path(self.args.output_dir) / "observation" / summary["observer_session_id"] / name
        with path.open(encoding="utf-8") as stream:
            return [json.loads(line) for line in stream]

    def verify(self, healthy, failure):
        events, windows = self.read(healthy, "events.jsonl"), self.read(healthy, "windows.jsonl")
        accepted = [item for item in self.ledger if item["kind"] == "valid" and item["puback"] in (0, 16)]
        self.check("all_valid_publishes_accepted", len(accepted) == sum(i["kind"] == "valid" for i in self.ledger)
                   and accepted, accepted=len(accepted))
        by_hash = {}
        for event in events:
            by_hash.setdefault(event["payload_sha256"], []).append(event)
        correlated = [item for item in accepted if len(by_hash.get(item["payload_sha256"], [])) == 1
                      and by_hash[item["payload_sha256"]][0]["disposition"] == "COUNTED"
                      and by_hash[item["payload_sha256"]][0]["bound_device"] == "device01"
                      and by_hash[item["payload_sha256"]][0]["payload_bytes"] == item["bytes"]]
        self.check("accepted_publishes_correlated_exactly_once_by_payload_sha256", len(correlated) == len(accepted),
                   correlated=len(correlated), accepted=len(accepted))
        self.check("forged_payload_claim_bound_by_topic_not_payload",
                   all(e["bound_device"] == "device01" for e in events if e["topic"].endswith("device01/telemetry")))
        cross = [i for i in self.ledger if i["kind"] == "cross_namespace"]
        foreign = [e for e in events if e["topic"] == topic("device02", "telemetry") or e["bound_device"] == "device02"
                   or any(e["payload_sha256"] == c["payload_sha256"] for c in cross)]
        self.check("no_event_attributed_to_device02", not foreign, foreign_events=len(foreign))
        d1 = [w for w in windows if w["device"] == "device01"]
        d2 = [w for w in windows if w["device"] == "device02"]
        self.check("every_device_every_window_emitted", len(d1) == len(d2) == HEALTHY_WINDOWS)
        self.check("healthy_coverage_complete", all(w["coverage"]["state"] == "COMPLETE" for w in windows))
        self.check("device01_counts_sum_to_accepted",
                   sum(w["measures"]["delivered_count"]["value"] for w in d1) == len(accepted),
                   counts=[w["measures"]["delivered_count"]["value"] for w in d1])
        self.check("silent_device02_true_zero_with_complete_coverage",
                   all(w["measures"]["delivered_count"] == dict(value=0, status="VALUE") for w in d2)
                   and all(w["measures"]["last_delivery_age_ms"]["status"] == "NEVER_OBSERVED_IN_SESSION" for w in d2)
                   and all(w["measures"]["payload_bytes_mean"]["status"] == "NO_MESSAGES" for w in d2))
        meta_path = Path(self.args.output_dir) / "observation" / healthy["observer_session_id"] / "session_metadata.json"
        header = json.loads(meta_path.read_text(encoding="utf-8"))["window_header"]
        replayed = replay(events, self.registry, WindowConfig(self.duration_ns, HEALTHY_WINDOWS),
                          healthy["coverage_start_offset_ns"], healthy["coverage_end_offset_ns"], header)
        self.check("healthy_windows_replay_identically", canonical(replayed) == canonical(windows))
        self.check("healthy_session_complete_with_invariants", healthy["state"] == "COMPLETE"
                   and all(healthy["invariants"].values()), state=healthy["state"], failure=healthy["failure_code"])
        fwindows = self.read(failure, "windows.jsonl")
        states = {w["window"]["index"]: w["coverage"]["state"] for w in fwindows if w["device"] == "device01"}
        self.check("disconnect_session_incomplete", failure["state"] == "INCOMPLETE",
                   failure=failure["failure_code"])
        self.check("disconnect_remainder_observer_unavailable",
                   len(fwindows) == 2 * FAILURE_WINDOWS
                   and all(states.get(i) == "COMPLETE" for i in (0, 1)) and states.get(2) == "PARTIAL"
                   and states.get(3) == "NONE"
                   and all(m["status"] == "OBSERVER_UNAVAILABLE" and m["value"] is None
                           for w in fwindows if w["window"]["index"] >= 2 for m in w["measures"].values()),
                   coverage=states)
        fheader = json.loads((Path(self.args.output_dir) / "observation" / failure["observer_session_id"]
                              / "session_metadata.json").read_text(encoding="utf-8"))["window_header"]
        freplay = replay(self.read(failure, "events.jsonl"), self.registry, WindowConfig(self.duration_ns, FAILURE_WINDOWS),
                         failure["coverage_start_offset_ns"], failure["coverage_end_offset_ns"], fheader)
        self.check("failure_windows_replay_identically", canonical(freplay) == canonical(fwindows))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--window-duration-ms", required=True, type=int)
    parser.add_argument("--binding-audit-ref", required=True)
    parser.add_argument("--registry", default="/app/configs/observation/device_registry.json")
    parser.add_argument("--output-dir", default="/results")
    parser.add_argument("--host", default=os.getenv("MQTT_HOST", "broker"))
    args = parser.parse_args(argv)
    if not IDENTIFIER.fullmatch(args.run_id) or args.window_duration_ms <= 0:
        print("PROBE_CONFIG_ERROR", file=sys.stderr)
        return 2
    out = Path(args.output_dir) / args.run_id
    out.mkdir(parents=True, exist_ok=False)
    probe = Probe(args, DeviceRegistry.load(args.registry))
    healthy = failure = None
    stop = None
    try:
        healthy = probe.healthy()
        failure = probe.failure()
        probe.verify(healthy, failure)
    except ProbeError as exc:
        stop = str(exc)
    except Exception as exc:
        stop = "probe_error_" + type(exc).__name__
    state = "COMPLETE" if stop is None and probe.checks and all(c["result"] == "PASS" for c in probe.checks) else "FAILED"
    summary = dict(probe="gate5b-functional-probe", purpose="FUNCTIONAL_TEST",
                   window_duration_ms=args.window_duration_ms,
                   window_duration_note="FUNCTIONAL_TEST only; no scientific or experimental significance",
                   run_id=args.run_id, binding_audit_ref=args.binding_audit_ref, state=state, stop=stop,
                   checks=probe.checks, publisher_ledger=probe.ledger,
                   sessions=dict(healthy=healthy and healthy["observer_session_id"],
                                 failure=failure and failure["observer_session_id"]),
                   enforcement="NONE", policy_mutation="NONE")
    with (out / "probe_summary.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(summary, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(f"OBSERVATION_PROBE {state} run_id={args.run_id} checks="
          f"{sum(c['result'] == 'PASS' for c in probe.checks)}/{len(probe.checks)} stop={stop}")
    return 0 if state == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
