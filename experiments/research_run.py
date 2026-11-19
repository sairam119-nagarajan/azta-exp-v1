"""Finite LIVE_MQTT research publisher + separately authenticated PDP recorder."""
import argparse
import importlib.metadata
import os
from pathlib import Path
import platform
import signal
import sys
import threading
import time
import uuid

import paho.mqtt.client as mqtt
from experiments.research_records import RunConfig, RunRecords, digest, encode_payload, new_run_id, utc_now
from pdp.research_subscriber import ResearchPDP


class RunFailure(Exception):
    """Contains only our fixed error codes, never exception/payload/credential text."""


class PublisherLedger:
    def __init__(self):
        self.messages = {}

    def attempt(self, sequence, fingerprint):
        self.messages[sequence] = dict(queued=False, ack=None, payload_sha256=fingerprint)

    def counts(self):
        values = list(self.messages.values())
        queued = sum(item["queued"] for item in values)
        accepted = sum(item["ack"] in (0, 16) for item in values)
        denied = sum(item["ack"] is not None and item["ack"] >= 128 for item in values)
        other = sum(item["ack"] is not None and item["ack"] not in (0, 16)
                    and item["ack"] < 128 for item in values)
        return dict(attempted_messages=len(values), queued_messages=queued,
                    enqueue_failures=len(values)-queued, accepted_acknowledgements=accepted,
                    denied_publishes=denied, other_acknowledgements=other,
                    unacknowledged_messages=queued-accepted-denied-other)


class Peer:
    def __init__(self, runner, stream, username, password_file):
        self.runner, self.stream, self.username = runner, stream, username
        self.local_id = ("pub-" if stream == "publisher" else "pdp-") + uuid.uuid4().hex
        self.connack = None
        self.connected = False
        self.closing = False
        self.subscription = None
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=username,
                                  protocol=mqtt.MQTTv5, reconnect_on_failure=False)
        self.client.connect_timeout = 1.0
        try:
            # Only this selected secret is read, never broker state/admin credentials.
            with Path(password_file).open(encoding="utf-8") as stream_file:
                password = stream_file.read(4097).strip()
            if not password or len(password) > 4096:
                raise ValueError()
        except (OSError, ValueError, TypeError):
            raise RunFailure("credential_unavailable") from None
        self.client.username_pw_set(username, password)
        self.client.on_connect = self._connected
        self.client.on_disconnect = self._disconnected
        self.client.on_subscribe = self._subscribed

    def _connected(self, client, userdata, flags, reason, properties):
        self.connack = reason.value
        self.connected = reason.value == 0
        self.runner.records.event(
            self.stream, "CONNACK", local_session_id=self.local_id,
            configured_username=self.username, mqtt_client_id=self.username,
            reason_code=reason.value, result="accepted" if self.connected else "rejected",
            authentication_evidence="broker_connack_for_configured_credentials",
        )

    def _disconnected(self, client, userdata, flags, reason, properties):
        self.connected = False
        if not self.closing:
            self.runner.failure = "connection_lost"

    def _subscribed(self, client, userdata, mid, reasons, properties):
        self.subscription = [reason.value for reason in reasons]
        self.runner.records.event("pdp", "SUBACK", local_session_id=self.local_id,
                                  reason_codes=self.subscription,
                                  result="accepted" if self.subscription == [1] else "rejected")

    def close(self):
        self.closing = True
        self.client.disconnect()


class ResearchRunner:
    def __init__(self, config, records, host, port, stop=None):
        self.config, self.records, self.host, self.port = config, records, host, port
        self.stop = stop or threading.Event()
        self.deadline_ns = records.start_ns + int(config.timeout * 1e9)
        self.peers = []
        self.failure = None
        self.ledger = PublisherLedger()
        self.pending = {}
        self.pdp = None
        self.subscribed = False
        self.errors = 0

    def check(self):
        if self.stop.is_set():
            raise RunFailure("interrupted")
        if self.records.clock() >= self.deadline_ns:
            raise RunFailure("timeout")
        if self.failure:
            raise RunFailure(self.failure)

    def pump(self):
        self.check()
        for peer in self.peers:
            if peer.connected and peer.client.loop(timeout=0.01) != mqtt.MQTT_ERR_SUCCESS:
                raise RunFailure("mqtt_loop_error")
        self.check()

    def until(self, predicate):
        while not predicate():
            self.pump()

    def connect(self, peer):
        for attempt in range(1, 4):
            self.check()
            peer.connack = None
            try:
                peer.client.connect_timeout = min(1.0, max(0.01,
                    (self.deadline_ns - self.records.clock()) / 1e9))
                rc = peer.client.connect(self.host, self.port, keepalive=30, clean_start=True)
                if rc != mqtt.MQTT_ERR_SUCCESS:
                    raise OSError()
                until = min(self.deadline_ns, self.records.clock() + 1_000_000_000)
                while peer.connack is None and self.records.clock() < until:
                    self.check()
                    if peer.client.loop(timeout=0.01) != mqtt.MQTT_ERR_SUCCESS:
                        break
                if peer.connack == 0:
                    return
                if peer.connack is not None:
                    raise RunFailure("authentication_rejected")
            except OSError:
                pass
            peer.closing = True
            peer.client.disconnect()
            peer.closing = False
            self.records.event(peer.stream, "CONNECTION_RETRY", attempt=attempt,
                               local_session_id=peer.local_id, result="connection_unavailable")
            if attempt < 3:
                wait_until = self.records.clock() + 100_000_000
                while self.records.clock() < wait_until:
                    self.check()
                    self.stop.wait(0.01)
        self.check()
        raise RunFailure("broker_unavailable")

    def acknowledged(self, client, userdata, mid, reason, properties):
        if mid not in self.pending:
            self.failure = "unexpected_puback"
            return
        sequence = self.pending.pop(mid)
        self.ledger.messages[sequence]["ack"] = reason.value
        self.records.event(
            "publisher", "PUBACK", sequence=sequence,
            event_id=f"{self.config.run_id}:{sequence}",
            local_session_id=self.publisher.local_id, mqtt_mid=mid, reason_code=reason.value,
            payload_length=self.config.payload_size,
            result="accepted" if reason.value in (0, 16) else "denied" if reason.value >= 128 else "other",
        )
        if reason.value not in (0, 16):
            self.failure = "publish_denied" if reason.value >= 128 else "unexpected_puback_code"

    def execute(self, device_password_file, pdp_password_file):
        state, failure = "INCOMPLETE", None
        try:
            receiver = Peer(self, "pdp", "azta-pdp", pdp_password_file)
            self.peers.append(receiver)
            self.pdp = ResearchPDP(self.config, self.records, receiver.local_id)
            receiver.client.on_message = lambda client, userdata, message: self.pdp.observe(
                message.topic, message.qos, message.payload, message.dup, message.retain)
            self.connect(receiver)
            rc, _ = receiver.client.subscribe(self.config.topic, qos=1)
            if rc != mqtt.MQTT_ERR_SUCCESS:
                raise RunFailure("subscribe_enqueue_failed")
            self.until(lambda: receiver.subscription is not None)
            if receiver.subscription != [1]:
                raise RunFailure("subscription_denied")
            self.subscribed = True
            self.records.event("pdp", "SUBSCRIPTION_READY", local_session_id=receiver.local_id,
                               result="confirmed", decision="NOT_IMPLEMENTED")
            self.publisher = Peer(self, "publisher", self.config.device_identity, device_password_file)
            self.peers.append(self.publisher)
            self.publisher.client.on_publish = self.acknowledged
            self.connect(self.publisher)
            next_send_ns = self.records.clock()
            for seq in range(1, self.config.message_count + 1):
                self.until(lambda: self.records.clock() >= next_send_ns)
                self.check()
                stamp = utc_now()
                payload = encode_payload(self.config, seq, self.publisher.local_id, stamp)
                fingerprint = digest(payload)
                self.ledger.attempt(seq, fingerprint)
                self.records.event(
                    "publisher", "PUBLISH_ATTEMPT", sequence=seq,
                    event_id=f"{self.config.run_id}:{seq}", local_session_id=self.publisher.local_id,
                    configured_username=self.config.device_identity,
                    claimed_device_id=self.config.claimed_device_id,
                    payload_publish_utc=stamp, payload_sha256=fingerprint,
                    payload_length=len(payload), result="attempted",
                )
                sent_ns = self.records.clock()
                info = self.publisher.client.publish(self.config.topic, payload, qos=1, retain=False)
                if info.rc != mqtt.MQTT_ERR_SUCCESS:
                    raise RunFailure("publish_enqueue_failed")
                self.ledger.messages[seq]["queued"] = True
                self.pending[info.mid] = seq
                self.records.event("publisher", "PUBLISH_QUEUED", sequence=seq,
                                   event_id=f"{self.config.run_id}:{seq}",
                                   local_session_id=self.publisher.local_id,
                                   mqtt_mid=info.mid, payload_length=len(payload), result="queued")
                self.until(lambda: self.ledger.messages[seq]["ack"] is not None)
                self.check()
                next_send_ns = sent_ns + int(self.config.interval * 1e9)
            self.until(lambda: len(self.pdp.received) >= self.config.message_count)
            self.check()
            matched = self.matched_sequences()
            if len(matched) != self.config.message_count or self.pdp.malformed or self.pdp.conflicts:
                raise RunFailure("reconciliation_failed")
            state = "COMPLETE"
        except RunFailure as exc:
            failure = str(exc)
        except (OSError, ValueError, TypeError, RuntimeError):
            failure = "runtime_or_output_error"
        except Exception:
            # Fail closed for evidence success, without echoing arbitrary exception text.
            failure = "unexpected_runtime_error"
        finally:
            for peer in self.peers:
                try:
                    peer.close()
                except Exception:
                    state, failure = "INCOMPLETE", "shutdown_error"
        if failure:
            self.errors += 1
            self.records.event("publisher", "RUN_ERROR", result=failure)
        counts = self.ledger.counts()
        counts.update(
            pdp_observation_started=self.subscribed,
            pdp_observed_messages=self.pdp.observed if self.subscribed else None,
            pdp_unique_sequences=len(self.pdp.received) if self.subscribed else None,
            pdp_duplicate_messages=self.pdp.duplicates if self.subscribed else None,
            pdp_malformed_messages=self.pdp.malformed if self.subscribed else None,
            pdp_unrelated_messages=self.pdp.unrelated if self.subscribed else None,
            pdp_conflicting_duplicates=self.pdp.conflicts if self.subscribed else None,
            downstream_receiver_messages=None, errors=self.errors,
        )
        summary = dict(state=state, incomplete=state != "COMPLETE", timeout=failure == "timeout",
                       failure_code=failure, counts=counts, configured_messages=self.config.message_count,
                       correlated_sequences=self.matched_sequences(),
                       correlation_basis="run_id_sequence_and_exact_payload_sha256",
                       authenticated_publisher_identity_at_pdp=None, decision="NOT_IMPLEMENTED")
        self.records.finish(summary)
        return summary

    def matched_sequences(self):
        if not self.pdp:
            return []
        return sorted(seq for seq, message in self.ledger.messages.items()
                      if message["ack"] in (0, 16)
                      and self.pdp.received.get(seq) == message["payload_sha256"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__ + " Defaults are functional-test parameters.")
    parser.add_argument("--run-id")
    parser.add_argument("--scenario", default="functional-test")
    parser.add_argument("--device-identity", default="azta-device-01")
    parser.add_argument("--claimed-device-id", default="device01")
    parser.add_argument("--topic", default=RunConfig.__dataclass_fields__["topic"].default)
    parser.add_argument("--qos", type=int, default=1)
    parser.add_argument("--message-count", type=int, default=10)
    parser.add_argument("--interval", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--payload-size", type=int, default=512)
    parser.add_argument("--timeout", type=float, default=20)
    parser.add_argument("--evidence-type", default="LIVE_MQTT")
    parser.add_argument("--output-dir", default="/results")
    parser.add_argument("--host", default=os.getenv("MQTT_HOST", "broker"))
    parser.add_argument("--port", type=int, default=1883)
    args = parser.parse_args(argv)
    values = {key: getattr(args, key) for key in RunConfig.__dataclass_fields__}
    values["run_id"] = args.run_id if args.run_id is not None else new_run_id()
    try:
        config = RunConfig(**values).validate()
        if not 1 <= args.port <= 65535:
            raise ValueError("Invalid port")
        encode_payload(config, config.message_count, "pub-" + "0" * 32, utc_now())
    except ValueError as exc:
        print(f"CONFIG_ERROR: {exc}", file=sys.stderr)
        return 2
    runtime = dict(python=platform.python_version(), paho_mqtt=importlib.metadata.version("paho-mqtt"),
                   git_commit=os.getenv("AZTA_GIT_COMMIT", "unknown"),
                   git_state=os.getenv("AZTA_GIT_STATE", "unknown"),
                   container_image=os.getenv("AZTA_RUNTIME_IMAGE", "unknown"))
    records = None
    old_handlers = {}
    stop = threading.Event()
    try:
        records = RunRecords(args.output_dir, config, runtime)
        for sig in (signal.SIGINT, signal.SIGTERM):
            old_handlers[sig] = signal.signal(sig, lambda *_: stop.set())
        summary = ResearchRunner(config, records, args.host, args.port, stop).execute(
            os.getenv("DEVICE_PASSWORD_FILE", "/run/secrets/device_password"),
            os.getenv("PDP_PASSWORD_FILE", "/run/secrets/pdp_password"),
        )
        print(f'RESEARCH_RUN run_id={config.run_id} state={summary["state"]} '
              f'failure={summary["failure_code"]} correlated={len(summary["correlated_sequences"])}')
        return 0 if summary["state"] == "COMPLETE" else 1
    except OSError:
        print("OUTPUT_ERROR: cannot create/write unique run evidence directory", file=sys.stderr)
        return 2
    finally:
        if records:
            records.close()
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    raise SystemExit(main())
