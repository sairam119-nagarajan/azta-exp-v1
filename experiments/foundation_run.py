"""A3 extension of A2 records: two devices, actual operational receipt, QoS0/1."""
import argparse
from dataclasses import dataclass, fields
import importlib.metadata
import os
import platform
import signal
import time
from experiments.research_records import RunConfig, RunRecords, encode_payload, digest, new_run_id, utc_now
from experiments.a3_mqtt import DEVICES, RECEIVER, MQTTClient, ProbeError, topic, password_for, pump_until
from pdp.research_subscriber import ResearchPDP
from receivers.operational import OperationalReceiver


@dataclass(frozen=True)
class FoundationConfig(RunConfig):
    schema_version: int = 2
    workload: str = "telemetry"

    def validate(self):
        values = {field.name: getattr(self, field.name) for field in fields(RunConfig)}
        values["qos"] = 1
        RunConfig(**values).validate()
        if type(self.qos) is not int or self.qos not in (0, 1) or self.schema_version != 2:
            raise ValueError("A3 requires schema 2 and QoS 0 or 1")
        device = next((name for name, identity in DEVICES.items() if identity == self.device_identity), None)
        if device is None or self.topic != topic(device, self.workload):
            raise ValueError("Device/topic/workload mismatch")
        return self


def runtime():
    return dict(python=platform.python_version(), paho_mqtt=importlib.metadata.version("paho-mqtt"),
                git_commit=os.getenv("AZTA_GIT_COMMIT", "unknown"),
                git_state=os.getenv("AZTA_GIT_STATE", "unknown"),
                container_image=os.getenv("AZTA_RUNTIME_IMAGE", "unknown"))


def run(config, root="/results", *, credentials="/run/secrets", receiver_enabled=True,
        receiver_host="broker", publisher_host="broker"):
    config.validate()
    records = RunRecords(root, config, runtime(), streams=("publisher", "pdp", "receiver"))
    started = time.monotonic()
    clients, messages = [], {}
    receiver = None
    sink = None
    failure = None
    interrupted = False
    old = {}

    def stop(*_):
        nonlocal interrupted
        interrupted = True

    def remaining():
        if interrupted:
            raise ProbeError("interrupted")
        value = config.timeout - (time.monotonic()-started)
        if value <= 0:
            raise ProbeError("timeout")
        return value

    def drain():
        if receiver:
            while receiver.messages:
                message = receiver.messages.pop(0)
                sink.observe(message.topic, message.qos, message.payload, message.dup, message.retain)

    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            old[sig] = signal.signal(sig, stop)
        stream = "pdp" if config.workload == "telemetry" else "receiver"
        if receiver_enabled:
            identity = "azta-pdp" if config.workload == "telemetry" else RECEIVER
            receiver = MQTTClient(identity, password_for(identity, credentials),
                                  lambda kind, **v: records.event(stream, kind, **v), receiver_host)
            clients.append(receiver)
            if receiver.connect(min(3, remaining())) != 0:
                raise ProbeError("receiver_authentication_rejected")
            if receiver.subscribe(config.topic, config.qos, min(3, remaining())) != [config.qos]:
                raise ProbeError("subscription_denied")
            factory = ResearchPDP if stream == "pdp" else OperationalReceiver
            sink = factory(config, records, receiver.session_id)
        publisher = MQTTClient(config.device_identity, password_for(config.device_identity, credentials),
                               lambda kind, **v: records.event("publisher", kind, **v), publisher_host)
        clients.append(publisher)
        if publisher.connect(min(3, remaining())) != 0:
            raise ProbeError("publisher_authentication_rejected")
        due = time.monotonic()
        for sequence in range(1, config.message_count+1):
            pump_until(clients, lambda: time.monotonic() >= due or interrupted, remaining())
            remaining()
            data = encode_payload(config, sequence, publisher.session_id, utc_now())
            messages[sequence] = dict(queued=False, sent=False, ack=None, hash=digest(data))
            records.event("publisher", "PUBLISH_ATTEMPT", sequence=sequence,
                          event_id=f"{config.run_id}:{sequence}", payload_length=len(data),
                          payload_sha256=digest(data), claimed_device_id=config.claimed_device_id,
                          local_session_id=publisher.session_id, result="attempted")
            info = publisher.publish(config.topic, data, config.qos)
            messages[sequence]["queued"] = True
            records.event("publisher", "PUBLISH_QUEUED", sequence=sequence,
                          event_id=f"{config.run_id}:{sequence}", payload_length=len(data), result="queued")
            due = time.monotonic() + config.interval
            pump_until(clients, lambda: info.mid in (publisher.acks if config.qos else publisher.sent)
                       or interrupted, remaining())
            remaining()
            messages[sequence]["sent"] = True
            if config.qos:
                ack = publisher.acks.pop(info.mid)
                messages[sequence]["ack"] = ack
                records.event("publisher", "PUBACK", sequence=sequence,
                              reason_code=ack, result="accepted" if ack in (0,16) else "denied")
                if ack not in (0, 16):
                    raise ProbeError("publish_denied")
            else:
                records.event("publisher", "QOS0_CLIENT_SENT", sequence=sequence,
                              reason_code=None, result="client_side_only_no_puback",
                              connection_valid=publisher.connected)
            drain()
        def complete():
            drain()
            return bool(sink and len(sink.received) == config.message_count) or interrupted
        pump_until(clients, complete, remaining())
        remaining()
        if any(sink.received.get(seq) != item["hash"] for seq,item in messages.items()) or sink.conflicts or sink.malformed:
            raise ProbeError("reconciliation_failed")
        records.event("publisher", "CONNECTION_VALID_AT_COMPLETION", connected=publisher.connected)
    except ProbeError as exc:
        failure = str(exc)
    except Exception as exc:
        records.event("publisher", "RUNTIME_ERROR_TYPE", exception_type=type(exc).__name__)
        failure = "runtime_or_output_error"
    finally:
        for client in clients:
            try:
                client.close()
            except Exception:
                failure = "shutdown_error"
        for sig, handler in old.items():
            signal.signal(sig, handler)
    try:
        if failure:
            records.event("publisher", "RUN_ERROR", result=failure)
        values = list(messages.values())
        counts = dict(attempted_messages=len(values), queued_messages=sum(v["queued"] for v in values),
                      client_sent_messages=sum(v["sent"] for v in values),
                      accepted_acknowledgements=sum(v["ack"] in (0,16) for v in values) if config.qos else None,
                      denied_publishes=sum(v["ack"] is not None and v["ack"] >= 128 for v in values) if config.qos else None,
                      puback_applicable=config.qos == 1,
                      pdp_observed_messages=sink.observed if sink and config.workload == "telemetry" else None,
                      downstream_receiver_messages=sink.observed if sink and config.workload == "operations" else None,
                      receive_duplicates=sink.duplicates if sink else None, errors=int(failure is not None))
        summary = dict(state="INCOMPLETE" if failure else "COMPLETE", incomplete=bool(failure),
                       failure_code=failure, timeout=failure == "timeout", counts=counts,
                       correlated_sequences=sorted(seq for seq,item in messages.items()
                           if sink and sink.received.get(seq) == item["hash"]),
                       decision="NOT_IMPLEMENTED", authenticated_publisher_identity=None)
        records.finish(summary)
        return summary
    finally:
        records.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", choices=tuple(DEVICES), default="device01")
    parser.add_argument("--workload", choices=("telemetry","operations"), default="telemetry")
    parser.add_argument("--qos", type=int, choices=(0,1), default=1)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--interval", type=float, default=0.1)
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--payload-size", type=int, default=512)
    parser.add_argument("--output-dir", default="/results")
    args = parser.parse_args()
    try:
        config = FoundationConfig(run_id=args.run_id or new_run_id(), scenario="a3-functional",
            device_identity=DEVICES[args.device], claimed_device_id=args.device,
            topic=topic(args.device,args.workload), workload=args.workload, qos=args.qos,
            message_count=args.count, interval=args.interval, timeout=args.timeout,
            seed=args.seed,payload_size=args.payload_size).validate()
        result = run(config,args.output_dir)
        print(f'A3_RUN {config.run_id} {result["state"]} {result["counts"]}')
        return int(result["incomplete"])
    except (ValueError, OSError):
        print("A3_CONFIG_OR_OUTPUT_ERROR")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
