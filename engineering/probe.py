"""Operator-only data-plane probes for the isolated engineering broker: what the broker actually ALLOWS, not what its metadata says.

    python -m engineering.probe matrix --device deviceNN --phase NAME --out FILE
    python -m engineering.probe hold   --device deviceNN --seconds N --ready-file FILE --out FILE

The probe controller holds the credentials of the identities it acts as (the A3 pattern); it is never a PDP, device service or observer. `matrix` connects as the device's own
principal and records the MQTT outcome codes of: the connection, a publication to its own telemetry topic, to its own operations topic, to another device's telemetry topic, an exact
subscription to its own telemetry topic and a wildcard subscription, and reports what a receive-only observer (telemetry, all ten topics) and the operations receiver actually RECEIVED
from those publications, so an accepted publication is confirmed by delivery. `hold` keeps a session open until the broker ends it and records the server DISCONNECT packet (active
session termination) with its reason code. Codes: CONNACK/PUBACK/SUBACK 0 success, 16 accepted without matching subscribers, 135 not authorized. Nothing is retained, no password is logged,
and no broker response object is printed.
"""
import argparse
import json
from pathlib import Path
import sys
import time

from experiments.a3_mqtt import MQTTClient, ProbeError, pump_until
from observation.registry import DeviceRegistry

CREDENTIALS = Path("/credentials")
CONFIGS = Path("/app/configs")
OPERATIONS_DEVICES = ("device01", "device02")


def credential(principal):
    return CREDENTIALS / f"{principal}-password"


def registry():
    return DeviceRegistry.load(CONFIGS / "observation" / "device_registry_v2.json")


def _client(principal, events, host="broker"):
    return MQTTClient(principal, credential(principal), lambda kind, **data: events.append(dict(kind=kind, **data)), host=host)


def _drain(client, seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        client.loop()


def matrix(device, phase, host="broker"):
    reg = registry()
    by_device = {e.device: e for e in reg.devices}
    entry = by_device[device]
    other = by_device["device02" if device != "device02" else "device01"]
    events = []
    result = dict(device=device, phase=phase, started_utc_ns=time.time_ns(), connack=None, publishes={}, subscribes={}, received={}, disconnect=None)
    observer = _client("azta-observer", events, host)
    receiver = _client("azta-operations-receiver", events, host)
    subject = _client(entry.username, events, host)
    try:
        for client in (observer, receiver):
            if client.connect() != 0:
                raise ProbeError("listener_connect_failed")
        for e in reg.devices:
            if observer.subscribe(e.telemetry_topic) != [1]:
                raise ProbeError("observer_subscription_failed")
        for d in OPERATIONS_DEVICES:
            if receiver.subscribe(f"azta/devices/{d}/operations") != [1]:
                raise ProbeError("receiver_subscription_failed")
        received = {}
        for client in (observer, receiver):
            client.client.on_message = lambda c, u, m, store=received: store.setdefault(m.topic, []).append(json.loads(m.payload).get("probe"))
        result["connack"] = subject.connect()
        if result["connack"] == 0:
            probe_id = f"{phase}-{device}-{time.time_ns()}"
            targets = dict(own_telemetry=entry.telemetry_topic, own_operations=f"azta/devices/{device}/operations", other_telemetry=other.telemetry_topic)
            for name, topic in targets.items():
                info = subject.publish(topic, json.dumps(dict(probe=f"{probe_id}:{name}", device_id=device)).encode(), 1)
                pump_until([subject], lambda i=info: i.mid in subject.acks, 3)
                result["publishes"][name] = dict(topic=topic, puback=subject.acks.pop(info.mid))
            for name, topic in dict(own_telemetry=entry.telemetry_topic, wildcard="azta/devices/#").items():
                result["subscribes"][name] = dict(topic=topic, suback=subject.subscribe(topic)[0])
            for client in (observer, receiver, subject):
                _drain(client, 0.4)
            for name, spec in result["publishes"].items():
                tag = f"{probe_id}:{name}"
                spec["delivered_to_listener"] = any(tag in tags for tags in received.values())
            result["received"] = {t: len(v) for t, v in received.items()}
        result["finished_utc_ns"] = time.time_ns()
    finally:
        for client in (subject, observer, receiver):
            try:
                client.close()
            except Exception:
                pass
    return result


def hold(device, seconds, ready_file, host="broker"):
    entry = {e.device: e for e in registry().devices}[device]
    events = []
    client = _client(entry.username, events, host)
    out = dict(device=device, connack=client.connect(), ended_by="deadline")
    if out["connack"] != 0:
        out["ended_by"] = "not_connected"
        return out
    Path(ready_file).write_text("ready\n", encoding="utf-8")
    out["ready_utc_ns"] = time.time_ns()
    deadline = time.monotonic() + seconds
    while client.connected and time.monotonic() < deadline:
        client.loop()
    if client.disconnection:
        out.update(ended_by="server_disconnect" if client.disconnection["server_disconnect_packet"] else "connection_lost", disconnect=client.disconnection,
                   disconnected_utc_ns=time.time_ns())
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=("matrix", "hold"))
    parser.add_argument("--device", required=True)
    parser.add_argument("--phase", default="probe")
    parser.add_argument("--seconds", type=float, default=60)
    parser.add_argument("--ready-file")
    parser.add_argument("--out", required=True)
    parser.add_argument("--host", default="broker")
    args = parser.parse_args(argv)
    try:
        result = matrix(args.device, args.phase, args.host) if args.action == "matrix" else hold(args.device, args.seconds, args.ready_file, args.host)
    except (ProbeError, OSError, KeyError, ValueError) as exc:
        print(f"ENGINEERING_PROBE_FAILED {type(exc).__name__}: {str(exc)[:120]}", file=sys.stderr)
        return 1
    Path(args.out).write_text(json.dumps(result, sort_keys=True, indent=1) + "\n", encoding="utf-8")
    print("ENGINEERING_PROBE " + args.action.upper() + " " + json.dumps({k: result.get(k) for k in ("device", "phase", "connack", "ended_by")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
