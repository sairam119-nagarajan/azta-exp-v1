"""Finite MQTT v5 primitives for explicit A3 research/probes. No policy decisions."""
from pathlib import Path
import time
import uuid
import paho.mqtt.client as mqtt

DEVICES = {"device01": "azta-device-01", "device02": "azta-device-02"}
RECEIVER = "azta-operations-receiver"


def topic(device, workload):
    if device not in DEVICES or workload not in ("telemetry", "operations"):
        raise ValueError("Unknown device/workload")
    return f"azta/devices/{device}/{workload}"


def password_for(identity, root="/run/secrets"):
    names = {"admin": "dynsec_admin_password", "azta-device-01": "device_password",
             "azta-device-02": "device02_password", "azta-pdp": "pdp_password",
             RECEIVER: "receiver_password"}
    return Path(root) / names[identity]


class ProbeError(Exception):
    pass


class MQTTClient:
    def __init__(self, identity, credential, emit, host="broker"):
        self.identity, self.emit, self.host = identity, emit, host
        self.session_id = ("pub-" if identity in DEVICES.values() else "session-") + uuid.uuid4().hex
        self.connected = False
        self.connack = None
        self.disconnection = None
        self.intentional_close = False
        self.subacks, self.acks, self.sent = {}, {}, set()
        self.messages = []
        self.qos_by_mid = {}
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=identity,
                                  protocol=mqtt.MQTTv5, reconnect_on_failure=False)
        self.client.connect_timeout = 1
        try:
            with Path(credential).open(encoding="utf-8") as stream:
                secret = stream.read(4097).strip()
            if not secret or len(secret) > 4096:
                raise ValueError()
        except (OSError, ValueError):
            raise ProbeError("credential_unavailable") from None
        self.client.username_pw_set(identity, secret)
        self.client.on_connect = self._connect
        self.client.on_disconnect = self._disconnect
        self.client.on_subscribe = lambda c, u, mid, reasons, p: self.subacks.update(
            {mid: [reason.value for reason in reasons]})
        self.client.on_publish = self._publish
        self.client.on_message = lambda c, u, m: self.messages.append(m)

    def event(self, kind, **fields):
        self.emit(kind, identity=self.identity, client_id=self.identity,
                  local_session_id=self.session_id, **fields)

    def _connect(self, client, userdata, flags, reason, properties):
        self.connack = reason.value
        self.connected = self.connack == 0
        self.event("CONNACK", reason_code=self.connack,
                   authentication_evidence="broker_response_to_configured_credentials")

    def _disconnect(self, client, userdata, flags, reason, properties):
        self.connected = False
        self.disconnection = dict(reason_code=reason.value,
                                  server_disconnect_packet=flags.is_disconnect_packet_from_server,
                                  intentional=self.intentional_close)
        self.event("DISCONNECT", **self.disconnection)

    def _publish(self, client, userdata, mid, reason, properties):
        # QoS0 callbacks can happen synchronously in publish(). Never label these PUBACK.
        self.sent.add(mid)
        if self.qos_by_mid.get(mid) == 1:
            self.acks[mid] = reason.value

    def loop(self):
        return self.client.loop(timeout=0.005)

    def connect(self, timeout=3):
        deadline = time.monotonic() + timeout
        # Paho prohibits changing this property once connect() has entered its
        # connecting state, including after a refused TCP connection.
        self.client.connect_timeout = max(0.01, min(1, timeout / 3))
        for attempt in range(1, 4):
            self.connack = None
            try:
                self.client.connect(self.host, 1883, keepalive=15, clean_start=True)
                while self.connack is None and time.monotonic() < deadline:
                    if self.loop() != mqtt.MQTT_ERR_SUCCESS:
                        break
                if self.connack is not None:
                    return self.connack
            except OSError:
                pass
            if time.monotonic() >= deadline:
                break
            time.sleep(0.05)
        raise ProbeError("broker_unavailable")

    def subscribe(self, exact_topic, qos=1, timeout=3):
        rc, mid = self.client.subscribe(exact_topic, qos=qos)
        if rc != 0:
            raise ProbeError("subscribe_enqueue_failed")
        pump_until([self], lambda: mid in self.subacks, timeout)
        result = self.subacks.pop(mid)
        self.event("SUBACK", topic=exact_topic, qos=qos, reason_codes=result)
        return result

    def publish(self, target, payload, qos):
        info = self.client.publish(target, payload, qos=qos, retain=False)
        self.qos_by_mid[info.mid] = qos
        if info.rc != 0:
            raise ProbeError("publish_enqueue_failed")
        return info

    def close(self):
        self.intentional_close = True
        self.client.disconnect()


def pump_until(clients, predicate, timeout, allow_disconnect=False):
    deadline = time.monotonic() + max(0, timeout)
    while not predicate():
        if time.monotonic() >= deadline:
            raise ProbeError("timeout")
        for client in clients:
            if client.connected:
                rc = client.loop()
                if rc != 0 and not allow_disconnect:
                    raise ProbeError("connection_lost")
            elif not allow_disconnect:
                raise ProbeError("connection_lost")


def observe_window(clients, seconds):
    end = time.monotonic() + seconds
    pump_until(clients, lambda: time.monotonic() >= end, seconds + 1)
