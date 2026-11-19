"""Bounded MQTT v5/QoS 1 traffic for the isolated A1-P broker only."""

import json
import os
import threading
import time

import paho.mqtt.client as mqtt


HOST = os.environ.get("POC_HOST", "a1p-broker")
COUNT = 100
TIMEOUT = 8.0


class Peer:
    def __init__(self, name: str, password: str):
        self.name = name
        self.connected = threading.Event()
        self.suback = threading.Event()
        self.suback_codes = []
        self.puback_codes = {}
        self.received = []
        self.lock = threading.Lock()
        self.client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=name,
            protocol=mqtt.MQTTv5,
        )
        self.client.username_pw_set(name, password)
        self.client.on_connect = self._connect
        self.client.on_subscribe = self._subscribe
        self.client.on_publish = self._publish
        self.client.on_message = self._message

    def _connect(self, client, userdata, flags, reason_code, properties):
        if reason_code.value == 0:
            self.connected.set()

    def _subscribe(self, client, userdata, mid, reason_codes, properties):
        self.suback_codes = [code.value for code in reason_codes]
        self.suback.set()

    def _publish(self, client, userdata, mid, reason_code, properties):
        with self.lock:
            self.puback_codes[mid] = reason_code.value

    def _message(self, client, userdata, message):
        if message.topic == "poc/shared":
            with self.lock:
                self.received.append(message.payload)

    def start(self):
        self.client.connect(HOST, 1883, keepalive=15)
        self.client.loop_start()
        if not self.connected.wait(TIMEOUT):
            raise AssertionError(f"{self.name} did not authenticate")

    def subscribe(self, topic: str) -> int:
        self.suback.clear()
        result, _ = self.client.subscribe(topic, qos=1)
        if result != mqtt.MQTT_ERR_SUCCESS or not self.suback.wait(TIMEOUT):
            raise AssertionError(f"{self.name} subscription did not complete")
        return self.suback_codes[0]

    def publish(self, topic: str, payload: bytes) -> int:
        info = self.client.publish(topic, payload, qos=1)
        info.wait_for_publish(timeout=TIMEOUT)
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            with self.lock:
                if info.mid in self.puback_codes:
                    return self.puback_codes.pop(info.mid)
            time.sleep(0.01)
        raise AssertionError(f"{self.name} PUBACK missing")

    def stop(self):
        self.client.disconnect()
        self.client.loop_stop()


def main():
    started = time.monotonic()
    peers = [
        Peer("poc-reader", os.environ["POC_READER_PASSWORD"]),
        Peer("poc-a", os.environ["POC_A_PASSWORD"]),
        Peer("poc-b", os.environ["POC_B_PASSWORD"]),
        Peer("poc-admin", os.environ["POC_ADMIN_PASSWORD"]),
    ]
    reader, a, b, admin = peers
    try:
        for peer in peers:
            peer.start()
        assert reader.subscribe("poc/shared") == 1
        denied_sub = a.subscribe("poc/#")
        assert denied_sub == 135, denied_sub
        accepted = 0
        for _ in range(COUNT):
            # Spoofed payload claims differ from broker-authenticated identities.
            assert a.publish("poc/shared", b'{"device_id":"poc-b"}') == 0
            assert b.publish("poc/shared", b'{"device_id":"poc-a"}') == 0
            accepted += 2
        denied_pub = a.publish("poc/forbidden", b"synthetic")
        assert denied_pub == 135, denied_pub
        # Valid traffic excluded by principal/topic filters, plus bounded metadata.
        assert admin.publish("poc/shared", b'{"device_id":"payload-marker"}') == 0
        assert a.publish("poc/other", b'{"device_id":"payload-marker"}') == 16
        assert a.publish("poc/long/" + "x" * 240, b'{"device_id":"payload-marker"}') == 16
        accepted += 3
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            with reader.lock:
                received = len(reader.received)
            if received >= COUNT * 2 + 1:
                break
            time.sleep(0.02)
        assert received == COUNT * 2 + 1, (received, accepted)
        print(json.dumps({
            "result": "PASS", "mqtt_version": 5, "qos": 1,
            "synthetic_clients": [peer.name for peer in peers],
            "publish_attempted": accepted + 1,
            "publish_puback_allowed": accepted,
            "publish_puback_denied": 1,
            "subscribe_allowed": 1,
            "subscribe_denied": 1,
            "receiver_messages": received,
            "rough_elapsed_ms": round((time.monotonic() - started) * 1000),
        }))
    finally:
        for peer in peers:
            peer.stop()


if __name__ == "__main__":
    main()
