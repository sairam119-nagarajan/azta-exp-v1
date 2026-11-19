'''Small synchronous MQTT loop shared by the bounded Gate 3 clients.'''
import json
import os
from pathlib import Path
import signal
import threading
import time

import paho.mqtt.client as mqtt

TOPIC = 'azta/devices/device01/telemetry'


def log(event, **fields):
    print(json.dumps(dict(event=event, **fields), sort_keys=True), flush=True)


class Session:
    def __init__(self, identity):
        self.identity = identity
        self.stop = threading.Event()
        self.connected = False
        self.connack = None
        self.client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2, client_id=identity,
            protocol=mqtt.MQTTv5, reconnect_on_failure=False)
        self.client.connect_timeout = 3
        password = Path(os.environ['MQTT_PASSWORD_FILE']).read_text().strip()
        if not password:
            raise ValueError('MQTT credential file is empty')
        self.client.username_pw_set(identity, password)
        self.client.on_connect = self._connected
        self.client.on_disconnect = self._disconnected
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_: self.stop.set())

    def _connected(self, client, userdata, flags, reason, properties):
        self.connack = reason.value
        self.connected = not reason.is_failure
        log('connack', identity=self.identity, reason_code=reason.value)

    def _disconnected(self, client, userdata, flags, reason, properties):
        self.connected = False

    def connect(self):
        host = os.getenv('MQTT_HOST', 'broker')
        for attempt in range(1, 6):
            if self.stop.is_set():
                raise InterruptedError('Shutdown requested')
            self.connack = None
            try:
                self.client.connect(host, 1883, keepalive=30, clean_start=True)
                deadline = time.monotonic() + 3
                while self.connack is None and time.monotonic() < deadline:
                    if self.stop.is_set():
                        raise InterruptedError('Shutdown requested')
                    if self.client.loop(timeout=0.2) != mqtt.MQTT_ERR_SUCCESS:
                        break
                if self.connected:
                    return
                if self.connack is not None:
                    raise RuntimeError(f'Authentication rejected: CONNACK {self.connack}')
                error = 'CONNACK timeout or connection lost'
            except OSError as exc:
                error = type(exc).__name__
            self.client.disconnect()
            log('connection_retry', attempt=attempt, max_attempts=5, error=error)
            if attempt < 5:
                self.stop.wait(2)
        raise RuntimeError('Broker connection failed after 5 attempts')

    def until(self, predicate, timeout):
        deadline = time.monotonic() + timeout
        while not predicate():
            if self.stop.is_set():
                raise InterruptedError('Shutdown requested')
            if not self.connected:
                raise RuntimeError('Broker connection lost; run stopped')
            if time.monotonic() >= deadline:
                raise TimeoutError('MQTT acknowledgement or message deadline exceeded')
            rc = self.client.loop(timeout=0.2)
            if rc != mqtt.MQTT_ERR_SUCCESS:
                raise RuntimeError(f'MQTT loop failed: {rc}')

    def close(self):
        self.client.disconnect()
        log('shutdown')
