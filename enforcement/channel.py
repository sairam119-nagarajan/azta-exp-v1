"""Control channel to Mosquitto Dynamic Security: the ONLY module of the enforcement layer that touches the network.

`MqttControlChannel` publishes one command per request to `$CONTROL/dynamic-security/v1` (QoS 1, MQTT v5) as the administrative principal and waits for the
response that carries the same correlation data. It reads its credential from a file named by the caller and never logs it; commands are logged by NAME and
correlation id only (no password field exists in any command this layer sends). A missing PUBACK, a missing response, a lost connection or a refused CONNECT
raises `ControlUnavailable`: the effect of an in-flight command is then UNKNOWN and the caller settles it by reading the broker's state, never by assuming.

The protocol every channel (this one, the fake broker of the tests) implements is `command(name, **fields) -> dict(success, error, data)` plus `close()`.
Administrative credentials exist only in the process that builds this channel: the PDP, the decision pipeline and every device process are separate programs
with their own single credential and never import this module.
"""
import json
from pathlib import Path
import time
import uuid

import paho.mqtt.client as mqtt

from enforcement.errors import ControlUnavailable

CONTROL = "$CONTROL/dynamic-security/v1"
MAX_CREDENTIAL_BYTES = 4096


class MqttControlChannel:
    def __init__(self, host, credential_file, *, identity="admin", port=1883, response_timeout_s=5.0, connect_attempts=3, connect_timeout_s=3.0, log=None):
        self.host, self.port, self.identity = host, port, identity
        self.response_timeout_s, self.connect_attempts, self.connect_timeout_s = response_timeout_s, connect_attempts, connect_timeout_s
        self._log = log or (lambda event, **fields: None)
        self._credential_file = Path(credential_file)
        self._prefix = f"pep-{uuid.uuid4().hex[:12]}"
        self._counter = 0
        self._client = None
        self._connected = False
        self._connack = None
        self._acks, self._subacks, self._responses = {}, {}, {}

    # ---------------------------------------------------------------------------------------------------------- connection
    def _credential(self):
        try:
            text = self._credential_file.read_text(encoding="utf-8")[: MAX_CREDENTIAL_BYTES + 1].strip()
        except OSError:
            raise ControlUnavailable("CREDENTIAL_UNAVAILABLE", "the administrative credential file cannot be read") from None
        if not text or len(text) > MAX_CREDENTIAL_BYTES:
            raise ControlUnavailable("CREDENTIAL_UNAVAILABLE", "the administrative credential file is empty or oversized")
        return text

    def _on_connect(self, client, userdata, flags, reason, properties):
        self._connack, self._connected = reason.value, not reason.is_failure

    def _on_disconnect(self, client, userdata, flags, reason, properties):
        self._connected = False

    def _on_message(self, client, userdata, message):
        try:
            for item in json.loads(message.payload).get("responses", []):
                if isinstance(item, dict) and isinstance(item.get("correlationData"), str):
                    self._responses[item["correlationData"]] = item
        except (ValueError, AttributeError):
            pass

    def _pump(self, predicate, timeout, *, need_connection=True):
        deadline = time.monotonic() + timeout
        while not predicate():
            if time.monotonic() >= deadline or (need_connection and not self._connected):
                return False
            if self._client.loop(timeout=0.1) != mqtt.MQTT_ERR_SUCCESS:
                self._connected = False
                return False
        return True

    def connect(self):
        self._drop()
        secret = self._credential()
        for attempt in range(1, self.connect_attempts + 1):
            client_id = f"{self._prefix}-{attempt}"
            client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id, protocol=mqtt.MQTTv5, reconnect_on_failure=False)
            client.connect_timeout = self.connect_timeout_s
            client.username_pw_set(self.identity, secret)
            client.on_connect, client.on_disconnect, client.on_message = self._on_connect, self._on_disconnect, self._on_message
            client.on_subscribe = lambda c, u, mid, reasons, p: self._subacks.update({mid: [r.value for r in reasons]})
            client.on_publish = lambda c, u, mid, reason, p: self._acks.update({mid: reason.value})
            self._client, self._connack, self._connected = client, None, False
            try:
                client.connect(self.host, self.port, keepalive=30, clean_start=True)
                self._pump(lambda: self._connack is not None, self.connect_timeout_s, need_connection=False)
            except OSError:
                pass
            if self._connected:
                rc, mid = client.subscribe(CONTROL + "/response", qos=1)
                if rc == mqtt.MQTT_ERR_SUCCESS and self._pump(lambda: mid in self._subacks, self.response_timeout_s) and self._subacks.pop(mid) == [1]:
                    self._log("control_connected", attempt=attempt)
                    return
            self._drop()
            time.sleep(0.5)
        raise ControlUnavailable("CONTROL_CONNECT_FAILED", f"no authenticated control session after {self.connect_attempts} attempts")

    def _drop(self):
        if self._client is not None:
            try:
                self._client.disconnect()
            except Exception:
                pass
        self._client, self._connected = None, False

    # ------------------------------------------------------------------------------------------------------------ command
    def command(self, name, **fields):
        """One command and its response. Mosquitto disconnects a client whose roles it changes ('administrative action'), including this channel's own principal: pending network events are
        processed first so a closed connection is noticed, and a READ whose transport failed is retried once on a fresh connection (a read has no effect to settle). A mutation is never
        re-sent here: its outcome is unknown and the caller settles it by reading state."""
        try:
            return self._command_once(name, fields)
        except ControlUnavailable as exc:
            if name.startswith(("get", "list")) and exc.code in ("CONTROL_NO_PUBACK", "CONTROL_NO_RESPONSE", "CONTROL_ENQUEUE_FAILED"):
                self._drop()
                return self._command_once(name, fields)
            raise

    def _command_once(self, name, fields):
        if self._client is not None:
            self._client.loop(timeout=0.05)
        if not self._connected:
            self.connect()
        self._counter += 1
        correlation = f"{self._prefix}:{self._counter}:{name}"
        payload = json.dumps(dict(commands=[dict(command=name, correlationData=correlation, **fields)])).encode("utf-8")
        self._log("control_request", command=name, correlation=correlation)
        info = self._client.publish(CONTROL, payload, qos=1)
        if info.rc != mqtt.MQTT_ERR_SUCCESS:
            self._drop()
            raise ControlUnavailable("CONTROL_ENQUEUE_FAILED", name)
        if not self._pump(lambda: info.mid in self._acks, self.response_timeout_s):
            self._drop()
            raise ControlUnavailable("CONTROL_NO_PUBACK", f"{name}: the effect is unknown")
        if self._acks.pop(info.mid) not in (0, 16):
            raise ControlUnavailable("CONTROL_PUBLISH_DENIED", name)
        if not self._pump(lambda: correlation in self._responses, self.response_timeout_s):
            self._drop()
            raise ControlUnavailable("CONTROL_NO_RESPONSE", f"{name}: the effect is unknown")
        item = self._responses.pop(correlation)
        success = "error" not in item
        self._log("control_response", command=name, correlation=correlation, success=success)
        return dict(success=success, error=None if success else str(item.get("error"))[:200], data=item.get("data") or {})

    def close(self):
        self._drop()
