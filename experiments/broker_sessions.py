"""Read-only parsing of selected Mosquitto connection log events.

Only ``New client connected`` is evidence of an authenticated MQTT session.
The broker log format inspected for FE-01 does not attribute individual
PUBLISH, SUBSCRIBE, or authorization-denial events to that session. Payload
``device_id`` is never read or treated as authentication evidence.
The observed disconnect line does not, by itself, distinguish a broker-
initiated quarantine from every other disconnect; that field remains null
unless the text explicitly says the client closed its own connection.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime, timezone


_PREFIX = re.compile(r"^(?:(?P<epoch>\d{9,13}): )?(?P<body>.*)$")
_TCP = re.compile(r"^New connection from (?P<endpoint>\S+) on port \d{1,5}\.$")
_CONNECT = re.compile(
    r"^New client connected from (?P<endpoint>\S+) as "
    r"(?P<client_id>[^\s()]+) \((?P<details>[^)]{0,256})\)\.$"
)
_DISCONNECT = re.compile(
    r"^Client (?P<client_id>[^\s\[\]]+) \[(?P<endpoint>[^\]]+)\] "
    r"disconnected: (?P<reason>.*)\.$"
)
_USERNAME = re.compile(r"(?:^|, )u'(?P<username>[^']+)'(?:,|$)")
_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_SENSITIVE_MARKERS = ("password", "passwd", "secret", "token", "credential")
_REASONS = {
    "connection closed by client": ("CLIENT_CLOSED", False),
    "not authorised": ("NOT_AUTHORISED", None),
}


def _safe_identifier(value: str) -> str | None:
    if not _IDENTIFIER.fullmatch(value):
        return None
    if any(marker in value.lower() for marker in _SENSITIVE_MARKERS):
        return None
    return value


def _safe_endpoint(value: str) -> str | None:
    host, separator, port_text = value.rpartition(":")
    if not separator or not port_text.isdecimal():
        return None
    try:
        ipaddress.ip_address(host)
        port = int(port_text)
    except ValueError:
        return None
    return value if 1 <= port <= 65535 else None


def _timestamp(epoch_text: str | None) -> str | None:
    if epoch_text is None:
        return None
    try:
        return datetime.fromtimestamp(int(epoch_text), timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
    except (OverflowError, OSError, ValueError):
        return None


class BrokerSessionParser:
    """Statefully join authenticated connects to exact client/endpoint closes.

    Session IDs are random local UUID4 labels, not MQTT session identifiers.
    They are stable only within this parser instance and are not persisted.
    An unmatched disconnect has no authenticated username or session ID.
    Matching by client ID and endpoint assumes an ordered, complete log stream;
    it cannot prove identity across missing lines or a broker restart.
    """

    def __init__(self) -> None:
        self._sessions: dict[tuple[str, str], tuple[str, str | None]] = {}

    def parse_line(self, line: str) -> dict[str, object] | None:
        """Return a bounded structured event, or ``None`` for unknown lines."""
        prefix = _PREFIX.fullmatch(line.strip())
        if prefix is None:
            return None
        body = prefix.group("body")
        timestamp = _timestamp(prefix.group("epoch"))

        tcp = _TCP.fullmatch(body)
        if tcp is not None:
            endpoint = _safe_endpoint(tcp.group("endpoint"))
            if endpoint is None:
                return None
            return self._event(
                "TCP_ACCEPTED", timestamp, None, None, endpoint, None,
                "broker_tcp_accept_line", None,
                ["tcp_accept_does_not_prove_mqtt_authentication"],
            )

        connect = _CONNECT.fullmatch(body)
        if connect is not None:
            endpoint = _safe_endpoint(connect.group("endpoint"))
            client_id = _safe_identifier(connect.group("client_id"))
            if endpoint is None or client_id is None:
                return None
            username_match = _USERNAME.search(connect.group("details"))
            username = (
                _safe_identifier(username_match.group("username"))
                if username_match is not None else None
            )
            session_id = f"azta-local-{uuid.uuid4().hex}"
            self._sessions[(client_id, endpoint)] = (session_id, username)
            limitations = [] if username is not None else ["username_not_available"]
            return self._event(
                "CONNECT", timestamp, username, client_id, endpoint, session_id,
                "broker_authenticated_connect_line", None, limitations,
            )

        disconnect = _DISCONNECT.fullmatch(body)
        if disconnect is not None:
            endpoint = _safe_endpoint(disconnect.group("endpoint"))
            client_id = _safe_identifier(disconnect.group("client_id"))
            if endpoint is None or client_id is None:
                return None
            matched = self._sessions.pop((client_id, endpoint), None)
            reason = _REASONS.get(disconnect.group("reason"))
            limitations = []
            if matched is None:
                limitations.append("unmatched_disconnect_identity_unconfirmed")
            if reason is None:
                limitations.append("disconnect_reason_not_classified")
            return self._event(
                "DISCONNECT", timestamp, matched[1] if matched else None,
                client_id, endpoint, matched[0] if matched else None,
                "broker_disconnect_line", reason, limitations,
            )

        return None

    def parse_text(self, text: str) -> list[dict[str, object]]:
        """Parse log text in order so exact connect/disconnect joins are possible."""
        return [event for line in text.splitlines() if (event := self.parse_line(line))]

    @staticmethod
    def _event(
        event_type: str,
        timestamp: str | None,
        username: str | None,
        client_id: str | None,
        endpoint: str | None,
        session_id: str | None,
        classification: str,
        reason: tuple[str, bool | None] | None,
        limitations: list[str],
    ) -> dict[str, object]:
        return {
            "event_type": event_type,
            "timestamp_utc": timestamp,
            "username": username,
            "client_id": client_id,
            "remote_endpoint": endpoint,
            "session_id": session_id,
            "raw_event_classification": classification,
            "disconnect_context": reason[0] if reason else None,
            "server_triggered_disconnect": reason[1] if reason else None,
            "parsing_limitations": limitations,
        }
