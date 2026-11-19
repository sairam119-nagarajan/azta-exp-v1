"""Phase 2 (protocol P2-REL section 7): broker-confirmed connection evidence and the reconnection-aware interpretation RC-1 of behavioural evidence.

Evidence. The broker's own log (Mosquitto, Dynamic Security) names the AUTHENTICATED client of every connection, disconnection and session takeover. That is evidence the system genuinely has;
the device's own ledger (what it says it did) is never used. A `ConnectionEvent` is one parsed broker line: the Docker receipt timestamp (VM clock, the clock of the observer), the kind and the
client id (and, for a connection, the authenticated username).

Interpretation RC-1 (declared before any Phase 2 evaluation; versioned; absent = the unchanged behaviour):
  * a RECONNECTION is an authenticated connection of the device's registered client id AND username at t_c that follows either a disconnection of the same client id at t_d with
    0 <= t_c - t_d <= G_MAX (clean DISCONNECT, closed socket, socket error or keep-alive timeout), or a TAKEOVER line (the broker closing the old connection of the same client id at t_c);
  * its EXPLAINED interval is [t_d, t_c] (takeover: [max(last delivery before t_c, t_c - G_MAX), t_c]), widened by the declared clock tolerance on both sides;
  * at most BUDGET reconnections of a device are explained in any rolling hour; a further one (flapping) and an offline time longer than G_MAX are NOT explained;
  * a behavioural evidence item whose observation interval overlaps an explained interval is turned into a MISSING item with reason `CONNECTION_EXPLAINED`: it neither confirms nor clears
    anything (missing evidence is never healthy; the unchanged N = 2 filter holds and resets on it); every other item is untouched, so an anomaly before or after the reconnection is judged as
    before. Nothing is granted beyond the explained interval, nothing is automatic, nothing changes trust weights, thresholds, lambda or N = 2.
A silence with NO broker event (telemetry interrupted while the session stays connected, a dropped message, complete suppression, an observer outage) is never explained.
"""
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import re

RC_VERSION = "RC-1"
G_MAX_NS = 15_000_000_000
BUDGET = 4
BUDGET_WINDOW_NS = 3600 * 1_000_000_000
TOLERANCE_NS = 1_000_000_000
REASON = "CONNECTION_EXPLAINED"

_LINE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z\s+(?:\d+: )?(.*?)\s*$")
_CONNECTED = re.compile(r"^New client connected from \S+ as (\S+) \(p\d+, c\d+, k\d+(?:, u'([^']*)')?\)\.?$")
# Mosquitto 2.x (VERIFIED on the engineering broker, run g6c-h00): "Client <id> [<addr>] disconnected." (clean), "Client <id> [<addr>] disconnected: session taken over." (takeover); the
# older 1.x/2.0 wordings are accepted too, so a broker version change cannot silently turn a disconnection into "no event"
_CLIENT_LINE = re.compile(r"^Client (\S+)(?: \[[^\]]*\])? (disconnected|closed its connection|has exceeded timeout, disconnecting|already connected, closing old connection)(?::\s*(.*?))?\.?$")
_SOCKET_ERROR = re.compile(r"^Socket error on client (\S+), disconnecting\.?$")


def _classify(verb, reason):
    reason = (reason or "").lower()
    if verb.startswith("already connected") or "taken over" in reason:
        return "TAKEOVER"
    if verb.startswith("has exceeded") or "timeout" in reason:
        return "TIMEOUT"
    if verb.startswith("closed") or "closed" in reason:
        return "CLOSED"
    if "error" in reason or "protocol" in reason:
        return "SOCKET_ERROR"
    return "DISCONNECTED"
OFFLINE_KINDS = ("DISCONNECTED", "CLOSED", "TIMEOUT", "SOCKET_ERROR")


@dataclass(frozen=True)
class ConnectionEvent:
    t_ns: int              # UTC epoch ns (Docker receipt timestamp of the broker line)
    kind: str
    client_id: str
    username: object = None


def utc_ns(stamp, fraction=None):
    seconds = int(datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp())
    return seconds * 1_000_000_000 + (int((fraction or "0").ljust(9, "0")) if fraction else 0)


def parse_broker_log(text):
    """[ConnectionEvent] of the connection-related lines of a `docker logs --timestamps` capture, in order; every other line is ignored."""
    out = []
    for raw in text.splitlines():
        m = _LINE.match(raw.strip())
        if not m:
            continue
        stamp, fraction, message = m.groups()
        t = utc_ns(stamp, fraction)
        hit = _CONNECTED.match(message)
        if hit:
            out.append(ConnectionEvent(t, "CONNECTED", hit.group(1), hit.group(2)))
            continue
        hit = _CLIENT_LINE.match(message)
        if hit:
            out.append(ConnectionEvent(t, _classify(hit.group(2), hit.group(3)), hit.group(1)))
            continue
        hit = _SOCKET_ERROR.match(message)
        if hit:
            out.append(ConnectionEvent(t, "SOCKET_ERROR", hit.group(1)))
    return out


@dataclass(frozen=True)
class Decision:
    t_ns: int
    outcome: str           # EXPLAINED, NOT_EXPLAINED_LONG_OFFLINE, NOT_EXPLAINED_BUDGET, NOT_EXPLAINED_IDENTITY, SESSION_START
    start_ns: object = None
    end_ns: object = None


class Explainer:
    """The explained intervals of ONE device under RC-1. `events` = ConnectionEvent (any clients, any order, UTC ns); `to_offset` maps a UTC instant onto the clock of the behavioural items
    (identity when both are already on one clock); `last_delivery_before(t)` = the latest observed delivery of the device before t on the items' clock (or None) for the takeover case."""

    def __init__(self, events, *, client_id, username, to_offset=lambda t: t, last_delivery_before=None, g_max_ns=G_MAX_NS, budget=BUDGET, budget_window_ns=BUDGET_WINDOW_NS,
                 tolerance_ns=TOLERANCE_NS):
        self.decisions, self.intervals = [], []
        explained_at, offline_since, connected_once = [], None, False
        mine = sorted((e for e in events if e.client_id == client_id), key=lambda e: e.t_ns)
        for i, e in enumerate(mine):
            if e.kind in OFFLINE_KINDS:
                offline_since = e.t_ns if offline_since is None else offline_since
                continue
            if e.kind != "CONNECTED":
                continue
            takeover = any(x.kind == "TAKEOVER" and abs(x.t_ns - e.t_ns) <= tolerance_ns for x in mine[max(0, i - 3):i + 3])
            t_c = to_offset(e.t_ns)
            if e.username != username:
                self.decisions.append(Decision(t_c, "NOT_EXPLAINED_IDENTITY"))
            elif not connected_once and offline_since is None and not takeover:
                self.decisions.append(Decision(t_c, "SESSION_START"))
            else:
                if takeover:
                    start = t_c - g_max_ns
                    last = last_delivery_before(t_c) if last_delivery_before else None
                    if last is not None:
                        start = max(start, last)
                    long = False
                else:
                    start = to_offset(offline_since) if offline_since is not None else None
                    long = start is None or t_c - start > g_max_ns
                recent = [t for t in explained_at if e.t_ns - t < budget_window_ns]
                if long:
                    self.decisions.append(Decision(t_c, "NOT_EXPLAINED_LONG_OFFLINE", start, t_c))
                elif len(recent) >= budget:
                    self.decisions.append(Decision(t_c, "NOT_EXPLAINED_BUDGET", start, t_c))
                else:
                    explained_at.append(e.t_ns)
                    interval = (start - tolerance_ns, t_c + tolerance_ns)
                    self.intervals.append(interval)
                    self.decisions.append(Decision(t_c, "EXPLAINED", *interval))
            connected_once, offline_since = True, None

    def explains(self, start_ns, end_ns):
        """True when the observation interval [start_ns, end_ns) overlaps an explained interval (a point item: start_ns None)."""
        lo = end_ns - 1 if start_ns is None else start_ns
        return any(lo < b and end_ns > a for a, b in self.intervals)

    def filter_items(self, items):
        """Items with every explained one turned into a MISSING item (reason CONNECTION_EXPLAINED); the others unchanged."""
        return [replace(i, a=None, reason=REASON) if i.a is not None and self.explains(i.start_ns, i.observed_ns) else i for i in items]


class ConnectionEvidence:
    """The provider `hybrid.engine.HybridBehaviorEvaluator.with_connection` takes: one `Explainer` (or anything with `explains`/`filter_items`) per device; a device without one is never
    explained. A live deployment rebuilds the explainers from a follower of the broker log (Phase 3); offline, they are built once from a captured log."""

    def __init__(self, explainers):
        self.explainers = dict(explainers)

    def explains(self, device, start_ns, end_ns):
        x = self.explainers.get(device)
        return bool(x and x.explains(start_ns, end_ns))

    def filter_items(self, device, items):
        x = self.explainers.get(device)
        return x.filter_items(items) if x else list(items)


def explain_records(records, windows, explainer):
    """RC-1 on per-tick AE-only records (devices scored by one 10 s autoencoder): a tick whose window overlaps an explained interval becomes MISSING (CONNECTION_EXPLAINED)."""
    out = []
    for r, w in zip(records, windows):
        if r["a"] is not None and explainer.explains(w.start_ns, w.end_ns):
            r = dict(r, a=None, status="MISSING", reasons=[REASON], explained=True)
        out.append(r)
    return out


def explaining_monitor(spec, explainer):
    """A `hybrid.monitor.DeviceMonitor` whose fusion sees RC-1-filtered items (the monitor itself, its streams and its fusion are unchanged)."""
    from hybrid import monitor as mon

    monitor = mon.DeviceMonitor(spec)
    inner = monitor.fusion.tick
    monitor.fusion.tick = lambda tick_ns, items: inner(tick_ns, explainer.filter_items(items))
    return monitor


def run_stream(spec, windows, explainer, *, outages=()):
    """`hybrid.monitor.run_stream` under RC-1."""
    from hybrid import monitor as mon

    monitor = explaining_monitor(spec, explainer)
    return [monitor.tick(mon.record_of(w, complete=w.index not in outages), tick_ns=w.end_ns) for w in windows]
