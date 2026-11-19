"""Phase 2 review (protocol P2R section 6): the read-only LIVE feed of broker connection evidence for RC-1. Core completion repair: an explicit session lifecycle.

RC-1 itself is `family.connection` and is unchanged (G_MAX 15 s, budget 4 per rolling hour, tolerance 1 s, an explained item becomes MISSING, never healthy). This module adds only how the
evidence arrives while a session runs, and when it must NOT be used:

* Sources, all read-only, none from the device: the broker's own log lines (`docker logs --follow --timestamps`), and the observer session's own `health.jsonl` (each record carries the observer's
  monotonic offset AND its UTC) and `events.jsonl` (the deliveries the observer bound). No credentials, nothing written to the broker or the observer.
* Identity: client id AND authenticated username of every device come from the observer session's registry (`session_metadata.json`), never from a payload or the device.
* Clock: a broker UTC instant is mapped onto the observer offset clock through the health records (piecewise linear), which removes the drift between the observer's monotonic and wall clocks
  (about 47 ppm measured on g6c-h03). The anchor is VERIFIED when the broker's own connection line of the observer's client id lies within 1 s of the observer's CONNACK health record.
* Session domain (the repair of the P2R live failure): RC-1 sees only broker events from the anchor line up to the instant of this session's SESSION_END record. Earlier lines (the tail of a preceding
  back-to-back session, whose devices carry the same client ids) and later lines (the shutdown and the next session) are counted as boundary discards and can neither explain nor produce a decision.
  Lines that arrive before the metadata or the anchor are held and judged once the anchor is known; nothing from before it is ever admitted.
* Lifecycle: a follower EOF after the session ended (the observer's own disconnection seen, SESSION_END read) is an orderly teardown. An EOF inside the session, a changed broker instance, a health record
  of another session, a contradictory clock, a backward broker clock jump or an exceeded buffer is a failure.
* Fail closed (`status`): nothing is explained while the anchor is unverified, the follower has failed, no health record has ARRIVED for 30 s (arrival is measured on the reader's own clock, so
  no cross-clock comparison is involved), the queried item ends beyond the last health record plus 30 s, or it ends after the session end. "Nothing explained" is the plain behaviour, never a healthy score.
"""
from bisect import bisect_left
from datetime import datetime, timezone

from family import connection as fc

HEALTH_STALE_NS = 30_000_000_000
ANCHOR_TOLERANCE_NS = 1_000_000_000
CLOCK_STEP_TOLERANCE_NS = 1_000_000_000        # the RC-1 tolerance: two consecutive health records may not disagree by more than this between their UTC and offset steps
BROKER_REORDER_NS = 60_000_000_000             # a broker line this far behind the newest one is a clock jump, not a delayed line
MAX_LINES = 2_000_000


def utc_text_ns(text):
    """'2026-11-03T01:12:38.022748Z' -> UTC epoch ns."""
    base, _, frac = text.rstrip("Z").partition(".")
    seconds = int(datetime.strptime(base, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp())
    return seconds * 1_000_000_000 + (int(frac.ljust(9, "0")[:9]) if frac else 0)


class LineAssembler:
    """Complete lines from arbitrary chunks of follower output: a partial line waits for its newline and a partial tail at EOF is dropped (and counted), so a cut line is never parsed as another event."""

    def __init__(self, max_partial=1 << 20):
        self.rest, self.max_partial, self.dropped = "", max_partial, 0

    def feed(self, chunk):
        *lines, self.rest = (self.rest + chunk).split("\n")
        if len(self.rest) > self.max_partial:
            self.rest, self.dropped = "", self.dropped + 1
        return lines

    def close(self):
        if self.rest:
            self.dropped += 1
        self.rest = ""


class ClockMap:
    """UTC -> observer offset through the observer's own (utc, offset) health points; between points linear, after the last point at unit slope (at most 30 s, see `LiveFeed.status`)."""

    def __init__(self):
        self.utc, self.offset = [], []

    def add(self, utc_ns, offset_ns):
        if self.utc and utc_ns <= self.utc[-1]:
            return
        self.utc.append(utc_ns)
        self.offset.append(offset_ns)

    def to_offset(self, utc_ns):
        if not self.utc:
            raise ValueError("no health point yet")
        i = bisect_left(self.utc, utc_ns)
        if i == 0:
            return self.offset[0] - (self.utc[0] - utc_ns)
        if i >= len(self.utc):
            return self.offset[-1] + (utc_ns - self.utc[-1])
        u0, u1, o0, o1 = self.utc[i - 1], self.utc[i], self.offset[i - 1], self.offset[i]
        return o0 + (o1 - o0) * (utc_ns - u0) // (u1 - u0)

    @property
    def last_offset(self):
        return self.offset[-1] if self.offset else None


class LiveFeed:
    """The evidence of ONE observer session as it arrives. Feed it with `broker_line`, `health_record` and `event_record` (any order); ask `status(now_ns)` and `provider(now_ns)`.
    `now_ns` and the `arrival_ns` given to `health_record` are on ONE clock of the caller (live: the reader's monotonic clock; replay: the replayed UTC). A restart rebuilds the feed by reading everything again:
    duplicate broker lines are dropped, so the result does not depend on how often a line was read."""

    def __init__(self, session_metadata, *, health_stale_ns=HEALTH_STALE_NS, anchor_tolerance_ns=ANCHOR_TOLERANCE_NS, max_lines=MAX_LINES):
        self.identities = {d["device"]: (d["client_id"], d["username"]) for d in session_metadata["registry"]["devices"]}
        self.observer = session_metadata["observer_identity"]
        self.session_id = session_metadata.get("observer_session_id")
        self.stale_ns, self.anchor_tolerance_ns, self.max_lines = health_stale_ns, anchor_tolerance_ns, max_lines
        self.raw_events, self.clock, self.deliveries = [], ClockMap(), {}
        self.seen_lines = set()
        self.newest_line_ns = None
        self.connack_utc_ns = None
        self.last_health_arrival_ns = None
        self.session_ended = False
        self.session_end_utc_ns = None
        self.session_end_offset_ns = None
        self.failure = None
        self.follower_eof = None
        self.broker_instance = None
        self.duplicate_lines = 0
        self._cache = None

    # ---------------------------------------------------------------- input
    def broker_line(self, line):
        stripped = line.strip()
        if stripped in self.seen_lines:
            self.duplicate_lines += 1
            return
        events = fc.parse_broker_log(line)
        if not events:
            return
        if len(self.seen_lines) >= self.max_lines:
            self.follower_failed("BUFFER_EXCEEDED")
            return
        self.seen_lines.add(stripped)
        for event in events:
            if self.newest_line_ns is not None and event.t_ns < self.newest_line_ns - BROKER_REORDER_NS:
                self.follower_failed("BROKER_CLOCK_JUMP")
            self.newest_line_ns = max(self.newest_line_ns or event.t_ns, event.t_ns)
        self.raw_events.extend(events)
        self._cache = None

    def health_record(self, record, arrival_ns):
        if self.session_id is not None and record.get("observer_session_id") not in (None, self.session_id):
            self.follower_failed("HEALTH_OF_ANOTHER_SESSION")
            return
        if self.session_ended:
            return                                    # nothing after the authoritative end of the session changes it
        utc, offset = utc_text_ns(record["utc"]), record["offset_ns"]
        if self.clock.utc:
            d_utc, d_offset = utc - self.clock.utc[-1], offset - self.clock.offset[-1]
            if d_offset == 0 and d_utc == 0:
                self.last_health_arrival_ns = arrival_ns
                return                                # the same record read again
            if d_offset <= 0 or abs(d_utc - d_offset) > CLOCK_STEP_TOLERANCE_NS:
                self.follower_failed("CLOCK_CONTRADICTION")
                return
        self.clock.add(utc, offset)
        self.last_health_arrival_ns = arrival_ns
        if record.get("kind") == "CONNACK" and (record.get("details") or {}).get("client_id") == self.observer and self.connack_utc_ns is None:
            self.connack_utc_ns = utc
        if record.get("kind") == "SESSION_END":
            self.session_ended, self.session_end_utc_ns, self.session_end_offset_ns = True, utc, offset
        self._cache = None

    def event_record(self, record):
        if record.get("binding_status") == "BOUND" and record.get("disposition") == "COUNTED":
            self.deliveries.setdefault(record["bound_device"], []).append(record["receive_offset_ns"])

    def follower_started(self, broker_instance):
        """The identity of the broker container being followed. A follower restart on the SAME instance is fine (duplicates are dropped); another instance inside a session is a failure."""
        if self.broker_instance is not None and broker_instance != self.broker_instance:
            self.follower_failed("BROKER_INSTANCE_CHANGED")
        self.broker_instance = broker_instance
        self.follower_eof = None

    def follower_stopped(self, reason):
        """The log follower ended. It is judged by `status`: orderly only after the session has ended, so an EOF read a little before the SESSION_END record stays fail-closed until that record arrives."""
        self.follower_eof = str(reason)

    def follower_failed(self, reason):
        self.failure = self.failure or str(reason)

    # ---------------------------------------------------------------- session domain
    def _observer_lines(self):
        return [e.t_ns for e in self.raw_events if e.kind == "CONNECTED" and e.client_id == self.observer]

    def anchor(self):
        """(verified, error_ns): the broker's own CONNECTED line of the observer's client id nearest to the observer's CONNACK."""
        if self.connack_utc_ns is None:
            return False, None
        lines = self._observer_lines()
        if not lines:
            return False, None
        error = min((t - self.connack_utc_ns for t in lines), key=abs)
        return abs(error) <= self.anchor_tolerance_ns, error

    def _split(self):
        """(in the session domain, before it, after it). Nothing is in the domain until the anchor is verified."""
        if self._cache is not None:
            return self._cache
        verified, error = self.anchor()
        if not verified:
            result = ([], list(self.raw_events), [])
        else:
            start = self.connack_utc_ns + error
            inside, before, after = [], [], []
            for e in self.raw_events:
                (before if e.t_ns < start else after if self.session_end_utc_ns is not None and e.t_ns > self.session_end_utc_ns else inside).append(e)
            result = (inside, before, after)
        self._cache = result
        return result

    @property
    def events(self):
        return self._split()[0]

    def boundary_discards(self):
        _, before, after = self._split()
        return dict(before_session=len(before), after_session=len(after), duplicate_lines=self.duplicate_lines)

    def _orderly_end(self):
        return self.session_ended and any(e.client_id == self.observer and e.kind in fc.OFFLINE_KINDS for e in self.raw_events)

    def lifecycle(self):
        if self.failure:
            return "FAILED"
        if self.follower_eof:
            return "ENDED_ORDERLY" if self._orderly_end() else "FOLLOWER_EOF_UNEXPLAINED"
        return "SESSION_ENDED" if self.session_ended else "RUNNING"

    # ---------------------------------------------------------------- state
    def status(self, now_ns, item_end_offset_ns=None):
        """'OK' or the reason nothing may be explained now."""
        if self.failure:
            return f"FOLLOWER_FAILED: {self.failure}"
        if self.follower_eof and not self._orderly_end():
            return f"FOLLOWER_FAILED: {self.follower_eof}"
        if not self.anchor()[0]:
            return "ANCHOR_UNVERIFIED"
        if self.last_health_arrival_ns is None or (not self.session_ended and now_ns - self.last_health_arrival_ns > self.stale_ns):
            return "HEALTH_STALE"
        if item_end_offset_ns is not None:
            if self.session_ended and item_end_offset_ns > self.session_end_offset_ns:
                return "OUTSIDE_SESSION"
            if item_end_offset_ns > self.clock.last_offset + self.stale_ns:
                return "BEYOND_HEALTH_COVERAGE"
        return "OK"

    def explainer(self, device):
        """The RC-1 `Explainer` of one device on the in-session evidence received so far (identity from the registry, clock through the health records)."""
        client_id, username = self.identities[device]
        times = sorted(self.deliveries.get(device, []))
        last = lambda t: (times[bisect_left(times, t) - 1] if bisect_left(times, t) > 0 else None)
        return fc.Explainer(self.events, client_id=client_id, username=username, to_offset=self.clock.to_offset, last_delivery_before=last)

    def outside_domain(self):
        """Decisions whose instant lies outside [0, session end] on the observer offset clock: always empty when the domain holds. The live check asserts this separately from the live/replay comparison."""
        end = self.session_end_offset_ns
        out = []
        for device in self.identities:
            for d in self.explainer(device).decisions:
                if d.t_ns < -ANCHOR_TOLERANCE_NS or (end is not None and d.t_ns > end + ANCHOR_TOLERANCE_NS):
                    out.append((device, d.outcome, d.t_ns))
        return out

    def provider(self, now_ns):
        """A `hybrid.engine.HybridBehaviorEvaluator.with_connection` provider that answers for `now_ns` and fails closed."""
        return LiveProvider(self, now_ns)


class LiveProvider:
    def __init__(self, feed, now_ns):
        self.feed, self.now_ns, self._x = feed, now_ns, {}

    def _explainer(self, device):
        if device not in self.feed.identities:
            return None
        if device not in self._x:
            self._x[device] = self.feed.explainer(device)
        return self._x[device]

    def explains(self, device, start_ns, end_ns):
        if self.feed.status(self.now_ns, end_ns) != "OK":
            return False
        x = self._explainer(device)
        return bool(x and x.explains(start_ns, end_ns))

    def filter_items(self, device, items):
        items = list(items)
        if not items or self.feed.status(self.now_ns, max(i.observed_ns for i in items)) != "OK":
            return items
        x = self._explainer(device)
        return x.filter_items(items) if x else items
