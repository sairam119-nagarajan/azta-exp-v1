"""Incremental, byte-exact reader of ONE unfinished observer session: the live provenance of every window.

An unfinished session has no digest-pinned artifact, so provenance is established from what CAN be verified while it runs:

  * the session is named EXPLICITLY (no discovery) and its `session_metadata.json` must agree with the declaration and the committed plan: run, purpose,
    registry, schema and configuration pins, 10 s geometry, device routes, observer rules, the collection attestation of the committed RUN_PLANNED
    entry, a clean checkout, and a start time inside the authorization and plausibly "now" (a finished or long-dead session is never followed as live);
  * `windows.jsonl` is read from byte 0, only up to its last complete line, and a rolling SHA-256 is kept over EVERY consumed byte. Each accepted
    window therefore carries `prefix_sha256`: the digest of the exact file prefix it came from. Any later change to an already consumed byte (rewrite)
    or any shrinkage (truncation) is a fatal integrity failure, and at the end the chain must equal the digest the observer itself attests in its
    `session_summary.json`. That equality is the bridge to the finalized session (`shadow_live.finalize`); it is necessary, never sufficient;
  * every complete line must be a valid Gate 5B window of THIS run, session, purpose, pins and device route (identity and registry), on THE coverage
    grid (one constant coverage start, 10 s windows). A positive nominal future lead within the declared tolerance is UNCERTAIN, not wrong (the observer's
    anchored monotonic timeline runs ahead of the host wall clock): the line is HELD, unconsumed and recorded once as WINDOW_HELD_NOMINALLY_FUTURE, until the
    nominal end has passed on this clock; a lead beyond the tolerance is the refusal WINDOW_FROM_FUTURE. Nothing is clamped, and a decision never rests on a
    future timestamp;
  * only `session_metadata.json`, `windows.jsonl` and `session_summary.json` of that session are ever opened. Events, health and ledgers are not.

Ordering, duplicates and gaps are NOT decided here: the existing streaming pipeline owns those rules. This module owns bytes, binding and time.
The UTC placement of a window is `utc_start (session metadata) + offset`, an UPPER bound of the true instant by at most the observer's own start-up
time under stable clock relationships; the declared clock tolerance is not a measured mapping and every output says which basis was used. Honest limit: this assumes the observer's output directory
is written only by the authorized observer process (an isolation property of the deployment, not cryptographic authentication).
"""
from dataclasses import dataclass, field
import hashlib
import json

from observation.schema import SESSION_ID, SHA256, validate_window
from shadow_feed import reader
from shadow_feed.stream import Arrival
from shadow_live.errors import LiveIntegrityFailure, LiveRefused
from trust.timeline import parse_utc_ns

MAX_WINDOWS_BYTES = 64 * 1024 * 1024
WINDOW_END_BASIS = "SESSION_METADATA_UTC_START_PLUS_OFFSET_UPPER_BOUND"
HOLD_CODE = "WINDOW_HELD_NOMINALLY_FUTURE"              # an EVENT, never a refusal: the line stays unconsumed until its nominal end has passed on this clock
OBSERVER_CLOCK_DOMAIN = "observer_process_monotonic_ns"


def _fail(code, message):
    raise LiveRefused(code, message)


def _fatal(code, message):
    raise LiveIntegrityFailure(code, message)


class _Unreadable(Exception):
    """An allowlisted file could not be read RIGHT NOW (a sharing violation, an antivirus lock, a share that has not caught up): the poll consumes nothing,
    records the event and the next poll retries. It is never mistaken for a missing or a changed file, and its persistence is bounded by the stall detector."""

    def __init__(self, name, error):
        super().__init__(f"{name}: {error}")
        self.name, self.error = name, error


def _error_text(exc):
    code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
    return f"{exc.__class__.__name__}:{code}" if code else exc.__class__.__name__


def _reject_constant(name):
    raise ValueError(f"non-finite JSON constant {name}")


def sha256_hex(blob):
    return hashlib.sha256(blob).hexdigest()


@dataclass(frozen=True)
class SessionFacts:
    session_id: str
    observer_identity: str
    metadata_sha256: str
    utc_start_text: str
    origin_utc_ns: int
    purpose: str
    binding_audit_ref: object
    collection_attestation: object
    git_commit: object


@dataclass(frozen=True)
class LiveLine:
    """One accepted window line and the verifiable facts about where it came from."""
    window: dict
    device: str
    index: int
    line_number: int
    byte_start: int
    byte_end: int
    line_sha256: str
    prefix_sha256: str
    arrival: Arrival
    previous_read_utc_ns: object
    read_after_session_summary: bool
    window_end_utc_ns: int


@dataclass(frozen=True)
class LineRefusal:
    code: str
    reason: str
    line_number: int
    byte_start: int
    byte_end: int
    line_sha256: str
    prefix_sha256: str
    arrival: Arrival
    device: object = None
    index: object = None


@dataclass(frozen=True)
class SummaryFacts:
    state: str
    failure_code: object
    windows_sha256: str
    metadata_sha256: str
    summary_sha256: str
    coverage_start_offset_ns: object
    coverage_end_offset_ns: object
    utc_end: object
    counters: dict
    invariants: dict


@dataclass
class PollResult:
    read: Arrival
    previous_read: object
    waiting: bool = False
    attached_now: bool = False
    facts: object = None
    items: list = field(default_factory=list)       # LiveLine | LineRefusal, in file order
    events: list = field(default_factory=list)      # non-fatal integrity events
    summary: object = None
    summary_present: bool = False                   # the observer's own summary existed BEFORE this read (so everything it covers was fully flushed)
    unconsumed_bytes: int = 0
    clock_delta: object = None                      # same-process wall/monotonic elapsed comparison; never continued across resume


class LiveWindowSource:
    def __init__(self, plan, session_id, *, clock):
        if not isinstance(session_id, str) or not SESSION_ID.fullmatch(session_id):
            _fail("SESSION_ID_INVALID", "an explicit observer session id (obs-<32 hex>) is required: sessions are never discovered")
        if session_id in plan.reserved_tokens:
            _fail("SESSION_RESERVED", "the session is reserved evidence and can never be followed")
        self.plan, self.session_id, self.clock = plan, session_id, clock
        base = f"observation/{session_id}"
        self._paths = {name: reader.safe_path(plan.evidence_root, f"{base}/{name}") for name in ("session_metadata.json", "windows.jsonl", "session_summary.json")}
        self.facts = None
        self.summary = None
        self.offset = 0
        self.line_number = 0
        self.coverage_start_offset_ns = None
        self.last_read = None
        self._hash = hashlib.sha256()
        self._last_progress_mono = None
        self._process_read = None
        self._stalled = False
        self._last_error = None                     # (file, error) of the last transient read failure, so that a repeating failure is recorded once
        self._pending_bytes = 0                     # bytes after the last complete line at the previous read, so that a partial line is recorded on change
        self._unparsed = {}                         # file -> monotonic instant of its first unparseable read (a write that may still be in progress)
        self._held = None                           # the line waiting for its nominal end: {key: (device, index), previous_read, first_read}; transient, never persisted
        self._lead_ns = 0

    # ------------------------------------------------------------------------------------------------------------- attach
    def _read(self, name):
        """The file's bytes, None when it does not exist, or `_Unreadable` when it exists but cannot be read now."""
        try:
            return self._paths[name].read_bytes()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise _Unreadable(name, _error_text(exc)) from None

    def _exists(self, name):
        try:
            return self._paths[name].exists()
        except OSError as exc:
            raise _Unreadable(name, _error_text(exc)) from None

    def _not_yet(self, name, give_up):
        """The observer writes `session_metadata.json` and `session_summary.json` in two steps (create the file, then write it: `ObservationRecords.write_json`), so a
        reader can find one EMPTY or cut off: a write in progress, retried at the next poll like an unreadable file (recorded once as NOT_PARSEABLE_YET). Content that
        stays unparseable for longer than the declared stall timeout is refused by `give_up`, which raises with the caller's own code."""
        first = self._unparsed.setdefault(name, self.clock.monotonic_ns())
        if self.clock.monotonic_ns() - first > self.plan.declaration.stall_timeout_ns:
            give_up()
        raise _Unreadable(name, "NOT_PARSEABLE_YET")

    def _validate_metadata(self, meta, blob):
        plan, d = self.plan, self.plan.declaration

        def need(condition, code, message):
            if not condition:
                _fail(code, message)
        try:
            need(meta["observer_session_id"] == self.session_id and meta["collection_run_id"] == plan.run_id, "SESSION_MISMATCH",
                 "the session belongs to another run or session id")
            need(meta["purpose"] == plan.purpose and meta["enforcement"] == "NONE", "SESSION_PURPOSE_MISMATCH",
                 f"the session purpose must be {plan.purpose} and declare enforcement NONE")
            need(meta["schema_fingerprint"] == plan.schema_fingerprint and meta["observation_config_sha256"] == plan.observation_config_sha256
                 and meta["registry_sha256"] == plan.registry_sha256, "SESSION_PINS_MISMATCH", "registry, schema or configuration pins differ from the plan")
            need(meta["window_duration_ns"] == plan.window_ns and meta["window_count"] == plan.planned_window_count, "SESSION_GEOMETRY_MISMATCH",
                 "the window duration or count differs from the plan")
            need(meta["clock_domain"] == OBSERVER_CLOCK_DOMAIN, "SESSION_CLOCK_DOMAIN", "unexpected observer clock domain")
            registry = {e["device"]: e for e in meta["registry"]["devices"]}
            need(set(registry) == set(plan.devices) and all(registry[dev]["username"] == route["username"] and registry[dev]["client_id"] == route["client_id"]
                                                              and registry[dev]["telemetry_topic"] == route["telemetry_topic"]
                                                              for dev, route in plan.devices.items()),
                 "SESSION_DEVICES_MISMATCH", "the observer registry differs from the planned device routes")
            identity = meta["observer_identity"]
            if identity == reader.OBSERVER_IDENTITY:
                need(d.allow_legacy_observer, "OBSERVER_NOT_ALLOWED", "observed by the legacy azta-pdp subscriber; the declaration must allow it explicitly")
                need(set(registry) <= reader.LEGACY_OBSERVER_DEVICES, "OBSERVER_NOT_ALLOWED", "the legacy subscriber cannot serve a wider registry")
            else:
                need(isinstance(identity, str) and reader.DEDICATED_OBSERVER.fullmatch(identity), "OBSERVER_NOT_ALLOWED", "unknown observer identity")
            audit_ref = meta["binding_audit_ref"]
            if plan.purpose == "COLLECTION":
                attestation = meta["collection_attestation"]
                need(isinstance(attestation, dict) and attestation.get("planned_entry_sha256") == plan.planned_entry_sha256
                     and attestation.get("manifest_sha256") is not None
                     and meta["runtime"]["git_state"] == "clean" and audit_ref == f"{plan.run_id}-audit-pre", "ATTESTATION_MISMATCH",
                     "the collection attestation, checkout state or audit reference does not match the committed RUN_PLANNED entry")
            else:
                attestation = None
                need(meta["collection_attestation"] is None and audit_ref in (None, f"{plan.run_id}-audit-pre"), "ATTESTATION_MISMATCH",
                     "a functional session carries no attestation; its audit reference must be the run's pre audit or absent")
            origin = parse_utc_ns(meta["utc_start"])
            git_commit = (meta.get("runtime") or {}).get("git_commit")
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, LiveRefused):
                raise
            _fail("SESSION_METADATA_INVALID", f"session_metadata.json is malformed ({type(exc).__name__})")
        return SessionFacts(self.session_id, identity, sha256_hex(blob), meta["utc_start"], origin, plan.purpose, audit_ref, attestation, git_commit)

    def attach(self, *, resuming=False):
        """The verified session facts, or None while the observer has not created the session yet. Idempotent once attached."""
        if self.facts is not None:
            return self.facts
        blob = self._read("session_metadata.json")
        if blob is None:
            return None
        try:
            meta = json.loads(blob.decode("utf-8"), parse_constant=_reject_constant)
        except (UnicodeDecodeError, ValueError):
            self._not_yet("session_metadata.json", lambda: _fail("SESSION_METADATA_INVALID", "session_metadata.json is not valid JSON"))
        self._unparsed.pop("session_metadata.json", None)
        facts = self._validate_metadata(meta, blob)
        now, d = self.clock.utc_ns(), self.plan.declaration
        if not resuming:
            if self._exists("session_summary.json"):
                _fail("SESSION_ALREADY_FINISHED", "the observer session already ended: a finished session is replayed by the manifest-verified reader, "
                                                  "never followed as live")
            span = self.plan.planned_window_count * self.plan.window_ns + d.stall_timeout_ns + d.clock_tolerance_ns
            if facts.origin_utc_ns - now > d.clock_tolerance_ns:
                _fail("SESSION_FROM_FUTURE", "the session claims to have started in the future of this host's clock")
            if now - facts.origin_utc_ns > span:
                _fail("SESSION_NOT_LIVE", "the session started too long ago to still be running: it is not followed as live")
        if not d.valid_from_ns <= facts.origin_utc_ns <= d.valid_until_ns:
            _fail("SESSION_OUTSIDE_AUTHORIZATION", "the session started outside the interval the declaration authorizes")
        self.facts = facts
        self._last_progress_mono = self.clock.monotonic_ns()
        return facts

    # ----------------------------------------------------------------------------------------------------------- resumption
    def progress(self):
        return dict(offset=self.offset, prefix_sha256=self._hash.hexdigest(), line_number=self.line_number,
                    coverage_start_offset_ns=self.coverage_start_offset_ns, metadata_sha256=self.facts.metadata_sha256 if self.facts else None,
                    last_read_utc_ns=self.last_read.utc_ns if self.last_read else None,
                    last_read_mono_ns=self.last_read.mono_ns if self.last_read else None)

    def resume(self, progress):
        """Continue after a restart from a recorded progress, after proving that every consumed byte is still exactly what was consumed."""
        try:
            facts = self.attach(resuming=True)
            blob = self._read("windows.jsonl") if progress["offset"] else None
        except _Unreadable as exc:
            _fail("SOURCE_UNREADABLE", f"{exc.name} cannot be read right now ({exc.error}); the resume is refused and may be retried")
        if facts is None or facts.metadata_sha256 != progress["metadata_sha256"]:
            _fatal("SOURCE_METADATA_CHANGED", "the session metadata is missing or differs from the attached session")
        if progress["offset"]:
            if blob is None or len(blob) < progress["offset"]:
                _fatal("SOURCE_TRUNCATED", "the window file is shorter than what was consumed before the restart")
            if sha256_hex(blob[:progress["offset"]]) != progress["prefix_sha256"]:
                _fatal("SOURCE_REWRITTEN", "bytes consumed before the restart changed")
            self._hash = hashlib.sha256(blob[:progress["offset"]])
        self.offset, self.line_number = progress["offset"], progress["line_number"]
        self.coverage_start_offset_ns = progress["coverage_start_offset_ns"]
        if progress["last_read_utc_ns"] is not None:
            self.last_read = Arrival(progress["last_read_utc_ns"], progress["last_read_mono_ns"])

    # --------------------------------------------------------------------------------------------------------------- polling
    def _check_line(self, raw, arrival, summary_exists):
        """(window, None) or (None, (code, reason, device, index)). Source-level rules only; ordering and duplicates belong to the pipeline.

        `summary_exists`: the observer's own summary was present before this read, so the session is over. An observer that failed flushes placeholder windows
        for the REST of the grid at shutdown (coverage NONE or PARTIAL, nominal times still ahead of the clock); once the session is over those are the
        observer's own statement "not covered" and are accepted, while a COMPLETE window can never be ahead of the clock."""
        plan, facts = self.plan, self.facts
        try:
            window = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
            validate_window(window)
        except (UnicodeDecodeError, ValueError, TypeError, AttributeError, KeyError) as exc:
            return None, ("WINDOW_MALFORMED", f"not a valid observation window ({str(exc)[:100]})", None, None)
        device, index = window["device"], window["window"]["index"]
        route = plan.devices.get(device)
        if (window["collection_run_id"] != plan.run_id or window["observer_session_id"] != self.session_id or window["purpose"] != plan.purpose
                or route is None or not 0 <= index < plan.planned_window_count):
            return None, ("WINDOW_FOREIGN", "the window belongs to another run, session, purpose or device, or lies outside the planned grid", device, index)
        identity = window["identity"]
        if (identity["bound_username"] != route["username"] or identity["bound_client_id"] != route["client_id"]
                or identity["registry_sha256"] != plan.registry_sha256 or window["observation_config_sha256"] != plan.observation_config_sha256
                or identity["binding_audit_ref"] != facts.binding_audit_ref):
            return None, ("WINDOW_FOREIGN", "the window's bound identity, registry, configuration or audit reference differs from the declared route",
                          device, index)
        span = window["window"]
        coverage = span["start_offset_ns"] - index * plan.window_ns
        if span["duration_ns"] != plan.window_ns or coverage < 0 or (self.coverage_start_offset_ns is not None and coverage != self.coverage_start_offset_ns):
            return None, ("WINDOW_GRID_VIOLATION", "the window is not on the session's coverage grid (constant coverage start, fixed duration)", device, index)
        lead = facts.origin_utc_ns + span["end_offset_ns"] - arrival.utc_ns
        shutdown_flush = summary_exists and window["coverage"]["state"] != "COMPLETE"
        if lead > self.plan.declaration.clock_tolerance_ns and not shutdown_flush:
            return None, ("WINDOW_FROM_FUTURE", f"the window ends {lead} ns after the instant it was read (a window cannot be seen before it ended)",
                          device, index)
        if lead > 0 and not shutdown_flush:
            # Inside the declared tolerance the nominal end is uncertain, not wrong: the observer's anchored monotonic timeline runs measurably ahead of the host
            # wall clock (about 63 ppm in g5f-lv01), so a genuine window can be read a few milliseconds "before" its nominal end. The line is NOT consumed: it
            # waits (bounded by the tolerance, since the lead shrinks with real time) until the nominal end has passed on THIS clock, so no decision ever rests on a
            # future timestamp and nothing is clamped or lost. A lead beyond the tolerance stays the refusal above.
            self._lead_ns = lead
            return None, (HOLD_CODE, f"the nominal window end is {lead} ns after the read, inside the declared clock tolerance: held, not decided", device, index)
        return window, None

    def _read_summary(self):
        blob = self._read("session_summary.json")
        if blob is None:
            return None
        plan = self.plan
        try:
            summary = json.loads(blob.decode("utf-8"), parse_constant=_reject_constant)
        except (UnicodeDecodeError, ValueError) as exc:
            self._not_yet("session_summary.json", lambda: _fatal("SUMMARY_INVALID", f"session_summary.json is malformed ({str(exc)[:100]})"))
        self._unparsed.pop("session_summary.json", None)
        try:
            artifacts = summary["artifact_sha256"]
            if not (summary["observer_session_id"] == self.session_id and summary["purpose"] == plan.purpose and summary["enforcement"] == "NONE"
                    and summary["schema_fingerprint"] == plan.schema_fingerprint and summary["observation_config_sha256"] == plan.observation_config_sha256
                    and summary["state"] in ("COMPLETE", "INCOMPLETE") and SHA256.fullmatch(artifacts["windows.jsonl"])
                    and artifacts["session_metadata.json"] == self.facts.metadata_sha256):
                raise ValueError("the observer's summary does not belong to the attached session")
            return SummaryFacts(summary["state"], summary["failure_code"], artifacts["windows.jsonl"], artifacts["session_metadata.json"], sha256_hex(blob),
                                summary.get("coverage_start_offset_ns"), summary.get("coverage_end_offset_ns"), summary.get("utc_end"),
                                dict(summary.get("counters") or {}), dict(summary.get("invariants") or {}))
        except (UnicodeDecodeError, ValueError, KeyError, TypeError) as exc:
            _fatal("SUMMARY_INVALID", f"session_summary.json is malformed or belongs to another session ({str(exc)[:100]})")

    def poll(self):
        arrival = Arrival(self.clock.utc_ns(), self.clock.monotonic_ns())
        result = PollResult(read=arrival, previous_read=self.last_read)
        try:
            self._poll(arrival, result)
            self._last_error = None
        except _Unreadable as exc:                                       # nothing further is consumed in this poll; the next one retries
            if (exc.name, exc.error) != self._last_error:
                result.events.append(dict(kind="SOURCE_READ_ERROR", file=exc.name, error=exc.error))
            self._last_error = (exc.name, exc.error)
        arrival = result.read
        if self.last_read is not None and arrival.utc_ns < self.last_read.utc_ns:
            result.events.append(dict(kind="CLOCK_STEPPED_BACK", step_ns=arrival.utc_ns - self.last_read.utc_ns))
        if self._process_read is not None:
            wall_elapsed = arrival.utc_ns - self._process_read.utc_ns
            mono_elapsed = arrival.mono_ns - self._process_read.mono_ns
            result.clock_delta = dict(wall_elapsed_ns=wall_elapsed, monotonic_elapsed_ns=mono_elapsed,
                                     wall_minus_monotonic_elapsed_ns=wall_elapsed - mono_elapsed,
                                     domain="CURRENT_ADAPTER_PROCESS_ONLY")
        self._process_read = arrival
        if (self.facts is not None and self.summary is None and not result.items and not result.summary_present and not self._stalled
                and arrival.mono_ns - self._last_progress_mono > self.plan.declaration.stall_timeout_ns):
            self._stalled = True
            result.events.append(dict(kind="SOURCE_STALLED", silent_ns=arrival.mono_ns - self._last_progress_mono))
        self.last_read = arrival
        return result

    def _poll(self, arrival, result):
        if self.facts is None:
            if self.attach() is None:
                result.waiting = True
                return
            result.attached_now = True
        result.facts = self.facts
        if self.summary is not None:         # the session already ended and was handled: nothing further is read
            return
        metadata = self._read("session_metadata.json")
        if metadata is None or sha256_hex(metadata) != self.facts.metadata_sha256:
            _fatal("SOURCE_METADATA_CHANGED", "the session metadata disappeared or changed after the session was attached")
        summary_before = result.summary_present = self._exists("session_summary.json")      # checked BEFORE the read: everything it covers is then fully flushed
        blob = self._read("windows.jsonl")
        arrival = result.read = Arrival(self.clock.utc_ns(), self.clock.monotonic_ns())  # feature readiness is AFTER the read, before validation/submission
        if blob is None:
            if self.offset:
                _fatal("SOURCE_TRUNCATED", "the window file disappeared after it was consumed")
            blob = b""
        if len(blob) > MAX_WINDOWS_BYTES:
            _fatal("SOURCE_TOO_LARGE", "the window file exceeds the safety limit")
        if len(blob) < self.offset:
            _fatal("SOURCE_TRUNCATED", "the window file is shorter than what was already consumed")
        if self.offset and sha256_hex(blob[:self.offset]) != self._hash.hexdigest():
            _fatal("SOURCE_REWRITTEN", "bytes that were already consumed changed")
        fresh = blob[self.offset:]
        complete = fresh[:fresh.rfind(b"\n") + 1]
        position = self.offset
        held = None
        for raw in complete.splitlines(keepends=True):
            window, refusal = self._check_line(raw, arrival, summary_before)
            if refusal is not None and refusal[0] == HOLD_CODE:         # not consumed: no hash update, no line number, the position stays at its first byte
                held = (refusal[2], refusal[3])
                break
            self._hash.update(raw)
            self.line_number += 1
            start, position = position, position + len(raw)
            common = dict(line_number=self.line_number, byte_start=start, byte_end=position, line_sha256=sha256_hex(raw), prefix_sha256=self._hash.hexdigest())
            if window is None:
                code, reason, device, index = refusal
                result.items.append(LineRefusal(code, reason, arrival=arrival, device=device, index=index, **common))
                continue
            if self.coverage_start_offset_ns is None:
                self.coverage_start_offset_ns = window["window"]["start_offset_ns"] - window["window"]["index"] * self.plan.window_ns
            previous = self.last_read
            if self._held is not None and position <= self._held["visible_end"]:
                previous = self._held["previous_read"]                      # the bracket spans the hold: everything already visible at the held read was first seen after THAT read
            result.items.append(LiveLine(window, window["device"], window["window"]["index"], arrival=arrival,
                                         previous_read_utc_ns=previous.utc_ns if previous else None, read_after_session_summary=summary_before,
                                         window_end_utc_ns=self.facts.origin_utc_ns + window["window"]["end_offset_ns"], **common))
        self.offset = position
        partial_bytes = len(fresh) - len(complete)                      # a line still being written: only the bytes after the last newline
        held_bytes = len(complete) - (position - (len(blob) - len(fresh)))
        result.unconsumed_bytes = partial_bytes + held_bytes
        if partial_bytes != self._pending_bytes:                         # direct evidence about the file-flush behaviour of the environment
            if partial_bytes:
                result.events.append(dict(kind="PARTIAL_LINE_PENDING", pending_bytes=partial_bytes))
            self._pending_bytes = partial_bytes
        if self._held is not None and position >= self._held["visible_end"]:
            self._held = None                                                # every line that was visible at the held read has now been consumed
        if held is not None:
            announce = True
            if self._held is None:
                self._held = dict(key=held, previous_read=self.last_read, visible_end=len(blob) - partial_bytes)
            elif self._held["key"] == held:
                announce = False                                             # the same line is still waiting: recorded once, not once per poll
            else:
                self._held["key"] = held                                     # the next line is now the one waiting; the older bracket still covers it
            if announce:
                result.events.append(dict(kind=HOLD_CODE, device=held[0], window_index=held[1], lead_ns=self._lead_ns,
                                          tolerance_ns=self.plan.declaration.clock_tolerance_ns, held_bytes=held_bytes))
        if result.items:
            self._last_progress_mono, self._stalled = arrival.mono_ns, False
        if summary_before and held is None:                               # a held line means the file is not yet fully consumed: the end is handled at a later poll
            self.summary = result.summary = self._read_summary()
            if self.summary is None:
                _fatal("SUMMARY_INVALID", "the observer's summary disappeared after it was seen")
            self._end_checks(result)

    def _end_checks(self, result):
        """At the end the consumed chain must be exactly the file the observer attests, and the coverage start it reports must be the one derived."""
        summary = self.summary
        if result.unconsumed_bytes:
            _fatal("FINAL_DIGEST_MISMATCH", f"{result.unconsumed_bytes} bytes of the window file were never consumed as complete lines")
        if self._hash.hexdigest() != summary.windows_sha256:
            _fatal("FINAL_DIGEST_MISMATCH", "the consumed byte chain differs from the digest the observer attests for windows.jsonl")
        if summary.coverage_start_offset_ns is not None and self.coverage_start_offset_ns not in (None, summary.coverage_start_offset_ns):
            _fatal("COVERAGE_START_MISMATCH", "the coverage start derived from the windows differs from the observer's own")
