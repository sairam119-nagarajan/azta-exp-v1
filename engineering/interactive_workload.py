"""DEVELOPMENT_ONLY interactive workload (Gate 6A): the perturbed-workload publisher with a runtime control channel, so an operator can START and STOP a synthetic anomaly on a chosen
device at any instant of a running simulation without restarting anything.

It is `engineering.dev_workload.DevWorkloadRunner` (ledger, acknowledgements, observer-coverage synchronisation, summary, tolerated containment) with one difference: the schedule of each
device is not fixed at construction. Every device keeps its benign workload-v2 schedule; a START command replaces that device's schedule from the current instant with the synthetic
anomaly (the same generators as the offline perturbation: rate, payload, burst, jitter, drop), a STOP command restores the benign schedule from the current instant. Schedules of the
other devices are never recomputed or touched. Messages are real QoS 1 Paho publishes on the device's own authorized telemetry topic with its own credential.

Control channel (host <-> container, inside the run directory mounted at /results): control/commands.jsonl (host appends, this process consumes complete lines), control/events.jsonl
(append-only record of every outcome with UTC and run offset) and control/status.json (atomic, at least once a second). See `engineering.attack_control`.

Enforcement is independent of this process: a contained device is only a connection the broker closed. STOP restores no permission. After a manual RESTORE by the operator the device behaves like a
real device: the next probe connection with its own credential is accepted and it resumes publishing (the attack, if still started, resumes with it). Nothing here edits broker policy.
Everything it produces is DEVELOPMENT_ONLY engineering evidence, neither calibration nor D_shadow/D_test nor detection-accuracy evidence.
"""
import collections
import copy
import hashlib
import json
import os
from pathlib import Path
import queue
import threading
import sys
import time

from engineering import attack_control as control
from engineering import dev_workload as dw
from experiments import collection_workload as v1
from experiments import collection_workload_v2 as v2

POLL_NS = 50_000_000
STATUS_NS = 1_000_000_000


def apply_segment(config, device, pairs, kind, params, start, end):
    """The offset-ordered [(offset, size)] with [start, end) replaced by the anomaly. `pairs` is the schedule the segment is applied to; offsets are run-relative nanoseconds.

    The same rules as `dev_workload.perturbed_items` for the behavioural kinds (a test keeps the two identical for window-aligned segments), but on arbitrary instants."""
    keep = [(o, s) for o, s in pairs if o < start or o >= end]
    profile = copy.deepcopy(config["devices"][device]["profile_definition"])
    run_id = config["run_id"]
    if kind in ("rate", "jitter", "payload"):
        if kind == "rate":
            profile["nominal_gap_ns"] = round(profile["nominal_gap_ns"] / params["factor"])
        elif kind == "jitter":
            profile["jitter_fraction"] = params["fraction"]
        else:
            profile["payload"] = params["definition"]
        altered = copy.deepcopy(config)
        altered["devices"][device]["profile_definition"] = profile
        if profile["payload"]["kind"] != "fixed" and altered["devices"][device]["size_seed"] is None:
            altered["devices"][device]["size_seed"] = int(hashlib.sha256(f"dev-size|{run_id}|{device}".encode("utf-8")).hexdigest()[:16], 16)
        inside = [(o, s) for _, o, s in v2.schedule(altered, device) if start <= o < end]
    elif kind == "silence":                               # complete suppression (stabilization R1): connected, authenticated, publishing nothing
        inside = []
    elif kind == "drop":
        rng = dw._rng(run_id, device, "drop")
        inside = [(o, s) for o, s in pairs if start <= o < end and rng.random() >= params["probability"]]
    elif kind == "burst":
        group = params["group"]
        altered = copy.deepcopy(config)
        altered["devices"][device]["profile_definition"]["nominal_gap_ns"] = profile["nominal_gap_ns"] * group
        inside = [(o + k * dw.BURST_SPACING_NS, s) for _, o, s in v2.schedule(altered, device) if start <= o < end for k in range(group)]
    else:
        raise control.ControlRefused(f"unsupported anomaly kind {kind!r}")
    return sorted(keep + inside)


def device_pairs(config, device, base, segments):
    """The device's complete schedule under the given anomaly segments (each {kind, params, start, end}); with no segment it is the benign v2 schedule."""
    pairs = [(o, s) for _, o, s in base]
    for segment in segments:
        pairs = apply_segment(config, device, pairs, segment["kind"], segment["params"], segment["start"], segment["end"])
    return pairs


class ControlIO:
    """The control channel's file I/O on a background thread, so that the publish loop never waits on it (Gate 6C, defect F2).

    On the Docker Desktop Windows bind mount, opening and reading `commands.jsonl` costs a median of 9.8 ms (p95 15 ms, max 174 ms) and replacing `status.json` a median of 23 ms (against 0.3 and 1.1 ms
    on container-local storage). Done inside the loop every 50 ms and every second, that blocked the loop about 20 percent of the time and made 10 to 17 percent of all messages more than 5 ms late. The
    thread does exactly the reads and writes the loop did, in the same order: it appends the complete new lines of the command file to `lines` (a thread-safe queue the loop drains without I/O), and writes
    what the loop queues in `outbox` (event lines, status files) in order. Nothing is reordered, dropped or buffered past `close()`, which drains the outbox and joins before the caller closes the files."""

    def __init__(self, commands, events_stream, status_path, *, poll_s):
        self.commands, self.events, self.status = Path(commands), events_stream, Path(status_path)
        self.lines, self.outbox = queue.SimpleQueue(), queue.SimpleQueue()
        self.pos, self.tail, self.poll_s = 0, b"", poll_s
        self._stop = threading.Event()
        self.failure = None
        self._thread = threading.Thread(target=self._run, name="control-io", daemon=True)
        self._thread.start()

    def _read(self):
        try:
            with open(self.commands, "rb") as stream:
                stream.seek(self.pos)
                data = self.tail + stream.read()
                self.pos += len(data) - len(self.tail)
        except OSError:
            return
        *complete, self.tail = data.split(b"\n")
        for line in complete:
            if line.strip():
                self.lines.put(line)

    def _write(self):
        while True:
            try:
                kind, payload = self.outbox.get_nowait()
            except queue.Empty:
                return
            try:
                if kind == "event":
                    self.events.write(payload)
                    self.events.flush()
                else:
                    temporary = self.status.with_name(self.status.name + ".tmp")
                    temporary.write_text(payload, encoding="utf-8")
                    if control.replace_status(temporary, self.status):   # bounded retry of a host reader's transient lock; visible when it happened
                        print(f"STATUS_REPLACE_RETRIED {self.status}", file=sys.stderr, flush=True)
            except OSError as exc:                      # recorded, never silent; the loop reads `failure` and stops the run
                self.failure = self.failure or f"control_io_{type(exc).__name__}"

    def _run(self):
        while not self._stop.is_set():
            self._read()
            self._write()
            self._stop.wait(self.poll_s)
        self._write()

    def close(self):
        self._stop.set()
        self._thread.join(timeout=30)
        self._write()                                   # anything queued after the thread's last pass (it is idle now, so this is the only writer)


class InteractiveRunner(dw.DevWorkloadRunner):
    def __init__(self, *, control_dir, control_io_thread=False, **kwargs):
        super().__init__(**kwargs)
        self.control = Path(control_dir)
        self.control.mkdir(parents=True, exist_ok=True)
        self.commands = self.control / "commands.jsonl"
        self.commands.touch()
        self.events = (self.control / "events.jsonl").open("x", encoding="utf-8", newline="\n")
        self.base = {d: list(self.schedules[d]) for d in self.devices}
        self.end_ns = v2.publishing_end_ns(self.config) + 1
        self.segments = {d: [] for d in self.devices}
        self.active = {}
        self.tails = {d: collections.deque((o, s) for _, o, s in self.base[d]) for d in self.devices}
        self.sent = {d: [] for d in self.devices}
        self.acked = {d: 0 for d in self.devices}
        self.command_log, self.resumed, self.seen = [], [], set()
        self.cmd_pos, self.cmd_tail, self.next_poll, self.next_status = 0, b"", 0, 0
        self.metadata["interactive_control"] = dict(control_dir="control", anomalies=sorted(control.CATALOGUE), note="schedules change at runtime; planned_messages equals the messages actually scheduled")
        self.io = ControlIO(self.commands, self.events, self.control / "status.json", poll_s=POLL_NS / 1e9) if control_io_thread else None
        self.metadata["interactive_control"]["control_io"] = "thread" if control_io_thread else "inline"

    # ------------------------------------------------------------------------------------------------------------------------------ records
    def _event(self, kind, **fields):
        now = self.clock() if self.mono_coverage is not None else None
        row = dict(schema=control.EVENT_SCHEMA, kind=kind, utc=self.utc(), utc_ns=self.wall(), offset_ns=None if now is None else self._offset(now), **fields)
        text = json.dumps(row, sort_keys=True) + "\n"
        if self.io is not None:
            self.io.outbox.put(("event", text))
            return row
        self.events.write(text)
        self.events.flush()
        return row

    def _device_state(self, device):
        return "CONTAINED" if device in self.contained else "ATTACK" if device in self.active else "LEGITIMATE"

    def _connected(self, device):
        """The publisher's own MQTT connection state at this instant (None before it exists), recorded rather than assumed from a running process."""
        publisher = self.publishers.get(device)
        return None if publisher is None or device in self.contained else bool(getattr(publisher, "connected", False))

    def _status(self, phase):
        devices = {}
        for device in self.devices:
            spec, active = self.config["devices"][device], self.active.get(device)
            devices[device] = dict(profile=spec["profile"], username=spec["username"], topic=spec["telemetry_topic"], state=self._device_state(device),
                                   contained=device in self.contained, mqtt_connected=self._connected(device), sent=len(self.sent[device]), acked=self.acked[device],
                                   attack=None if not active else dict(anomaly=active["anomaly"], params=active["shown"], started_utc=active["utc"], started_offset_ns=active["start"],
                                                                      command_id=active["command_id"]))
        data = dict(schema=control.STATUS_SCHEMA, run_id=self.run_id, phase=phase, utc=self.utc(), offset_ns=0 if self.mono_coverage is None else self._offset(),
                    anomalies=sorted(control.CATALOGUE), devices=devices)
        if self.io is not None:
            self.io.outbox.put(("status", json.dumps(data, sort_keys=True)))
            return
        temporary = self.control / "status.json.tmp"
        temporary.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
        control.replace_status(temporary, self.control / "status.json")        # bounded retry of a host reader's transient lock; persistent denial still raises

    def _maybe_status(self, force=False):
        now = self.clock()
        if force or now >= self.next_status:
            self.next_status = now + STATUS_NS
            self._status("RUNNING")

    # ------------------------------------------------------------------------------------------------------------------------------ commands
    def _poll_commands(self):
        now = self.clock()
        if now < self.next_poll:
            return
        self.next_poll = now + POLL_NS
        if self.io is not None:                         # the thread already read the file: draining an in-memory queue costs no I/O
            if self.io.failure:
                self.failure = self.failure or self.io.failure
            while True:
                try:
                    line = self.io.lines.get_nowait()
                except queue.Empty:
                    return
                self._handle(line)
        try:
            with open(self.commands, "rb") as stream:
                stream.seek(self.cmd_pos)
                data = self.cmd_tail + stream.read()
                self.cmd_pos += len(data) - len(self.cmd_tail)
        except OSError:
            return
        *lines, self.cmd_tail = data.split(b"\n")
        for line in lines:
            if line.strip():
                self._handle(line)

    def _reject(self, command, reason):
        self.command_log.append(dict(command_id=command.get("command_id"), action=command.get("action"), device=command.get("device"), outcome="REJECTED", reason=reason))
        self._event("COMMAND_REJECTED", command_id=command.get("command_id"), action=command.get("action"), device=command.get("device"), reason=reason)

    def _handle(self, line):
        try:
            command = json.loads(line)
            assert isinstance(command, dict) and command.get("schema") == control.COMMAND_SCHEMA and command.get("action") in control.ACTIONS
            command_id, device = command["command_id"], command["device"]
            assert isinstance(command_id, str) and isinstance(device, str)
        except (ValueError, AssertionError, KeyError):
            self._event("COMMAND_REJECTED", command_id=None, action=None, device=None, reason="MALFORMED_COMMAND")
            return
        if command_id in self.seen:
            return self._reject(command, "DUPLICATE_COMMAND_ID")
        self.seen.add(command_id)
        if device not in self.devices:
            return self._reject(command, f"UNKNOWN_DEVICE:{device}")
        t = self._offset()
        if command["action"] == "start":
            if device in self.active:
                return self._reject(command, f"ATTACK_ALREADY_ACTIVE:{self.active[device]['anomaly']}")
            try:
                kind, dev_params, shown = control.normalize(command.get("anomaly"), command.get("params"))
                dw.validate_spec(dict(schema=dw.SPEC_SCHEMA, label=dw.LABEL, run_id=self.run_id,
                                      devices={device: dict(kind=kind, params=dev_params, first_window=1, last_window=1)}), self.config)
            except (control.ControlRefused, dw.PerturbationRefused) as exc:
                return self._reject(command, f"INVALID_ANOMALY:{exc}")
            segment = dict(kind=kind, params=dev_params, start=t, end=self.end_ns, anomaly=kind, shown=shown, command_id=command_id, utc=self.utc())
            self.segments[device].append(segment)
            self.active[device] = segment
            self._rebuild(device, t)
            row = self._event("COMMAND_APPLIED", command_id=command_id, action="start", device=device, anomaly=kind, params=shown, operator_ref=command.get("operator_ref"),
                              requested_utc=command.get("requested_utc"), device_state=self._device_state(device), mqtt_connected=self._connected(device))
            self._event("ATTACK_STARTED", command_id=command_id, device=device, anomaly=kind, params=shown)
        else:
            segment = self.active.pop(device, None)
            if segment is None:
                return self._reject(command, "NO_ACTIVE_ATTACK")
            segment["end"] = t
            self._rebuild(device, t)
            row = self._event("COMMAND_APPLIED", command_id=command_id, action="stop", device=device, anomaly=segment["anomaly"], params=segment["shown"],
                              operator_ref=command.get("operator_ref"), requested_utc=command.get("requested_utc"), device_state=self._device_state(device), mqtt_connected=self._connected(device))
            self._event("ATTACK_STOPPED", command_id=command_id, device=device, anomaly=segment["anomaly"])
        self.command_log.append(dict(command_id=command_id, action=command["action"], device=device, outcome="APPLIED", offset_ns=row["offset_ns"], utc=row["utc"]))
        self._maybe_status(force=True)

    def _rebuild(self, device, t):
        """Only `device`'s tail changes: unsent items already due stay, everything from `t` on is recomputed under the device's segments. A contained device has no tail."""
        if device in self.contained:
            self.tails[device] = collections.deque()
            return
        due = [x for x in self.tails[device] if x[0] < t]
        future = [(o, s) for o, s in device_pairs(self.config, device, self.base[device], self.segments[device]) if o >= t]
        self.tails[device] = collections.deque(due + future)

    # ------------------------------------------------------------------------------------------------------------------------------ containment and resumption
    def _contain(self, device, reason):
        if device in self.contained:
            return
        super()._contain(device, reason)
        self.tails[device] = collections.deque()
        self._event("DEVICE_CONTAINED", device=device, reason=reason)

    def _pump(self, until_ns):
        while True:
            now = self.clock()
            if now >= until_ns:
                return
            live = {d: p for d, p in self.publishers.items() if d not in self.contained}
            if live:
                share = min(v1.LOOP_SLICE_S, (until_ns - now) / 1e9 / len(live))
                for device, publisher in live.items():
                    if publisher.loop(max(0.0, share)) != 0 or not publisher.connected:
                        self._contain(device, "connection_closed_by_broker")
            else:
                self.idle(min(0.02, (until_ns - now) / 1e9))
            self._effect_probes()

    def _make_publisher(self, device):
        spec = self.config["devices"][device]
        return self.publisher_factory(
            spec["username"], lambda mid, reason, d=device: self._ack(d, mid, reason),
            lambda kind, d=device, **fields: self.lifecycle.append(dict(device=d, kind=kind, **{k: v for k, v in fields.items() if k in ("reason_code", "intentional", "server_disconnect_packet")})))

    def _effect_probes(self):
        """A contained device keeps trying to connect with its OWN credential (200 ms for 30 s, then every second), as a real device would. The broker's answer is the independent effect
        observation: CONNACK 135 = the containment is in effect. CONNACK 0 only follows an explicit administrative RESTORE; the accepted connection then becomes the device's publisher and the
        legitimate schedule resumes from that instant (the earlier messages are not replayed)."""
        for device, info in list(self.contained.items()):
            now = self.clock()
            if now < self.next_probe.get(device, 0):
                continue
            self.next_probe[device] = now + (200_000_000 if now - info["mono_ns"] < 30_000_000_000 else 1_000_000_000)
            started, started_utc, fresh = now, self.utc(), None
            try:
                fresh = self._make_publisher(device)
                code = fresh.connect(1)
            except Exception as exc:                                     # a probe must never stop the run
                code = f"error:{type(exc).__name__}"
            ended = self.clock()
            self._ledger(device, record_type="EFFECT_PROBE", connack=code, start_offset_ns=self._offset(started), end_offset_ns=self._offset(ended), start_utc=started_utc,
                         end_utc=self.utc(), start_monotonic_ns=started, end_monotonic_ns=ended)
            if code == 0:
                self._resume(device, fresh, info)
            elif fresh is not None:
                try:
                    fresh.close()
                except Exception:
                    pass

    def _resume(self, device, publisher, info):
        now = self.clock()
        self.publishers[device] = publisher
        del self.contained[device]
        self.next_probe.pop(device, None)
        self.pending[device].clear()
        self.resumed.append(dict(device=device, contained_utc=info["utc"], contained_offset_ns=info["offset_ns"], resumed_offset_ns=self._offset(now), resumed_utc=self.utc()))
        self._ledger(device, record_type="RESUMED", offset_ns=self._offset(now), monotonic_ns=now, utc=self.utc())
        self._rebuild(device, self._offset(now))
        self._event("DEVICE_RESUMED", device=device, attack_active=device in self.active)

    def _ack(self, device, mid, reason):
        super()._ack(device, mid, reason)
        if reason == 0 and device not in self.contained:
            self.acked[device] += 1

    # ------------------------------------------------------------------------------------------------------------------------------ run
    def _next_due(self):
        heads = [(self.tails[d][0][0], d) for d in self.devices if d not in self.contained and self.tails[d]]
        return min(heads) if heads else None

    def _send(self, device, offset, size):
        spec = self.config["devices"][device]
        sequence = len(self.sent[device]) + 1
        data = v1.payload(self.run_id, device, sequence, size)
        attempt = self.clock()
        self._pre_publish_wall_ns = self.wall()
        mid = self.publishers[device].publish(spec["telemetry_topic"], data)
        self.sent[device].append((sequence, offset, size))
        self.messages[device][sequence] = dict(queued=mid is not None, puback_reason=None)
        if mid is not None:
            self.pending[device][mid] = sequence
        self._ledger(device, record_type="ATTEMPT", configured_username=spec["username"], configured_client_id=spec["client_id"], topic=spec["telemetry_topic"], qos=v1.PUBLISH_QOS,
                     retain=False, sequence=sequence, scheduled_offset_ns=offset, scheduled_utc=v1.epoch_ns_to_utc(self.epoch_coverage + offset), attempt_offset_ns=self._offset(attempt),
                     attempt_monotonic_ns=attempt, attempt_utc=self.utc(), payload_bytes=len(data), payload_sha256=hashlib.sha256(data).hexdigest(), mqtt_mid=mid,
                     queued=mid is not None, outcome="queued" if mid is not None else "enqueue_failed", under_attack=device in self.active)
        if mid is None:
            self._contain(device, "enqueue_failed")

    def run(self):
        state = "INCOMPLETE"
        try:
            self.coverage = self._wait_coverage()
            self.epoch_coverage = v1.utc_to_epoch_ns(self.coverage["coverage_start_utc"])
            self.mono_coverage = self.clock() - (self.wall() - self.epoch_coverage)
            for device in self.devices:
                spec = self.config["devices"][device]
                if spec["username"] != spec["client_id"]:
                    raise v1.WorkloadError("bound client id must equal the registered username")
                publisher = self._make_publisher(device)
                self.publishers[device] = publisher
                if publisher.connect(3) != 0:
                    raise v1.WorkloadError("publisher_authentication_rejected")
            first = self._next_due()
            if first is None:
                raise v1.WorkloadError("empty_schedule")
            if self._offset() >= first[0]:
                raise v1.WorkloadError("coverage_detected_too_late")
            self._event("RUNNER_STARTED", devices=self.devices, anomalies=sorted(control.CATALOGUE))
            self._maybe_status(force=True)
            while not self.failure:
                self._poll_commands()
                self._maybe_status()
                due = self._next_due()
                if due is None:
                    # every device is contained (keep probing), or an anomaly with nothing to send is active (a silence: keep the connection alive and keep reading commands, so its
                    # STOP is applied and the benign schedule resumes; stb-l01/stb-l02 found the shard ending at the silence start), until the planned end of the simulation
                    if (self.contained or self.active) and self.clock() < self.mono_coverage + v2.publishing_end_ns(self.config):
                        self._pump(self.clock() + POLL_NS)
                        continue
                    break
                offset, device = due
                now = self.clock()
                if now < self.mono_coverage + offset:
                    self._pump(min(self.mono_coverage + offset, now + POLL_NS))
                    continue
                offset, size = self.tails[device].popleft()
                if device not in self.contained:
                    self._send(device, offset, size)
            deadline = self.clock() + self.ack_timeout_ns
            while any(self.pending[d] for d in self.devices if d not in self.contained) and self.clock() < deadline and not self.failure:
                self._pump(min(deadline, self.clock() + 10_000_000))
            if any(self.pending[d] for d in self.devices if d not in self.contained) and not self.failure:
                self.failure = "puback_timeout"
            if not self.failure:
                if self.contained:
                    self.failure = "device_contained:" + ",".join(sorted(self.contained))
                else:
                    state = "COMPLETE"
        except v1.WorkloadError as exc:
            self.failure = self.failure or str(exc)
        except Exception as exc:  # fail closed, without echoing arbitrary text
            self.failure = self.failure or f"unexpected_{type(exc).__name__}"
        finally:
            for publisher in self.publishers.values():
                try:
                    publisher.close()
                except Exception:
                    self.failure = self.failure or "shutdown_error"
                    state = "INCOMPLETE"
            for stream in self.files.values():
                stream.close()
            self.attempts.close()
        return self._finish(state)

    def _finish(self, state):
        for device in self.devices:
            self.schedules[device] = list(self.sent[device])
            self.metadata["devices"][device]["planned_messages"] = len(self.sent[device])
        self.metadata["interactive_control"].update(commands=self.command_log, resumed=self.resumed,
                                                    segments={d: [dict(anomaly=s["anomaly"], params=s["shown"], start_offset_ns=s["start"], end_offset_ns=None if s["end"] == self.end_ns else s["end"],
                                                                       command_id=s["command_id"]) for s in self.segments[d]] for d in self.devices})
        self._event("RUNNER_ENDED", state=state, failure=self.failure)
        self._status("ENDED")
        if self.io is not None:
            self.io.close()                             # drains the outbox (the last event and the final status) before the event file is closed
        self.events.close()
        return super()._finish(state)
