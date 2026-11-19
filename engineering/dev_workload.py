"""DEVELOPMENT_ONLY perturbed workload publisher (calibration-readiness development, 24 October 2026). Runs ONLY inside the isolated engineering project.

It is the unchanged workload-v2 runner (ledger, acknowledgements, observer-coverage synchronisation, summary) with one difference: after construction the schedule of each device is
replaced inside a declared window segment by a perturbed one. Outside the segment the benign v2 schedule is kept, so every run carries its own benign windows before and after the
perturbation. Messages are real QoS 1 Paho publishes on the device's own authorized telemetry topic with its own credential; nothing is added to the broker policy and no topic outside the
device's entitlement is touched. The plan stays an ordinary FUNCTIONAL_TEST plan (the pinned plan machinery defines no attack workload and is not edited), and the perturbation specification is
a separate committed file named on the command line. Everything it produces is labelled DEVELOPMENT_ONLY and is neither calibration, nor D_shadow, nor D_test, nor attack-detection evidence.

Perturbation kinds (all derived from the declared profile of the device; `first_window`..`last_window` are observer window indices, 1 = first eligible):
  rate    factor            the nominal gap is divided by `factor`
  drop    probability       each message of the segment is dropped with this probability (seeded)
  payload definition        the payload rule is replaced (`fixed` bytes or `uniform_int` low/high)
  jitter  fraction          the gap jitter fraction is replaced
  burst   group             messages arrive in groups of `group`, 20 ms apart, at the unchanged mean rate
  delay   delay_ms          in every window of the segment the message nearest the middle is sent `delay_ms` late (FIFO, later messages cannot overtake)
  silence (no parameter)    complete suppression: the device stays connected and authenticated and publishes NOTHING inside the segment (stabilization R1, the liveness case)
  foreign_topic target      CONTEXT violation, not a behavioural perturbation: the benign schedule is untouched, but once per window of the segment the device ALSO attempts one
                            QoS 0 publish on `target` ("peer_telemetry": the other device's telemetry topic) through its OWN connection and credential. The broker's ACL denies it, so
                            nothing is delivered and the six behavioural features are unaffected; the only trace is the broker's denial record. Those attempts bypass the benign
                            acknowledgement ledger (a QoS 0 publish has no PUBACK) and are listed in `foreign_topic_attempts.jsonl`.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import random
import re
import sys

from experiments import collection_plan as plans
from experiments import collection_plan_v2 as plans_v2
from experiments import collection_runner_v2 as runner_v2
from experiments import collection_sessions_v2 as sessions_v2
from experiments import collection_workload as v1
from experiments import collection_workload_v2 as v2
from observation.registry import DeviceRegistry

LABEL = "DEVELOPMENT_ONLY"
KINDS = ("rate", "drop", "payload", "jitter", "burst", "delay", "foreign_topic", "silence")
VIOLATION_PAYLOAD = b"azta-pilot-context-violation"
BURST_SPACING_NS = 20_000_000
SPEC_SCHEMA = "azta.engineering.dev_perturbation"
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


class PerturbationRefused(ValueError):
    pass


def _require(condition, text):
    if not condition:
        raise PerturbationRefused(text)


def validate_spec(spec, config):
    _require(isinstance(spec, dict) and spec.get("schema") == SPEC_SCHEMA and spec.get("label") == LABEL, "specification schema or label")
    _require(spec.get("run_id") == config["run_id"], "the specification names another run")
    _require(spec.get("tolerate_containment", False) in (True, False), "tolerate_containment must be a boolean")
    devices = spec.get("devices")
    _require(isinstance(devices, dict) and set(devices) <= set(config["devices"]), "specification devices must be a subset of the run's devices")
    eligible = config["eligible_windows"]
    for device, item in devices.items():
        _require(item.get("kind") in KINDS, f"{device}: unknown kind")
        first, last = item.get("first_window"), item.get("last_window")
        _require(type(first) is int and type(last) is int and 1 <= first <= last <= eligible, f"{device}: segment must lie inside the eligible windows")
        params = item.get("params")
        _require(isinstance(params, dict), f"{device}: params")
        kind = item["kind"]
        if kind == "rate":
            _require(set(params) == {"factor"} and 0.05 <= params["factor"] <= 20, f"{device}: rate factor")
        elif kind == "drop":
            _require(set(params) == {"probability"} and 0 < params["probability"] < 1, f"{device}: drop probability")
        elif kind == "payload":
            rule = params.get("definition")
            _require(set(params) == {"definition"} and isinstance(rule, dict) and (
                (rule.get("kind") == "fixed" and set(rule) == {"kind", "bytes"} and 96 <= rule["bytes"] <= 4096) or
                (rule.get("kind") == "uniform_int" and set(rule) == {"kind", "low", "high"} and 96 <= rule["low"] <= rule["high"] <= 4096)), f"{device}: payload rule")
        elif kind == "jitter":
            _require(set(params) == {"fraction"} and 0 <= params["fraction"] < 1, f"{device}: jitter fraction")
        elif kind == "burst":
            _require(set(params) == {"group"} and type(params["group"]) is int and 2 <= params["group"] <= 20, f"{device}: burst group")
        elif kind == "foreign_topic":
            _require(params == {"target": "peer_telemetry"} and len(config["devices"]) == 2, f"{device}: foreign_topic needs target peer_telemetry in a two-device run")
        elif kind == "silence":
            _require(params == {}, f"{device}: silence takes no parameter")
        else:
            _require(set(params) == {"delay_ms"} and 1 <= params["delay_ms"] <= 5000, f"{device}: delay")
    return spec


def _rng(run_id, device, name):
    return random.Random(int(hashlib.sha256(f"dev-perturbation|{run_id}|{device}|{name}".encode("utf-8")).hexdigest()[:16], 16))


def perturbed_items(config, device, item):
    """The device's message list [(sequence, offset_ns, size)] with the declared segment perturbed; sequences are renumbered 1..n in offset order."""
    w = v2.window_ns(config)
    start, end = (config["lead_in_windows"] - 1 + item["first_window"]) * w, (config["lead_in_windows"] + item["last_window"]) * w
    base = v2.schedule(config, device)
    kind, params = item["kind"], item["params"]
    if kind == "foreign_topic":                              # a context violation: the benign schedule is not touched
        return list(base)
    profile = copy.deepcopy(config["devices"][device]["profile_definition"])
    run_id = config["run_id"]
    keep = [(o, s) for _, o, s in base if o < start or o >= end]
    inside = []
    if kind == "silence":                                    # complete suppression: nothing inside the segment
        return [(n + 1, o, s) for n, (o, s) in enumerate(sorted(keep))]
    if kind in ("rate", "jitter", "payload", "drop", "delay"):
        if kind == "rate":
            profile["nominal_gap_ns"] = round(profile["nominal_gap_ns"] / params["factor"])
        elif kind == "jitter":
            profile["jitter_fraction"] = params["fraction"]
        elif kind == "payload":
            profile["payload"] = params["definition"]
        altered = copy.deepcopy(config)
        altered["devices"][device]["profile_definition"] = profile
        if profile["payload"]["kind"] != "fixed" and altered["devices"][device]["size_seed"] is None:
            altered["devices"][device]["size_seed"] = int(hashlib.sha256(f"dev-size|{run_id}|{device}".encode("utf-8")).hexdigest()[:16], 16)
        generated = [(o, s) for _, o, s in v2.schedule(altered, device) if start <= o < end]
        if kind == "drop":
            generated = [(o, s) for o, s in [(o, s) for _, o, s in base if start <= o < end]]
            rng = _rng(run_id, device, "drop")
            generated = [(o, s) for o, s in generated if rng.random() >= params["probability"]]
        inside = generated
    else:                                                    # burst: groups at the unchanged mean rate
        group = params["group"]
        altered = copy.deepcopy(config)
        altered["devices"][device]["profile_definition"]["nominal_gap_ns"] = profile["nominal_gap_ns"] * group
        heads = [(o, s) for _, o, s in v2.schedule(altered, device) if start <= o < end]
        inside = [(o + k * BURST_SPACING_NS, s) for o, s in heads for k in range(group)]
    merged = sorted(keep + inside)
    if kind == "delay":
        delay = int(params["delay_ms"] * 1e6)
        offsets = [o for o, _ in merged]
        for window in range(config["lead_in_windows"] - 1 + item["first_window"], config["lead_in_windows"] + item["last_window"]):
            middle = (window + 0.5) * w
            inside_idx = [i for i, o in enumerate(offsets) if window * w <= o < (window + 1) * w]
            if not inside_idx:
                continue
            i = min(inside_idx, key=lambda j: abs(offsets[j] - middle))
            offsets[i] += delay
            for j in range(i + 1, len(offsets)):
                if offsets[j] > offsets[j - 1]:
                    break
                offsets[j] = offsets[j - 1] + 1
        merged = sorted(zip(offsets, [s for _, s in merged]))
    return [(n + 1, o, s) for n, (o, s) in enumerate(merged)]


class ViolationPublisher(v1.DevicePublisher):
    """The unchanged publisher plus, inside a declared segment, ONE denied QoS 0 attempt per window on a topic outside the device's entitlement (see `foreign_topic`)."""

    def __init__(self, username, on_ack, emit, host, credentials, *, segment=None, offset=None, record=None):
        super().__init__(username, on_ack, emit, host, credentials)
        self.segment, self.offset, self.record = segment, offset, record
        self.ignored, self.done_window, self.violating = set(), None, False
        delivered = self.inner.client.on_publish

        def guarded(client, userdata, mid, reason, properties):
            if self.violating or mid in self.ignored:         # a QoS 0 violation has no PUBACK and is not part of the benign acknowledgement ledger (Paho may call back DURING publish())
                self.ignored.discard(mid)
                return
            delivered(client, userdata, mid, reason, properties)
        self.inner.client.on_publish = guarded

    def publish(self, topic, data):
        mid = super().publish(topic, data)
        if self.segment is not None and self.offset is not None and self.inner.connected:
            now = self.offset()
            index = now // self.segment["window_ns"]
            if self.segment["start_ns"] <= now < self.segment["end_ns"] and index != self.done_window:
                self.done_window = index
                self.violating = True
                try:
                    info = self.inner.client.publish(self.segment["topic"], VIOLATION_PAYLOAD, qos=0, retain=False)
                finally:
                    self.violating = False
                self.ignored.add(info.mid)
                self.record(dict(window_slot=int(index), offset_ns=int(now), topic=self.segment["topic"], qos=0, mqtt_mid=info.mid, rc=int(info.rc)))
        return mid


class DevWorkloadRunner(runner_v2.WorkloadRunnerV2):
    """Optional `tolerate_containment` (top-level boolean of the specification): when a device is CONTAINED by the enforcement point under test (its connection is closed by the broker,
    or its telemetry publish is denied), the runner records that, stops publishing for THAT device only and keeps publishing the others on their unchanged schedules, instead of
    aborting the whole run on the first failure as the unchanged runner does. The run still ends INCOMPLETE with failure `device_contained:<devices>` (it is development evidence, never a
    complete workload), and everything about the contained device before containment stays in its ledger."""

    def __init__(self, *, spec, **kwargs):
        super().__init__(**kwargs)
        self.spec = spec
        self.tolerate = spec.get("tolerate_containment") is True
        self.contained, self.skipped, self.next_probe = {}, {}, {}
        self.probe_factory = None                                   # set by main(): username -> a NEW publisher for an independent connection probe
        self.changes = {}
        self.attempts = (self.path / "foreign_topic_attempts.jsonl").open("x", encoding="utf-8", newline="\n")
        for device, item in spec["devices"].items():
            before = len(self.schedules[device])
            self.schedules[device] = perturbed_items(self.config, device, item)
            self.changes[device] = dict(kind=item["kind"], params=item["params"], first_window=item["first_window"], last_window=item["last_window"],
                                        benign_messages=before, planned_messages=len(self.schedules[device]))
            self.metadata["devices"][device]["planned_messages"] = len(self.schedules[device])
        self.metadata.update(development_only=True, development_label=LABEL, development_perturbation=dict(spec_sha256=plans.digest(spec), devices=self.changes))
        with (self.path / "DEV_PERTURBATION.json").open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(dict(spec, evidence_class=LABEL, changes=self.changes, note="neither calibration, nor D_shadow, nor D_test, nor attack-detection evidence"), stream, indent=2, sort_keys=True)
            stream.write("\n")

    # ------------------------------------------------------------------------------------------------------------ containment-tolerant run
    def _contain(self, device, reason):
        if device in self.contained:
            return
        now = self.clock()
        self.contained[device] = dict(reason=reason, offset_ns=self._offset(now), utc=self.utc(), mono_ns=now)
        self.next_probe[device] = now
        self.skipped.setdefault(device, 0)
        self.pending[device].clear()
        self._ledger(device, record_type="CONTAINED", reason=reason, offset_ns=self._offset(now), monotonic_ns=now, utc=self.utc())

    def _pump(self, until_ns):
        if not self.tolerate:
            return super()._pump(until_ns)
        while True:
            now = self.clock()
            if now >= until_ns:
                return
            live = {d: p for d, p in self.publishers.items() if d not in self.contained}
            if not live:
                raise v1.WorkloadError("all_publishers_contained")
            share = min(v1.LOOP_SLICE_S, (until_ns - now) / 1e9 / len(live))
            for device, publisher in live.items():
                if publisher.loop(max(0.0, share)) != 0 or not publisher.connected:
                    self._contain(device, "connection_closed_by_broker")
            self._effect_probes()

    def _effect_probes(self):
        """Independent effective-access observation of a contained device: a fresh CONNECT with the device's own credential every 200 ms for 30 s, then every second. A refused CONNACK (135)
        bounds from above the instant the broker's denial was in effect; an ACCEPTED connection would show that the containment is NOT in effect. All stamps are on this container's clock
        (the same virtual-machine clock as the observer and the broker)."""
        for device, info in self.contained.items():
            now = self.clock()
            if now < self.next_probe.get(device, 0):
                continue
            self.next_probe[device] = now + (200_000_000 if now - info["mono_ns"] < 30_000_000_000 else 1_000_000_000)
            started, started_utc = now, self.utc()
            fresh = None
            try:
                # a client whose connection the broker closed cannot be reconnected reliably (Paho raises), so every probe is a NEW client with the device's own credential
                fresh = self.probe_factory(self.config["devices"][device]["username"]) if self.probe_factory else self.publishers[device]
                code = fresh.connect(1)
            except Exception as exc:                       # a probe must never stop the run
                code = f"error:{type(exc).__name__}"
            ended = self.clock()
            self._ledger(device, record_type="EFFECT_PROBE", connack=code, start_offset_ns=self._offset(started), end_offset_ns=self._offset(ended), start_utc=started_utc,
                         end_utc=self.utc(), start_monotonic_ns=started, end_monotonic_ns=ended)
            if fresh is not None and self.probe_factory:   # the probe client is always closed (a refused connection has nothing to close)
                try:
                    fresh.close()
                except Exception:
                    pass
            elif code == 0:                                # the broker accepted the contained device: record it, then close the connection again
                try:
                    self.publishers[device].close()
                except Exception:
                    pass

    def _ack(self, device, mid, reason):
        if not self.tolerate:
            return super()._ack(device, mid, reason)
        if device in self.contained:
            return                                            # a late acknowledgement after containment
        if reason >= 128:                                     # the broker denies this device's telemetry publish: containment
            sequence = self.pending[device].pop(mid, None)
            self._ledger(device, record_type="PUBACK", sequence=sequence, mqtt_mid=mid, puback_reason=reason, puback_monotonic_ns=self.clock(), puback_utc=self.utc(), outcome="denied")
            if sequence is not None:
                self.messages[device][sequence]["puback_reason"] = reason
            self._contain(device, f"publish_denied_{reason}")
            return
        return super()._ack(device, mid, reason)

    def run(self):
        if not self.tolerate:
            return super().run()
        state = "INCOMPLETE"
        try:
            self.coverage = self._wait_coverage()
            self.epoch_coverage = v1.utc_to_epoch_ns(self.coverage["coverage_start_utc"])
            self.mono_coverage = self.clock() - (self.wall() - self.epoch_coverage)
            for device in self.devices:
                spec = self.config["devices"][device]
                if spec["username"] != spec["client_id"]:
                    raise v1.WorkloadError("bound client id must equal the registered username")
                publisher = self.publisher_factory(
                    spec["username"], lambda mid, reason, d=device: self._ack(d, mid, reason),
                    lambda kind, d=device, **fields: self.lifecycle.append(dict(device=d, kind=kind, **{
                        k: v for k, v in fields.items() if k in ("reason_code", "intentional", "server_disconnect_packet")})))
                self.publishers[device] = publisher
                if publisher.connect(3) != 0:
                    raise v1.WorkloadError("publisher_authentication_rejected")
            items = sorted((offset, device, sequence, size) for device in self.devices for sequence, offset, size in self.schedules[device])
            if not items:
                raise v1.WorkloadError("empty_schedule")
            if self._offset() >= items[0][0]:
                raise v1.WorkloadError("coverage_detected_too_late")
            for offset, device, sequence, size in items:
                self._pump(self.mono_coverage + offset)
                if self.failure:
                    break
                if device in self.contained:
                    self.skipped[device] += 1
                    continue
                spec = self.config["devices"][device]
                data = v1.payload(self.run_id, device, sequence, size)
                attempt = self.clock()
                self._pre_publish_wall_ns = self.wall()
                mid = self.publishers[device].publish(spec["telemetry_topic"], data)
                self.messages[device][sequence] = dict(queued=mid is not None, puback_reason=None)
                if mid is not None:
                    self.pending[device][mid] = sequence
                self._ledger(device, record_type="ATTEMPT", configured_username=spec["username"], configured_client_id=spec["client_id"], topic=spec["telemetry_topic"],
                             qos=v1.PUBLISH_QOS, retain=False, sequence=sequence, scheduled_offset_ns=offset, scheduled_utc=v1.epoch_ns_to_utc(self.epoch_coverage + offset),
                             attempt_offset_ns=self._offset(attempt), attempt_monotonic_ns=attempt, attempt_utc=self.utc(), payload_bytes=len(data),
                             payload_sha256=hashlib.sha256(data).hexdigest(), mqtt_mid=mid, queued=mid is not None, outcome="queued" if mid is not None else "enqueue_failed")
                if mid is None:
                    self._contain(device, "enqueue_failed")
            deadline = self.clock() + self.ack_timeout_ns
            while any(self.pending[d] for d in self.devices if d not in self.contained) and self.clock() < deadline and not self.failure:
                self._pump(min(deadline, self.clock() + 10_000_000))
            if any(self.pending[d] for d in self.devices if d not in self.contained) and not self.failure:
                self.failure = "puback_timeout"
            planned = all(len(self.messages[d]) + self.skipped.get(d, 0) == len(self.schedules[d]) for d in self.devices)
            if not self.failure:
                if self.contained:
                    self.failure = "device_contained:" + ",".join(sorted(self.contained))
                elif planned:
                    state = "COMPLETE"
                else:
                    self.failure = "schedule_not_completed"
        except v1.WorkloadError as exc:
            self.failure = self.failure or str(exc)
        except Exception as exc:  # fail closed, without echoing arbitrary text
            self.failure = self.failure or f"unexpected_{type(exc).__name__}"
        finally:
            self.metadata["containment"] = dict(devices=self.contained, messages_not_sent_after_containment=self.skipped)
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
        self.attempts.close()
        return super()._finish(state)

    def record_attempt(self, device, row):
        self.attempts.write(json.dumps(dict(row, device=device, kind="FOREIGN_TOPIC_ATTEMPT"), sort_keys=True) + "\n")
        self.attempts.flush()


def violation_segments(spec, config):
    """{username: segment} for every device with a `foreign_topic` item: the run-relative interval and the denied topic (the peer's telemetry topic)."""
    segments, w = {}, v2.window_ns(config)
    for device, item in spec["devices"].items():
        if item["kind"] != "foreign_topic":
            continue
        peer = next(d for d in config["devices"] if d != device)
        segments[config["devices"][device]["username"]] = dict(
            device=device, window_ns=w, topic=config["devices"][peer]["telemetry_topic"],
            start_ns=(config["lead_in_windows"] - 1 + item["first_window"]) * w, end_ns=(config["lead_in_windows"] + item["last_window"]) * w)
    return segments


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--purpose", required=True, choices=("FUNCTIONAL_TEST",))
    parser.add_argument("--plan", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--perturbation", required=True)
    parser.add_argument("--registry", default="/app/configs/observation/device_registry.json")
    parser.add_argument("--output-dir", default="/results")
    parser.add_argument("--host", default=os.getenv("MQTT_HOST", "broker"))
    parser.add_argument("--credentials", default="/run/secrets")
    parser.add_argument("--coverage-timeout-s", type=float, default=120.0)
    args = parser.parse_args(argv)
    try:
        registry = DeviceRegistry.load(args.registry)
        plan = plans_v2.validate_plan_v2(plans.load_plan(args.plan), registry)
        config = plan["runs"].get(args.run_id)
        if config is None or plan["kind"] != "FUNCTIONAL_TEST":
            raise ValueError("the run must belong to a FUNCTIONAL_TEST plan")
        spec = validate_spec(json.loads(Path(args.perturbation).read_text(encoding="utf-8")), config)
        coverage_source = sessions_v2.coverage_from_environment(args.output_dir, args.run_id, args.purpose, os.environ)
        boundary = dict(count=len(coverage_source.excluded), sha256=sessions_v2.snapshot_digest(coverage_source.excluded))
        segments, holder = violation_segments(spec, config), {}

        def make_publisher(username, on_ack, emit):
            segment = segments.get(username)
            if segment is None:
                return v1.DevicePublisher(username, on_ack, emit, args.host, args.credentials)
            return ViolationPublisher(username, on_ack, emit, args.host, args.credentials, segment=segment, offset=lambda: holder["runner"]._offset(),
                                      record=lambda row: holder["runner"].record_attempt(segment["device"], row))
        runner_class, extra = DevWorkloadRunner, {}
        if spec.get("interactive") is True:                  # Gate 6A: anomalies are started and stopped at runtime through the control channel (engineering.interactive_workload)
            from engineering.interactive_workload import InteractiveRunner
            runner_class, extra = InteractiveRunner, dict(control_dir=Path(args.output_dir) / "control")
        runner = runner_class(
            spec=spec, config=config, purpose=args.purpose, output_root=args.output_dir, **extra,
            publisher_factory=make_publisher,
            coverage_source=coverage_source, session_boundary=boundary, runtime=v1.runtime(),
            plan_ref=dict(plan_id=plan["plan_id"], plan_sha256=plans.digest(plan)), attestation=None, coverage_timeout_ns=int(args.coverage_timeout_s * 1e9))
        holder["runner"] = runner
        runner.probe_factory = lambda username: v1.DevicePublisher(username, lambda mid, reason: None, lambda kind, **fields: None, args.host, args.credentials)
    except (ValueError, OSError, KeyError) as exc:
        print(f"DEV_WORKLOAD_REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    summary = runner.run()
    counts = " ".join(f'{d}={r["accepted"]}/{r["planned_messages"]}' for d, r in summary["devices_result"].items())
    print(f'DEV_WORKLOAD_RUN {args.run_id} {LABEL} {summary["state"]} failure={summary["failure_code"]} accepted {counts}')
    return 0 if summary["state"] == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
