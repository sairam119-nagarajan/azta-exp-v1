"""DEVELOPMENT_ONLY interactive fleet workload (Gate 6B): the Gate 6A interactive publisher over N devices, each on its OWN committed legitimate traffic law.

It is `engineering.interactive_workload.InteractiveRunner` (ledger, acknowledgements, observer-coverage synchronisation, runtime START/STOP control channel, containment tolerance, resumption
after an administrative RESTORE) with exactly two differences: the benign schedule of each device is the committed ten-slot law of that device (`fleet.laws`, not the S/V steady law of the
two-device plan), and a START replaces the schedule from that instant with the anomaly derived from the device's OWN law (`fleet.laws.anomaly_items`). The control protocol
(`engineering.attack_control`) is unchanged. Messages are real QoS 1 Paho publishes on the device's own authorized telemetry topic with its own credential. Nothing here edits broker
policy; STOP restores no permission. DEVELOPMENT_ONLY engineering evidence: neither calibration, nor D_shadow/D_test, nor detection-accuracy evidence.
"""
import argparse
import collections
import json
import os
from pathlib import Path
import sys

from engineering import attack_control as control
from engineering import dev_workload as dw
from engineering import interactive_workload as iw
from experiments import collection_plan as plans
from experiments import collection_sessions_v2 as sessions_v2
from experiments import collection_workload as v1
from experiments import collection_workload_v2 as v2
from fleet import laws, plan as fleet_plan
from observation.registry import DeviceRegistry

PUMP_STEP_MIN_S = 0.0002      # sleep step when a message is due within a few steps ...
PUMP_STEP_MAX_S = 0.005       # ... and the longest step otherwise (a quarter of the remaining time in between)


class FleetDevicePublisher(v1.DevicePublisher):
    """`v1.DevicePublisher` (unchanged A3 client, QoS 1) with credential resolution for every registry-v2 device: device01/device02 keep the names the frozen helper knows, every other
    device reads `<credentials>/<username>-password` (mounted by the compose service for exactly the devices of the run, one file per device)."""

    def __init__(self, username, on_ack, emit, host="broker", credentials="/run/secrets"):
        from experiments import a3_mqtt
        original = a3_mqtt.password_for

        def resolve(identity, root="/run/secrets"):
            try:
                return original(identity, root)
            except KeyError:
                return Path(root) / f"{identity}-password"
        a3_mqtt.password_for = resolve
        try:
            super().__init__(username, on_ack, emit, host, credentials)
        finally:
            a3_mqtt.password_for = original


class FleetRunner(iw.InteractiveRunner):
    reconnect_plan, offline = {}, {}          # replaced per instance in __init__; the class defaults keep a runner without declared reconnections exactly as before

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        w = v2.window_ns(self.config)
        variation = laws.validate_timing_variation(self.spec["timing_variation"]) if "timing_variation" in self.spec else None      # Gate 6C: declared benign collection condition, absent = unchanged
        # Gate 6C Phase 2: declared benign reconnections (absent = unchanged); the messages that fall while a device is offline are never scheduled
        reconnections = laws.validate_reconnections(self.spec["reconnections"], sorted(self.spec["reconnections"]), window_ns=w) if "reconnections" in self.spec else {}
        self.reconnect_plan, self.offline = {}, {}
        for device in self.devices:
            items = laws.benign_items(self.run_id, device, window_ns=w, lead_in_windows=self.config["lead_in_windows"], eligible_windows=self.config["eligible_windows"],
                                      post_roll_windows=self.config["post_roll_windows"])
            items = laws.vary_timing(items, variation, self.run_id, device, window_ns=w, lead_in_windows=self.config["lead_in_windows"])
            if reconnections.get(device):
                intervals = laws.reconnection_intervals(reconnections[device], window_ns=w, lead_in_windows=self.config["lead_in_windows"])
                items = laws.drop_offline(items, intervals)
                self.reconnect_plan[device] = collections.deque(intervals)
            self.schedules[device] = list(items)
            self.base[device] = list(items)
            self.tails[device] = collections.deque((o, s) for _, o, s in items)
            self.metadata["devices"][device]["planned_messages"] = len(items)
        self.end_ns = v2.publishing_end_ns(self.config) + 1
        self.metadata["fleet_workload"] = dict(version=self.config["fleet_workload_version"], laws={d: self.config["devices"][d]["law"]["shape"] for d in self.devices})
        if variation:
            self.metadata["fleet_workload"]["timing_variation"] = variation
        if reconnections:
            self.metadata["fleet_workload"]["reconnections"] = {d: reconnections[d] for d in self.devices if d in reconnections}

    # ------------------------------------------------------------------------------------------------------------------------------ declared benign reconnections (Phase 2)
    def _reconnections(self):
        if not self.reconnect_plan or self.mono_coverage is None or self.failure:
            return
        now = self.clock()
        for device in self.devices:
            if device in self.contained:
                continue
            if device in self.offline:
                if now >= self.mono_coverage + self.offline[device]["end"]:
                    self._come_online(device)
            elif self.reconnect_plan.get(device) and now >= self.mono_coverage + self.reconnect_plan[device][0][0]:
                self._go_offline(device, *self.reconnect_plan[device].popleft())

    def _go_offline(self, device, start, end, mode):
        """The in-flight PUBACKs are collected first (at most 2 s), then `clean` sends DISCONNECT and `takeover` simply stops servicing the connection (no PINGREQ, no DISCONNECT)."""
        publisher = self.publishers[device]
        deadline = self.clock() + 2_000_000_000
        while self.pending[device] and self.clock() < deadline:
            if publisher.loop(0.0) != 0:
                break
            self.idle(0.001)
        lost = len(self.pending[device])
        self.pending[device].clear()
        now = self.clock()
        if mode == "clean":
            publisher.close()
            deadline = self.clock() + 1_000_000_000
            while publisher.connected and self.clock() < deadline:
                if publisher.loop(0.01) != 0:
                    break
        self.offline[device] = dict(start=start, end=end, mode=mode, old=publisher)
        self._ledger(device, record_type="RECONNECT_OFFLINE", mode=mode, planned_start_offset_ns=start, planned_end_offset_ns=end, offset_ns=self._offset(now), monotonic_ns=now,
                     utc=self.utc(), unacknowledged_at_offline=lost)
        self._event("DEVICE_OFFLINE", device=device, mode=mode)

    def _come_online(self, device):
        info = self.offline.pop(device)
        started = self.clock()
        try:
            fresh = self._make_publisher(device)
            code = fresh.connect(3)
        except Exception as exc:                       # recorded, then the run fails closed
            fresh, code = None, f"error:{type(exc).__name__}"
        ended = self.clock()
        if info["mode"] == "takeover":
            try:
                info["old"].loop(0.0)                  # reads the broker's close of the old connection, so its socket is released
            except Exception:
                pass
        self._ledger(device, record_type="RECONNECT_ONLINE", mode=info["mode"], connack=code, planned_end_offset_ns=info["end"], start_offset_ns=self._offset(started),
                     end_offset_ns=self._offset(ended), utc=self.utc())
        if code != 0:
            self.failure = self.failure or "reconnection_refused"
            return
        self.publishers[device] = fresh
        self._event("DEVICE_ONLINE", device=device, mode=info["mode"])

    def _send(self, device, offset, size):
        if device in self.offline:
            self._come_online(device)
        if self.failure:
            return
        super()._send(device, offset, size)

    def _pump(self, until_ns):
        """Service every live publisher with NON-blocking loop calls and sleep in short steps, instead of the Gate 6A pump (`loop(timeout)` per publisher in turn).

        With ten publishers in one process the blocking version overshot every due instant by the cost of a whole pass: the first live fleet session measured a publish lateness of median
        2 to 3 ms, p95 15 ms, SD about 6 ms (the collection runs had one publisher per container, inter-arrival SD 0.6 ms for the exactly periodic device05), which the periodic profile
        reads as a large reconstruction error. Here the schedule is met to within about a pass of non-blocking calls; PUBACKs and keep-alives are still serviced every pass."""
        while True:
            self._reconnections()
            now = self.clock()
            if now >= until_ns:
                return
            for device, publisher in [(d, p) for d, p in self.publishers.items() if d not in self.contained and d not in self.offline]:
                if publisher.loop(0.0) != 0 or not publisher.connected:
                    self._contain(device, "connection_closed_by_broker")
            self.idle(min(max((until_ns - now) / 4e9, PUMP_STEP_MIN_S), PUMP_STEP_MAX_S, (until_ns - now) / 1e9))
            self._effect_probes()

    def _handle(self, line):
        try:
            command = json.loads(line)
            if command.get("action") == "start" and command.get("device") in self.devices:
                check_command_applicable(self.config, command["device"], command.get("anomaly"))
        except control.ControlRefused as exc:
            self.seen.add(command.get("command_id"))
            return self._reject(command, f"INVALID_ANOMALY:{exc}")
        except (ValueError, AttributeError):
            pass                                     # malformed lines are rejected by the unchanged handler
        return super()._handle(line)

    def _rebuild(self, device, t):
        if device in self.contained:
            self.tails[device] = collections.deque()
            return
        due = [x for x in self.tails[device] if x[0] < t]
        future = [(o, s) for o, s in laws.device_pairs(self.run_id, device, self.base[device], self.segments[device]) if o >= t]
        self.tails[device] = collections.deque(due + future)


def check_command_applicable(config, device, kind):
    """A START the device's own law cannot express (jitter on a periodic law) is refused up front, never emulated."""
    if kind == "jitter" and "jitter_fraction" not in config["devices"][device]["law"]:
        raise control.ControlRefused(f"{device}: a {config['devices'][device]['law']['shape']} law has no jitter to change")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--purpose", required=True, choices=("FUNCTIONAL_TEST",))
    parser.add_argument("--plan", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--perturbation", required=True, help="a development perturbation specification with interactive: true and no devices (anomalies come from the control channel)")
    parser.add_argument("--registry", default="/app/configs/observation/device_registry_v2.json")
    parser.add_argument("--output-dir", default="/results")
    parser.add_argument("--host", default=os.getenv("MQTT_HOST", "broker"))
    parser.add_argument("--credentials", default="/run/secrets")
    parser.add_argument("--coverage-timeout-s", type=float, default=120.0)
    parser.add_argument("--isolation", choices=("shared", "per-device"), default="shared",
                        help="shared (default, the unchanged single process: the rollback path) or per-device (Gate 6B F2: one runner process per device, see engineering.fleet_shards)")
    parser.add_argument("--control-io", choices=("inline", "thread"), default="inline",
                        help="inline (default, the unchanged runner: the rollback path) or thread (Gate 6C F2: command polling and status/event writes on a background thread, off the publish path)")
    parser.add_argument("--shard-device", default=None, help="internal: run ONLY this device, in its own shard directories (the child of a per-device run)")
    args = parser.parse_args(argv)
    if args.shard_device and args.isolation != "shared":
        parser.error("--shard-device is the child of a per-device run and takes no --isolation")
    output_root, control_dir = args.output_dir, Path(args.output_dir) / "control"
    try:
        registry = DeviceRegistry.load(args.registry)
        plan = fleet_plan.load_plan(args.plan, registry)
        config = plan["runs"].get(args.run_id)
        if config is None:
            raise ValueError("the run is not in the fleet plan")
        if args.isolation == "per-device":
            from engineering import fleet_shards
            parent_devices = sorted(config["devices"])
        elif args.shard_device:
            if args.shard_device not in config["devices"]:
                raise ValueError(f"{args.shard_device} is not a device of the run")
            from engineering import fleet_shards
            config = dict(config, devices={args.shard_device: config["devices"][args.shard_device]})
            output_root, control_dir = fleet_shards.shard_dirs(args.output_dir, args.shard_device)
            parent_devices = None
        else:
            parent_devices = None
    except (ValueError, OSError, KeyError) as exc:
        print(f"FLEET_WORKLOAD_REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    if parent_devices:
        return fleet_shards.run(args, parent_devices)
    try:
        spec = json.loads(Path(args.perturbation).read_text(encoding="utf-8"))
        if spec.get("interactive") is not True or spec.get("devices") or spec.get("run_id") != args.run_id or spec.get("schema") != dw.SPEC_SCHEMA or spec.get("label") != dw.LABEL:
            raise ValueError("the specification must be an interactive, device-less DEVELOPMENT_ONLY specification of this run")
        coverage_source = sessions_v2.coverage_from_environment(args.output_dir, args.run_id, args.purpose, os.environ)
        boundary = dict(count=len(coverage_source.excluded), sha256=sessions_v2.snapshot_digest(coverage_source.excluded))
        runner = FleetRunner(
            spec=spec, config=config, purpose=args.purpose, output_root=output_root, control_dir=control_dir,
            publisher_factory=lambda username, on_ack, emit: FleetDevicePublisher(username, on_ack, emit, args.host, args.credentials),
            coverage_source=coverage_source, session_boundary=boundary, runtime=v1.runtime(), plan_ref=dict(plan_id=plan["plan_id"], plan_sha256=plans.digest(plan)),
            attestation=None, coverage_timeout_ns=int(args.coverage_timeout_s * 1e9), control_io_thread=args.control_io == "thread")
        runner.probe_factory = lambda username: FleetDevicePublisher(username, lambda mid, reason: None, lambda kind, **fields: None, args.host, args.credentials)
        if args.shard_device:
            runner.metadata["fleet_workload"] = dict(runner.metadata["fleet_workload"], isolation="per-device", shard=args.shard_device)
    except (ValueError, OSError, KeyError) as exc:
        print(f"FLEET_WORKLOAD_REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    summary = runner.run()
    counts = " ".join(f'{d}={r["accepted"]}/{r["planned_messages"]}' for d, r in summary["devices_result"].items())
    print(f'FLEET_WORKLOAD_RUN {args.run_id} {dw.LABEL} {summary["state"]} failure={summary["failure_code"]} accepted {counts}')
    return 0 if summary["state"] == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
