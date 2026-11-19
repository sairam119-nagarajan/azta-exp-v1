"""Per-device publisher isolation for the Gate 6B fleet workload (defect F2).

The single-process fleet emulator serves ten publishers from ONE loop. Its publish lateness was median 2 to 3 ms and p95 12 to 16 ms in the first authorized pilot session (15% of all
messages of the second session were more than 5 ms late; the stalls are loop-wide, not periodic and not tied to co-scheduled messages), against a median of 0.2 to 0.3 ms and a maximum of
1.3 ms in the collection runs, which had one publisher container per device. The exactly periodic device05 reads those milliseconds as a large reconstruction error (see
`rehearsal_tools/f2_timing_investigation.py`). This module restores the collection's isolation inside the one workload container: ONE UNCHANGED `FleetRunner` PROCESS PER DEVICE
(`engineering.fleet_workload --shard-device D`), each with its own MQTT client, credential, schedule, ledger and control files, so nothing one device does can delay another. Timing is
not made artificially perfect: each process keeps the ordinary operating-system scheduling noise of a separate process.

The parent process (this module) is the only owner of the operator-facing control channel and the only merger of outputs:

  * `control/commands.jsonl` (written by `rehearsal_tools/attack_ctl.py`, unchanged) is read here and each well-formed command is appended, byte for byte, to the command file of the
    shard of its target device; a malformed line or an unknown device is rejected here with the unchanged runner's wording;
  * every shard event is copied into `control/events.jsonl` (tagged with its shard, otherwise unchanged); one merged RUNNER_STARTED and one RUNNER_ENDED replace the per-shard ones;
  * `control/status.json` is the union of the shards' device entries (phase RUNNING only when every shard is RUNNING, ENDED only when every shard has ended);
  * when the shards have ended, `collection/<run>/` receives byte copies of the per-device ledgers, the concatenated foreign-topic attempts and a merged metadata and summary. The per-shard
    directories (`shards/<device>/`) stay as the primary evidence; nothing is ever overwritten.

A shard that fails keeps its failure visible (the merged summary is INCOMPLETE and names it); the other shards continue on their own schedules, exactly as a contained device already does.
Nothing here touches the broker, a policy or a credential beyond starting the children that use them. Without `--isolation per-device` the workload is the unchanged single process.
"""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

from engineering import attack_control as control
from engineering import dev_workload as dw

POLL_S = 0.05
STATUS_PERIOD_S = 0.5
PASS_THROUGH = ("purpose", "plan", "run_id", "perturbation", "registry", "output_dir", "host", "credentials", "coverage_timeout_s")


def shard_command(args, device, *, python=None):
    """The child command: the same module and the same arguments, restricted to ONE device by `--shard-device` (isolation is not passed on: a shard is never a parent)."""
    command = [python or sys.executable, "-B", "-m", "engineering.fleet_workload"]
    for name in PASS_THROUGH:
        command += ["--" + name.replace("_", "-"), str(getattr(args, name))]
    return command + ["--control-io", getattr(args, "control_io", "inline"), "--shard-device", device]


def shard_dirs(output_dir, device):
    root = Path(output_dir)
    return root / "shards" / device, root / "control" / "shards" / device


class Router:
    """Operator commands out to the shards, shard events and statuses back into the one control channel. All state is a byte position; nothing is read twice or dropped."""

    def __init__(self, output_dir, run_id, devices, *, utc=None, wall=None):
        self.run_id, self.devices = run_id, sorted(devices)
        self.control = Path(output_dir) / "control"
        self.control.mkdir(parents=True, exist_ok=True)
        self.commands = self.control / "commands.jsonl"
        self.commands.touch()
        self.events = (self.control / "events.jsonl").open("x", encoding="utf-8", newline="\n")
        self.utc, self.wall = utc or control.utc_now, wall or time.time_ns
        self.command_pos, self.command_tail = 0, b""
        self.shard_pos = {d: 0 for d in self.devices}
        self.shard_tail = {d: b"" for d in self.devices}
        self.started, self.ended = set(), {}
        self.merged_started = self.merged_ended = False
        self.next_status = 0.0
        for device in self.devices:
            _, directory = shard_dirs(output_dir, device)
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "commands.jsonl").touch()
        self.output_dir = Path(output_dir)

    # --------------------------------------------------------------------------------------------------------------------------- commands
    def _write_event(self, row):
        self.events.write(json.dumps(row, sort_keys=True) + "\n")
        self.events.flush()

    def _reject(self, command_id, action, device, reason):
        self._write_event(dict(schema=control.EVENT_SCHEMA, kind="COMMAND_REJECTED", utc=self.utc(), utc_ns=self.wall(), offset_ns=None, command_id=command_id, action=action,
                               device=device, reason=reason, shard="router"))

    def route_commands(self):
        try:
            with open(self.commands, "rb") as stream:
                stream.seek(self.command_pos)
                data = self.command_tail + stream.read()
                self.command_pos += len(data) - len(self.command_tail)
        except OSError:
            return 0
        *lines, self.command_tail = data.split(b"\n")
        routed = 0
        for raw in lines:
            if not raw.strip():
                continue
            try:
                command = json.loads(raw)
                assert isinstance(command, dict) and command.get("schema") == control.COMMAND_SCHEMA and command.get("action") in control.ACTIONS
                command_id, device = command["command_id"], command["device"]
                assert isinstance(command_id, str) and isinstance(device, str)
            except (ValueError, AssertionError, KeyError):
                self._reject(None, None, None, "MALFORMED_COMMAND")
                continue
            if device not in self.devices:
                self._reject(command_id, command["action"], device, f"UNKNOWN_DEVICE:{device}")
                continue
            if device in self.ended:                 # nobody would read it: answer now instead of leaving the command unanswered (stb-l02, device01)
                self._reject(command_id, command["action"], device, "SHARD_ENDED")
                continue
            _, directory = shard_dirs(self.output_dir, device)
            with open(directory / "commands.jsonl", "ab") as stream:
                stream.write(raw + b"\n")
            routed += 1
        return routed

    # ----------------------------------------------------------------------------------------------------------------------------- events
    def merge_events(self):
        merged = 0
        for device in self.devices:
            _, directory = shard_dirs(self.output_dir, device)
            try:
                with open(directory / "events.jsonl", "rb") as stream:
                    stream.seek(self.shard_pos[device])
                    data = self.shard_tail[device] + stream.read()
                    self.shard_pos[device] += len(data) - len(self.shard_tail[device])
            except OSError:
                continue
            *lines, self.shard_tail[device] = data.split(b"\n")
            for raw in lines:
                if not raw.strip():
                    continue
                row = json.loads(raw)
                if row.get("kind") == "RUNNER_STARTED":
                    self.started.add(device)
                    continue
                if row.get("kind") == "RUNNER_ENDED":
                    self.ended[device] = row
                    continue
                self._write_event(dict(row, shard=device))
                merged += 1
        if not self.merged_started and self.started == set(self.devices):
            self._write_event(dict(schema=control.EVENT_SCHEMA, kind="RUNNER_STARTED", utc=self.utc(), utc_ns=self.wall(), offset_ns=None, devices=self.devices,
                                   anomalies=sorted(control.CATALOGUE), isolation="per-device", shard="router"))
            self.merged_started = True
        if not self.merged_ended and set(self.ended) == set(self.devices):
            states = {d: r.get("state") for d, r in self.ended.items()}
            failures = {d: r.get("failure") for d, r in self.ended.items() if r.get("failure")}
            self._write_event(dict(schema=control.EVENT_SCHEMA, kind="RUNNER_ENDED", utc=self.utc(), utc_ns=self.wall(), offset_ns=None, shard="router",
                                   state="COMPLETE" if all(s == "COMPLETE" for s in states.values()) else "INCOMPLETE", failure=failures or None, shard_states=states))
            self.merged_ended = True
        return merged

    # ----------------------------------------------------------------------------------------------------------------------------- status
    def merge_status(self, *, force=False):
        now = time.monotonic()
        if not force and now < self.next_status:
            return None
        self.next_status = now + STATUS_PERIOD_S
        parts = {}
        for device in self.devices:
            _, directory = shard_dirs(self.output_dir, device)
            try:
                parts[device] = json.loads((directory / "status.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
        if not parts:
            return None
        phases = {p.get("phase") for p in parts.values()}
        phase = "ENDED" if len(parts) == len(self.devices) and phases == {"ENDED"} else "RUNNING" if len(parts) == len(self.devices) and phases == {"RUNNING"} else "STARTING"
        if phase == "STARTING" and "ENDED" in phases and "RUNNING" in phases:
            phase = "RUNNING"                                  # some shards ended (a contained or failed device): the others are still publishing
        devices = {}
        for part in parts.values():
            devices.update(part["devices"])
        data = dict(schema=control.STATUS_SCHEMA, run_id=self.run_id, phase=phase, utc=self.utc(), offset_ns=max(p.get("offset_ns") or 0 for p in parts.values()),
                    anomalies=sorted(control.CATALOGUE), devices=devices, isolation="per-device", shards_reporting=sorted(parts))
        temporary = self.control / "status.json.tmp"
        temporary.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
        retried = control.replace_status(temporary, self.control / "status.json")        # bounded retry of a host reader's transient lock; persistent denial still raises
        if retried:
            print(f"{self.utc()} STATUS_REPLACE_RETRIED router status.json attempts={retried + 1}", file=sys.stderr, flush=True)     # visible evidence of an absorbed lock
        return phase

    def step(self):
        self.route_commands()
        self.merge_events()
        self.merge_status()

    def close(self):
        self.events.close()


# ------------------------------------------------------------------------------------------------------------------------------- outputs
def _json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def merge_outputs(output_dir, run_id, devices, exit_codes):
    """Byte copies of the per-device ledgers and merged metadata/summary under `collection/<run>/` (exclusive creation: an existing file is an error, never overwritten)."""
    target = Path(output_dir) / "collection" / run_id
    target.parent.mkdir(parents=True, exist_ok=True)
    target.mkdir(exist_ok=False)
    parts = {}
    for device in sorted(devices):
        directory, _ = shard_dirs(output_dir, device)
        source = directory / "collection" / run_id
        if not (source / "workload_summary.json").exists():
            parts[device] = None                                                   # the shard never reached its summary: it is reported, not invented
            continue
        parts[device] = dict(metadata=_json(source / "workload_metadata.json"), summary=_json(source / "workload_summary.json"), source=source)
        with open(source / f"ledger_{device}.jsonl", "rb") as src, open(target / f"ledger_{device}.jsonl", "xb") as dst:
            shutil.copyfileobj(src, dst)
    with open(target / "foreign_topic_attempts.jsonl", "xb") as dst:
        for device, part in sorted(parts.items()):
            if part is not None and (part["source"] / "foreign_topic_attempts.jsonl").exists():
                with open(part["source"] / "foreign_topic_attempts.jsonl", "rb") as src:
                    shutil.copyfileobj(src, dst)
    present = {d: p for d, p in parts.items() if p is not None}
    failures = {d: (p["summary"].get("failure_code") if p else "shard_produced_no_summary") for d, p in parts.items() if p is None or p["summary"].get("failure_code")}
    states = {d: (p["summary"]["state"] if p else "INCOMPLETE") for d, p in parts.items()}
    state = "COMPLETE" if all(s == "COMPLETE" for s in states.values()) and all(code == 0 for code in exit_codes.values()) else "INCOMPLETE"
    first = next(iter(present.values()), None)
    metadata = dict(first["metadata"], devices={d: p["metadata"]["devices"][d] for d, p in present.items()}) if first else {}
    metadata["fleet_workload"] = dict(metadata.get("fleet_workload", {}), isolation="per-device", shards=sorted(devices),
                                      note="one FleetRunner process per device; per-shard evidence under shards/<device>/")
    summary = dict(first["summary"], **{k: v for k, v in metadata.items() if k in ("devices", "fleet_workload")}) if first else {}
    summary.update(state=state, failure_code=failures or None, shard_states=states, shard_exit_codes=exit_codes,
                   devices_result={d: p["summary"]["devices_result"][d] for d, p in present.items()},
                   lifecycle=[item for p in present.values() for item in p["summary"].get("lifecycle", [])])
    for name, value in (("workload_metadata.json", metadata), ("workload_summary.json", summary)):
        with open(target / name, "x", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, sort_keys=True, indent=1)
            stream.write("\n")
    if first is not None and (first["source"] / "DEV_PERTURBATION.json").exists():
        shutil.copyfile(first["source"] / "DEV_PERTURBATION.json", target / "DEV_PERTURBATION.json")
    return summary


# ---------------------------------------------------------------------------------------------------------------------------------- run
def run(args, devices, *, popen=subprocess.Popen, command=shard_command, sleep=time.sleep, deadline_s=None):
    """Start one child per device, route the control channel until every child has ended, merge the outputs, and return 0 only when every shard completed."""
    output_dir = Path(args.output_dir)
    router = Router(output_dir, args.run_id, devices)
    children, logs = {}, []
    stopping = []

    def terminate(*_):
        stopping.append(True)
        for process in children.values():
            if process.poll() is None:
                process.terminate()
    try:
        signal.signal(signal.SIGTERM, terminate)
    except (ValueError, OSError):
        pass                                                      # not the main thread (tests): the caller terminates the children
    try:
        for device in sorted(devices):
            directory, _ = shard_dirs(output_dir, device)
            directory.mkdir(parents=True, exist_ok=True)
            log = open(directory / "shard.log", "ab")
            logs.append(log)
            children[device] = popen(command(args, device), stdout=log, stderr=subprocess.STDOUT, env=dict(os.environ))
        started = time.monotonic()
        while any(p.poll() is None for p in children.values()):
            router.step()
            if deadline_s is not None and time.monotonic() - started > deadline_s:
                terminate()
                break
            sleep(POLL_S)
        exit_codes = {d: p.wait() for d, p in children.items()}
        router.merge_events()
        router.route_commands()
        router.merge_status(force=True)
        summary = merge_outputs(output_dir, args.run_id, devices, exit_codes)
    finally:
        router.close()
        for log in logs:
            log.close()
    counts = " ".join(f'{d}={r["accepted"]}/{r["planned_messages"]}' for d, r in summary["devices_result"].items())
    print(f'FLEET_WORKLOAD_RUN {args.run_id} {dw.LABEL} {summary["state"]} isolation=per-device failure={summary["failure_code"]} accepted {counts}')
    return 0 if summary["state"] == "COMPLETE" else 1
