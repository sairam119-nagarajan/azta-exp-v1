"""On-demand anomaly control for the DEVELOPMENT_ONLY interactive workload (Gate 6A): the command protocol, the anomaly catalogue and the operator command line.

    python -I -B rehearsal_tools/attack_ctl.py --run-id ID devices
    python -I -B rehearsal_tools/attack_ctl.py --run-id ID anomalies
    python -I -B rehearsal_tools/attack_ctl.py --run-id ID status [--device device02]
    python -I -B rehearsal_tools/attack_ctl.py --run-id ID start --device device02 --anomaly rate [--param factor=5]
    python -I -B rehearsal_tools/attack_ctl.py --run-id ID stop  --device device02
    python -I -B rehearsal_tools/attack_ctl.py --run-id ID shell

The controller never touches the broker, the trust engine or the PEP. It appends one JSON command per line to results/engineering/runs/ID/control/commands.jsonl; the publisher
container of that run (`engineering.interactive_workload`) polls the file, changes the traffic of ONE named device from that instant and records every outcome in control/events.jsonl and
control/status.json. STOP returns the device to its legitimate schedule; it restores no MQTT permission (RESTORE is the separate manual operator command). The anomalies are the
existing DEVELOPMENT_ONLY synthetic generators (`engineering.dev_workload`): real QoS 1 Paho publishes on the device's own authorized topic with its own credential, nothing else.
This module is standard library only so the container and the host share one protocol definition.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
DEVICE = re.compile(r"device\d{2}\Z")
OPERATOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}\Z")
COMMAND_SCHEMA = "azta.engineering.attack_command"
EVENT_SCHEMA = "azta.engineering.attack_event"
STATUS_SCHEMA = "azta.engineering.attack_status"
ACTIONS = ("start", "stop")
STALE_AFTER_S = 5.0

# The ranges are the ones `engineering.dev_workload.validate_spec` enforces (a test keeps the two in step); `default` is what START uses without --param.
CATALOGUE = {
    "rate": dict(summary="message rate multiplied (flood); the nominal gap is divided by `factor`", params=dict(factor=dict(default=5, min=0.05, max=20, integer=False))),
    "payload": dict(summary="payload size replaced by a fixed size in bytes (oversize)", params=dict(bytes=dict(default=1024, min=96, max=4096, integer=True))),
    "burst": dict(summary="messages arrive in groups of `group`, 20 ms apart, at the unchanged mean rate", params=dict(group=dict(default=5, min=2, max=20, integer=True))),
    "jitter": dict(summary="inter-message timing irregularity (gap jitter fraction replaced)", params=dict(fraction=dict(default=0.8, min=0.0, max=0.99, integer=False))),
    "drop": dict(summary="a seeded fraction of the messages is not sent (partial silence)", params=dict(probability=dict(default=0.8, min=0.01, max=0.99, integer=False))),
    "silence": dict(summary="complete suppression: the device stays connected and publishes nothing (the liveness case)", params={}),
}


class ControlRefused(ValueError):
    pass


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def normalize(anomaly, params=None):
    """(kind, dev_workload parameters, explicit parameters) for a catalogue anomaly. Unknown names, unknown keys, non-finite or out-of-range values are refused."""
    if anomaly not in CATALOGUE:
        raise ControlRefused(f"unknown anomaly {anomaly!r}; supported: {', '.join(CATALOGUE)}")
    spec, given = CATALOGUE[anomaly]["params"], dict(params or {})
    if not set(given) <= set(spec):
        raise ControlRefused(f"{anomaly}: unknown parameter(s) {sorted(set(given) - set(spec))}; supported: {sorted(spec)}")
    explicit = {}
    for key, rule in spec.items():
        value = given.get(key, rule["default"])
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value or value in (float("inf"), float("-inf")):
            raise ControlRefused(f"{anomaly}.{key} must be a finite number")
        if rule["integer"]:
            if value != int(value):
                raise ControlRefused(f"{anomaly}.{key} must be an integer")
            value = int(value)
        if not rule["min"] <= value <= rule["max"]:
            raise ControlRefused(f"{anomaly}.{key} must lie in [{rule['min']}, {rule['max']}]")
        explicit[key] = value
    if anomaly == "drop" and not 0 < explicit["probability"] < 1 or anomaly == "jitter" and not 0 <= explicit["fraction"] < 1:
        raise ControlRefused(f"{anomaly}: parameter outside its open interval")
    dev = {"payload": lambda: {"definition": {"kind": "fixed", "bytes": explicit["bytes"]}}}.get(anomaly, lambda: dict(explicit))()
    return anomaly, dev, explicit


def run_dir(run_id, root=ROOT):
    if not RUN_ID.fullmatch(run_id or ""):
        raise ControlRefused("invalid run id")
    return Path(root) / "results" / "engineering" / "runs" / run_id


def control_dir(run_id, root=ROOT):
    return run_dir(run_id, root) / "control"


def make_command(action, device, anomaly=None, params=None, operator_ref=None):
    if action not in ACTIONS or not DEVICE.fullmatch(device or ""):
        raise ControlRefused("action must be start or stop and device must look like device02")
    operator_ref = operator_ref or os.environ.get("USERNAME") or "OPERATOR"
    if not OPERATOR.fullmatch(operator_ref):
        raise ControlRefused("invalid operator reference")
    command = dict(schema=COMMAND_SCHEMA, command_id=uuid.uuid4().hex[:16], action=action, device=device, operator_ref=operator_ref, requested_utc=utc_now(), requested_ns=time.time_ns())
    if action == "start":
        _, _, explicit = normalize(anomaly, params)          # validated on the host as well; the runner validates again and is authoritative
        command.update(anomaly=anomaly, params=explicit)
    return command


def append_command(directory, command):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    line = (json.dumps(command, sort_keys=True) + "\n").encode("utf-8")
    with open(directory / "commands.jsonl", "ab") as stream:
        stream.write(line)                                    # one write of one complete line: the runner only consumes lines that end with a newline
        stream.flush()
        os.fsync(stream.fileno())
    return command["command_id"]


def read_events(directory):
    path = Path(directory) / "events.jsonl"
    if not path.exists():
        return []
    rows = []
    for line in path.read_bytes().decode("utf-8", errors="replace").splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    return rows


def wait_outcome(directory, command_id, timeout_s):
    deadline = time.monotonic() + timeout_s
    while True:
        for row in read_events(directory):
            if row.get("command_id") == command_id and row.get("kind") in ("COMMAND_APPLIED", "COMMAND_REJECTED"):
                return row
        if time.monotonic() >= deadline:
            return None
        time.sleep(0.1)


REPLACE_ATTEMPTS = 20
REPLACE_PAUSE_S = 0.05


def replace_status(temporary, target, *, attempts=None, pause_s=None, sleep=time.sleep):
    """The atomic rename of a freshly written status file, with the bounded retry of `engineering/handoff.py`. Docker Desktop/Windows readers (the host-side
    `read_status` below) can briefly deny FILE_SHARE_DELETE, and the rename then fails with PermissionError (found live: `stb-l01`, 8 November 2026, which
    stopped the whole workload). Only the rename is retried, and only on PermissionError; a persistent denial is re-raised after the last attempt and stays a
    visible failure. Any other OSError is raised at once."""
    attempts = REPLACE_ATTEMPTS if attempts is None else attempts
    pause_s = REPLACE_PAUSE_S if pause_s is None else pause_s
    for attempt in range(attempts):
        try:
            os.replace(temporary, target)
            return attempt
        except PermissionError:
            if attempt == attempts - 1:
                raise
            sleep(pause_s)


def read_status(directory):
    path = Path(directory) / "status.json"
    for _ in range(5):                                        # the runner replaces the file atomically; a host read can still meet a transient sharing error
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            data["age_s"] = max(0.0, time.time() - path.stat().st_mtime)
            return data
        except (OSError, ValueError):
            time.sleep(0.1)
    return None


def format_status(status, device=None):
    if status is None:
        return "no status: the run has not created its control channel (is the run started and past the observer coverage start?)"
    stale = status["age_s"] > STALE_AFTER_S and status.get("phase") == "RUNNING"
    lines = [f'run {status["run_id"]}  phase {status["phase"]}{"  (STALE: no update for %.0f s)" % status["age_s"] if stale else ""}  offset {status["offset_ns"] / 1e9:.1f} s  utc {status["utc"]}']
    for name, d in sorted(status["devices"].items()):
        if device and name != device:
            continue
        attack = d["attack"]
        text = f'ATTACK {attack["anomaly"]} {attack["params"]} since {attack["started_utc"]}' if attack else "no attack"
        lines.append(f'  {name} profile {d["profile"]:1} user {d["username"]}  traffic {d["state"]:10}  {text}  sent {d["sent"]} acked {d["acked"]}')
    return "\n".join(lines)


def parse_params(pairs):
    out = {}
    for pair in pairs or ():
        key, sep, value = pair.partition("=")
        if not sep or not key:
            raise ControlRefused(f"--param expects key=value, got {pair!r}")
        try:
            out[key] = json.loads(value)
        except ValueError:
            raise ControlRefused(f"--param {key}: {value!r} is not a number") from None
    return out


def perform(directory, action, device, anomaly=None, params=None, operator_ref=None, timeout_s=15.0):
    """Validate, append and wait for the runner's outcome. Returns (ok, text)."""
    status = read_status(directory)
    if status is None or status.get("phase") != "RUNNING" or status["age_s"] > STALE_AFTER_S:
        return False, "REFUSED the run is not RUNNING (no fresh status); nothing was sent"
    if device not in status["devices"]:
        return False, f'REFUSED unknown device {device!r}; devices of this run: {", ".join(sorted(status["devices"]))}'
    try:
        command = make_command(action, device, anomaly, params, operator_ref)
    except ControlRefused as exc:
        return False, f"REFUSED {exc}"
    append_command(directory, command)
    outcome = wait_outcome(directory, command["command_id"], timeout_s)
    if outcome is None:
        return False, f'NO_OUTCOME command {command["command_id"]} was written but the runner did not answer within {timeout_s:.0f} s'
    if outcome["kind"] == "COMMAND_REJECTED":
        return False, f'REJECTED {outcome["reason"]}'
    return True, (f'{action.upper()} {device} {anomaly or ""} {outcome.get("params", "")} effective at offset {outcome["offset_ns"] / 1e9:.3f} s ({outcome["utc"]}); '
                  f'command {command["command_id"]} requested {command["requested_utc"]}').replace("  ", " ")


def shell(directory, operator_ref):
    """A small operator console: devices / anomalies / select D / start A [k=v ...] / stop / status / quit."""
    selected = None
    print("AZTA attack console. Commands: devices | anomalies | select DEVICE | start ANOMALY [k=v ...] | stop | status | quit")
    while True:
        try:
            line = input(f"[{selected or '-'}]> ").strip()
        except EOFError:
            return 0
        if not line:
            continue
        word, *rest = line.split()
        try:
            if word in ("quit", "exit"):
                return 0
            if word == "devices":
                print(format_status(read_status(directory)))
            elif word == "anomalies":
                print(format_catalogue())
            elif word == "status":
                print(format_status(read_status(directory), selected))
            elif word == "select" and rest:
                selected = rest[0]
            elif word in ("start", "stop") and selected:
                ok, text = perform(directory, word, selected, rest[0] if word == "start" and rest else None, parse_params(rest[1:]) if word == "start" else None, operator_ref)
                print(text)
            else:
                print("unknown command, or no device selected (use: select device02)")
        except (ControlRefused, IndexError) as exc:
            print(f"REFUSED {exc}")


def format_catalogue():
    rows = []
    for name, item in CATALOGUE.items():
        parameters = ", ".join(f'{k} (default {r["default"]}, range {r["min"]}..{r["max"]})' for k, r in item["params"].items())
        rows.append(f"  {name:8} {item['summary']}\n           parameters: {parameters}")
    return "\n".join(rows)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--operator-ref", default=None)
    parser.add_argument("--timeout-s", type=float, default=15.0)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("devices")
    sub.add_parser("anomalies")
    status = sub.add_parser("status")
    status.add_argument("--device")
    start = sub.add_parser("start")
    start.add_argument("--device", required=True)
    start.add_argument("--anomaly", required=True, choices=sorted(CATALOGUE))
    start.add_argument("--param", action="append", default=[], help="key=value, repeatable (see `anomalies`)")
    stop = sub.add_parser("stop")
    stop.add_argument("--device", required=True)
    sub.add_parser("shell")
    args = parser.parse_args(argv)
    try:
        directory = control_dir(args.run_id)
        if args.command == "anomalies":
            print(format_catalogue())
            return 0
        if args.command in ("devices", "status"):
            text = format_status(read_status(directory), getattr(args, "device", None))
            print(text)
            return 0 if not text.startswith("no status") else 1
        if args.command == "shell":
            return shell(directory, args.operator_ref)
        ok, text = perform(directory, args.command, args.device, getattr(args, "anomaly", None), parse_params(getattr(args, "param", None)), args.operator_ref, args.timeout_s)
        print(text)
        return 0 if ok else 1
    except ControlRefused as exc:
        print(f"REFUSED {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
