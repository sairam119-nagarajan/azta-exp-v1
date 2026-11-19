"""Per-message observer events of the collected fleet runs, with the partition role enforced at the door.

A run's observer session records every counted delivery of every bound device (`events.jsonl`: receive offset in ns on the observer's monotonic clock, payload size). The development
partition assignment (`configs/gate6b/partition_assignment.json`) gives each WHOLE run exactly one role; `load_run` refuses the reserved TEST role (and any run outside the assignment) before
a byte of the session is opened, so a study written on top of it cannot touch held-out evidence. Geometry: window 0 starts at the recorded coverage start; the design-excluded windows of the
assignment (lead-in 0, the truncated last eligible window 60 and the post-roll 61) bound the USABLE span [first, last) in ns; everything before it is kept only as history (a message before the
span still counts as "the last delivery" for `last_delivery_age_ms`, exactly as in the observer).
"""
from collections import namedtuple
import json
from pathlib import Path

from fleet import dataset

RUNS = dataset.spec.ROOT / "results" / "engineering" / "runs"
READABLE_ROLES = ("TRAIN", "VAL", "CAL", "DEVEVAL")
PRELIVE_SCHEMA = "azta.gate6c.prelive_partition_plan"         # the Gate 6C pre-live campaign: runs of the corrected benign chain (`engineering.live_path_a`), roles declared before collection
Run = namedtuple("Run", "run role start_ns width_ns usable_first_ns usable_last_ns events recorded_windows session")


class RoleRefused(ValueError):
    pass


def role_of(assignment, run):
    role = assignment["roles"].get(run)
    if role is None:
        raise RoleRefused(f"{run}: not a run of the partition assignment")
    if role not in READABLE_ROLES:
        raise RoleRefused(f"{run}: role {role} is reserved and is never opened by development studies")
    return role


def load_prelive_assignment(root=dataset.spec.ROOT):
    """The pre-live partition plan as an assignment: {run: role}, with window 0 and every post-roll window excluded (the plan's own rule)."""
    plan = json.loads((Path(root) / "configs" / "gate6c" / "prelive_partition_plan.json").read_text(encoding="utf-8"))
    if plan.get("schema") != PRELIVE_SCHEMA or not set(x["role"] for x in plan["runs"].values()) <= set(dataset.ROLES):
        raise dataset.DatasetRefused("not a valid pre-live partition plan")
    eligible = plan["eligible_windows"]
    return dict(schema=PRELIVE_SCHEMA, roles={run: x["role"] for run, x in plan["runs"].items()}, excluded_window_indices=[0] + list(range(eligible + 1, eligible + 12)), eligible_windows=eligible,
                conditions={run: x["segments"] for run, x in plan["runs"].items()})


CORE_PLAN = "configs/gate6c/core_partition_plan.json"
CORE_READABLE = {"CAL2": "CAL", "DEV2": "DEVEVAL"}          # core-campaign roles that map onto the readable roles of the door; DEV2_LOCKED maps onto nothing until the freeze marker unlocks it


def load_core_assignment(root=dataset.spec.ROOT, *, freeze_marker=None):
    """The pre-live assignment PLUS the runs of the core campaign (protocol CORE-P1): g6c-e01 = CAL2 (readable as CAL), g6c-e02 = DEV2_LOCKED.

    The development-evaluation run stays unreadable (`RoleRefused` at the door of `load_run`) unless `freeze_marker` is the path of a JSON file whose `schema` is
    `azta.gate6c.core_freeze` and whose `dev2_run` names the run: only then is it readable as DEVEVAL. The marker is written by the freeze step AFTER every candidate and its
    calibration exist, and the freeze commit precedes the first evaluation on the run; this function checks the marker, git history proves the order."""
    assignment = load_prelive_assignment(root)
    plan = json.loads((Path(root) / CORE_PLAN).read_text(encoding="utf-8"))
    if plan.get("schema") != PRELIVE_SCHEMA or plan.get("core") is not True:
        raise dataset.DatasetRefused("not a valid core partition plan")
    unlocked = None
    if freeze_marker is not None:
        marker = json.loads(Path(freeze_marker).read_text(encoding="utf-8"))
        if marker.get("schema") != "azta.gate6c.core_freeze" or marker.get("dev2_run") not in plan["runs"] or not marker.get("candidate_record_sha256"):
            raise dataset.DatasetRefused("the freeze marker does not name the DEV2 run and the digest of the frozen candidate record")
        unlocked = marker["dev2_run"]
    roles = dict(assignment["roles"])
    for run, item in plan["runs"].items():
        role = item["role"]
        if role == "DEV2_LOCKED":
            roles[run] = "DEVEVAL" if run == unlocked else role          # any other value is refused by `role_of`
        elif role in CORE_READABLE:
            roles[run] = CORE_READABLE[role]
        else:
            raise dataset.DatasetRefused(f"{run}: unknown core role {role}")
    conditions = dict(assignment["conditions"], **{run: x["segments"] for run, x in plan["runs"].items()})
    return dict(assignment, roles=roles, conditions=conditions, core=True)


def accept_live_path_run(base, run):
    """A pre-live run is usable only if the orchestrator reports the observer and the workload clean, every binding audit PASSED and the observer session COMPLETE."""
    log = (base / "logs" / "orchestrator.log").read_text(encoding="utf-8").splitlines()
    audits = [line for line in log if " audit-" in line]
    if not any("observer_failed=False observer_exit=0 workload_exit=0" in line for line in log) or any("BINDING_AUDIT PASS" not in line for line in audits):
        raise dataset.DatasetRefused(f"{run}: the orchestrator log does not show a clean run")
    sessions = [p for p in (base / "observation").iterdir() if p.is_dir()]
    if len(sessions) != 1 or json.loads((sessions[0] / "session_summary.json").read_text(encoding="utf-8")).get("state") != "COMPLETE":
        raise dataset.DatasetRefused(f"{run}: the observer session is not COMPLETE")


def load_run(run, assignment=None, runs_root=RUNS):
    assignment = assignment or dataset.load_assignment()
    role = role_of(assignment, run)
    base = Path(runs_root) / run
    if assignment.get("schema") == PRELIVE_SCHEMA:
        accept_live_path_run(base, run)
    else:
        reconciliation = json.loads((base / f"gate5d3_reconcile_{run}.json").read_text(encoding="utf-8"))
        if reconciliation.get("verdict") != "CONSISTENT":
            raise dataset.DatasetRefused(f"{run}: reconciliation is {reconciliation.get('verdict')}, not CONSISTENT")
    sessions = sorted(p for p in (base / "observation").iterdir() if p.is_dir())
    if len(sessions) != 1:
        raise dataset.DatasetRefused(f"{run}: expected one observer session, found {len(sessions)}")
    session = sessions[0]
    windows = [json.loads(line) for line in (session / "windows.jsonl").read_text(encoding="utf-8").splitlines()]
    first = min(w["window"]["start_offset_ns"] for w in windows)
    width = windows[0]["window"]["duration_ns"]
    excluded = set(assignment["excluded_window_indices"])
    usable = sorted({w["window"]["index"] for w in windows} - excluded)
    events = {}
    for line in (session / "events.jsonl").read_text(encoding="utf-8").splitlines():
        e = json.loads(line)
        if e.get("binding_status") == "BOUND" and e.get("disposition") == "COUNTED":
            events.setdefault(e["bound_device"], []).append((e["receive_offset_ns"], e["payload_bytes"]))
    for rows in events.values():
        rows.sort()
    recorded = {}
    for w in windows:
        recorded.setdefault(w["device"], {})[w["window"]["index"]] = w
    return Run(run, role, first, width, first + usable[0] * width, first + (usable[-1] + 1) * width, events, recorded, session.name)


def runs_of_role(role, assignment=None):
    assignment = assignment or dataset.load_assignment()
    if role not in READABLE_ROLES:
        raise RoleRefused(f"role {role} is reserved")
    if assignment.get("schema") == PRELIVE_SCHEMA:
        def finished(run):          # a run in progress is not a run yet: its orchestrator log has no closing line
            log = RUNS / run / "logs" / "orchestrator.log"
            return log.exists() and "observer_failed=False observer_exit=0 workload_exit=0" in log.read_text(encoding="utf-8")
        return sorted(r for r, x in assignment["roles"].items() if x == role and finished(r))
    return sorted(r for r, x in assignment["roles"].items() if x == role and (RUNS / r / f"gate5d3_reconcile_{r}.json").exists())
