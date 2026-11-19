"""The run assignment of protocol P1-FAM: which recorded runs a Phase 1 tool may open, enforced at the door.

Readable without a marker: TRAIN (g6c-d01..d03), VAL (g6c-d04) and CAL3 (g6c-f01, readable as the calibration role; the single-use marker of `family.calibrate` guards the one pass).
Readable only with the Phase 1 freeze marker: the two RE-USED development runs (g6c-d06, g6c-e02), which earlier campaigns inspected and which are therefore NOT fresh independent evidence.
Never readable: the consumed calibration runs (g6c-d05, g6c-e01), the reserved TEST runs (g6c-d07 and the Gate 6B TEST runs) and every run outside the plan: they are absent from the assignment,
so `hybrid.events.load_run` raises `RoleRefused` before a byte of the session is opened. The geometry (excluded windows, eligible windows) is that of the pre-live plan, unchanged.
"""
import json
from pathlib import Path

from fleet import dataset
from hybrid import events as ev

P1_PLAN = "configs/gate6c/p1_partition_plan.json"
FREEZE_SCHEMA = "azta.gate6c.p1_freeze"
TRAIN_RUNS = ("g6c-d01", "g6c-d02", "g6c-d03")
VAL_RUNS = ("g6c-d04",)
CAL3_RUNS = ("g6c-f01",)
DEV_REUSED_RUNS = ("g6c-d06", "g6c-e02")
NEVER_RUNS = ("g6c-d05", "g6c-e01", "g6c-d07", "g5d3a-fx-g6b09", "g5d3a-fx-g6b17")


class P1Refused(ValueError):
    pass


# ------------------------------------------------------------------------------------------------------------------------------ Phase 2 (protocol P2-REL)
P2_PLAN = "configs/gate6c/p2_partition_plan.json"
P2_FREEZE_SCHEMA = "azta.gate6c.p2_freeze"
CAL4_RUNS = ("g6c-h01", "g6c-h02")
DEV3_RUNS = ("g6c-h03", "g6c-h04", "g6c-h05", "g6c-h06", "g6c-h07")
P2_NEVER_RUNS = NEVER_RUNS_P2 = ("g6c-d05", "g6c-e01", "g6c-f01", "g6c-d07", "g5d3a-fx-g6b09", "g5d3a-fx-g6b17", "g6c-h00")


def load_p2_assignment(root=dataset.spec.ROOT, *, freeze_marker=None, diagnosis=False):
    """The Phase 2 assignment: TRAIN g6c-d01..d03, VAL g6c-d04, CAL4 g6c-h01/h02 (readable as CAL; the single-use marker guards the one pass), DEV3 g6c-h03..h07 (DEV3_LOCKED, refused, until
    `freeze_marker` names them and the digest of the frozen candidate record). `diagnosis=True` (the Phase 2 diagnosis tool only) adds the RE-USED runs g6c-d06/g6c-e02 as DEVEVAL and nothing
    else: it can be combined with neither a freeze marker nor any CAL4/DEV3 run. The consumed and reserved runs and the functional check g6c-h00 are absent, so the door refuses them."""
    root = Path(root)
    base = ev.load_prelive_assignment(root)
    plan = json.loads((root / P2_PLAN).read_text(encoding="utf-8"))
    if plan.get("schema") != ev.PRELIVE_SCHEMA or plan.get("p2") is not True or set(plan["runs"]) != set(CAL4_RUNS + DEV3_RUNS):
        raise P1Refused("not the Phase 2 partition plan this module knows")
    if tuple(plan["reused_runs"]["train"]) != TRAIN_RUNS or tuple(plan["reused_runs"]["val"]) != VAL_RUNS:
        raise P1Refused("the Phase 2 plan declares other TRAIN/VAL runs")
    roles = {run: "TRAIN" for run in TRAIN_RUNS}
    roles.update({run: "VAL" for run in VAL_RUNS})
    conditions = {run: base["conditions"][run] for run in TRAIN_RUNS + VAL_RUNS}
    if diagnosis:
        if freeze_marker is not None:
            raise P1Refused("the diagnosis assignment never unlocks the Phase 2 evaluation runs")
        p1 = load_p1_assignment(root, freeze_marker=root / "configs/gate6c/p1_freeze_01.json")
        roles.update({run: "DEVEVAL" for run in DEV_REUSED_RUNS})
        conditions.update({run: p1["conditions"][run] for run in DEV_REUSED_RUNS})
    else:
        unlocked = ()
        if freeze_marker is not None:
            marker = json.loads(Path(freeze_marker).read_text(encoding="utf-8"))
            if marker.get("schema") != P2_FREEZE_SCHEMA or tuple(marker.get("dev_runs", ())) != DEV3_RUNS or not marker.get("candidate_record_sha256"):
                raise P1Refused("the freeze marker does not name the DEV3 runs and the digest of the frozen candidate record")
            unlocked = DEV3_RUNS
        roles.update({run: "CAL" for run in CAL4_RUNS})
        roles.update({run: ("DEVEVAL" if run in unlocked else "DEV3_LOCKED") for run in DEV3_RUNS})
        conditions.update({run: plan["runs"][run]["segments"] for run in CAL4_RUNS + DEV3_RUNS})
    for run in P2_NEVER_RUNS:
        if run in roles:
            raise P1Refused(f"{run} must never be in the Phase 2 assignment")
    return dict(schema=ev.PRELIVE_SCHEMA, roles=roles, excluded_window_indices=base["excluded_window_indices"], eligible_windows=base["eligible_windows"], conditions=conditions, p2=True,
                diagnosis=diagnosis)


# ------------------------------------------------------------------------------------------------------------------------------ Phase 2 review (protocol P2R)
P2R_PLAN = "configs/gate6c/p2r_partition_plan.json"
P2R_FREEZE_SCHEMA = "azta.gate6c.p2r_freeze"
DEV4_RUNS = ("g6c-m01", "g6c-m02", "g6c-m03")            # protocol P2R amendment 1: g6c-k01..k03 are the Campaign 2 live pilot sessions
P2R_NEVER_RUNS = P2_NEVER_RUNS + CAL4_RUNS + DEV3_RUNS


def load_p2r_assignment(root=dataset.spec.ROOT, *, freeze_marker=None):
    """The review assignment: TRAIN g6c-d01..d03 and VAL g6c-d04 (for the offline pathway check only) and DEV4 g6c-m01..m03 (DEV4_LOCKED, refused, until `freeze_marker` names them and
    the digest of the candidate record). CAL4 (consumed) and DEV3 (the Phase 2 selection evidence) are absent, as are the consumed, reserved and functional runs: the door refuses them."""
    root = Path(root)
    base = ev.load_prelive_assignment(root)
    plan = json.loads((root / P2R_PLAN).read_text(encoding="utf-8"))
    if plan.get("schema") != ev.PRELIVE_SCHEMA or plan.get("p2r") is not True or set(plan["runs"]) != set(DEV4_RUNS):
        raise P1Refused("not the review partition plan this module knows")
    if tuple(plan["reused_runs"]["train"]) != TRAIN_RUNS or tuple(plan["reused_runs"]["val"]) != VAL_RUNS:
        raise P1Refused("the review plan declares other TRAIN/VAL runs")
    roles = {run: "TRAIN" for run in TRAIN_RUNS}
    roles.update({run: "VAL" for run in VAL_RUNS})
    conditions = {run: base["conditions"][run] for run in TRAIN_RUNS + VAL_RUNS}
    unlocked = ()
    if freeze_marker is not None:
        marker = json.loads(Path(freeze_marker).read_text(encoding="utf-8"))
        if marker.get("schema") != P2R_FREEZE_SCHEMA or tuple(marker.get("dev_runs", ())) != DEV4_RUNS or not marker.get("candidate_record_sha256"):
            raise P1Refused("the freeze marker does not name the DEV4 runs and the digest of the candidate record")
        unlocked = DEV4_RUNS
    roles.update({run: ("DEVEVAL" if run in unlocked else "DEV4_LOCKED") for run in DEV4_RUNS})
    conditions.update({run: plan["runs"][run]["segments"] for run in DEV4_RUNS})
    for run in P2R_NEVER_RUNS:
        if run in roles:
            raise P1Refused(f"{run} must never be in the review assignment")
    return dict(schema=ev.PRELIVE_SCHEMA, roles=roles, excluded_window_indices=base["excluded_window_indices"], eligible_windows=base["eligible_windows"], conditions=conditions, p2r=True)


def load_p1_assignment(root=dataset.spec.ROOT, *, freeze_marker=None):
    """The Phase 1 assignment as `hybrid.events.load_run` reads it: {run: role} over the runs above. `freeze_marker` (path of an `azta.gate6c.p1_freeze` JSON naming `dev_runs` and the digest
    of the frozen candidate record) unlocks the RE-USED development runs as DEVEVAL; without it they carry the role DEV_REUSED_LOCKED, which the door refuses."""
    root = Path(root)
    base = ev.load_prelive_assignment(root)
    plan = json.loads((root / P1_PLAN).read_text(encoding="utf-8"))
    core = json.loads((root / ev.CORE_PLAN).read_text(encoding="utf-8"))
    if plan.get("schema") != ev.PRELIVE_SCHEMA or plan.get("p1") is not True:
        raise P1Refused("not a valid Phase 1 partition plan")
    reused = plan["reused_runs"]
    if tuple(reused["train"]) != TRAIN_RUNS or tuple(reused["val"]) != VAL_RUNS or tuple(reused["dev_reused_not_fresh"]) != DEV_REUSED_RUNS or set(plan["runs"]) != set(CAL3_RUNS):
        raise P1Refused("the Phase 1 plan does not declare the runs this module knows")
    unlocked = ()
    if freeze_marker is not None:
        marker = json.loads(Path(freeze_marker).read_text(encoding="utf-8"))
        if marker.get("schema") != FREEZE_SCHEMA or tuple(marker.get("dev_runs", ())) != DEV_REUSED_RUNS or not marker.get("candidate_record_sha256"):
            raise P1Refused("the freeze marker does not name the re-used development runs and the digest of the frozen candidate record")
        unlocked = DEV_REUSED_RUNS
    roles = {}
    roles.update({run: "TRAIN" for run in TRAIN_RUNS})
    roles.update({run: "VAL" for run in VAL_RUNS})
    roles.update({run: "CAL" for run in CAL3_RUNS})
    roles.update({run: ("DEVEVAL" if run in unlocked else "DEV_REUSED_LOCKED") for run in DEV_REUSED_RUNS})
    conditions = {}
    for run in TRAIN_RUNS + VAL_RUNS + ("g6c-d06",):
        conditions[run] = base["conditions"][run]
    conditions["g6c-e02"] = core["runs"]["g6c-e02"]["segments"]
    conditions["g6c-f01"] = plan["runs"]["g6c-f01"]["segments"]
    for run in NEVER_RUNS:
        if run in roles:
            raise P1Refused(f"{run} must never be in the Phase 1 assignment")
    return dict(schema=ev.PRELIVE_SCHEMA, roles=roles, excluded_window_indices=base["excluded_window_indices"], eligible_windows=base["eligible_windows"], conditions=conditions, p1=True)
