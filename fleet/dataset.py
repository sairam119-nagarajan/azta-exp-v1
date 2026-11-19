"""Development window datasets of the ten-device FUNCTIONAL runs (`engineering.live_ten_device`) under a role assignment declared before inspection.

Reads only the observer's `windows.jsonl` of the runs the assignment names, validates every window with the frozen `observation.schema.validate_window`, checks the pins of the
ten-device registry, applies the six-feature readiness rule exactly as the frozen reader does (complete coverage and all six measures present; nothing imputed) and returns plain
records. The role of a run decides what its windows may be used for; windows of one run never appear in two roles. The functional runs are engineering evidence (not a scientific
partition): a run whose reconciliation is not CONSISTENT is refused.
"""
from collections import namedtuple
import json
from pathlib import Path

from observation.schema import PREDICTOR_CANDIDATES, candidate_vector, validate_window

from fleet import spec

Record = namedtuple("Record", "run role device index ready reason vector window_ref")
ROLES = ("TRAIN", "VAL", "CAL", "DEVEVAL", "TEST")
REASON_PRECEDENCE = ("OBSERVER_UNAVAILABLE", "NO_MESSAGES", "INSUFFICIENT_MESSAGES", "NEVER_OBSERVED_IN_SESSION")


class DatasetRefused(ValueError):
    pass


def load_assignment(root=spec.ROOT):
    data = json.loads((Path(root) / "configs" / "gate6b" / "partition_assignment.json").read_text(encoding="utf-8"))
    if data.get("schema") != "azta.gate6b.partition_assignment" or not set(data["roles"].values()) <= set(ROLES):
        raise DatasetRefused("not a valid partition assignment")
    return data


def classify(window):
    """(ready, reason, vector): the frozen R2 rule for a complete window of a registry-v2 observation."""
    statuses = {window["measures"][name]["status"] for name in PREDICTOR_CANDIDATES}
    if window["coverage"]["state"] != "COMPLETE":
        return False, "OBSERVER_UNAVAILABLE", None
    for reason in REASON_PRECEDENCE[1:]:
        if reason in statuses:
            return False, reason, None
    values, mask = candidate_vector(window)
    if not all(mask):
        return False, "SCHEMA_MISMATCH", None
    return True, None, tuple(float(v) for v in values)


def run_windows(runs_root, run_id):
    """The validated window records of ONE run's single observer session (all devices)."""
    base = Path(runs_root) / run_id
    reconciliation = json.loads((base / f"gate5d3_reconcile_{run_id}.json").read_text(encoding="utf-8"))
    if reconciliation.get("verdict") != "CONSISTENT":
        raise DatasetRefused(f"{run_id}: reconciliation is {reconciliation.get('verdict')}, not CONSISTENT")
    sessions = sorted(p for p in (base / "observation").iterdir() if p.is_dir())
    if len(sessions) != 1:
        raise DatasetRefused(f"{run_id}: expected one observer session, found {len(sessions)}")
    pins = spec.v2_pins()
    windows = []
    for line in (sessions[0] / "windows.jsonl").read_text(encoding="utf-8").splitlines():
        window = json.loads(line)
        validate_window(window)
        if (window["collection_run_id"] != run_id or window["purpose"] != "FUNCTIONAL_TEST" or window["identity"]["registry_sha256"] != pins["registry_sha256"]
                or window["observation_config_sha256"] != pins["observation_config_sha256"] or window["schema_fingerprint"] != pins["schema_fingerprint"]):
            raise DatasetRefused(f"{run_id}: a window carries other pins, purpose or run id")
        windows.append(window)
    return windows


def load_records(runs_root, assignment, roles=None):
    """Records of every assigned run (restricted to `roles`), design-excluded windows (lead-in, last eligible, lead-out) dropped."""
    excluded = set(assignment["excluded_window_indices"])
    records = []
    for run, role in sorted(assignment["roles"].items()):
        if roles is not None and role not in roles:
            continue
        if not (Path(runs_root) / run / f"gate5d3_reconcile_{run}.json").exists():
            continue          # not collected yet, or still running: only a finished run with a reconciliation report is read
        for window in run_windows(runs_root, run):
            index = window["window"]["index"]
            if index in excluded:
                continue
            ready, reason, vector = classify(window)
            records.append(Record(run, role, window["device"], index, ready, reason, vector,
                                  dict(collection_run_id=run, observer_session_id=window["observer_session_id"], device=window["device"], window_index=index)))
    return records


def by_device(records, role, device):
    return [r for r in records if r.role == role and r.device == device]
