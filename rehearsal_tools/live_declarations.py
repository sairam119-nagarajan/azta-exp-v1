"""Declarations of the live-adapter functional rehearsal: the authorized one (A), the late one that expires mid-run (B, built by the driver at attach time) and
the negative controls that must be REFUSED. Declarations are written outside the repository tree that Git tracks (results/raw/functional-prechecks/...).
Resolving a declaration opens NO evidence.

usage: python -I -B rehearsal_tools/live_declarations.py make <params.json>        (writes A and the negative controls, checks every one of them, prints a JSON report)
The same module serves the offline tooling dress rehearsal (params choose another run, plan and evidence root).
"""
import hashlib
import json
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO)]

from experiments import collection_plan as plans                # noqa: E402
from shadow_live import declaration                              # noqa: E402
from shadow_live.errors import LiveRefused                       # noqa: E402

BASELINE = "582efb4597b42d0cb6b5708d5a7a1c009a35bbf529e599155bb9783ce161f207"
RESERVE = ("configs/collection_manifests/g5f_scientific_v2_approved.jsonl", "configs/collection_manifests/gate5c_main.jsonl")
NS = 1_000_000_000
CFG = {}


def configure(params):
    CFG.update(run=params["run_id"], plan=params["plan"], evidence_root=params["evidence_root"], raw_access=params["raw_evidence_access"],
               prefix=params["live_prefix"], auth=params["authorization_ref"])


def utc_text(ns):
    seconds, rest = divmod(int(ns), NS)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(seconds)) + f".{rest:09d}Z"


def sha_file(rel):
    return hashlib.sha256((REPO / rel).read_bytes()).hexdigest()


def build(name, *, valid_from_ns, valid_until_ns, clock_tolerance_ns, stall_timeout_ns=30 * NS, **overrides):
    plan = json.loads((REPO / CFG["plan"]).read_text(encoding="utf-8"))
    raw = dict(authorized=True, reference=CFG["auth"]) if CFG["raw_access"] else dict(authorized=False, reference=None)
    data = dict(
        schema=declaration.DECLARATION_SCHEMA, schema_version=1, declaration_id=f"{CFG['prefix']}-{name}", authorization_ref=CFG["auth"], partition="FUNCTIONAL",
        run_id=CFG["run"], plan=dict(path=CFG["plan"], sha256=plans.digest(plan)), manifest=None, reserve_manifests=[dict(path=p, sha256=sha_file(p)) for p in RESERVE],
        evidence_root=CFG["evidence_root"], raw_evidence_access=raw, observer=dict(allow_legacy_observer=True), baseline_policy_sha256=BASELINE,
        validity=dict(valid_from_utc=utc_text(valid_from_ns), valid_until_utc=utc_text(valid_until_ns)),
        tolerances=dict(clock_tolerance_ns=int(clock_tolerance_ns), stall_timeout_ns=int(stall_timeout_ns)), audit_interval_s=30)
    data.update(overrides)
    return data


def write(directory, name, data):
    path = Path(directory) / f"declaration_{name}.json"
    blob = json.dumps(data, sort_keys=True, indent=1).encode("utf-8")
    with open(path, "xb") as stream:
        stream.write(blob)
    return path, hashlib.sha256(blob).hexdigest()


def check(path, digest):
    """(outcome, detail) of resolving a declaration exactly as the CLI does; resolution opens no evidence."""
    try:
        plan = declaration.load_declaration(REPO, path, authorized_sha256=digest)
        return "RESOLVED", plan.describe()
    except LiveRefused as exc:
        return "REFUSED", exc.code


def make(params_path):
    params = json.loads(Path(params_path).read_text(encoding="utf-8"))
    configure(params)
    directory = Path(params["directory"])
    directory.mkdir(parents=True, exist_ok=True)
    now = time.time_ns()
    base = dict(clock_tolerance_ns=params["clock_tolerance_ns"], stall_timeout_ns=params["stall_timeout_ns"])
    report = dict(created_utc=utc_text(now), authorization_ref=CFG["auth"], parameters=params, declarations={}, negative_controls={})
    positive = build("A", valid_from_ns=now - 3600 * NS, valid_until_ns=now + params["validity_a_hours"] * 3600 * NS, **base)
    path, digest = write(directory, "A", positive)
    outcome, detail = check(path, digest)
    report["declarations"]["A"] = dict(path=str(path), sha256=digest, outcome=outcome, resolved=detail if outcome == "RESOLVED" else None,
                                       code=None if outcome == "RESOLVED" else detail)
    controls = {
        "D_test_partition": ("PARTITION_LOCKED", dict(partition="D_test")),
        "CAL_V2_partition": ("PARTITION_LOCKED", dict(partition="CAL_V2")),
        "B_cal_partition": ("PARTITION_LOCKED", dict(partition="B_cal")),
        "scientific_run_id_under_functional": ("RUN_NOT_PLANNED", dict(run_id="g5f-r08")),
        "wrong_plan_digest": ("PLAN_DIGEST_MISMATCH", dict(plan=dict(path=CFG["plan"], sha256="0" * 64))),
        "unknown_field": ("DECLARATION_INVALID", dict(extra_field=1)),
    }
    if CFG["raw_access"]:
        controls["raw_evidence_not_authorized"] = ("RAW_EVIDENCE_NOT_AUTHORIZED", dict(raw_evidence_access=dict(authorized=False, reference=None)))
    for index, (label, (expected, override)) in enumerate(controls.items()):
        neg_path, neg_digest = write(directory, f"neg_{label}", dict(positive, declaration_id=f"{CFG['prefix']}-neg{index}", **override))
        outcome, detail = check(neg_path, neg_digest)
        report["negative_controls"][label] = dict(expected_code=expected, outcome=outcome, code=detail if outcome == "REFUSED" else None,
                                                  as_expected=outcome == "REFUSED" and detail == expected)
    expired = build("neg_expired", valid_from_ns=now - 7200 * NS, valid_until_ns=now - 3600 * NS, **base)
    neg_path, neg_digest = write(directory, "neg_expired", expired)
    outcome, _ = check(neg_path, neg_digest)                              # an expired declaration resolves (it opens nothing); the SESSION START refuses it
    report["negative_controls"]["expired_validity"] = dict(path=str(neg_path), sha256=neg_digest, resolves=outcome == "RESOLVED",
                                                           note="refused at session start with AUTHORIZATION_NOT_VALID_NOW (exercised separately)")
    bad = check(path, "1" * 64)
    report["negative_controls"]["wrong_authorized_digest"] = dict(expected_code="DECLARATION_DIGEST_MISMATCH", outcome=bad[0], code=bad[1],
                                                                  as_expected=bad == ("REFUSED", "DECLARATION_DIGEST_MISMATCH"))
    Path(directory, "declarations_report.json").write_text(json.dumps(report, indent=1, sort_keys=True), encoding="utf-8")
    refused_ok = all(item.get("as_expected", True) for item in report["negative_controls"].values())
    print(json.dumps(dict(A=report["declarations"]["A"]["outcome"], A_sha256=digest, negative_controls_as_expected=refused_ok), sort_keys=True))
    return 0 if refused_ok and report["declarations"]["A"]["outcome"] == "RESOLVED" else 1


if __name__ == "__main__":
    sys.exit(make(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[1] == "make" else 2)
