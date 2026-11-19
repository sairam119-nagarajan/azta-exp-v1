"""Formal Experimental Validation (AZTA-EXP-v1, addendum 1): turn the owner's WRITTEN answers into the pinned records the formal sessions check. It runs only to record an answer
the owner actually gave; it never authors one. It reuses the frozen record writers of `core_final_approve.py` (`write`, `enforcement_records`) and the frozen field set of
`core_runtime.cli.check_session_approval`.

    python -B rehearsal_tools/exp_approve.py test   --answer-ref REF --approved-by NAME --verbatim TEXT     # FORMAL_TEST_AUTHORIZATION (no expiry; binds the release digests)
    python -B rehearsal_tools/exp_approve.py shadow --batch S1|S2 --answer-ref REF --approved-by NAME          # session records for one shadow batch, under the recorded test authorization
    python -B rehearsal_tools/exp_approve.py active --answer-ref REF --approved-by NAME --verbatim TEXT --valid-minutes N   # the owner's Friday approval of the device02 block
    python -B rehearsal_tools/exp_approve.py amend  --number 2 --answer-ref REF --approved-by NAME --verbatim TEXT          # the owner's acceptance of a protocol addendum

Session records are valid for at most 720 minutes (the frozen limit), so the two shadow batches are recorded separately, each from the same test authorization.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "rehearsal_tools")]

import core_final_approve as cfa                  # noqa: E402  (frozen writers)
from core_runtime import cli                      # noqa: E402

MATRIX = "configs/formal/exp_matrix_v1.json"
PROTOCOL = "docs/final/AZTA_FORMAL_EXPERIMENT_PROTOCOL.md"
APPROVALS = ROOT / "configs/formal/approvals"
TEST_DIR = APPROVALS / "FORMAL_TEST_AUTHORIZATION"
ADDENDUM = "configs/formal/AZTA-EXP-v1_formal_addendum_manifest.json"
FREEZE = "configs/exp_v1/AZTA-EXP-v1_freeze_manifest.json"
ACTIVE_SCOPE = {"device02": ["RESTRICT", "QUARANTINE", "RESTORE"]}


def sha(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def session_approval(path, *, request, answer_ref, mode, run_id, approved_by, issued, expires):
    return cfa.write(path, dict(schema=cli.APPROVAL_SCHEMA, request_id=f"{request}:{answer_ref}", purpose=request, mode=mode, run_id=run_id, approved_by=approved_by,
                                approved_utc_ns=issued, expires_utc_ns=expires, protocol_sha256=sha(PROTOCOL), route_sha256=sha(cli.ROUTE), authority_map_sha256=sha(cli.AUTHORITY)))


def test(args):
    import exp_addendum
    check = exp_addendum.verify_all()
    if check["problems"]:
        raise SystemExit(f"REFUSED: the release does not verify: {check['problems'][:5]}")
    TEST_DIR.mkdir(parents=True, exist_ok=False)
    record = dict(schema="azta.formal.owner_answer", request="FORMAL_TEST_AUTHORIZATION", answer_ref=args.answer_ref, approver=args.approved_by, verbatim=args.verbatim,
                  recorded_utc_ns=time.time_ns(), expires=None, freeze_manifest=FREEZE, freeze_manifest_sha256=sha(FREEZE), addendum_manifest=ADDENDUM, addendum_manifest_sha256=sha(ADDENDUM),
                  experiment_matrix=MATRIX, experiment_matrix_sha256=sha(MATRIX), protocol=PROTOCOL, protocol_sha256=sha(PROTOCOL),
                  consequences=["the reserved TEST runs may be opened ONCE and scored by the frozen release (exp_test_score.py, single-use marker)",
                                "non-enforcing (shadow) formal sessions of the matrix may run unattended; their session records are written per batch from this answer",
                                "no model, threshold or configuration change after the TEST runs are opened; a change needs a new release identifier",
                                "every policy-changing session still needs its own written owner approval with the owner at the console"])
    digest = cfa.write(TEST_DIR / "owner_answer.json", record)
    print(json.dumps(dict(written=str((TEST_DIR / "owner_answer.json").relative_to(ROOT)), sha256=digest), indent=1))
    return 0


def amend(args):
    """The owner's written acceptance of a protocol addendum made after FORMAL_TEST_AUTHORIZATION (addendum 2: jitter not applicable to devices 05-09). It binds the new digests;
    the reserved TEST runs are NOT re-scored (single-use marker)."""
    import exp_addendum
    if not (TEST_DIR / "owner_answer.json").exists():
        raise SystemExit("REFUSED: FORMAL_TEST_AUTHORIZATION is not recorded")
    check = exp_addendum.verify_all()
    if check["problems"]:
        raise SystemExit(f"REFUSED: the release does not verify: {check['problems'][:5]}")
    request = f"FORMAL_ADDENDUM_{args.number}"
    doc = f"docs/final/AZTA_FORMAL_PROTOCOL_ADDENDUM_{args.number}.md"
    out = APPROVALS / request
    out.mkdir(parents=True, exist_ok=False)
    record = dict(schema="azta.formal.owner_answer", request=request, answer_ref=args.answer_ref, approver=args.approved_by, verbatim=args.verbatim, recorded_utc_ns=time.time_ns(),
                  expires=None, addendum_document=doc, addendum_document_sha256=sha(doc), freeze_manifest=FREEZE, freeze_manifest_sha256=sha(FREEZE), addendum_manifest=ADDENDUM,
                  addendum_manifest_sha256=sha(ADDENDUM), experiment_matrix=MATRIX, experiment_matrix_sha256=sha(MATRIX), protocol=PROTOCOL, protocol_sha256=sha(PROTOCOL),
                  consequences=["the amended matrix and scripts named by these digests replace the earlier ones for every run not yet made",
                                "the reserved TEST runs are NOT re-scored; the single scoring already made stands",
                                "runs already made keep their recorded verdicts; a STOP reviewed by this answer may be continued (exp_campaign.py --after-review)",
                                "no model, threshold or configuration of AZTA-EXP-v1 changes"])
    digest = cfa.write(out / "owner_answer.json", record)
    print(json.dumps(dict(written=str((out / "owner_answer.json").relative_to(ROOT)), sha256=digest), indent=1))
    return 0


def latest_answer():
    """The most recent recorded owner answer that binds the release digests: FORMAL_TEST_AUTHORIZATION or a later protocol addendum."""
    paths = [TEST_DIR / "owner_answer.json"] + sorted(APPROVALS.glob("FORMAL_ADDENDUM_*/owner_answer.json"))
    records = [json.loads(p.read_text(encoding="utf-8")) for p in paths if p.exists()]
    return max(records, key=lambda r: r["recorded_utc_ns"]) if records else None


def shadow(args):
    if not (TEST_DIR / "owner_answer.json").exists():
        raise SystemExit("REFUSED: FORMAL_TEST_AUTHORIZATION is not recorded")
    recorded = latest_answer()
    if recorded["addendum_manifest_sha256"] != sha(ADDENDUM) or recorded["experiment_matrix_sha256"] != sha(MATRIX) or recorded["protocol_sha256"] != sha(PROTOCOL):
        raise SystemExit("REFUSED: the release changed after the owner's latest recorded answer")
    m = json.loads((ROOT / MATRIX).read_text(encoding="utf-8"))
    request = f"FORMAL_SHADOW_{args.batch}"
    issued, expires = time.time_ns() - 1_000_000_000, time.time_ns() + 720 * 60 * 1_000_000_000
    printed = {}
    for run_id in m["batches"][args.batch]:
        out = APPROVALS / request / run_id
        out.mkdir(parents=True, exist_ok=False)
        printed[run_id] = session_approval(out / f"session_approval_{run_id}.json", request=request, answer_ref=args.answer_ref, mode="shadow", run_id=run_id,
                                           approved_by=args.approved_by, issued=issued, expires=expires)
    print(json.dumps(dict(request=request, runs=len(printed), expires_utc_ns=expires), indent=1))
    return 0


def active(args):
    if not 1 <= args.valid_minutes <= 720:
        raise SystemExit("--valid-minutes must be between 1 and 720")
    m = json.loads((ROOT / MATRIX).read_text(encoding="utf-8"))
    issued, expires = time.time_ns() - 1_000_000_000, time.time_ns() + args.valid_minutes * 60 * 1_000_000_000
    printed = {}
    for run_id in m["batches"]["A"]:
        spec = m["runs"][run_id]
        out = APPROVALS / "FORMAL_ACTIVE" / run_id
        out.mkdir(parents=True, exist_ok=False)
        approval = session_approval(out / f"session_approval_{run_id}.json", request="FORMAL_ACTIVE", answer_ref=args.answer_ref, mode="active-authorized", run_id=run_id,
                                    approved_by=args.approved_by, issued=issued, expires=expires)
        records = cfa.enforcement_records(out, role="OWNER", approved_by=args.approved_by, answer_ref=args.answer_ref, issued=issued, expires=expires, run_id=run_id,
                                          mode="active-authorized", automatic=("device02",), scope_actions=ACTIVE_SCOPE)
        cfa.write(out / "owner_answer.json", dict(schema="azta.formal.owner_answer", request="FORMAL_ACTIVE", answer_ref=args.answer_ref, approver=args.approved_by, verbatim=args.verbatim,
                                                  run_id=run_id, recorded_utc_ns=time.time_ns(), expires_utc_ns=expires))
        rel = out.relative_to(ROOT).as_posix()
        session = dict(approved_config=cli.CONFIG, approved_registry=f"{rel}/registry_approved.json", authority_scope=f"{rel}/authority_scope.json", authority_scope_sha256=records["authority_scope_sha256"],
                       authorization_ref="FORMAL_ACTIVE", baseline_policy_sha256=m["session"]["baseline_policy_sha256"], calibration_bundle=f"{rel}/calibration_bundle.json",
                       clock_session_s=m["session"]["clock_session_s"], dev_perturbation=f"configs/dev_perturbations/{run_id}.json", label=run_id, max_duration_s=m["session"]["max_duration_s"],
                       operational_approval=f"{rel}/operational_approval.json", operational_approval_sha256=records["operational_approval_sha256"],
                       plan=f"configs/collection_plans/core_final_{run_id.replace('-', '_')}.json", review_ttl_s=300, run_id=run_id)
        if spec.get("time_cut_after_s"):
            session.update(time_cut_device="device02", time_cut_after_s=spec["time_cut_after_s"])
        with (ROOT / "configs/formal/sessions" / f"{run_id}.json").open("xb") as stream:
            stream.write((json.dumps(session, indent=1, sort_keys=True) + "\n").encode("utf-8"))
        printed[run_id] = approval
    print(json.dumps(dict(request="FORMAL_ACTIVE", runs=len(printed), expires_utc_ns=expires, approvals=printed), indent=1))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    t = sub.add_parser("test")
    s = sub.add_parser("shadow")
    a = sub.add_parser("active")
    m = sub.add_parser("amend")
    for p in (t, s, a, m):
        p.add_argument("--answer-ref", required=True)
        p.add_argument("--approved-by", required=True)
    for p in (t, a, m):
        p.add_argument("--verbatim", required=True)
    m.add_argument("--number", type=int, required=True)
    a.add_argument("--valid-minutes", type=int, required=True)
    s.add_argument("--batch", choices=("S1", "S2"), required=True)
    args = parser.parse_args(argv)
    return dict(test=test, shadow=shadow, active=active, amend=amend)[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
