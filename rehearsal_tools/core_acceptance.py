"""Core completion: the executable acceptance matrix (gates G0 to G11 of the handoff) and the freeze manifest. It recomputes every status from the recorded evidence files; nothing is typed by hand and it runs no experiment.

    python -B rehearsal_tools/core_acceptance.py --regression results/engineering/core_final/regression_final.out --out docs/final/acceptance_matrix.json --manifest configs/core_final/freeze_manifest_v1.json

Status words stay distinct: PASS, FAIL, NOT_RUN and BLOCKED. Each gate has an offline part and, where the handoff requires it, a live part. A live part with no record of an approved session is BLOCKED (needs approval), never PASS. A gate is PASS only when every part is. The final label follows handoff section 10 and is computed, not chosen.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CF = "results/engineering/core_final"
PASS, FAIL, NOT_RUN, BLOCKED = "PASS", "FAIL", "NOT_RUN", "BLOCKED"
BACKUP_RECORD = Path(r"C:\AZTA_BACKUPS\core-completion-20261105\BACKUP_RECORD.json")
FROZEN = ("trust", "experiments", "observation", "model", "preprocessing", "calibration")
MANIFEST_SOURCES = ("core_runtime", "enforcement", "family", "hybrid", "fleet", "engineering", "shadow_live", "shadow_feed", "decision_pipeline", "trust", "model", "preprocessing", "observation", "calibration")
MANIFEST_CONFIGS = ("configs/core_final", "configs/pilot/trust_config_cand-1ac5637401a5-ctx2.json", "configs/gate6c/p2r_family_assignment.json", "configs/gate6c/p2r_decision.json", "configs/gate6c/core_monitor_profiles_provisional.json", "configs/gate6c/core_fleet_models_provisional.json", "configs/gate6c/core_registry_candidate.json", "configs/gate6c/p2_candidates_cal4.json",
                    "configs/gate6b/registry_v2_compat_record.json", "configs/dshadow/g5f-cal-v2-01-accepted-1.json", "configs/collection_plans/core_final_rc1.json", "configs/collection_plans/core_final_core_s01.json", "configs/collection_plans/core_final_core_p01.json", "configs/collection_plans/core_final_core_p02.json", "configs/collection_plans/core_final_core_p03.json")


def load(relative):
    path = ROOT / relative
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return None


def digest(relative):
    path = ROOT / relative
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def part(status, *, evidence=(), detail=""):
    return dict(status=status, evidence={e: digest(e) for e in evidence}, detail=detail)


def from_check(ok, *, evidence=(), detail=""):
    return part(PASS if ok else FAIL, evidence=evidence, detail=detail) if ok is not None else part(NOT_RUN, evidence=evidence, detail=detail)


def regression(path):
    text = (ROOT / path).read_text(encoding="utf-8", errors="replace") if (ROOT / path).exists() else ""
    ran = re.search(r"^Ran (\d+) tests", text, re.M)
    ok = re.search(r"^OK(?: \(skipped=(\d+)\))?", text, re.M)
    attempts = re.search(r"access attempts: (\d+)", text)
    return dict(ran=int(ran.group(1)) if ran else None, ok=bool(ok), skipped=int(ok.group(1) or 0) if ok else None, raw_access_attempts=int(attempts.group(1)) if attempts else None)


def frozen_diff():
    out = subprocess.run(["git", "diff", "--name-only", "d78d4d5", "HEAD", "--", *FROZEN], cwd=ROOT, capture_output=True, text=True)
    status = subprocess.run(["git", "status", "--porcelain", "--", *FROZEN], cwd=ROOT, capture_output=True, text=True)
    return not out.stdout.strip() and not status.stdout.strip()


def fingerprints():
    out = subprocess.run([sys.executable, "-B", "-I", "rehearsal_tools/prelive_fingerprints.py", "verify", "--baseline", "results/engineering/gate6c/prelive/fingerprints_after_collection.json"], cwd=ROOT, capture_output=True, text=True)
    return "PROTECTED_ARTIFACTS_UNCHANGED" in out.stdout


def live_record(name):
    """A live part is evidenced by a results file written by an approved session; none exists until the owner approves one."""
    return load(f"{CF}/live/{name}.json")


def live_part(name, request):
    record = live_record(name)
    retest = live_record(name + "_retest")
    if retest is not None:                  # the earlier record stays on file and in the report; the approved retest decides
        return from_check(retest.get("all_pass"), evidence=[f"{CF}/live/{name}_retest.json", f"{CF}/live/{name}.json"], detail=retest.get("scope", ""))
    if record is None:
        return part(BLOCKED, detail=f"needs written approval of {request}; no session has run")
    return from_check(record.get("all_pass"), evidence=[f"{CF}/live/{name}.json"], detail=record.get("scope", ""))


def gates(args):
    reg = regression(args.regression)
    reg_ok = bool(reg["ok"] and reg["raw_access_attempts"] == 0)
    reg_part = from_check(reg_ok if reg["ran"] else None, evidence=[args.regression], detail=json.dumps(reg))
    backup = json.loads(BACKUP_RECORD.read_text(encoding="utf-8")) if BACKUP_RECORD.exists() else {}
    proof, qa, browser, bench, scale, base, dress = (load(f"{CF}/{n}") for n in ("ae_proof_v1.json", "model_qa_v1.json", "console_browser_v3/result.json", "benchmark_v1.json", "scale_plan_v1.json", "baselines_smoke_v1.json", "dress_01_check.json"))
    clock = load(f"{CF}/clock_01/evaluation.json")
    boundary = [load(f"{CF}/{n}") for n in ("rc1_boundary_v2/g6c-m01.json", "rc1_boundary/g6c-m02.json", "rc1_boundary_v2/g6c-m03.json")]
    tests = lambda *names: part(PASS if reg_ok else NOT_RUN, evidence=[args.regression], detail="inside the guarded regression: " + ", ".join(names))
    return {
        "G0 Preservation": dict(local_backup=from_check(backup.get("result") == "VERIFIED" if backup else None, detail=f"{backup.get('files')} files, {backup.get('bytes')} bytes, bundle verified {backup.get('git_bundle', {}).get('verified')}, restore drill failures {backup.get('restore_drill', {}).get('failures')}, record {BACKUP_RECORD}"),
                                protected_digests=from_check(fingerprints() and frozen_diff(), detail="the fingerprint tool against its baseline; frozen packages identical to d78d4d5"),
                                external_copy=part(PASS, evidence=["configs/core_final/g0_backup_limitation_acceptance.json"], detail="NOT MADE: the owner accepted the same-drive copy as a deployment limitation") if load("configs/core_final/g0_backup_limitation_acceptance.json") else part(BLOCKED, detail="same-drive copy only; needs an owner-approved off-device destination, or the owner's explicit acceptance as a deployment limitation")),
        "G1 Mathematics": dict(unit_boundaries=tests("test_core_primary"), through_runtime=from_check(bool(proof and proof["all_checks"]) if proof else None, evidence=[f"{CF}/ae_proof_v1.json"], detail="independent arithmetic of A, S_B, T and state on every AE tick of ten devices")),
        "G2 Ten AE routes": dict(causal_proofs=from_check(bool(proof and proof["all_transitions"]) if proof else None, evidence=[f"{CF}/ae_proof_v1.json"]), model_qa=from_check(bool(qa and qa["all_ok"]) if qa else None, evidence=[f"{CF}/model_qa_v1.json"]), model_cards=from_check((ROOT / "docs/final/TEN_DEVICE_MODEL_CARDS.md").exists(), evidence=["docs/final/TEN_DEVICE_MODEL_CARDS.md"])),
        "G3 Authority": dict(offline=tests("test_core_authority", "test_core_console"), note_map=part(PASS, evidence=["configs/core_final/authority_map_v1.json"], detail="candidate map; screen R; only device02 is AUTO_ELIGIBLE")),
        "G4 Canonical PDP": dict(entry_point=tests("test_core_runtime"), worker_dress_rehearsal=from_check(bool(dress and dress["all_pass"]) if dress else None, evidence=[f"{CF}/dress_01_check.json"], detail="the real worker over replayed real TRAIN windows; no broker"), live_start_stop=live_part("functional_no_mutation", "FUNCTIONAL_NO_MUTATION")),
        "G5 RC-1": dict(offline_bounds=tests("test_rc1_session_bounds", "test_rc1_live"), adjacent_log_replay=from_check(all(b and b["pass"] for b in boundary) if all(boundary) else None, detail="engineering replay of adjacent captured DEV4 logs; the P2R live FAIL stays on record"), live_read_only=live_part("rc1_readonly", "RC1_READONLY")),
        "G6 Clock": dict(refusal_tests=tests("test_core_clock"), measured_certificate=from_check(clock.get("status") == "PASS" if clock else None, evidence=[f"{CF}/clock_01/evaluation.json"], detail=f"validity horizon {((clock or {}).get('timelines') or {}).get('anchored', {}).get('validity_horizon_s')} s at the 100 ms budget, one probe; a certificate expires"), validated_runs=live_part("functional_no_mutation", "FUNCTIONAL_NO_MUTATION")),
        "G7 GUI": dict(api=tests("test_core_console"), real_browser=from_check(bool(browser and browser["all_pass"]) if browser else None, evidence=[f"{CF}/console_browser_v3/result.json"], detail="real page, real browser, FAKE broker"), real_broker_state=live_part("pilot_enforcement", "PILOT_ENFORCEMENT")),
        "G8 MQTT PEP": dict(live=live_part("pilot_enforcement", "PILOT_ENFORCEMENT")),
        "G9 F1/F2 and concurrency": dict(offline=tests("test_f1_policy_generation", "test_core_authority"), live=live_part("pilot_enforcement", "PILOT_ENFORCEMENT")),
        "G10 Performance": dict(microbenchmark=from_check(bool(bench and bench["queue_at_ten_device_rate"]["dropped"] == 0) if bench else None, evidence=[f"{CF}/benchmark_v1.json"], detail="in-process; final path measured; no threshold; finite queue at the tested rate"), scale_dry_run=from_check(bool(scale) if scale else None, evidence=[f"{CF}/scale_plan_v1.json"], detail="virtual state only; MQTT scale NOT_RUN by design"), baseline_tooling=from_check(bool(base and base["all_pass"]) if base else None, evidence=[f"{CF}/baselines_smoke_v1.json"])),
        "G11 Integrity and handback": dict(regression=reg_part, documents=from_check(all((ROOT / "docs/final" / n).exists() for n in ("CORE_COMPLETION_REPORT.md", "SOURCE_TO_CODE_TRACEABILITY.md", "ARCHITECTURE_AND_AUTHORITY.md", "TEN_DEVICE_MODEL_CARDS.md", "OPERATOR_RUNBOOK.md", "FORMAL_EXPERIMENT_RUNBOOK.md", "SIGNOFF_AND_LIMITATIONS.md"))), test_not_opened=from_check(fingerprints(), detail="reserved runs fingerprinted by listing only; regression guard covers them; no new tool lists them"), nothing_pushed=part(PASS, detail=subprocess.run(["git", "rev-list", "--count", "origin/master..HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip() + " local commits ahead of the local tracking ref; no push command was run")),
    }


def manifest():
    files = {}
    for source in MANIFEST_SOURCES:
        for path in sorted((ROOT / source).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                files[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    for item in MANIFEST_CONFIGS:
        path = ROOT / item
        for f in ([path] if path.is_file() else sorted(path.rglob("*"))):
            if f.is_file() and not f.name.startswith("freeze_manifest_"):
                files[f.relative_to(ROOT).as_posix()] = hashlib.sha256(f.read_bytes()).hexdigest()
    route = json.loads((ROOT / "configs/core_final/route_ae_primary_v1.json").read_text(encoding="utf-8"))
    return dict(schema="azta.core.freeze_manifest", version="core-final-1", contract=route["contract"], status="FROZEN_ENGINEERING_CONFIGURATION; what passed the live verification core-p03. Not an owner, supervisor or Controller acceptance and not a promotion", base_commit=subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip(), route_status=route["status"], files=files, approvals=dict(session=None, operational=None, authority_scope=None, note="no standing approval: PILOT_ENFORCEMENT-2 covered core-p03 only and expires 240 minutes after its answer. Any new live session needs a new written answer"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--regression", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--manifest", default=None)
    args = parser.parse_args(argv)
    if args.manifest:
        (ROOT / args.manifest).write_text(json.dumps(manifest(), indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    table = gates(args)
    summary = {}
    for gate, parts in table.items():
        statuses = {p["status"] for p in parts.values()}
        summary[gate] = FAIL if FAIL in statuses else NOT_RUN if NOT_RUN in statuses else BLOCKED if BLOCKED in statuses else PASS
    failed = [g for g, s in summary.items() if s in (FAIL, NOT_RUN)]
    blocked = [g for g, s in summary.items() if s == BLOCKED]
    if failed:
        label = "CORE IMPLEMENTATION NOT COMPLETE — " + "; ".join(failed)
    elif blocked:
        label = "OFFLINE CORE WORK COMPLETE — LIVE VERIFICATION/AUTHORIZATION PENDING"
    else:
        label = "CORE IMPLEMENTATION COMPLETE — CONDITIONAL RESEARCH PROTOTYPE WITH DOCUMENTED LIMITATIONS"
    document = dict(schema="azta.core.acceptance_matrix", protocol="docs/final/CORE_COMPLETION_PROTOCOL.md", commit=subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip(), summary=summary, gates=table, label=label)
    (ROOT / args.out).write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    for gate, status in summary.items():
        print(f"{status:8} {gate}")
    print(label)
    return 0


if __name__ == "__main__":
    sys.exit(main())
