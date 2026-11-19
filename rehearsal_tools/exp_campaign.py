"""Formal Experimental Validation (AZTA-EXP-v1, addendum 1): the unattended runner of one batch of SHADOW sessions (no owner, no policy change), one run after another:
verify -> run -> finish -> validity, with every result appended to the campaign ledger. It never starts an active (policy-changing) session.

    python -I -B rehearsal_tools/exp_campaign.py --batch S1 --source-commit C        # resumes: runs already VALID or VOID in the ledger are skipped
    (create results/engineering/formal/CAMPAIGN_STOP to stop after the current run)

Rules (experiment matrix, declared before the data):
  * a VOID run is kept in the ledger and replaced once by the next spare of this batch (exp-s36..s40 for DETECTION/BENIGN, exp-s41..s45 one to one for exp-s26..s30);
  * the campaign STOPS on a failed verification, a STOP verdict (safety), a second consecutive VOID with the same failed checks, or the stop file;
  * after a STOP it continues only with --after-review REF, naming the owner's recorded written review (addendum 2); a REVIEWED row is then appended to the ledger.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "rehearsal_tools")]

import exp_validity                                # noqa: E402

PY = str(ROOT / ".venv" / "Scripts" / "python.exe")
MATRIX = "configs/formal/exp_matrix_v1.json"
FORMAL = ROOT / "results/engineering/formal"
LEDGER = FORMAL / "campaign_ledger.jsonl"
STOP_FILE = FORMAL / "CAMPAIGN_STOP"


def utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(text, stream=None):
    line = f"{utc()} {text}"
    print(line, flush=True)


def ledger():
    return exp_validity.jsonl(LEDGER)


def append(entry):
    FORMAL.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(dict(entry, utc=utc()), sort_keys=True) + "\n")


def step(run_id, *command):
    result = subprocess.run([PY, "-I", "-B", "rehearsal_tools/exp_session.py", "--run", run_id, *command], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5400)
    side = ROOT / "results/engineering/pilot" / f"{run_id}-session"
    side.mkdir(parents=True, exist_ok=True)
    with (side / f"campaign_{command[0]}.log").open("a", encoding="utf-8") as stream:
        stream.write(result.stdout + "\n--- stderr ---\n" + result.stderr)
    return result.returncode


def reviewed(answer_ref):
    """The owner's recorded written answer (exp_approve.py) that reviewed a STOP: a protocol addendum or a STOP review, matched by its answer reference."""
    for path in sorted((ROOT / "configs/formal/approvals").glob("*/owner_answer.json")):
        record = exp_validity.load(path)
        if record.get("answer_ref") == answer_ref and str(record.get("request", "")).startswith(("FORMAL_ADDENDUM_", "FORMAL_STOP_REVIEW")):
            return record
    return None


def spare_for(void_run, spec, spares, used):
    if spec["component"] == "SCI":
        wanted = f"exp-s{int(void_run[-2:]) + 15:02d}"
        return wanted if wanted in spares and wanted not in used else None
    return next((s for s in spares if s not in used and int(s[-2:]) <= 40), None)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--batch", choices=("S1", "S2"), required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--after-review", default=None, help="answer reference of the owner's recorded written review; required to continue a ledger that ends with a STOP")
    args = parser.parse_args(argv)
    m = json.loads((ROOT / MATRIX).read_text(encoding="utf-8"))
    batch = m["batches"][args.batch]
    primary = [r for r in batch if m["runs"][r]["component"] != "SPARE"]
    spares = [r for r in batch if m["runs"][r]["component"] == "SPARE"]
    rows = ledger()
    if rows and rows[-1].get("status") == "STOP":
        answer = reviewed(args.after_review) if args.after_review else None
        if answer is None:
            log("REFUSED: the ledger ends with a STOP; a person must review it before anything else runs (--after-review REF names the owner's recorded written answer)")
            return 4
        append(dict(run_id=rows[-1]["run_id"], as_run=rows[-1].get("as_run"), batch=args.batch, status="REVIEWED", reason="the owner's written review of the STOP", answer_ref=args.after_review,
                    answer_request=answer["request"]))
        log(f"the STOP after {rows[-1]['run_id']} was reviewed by the owner ({answer['request']}, {args.after_review}); the batch continues")
        rows = ledger()
    finished = {(r["run_id"], r.get("as_run")) for r in rows if r.get("status") in ("VALID", "VOID")}
    used = {r["run_id"] for r in rows}
    queue = [(r, None) for r in primary if (r, None) not in finished]
    for r in rows:                                  # a VOID primary whose replacement has not run yet (resume after an interruption)
        if r.get("status") == "VOID" and r.get("as_run") is None and r["run_id"] in primary and not any(x.get("as_run") == r["run_id"] for x in rows):
            spare = spare_for(r["run_id"], m["runs"][r["run_id"]], spares, used)
            if spare:
                queue.append((spare, r["run_id"]))
                used.add(spare)
    log(f"batch {args.batch}: {len(queue)} runs to do, {len(finished)} already finished")
    previous_void = None
    while queue:
        if STOP_FILE.exists():
            log("stop file present: the campaign stops before the next run")
            append(dict(run_id=queue[0][0], as_run=queue[0][1], batch=args.batch, status="NOT_STARTED", reason="stop file"))
            return 5
        run_id, as_run = queue.pop(0)
        used.add(run_id)
        log(f"{run_id}{' as ' + as_run if as_run else ''}: verify")
        code = step(run_id, "verify", "--source-commit", args.source_commit)
        if code != 0:
            pre = exp_validity.load(FORMAL / f"preconditions_{run_id}.json")
            failed = [k for k, v in (pre.get("checks") or {}).items() if v is not True]
            log(f"{run_id}: verification FAILED {failed}; the campaign stops (nothing was started)")
            append(dict(run_id=run_id, as_run=as_run, batch=args.batch, status="STOP", reason="verification failed", failed=failed))
            return 4
        log(f"{run_id}: run")
        run_args = ["run"] + (["--as", as_run] if as_run else [])
        run_code = step(run_id, *run_args)
        log(f"{run_id}: run exit {run_code}; finish")
        finish_code = step(run_id, "finish")
        verdict = exp_validity.validity(run_id, as_run)
        out = ROOT / "results/engineering/pilot" / run_id
        target = out if out.exists() else ROOT / "results/engineering/pilot" / f"{run_id}-session"
        (target / "validity.json").write_text(json.dumps(verdict, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        status = verdict["status"] if finish_code in (0,) or verdict["status"] == "STOP" else "STOP"
        entry = dict(run_id=run_id, as_run=as_run, batch=args.batch, component=verdict["component"], status=status, failed=verdict["failed"], run_exit=run_code, finish_exit=finish_code)
        append(entry)
        log(f"{run_id}: {status} {verdict['failed']}")
        if status == "STOP":
            log("STOP: a safety check failed; the campaign does not continue")
            return 4
        if status == "VOID":
            if previous_void == sorted(verdict["failed"]):
                log("STOP: a second consecutive VOID with the same failed checks")
                append(dict(run_id=run_id, as_run=as_run, batch=args.batch, status="STOP", reason="second consecutive VOID for the same cause", failed=verdict["failed"]))
                return 4
            previous_void = sorted(verdict["failed"])
            original = as_run or run_id
            if as_run is None:
                spare = spare_for(run_id, m["runs"][run_id], spares, used)
                if spare:
                    queue.append((spare, original))
                    used.add(spare)
                    log(f"{run_id} will be replaced by {spare} at the end of the batch")
                else:
                    log(f"{run_id}: no spare left in this batch; it stays VOID and unreplaced")
        else:
            previous_void = None
        time.sleep(5)
    log(f"batch {args.batch} complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
