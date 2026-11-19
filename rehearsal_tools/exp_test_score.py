"""Formal Experimental Validation (AZTA-EXP-v1, addendum 1): the ONE scoring of the reserved TEST runs by the frozen release, after the owner's FORMAL_TEST_AUTHORIZATION.

    python -B -I rehearsal_tools/exp_test_score.py --out results/engineering/formal/test_scoring_v1.json            # single use: an exclusive marker is created before the first byte
    python -B -I rehearsal_tools/exp_test_score.py --dry-run g6c-d06 --out <scratch file>                               # plumbing check on a DEVEVAL run; no marker; labelled DRY_RUN

The reserved runs (`g6c-d07`, `g5d3a-fx-g6b09`, `g5d3a-fx-g6b17`) are benign ten-device runs, so every score-ready window is NEGATIVE: they give held-out benign evidence (false
flags, false non-FULL decisions, trust-state agreement and the T distribution) per device, never detection. Each recorded observer window is replayed through the frozen,
digest-verified evaluator (`core_runtime.loader.load_primary` with the frozen route) and the unchanged `DecisionEngine` with the frozen trust configuration, one fresh evaluator per run
and device, valid identity and conforming context (as recorded benign operation), exactly as the CAL5 replay did. Slow (monitor) devices are score-ready once per native window.
The frozen run loader (`hybrid.events.load_run`) refuses the TEST role by design; `load_reserved` below repeats its geometry for exactly these three runs, and the test suite checks that
it returns the same windows as the frozen loader on a readable run.
Nothing is fitted, calibrated, selected or tuned. The result is recorded as measured.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "rehearsal_tools")]

RESERVED = ("g6c-d07", "g5d3a-fx-g6b09", "g5d3a-fx-g6b17")
FORMAL = ROOT / "results/engineering/formal"
MARKER = FORMAL / "test_marker_v1.json"
AUTHORIZATION = ROOT / "configs/formal/approvals/FORMAL_TEST_AUTHORIZATION/owner_answer.json"
A_R = 6.931471805599452
NON_FULL = ("RESTRICT", "QUARANTINE")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def assignment_for(run):
    from fleet import dataset
    from hybrid import events as ev
    return ev.load_prelive_assignment() if run.startswith("g6c-") else dataset.load_assignment()


def load_reserved(run, assignment, runs_root=None):
    """`hybrid.events.load_run` without its role refusal, for one of the three named reserved runs only (or, for the equivalence test, a run of a readable role)."""
    from fleet import dataset
    from hybrid import events as ev
    runs_root = Path(runs_root) if runs_root else ev.RUNS
    role = assignment["roles"].get(run)
    if role is None:
        raise SystemExit(f"{run}: not a run of the partition assignment")
    base = runs_root / run
    if assignment.get("schema") == ev.PRELIVE_SCHEMA:
        ev.accept_live_path_run(base, run)
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
    usable = sorted({w["window"]["index"] for w in windows} - set(assignment["excluded_window_indices"]))
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
    return ev.Run(run, role, first, width, first + usable[0] * width, first + (usable[-1] + 1) * width, events, recorded, session.name)


def summary(values):
    values = sorted(v for v in values if isinstance(v, (int, float)))
    if not values:
        return dict(n=0)
    pick = lambda q: values[min(len(values) - 1, int(q * (len(values) - 1) + 0.5))]
    return dict(n=len(values), min=values[0], median=statistics.median(values), p05=pick(0.05), p95=pick(0.95), max=values[-1])


def score_run(run, assignment, evaluator, config, route):
    import core_ae_proof as proof
    from trust.engine import DecisionEngine
    out = {}
    for device, item in sorted(route.items()):
        if device not in run.recorded_windows:
            out[device] = dict(present=False)
            continue
        engine = DecisionEngine(config, proof.fresh(evaluator))
        rows = []
        for i in sorted(set(run.recorded_windows[device]) - set(assignment["excluded_window_indices"])):
            decision = engine.decide(proof.bundle(device, run.recorded_windows[device][i], item["profile"], (f"azta-device-{device[-2:]}",) * 2))
            primary = (decision.get("behavior") or {}).get("ae_primary") or {}
            if primary.get("ae_status") == "SCORE_READY":
                rows.append(dict(a=primary.get("a_ae"), trust=(decision.get("fusion") or {}).get("trust"), state=decision.get("proposed_state")))
        n = len(rows)
        flags = sum(1 for r in rows if isinstance(r["a"], (int, float)) and r["a"] > A_R)
        nonfull = sum(1 for r in rows if r["state"] in NON_FULL)
        out[device] = dict(present=True, width_s=item["width_s"], arm=item["arm"], score_ready_windows=n,
                           detector_flag=dict(fp=flags, tn=n - flags, fpr=flags / n if n else None),
                           trust_decision=dict(fp=nonfull, tn=n - nonfull, fpr=nonfull / n if n else None),
                           trust_state_accuracy=(n - nonfull) / n if n else None,
                           states={s: sum(1 for r in rows if r["state"] == s) for s in ("FULL_ACCESS", "RESTRICT", "QUARANTINE")},
                           t=summary(r["trust"] for r in rows), a=summary(r["a"] for r in rows))
    present = [v for v in out.values() if v.get("present")]
    n = sum(v["score_ready_windows"] for v in present)
    flags = sum(v["detector_flag"]["fp"] for v in present)
    nonfull = sum(v["trust_decision"]["fp"] for v in present)
    return dict(role=run.role, observer_session=run.session, devices=out,
                pooled=dict(score_ready_windows=n, detector_flag=dict(fp=flags, tn=n - flags, fpr=flags / n if n else None),
                            trust_decision=dict(fp=nonfull, tn=n - nonfull, fpr=nonfull / n if n else None), trust_state_accuracy=(n - nonfull) / n if n else None))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", required=True)
    parser.add_argument("--dry-run", help="a DEVEVAL run id: plumbing only, no marker, labelled DRY_RUN")
    args = parser.parse_args(argv)
    out_path = Path(args.out) if Path(args.out).is_absolute() else ROOT / args.out
    if out_path.exists():
        raise SystemExit("REFUSED: the output exists; nothing is overwritten")
    from core_runtime import cli, loader as cl
    from model import autoencoder as ae
    from trust.config import TrustConfig
    import exp_addendum
    if args.dry_run:
        if args.dry_run in RESERVED:
            raise SystemExit("REFUSED: a dry run never opens a reserved run")
        runs = [args.dry_run]
        assignments = {args.dry_run: assignment_for(args.dry_run)}
        if assignments[args.dry_run]["roles"].get(args.dry_run) != "DEVEVAL":
            raise SystemExit("REFUSED: the dry run must be a DEVEVAL run")
        authorization = None
    else:
        if not AUTHORIZATION.exists():
            raise SystemExit("REFUSED: FORMAL_TEST_AUTHORIZATION is not recorded; the reserved runs stay closed")
        authorization = json.loads(AUTHORIZATION.read_text(encoding="utf-8"))
        check = exp_addendum.verify_all()
        if check["problems"]:
            raise SystemExit(f"REFUSED: the release does not verify: {check['problems'][:5]}")
        if authorization["addendum_manifest_sha256"] != check["addendum_manifest_sha256"] or authorization["freeze_manifest_sha256"] != check["freeze_manifest_sha256"]:
            raise SystemExit("REFUSED: the authorization names another release")
        runs = list(RESERVED)
        assignments = {r: assignment_for(r) for r in runs}
        for r in runs:
            if assignments[r]["roles"].get(r) != "TEST":
                raise SystemExit(f"REFUSED: {r} is not a reserved TEST run of its assignment")
        FORMAL.mkdir(parents=True, exist_ok=True)
        with MARKER.open("x", encoding="utf-8") as stream:          # single use: created BEFORE the first reserved byte is read
            json.dump(dict(runs=runs, utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), authorization_sha256=sha(AUTHORIZATION),
                           note="the reserved TEST runs are opened by this pass and by no other"), stream)
    ae.configure_determinism()
    evaluator = cl.load_primary(ROOT, route_path=ROOT / cli.ROUTE, route_sha256=sha(ROOT / cli.ROUTE))
    config = TrustConfig.from_dict(json.loads((ROOT / cli.CONFIG).read_text(encoding="utf-8")))
    route = json.loads((ROOT / cli.ROUTE).read_text(encoding="utf-8"))["devices"]
    results, errors = {}, {}
    for r in runs:
        try:
            run = load_reserved(r, assignments[r])
            results[r] = score_run(run, assignments[r], evaluator, config, route)
        except Exception as exc:                                  # recorded, never retried: the pass is consumed
            errors[r] = f"{type(exc).__name__}: {exc}"
            print(f"{r}: ERROR {errors[r]}", flush=True)
    record = dict(schema="azta.formal.test_scoring", schema_version=1, status="DRY_RUN_NOT_TEST_EVIDENCE" if args.dry_run else "FORMAL_TEST_SCORED_ONCE",
                  runs=runs, results=results, errors=errors, release=dict(route=cli.ROUTE, route_sha256=sha(ROOT / cli.ROUTE), config=cli.CONFIG, config_sha256=sha(ROOT / cli.CONFIG)),
                  authorization_sha256=sha(AUTHORIZATION) if authorization else None, a_r=A_R,
                  note="benign held-out runs: every score-ready window is NEGATIVE; false flags and false non-FULL decisions are the measured false positives; no detection evidence",
                  generated_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(record, stream, indent=1, sort_keys=True)
        stream.write("\n")
    for r, res in results.items():
        p = res["pooled"]
        print(f"{r}: windows {p['score_ready_windows']}, flag FPR {p['detector_flag']['fpr']}, decision FPR {p['trust_decision']['fpr']}, trust-state accuracy {p['trust_state_accuracy']}", flush=True)
    print("written", out_path, sha(out_path))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
