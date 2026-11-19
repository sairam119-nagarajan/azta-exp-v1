"""Stabilization: the verdict of the shadow verification `stb-s01`, computed only from the session's own files. The checks were fixed BEFORE the session
(9 November 2026), after the `stb-l01` workload crash (status.json rename race on the Windows bind mount) and its correction (`attack_control.replace_status`).

    python -B -I rehearsal_tools/stb_shadow_verdict.py --run stb-s01 --stress results/engineering/stabilization/stb-s01_stress_reader.json --operator-log results/engineering/stabilization/stb-s01_operator.log --out results/engineering/stabilization/stb-s01_verdict.json

W1  the workload exited 0 and its container log has no traceback and no PermissionError
W2  the merged control status reached ENDED (every shard ended normally)
O1  the observer did not fail and exited 0
A1  every binding audit passed and every audit policy digest equals the baseline (shadow: any mutation is a failure)
P1  zero enforcement: the PEP log has no REQUEST_RECEIVED, COMMAND_SENT or OUTCOME
R1  all ten devices have recommendations, and every device has at least one SCORE_READY autoencoder window
R2  device02 has an AE_BEHAVIOR non-FULL recommendation after the operator's executed onset
T1  every EVALUATED recommendation carries a trust value
L1  no liveness recommendation for any device (the run is benign apart from one payload anomaly, which does not silence)
X1  the declared host stress reader read the status files throughout the RUNNING phase and every read succeeded
Informational: STATUS_REPLACE_RETRIED lines in the workload log (an absorbed host lock), and the recommendation counts.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "3e6c25881bc1846036fa27445001f0a69f39e6dd85bc5e137048a78c03179c7b"
DEVICES = [f"device{n:02d}" for n in range(1, 11)]


def jsonl(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", default="stb-s01")
    parser.add_argument("--stress", required=True)
    parser.add_argument("--operator-log", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    run = ROOT / "results/engineering/runs" / args.run
    checks, detail = {}, {}
    orchestrator = (run / "logs/orchestrator.log").read_text(encoding="utf-8", errors="replace")
    wl_logs = sorted((run / "logs").glob("*-wl-*.log"))
    wl_text = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in wl_logs)
    exit_line = re.search(r"observer_failed=(\w+) observer_exit=(-?\d+) workload_exit=(-?\d+)", orchestrator)
    checks["W1"] = bool(exit_line) and exit_line.group(3) == "0" and "Traceback" not in wl_text and "PermissionError" not in wl_text
    status = json.loads((run / "control/status.json").read_text(encoding="utf-8"))
    checks["W2"] = status.get("phase") == "ENDED"
    checks["O1"] = bool(exit_line) and exit_line.group(1) == "False" and exit_line.group(2) == "0"
    audits = re.findall(r"(audit-\S+) exit=(\d+) BINDING_AUDIT (\w+) run_id=\S+ policy_sha256=([0-9a-f]{64})", orchestrator)
    checks["A1"] = bool(audits) and all(e == "0" and v == "PASS" and d == BASELINE for _, e, v, d in audits)
    pep = jsonl(run / "pep/continuous.jsonl")
    kinds = {}
    for row in pep:
        kinds[row.get("kind")] = kinds.get(row.get("kind"), 0) + 1
    checks["P1"] = not any(kinds.get(k) for k in ("REQUEST_RECEIVED", "COMMAND_SENT", "OUTCOME"))
    recs = jsonl(run / "service/recommendations.jsonl")
    by_device = {d: [r for r in recs if r.get("device") == d] for d in DEVICES}
    checks["R1"] = all(rows and any(r.get("ae_status") == "SCORE_READY" for r in rows) for rows in by_device.values())
    operator_text = Path(args.operator_log).read_text(encoding="utf-8", errors="replace") if Path(args.operator_log).exists() else ""
    onset = re.search(r"START ok=True: START device02 .* effective at offset [\d.]+ s \((\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?Z\)", operator_text)   # the executed onset, not the request
    onset_ns = None
    if onset:
        stamp = datetime.strptime(onset.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
        onset_ns = int(stamp * 1e9) + int(float(onset.group(2) or "0") * 1e9)
    ae02 = [r for r in by_device["device02"] if r.get("decision_source") == "AE_BEHAVIOR" and r.get("recommendation") not in (None, "NONE", "FULL_ACCESS")]
    checks["R2"] = bool(onset_ns) and any(r["decision_ns"] >= onset_ns for r in ae02)
    evaluated = [r for r in recs if r.get("engine_status") == "EVALUATED"]
    checks["T1"] = bool(evaluated) and all(r.get("t_ae") is not None for r in evaluated)
    liveness = [(r["device"], r["decision_ns"]) for r in recs if (r.get("supplementary") or {}).get("recommendation")]
    checks["L1"] = not liveness
    stress = json.loads(Path(args.stress).read_text(encoding="utf-8"))
    checks["X1"] = stress.get("reads", 0) > 0 and stress.get("unreadable_after_retries") == 0 and (stress.get("merged_phase_counts") or {}).get("RUNNING", 0) > 0
    combos = {}
    for r in recs:
        key = f"{r.get('device')}|{r.get('ae_status')}|{r.get('decision_source')}|{r.get('recommendation')}"
        combos[key] = combos.get(key, 0) + 1
    detail.update(workload_logs=[p.name for p in wl_logs], status_replace_retried=wl_text.count("STATUS_REPLACE_RETRIED"), exit_line=exit_line.group(0) if exit_line else None,
                  audits=len(audits), audit_digests=sorted({d for *_, d in audits}), pep_kinds=kinds, recommendations=len(recs), evaluated=len(evaluated),
                  device02_ae_non_full=len(ae02), operator_onset_utc_ns=onset_ns, liveness=liveness[:20], stress=stress, combinations=combos)
    document = dict(schema="azta.stabilization.shadow_verdict", run=args.run, checks=checks, all_pass=all(checks.values()), detail=detail)
    out = ROOT / args.out
    with out.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(document, stream, indent=1, sort_keys=True)
        stream.write("\n")
    print(json.dumps(dict(checks=checks, all_pass=document["all_pass"]), indent=1))
    return 0 if document["all_pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
