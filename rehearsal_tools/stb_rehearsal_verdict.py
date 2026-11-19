"""Stabilization amendment 2: the verdict of the NON-ENFORCING rehearsal `stb-s02` (shadow mode, pilot broker, no policy change), from the session's own files. The checks were fixed BEFORE the
session (9 November 2026, protocol amendment 2) and are the live part of the proof that the L5 corrections work; C1 and the owner sequence are proved by the offline replay
(`tests/test_stb_rehearsal_replay.py`), because a shadow session opens no reviews and changes no permission.

    python -B -I rehearsal_tools/stb_rehearsal_verdict.py --run stb-s02 --stress results/engineering/stabilization/stb-s02_stress_reader.json --operator-log results/engineering/stabilization/stb-s02_operator.log --relay-out results/engineering/stabilization/stb-s02_relay.out --out results/engineering/stabilization/stb-s02_verdict.json

W1 W2 O1 A1 P1 R1 T1 X1   as in `stb_shadow_verdict.py` (workload exit 0 without traceback or PermissionError; ENDED; observer OK; every audit PASS on the baseline digest; zero enforcement;
                          every device scored; every EVALUATED recommendation has a trust value; the stress reader read throughout, never unreadable)
I1-I5                     the scenario integrity of `stb_live_verdict.integrity_v2`: one device01 silence start and one stop applied, the MQTT connection recorded live at both, no containment or
                          rejected/unanswered device01 command, nothing published inside the silence and publishing resumed after it, the workload COMPLETE
LV1                       the liveness rule detected the silence: a device01 liveness recommendation later than silence start + the 40 s bound and not after stop + one bound
LV2                       the L5 rule on live records: no liveness recommendation for any other device, and none for device01 outside [silence start, silence stop + 40 s]
LV3                       device01 is observed again after the silence: SCORE_READY autoencoder windows after stop + 40 s
G1                        the guide relay delivered every line of the operator log, once and in order
"""
import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "rehearsal_tools")]

import stb_live_verdict as lv        # noqa: E402

BASELINE = lv.BASELINE
DEVICES = [f"device{n:02d}" for n in range(1, 11)]
BOUND_NS = lv.LIVENESS_BOUND_S * lv.NS


def jsonl(path):
    path = Path(path)
    return [json.loads(line) for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()] if path.exists() else []


def evaluate(run_id, stress_path, operator_log, relay_out):
    run = ROOT / "results/engineering/runs" / run_id
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
    evaluated = [r for r in recs if r.get("engine_status") == "EVALUATED"]
    checks["T1"] = bool(evaluated) and all(r.get("t_ae") is not None for r in evaluated)
    stress = json.loads(Path(stress_path).read_text(encoding="utf-8"))
    checks["X1"] = stress.get("reads", 0) > 0 and stress.get("unreadable_after_retries") == 0 and (stress.get("merged_phase_counts") or {}).get("RUNNING", 0) > 0
    events = jsonl(run / "control/events.jsonl")
    integrity, idetail = lv.integrity_v2(run, run_id, events, [], [])
    for key in ("I1", "I2", "I3", "I4", "I5"):
        checks[key] = integrity[key]
    starts, stops = idetail["silence"]["starts"], idetail["silence"]["stops"]
    seg = (starts[0], stops[0]) if len(starts) == 1 and len(stops) == 1 else None
    liveness = [(r["device"], r["decision_ns"]) for r in recs if (r.get("supplementary") or {}).get("recommendation")]
    checks["LV1"] = bool(seg) and any(d == "device01" and seg[0] + BOUND_NS < t <= seg[1] + BOUND_NS for d, t in liveness)
    stray = [(d, t) for d, t in liveness if d != "device01" or not (seg and seg[0] <= t <= seg[1] + BOUND_NS)]
    checks["LV2"] = bool(seg) and not stray
    after = [r for r in by_device["device01"] if seg and r.get("decision_ns", 0) > seg[1] + BOUND_NS and r.get("ae_status") == "SCORE_READY"]
    checks["LV3"] = bool(after)
    log_lines = [line for line in Path(operator_log).read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()] if Path(operator_log).exists() else []
    relayed = [line for line in Path(relay_out).read_text(encoding="utf-8", errors="replace").splitlines() if line.strip() and not line.startswith("RELAY_")] if Path(relay_out).exists() else []
    checks["G1"] = bool(log_lines) and relayed == log_lines
    detail.update(exit_line=exit_line.group(0) if exit_line else None, status_replace_retried=wl_text.count("STATUS_REPLACE_RETRIED"), audits=len(audits), audit_digests=sorted({d for *_, d in audits}),
                  pep_kinds=kinds, recommendations=len(recs), evaluated=len(evaluated), integrity=idetail, silence_segment_utc_ns=seg, liveness_records=len(liveness),
                  liveness_first_last=(liveness[0][1], liveness[-1][1]) if liveness else None, liveness_stray=stray[:20], device01_score_ready_after=len(after),
                  relay=dict(log_lines=len(log_lines), relayed=len(relayed)), stress=stress)
    return dict(schema="azta.stabilization.rehearsal_verdict", run=run_id, protocol="docs/stabilization/STB_LIVE_SESSION_PROTOCOL.md (amendment 2)", checks=checks, all_pass=all(checks.values()), detail=detail)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", default="stb-s02")
    parser.add_argument("--stress", required=True)
    parser.add_argument("--operator-log", required=True)
    parser.add_argument("--relay-out", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    document = evaluate(args.run, args.stress, args.operator_log, args.relay_out)
    with (ROOT / args.out).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(document, stream, indent=1, sort_keys=True, default=str)
        stream.write("\n")
    print(json.dumps(dict(checks=document["checks"], all_pass=document["all_pass"]), indent=1))
    return 0 if document["all_pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
