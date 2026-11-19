"""AZTA-EXP-v1 measurement procedure: the six assigned metrics of ONE live session, computed from the session's own durable records against an oracle that is independent of
prediction. Read only. It computes no final result by itself: on development evidence its output is labelled DEVELOPMENT_ONLY, and the formal campaign runs it only under its own frozen,
approved protocol. It never opens the reserved TEST runs (refused by name).

    python -B -I rehearsal_tools/exp_metrics.py --run stb-l02 --out results/engineering/stabilization/stb-l02_metrics_dev.json

Oracle (independent of every score): the EXECUTED anomaly segments of the workload control channel (`control/events.jsonl`, COMMAND_APPLIED start .. stop, or the run end when no stop).
A behavioural segment (rate, payload, burst, jitter, drop) is a positive episode for the autoencoder; `silence` is a liveness episode (no AE window can be scored inside it) and is reported
separately; a declared context change (the session's time cut) is a context episode, also separate. Nothing in the oracle comes from a model, a recommendation or the PEP.

Window units: a SCORE_READY AE window is [observed_ns - width, observed_ns] (the decision record's window end and the route width). It is
  POSITIVE    when at least half of it lies inside a behavioural segment of its device;
  NEGATIVE    when it overlaps no segment of its device and starts at least one window after the end of the device's last segment (no carry-over);
  TRANSITION  otherwise (excluded and counted); windows that are not SCORE_READY (e.g. a contained, disconnected device: intervention censoring) are excluded and counted.

1 Trust-score accuracy   There is NO ground-truth continuous trust score. It is defined as STATE agreement: the state T maps to (journal eq. 12; the engine's recorded proposed_state under the frozen tau_Q 65 / tau_R 75) against the
                         oracle's expected state (NEGATIVE -> FULL_ACCESS, POSITIVE -> not FULL_ACCESS), on POSITIVE and NEGATIVE windows; with the T distribution per class.
2 FPR, 3 FNR             at three distinct levels, never mixed: (a) detector flag = A > A_R on windows; (b) decision = a non-FULL recommendation whose cause includes the AE, on windows;
                         (c) enforcement = a verified non-RESTORE PEP action, per episode (a benign device-interval with an action is a false containment). TP, FP, TN, FN and support always
                         come with the rates; an undefined denominator stays None.
4 Time-to-Contain        per positive episode: executed onset -> verified containment outcome; censored when no verified containment before the episode end plus one window. Containment rate
                         reported. Decomposed: observation delay (onset -> end of the first flagged window), PDP decision latency, authorization delay (review), enforcement latency
                         (request -> verified). The onset is host UTC and the outcome PEP (Docker VM) UTC: cross-clock, about 56 ppm and a millisecond offset, stated.
5 PDP decision latency   decision_ns - window end, for every EVALUATED decision record (host clock both).
6 Enforcement success    requested actions (every OUTCOME, RESTORE included) -> APPLIED_VERIFIED by the broker read-back of the same request id; NOOP_ALREADY_IN_STATE and failures counted
                         apart; and the post-session probes against the final verified states. A request or a recommendation is never counted as enforcement.
"""
import argparse
import json
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
RESERVED = ("g6c-d07", "g5d3a-fx-g6b09", "g5d3a-fx-g6b17")
BEHAVIOURAL = ("rate", "payload", "burst", "jitter", "drop")
A_R = 6.931471805599452                    # S_B = 100 exp(-0.1 A) reaches the RESTRICT boundary with S_ID = S_C = 100 (unchanged parameters)
NON_FULL = ("RESTRICT", "QUARANTINE")
RENEWAL_GAP_NS = 2 * 10**9                 # a stop and a start of the same kind closer than this are one segment (the scenario driver's 120 s renewal)


def jsonl(path):
    path = Path(path)
    return [json.loads(line) for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()] if path.exists() else []


def rates(tp, fp, tn, fn):
    div = lambda a, b: a / b if b else None
    precision, recall = div(tp, tp + fp), div(tp, tp + fn)
    f1 = div(2 * precision * recall, precision + recall) if precision is not None and recall is not None and precision + recall else None
    return dict(tp=tp, fp=fp, tn=tn, fn=fn, support_positive=tp + fn, support_negative=fp + tn, precision=precision, recall=recall, f1=f1, fpr=div(fp, fp + tn), fnr=div(fn, fn + tp))


def summary(values):
    values = sorted(v for v in values if v is not None)
    if not values:
        return dict(n=0)
    pick = lambda q: values[min(len(values) - 1, int(q * (len(values) - 1) + 0.5))]
    return dict(n=len(values), median=statistics.median(values), p95=pick(0.95), max=values[-1], min=values[0])


def segments_of(events, run_end_ns):
    """{device: [dict(kind, start, end, stop_recorded)]} from the executed commands only."""
    out, open_ = {}, {}
    for e in sorted((e for e in events if e.get("kind") == "COMMAND_APPLIED"), key=lambda e: e["utc_ns"]):
        device = e.get("device")
        if e.get("action") == "start":
            open_[device] = dict(kind=e.get("anomaly"), start=e["utc_ns"])
        elif e.get("action") == "stop" and device in open_:
            seg = open_.pop(device)
            out.setdefault(device, []).append(dict(seg, end=e["utc_ns"], stop_recorded=True))
    for device, seg in open_.items():
        out.setdefault(device, []).append(dict(seg, end=run_end_ns, stop_recorded=False))
    merged = {}
    for device, ss in out.items():                # a driver's segment renewal (stop, then start of the same kind within RENEWAL_GAP_NS) is one executed episode, not a new onset
        rows = []
        for s in sorted(ss, key=lambda s: s["start"]):
            if rows and rows[-1]["kind"] == s["kind"] and 0 <= s["start"] - rows[-1]["end"] <= RENEWAL_GAP_NS:
                rows[-1] = dict(rows[-1], end=s["end"], stop_recorded=s["stop_recorded"], renewals=rows[-1].get("renewals", 0) + 1)
            else:
                rows.append(dict(s))
        merged[device] = rows
    return merged


def label(window, segs, width_ns):
    end = window["end"]
    start = end - width_ns
    behavioural = [s for s in segs if s["kind"] in BEHAVIOURAL]
    inside = sum(max(0, min(end, s["end"]) - max(start, s["start"])) for s in behavioural)
    if inside * 2 >= width_ns:
        return "POSITIVE"
    if any(min(end, s["end"]) > max(start, s["start"]) for s in segs):
        return "TRANSITION"
    if any(s["end"] <= start < s["end"] + width_ns for s in segs):
        return "TRANSITION"
    return "NEGATIVE"


def evaluate(run_dir, widths_s, *, time_cut_ns=None):
    run_dir = Path(run_dir)
    if any(name in str(run_dir) for name in RESERVED):
        raise SystemExit("refused: a reserved TEST run")
    decisions = [d for d in jsonl(run_dir / "service/inbox.jsonl") if isinstance(d, dict) and d.get("evidence_id")]
    recs = {r["evidence_id"]: r for r in jsonl(run_dir / "service/recommendations.jsonl")}
    events = jsonl(run_dir / "control/events.jsonl")
    pep = jsonl(run_dir / "pep/continuous.jsonl")
    ends = [d.get("decision_ns") for d in decisions if isinstance(d.get("decision_ns"), int)] + [e["utc_ns"] for e in events if isinstance(e.get("utc_ns"), int)]
    run_end = max(ends) if ends else 0
    segs = segments_of(events, run_end)
    windows, excluded = [], dict(not_score_ready=0, transition=0, unknown_width=0)
    for d in decisions:
        device = d.get("device") or (d.get("annotations") or {}).get("device") or recs.get(d["evidence_id"], {}).get("device")
        behavior = d.get("behavior") or {}
        primary = behavior.get("ae_primary") or {}
        rec = recs.get(d["evidence_id"], {})
        if primary.get("ae_status") != "SCORE_READY" or not isinstance(behavior.get("observed_ns"), int):
            excluded["not_score_ready"] += 1
            continue
        width = widths_s.get(device)
        if not width:
            excluded["unknown_width"] += 1
            continue
        w = dict(device=device, end=behavior["observed_ns"], decision_ns=d.get("decision_ns"), a=primary.get("a_ae"), trust=(d.get("fusion") or {}).get("trust"), state=d.get("proposed_state"),
                 recommendation=rec.get("recommendation"), source=rec.get("decision_source"), evidence_id=d["evidence_id"])
        w["label"] = label(w, segs.get(device, []), int(width * 1e9))
        if w["label"] == "TRANSITION":
            excluded["transition"] += 1
            continue
        windows.append(w)
    pos = [w for w in windows if w["label"] == "POSITIVE"]
    neg = [w for w in windows if w["label"] == "NEGATIVE"]
    count = lambda rows, hit: sum(1 for w in rows if hit(w))
    flag = lambda w: isinstance(w["a"], (int, float)) and w["a"] > A_R
    decided = lambda w: w["recommendation"] in NON_FULL and w["source"] in ("AE_BEHAVIOR", "MIXED")
    state_bad = lambda w: w["state"] in NON_FULL
    detector = rates(count(pos, flag), count(neg, flag), count(neg, lambda w: not flag(w)), count(pos, lambda w: not flag(w)))
    decision = rates(count(pos, decided), count(neg, decided), count(neg, lambda w: not decided(w)), count(pos, lambda w: not decided(w)))
    trust = dict(definition="state agreement of the T-mapped state with the oracle's expected state; no continuous ground truth exists",
                 confusion=rates(count(pos, state_bad), count(neg, state_bad), count(neg, lambda w: not state_bad(w)), count(pos, lambda w: not state_bad(w))),
                 agreement=(count(pos, state_bad) + count(neg, lambda w: not state_bad(w))) / len(pos + neg) if pos + neg else None,
                 t_positive=summary(w["trust"] for w in pos), t_negative=summary(w["trust"] for w in neg))
    outcomes = [e for e in pep if e["kind"] == "OUTCOME"]
    requests = {e["body"].get("request_id"): e for e in pep if e["kind"] == "REQUEST_RECEIVED"}
    after = {e["body"].get("request_id"): e for e in pep if e["kind"] == "OBSERVED" and e["body"].get("phase") == "after"}
    resolved = {e["body"].get("request_id"): e for e in pep if e["kind"] == "REVIEW_RESOLVED" and e["body"].get("request_id")}
    contain = [o for o in outcomes if o["body"].get("request_kind") != "RESTORE" and o["body"].get("desired_state") in NON_FULL and o["body"].get("status") == "APPLIED_VERIFIED"]
    restores = [o for o in outcomes if o["body"].get("request_kind") == "RESTORE" and o["body"].get("status") == "APPLIED_VERIFIED"]
    episodes = []
    for device, ss in segs.items():
        width_ns = int((widths_s.get(device) or 0) * 1e9)
        for s in ss:
            if s["kind"] not in BEHAVIOURAL:
                continue
            horizon = s["end"] + width_ns
            inside = [o for o in sorted(contain, key=lambda o: o["ts_utc_ns"]) if o["body"]["device"] == device and s["start"] <= o["ts_utc_ns"] <= horizon]
            hit = inside[0] if inside else None
            first_flag = next((w for w in sorted(pos, key=lambda w: w["end"]) if w["device"] == device and s["start"] <= w["end"] <= horizon and flag(w)), None)
            row = dict(device=device, kind=s["kind"], onset_utc_ns=s["start"], end_utc_ns=s["end"], stop_recorded=s["stop_recorded"], renewals=s.get("renewals", 0), contained=bool(hit), censored=not hit)
            recontain = []                        # a containment after an operator RESTORE inside the same episode: timed from that RESTORE, never from the onset
            for o in inside[1:]:
                before = [r["ts_utc_ns"] for r in restores if r["body"]["device"] == device and s["start"] <= r["ts_utc_ns"] < o["ts_utc_ns"]]
                if before:
                    recontain.append(dict(restore_utc_ns=max(before), recontained_utc_ns=o["ts_utc_ns"], delay_s=(o["ts_utc_ns"] - max(before)) / 1e9))
            row["recontainments_after_restore"] = recontain
            if hit:
                req = requests.get(hit["body"]["request_id"])
                rev = resolved.get(hit["body"]["request_id"])
                row.update(ttc_s_cross_clock=(hit["ts_utc_ns"] - s["start"]) / 1e9, observation_delay_s=(first_flag["end"] - s["start"]) / 1e9 if first_flag else None,
                           authorization_s=((rev["body"].get("operator_delay_ns") or 0) / 1e9) if rev else 0.0,
                           enforcement_ms=(hit["ts_utc_ns"] - req["ts_utc_ns"]) / 1e6 if req else None, request_id=hit["body"]["request_id"])
            episodes.append(row)
    benign_devices = {w["device"] for w in neg}
    false_containments = [o["body"]["device"] for o in contain if not any(s["kind"] in BEHAVIOURAL and s["start"] <= o["ts_utc_ns"] <= s["end"] + int((widths_s.get(o["body"]["device"]) or 0) * 1e9)
                                                                           for s in segs.get(o["body"]["device"], []))
                          and not (time_cut_ns and o["body"]["device"] in (time_cut_ns.get("device"),) and o["ts_utc_ns"] >= time_cut_ns["utc_ns"])
                          and not any(s["kind"] == "silence" and s["start"] <= o["ts_utc_ns"] for s in segs.get(o["body"]["device"], []))]
    pdp = [d["decision_ns"] - (d.get("behavior") or {}).get("observed_ns") for d in decisions
           if d.get("status") == "EVALUATED" and isinstance(d.get("decision_ns"), int) and isinstance((d.get("behavior") or {}).get("observed_ns"), int)]
    verified = [o for o in outcomes if o["body"].get("status") == "APPLIED_VERIFIED"]
    readback = [o for o in verified if o["body"].get("request_id") in after]
    enforcement = dict(requested=len(outcomes), applied_verified=len(verified), with_broker_read_back=len(readback), noop_already_in_state=sum(o["body"].get("status") == "NOOP_ALREADY_IN_STATE" for o in outcomes),
                       failed_or_unknown=sum(o["body"].get("status") not in ("APPLIED_VERIFIED", "NOOP_ALREADY_IN_STATE") for o in outcomes),
                       success_rate=len(readback) / (len(outcomes) - sum(o["body"].get("status") == "NOOP_ALREADY_IN_STATE" for o in outcomes)) if len(outcomes) - sum(o["body"].get("status") == "NOOP_ALREADY_IN_STATE" for o in outcomes) else None,
                       note="numerator: verified by the broker's read-back of the same request; denominator: requests that asked for a change (NOOPs apart)")
    return dict(schema="azta.exp_v1.session_metrics", label="DEVELOPMENT_ONLY unless run under the frozen, approved formal protocol", run_dir=run_dir.as_posix(),
                oracle=dict(source="control/events.jsonl COMMAND_APPLIED (executed), independent of prediction", segments={d: [dict(s) for s in ss] for d, ss in segs.items()}),
                windows=dict(positive=len(pos), negative=len(neg), excluded=excluded),
                metric_1_trust_state_accuracy=trust,
                metric_2_3_fpr_fnr=dict(a_detector_flag_windows=detector, b_ae_decision_windows=decision,
                                        c_enforcement_episodes=dict(behavioural_episodes=len(episodes), contained=sum(e["contained"] for e in episodes), false_containments_on_benign_intervals=len(false_containments),
                                                                    devices_with_benign_windows=len(benign_devices))),
                context_episode=None if not time_cut_ns else dict(device=time_cut_ns["device"], declared_utc_ns=time_cut_ns["utc_ns"],
                                                                  containments=[dict(utc_ns=o["ts_utc_ns"], state=o["body"]["desired_state"], authorization_s=((resolved.get(o["body"]["request_id"]) or {}).get("body", {}).get("operator_delay_ns") or 0) / 1e9 if resolved.get(o["body"]["request_id"]) else None,
                                                                                     reviewed=bool(resolved.get(o["body"]["request_id"])), delay_from_declaration_s=(o["ts_utc_ns"] - time_cut_ns["utc_ns"]) / 1e9)
                                                                                for o in contain if o["body"]["device"] == time_cut_ns["device"] and o["ts_utc_ns"] >= time_cut_ns["utc_ns"]]),
                metric_4_time_to_contain=dict(episodes=episodes, containment_rate=sum(e["contained"] for e in episodes) / len(episodes) if episodes else None,
                                              ttc_s=summary(e.get("ttc_s_cross_clock") for e in episodes), clock_note="onset host UTC, outcome PEP UTC: cross-clock (about 56 ppm)"),
                metric_5_pdp_decision_latency_ms=summary(x / 1e6 for x in pdp),
                metric_6_enforcement=enforcement)


def route_widths(route_path):
    route = json.loads((ROOT / route_path).read_text(encoding="utf-8"))
    return {d: r["width_s"] for d, r in route["devices"].items()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", required=True)
    parser.add_argument("--route", default="configs/exp_v1/route_ae_primary_exp_v1.json")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    if args.run in RESERVED:
        parser.error("refused: a reserved TEST run")
    declared = next((t for t in jsonl(ROOT / "results/engineering/pilot" / args.run / "operator_timeline.jsonl") if t.get("step") == "TIME_CUT_DECLARED"), None)
    cut = dict(device=declared.get("device"), utc_ns=declared.get("effective_utc_ns")) if declared and isinstance(declared.get("effective_utc_ns"), int) else None
    document = evaluate(ROOT / "results/engineering/runs" / args.run, route_widths(args.route), time_cut_ns=cut)
    with (ROOT / args.out).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(document, stream, indent=1, sort_keys=True, default=str)
        stream.write("\n")
    print(json.dumps({k: document[k] for k in ("windows", "metric_5_pdp_decision_latency_ms", "metric_6_enforcement")}, indent=1, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
