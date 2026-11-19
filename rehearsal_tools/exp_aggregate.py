"""Formal Experimental Validation (AZTA-EXP-v1, addendum 1): the consolidated six metrics (plus precision, recall and F1) over the VALID formal runs of the campaign ledger,
per device, per anomaly type and in aggregate. Read only; computes nothing that feeds back into the release.

    python -B -I rehearsal_tools/exp_aggregate.py --out results/engineering/formal/consolidated_results_v1.json [--test results/engineering/formal/test_scoring_v1.json]

Definitions are those of the frozen `exp_metrics.py` (window labels, A_R, the three FPR/FNR levels, Time-to-Contain with censoring, PDP latency, enforcement success), whose functions
are imported unchanged; `exp_metrics.evaluate` is run on every VALID run and stored, and the per-window regrouping here must reproduce its window and detector counts exactly
(`consistency`, checked for every run; a mismatch is reported, never hidden). Declared before the data (addendum 1):
  * detection (flag and decision levels, recall/FNR per anomaly type and device, episode detection delay) uses the SHADOW runs, where all ten devices run under identical conditions;
  * trust-state accuracy separates the windows of a device whose operating time was withdrawn (after the declared cut) as CONTEXT windows, expected RESTRICT, from the behavioural
    POSITIVE/NEGATIVE windows (the frozen per-run tool would count them as benign disagreements);
  * Time-to-Contain and enforcement success use the ACTIVE (device02) runs; PDP decision latency uses every VALID run;
  * the reserved TEST scoring is reported separately as held-out benign evidence.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "rehearsal_tools")]

import exp_metrics as em                           # noqa: E402  (frozen definitions)

MATRIX = "configs/formal/exp_matrix_v1.json"
LEDGER = ROOT / "results/engineering/formal/campaign_ledger.jsonl"
METRICS_DIR = ROOT / "results/engineering/formal/metrics"
ROUTE = "configs/exp_v1/route_ae_primary_exp_v1.json"


def jsonl(path):
    return em.jsonl(path)


def time_cut(run_id):
    declared = next((t for t in jsonl(ROOT / "results/engineering/pilot" / run_id / "operator_timeline.jsonl") if t.get("step") == "TIME_CUT_DECLARED"), None)
    return dict(device=declared.get("device"), utc_ns=declared.get("effective_utc_ns")) if declared and isinstance(declared.get("effective_utc_ns"), int) else None


def windows_of(run_dir, widths, cut):
    """The frozen per-window construction of `exp_metrics.evaluate`, kept per window with its device, label and the anomaly kind that covers it."""
    decisions = [d for d in jsonl(run_dir / "service/inbox.jsonl") if isinstance(d, dict) and d.get("evidence_id")]
    recs = {r["evidence_id"]: r for r in jsonl(run_dir / "service/recommendations.jsonl")}
    events = jsonl(run_dir / "control/events.jsonl")
    ends = [d.get("decision_ns") for d in decisions if isinstance(d.get("decision_ns"), int)] + [e["utc_ns"] for e in events if isinstance(e.get("utc_ns"), int)]
    segs = em.segments_of(events, max(ends) if ends else 0)
    rows, excluded = [], dict(not_score_ready=0, transition=0, unknown_width=0)
    latencies = []
    for d in decisions:
        device = d.get("device") or (d.get("annotations") or {}).get("device") or recs.get(d["evidence_id"], {}).get("device")
        behavior = d.get("behavior") or {}
        primary = behavior.get("ae_primary") or {}
        rec = recs.get(d["evidence_id"], {})
        if d.get("status") == "EVALUATED" and isinstance(d.get("decision_ns"), int) and isinstance(behavior.get("observed_ns"), int):
            latencies.append((device, (d["decision_ns"] - behavior["observed_ns"]) / 1e6, d["evidence_id"]))
        if primary.get("ae_status") != "SCORE_READY" or not isinstance(behavior.get("observed_ns"), int):
            excluded["not_score_ready"] += 1
            continue
        width = widths.get(device)
        if not width:
            excluded["unknown_width"] += 1
            continue
        w = dict(device=device, end=behavior["observed_ns"], decision_ns=d.get("decision_ns"), a=primary.get("a_ae"), trust=(d.get("fusion") or {}).get("trust"), state=d.get("proposed_state"),
                 recommendation=rec.get("recommendation"), source=rec.get("decision_source"), origin=rec.get("recommendation_origin"), evidence_id=d["evidence_id"])
        w["label"] = em.label(w, segs.get(device, []), int(width * 1e9))
        if w["label"] == "TRANSITION":
            excluded["transition"] += 1
            continue
        start = w["end"] - int(width * 1e9)
        cover = [(min(w["end"], s["end"]) - max(start, s["start"]), s) for s in segs.get(device, []) if s["kind"] in em.BEHAVIOURAL]
        cover = [c for c in cover if c[0] > 0]
        w["kind"] = max(cover, key=lambda c: c[0])[1]["kind"] if w["label"] == "POSITIVE" and cover else None
        w["context"] = bool(cut and device == cut["device"] and w["end"] >= cut["utc_ns"])
        rows.append(w)
    return rows, excluded, segs, latencies, recs


def flag(w):
    return isinstance(w["a"], (int, float)) and w["a"] > em.A_R


def decided(w):
    return w["recommendation"] in em.NON_FULL and w["source"] in ("AE_BEHAVIOR", "MIXED")


def confusion(rows, hit):
    pos = [w for w in rows if w["label"] == "POSITIVE"]
    neg = [w for w in rows if w["label"] == "NEGATIVE"]
    return em.rates(sum(1 for w in pos if hit(w)), sum(1 for w in neg if hit(w)), sum(1 for w in neg if not hit(w)), sum(1 for w in pos if not hit(w)))


def trust_state(rows):
    behavioural = [w for w in rows if not w["context"]]
    context = [w for w in rows if w["context"]]
    pos = [w for w in behavioural if w["label"] == "POSITIVE"]
    neg = [w for w in behavioural if w["label"] == "NEGATIVE"]
    agree = sum(1 for w in pos if w["state"] in em.NON_FULL) + sum(1 for w in neg if w["state"] not in em.NON_FULL)
    ctx_agree = sum(1 for w in context if w["state"] == "RESTRICT")
    n = len(pos) + len(neg)
    return dict(behavioural_windows=n, behavioural_agreement=agree / n if n else None, agree=agree,
                confusion=em.rates(sum(1 for w in pos if w["state"] in em.NON_FULL), sum(1 for w in neg if w["state"] in em.NON_FULL), sum(1 for w in neg if w["state"] not in em.NON_FULL), sum(1 for w in pos if w["state"] not in em.NON_FULL)),
                context_windows=len(context), context_restrict=ctx_agree, context_quarantine=sum(1 for w in context if w["state"] == "QUARANTINE"),
                overall_agreement=(agree + ctx_agree) / (n + len(context)) if n + len(context) else None,
                t_positive=em.summary(w["trust"] for w in pos), t_negative=em.summary(w["trust"] for w in neg), t_context=em.summary(w["trust"] for w in context))


def episodes_detection(rows, segs, widths):
    out = []
    for device, ss in segs.items():
        width_ns = int((widths.get(device) or 0) * 1e9)
        for s in ss:
            if s["kind"] not in em.BEHAVIOURAL:
                continue
            horizon = s["end"] + width_ns
            inside = sorted((w for w in rows if w["device"] == device and w["label"] == "POSITIVE" and s["start"] <= w["end"] <= horizon), key=lambda w: w["end"])
            first_flag = next((w for w in inside if flag(w)), None)
            first_decision = next((w for w in inside if decided(w)), None)
            out.append(dict(device=device, kind=s["kind"], positive_windows=len(inside), detected_flag=bool(first_flag), detected_decision=bool(first_decision),
                            delay_flag_s=(first_flag["end"] - s["start"]) / 1e9 if first_flag else None, delay_decision_s=(first_decision["end"] - s["start"]) / 1e9 if first_decision else None,
                            recommended_state=first_decision["recommendation"] if first_decision else None))
    return out


def liveness_and_context(run_id, segs, recs, cut):
    rec_rows = sorted(recs.values(), key=lambda r: r.get("decision_ns") or 0)
    silence = []
    for device, ss in segs.items():
        for s in ss:
            if s["kind"] != "silence":
                continue
            hit = next((r for r in rec_rows if r.get("device") == device and r.get("recommendation_origin") == "SUPPLEMENTARY_TIMING" and r.get("recommendation") in em.NON_FULL
                        and isinstance(r.get("decision_ns"), int) and r["decision_ns"] >= s["start"]), None)
            silence.append(dict(run_id=run_id, device=device, onset_utc_ns=s["start"], duration_s=(s["end"] - s["start"]) / 1e9, detected=bool(hit),
                                delay_s=(hit["decision_ns"] - s["start"]) / 1e9 if hit else None, recommended=(hit or {}).get("recommendation")))
    context = None
    if cut:
        after = [r for r in rec_rows if r.get("device") == cut["device"] and isinstance(r.get("decision_ns"), int) and r["decision_ns"] >= cut["utc_ns"]]
        hit = next((r for r in after if r.get("recommendation_origin") == "CONTEXT_POLICY" and r.get("recommendation") in em.NON_FULL), None)
        context = dict(run_id=run_id, device=cut["device"], detected=bool(hit), delay_s=(hit["decision_ns"] - cut["utc_ns"]) / 1e9 if hit else None, recommended=(hit or {}).get("recommendation"),
                       escalated_to_quarantine=any(r.get("recommendation") == "QUARANTINE" for r in after), recommendations_after_cut=len(after))
    return silence, context


def identity_episodes(run_id):
    timeline = jsonl(ROOT / "results/engineering/pilot" / run_id / "operator_timeline.jsonl")
    pep = jsonl(ROOT / "results/engineering/runs" / run_id / "pep/continuous.jsonl")
    out = []
    for t in timeline:
        if t.get("step") != "REVOCATION":
            continue
        start = t["utc_ns"]
        review = next((e for e in pep if e.get("kind") == "REVIEW_OPENED" and (e.get("body") or {}).get("origin") == "IDENTITY_HARD_GATE" and e.get("ts_utc_ns", 0) >= start), None)
        outcome = next((e for e in pep if e.get("kind") == "OUTCOME" and (e.get("body") or {}).get("desired_state") == "QUARANTINE" and (e.get("body") or {}).get("status") in ("APPLIED_VERIFIED", "NOOP_ALREADY_IN_STATE")
                        and e.get("ts_utc_ns", 0) >= start), None)
        out.append(dict(run_id=run_id, revocation_utc_ns=start, review_opened=bool(review), review_delay_s=(review["ts_utc_ns"] - start) / 1e9 if review else None,
                        quarantine_verified=bool(outcome), outcome_status=(outcome or {}).get("body", {}).get("status"), time_to_verified_s=(outcome["ts_utc_ns"] - start) / 1e9 if outcome else None))
    return out


def ttc_with_pdp(doc, latencies):
    by_evidence = {e: ms for _, ms, e in latencies}
    rows = []
    for e in doc["metric_4_time_to_contain"]["episodes"]:
        row = dict(e)
        rid = e.get("request_id") or ""
        evidence = rid[3:] if rid.startswith("op-") else None
        row["pdp_decision_ms"] = by_evidence.get(evidence)
        rows.append(row)
    return rows


def grouped(rows, key):
    out = {}
    for w in rows:
        out.setdefault(key(w), []).append(w)
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", required=True)
    parser.add_argument("--test", default=None, help="the reserved TEST scoring record, reported separately")
    parser.add_argument("--ledger", default=str(LEDGER))
    args = parser.parse_args(argv)
    m = json.loads((ROOT / MATRIX).read_text(encoding="utf-8"))
    widths = em.route_widths(ROUTE)
    ledger = [r for r in jsonl(args.ledger) if r.get("status") in ("VALID", "VOID", "STOP", "NOT_STARTED")]
    valid = [r for r in ledger if r["status"] == "VALID"]
    METRICS_DIR.mkdir(parents=True, exist_ok=True)
    shadow_rows, all_latencies, detection_eps, silences, contexts, identities, ttc_rows, enforcement, consistency = [], [], [], [], [], [], [], [], {}
    for entry in valid:
        run_id = entry["run_id"]
        spec = m["runs"][entry.get("as_run") or run_id]
        run_dir = ROOT / "results/engineering/runs" / run_id
        cut = time_cut(run_id)
        doc = em.evaluate(run_dir, widths, time_cut_ns=cut)
        path = METRICS_DIR / f"{run_id}.json"
        if not path.exists():
            path.write_text(json.dumps(doc, indent=1, sort_keys=True, default=str) + "\n", encoding="utf-8")
        rows, excluded, segs, latencies, recs = windows_of(run_dir, widths, cut)
        det = confusion(rows, flag)
        consistency[run_id] = (doc["windows"] == dict(positive=sum(w["label"] == "POSITIVE" for w in rows), negative=sum(w["label"] == "NEGATIVE" for w in rows), excluded=excluded)
                               and all(det[k] == doc["metric_2_3_fpr_fnr"]["a_detector_flag_windows"][k] for k in ("tp", "fp", "tn", "fn")))
        all_latencies += [(d, ms) for d, ms, _ in latencies]
        for w in rows:
            w["run_id"], w["component"] = run_id, spec["component"]
        s, c = liveness_and_context(run_id, segs, recs, cut)
        silences += s
        if c:
            c["mode"] = spec["mode"]
            contexts.append(c)
        if spec["mode"] == "shadow":
            shadow_rows += rows
            detection_eps += [dict(e, run_id=run_id) for e in episodes_detection(rows, segs, widths)]
        else:
            ttc_rows += [dict(e, run_id=run_id) for e in ttc_with_pdp(doc, latencies)]
            enforcement.append(dict(run_id=run_id, **doc["metric_6_enforcement"]))
            identities += identity_episodes(run_id)
    per_device = {d: dict(detector_flag=confusion(rs, flag), trust_decision=confusion(rs, decided), trust_state=trust_state(rs)) for d, rs in sorted(grouped(shadow_rows, lambda w: w["device"]).items())}
    positives = [w for w in shadow_rows if w["label"] == "POSITIVE"]
    def recall(rs, hit):
        tp = sum(1 for w in rs if hit(w))
        return dict(tp=tp, fn=len(rs) - tp, recall=tp / len(rs) if rs else None, fnr=(len(rs) - tp) / len(rs) if rs else None)
    per_kind = {k: dict(windows_flag=recall(rs, flag), windows_decision=recall(rs, decided),
                        episodes=len([e for e in detection_eps if e["kind"] == k]), episodes_detected_flag=sum(e["detected_flag"] for e in detection_eps if e["kind"] == k),
                        episodes_detected_decision=sum(e["detected_decision"] for e in detection_eps if e["kind"] == k),
                        delay_flag_s=em.summary(e["delay_flag_s"] for e in detection_eps if e["kind"] == k), delay_decision_s=em.summary(e["delay_decision_s"] for e in detection_eps if e["kind"] == k))
                for k, rs in sorted(grouped(positives, lambda w: w["kind"]).items())}
    per_device_kind = {f"{d}/{k}": dict(windows_flag=recall(rs, flag), windows_decision=recall(rs, decided),
                                        episodes=sum(1 for e in detection_eps if e["device"] == d and e["kind"] == k),
                                        episodes_detected_decision=sum(e["detected_decision"] for e in detection_eps if e["device"] == d and e["kind"] == k),
                                        delay_decision_s=em.summary(e["delay_decision_s"] for e in detection_eps if e["device"] == d and e["kind"] == k))
                       for (d, k), rs in sorted(grouped(positives, lambda w: (w["device"], w["kind"])).items())}
    latency = {d: em.summary(ms for dd, ms in all_latencies if dd == d) for d in sorted({d for d, _ in all_latencies if d})}
    for d, values in latency.items():
        vs = sorted(ms for dd, ms in all_latencies if dd == d)
        values["p99"] = vs[min(len(vs) - 1, int(0.99 * (len(vs) - 1) + 0.5))] if len(vs) >= 100 else None
    contained = [e for e in ttc_rows if e.get("contained")]
    requested = sum(e["requested"] for e in enforcement)
    noop = sum(e["noop_already_in_state"] for e in enforcement)
    readback = sum(e["with_broker_read_back"] for e in enforcement)
    document = dict(schema="azta.formal.consolidated_results", schema_version=1, release="AZTA-EXP-v1", matrix=MATRIX,
                    label="FORMAL EXPERIMENTAL VALIDATION (AZTA-EXP-v1, addendum 1)" if valid else "NO VALID RUN",
                    generated_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    ledger=dict(valid=len(valid), void=sum(r["status"] == "VOID" for r in ledger), stop=sum(r["status"] == "STOP" for r in ledger), entries=ledger),
                    consistency_with_frozen_metric_tool=dict(all_runs_consistent=all(consistency.values()) if consistency else None, per_run=consistency),
                    metric_1_trust_state_accuracy=dict(aggregate=trust_state(shadow_rows), per_device={d: v["trust_state"] for d, v in per_device.items()}),
                    metric_2_3_detection=dict(aggregate=dict(detector_flag=confusion(shadow_rows, flag), trust_decision=confusion(shadow_rows, decided)),
                                              per_device={d: dict(detector_flag=v["detector_flag"], trust_decision=v["trust_decision"]) for d, v in per_device.items()},
                                              per_kind=per_kind, per_device_kind=per_device_kind,
                                              enforcement_level=dict(active_episodes=len(ttc_rows), contained=len(contained),
                                                                     false_containments=sum(json.loads((METRICS_DIR / f"{e['run_id']}.json").read_text(encoding="utf-8"))["metric_2_3_fpr_fnr"]["c_enforcement_episodes"]["false_containments_on_benign_intervals"] for e in enforcement))),
                    liveness_silence=dict(episodes=silences, detected=sum(s["detected"] for s in silences), delay_s=em.summary(s["delay_s"] for s in silences)),
                    context=dict(episodes=contexts, shadow_detected=sum(c["detected"] for c in contexts if c["mode"] == "shadow"), escalated=sum(c["escalated_to_quarantine"] for c in contexts)),
                    identity=dict(episodes=identities, quarantine_verified=sum(i["quarantine_verified"] for i in identities)),
                    metric_4_time_to_contain_device02=dict(episodes=ttc_rows, containment_rate=len(contained) / len(ttc_rows) if ttc_rows else None, censored=len(ttc_rows) - len(contained),
                                                           ttc_s=em.summary(e.get("ttc_s_cross_clock") for e in contained),
                                                           automatic=em.summary(e.get("ttc_s_cross_clock") for e in contained if not e.get("authorization_s")),
                                                           per_kind={k: dict(episodes=sum(1 for e in ttc_rows if e["kind"] == k), contained=sum(1 for e in contained if e["kind"] == k),
                                                                             ttc_s=em.summary(e.get("ttc_s_cross_clock") for e in contained if e["kind"] == k)) for k in em.BEHAVIOURAL},
                                                           components=dict(observation_delay_s=em.summary(e.get("observation_delay_s") for e in contained), pdp_decision_ms=em.summary(e.get("pdp_decision_ms") for e in contained),
                                                                           authorization_s=em.summary(e.get("authorization_s") for e in contained), enforcement_ms=em.summary(e.get("enforcement_ms") for e in contained)),
                                                           clock_note="onset host UTC, outcome PEP UTC: cross-clock, about 56 ppm"),
                    metric_5_pdp_decision_latency_ms=dict(per_device=latency, all=em.summary(ms for _, ms in all_latencies)),
                    metric_6_enforcement_success_device02=dict(requested=requested, noop=noop, with_broker_read_back=readback, success_rate=readback / (requested - noop) if requested - noop else None, per_run=enforcement),
                    reserved_test=json.loads(Path(args.test).read_text(encoding="utf-8")) if args.test and Path(args.test).exists() else None)
    out = Path(args.out) if Path(args.out).is_absolute() else ROOT / args.out
    with out.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(document, stream, indent=1, sort_keys=True, default=str)
        stream.write("\n")
    print(json.dumps(dict(valid_runs=len(valid), consistent=document["consistency_with_frozen_metric_tool"]["all_runs_consistent"], written=str(out)), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
