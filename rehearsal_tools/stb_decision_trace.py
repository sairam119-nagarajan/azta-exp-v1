"""Stabilization requirements 2 and 5: reconstruct every enforcement action of one live session from its own durable records, with its actual cause and a SEPARATED latency decomposition.

    python -B -I rehearsal_tools/stb_decision_trace.py --run core-p03 [--out results/engineering/stabilization/trace_core-p03.json]

Read only. Joins, by identifier only (never by time proximity):
    decision record (service/inbox.jsonl, evidence_id)  ->  PEP RECORD_HANDLED (evidence_id; disposition, confirmation, reconstruction block when the PEP is post-stabilization)
    -> REVIEW_OPENED / REVIEW_RESOLVED (evidence_ids, review_id, request_id) -> REQUEST_RECEIVED / OUTCOME / OBSERVED (request_id: the broker's own read-back)
The cause is recomputed from the recorded decision with the unchanged attribution rule (`enforcement.attribution`), so a pre-stabilization run is re-attributed retrospectively; the
cause the run itself recorded is shown next to it.

Latency components, each kept separate (no single ambiguous "latency"):
    observation_window_s        the device's AE window width: the wait for one complete observation (route record)
    ae_inference_ms             the measured AE inference time of the device's profile in this session (median and max of `inference_timing.jsonl`, host monotonic clock)
    pdp_decision_ms             decision instant - window-end instant of the confirming record (both host UTC)
    authorization_s             review opened -> operator approval (0 for an automatic action), PEP clock
    mqtt_enforcement_ms         PEP request received -> verified OUTCOME (PEP clock), and the PEP's own processing time
    decision_to_verified_s      confirming decision (host) -> verified outcome (PEP): CROSS-CLOCK (Docker VM vs host, about 56 ppm and a millisecond offset)
    onset_to_verified_s         (optional) the operator-console perturbation start of the device -> verified outcome: an engineering Time-to-Contain, NOT a formal TTC measurement
"""
import argparse
import json
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from enforcement import attribution as attr        # noqa: E402

RUNS = ROOT / "results" / "engineering" / "runs"


def jsonl(path):
    path = Path(path)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def route_widths():
    route = json.loads((ROOT / "configs/core_final/route_ae_primary_v1.json").read_text(encoding="utf-8"))
    return {d: r["width_s"] for d, r in route["devices"].items()}, {d: r["profile"] for d, r in route["devices"].items()}


def trace(run, *, run_dir=None):
    base = Path(run_dir) if run_dir else RUNS / run
    decisions = {r["evidence_id"]: r for r in jsonl(base / "service/inbox.jsonl") if isinstance(r, dict) and r.get("evidence_id")}
    recommendations = {r["evidence_id"]: r for r in jsonl(base / "service/recommendations.jsonl")}
    pep = jsonl(base / "pep/continuous.jsonl")
    timing = jsonl(base / "service/inference_timing.jsonl")
    events = jsonl(base / "control/events.jsonl")
    widths, profiles = route_widths()
    inference = {}
    for t in timing:
        inference.setdefault(t["profile"], []).append(t["duration_ns"] / 1e6)
    handled = {}
    confirming = {}
    for e in pep:
        if e["kind"] == "RECORD_HANDLED":
            b = e["body"]
            handled.setdefault(b["evidence_id"], []).append(dict(b, seq=e["seq"], ts_utc_ns=e["ts_utc_ns"]))
            if b.get("disposition") == "CONFIRMING":
                confirming.setdefault(b.get("device"), []).append(dict(evidence_id=b["evidence_id"], confirmations=b.get("confirmations"), needed=b.get("needed"), seq=e["seq"]))
    opened = {e["body"]["review_id"]: e for e in pep if e["kind"] == "REVIEW_OPENED"}
    resolved = {e["body"]["review_id"]: e for e in pep if e["kind"] == "REVIEW_RESOLVED"}
    requests = {e["body"]["request_id"]: e for e in pep if e["kind"] == "REQUEST_RECEIVED"}
    observed_after = {}
    for e in pep:
        if e["kind"] == "OBSERVED" and e["body"].get("phase") == "after":
            observed_after[e["body"].get("request_id")] = e
    starts = sorted((e for e in events if e.get("kind") == "COMMAND_APPLIED" and e.get("action") == "start"), key=lambda e: e["utc_ns"])
    actions, restores = [], []
    for e in pep:
        if e["kind"] != "OUTCOME":
            continue
        o = e["body"]
        req = requests.get(o["request_id"])
        row = dict(request_id=o["request_id"], device=o["device"], desired_state=o.get("desired_state"), request_kind=o.get("request_kind"), status=o["status"], final_states=o.get("final_states"),
                   permission_equivalent=o.get("permission_equivalent"), enforcement_utc_ns=e["ts_utc_ns"], origin_of_request=o.get("origin"))
        after = observed_after.get(o["request_id"])
        row["broker_verified"] = dict(states=after["body"].get("states"), shape=after["body"].get("shape"), disabled=(after["body"].get("observed") or {}).get("disabled"),
                                      roles=[r[0] for r in (after["body"].get("observed") or {}).get("roles", [])], read_back_utc_ns=after["ts_utc_ns"]) if after else None
        row["mqtt_enforcement_ms"] = dict(request_to_verified=(e["ts_utc_ns"] - req["ts_utc_ns"]) / 1e6 if req else None, pep_processing=(o.get("pep_processing_ns") or 0) / 1e6)
        if o.get("request_kind") == "RESTORE":
            restores.append(row)
            continue
        review = next((r for r in resolved.values() if r["body"].get("request_id") == o["request_id"]), None)
        if review:
            op = opened.get(review["body"]["review_id"])
            evidence_id = op["body"]["evidence_ids"][0] if op else None
            row["authorization"] = dict(kind="OPERATOR_REVIEW", review_id=review["body"]["review_id"], operator_ref=review["body"].get("operator_ref"), recorded_origin=op["body"].get("origin") if op else None,
                                        authority_mode=op["body"].get("authority_mode") if op else None, reason=op["body"].get("reason") if op else None,
                                        authorization_s=(review["body"].get("operator_delay_ns") or 0) / 1e9)
        else:
            hit = next((h for hs in handled.values() for h in hs if h.get("request_id") == o["request_id"]), None)
            evidence_id = hit["evidence_id"] if hit else None
            row["authorization"] = dict(kind="AUTOMATIC" if hit else "UNLINKED", authorization_s=0.0 if hit else None, recorded_origin=(hit or {}).get("origin"))
        decision = decisions.get(evidence_id) or {}
        rec = recommendations.get(evidence_id) or {}
        attribution = attr.attribute(decision) if decision else dict(decision_source=None, origin=None)
        fusion, behavior = decision.get("fusion") or {}, decision.get("behavior") or {}
        primary = behavior.get("ae_primary") or {}
        row.update(evidence_id=evidence_id, run_id=(behavior.get("window_ref") or {}).get("collection_run_id"), window_index=(behavior.get("window_ref") or {}).get("window_index"),
                   decision_ns=decision.get("decision_ns"), s_id=fusion.get("s_id"), s_b=fusion.get("s_b"), s_c=fusion.get("s_c"), trust=fusion.get("trust"), a_ae=primary.get("a_ae"), ae_loss=primary.get("ae_loss"),
                   proposed_state=decision.get("proposed_state"), decision_source=attribution.get("decision_source"), cause_origin=attribution.get("origin"), causes=attribution.get("causes"),
                   counterfactual=attribution.get("counterfactual"), recorded_recommendation_origin=rec.get("recommendation_origin"),
                   attribution_corrected=bool(rec.get("recommendation_origin")) and rec.get("recommendation_origin") != attribution.get("origin"),
                   confirmation_run=[c for c in confirming.get(o["device"], []) if c["seq"] < (handled.get(evidence_id) or [dict(seq=10 ** 12)])[0]["seq"]][-1:],
                   pep_record=(handled.get(evidence_id) or [None])[0])
        device = o["device"]
        times = inference.get(profiles.get(device), [])
        row["latency"] = dict(observation_window_s=widths.get(device), ae_inference_ms=dict(median=statistics.median(times), max=max(times), n=len(times)) if times else None,
                              pdp_decision_ms=(decision["decision_ns"] - behavior["observed_ns"]) / 1e6 if isinstance(decision.get("decision_ns"), int) and isinstance(behavior.get("observed_ns"), int) else None,
                              authorization_s=row["authorization"].get("authorization_s"), mqtt_enforcement_ms=row["mqtt_enforcement_ms"],
                              decision_to_verified_s_cross_clock=(e["ts_utc_ns"] - decision["decision_ns"]) / 1e9 if isinstance(decision.get("decision_ns"), int) else None)
        before = [s["utc_ns"] for s in starts if s.get("device") == device and s["utc_ns"] <= e["ts_utc_ns"]]
        row["latency"]["onset_to_verified_s_engineering"] = (e["ts_utc_ns"] - max(before)) / 1e9 if before else None
        actions.append(row)
    by_source = {}
    for hs in handled.values():
        for h in hs:
            key = (h.get("decision") or {}).get("decision_source") or "NOT_RECORDED_BY_THIS_PEP_VERSION"
            by_source[key] = by_source.get(key, 0) + 1
    recovery = dict(opened=sum(1 for e in pep if e["kind"] == "RECOVERY_WINDOW_OPENED"), closed=[e["body"] for e in pep if e["kind"] == "RECOVERY_WINDOW_CLOSED"])
    return dict(schema="azta.stabilization.decision_trace", run=run, label="DEVELOPMENT engineering reconstruction of one session; not a formal measurement", actions=actions, restores=restores,
                records_handled=sum(len(v) for v in handled.values()), handled_by_recorded_decision_source=by_source, recovery_windows=recovery,
                unlinked_actions=[a["request_id"] for a in actions if not a.get("evidence_id")], corrected_attributions=[(a["device"], a["desired_state"], a["recorded_recommendation_origin"], a["cause_origin"]) for a in actions if a.get("attribution_corrected")])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", required=True)
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    result = trace(args.run)
    text = json.dumps(result, indent=1, sort_keys=True, default=str)
    if args.out:
        out = ROOT / args.out
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(text + "\n")
    for a in result["actions"]:
        lat = a["latency"]
        print(f"{a['device']} {a['desired_state']:10} {a['status']:16} cause={a['decision_source']} (recorded {a['recorded_recommendation_origin']}) auth={a['authorization']['kind']} "
              f"window={lat['observation_window_s']}s pdp={lat['pdp_decision_ms'] if lat['pdp_decision_ms'] is None else round(lat['pdp_decision_ms'])}ms auth={lat['authorization_s']}s mqtt={round(lat['mqtt_enforcement_ms']['request_to_verified'] or 0)}ms "
              f"onset->verified={lat['onset_to_verified_s_engineering']}")
    print("unlinked:", result["unlinked_actions"], "| corrected attributions:", result["corrected_attributions"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
