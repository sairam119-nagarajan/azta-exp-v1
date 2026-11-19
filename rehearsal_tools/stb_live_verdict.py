"""STABILIZATION_LIVE_1 (`stb-l01`): the pass checks of docs/stabilization/STB_LIVE_SESSION_PROTOCOL.md section 3, evaluated from the session's own durable records. Read only.

    python -B -I rehearsal_tools/stb_live_verdict.py [--run stb-l01] --out results/engineering/stabilization/stb-l01_verdict.json

A check that cannot be evaluated (a record is missing) is FALSE, never skipped. Nothing here adjusts a check after seeing the data.

Rules: `v1` is how stb-l01 and stb-l02 were judged (both FAILED, 12/14; those verdicts stand and are never recomputed in place). `v2` (protocol amendment 2, declared before stb-l03) evaluates
C1 along the causal chain of the declared context review (`context_v2`) and adds the scenario-integrity block I1-I6 (`integrity_v2`), required for an overall pass. v2 only adds conditions;
no threshold or check of section 3 is relaxed.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "rehearsal_tools")]

import stb_decision_trace as trace                 # noqa: E402
from enforcement import attribution as attr        # noqa: E402

BASELINE = "3e6c25881bc1846036fa27445001f0a69f39e6dd85bc5e137048a78c03179c7b"
OUT_OF_SCOPE = [f"device{n:02d}" for n in range(3, 11)]
LIVENESS_BOUND_S = 40
NS = 1_000_000_000


def jsonl(path):
    path = Path(path)
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()] if path.exists() else []


def probes(path):
    """{device: probe body} of one probe text file (`== device phase` headers followed by a JSON line)."""
    out = {}
    path = Path(path)
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("{"):
            try:
                body = json.loads(line)
            except ValueError:
                continue
            out[body.get("device")] = body
    return out


def denied(body, key):
    return bool(body) and (body.get("publishes") or {}).get(key, {}).get("puback") == 135 and not (body.get("publishes") or {}).get(key, {}).get("delivered_to_listener")


def allowed(body, key):
    return bool(body) and (body.get("publishes") or {}).get(key, {}).get("puback") == 0 and (body.get("publishes") or {}).get(key, {}).get("delivered_to_listener") is True


def context_v2(pep, reviews, resolved, outcomes, after, roles, timeline, restricted):
    """C1 under amendment 2: the DECLARED review is the first device02 CONTEXT_POLICY review opened at or after the declared time cut, and the whole causal chain must hold for THAT review:
    review -> the owner's EXECUTED approval (operator reference) -> the outcome whose request id the approval names -> APPLIED_VERIFIED -> the broker read-back of that request (operations
    role removed, telemetry kept, not disabled) -> the post-session probe; and no device02 RESTRICT outcome between the review's opening and the approval. A later review never stands in for
    a cancelled, expired or rejected declared review: that is reported and C1 is false."""
    reasons = []
    cut = next((t.get("effective_utc_ns") for t in timeline if t.get("step") == "TIME_CUT_DECLARED"), None)
    if not isinstance(cut, int):
        return False, dict(reasons=["TIME_CUT_NOT_DECLARED"])
    candidates = sorted((e for e in reviews.values() if e["body"]["device"] == "device02" and e["body"]["origin"] == "CONTEXT_POLICY" and e["ts_utc_ns"] >= cut), key=lambda e: (e["ts_utc_ns"], e["seq"]))
    if not candidates:
        return False, dict(reasons=["NO_CONTEXT_REVIEW_AFTER_THE_TIME_CUT"])
    declared = candidates[0]
    rid = declared["body"]["review_id"]
    res = resolved.get(rid)
    if not res:
        reasons.append("DECLARED_REVIEW_NEVER_RESOLVED")
    elif res["body"].get("state") != "EXECUTED":
        reasons.append(f"DECLARED_REVIEW_{res['body'].get('state')}:{res['body'].get('reason')}")
    elif not res["body"].get("operator_ref"):
        reasons.append("NO_OPERATOR_REFERENCE")
    request_id = (res or {}).get("body", {}).get("request_id")
    out = next((o for o in outcomes if request_id and o["body"].get("request_id") == request_id), None)
    if res and res["body"].get("state") == "EXECUTED":
        if not out:
            reasons.append("NO_OUTCOME_FOR_THE_APPROVED_REQUEST")
        elif out["body"]["device"] != "device02" or out["body"].get("desired_state") != "RESTRICT" or out["body"]["status"] != "APPLIED_VERIFIED":
            reasons.append(f"OUTCOME_{out['body'].get('desired_state')}_{out['body']['status']}")
        elif out["ts_utc_ns"] < res["ts_utc_ns"] - NS:
            reasons.append("OUTCOME_BEFORE_APPROVAL")
    early = [o for o in outcomes if o["body"]["device"] == "device02" and o["body"].get("desired_state") == "RESTRICT" and declared["ts_utc_ns"] <= o["ts_utc_ns"]
             and (not res or o["ts_utc_ns"] < res["ts_utc_ns"] - NS)]
    if early:
        reasons.append("RESTRICT_BEFORE_THE_OWNERS_APPROVAL")
    rb = after.get(request_id) if request_id else None
    if out and not (rb and "azta-device02-operation-publish" not in roles(rb) and "azta-device02-telemetry-publish" in roles(rb) and (rb.get("observed") or {}).get("disabled") is False):
        reasons.append("BROKER_READ_BACK_DOES_NOT_SHOW_RESTRICT")
    if not (denied(restricted.get("device02"), "own_operations") and allowed(restricted.get("device02"), "own_telemetry")):
        reasons.append("POST_SESSION_PROBE_NOT_RESTRICTED")
    return not reasons, dict(declared_review_id=rid, opened_utc_ns=declared["ts_utc_ns"], resolution=(res or {}).get("body", {}).get("state"), approval_utc_ns=(res or {}).get("ts_utc_ns"),
                             request_id=request_id, outcome_utc_ns=(out or {}).get("ts_utc_ns"), later_context_reviews=[e["body"]["review_id"] for e in candidates[1:]], reasons=reasons)


def enforcement_reconnects(events, outcomes, device="device01", tolerance_ns=2 * NS):
    """(v3) A DEVICE_CONTAINED of `device` that is resumed within the tolerance AND lies within the tolerance of a verified RESTRICT outcome of that device: the broker closing the client's
    connection when its role changes (Dynamic Security), not a silence failure. Found live in stb-l03 (59 ms after removeClientRole, reconnected 8 ms later)."""
    restricts = [o["ts_utc_ns"] for o in outcomes if o["body"].get("device") == device and o["body"].get("desired_state") == "RESTRICT" and o["body"].get("status") == "APPLIED_VERIFIED"]
    resumed = [e["utc_ns"] for e in events if e.get("device") == device and e.get("kind") == "DEVICE_RESUMED"]
    out = []
    for e in events:
        if e.get("device") == device and e.get("kind") == "DEVICE_CONTAINED":
            if any(0 <= r - e["utc_ns"] <= tolerance_ns for r in resumed) and any(abs(t - e["utc_ns"]) <= tolerance_ns for t in restricts):
                out.append(e["utc_ns"])
    return out


def integrity_v2(base, run, events, outcomes, timeline, *, exempt_enforcement_reconnect=False):
    """Scenario integrity under amendment 2, evaluated beside the 14 checks and required for an overall pass (it can only make a verdict stricter):
    I1 exactly one device01 silence start and one stop are applied; I2 the device's MQTT connection is recorded live at both; I3 no containment of device01 and no rejected or unanswered
    device01 command inside the silence; I4 nothing published inside the silence and publishing resumes after it (the device's own ledger); I5 the workload ends COMPLETE;
    I6 every owner instruction is closed (DONE or CANCELLED) and every operator RESTORE happened while a RESTORE instruction for that device was open."""
    applied = [e for e in events if e.get("device") == "device01" and e.get("kind") == "COMMAND_APPLIED" and e.get("anomaly") == "silence"]
    starts, stops = [e for e in applied if e.get("action") == "start"], [e for e in applied if e.get("action") == "stop"]
    out, det = {}, {}
    out["I1"] = len(starts) == 1 and len(stops) == 1 and stops[0]["utc_ns"] > starts[0]["utc_ns"]
    det["silence"] = dict(starts=[e["utc_ns"] for e in starts], stops=[e["utc_ns"] for e in stops], end_missing=bool(starts) and not stops)
    out["I2"] = out["I1"] and starts[0].get("mqtt_connected") is True and stops[0].get("mqtt_connected") is True
    lo, hi = (starts[0]["utc_ns"], stops[0]["utc_ns"]) if out["I1"] else (None, None)
    exempt = set(enforcement_reconnects(events, outcomes)) if exempt_enforcement_reconnect else set()
    bad = [e["kind"] for e in events if e.get("device") == "device01" and (e.get("kind") == "COMMAND_REJECTED" or (e.get("kind") == "DEVICE_CONTAINED" and lo is not None and lo <= e["utc_ns"] <= hi
                                                                                                                       and e["utc_ns"] not in exempt))]
    det["enforcement_reconnects_exempted"] = sorted(exempt)
    unanswered = [t for t in timeline if t.get("device") == "device01" and t.get("step") in ("ANOMALY_START", "ANOMALY_STOP") and t.get("ok") is False]
    out["I3"] = out["I1"] and not bad and not unanswered
    det["device01_problems"] = dict(events=bad, unanswered_commands=len(unanswered))
    ledger = [r for r in jsonl(base / "collection" / run / "ledger_device01.jsonl") if r.get("record_type") == "ATTEMPT"]
    if out["I1"]:
        s_off, e_off = starts[0]["offset_ns"], stops[0]["offset_ns"]
        inside = [r["attempt_offset_ns"] for r in ledger if s_off < r["attempt_offset_ns"] < e_off]
        resumed = [r["attempt_offset_ns"] for r in ledger if r["attempt_offset_ns"] > e_off]
        out["I4"] = not inside and bool(resumed)
        det["publishing"] = dict(inside_silence=len(inside), after_silence=len(resumed), before_silence=len([r for r in ledger if r["attempt_offset_ns"] < s_off]))
    else:
        out["I4"] = False
    ended = next((e for e in events if e.get("kind") == "RUNNER_ENDED" and e.get("shard") == "router"), None)
    out["I5"] = bool(ended) and ended.get("state") == "COMPLETE"
    told = {t["n"]: t for t in timeline if t.get("step") == "INSTRUCTION"}
    closed = {t["n"]: t for t in timeline if t.get("step") in ("INSTRUCTION_DONE", "INSTRUCTION_CANCELLED")}
    open_at = lambda device, ts: any(t["device"] == device and t["action"].startswith("RESTORE") and t["utc_ns"] <= ts and (n not in closed or closed[n]["utc_ns"] >= ts - NS) for n, t in told.items())
    restores = [o for o in outcomes if o["body"].get("request_kind") == "RESTORE" and "final" not in str(o["body"].get("request_id")) and str(o["body"].get("request_id", "")).startswith("admin-restore-ui")]
    unplanned = [(o["body"]["device"], o["body"]["status"], o["ts_utc_ns"]) for o in restores if not open_at(o["body"]["device"], o["ts_utc_ns"])]
    out["I6"] = bool(told) and set(told) == set(closed) and not unplanned
    det["instructions"] = dict(told=len(told), closed=len(closed), unclosed=sorted(set(told) - set(closed)), operator_restores=len(restores), restores_without_an_open_instruction=unplanned)
    return out, det


def verdict(run, rules="v2"):
    base = ROOT / "results/engineering/runs" / run
    pep = jsonl(base / "pep/continuous.jsonl")
    recs = jsonl(base / "service/recommendations.jsonl")
    timeline = jsonl(ROOT / "results/engineering/pilot" / run / "operator_timeline.jsonl")
    events = jsonl(base / "control/events.jsonl")
    side = ROOT / "results/engineering/pilot" / f"{run}-session"
    post_state_path = ROOT / "results/engineering/pilot" / run / "post_state.json"
    post_state = json.loads(post_state_path.read_text(encoding="utf-8")) if post_state_path.exists() else {}
    restricted, pre, post = probes(side / "probe_restricted.txt"), probes(side / "probe_pre.txt"), probes(side / "probe_post.txt")
    outcomes = [e for e in pep if e["kind"] == "OUTCOME"]
    reviews = {e["body"]["review_id"]: e for e in pep if e["kind"] == "REVIEW_OPENED"}
    resolved = {e["body"]["review_id"]: e for e in pep if e["kind"] == "REVIEW_RESOLVED"}
    handled = [e for e in pep if e["kind"] == "RECORD_HANDLED"]
    after = {e["body"].get("request_id"): e["body"] for e in pep if e["kind"] == "OBSERVED" and e["body"].get("phase") == "after"}
    roles = lambda body: [r[0] for r in (body.get("observed") or {}).get("roles", [])]
    checks, detail = {}, {}

    # ---- liveness
    silence = sorted((e["utc_ns"], e.get("action")) for e in events if e.get("device") == "device01" and e.get("kind") == "COMMAND_APPLIED" and (e.get("anomaly") == "silence" or e.get("action") == "stop"))
    starts = [t for t, a in silence if a == "start"]
    stops = [t for t, a in silence if a == "stop"]
    seg = (min(starts), max(stops) + LIVENESS_BOUND_S * NS) if starts and stops else None
    live_reviews = [r for r in reviews.values() if r["body"]["device"] == "device01" and r["body"]["origin"] == "SUPPLEMENTARY_TIMING"]
    first = live_reviews[0]["body"] if live_reviews else None
    silent_ns = ((first or {}).get("decision_record") or {}).get("behavior", {}).get("supplementary", {}).get("silent_ns") if first else None
    checks["L1"] = bool(first) and (first.get("decision") or {}).get("decision_source") == "LIVENESS" and isinstance(silent_ns, int) and silent_ns > LIVENESS_BOUND_S * NS
    res = resolved.get(first["review_id"]) if first else None
    checks["L2"] = bool(res) and res["body"].get("state") == "EXECUTED" and bool(res["body"].get("operator_ref")) and not any(o["body"]["device"] == "device01" and o["body"].get("desired_state") == "RESTRICT"
                                                                                                                           and o["ts_utc_ns"] < res["ts_utc_ns"] - NS for o in outcomes)
    out01 = next((o for o in outcomes if o["body"]["device"] == "device01" and o["body"].get("desired_state") == "RESTRICT"), None)
    rb = after.get(out01["body"]["request_id"]) if out01 else None
    checks["L3"] = bool(out01) and out01["body"]["status"] == "APPLIED_VERIFIED" and bool(rb) and "azta-device01-operation-publish" not in roles(rb) and "azta-device01-telemetry-publish" in roles(rb) and (rb.get("observed") or {}).get("disabled") is False
    checks["L4"] = denied(restricted.get("device01"), "own_operations") and allowed(restricted.get("device01"), "own_telemetry")
    supplementary = [r for r in recs if (r.get("supplementary") or {}).get("recommendation")]
    stray = [r for r in supplementary if r["device"] != "device01" or not (seg and seg[0] <= r["decision_ns"] <= seg[1])]
    checks["L5"] = not stray
    detail["liveness"] = dict(silence_segment_utc_ns=seg, silent_ns_at_review=silent_ns, supplementary_records=len(supplementary), stray=[(r["device"], r["decision_ns"]) for r in stray][:20])

    # ---- AE automatic, recovery
    d02_q = [o for o in outcomes if o["body"]["device"] == "device02" and o["body"].get("desired_state") == "QUARANTINE" and o["body"]["status"] == "APPLIED_VERIFIED"]
    auto = []
    for o in d02_q:
        h = next((x["body"] for x in handled if x["body"].get("request_id") == o["body"]["request_id"]), None)
        auto.append(bool(h) and (h.get("decision") or {}).get("decision_source") == "AE_BEHAVIOR" and not any(r["body"].get("request_id") == o["body"]["request_id"] for r in resolved.values()))
    checks["A1"] = bool(auto) and all(auto)
    if rules == "v3":        # each device02 QUARANTINE judged by its RECOMPUTED cause: AE-caused ones automatic, every other cause reviewed (never automatic); at least one AE-caused
        causes = {a["request_id"]: a for a in trace.trace(run)["actions"]}
        ae_auto, other_reviewed = [], []
        for o in d02_q:
            a = causes.get(o["body"]["request_id"]) or {}
            reviewed = any(r["body"].get("request_id") == o["body"]["request_id"] for r in resolved.values())
            (ae_auto if a.get("decision_source") == "AE_BEHAVIOR" else other_reviewed).append(not reviewed if a.get("decision_source") == "AE_BEHAVIOR" else reviewed)
        checks["A1"] = bool(ae_auto) and all(ae_auto) and all(other_reviewed)
        detail["a1"] = dict(ae_caused=len(ae_auto), ae_caused_automatic=sum(ae_auto), other_causes=len(other_reviewed), other_causes_reviewed=sum(other_reviewed))
    opened = [e for e in pep if e["kind"] == "RECOVERY_WINDOW_OPENED"]
    closed = [e for e in pep if e["kind"] == "RECOVERY_WINDOW_CLOSED"]
    restores = [o for o in outcomes if o["body"].get("request_kind") == "RESTORE" and o["body"]["status"] == "APPLIED_VERIFIED" and "final" not in str(o["body"].get("request_id"))]
    checks["R1"] = bool(opened) and len(closed) >= len(opened) - 1 and all(any(c["body"]["device"] == op_["body"]["device"] and c["seq"] > op_["seq"] for c in closed) for op_ in opened[:-1])
    notes = {t["step"]: t for t in timeline}
    checks["R2"] = notes.get("AFTER_RESTORE_HEALTHY", {}).get("recontained") is False
    persistent = notes.get("PERSISTENT_ANOMALY", {})
    held = [x["body"] for x in handled if x["body"].get("device") == "device02" and x["body"].get("reason") == "POST_RESTORE_RECOVERY_WINDOW"]
    checks["R3"] = persistent.get("recontained") is True and persistent.get("recovery_window") is True and any(h.get("decision", {}).get("proposed_state") == "QUARANTINE" for h in held)
    detail["recovery"] = dict(opened=len(opened), closed=[c["body"] for c in closed], restores=len(restores), held=len(held))

    # ---- context
    if rules == "v1":
        ctx = [r["body"] for r in reviews.values() if r["body"]["device"] == "device02" and r["body"]["origin"] == "CONTEXT_POLICY"]
        ctx_res = resolved.get(ctx[0]["review_id"]) if ctx else None
        out_ctx = next((o for o in outcomes if o["body"]["device"] == "device02" and o["body"].get("desired_state") == "RESTRICT"), None)
        checks["C1"] = bool(ctx) and bool(ctx_res) and ctx_res["body"].get("state") == "EXECUTED" and bool(out_ctx) and out_ctx["body"]["status"] == "APPLIED_VERIFIED" and out_ctx["ts_utc_ns"] >= ctx_res["ts_utc_ns"] - NS \
            and denied(restricted.get("device02"), "own_operations") and allowed(restricted.get("device02"), "own_telemetry")
    else:
        checks["C1"], detail["context"] = context_v2(pep, reviews, resolved, outcomes, after, roles, timeline, restricted)

    # ---- reconstruction and labels
    t = trace.trace(run)
    mismatched = [(a["device"], a["desired_state"]) for a in t["actions"] if a.get("pep_record") and (a["pep_record"].get("decision") or {}).get("decision_source") != a.get("decision_source")]
    checks["G1"] = not t["unlinked_actions"] and not mismatched and bool(t["actions"])
    inbox = {r["evidence_id"]: r for r in jsonl(base / "service/inbox.jsonl") if isinstance(r, dict) and r.get("evidence_id")}
    wrong = [r["evidence_id"] for r in recs if r.get("recommendation_origin") == "AE_PRIMARY" and r.get("recommendation") not in ("FULL_ACCESS", "NONE") and attr.attribute(inbox.get(r["evidence_id"], {})).get("origin") != "AE_PRIMARY"]
    checks["G2"] = not wrong
    detail["trace"] = dict(actions=len(t["actions"]), unlinked=t["unlinked_actions"], mismatched=mismatched, ledger_mislabelled=wrong[:20])

    # ---- scope and final state
    foreign = [o["body"]["device"] for o in outcomes if o["body"]["device"] in OUT_OF_SCOPE]
    same = all(pre.get(d, {}).get("publishes") and {k: v.get("puback") for k, v in pre[d]["publishes"].items()} == {k: v.get("puback") for k, v in (post.get(d) or {}).get("publishes", {}).items()} for d in OUT_OF_SCOPE)
    checks["S1"] = not foreign and same
    checks["F1"] = post_state.get("final_audit_pass") is True and post_state.get("final_audit_policy_sha256") == BASELINE and post_state.get("down_used_v") is False and post_state.get("volume_kept") is True \
        and post_state.get("protected_fingerprints_unchanged") is True and post_state.get("post_probes_ok") is True
    integrity = None
    if rules != "v1":
        integrity, detail["integrity"] = integrity_v2(base, run, events, outcomes, timeline, exempt_enforcement_reconnect=rules == "v3")
    passed = all(checks.values()) and (integrity is None or all(integrity.values()))
    return dict(schema="azta.stabilization.live_verdict", run=run, protocol="docs/stabilization/STB_LIVE_SESSION_PROTOCOL.md", rules=rules, all_pass=passed, checks=checks, integrity=integrity, detail=detail,
                actions=[dict(device=a["device"], state=a["desired_state"], status=a["status"], cause=a["decision_source"], authorization=a["authorization"]["kind"], latency=a["latency"]) for a in t["actions"]])


def verdict_v4(run):
    """Amendment 4: the supervisor-directed AZTA-EXP-v1 verification (`stb-l04`, device02 only, tau_Q 65). Declared before the session; nothing is adjusted after seeing the data.
    P1 the runtime used the EXP-v1 configuration (every recommendation carries its digest; every evaluated decision records tau_Q 65 and tau_R 75).
    B1-B5 strong behavioural anomaly: an AE-caused QUARANTINE that is automatic, N = 2 confirmed, read back as QUARANTINE with the client disabled, seen by the device itself as a contained
          connection that resumes only after the owner's instructed RESTORE, followed by the recovery window and healthy reporting.
    C1 the context RESTRICT causal chain (amendment 2, unchanged); C2 the declared review was CONTEXT-caused RESTRICT under tau_Q 65 and device02 was never escalated to QUARANTINE after the
          time cut (no QUARANTINE review, no QUARANTINE outcome, no automatic action).
    G1 G2 tracing and labels; L0 no liveness recommendation on any device; S1 no action outside device02 and devices 01, 03-10 probe identically before and after; F1 final state;
    I5 the workload ends COMPLETE; I6 every owner instruction closed and every operator RESTORE instructed."""
    from core_runtime import cli
    from trust.config import TrustConfig
    base = ROOT / "results/engineering/runs" / run
    pep = jsonl(base / "pep/continuous.jsonl")
    recs = jsonl(base / "service/recommendations.jsonl")
    inbox = [r for r in jsonl(base / "service/inbox.jsonl") if isinstance(r, dict) and r.get("evidence_id")]
    timeline = jsonl(ROOT / "results/engineering/pilot" / run / "operator_timeline.jsonl")
    events = jsonl(base / "control/events.jsonl")
    side = ROOT / "results/engineering/pilot" / f"{run}-session"
    post_state_path = ROOT / "results/engineering/pilot" / run / "post_state.json"
    post_state = json.loads(post_state_path.read_text(encoding="utf-8")) if post_state_path.exists() else {}
    restricted, pre, post = probes(side / "probe_restricted.txt"), probes(side / "probe_pre.txt"), probes(side / "probe_post.txt")
    outcomes = [e for e in pep if e["kind"] == "OUTCOME"]
    reviews = {e["body"]["review_id"]: e for e in pep if e["kind"] == "REVIEW_OPENED"}
    resolved = {e["body"]["review_id"]: e for e in pep if e["kind"] == "REVIEW_RESOLVED"}
    after = {e["body"].get("request_id"): e["body"] for e in pep if e["kind"] == "OBSERVED" and e["body"].get("phase") == "after"}
    roles = lambda body: [r[0] for r in (body.get("observed") or {}).get("roles", [])]
    t = trace.trace(run)
    checks, detail = {}, {}

    # ---- P1 the configuration actually used
    config = TrustConfig.from_dict(json.loads((ROOT / cli.CONFIG).read_text(encoding="utf-8")))
    wrong_digest = [r["evidence_id"] for r in recs if r.get("config_sha256") != config.sha256()]
    evaluated = [r for r in inbox if r.get("status") == "EVALUATED" and not (r.get("fusion") or {}).get("hard_gate_applied")]
    wrong_tau = [r["evidence_id"] for r in evaluated if ((r.get("fusion") or {}).get("tau_Q"), (r.get("fusion") or {}).get("tau_R")) != (float(config.tau_q), float(config.tau_r))]
    checks["P1"] = bool(recs) and bool(evaluated) and not wrong_digest and not wrong_tau and (float(config.tau_q), float(config.tau_r)) == (65.0, 75.0)
    detail["configuration"] = dict(config=cli.CONFIG, config_sha256=config.sha256(), recommendations=len(recs), evaluated_decisions=len(evaluated), wrong_digest=wrong_digest[:10], wrong_tau=wrong_tau[:10])

    # ---- B strong behavioural anomaly
    q_actions = [a for a in t["actions"] if a["device"] == "device02" and a["desired_state"] == "QUARANTINE" and a["status"] == "APPLIED_VERIFIED"]
    ae = [a for a in q_actions if a.get("decision_source") == "AE_BEHAVIOR"]
    others = [a for a in q_actions if a.get("decision_source") != "AE_BEHAVIOR"]
    checks["B1"] = bool(ae) and all(a["authorization"]["kind"] == "AUTOMATIC" for a in ae) and all(a["authorization"]["kind"] == "OPERATOR_REVIEW" for a in others) \
        and all(isinstance(a.get("trust"), (int, float)) and a["trust"] < 65.0 for a in ae)
    first = ae[0] if ae else None
    run_ = (first or {}).get("confirmation_run") or []
    index_of = lambda evidence_id: int(str(evidence_id).rsplit("-w", 1)[1]) if "-w" in str(evidence_id) else None
    checks["B2"] = bool(run_) and run_[0].get("needed") == 2 and run_[0].get("confirmations") == 1 and index_of(run_[0]["evidence_id"]) == (first or {}).get("window_index", -9) - 1
    verified = (first or {}).get("broker_verified") or {}
    checks["B3"] = bool(first) and verified.get("states") == ["QUARANTINE"] and verified.get("disabled") is True
    restore = next((o for o in outcomes if first and o["body"]["device"] == "device02" and o["body"].get("request_kind") == "RESTORE" and o["body"]["status"] == "APPLIED_VERIFIED"
                    and str(o["body"].get("request_id", "")).startswith("admin-restore-ui") and o["ts_utc_ns"] > first["enforcement_utc_ns"]), None)
    contained = [e["utc_ns"] for e in events if e.get("device") == "device02" and e.get("kind") == "DEVICE_CONTAINED"]
    resumed = [e["utc_ns"] for e in events if e.get("device") == "device02" and e.get("kind") == "DEVICE_RESUMED"]
    seen = next((c for c in contained if first and abs(c - first["enforcement_utc_ns"]) <= 5 * NS), None)
    back = next((r for r in resumed if seen and r > seen), None)
    checks["B4"] = bool(seen) and bool(restore) and bool(back) and back >= restore["ts_utc_ns"] - 2 * NS
    notes = {x["step"]: x for x in timeline}
    opened_after = [e for e in pep if e["kind"] == "RECOVERY_WINDOW_OPENED" and e["body"].get("device") == "device02" and restore and e["seq"] > next(o["seq"] for o in outcomes if o is restore)]
    closed_after = [e for e in pep if e["kind"] == "RECOVERY_WINDOW_CLOSED" and e["body"].get("device") == "device02" and opened_after and e["seq"] > opened_after[0]["seq"]]
    checks["B5"] = bool(restore) and bool(opened_after) and bool(closed_after) and notes.get("AFTER_RESTORE_HEALTHY", {}).get("recontained") is False
    detail["behaviour"] = dict(ae_quarantines=[dict(request_id=a["request_id"], trust=a.get("trust"), a_ae=a.get("a_ae"), authorization=a["authorization"]["kind"], window_index=a.get("window_index"),
                                                    confirmation_run=a.get("confirmation_run"), broker_verified=a.get("broker_verified"), latency=a.get("latency")) for a in ae],
                               other_quarantines=[(a["request_id"], a.get("decision_source"), a["authorization"]["kind"]) for a in others], contained_utc_ns=seen, resumed_utc_ns=back,
                               restore_utc_ns=(restore or {}).get("ts_utc_ns"), recovery_opened=len(opened_after), recovery_closed=[c["body"] for c in closed_after])

    # ---- C context
    checks["C1"], detail["context"] = context_v2(pep, reviews, resolved, outcomes, after, roles, timeline, restricted)
    cut = next((x.get("effective_utc_ns") for x in timeline if x.get("step") == "TIME_CUT_DECLARED"), None)
    declared = reviews.get(detail["context"].get("declared_review_id")) if detail["context"].get("declared_review_id") else None
    record = ((declared or {}).get("body") or {}).get("decision_record") or {}
    cause = attr.attribute(record) if record else {}
    fusion = record.get("fusion") or {}
    later = [e for e in pep if isinstance(cut, int) and e["ts_utc_ns"] >= cut and e["body"].get("device") == "device02"]
    escalated_reviews = [e["body"]["review_id"] for e in later if e["kind"] == "REVIEW_OPENED" and (e["body"].get("action") == "QUARANTINE" or (e["body"].get("decision_record") or {}).get("proposed_state") == "QUARANTINE")]
    escalated_outcomes = [e["body"].get("request_id") for e in later if e["kind"] == "OUTCOME" and e["body"].get("desired_state") == "QUARANTINE"]
    automatic_after = [a["request_id"] for a in t["actions"] if a["device"] == "device02" and isinstance(cut, int) and a["enforcement_utc_ns"] >= cut and a["authorization"]["kind"] != "OPERATOR_REVIEW"]
    checks["C2"] = bool(record) and cause.get("decision_source") == "CONTEXT" and record.get("proposed_state") == "RESTRICT" and isinstance(fusion.get("s_c"), (int, float)) and fusion["s_c"] < 100 \
        and fusion.get("tau_Q") == 65.0 and not escalated_reviews and not escalated_outcomes and not automatic_after
    detail["context"].update(declared_cause=cause.get("decision_source"), declared_state=record.get("proposed_state"), declared_fusion={k: fusion.get(k) for k in ("s_id", "s_b", "s_c", "trust", "tau_Q", "tau_R")},
                             escalated_reviews=escalated_reviews, escalated_outcomes=escalated_outcomes, automatic_after_cut=automatic_after)

    # ---- tracing, scope, final state, integrity
    mismatched = [(a["device"], a["desired_state"]) for a in t["actions"] if a.get("pep_record") and (a["pep_record"].get("decision") or {}).get("decision_source") != a.get("decision_source")]
    checks["G1"] = not t["unlinked_actions"] and not mismatched and bool(t["actions"])
    by_id = {r["evidence_id"]: r for r in inbox}
    wrong = [r["evidence_id"] for r in recs if r.get("recommendation_origin") == "AE_PRIMARY" and r.get("recommendation") not in ("FULL_ACCESS", "NONE") and attr.attribute(by_id.get(r["evidence_id"], {})).get("origin") != "AE_PRIMARY"]
    checks["G2"] = not wrong
    detail["trace"] = dict(actions=len(t["actions"]), unlinked=t["unlinked_actions"], mismatched=mismatched, ledger_mislabelled=wrong[:20])
    liveness = [(r["device"], r["decision_ns"]) for r in recs if (r.get("supplementary") or {}).get("recommendation")]
    checks["L0"] = not liveness
    detail["liveness_records"] = liveness[:20]
    others_ = [f"device{n:02d}" for n in range(1, 11) if n != 2]
    foreign = [o["body"]["device"] for o in outcomes if o["body"]["device"] != "device02"]
    same = all(pre.get(d, {}).get("publishes") and {k: v.get("puback") for k, v in pre[d]["publishes"].items()} == {k: v.get("puback") for k, v in (post.get(d) or {}).get("publishes", {}).items()} for d in others_)
    checks["S1"] = not foreign and same
    checks["F1"] = post_state.get("final_audit_pass") is True and post_state.get("final_audit_policy_sha256") == BASELINE and post_state.get("down_used_v") is False and post_state.get("volume_kept") is True \
        and post_state.get("protected_fingerprints_unchanged") is True and post_state.get("post_probes_ok") is True
    ended = next((e for e in events if e.get("kind") == "RUNNER_ENDED" and e.get("shard") == "router"), None)
    checks["I5"] = bool(ended) and ended.get("state") == "COMPLETE"
    told = {x["n"]: x for x in timeline if x.get("step") == "INSTRUCTION"}
    closed = {x["n"]: x for x in timeline if x.get("step") in ("INSTRUCTION_DONE", "INSTRUCTION_CANCELLED")}
    open_at = lambda device, ts: any(x["device"] == device and x["action"].startswith("RESTORE") and x["utc_ns"] <= ts and (n not in closed or closed[n]["utc_ns"] >= ts - NS) for n, x in told.items())
    ui_restores = [o for o in outcomes if o["body"].get("request_kind") == "RESTORE" and str(o["body"].get("request_id", "")).startswith("admin-restore-ui")]
    unplanned = [(o["body"]["device"], o["body"]["status"], o["ts_utc_ns"]) for o in ui_restores if not open_at(o["body"]["device"], o["ts_utc_ns"])]
    checks["I6"] = bool(told) and set(told) == set(closed) and not unplanned
    detail["instructions"] = dict(told=len(told), closed=len(closed), unclosed=sorted(set(told) - set(closed)), operator_restores=len(ui_restores), restores_without_an_open_instruction=unplanned,
                                  cancelled=[closed[n].get("why") for n in closed if closed[n].get("step") == "INSTRUCTION_CANCELLED"])
    return dict(schema="azta.stabilization.live_verdict", run=run, protocol="docs/stabilization/STB_LIVE_SESSION_PROTOCOL.md", rules="v4", all_pass=all(checks.values()), checks=checks, integrity=None, detail=detail,
                actions=[dict(device=a["device"], state=a["desired_state"], status=a["status"], cause=a["decision_source"], authorization=a["authorization"]["kind"], latency=a["latency"]) for a in t["actions"]])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", default="stb-l01")
    parser.add_argument("--out", required=True)
    parser.add_argument("--rules", choices=("v1", "v2", "v3", "v4"), default="v3", help="v1: stb-l01 and stb-l02 (their verdicts stand); v2: amendment 2, stb-l03 (its verdict stands); v3: amendment 3; v4: amendment 4, stb-l04 (EXP-v1 verification)")
    args = parser.parse_args(argv)
    result = verdict_v4(args.run) if args.rules == "v4" else verdict(args.run, args.rules)
    out = ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, indent=1, sort_keys=True, default=str)
        stream.write("\n")
    print(json.dumps(dict(all_pass=result["all_pass"], checks=result["checks"]), indent=1))
    return 0 if result["all_pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
