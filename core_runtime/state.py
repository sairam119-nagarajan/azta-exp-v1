"""What the operator console and exports may say, read only from durable files: the recommendations ledger, the PEP's hash-chained audit log (the broker's own read-backs, reviews and outcomes) and the operator intent log.

Nothing here is a belief of the console. A broker state older than the stated bound, an unreadable or broken log and a missing file are shown as UNKNOWN or STALE. No credential, secret or administrative command passes through this module.
"""
from enforcement.authority import EXECUTION_STATUS, MAP_SCHEMA
from enforcement.audit import AuditLog
from enforcement.clock import SystemClock
from enforcement.errors import AuditIntegrityError
from pathlib import Path
import json

DEVICES = tuple(f"device{i:02d}" for i in range(1, 11))
STATE_STALE_NS = 120_000_000_000
EVIDENCE_STALE_NS = 60_000_000_000
PUBLIC_REVIEW_FIELDS = ("review_id", "device", "action", "origin", "evidence_ids", "reason", "authority_mode", "generation", "current_state", "opened_utc_ns", "expires_utc_ns", "digests", "risk", "scope_id", "state", "resolution")


def read_jsonl(path):
    """(records, problem). A partial last line waits; anything else unreadable is reported, never skipped silently."""
    path = Path(path)
    if not path.exists():
        return [], "MISSING"
    try:
        lines = path.read_bytes().split(b"\n")
    except OSError as exc:
        return [], type(exc).__name__
    out = []
    for line in lines[:-1]:
        if line.strip():
            try:
                out.append(json.loads(line.decode("utf-8")))
            except ValueError:
                return out, "UNPARSEABLE_LINE"
    return out, None


def read_chain(path):
    """(entries, problem): the hash chain is verified on every read."""
    path = Path(path)
    if not path.exists():
        return [], "MISSING"
    try:
        return AuditLog.open_existing(path, SystemClock()).entries, None
    except (AuditIntegrityError, OSError, ValueError) as exc:
        return [], getattr(exc, "code", type(exc).__name__)


class SessionFiles:
    def __init__(self, directory, *, pep_log=None, authority_map=None, session=None):
        self.directory = Path(directory)
        self.recommendations = self.directory / "recommendations.jsonl"
        self.intents = self.directory / "intents.jsonl"
        self.pep_log = Path(pep_log) if pep_log else self.directory / "pep.jsonl"
        self.rc1_status = self.directory / "rc1_status.json"
        self.authority_map = authority_map
        self.session = session or {}


def broker_states(entries):
    """{device: (verified body, read-back UTC ns)}: the last OBSERVED or BASELINE_OBSERVED entry of each device."""
    out = {}
    for entry in entries:
        if entry["kind"] in ("OBSERVED", "BASELINE_OBSERVED"):
            out[entry["body"]["device"]] = (entry["body"], entry["ts_utc_ns"])
    return out


CONFIRMATION_N = 2          # N = 2 is fixed by the launcher (`rehearsal_tools/fleet_run.py`); a CONFIRMING entry carries its own `needed`, which wins


def pep_confirmations(entries):
    """{device: the confirmation state of the PEP's OWN filter}, rebuilt from its audit log (stabilization requirement 2, console counter).

    The PEP's filter is the only counter that can reach the broker. Its count is the `confirmations` of the device's last RECORD_HANDLED entry when that entry is CONFIRMING, and 0
    otherwise (a hold, a request, a refusal or a recovery window resets it). A later verified operator RESTORE or an executed review also clears the PEP's pending count
    (`AuthorityRunner._restore`, `_approve`), so it resets the count here too. The recommendations ledger's own tracker never sees those events and is shown only as the PDP's view."""
    out = {}
    for entry in entries:
        body, kind = entry["body"], entry["kind"]
        device = body.get("device")
        if kind == "RECORD_HANDLED" and isinstance(device, str):
            confirming = body.get("disposition") == "CONFIRMING"
            out[device] = dict(source="PEP_AUDIT_LOG", seq=entry["seq"], evidence_id=body.get("evidence_id"), disposition=body.get("disposition"), reason=body.get("reason"),
                               confirmations=body.get("confirmations", 0) if confirming else 0, needed=body.get("needed") or CONFIRMATION_N, target=(body.get("decision") or {}).get("proposed_state") if confirming else None,
                               recovery_window=bool(body.get("recovery_window")))
        elif kind == "OUTCOME" and isinstance(device, str) and body.get("request_kind") == "RESTORE" and device in out:
            out[device] = dict(out[device], confirmations=0, target=None, seq=entry["seq"], disposition="RESET_BY_RESTORE", reason="RESTORE_CLEARS_THE_PEP_COUNT")
        elif kind == "REVIEW_RESOLVED" and body.get("state") == "EXECUTED" and isinstance(device, str) and device in out:
            out[device] = dict(out[device], confirmations=0, target=None, seq=entry["seq"], disposition="RESET_BY_EXECUTED_REVIEW", reason="AN_EXECUTED_REVIEW_CLEARS_THE_PEP_COUNT")
    return out


def recovery_of(entries):
    """{device: open recovery window body} after a verified RESTORE (rule POST_RESTORE_ONE_WINDOW_V1), from the PEP log."""
    out = {}
    for entry in entries:
        if entry["kind"] == "RECOVERY_WINDOW_OPENED":
            out[entry["body"]["device"]] = entry["body"]
        elif entry["kind"] == "RECOVERY_WINDOW_CLOSED":
            out.pop(entry["body"]["device"], None)
    return out


def reviews_of(entries):
    reviews = {}
    for entry in entries:
        body = entry["body"]
        if entry["kind"] == "REVIEW_OPENED":
            reviews[body["review_id"]] = dict(body, state="PENDING")
        elif entry["kind"] == "REVIEW_RESOLVED":
            reviews[body["review_id"]].update(state=body["state"], resolution=body)
    return reviews


def public_review(review):
    """Everything an operator needs, without the verbatim decision record."""
    return {k: review.get(k) for k in PUBLIC_REVIEW_FIELDS}


def snapshot(files, now_ns):
    """The fleet view. Every field says what it rests on; nothing is remembered between calls."""
    recommendations, rec_problem = read_jsonl(files.recommendations)
    entries, pep_problem = read_chain(files.pep_log)
    intents, intent_problem = read_chain(files.intents)
    states = broker_states(entries)
    reviews = reviews_of(entries)
    pep_counts, recovery = pep_confirmations(entries), recovery_of(entries)
    latest, history = {}, {d: [] for d in DEVICES}
    for record in recommendations:
        device = record.get("device")
        if device in history:
            latest[device] = record
            history[device].append(record)
    outcomes = {}
    for entry in entries:
        if entry["kind"] == "OUTCOME":
            outcomes.setdefault(entry["body"]["device"], []).append(dict(ts_utc_ns=entry["ts_utc_ns"], desired_state=entry["body"].get("desired_state"), status=entry["body"]["status"], execution_status=EXECUTION_STATUS.get(entry["body"]["status"], "UNKNOWN"), origin=entry["body"].get("origin"),
                                                                         request_kind=entry["body"].get("request_kind"), permission_equivalent=entry["body"].get("permission_equivalent")))
    stopped, generations = False, {}
    for entry in entries:
        if entry["kind"] == "ACTIONS_STOPPED":
            stopped = bool(entry["body"]["stopped"])
        elif entry["kind"] == "GENERATION":
            generations[entry["body"]["device"]] = entry["body"]["generation"]
    map_data = (files.authority_map or {}) if isinstance(files.authority_map, dict) else {}
    devices = []
    for device in DEVICES:
        record = latest.get(device) or {}
        state = states.get(device)
        pending = [public_review(r) for r in reviews.values() if r["device"] == device and r["state"] == "PENDING"]
        if pep_problem:
            broker = dict(state="UNKNOWN", reason=f"PEP_LOG_{pep_problem}")
        elif state is None:
            broker = dict(state="UNKNOWN", reason="NO_READ_BACK_YET")
        else:
            body, read_ns = state
            age = now_ns - read_ns
            shown = "/".join(body.get("states") or []) or body.get("shape") or "UNKNOWN"
            broker = dict(state="STALE" if age > STATE_STALE_NS else shown, last_verified=shown, read_back_age_ns=age, disabled=(body.get("observed") or {}).get("disabled"), roles=[r[0] for r in (body.get("observed") or {}).get("roles", [])])
        decision_ns = record.get("decision_ns")
        evidence_age = now_ns - decision_ns if isinstance(decision_ns, int) else None
        devices.append(dict(device=device, recommendation=record.get("recommendation", "NONE") if record else "UNKNOWN", origin=record.get("recommendation_origin"), behavior_source=record.get("behavior_source"), ae_status=record.get("ae_status"),
                            ae_loss=record.get("ae_loss"), a_ae=record.get("a_ae"), s_b_ae=record.get("s_b_ae"), s_id=record.get("s_id"), s_c=record.get("s_c"), t_ae=record.get("t_ae"), route_arm=record.get("route_arm"), calibration_id=record.get("calibration_id"), calibration_status=record.get("calibration_status"),
                            model_id=record.get("model_id"), window_index=record.get("window_index"), evidence_age_ns=evidence_age, evidence_stale=evidence_age is None or evidence_age > EVIDENCE_STALE_NS,
                            confirmation=(dict(state="UNKNOWN", reason=f"PEP_LOG_{pep_problem}") if pep_problem else pep_counts.get(device) or dict(source="PEP_AUDIT_LOG", confirmations=0, needed=CONFIRMATION_N, disposition="NO_RECORD_HANDLED_YET")),
                            pdp_confirmation=record.get("confirmation"), recovery_window_open=device in recovery, decision_source=record.get("decision_source"), causes=record.get("causes"), authority_mode=record.get("authority_mode") or (map_data.get("devices", {}).get(device) or {}).get("mode"),
                            restrict_is_permission_noop=(map_data.get("devices", {}).get(device) or {}).get("restrict_is_permission_noop"), generation=generations.get(device), broker=broker, pending_reviews=pending, outcomes=outcomes.get(device, [])[-5:]))
    return dict(now_ns=now_ns, session=files.session, problems={k: v for k, v in dict(recommendations=rec_problem, pep_log=pep_problem, intents=intent_problem).items() if v and v != "MISSING"}, missing=[k for k, v in dict(recommendations=rec_problem, pep_log=pep_problem).items() if v == "MISSING"],
                actions_stopped=stopped, devices=devices, reviews=[public_review(r) for r in reviews.values()], intents_seen=len(intents), intent_results=[dict(seq=e["body"].get("intent_seq"), key=e["body"].get("idempotency_key"), kind=e["body"].get("intent_kind"), device=e["body"].get("device"), result=e["body"].get("result")) for e in entries if e["kind"] == "INTENT_HANDLED"][-50:],
                rc1=_rc1(files), map_schema_ok=map_data.get("schema") == MAP_SCHEMA)


def _rc1(files):
    try:
        return json.loads(files.rc1_status.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return dict(status="NOT_RUNNING")


def device_detail(files, device, *, limit=120):
    if device not in DEVICES:
        return None
    records, _ = read_jsonl(files.recommendations)
    rows = [r for r in records if r.get("device") == device][-limit:]
    entries, _ = read_chain(files.pep_log)
    timeline = [dict(ts_utc_ns=e["ts_utc_ns"], kind=e["kind"], status=e["body"].get("status") or e["body"].get("state"), desired_state=e["body"].get("desired_state") or e["body"].get("action"), review_id=e["body"].get("review_id")) for e in entries
                if e["kind"] in ("OUTCOME", "REVIEW_OPENED", "REVIEW_RESOLVED") and e["body"].get("device") == device]
    return dict(device=device, history=rows, policy_timeline=timeline[-limit:])


def metrics(files, now_ns):
    """Counts and durations for the export: recommendations, approvals, attempted, applied, verified and failed actions. Recorded observations of this session only; no accuracy figure is derived here."""
    records, _ = read_jsonl(files.recommendations)
    entries, problem = read_chain(files.pep_log)
    reviews = reviews_of(entries)
    resolved = [r.get("resolution") or {} for r in reviews.values()]
    by = lambda key: sum(1 for r in records if r.get("recommendation") == key)
    delays = [r["operator_delay_ns"] for r in resolved if isinstance(r.get("operator_delay_ns"), int)]
    outcomes = [e["body"] for e in entries if e["kind"] == "OUTCOME"]
    return dict(schema="azta.core.session_metrics", label="DEVELOPMENT_ONLY engineering observations of one session; not a final paper value and not an accuracy figure", session=files.session, generated_utc_ns=now_ns, pep_log_problem=problem, recommendations_total=len(records), by_recommendation={k: by(k) for k in ("FULL_ACCESS", "RESTRICT", "QUARANTINE", "NONE")},
                by_origin={o: sum(1 for r in records if r.get("recommendation_origin") == o) for o in ("AE_PRIMARY", "CONTEXT_POLICY", "MIXED_AE_CONTEXT", "IDENTITY_HARD_GATE", "SUPPLEMENTARY_TIMING", "UNATTRIBUTED")}, by_ae_status={s: sum(1 for r in records if r.get("ae_status") == s) for s in sorted({str(r.get("ae_status")) for r in records})},
                reviews_opened=len(reviews), reviews_by_state={s: sum(1 for r in reviews.values() if r["state"] == s) for s in sorted({r["state"] for r in reviews.values()})}, operator_delays_ns=delays, attempted_actions=len(outcomes), applied_verified=sum(o["status"] == "APPLIED_VERIFIED" for o in outcomes), noop_already_in_state=sum(o["status"] == "NOOP_ALREADY_IN_STATE" for o in outcomes),
                failed=sum(o["status"] not in ("APPLIED_VERIFIED", "NOOP_ALREADY_IN_STATE") for o in outcomes), permission_equivalent=sum(bool(o.get("permission_equivalent")) for o in outcomes), not_measured=["false requests and containments need an independent scenario oracle", "censored misses", "time to contain", "resources"])
