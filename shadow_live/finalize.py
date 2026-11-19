"""Finalization bridge: what a live session's record can and cannot say about the FINISHED observer session.

A live decision is LIVE_PROVISIONAL. This module re-reads the finished observer files (the same three allowlisted files, plus the audit stages by exact
name) and proves, line by line, that every window the adapter consumed live is byte-identical to the finished `windows.jsonl`: each recorded line must
sit at the recorded byte range with the recorded line digest and the recorded rolling prefix digest, no line of the file may be unrecorded, the whole
file must equal the digest the observer itself attests, and the accepted audit files must be unchanged. It also re-derives the declared audit cadence with
the existing `collection_audits_v2.describe`.

What it never does: accept a session. The statuses mean exactly:

  OBSERVER_SESSION_UNFINISHED     the observer's summary does not exist yet; nothing can be reconciled
  FINALIZATION_CHECK_FAILED       at least one reconciliation condition failed (the reasons are listed); the live record is NOT a faithful record of the file
  FINALIZATION_CHECK_PASSED       the live byte chain equals the finished file and the observer's own attestation, all lines are accounted and the audits are
                                  unchanged. This is a NECESSARY condition for a later acceptance, not acceptance: that needs the existing collection
                                  reconciliation and a manifest RUN_COLLECTED entry, and is read back only by the manifest-verified reader.
  SCIENTIFIC_SESSION_DIGESTS_MATCH  additionally, a `ScientificSession` that the manifest-verified reader returned for the same run has the same window-file
                                  digest, session id and audit digests (the reader, not this module, is what verified that session).
"""
from collections import Counter
import hashlib
import json
from pathlib import Path

from experiments import collection_audits_v2 as audits_v2
from shadow_feed import reader
from shadow_live.audits import MAX_PERIODIC
from shadow_live.errors import LiveRefused
from shadow_live.ledger import LiveLedger
from trust.timeline import parse_utc_ns

REPORT_SCHEMA = "azta.gate5f.live_finalization_report"
REPORT_FILE = "finalization.json"
MAX_LISTED = 20


def _sha(blob):
    return hashlib.sha256(blob).hexdigest()


def _read(path):
    try:
        return path.read_bytes()
    except OSError:
        return None


def _stages(plan):
    """Existing audit stages by EXACT name, in time order (pre, p01.., post). The raw root is never listed; periodic stages are consecutive, so the first
    missing one ends them (a gap is then visible in the cadence description), and `post` is always probed on its own."""
    root, run = plan.evidence_root, plan.run_id

    def probe(stage):
        paths = [reader.safe_path(root, f"{audits_v2.audit_ref(run, stage)}/{name}") for name in ("binding_audit.json", "run_summary.json")]
        return (stage, paths) if paths[1].exists() else None
    found = [item for item in [probe("pre")] if item]
    for number in range(1, MAX_PERIODIC + 1):
        item = probe(f"p{number:02d}")
        if item is None:
            break
        found.append(item)
    return found + [item for item in [probe("post")] if item]


def check_finalization(live_dir, plan, *, scientific_session=None):
    ledger = LiveLedger.open_existing(live_dir)
    declared = ledger.entries[0]["body"] if ledger.entries and ledger.entries[0]["kind"] == "SESSION_DECLARED" else None
    if declared is None or declared["declaration"]["declaration_file_sha256"] != plan.declaration_file_sha256:
        raise LiveRefused("RESUME_MISMATCH", "the ledger belongs to another declaration")
    session_id = declared["session_id"]
    report = dict(schema=REPORT_SCHEMA, schema_version=1, live_id=declared["live_id"], run_id=plan.run_id, session_id=session_id,
                  declaration_file_sha256=plan.declaration_file_sha256, ledger_head_sha256=ledger.head_sha256, accepted_scientific_session=False,
                  status=None, reasons=[], checks={}, next_step="acceptance needs the existing collection reconciliation and a manifest RUN_COLLECTED entry; "
                                                               "this report is a necessary condition only")
    reasons = report["reasons"]
    ended = ledger.of_kind("SESSION_ENDED")
    if not ended:
        raise LiveRefused("SESSION_NOT_ENDED", "the live session has not ended: end it (or resume it) before reconciling")
    directory = f"observation/{session_id}"
    files = {name: _read(reader.safe_path(plan.evidence_root, f"{directory}/{name}")) for name in ("session_metadata.json", "windows.jsonl", "session_summary.json")}
    if files["session_summary.json"] is None or files["windows.jsonl"] is None or files["session_metadata.json"] is None:
        report["status"] = "OBSERVER_SESSION_UNFINISHED"
        reasons.append("the observer's session summary (or another allowlisted file) does not exist yet")
        return report
    summary = json.loads(files["session_summary.json"].decode("utf-8"))
    attested = summary["artifact_sha256"]
    windows = files["windows.jsonl"]
    report["checks"]["observer"] = dict(state=summary["state"], failure_code=summary["failure_code"], invariants=summary["invariants"])
    if summary["state"] != "COMPLETE" or summary["failure_code"] is not None or not all(summary["invariants"].values()):
        reasons.append(f"the observer session is {summary['state']} (failure {summary['failure_code']!r}) and cannot become an accepted session")

    # ---- the byte chain: every recorded line is the finished file's line, nothing is unrecorded, the whole equals the observer's own digest
    final = ended[0]["body"]["source"]
    recorded = {}
    for poll in ledger.polls():
        for item in (*poll["body"]["received"], *poll["body"]["refused"]):
            recorded[item["line_number"]] = item
    rolling, position, verified = hashlib.sha256(), 0, 0
    unrecorded, differing = [], []
    lines = windows.splitlines(keepends=True)
    for number, raw in enumerate(lines, 1):
        rolling.update(raw)
        item = recorded.get(number)
        start, position = position, position + len(raw)
        if item is None:
            unrecorded.append(f"line {number}: in the finished file but never recorded live")
        elif (item["byte_start"], item["byte_end"], item["line_sha256"], item["prefix_sha256"]) != (start, position, _sha(raw), rolling.hexdigest()):
            differing.append(f"line {number}: bytes or rolling digest differ from what was consumed live")
        else:
            verified += 1
    absent = [f"line {n}: recorded live but absent from the finished file" for n in sorted(set(recorded) - set(range(1, len(lines) + 1)))]
    mismatches = absent + unrecorded + differing                       # the structural findings first: the listing is capped
    file_digest = _sha(windows)
    chain = dict(file_sha256=file_digest, observer_attested_sha256=attested.get("windows.jsonl"), live_final_prefix_sha256=final["prefix_sha256"],
                 live_final_offset=final["offset"], file_bytes=len(windows), lines_in_file=len(lines), lines_recorded_live=len(recorded), lines_verified=verified,
                 mismatches=mismatches[:MAX_LISTED], mismatch_count=len(mismatches))
    report["checks"]["byte_chain"] = chain
    if mismatches:
        reasons.append(f"{len(mismatches)} line(s) of the live record do not match the finished window file")
    if file_digest != attested.get("windows.jsonl"):
        reasons.append("the finished window file differs from the digest the observer attests in its own summary")
    if final["prefix_sha256"] != file_digest or final["offset"] != len(windows):
        reasons.append("the live adapter did not consume the whole finished window file (it covers a prefix, or a different byte sequence)")
    if _sha(files["session_metadata.json"]) != attested.get("session_metadata.json"):
        reasons.append("the session metadata differs from the digest the observer attests")
    attached = ledger.of_kind("SESSION_ATTACHED")
    if not attached or attached[0]["body"]["facts"]["metadata_sha256"] != _sha(files["session_metadata.json"]):
        reasons.append("the session metadata differs from the metadata the live session attached to")

    # ---- the audits: unchanged since they were used, and the declared cadence re-derived by the existing description
    accepted = {e["stage"]: e for e in ledger.audit_events() if e["kind"] == "AUDIT_ACCEPTED"}
    stages = _stages(plan)
    changed = []
    for stage, event in accepted.items():
        paths = dict(stages).get(stage)
        blobs = None if paths is None else [_read(p) for p in paths]
        if blobs is None or None in blobs or (_sha(blobs[0]), _sha(blobs[1])) != (event["record_sha256"], event["summary_sha256"]):
            changed.append(stage)
    items = []
    for stage, paths in stages:
        try:
            items.append(dict(stage=stage, ref=audits_v2.audit_ref(plan.run_id, stage), summary=json.loads(paths[1].read_bytes().decode("utf-8"))))
        except (OSError, ValueError):
            items.append(dict(stage=stage, ref=audits_v2.audit_ref(plan.run_id, stage), summary=None))
    start_ns = parse_utc_ns(attached[0]["body"]["facts"]["utc_start_text"]) + (summary.get("coverage_start_offset_ns") or 0) if attached else None
    end_ns = start_ns + plan.planned_window_count * plan.window_ns if start_ns is not None and summary["state"] == "COMPLETE" else None
    cadence = audits_v2.describe(items, start_ns, end_ns, plan.declaration.audit_interval_s)
    report["checks"]["audits"] = dict(accepted_live=sorted(accepted), changed_since_use=changed, cadence=cadence,
                                      coverage_basis="SESSION_METADATA_UTC_START_PLUS_OFFSET_UPPER_BOUND")
    if changed:
        reasons.append(f"accepted audit(s) changed since they were used: {changed}")
    if cadence["problems"]:
        reasons.append(f"the audit cadence does not re-derive: {cadence['problems'][:3]}")
    flags = ended[0]["body"]["integrity_flags"]
    report["checks"]["integrity"] = dict(flags=flags, halt=ended[0]["body"]["halt"])
    report["checks"]["events"] = dict(Counter(e["kind"] for poll in ledger.polls() for e in (*poll["body"]["source_events"], *poll["body"]["audit_events"])))
    if flags or ended[0]["body"]["halt"]:
        reasons.append(f"integrity flags or a halt were recorded live: {sorted(flags)}")
    accounting = ended[0]["body"]["accounting"]
    report["checks"]["accounting"] = dict(every_eligible_window_accounted=accounting["every_eligible_window_accounted"],
                                          expected_eligible_windows=accounting["expected_eligible_windows"],
                                          eligible_windows_accounted=accounting["eligible_windows_accounted"])
    if not accounting["every_eligible_window_accounted"]:
        reasons.append("not every planned eligible window is accounted")
    report["status"] = "FINALIZATION_CHECK_FAILED" if reasons else "FINALIZATION_CHECK_PASSED"

    # ---- optional: the manifest-verified session of the SAME run, as returned by the replay reader
    if scientific_session is not None:
        same = (scientific_session.run_id == plan.run_id and scientific_session.session_id == session_id
                and scientific_session.windows_sha256 == file_digest)
        audit_match = all(scientific_session.audit_digests.get(f"{stage}/binding_audit.json") == event["record_sha256"]
                          and scientific_session.audit_digests.get(f"{stage}/run_summary.json") == event["summary_sha256"] for stage, event in accepted.items())
        report["checks"]["scientific_session"] = dict(run_and_session_match=same, window_digest_match=scientific_session.windows_sha256 == file_digest,
                                                      accepted_audit_digests_match=audit_match, partition=scientific_session.partition)
        if report["status"] == "FINALIZATION_CHECK_PASSED" and same and audit_match:
            report["status"] = "SCIENTIFIC_SESSION_DIGESTS_MATCH"
        else:
            report["status"] = "FINALIZATION_CHECK_FAILED"
            reasons.append("the supplied scientific session does not match the live record")
    return report


def write_report(live_dir, report):
    """finalization.json, created exclusively (an earlier report is never overwritten)."""
    with open(Path(live_dir) / REPORT_FILE, "xb") as stream_file:
        stream_file.write((json.dumps(report, sort_keys=True, indent=1, allow_nan=False) + "\n").encode("utf-8"))
    return report
