"""Gate 5F.3 live-demo event schema for dashboard consumption: a pure, read-only view of offline Shadow decision records.

This is a data contract and a converter, not an application. It takes a decision record produced by the offline engine (or a
BUNDLE_REFUSED record) and returns one flat, self-describing event that a dashboard may render. It reads no file, opens no connection,
holds no credential and cannot change anything: every event states that the proposal was NOT applied (`enforcement` NONE,
`broker_policy_changes` 0) and that restoration is manual. Nothing here is a trust state of its own (SHADOW and RESTORE are not states).

Event kinds:
  TRUST_DECISION  a decision record with status EVALUATED (a proposed state exists)
  NO_PROPOSAL     a decision record that is not evaluable (missing evidence, REFUSE policy): the broker's existing controls remain in force
  BUNDLE_REFUSED  an input line that was refused before any decision (the reason is carried verbatim)

`device_label` is a DISPLAY label (the bound broker username already inside the record) and is never identity evidence. Identity is the
`components.identity` block.
"""
import math

EVENT_SCHEMA = "azta.gate5f3.demo_event"
EVENT_SCHEMA_VERSION = 1
KINDS = ("TRUST_DECISION", "NO_PROPOSAL", "BUNDLE_REFUSED")
STATES = ("QUARANTINE", "RESTRICT", "FULL_ACCESS")
RESTORATION = "MANUAL_ADMINISTRATIVE_ONLY"
BANNER_COUNTERFACTUAL = "COUNTERFACTUAL SHADOW PROPOSAL: no broker policy was changed and none can be changed by this record"
BANNER_SYNTHETIC = "SYNTHETIC FIXTURE: engineering demonstration data, not scientific evidence. " + BANNER_COUNTERFACTUAL
_EVENT_KEYS = {"schema", "schema_version", "event_kind", "sequence", "evidence_id", "evidence_mode", "banner", "decision_ns", "clock_basis",
               "device_label", "proposal", "scores", "components", "behavior", "eligibility", "reasons"}
_PROPOSAL_KEYS = {"state", "applied", "enforcement", "broker_policy_changes", "restoration"}


def _component(block):
    return dict(outcome=block.get("outcome"), treatment=block.get("policy_treatment"), reasons=list(block.get("reasons") or []),
                score_used=block.get("score_used"))


def _number(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) else None


def decision_to_event(record, *, sequence):
    """One flat event from a Shadow decision or refusal record. `sequence` is the caller's monotonic display index."""
    if type(sequence) is not int or sequence < 0:
        raise ValueError("sequence must be a non-negative integer")
    if not isinstance(record, dict) or record.get("enforcement") != "NONE":
        raise ValueError("only records that declare enforcement NONE can be turned into demo events")
    if record.get("record_kind") == "BUNDLE_REFUSED":
        return dict(
            schema=EVENT_SCHEMA, schema_version=EVENT_SCHEMA_VERSION, event_kind="BUNDLE_REFUSED", sequence=sequence,
            evidence_id=record.get("evidence_id"), evidence_mode=None, banner=BANNER_COUNTERFACTUAL, decision_ns=None, clock_basis=None,
            device_label=None, proposal=dict(state=None, applied=False, enforcement="NONE", broker_policy_changes=0, restoration=RESTORATION),
            scores=dict(s_id=None, s_b=None, s_c=None, trust=None, tau_Q=None, tau_R=None, hard_gate_applied=None),
            components={}, behavior=dict(loss=None, anomaly_magnitude=None, calibration_id=None, workload_version=None, cross_workload_comparison=False),
            eligibility=dict(decision_eligible=False, azta_action="NO_PROPOSAL", restoration=RESTORATION, refused_components=[],
                             counterfactually_treated_components=[]),
            reasons=[str(record.get("reason"))])
    if record.get("record_kind") != "SHADOW_DECISION" or record.get("broker_policy_changes") != 0 or record.get("counterfactual") is not True:
        raise ValueError("unsupported record: not a counterfactual Shadow decision")
    fusion, behavior, eligibility = record.get("fusion") or {}, record["behavior"], record["eligibility"]
    evaluated = record["status"] == "EVALUATED" and record["proposed_state"] in STATES
    synthetic = record["evidence_mode"] == "SYNTHETIC_FIXTURE"
    return dict(
        schema=EVENT_SCHEMA, schema_version=EVENT_SCHEMA_VERSION, event_kind="TRUST_DECISION" if evaluated else "NO_PROPOSAL", sequence=sequence,
        evidence_id=record["evidence_id"], evidence_mode=record["evidence_mode"], banner=BANNER_SYNTHETIC if synthetic else BANNER_COUNTERFACTUAL,
        decision_ns=record["decision_ns"], clock_basis=record["clock_basis"], device_label=record["identity"].get("bound_username"),
        proposal=dict(state=record["proposed_state"] if evaluated else None, applied=False, enforcement="NONE", broker_policy_changes=0,
                      restoration=eligibility.get("restoration", RESTORATION)),
        scores=dict(s_id=_number(fusion.get("s_id")), s_b=_number(fusion.get("s_b")), s_c=_number(fusion.get("s_c")),
                    trust=_number(fusion.get("trust")), tau_Q=_number(fusion.get("tau_Q")), tau_R=_number(fusion.get("tau_R")),
                    hard_gate_applied=fusion.get("hard_gate_applied")),
        components={name: _component(record[name]) for name in ("identity", "behavior", "context")},
        behavior=dict(loss=_number(behavior.get("loss")), anomaly_magnitude=_number(behavior.get("anomaly_magnitude")),
                      calibration_id=behavior.get("calibration_id"), workload_version=behavior.get("workload_version"),
                      cross_workload_comparison=behavior.get("cross_workload_baseline_experiment_id") is not None),
        eligibility=dict(decision_eligible=eligibility["decision_eligible"], azta_action=eligibility["azta_action"],
                         restoration=eligibility.get("restoration", RESTORATION), refused_components=list(eligibility["refused_components"]),
                         counterfactually_treated_components=list(eligibility["counterfactually_treated_components"])),
        reasons=list(record["reasons"]))


def validate_event(event):
    """Return a list of problems (empty = a conformant event). The invariants a dashboard may rely on."""
    problems = []
    if not isinstance(event, dict) or set(event) != _EVENT_KEYS:
        return ["event: unexpected or missing fields"]
    if (event["schema"], event["schema_version"]) != (EVENT_SCHEMA, EVENT_SCHEMA_VERSION):
        problems.append("schema")
    if event["event_kind"] not in KINDS:
        problems.append("event_kind")
    proposal = event["proposal"]
    if not isinstance(proposal, dict) or set(proposal) != _PROPOSAL_KEYS:
        return problems + ["proposal fields"]
    if proposal["applied"] is not False or proposal["enforcement"] != "NONE" or proposal["broker_policy_changes"] != 0:
        problems.append("a demo event can never claim that a proposal was applied")
    if proposal["restoration"] != RESTORATION:
        problems.append("restoration must be manual")
    if proposal["state"] is not None and proposal["state"] not in STATES:
        problems.append("proposal state")
    if (event["event_kind"] == "TRUST_DECISION") != (proposal["state"] is not None):
        problems.append("a state is present exactly for TRUST_DECISION events")
    if event["evidence_mode"] == "SYNTHETIC_FIXTURE" and "SYNTHETIC" not in event["banner"]:
        problems.append("synthetic data must be bannered as such")
    if "no broker policy was changed" not in event["banner"]:
        problems.append("banner")
    if type(event["sequence"]) is not int or event["sequence"] < 0:
        problems.append("sequence")
    return problems
