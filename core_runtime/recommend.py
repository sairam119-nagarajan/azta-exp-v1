"""The recommendation record of AE_PRIMARY_AUTHORITY_V1 (`azta.core.recommendation`): one trust-engine decision, projected onto the separate axes the operator sees. A pure function of the decision, the authority map
and the confirmation counter: it computes no score and changes none, so toggling authority cannot change a score or a recommendation. `requested_action`, `applied_action`, `observed_broker_state` and
`execution_status` stay HELD/None here; the PEP audit log is the only source of what actually happened (`core_runtime.state`).
"""
from core_runtime import CONTRACT
from enforcement import attribution as attr
from enforcement.authority import ORIGIN_AE, ORIGIN_IDENTITY, ORIGIN_SUPPLEMENTARY, ORIGIN_UNATTRIBUTED, REVIEW_REQUIRED, SHADOW_ONLY

SCHEMA = "azta.core.recommendation"
NONE = "NONE"


def device_of(decision):
    window = (decision.get("behavior") or {}).get("window_ref") or {}
    note = (decision.get("annotations") or {}).get("decision_pipeline") or {}
    return window.get("device") or (note.get("route") or {}).get("device")


def recommendation_of(decision):
    """(recommendation, origin, behavior_source). Fused state from AE evidence or the identity gate; else the supplementary rule; else NONE. The origin is the ACTUAL cause
    (`enforcement.attribution`): a state caused by context is CONTEXT_POLICY and one caused by both is MIXED_AE_CONTEXT, never AE_PRIMARY."""
    behavior = decision.get("behavior") or {}
    primary = behavior.get("ae_primary") or {}
    if decision.get("status") == "EVALUATED" and decision.get("proposed_state"):
        if (decision.get("fusion") or {}).get("hard_gate_applied"):
            return decision["proposed_state"], ORIGIN_IDENTITY, "MISSING"
        if primary.get("behavior_source") == "AE":
            if decision["proposed_state"] == attr.FULL_ACCESS:
                return decision["proposed_state"], ORIGIN_AE, "AE"
            return decision["proposed_state"], attr.attribute(decision).get("origin") or ORIGIN_UNATTRIBUTED, "AE"
        return NONE, None, "MISSING"
    supplementary = behavior.get("supplementary") or {}
    if supplementary.get("recommendation"):
        return supplementary["recommendation"], ORIGIN_SUPPLEMENTARY, "SUPPLEMENTARY_TIMING"
    return NONE, None, "MISSING"


def build(decision, *, runtime_mode, authority_map=None, confirmation=None):
    device = device_of(decision)
    recommendation, origin, source = recommendation_of(decision)
    primary = (decision.get("behavior") or {}).get("ae_primary") or {}
    fusion, identity, context = decision.get("fusion") or {}, decision.get("identity") or {}, decision.get("context") or {}
    prov, note = decision.get("provenance") or {}, (decision.get("annotations") or {}).get("decision_pipeline") or {}
    route = note.get("route") or {}
    attribution = attr.attribute(decision) if recommendation != NONE else attr.attribute(None)
    if runtime_mode == "shadow":
        mode, reason = SHADOW_ONLY, "SHADOW_RUNTIME_MODE"
    elif origin == ORIGIN_AE and authority_map is not None:
        mode, reason = authority_map.mode(device), (authority_map.entry(device).get("screen_failed") or "SCREEN_R_PASSED")
    else:
        mode, reason = REVIEW_REQUIRED, "NOT_AN_AE_CAUSED_RECOMMENDATION"
    return dict(schema=SCHEMA, contract=CONTRACT, evidence_id=decision.get("evidence_id"), decision_ns=decision.get("decision_ns"), device=device, runtime_mode=runtime_mode,
                evidence_mode=decision.get("evidence_mode"), run_id=((decision.get("behavior") or {}).get("window_ref") or {}).get("collection_run_id"), window_index=((decision.get("behavior") or {}).get("window_ref") or {}).get("window_index"),
                behavior_source=source, ae_status=primary.get("ae_status"), ae_loss=primary.get("ae_loss"), a_ae=primary.get("a_ae"), s_b_ae=primary.get("s_b_ae"), mu_L=primary.get("mu_L"), sigma_L=primary.get("sigma_L"), n_B=primary.get("n_B"),
                route_arm=primary.get("route_arm"), basis=primary.get("basis"), confirmed=primary.get("confirmed"), s_id=fusion.get("s_id", identity.get("score_used")), s_c=fusion.get("s_c", context.get("score_used")), t_ae=fusion.get("trust"),
                engine_status=decision.get("status"), recommendation=recommendation, recommendation_origin=origin, evidence_ids=[decision.get("evidence_id")], reasons=decision.get("reasons"),
                supplementary=(decision.get("behavior") or {}).get("supplementary"), model_id=route.get("model_id"), config_sha256=prov.get("config_sha256"), config_status=prov.get("config_status"),
                registry_sha256=(note.get("registry") or {}).get("sha256"), calibration_id=(decision.get("behavior") or {}).get("calibration_id"), calibration_status=(decision.get("behavior") or {}).get("calibration_status"),
                decision_source=attribution.get("decision_source"), causes=attribution.get("causes"), mixed_kind=attribution.get("mixed_kind"), counterfactual=attribution.get("counterfactual"),
                authority_mode=mode, authority_reason=reason, confirmation=confirmation, requested_action=None, applied_action=None, observed_broker_state=None, execution_status="HELD")


class ConfirmationTracker:
    """The N progress the operator sees in every runtime mode, by the UNCHANGED `DecisionFilter`, against the state the PEP log last verified (`state_of(device)`; FULL_ACCESS is only ever assumed in shadow). It never
    requests anything: the PEP's own filter stays the only counter that can reach the PEP."""

    def __init__(self, filter_, state_of):
        self.filter, self.state_of = filter_, state_of

    def observe(self, device, recommendation, origin):
        if not isinstance(device, str):
            return dict(state="HELD", reason="DEVICE_NOT_RESOLVED")
        if recommendation == NONE or origin == ORIGIN_SUPPLEMENTARY:
            self.filter.observe_missing(device)
            return dict(state="HELD", reason="NO_QUALIFYING_EVIDENCE", confirmations=0, needed=self.filter.policy.escalate_after)
        verdict = self.filter.observe(device, recommendation, self.state_of(device))
        return dict(state=verdict["action"], reason=verdict.get("reason"), confirmations=verdict.get("confirmations", 0), needed=verdict.get("needed", self.filter.policy.escalate_after))
