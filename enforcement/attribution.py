"""Decision attribution (stabilization requirement 2; supervisor direction plan point 3): WHICH evidence caused a proposed access state. Stdlib only (it runs in the PEP container).

A pure function of one recorded trust-engine decision. It recomputes nothing the engine decided. It reads the recorded fusion block (alpha, beta, gamma, S_ID, S_B, S_C, tau_Q, tau_R) and asks two
counterfactual questions with the unchanged journal formula T = alpha*S_ID + beta*S_B + gamma*S_C and the unchanged mapping of eq. 5 (exact decimal arithmetic of the recorded values):

    behaviour_sufficient = the proposed state (or a more severe one) follows with the recorded S_B and a fully conforming context (S_C = 100)
    context_sufficient   = the proposed state (or a more severe one) follows with the recorded S_C and fully healthy behaviour (S_B = 100)

    decision_source    origin              meaning
    IDENTITY           IDENTITY_HARD_GATE  S_ID = 0: the hard identity gate (T = 0); nothing else is consulted
    AE_BEHAVIOR        AE_PRIMARY          behaviour alone is sufficient and context alone is not (the autoencoder's S_B decides)
    CONTEXT            CONTEXT_POLICY      context alone is sufficient and behaviour alone is not (for example a withdrawn operating time)
    MIXED              MIXED_AE_CONTEXT    both alone sufficient (OVERDETERMINED) or neither alone sufficient (JOINT): both contributed
    LIVENESS           SUPPLEMENTARY_TIMING  no evaluated trust state; the supplementary liveness rule recommends RESTRICT (a policy safeguard, not a trust component)
    NONE               None                FULL_ACCESS or no recommendation

Only AE_PRIMARY may use a device's AUTO_ELIGIBLE qualification (`enforcement.authority.decide_authority`): that qualification was earned by autoencoder evidence and never extends to a
contextual, mixed or liveness trigger, which go to the operator-review path. Nothing here changes a score, a weight, a threshold or a state.
"""
from fractions import Fraction

FULL_ACCESS, RESTRICT, QUARANTINE = "FULL_ACCESS", "RESTRICT", "QUARANTINE"
SEVERITY = {FULL_ACCESS: 0, RESTRICT: 1, QUARANTINE: 2}
SOURCE_IDENTITY, SOURCE_AE, SOURCE_CONTEXT, SOURCE_MIXED, SOURCE_LIVENESS, SOURCE_NONE = "IDENTITY", "AE_BEHAVIOR", "CONTEXT", "MIXED", "LIVENESS", "NONE"
ORIGIN_AE, ORIGIN_IDENTITY, ORIGIN_SUPPLEMENTARY, ORIGIN_CONTEXT, ORIGIN_MIXED = "AE_PRIMARY", "IDENTITY_HARD_GATE", "SUPPLEMENTARY_TIMING", "CONTEXT_POLICY", "MIXED_AE_CONTEXT"
ORIGIN_OF_SOURCE = {SOURCE_IDENTITY: ORIGIN_IDENTITY, SOURCE_AE: ORIGIN_AE, SOURCE_CONTEXT: ORIGIN_CONTEXT, SOURCE_MIXED: ORIGIN_MIXED, SOURCE_LIVENESS: ORIGIN_SUPPLEMENTARY, SOURCE_NONE: None}
SCHEMA = "azta.decision_attribution"
VERSION = 1


def _exact(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("not a recorded number")
    return Fraction(repr(value)) if isinstance(value, float) else Fraction(value)


def state_of(trust, tau_q, tau_r):
    if trust < tau_q:
        return QUARANTINE
    if trust < tau_r:
        return RESTRICT
    return FULL_ACCESS


def _base(source, **fields):
    return dict(schema=SCHEMA, version=VERSION, decision_source=source, origin=ORIGIN_OF_SOURCE[source], **fields)


def attribute(record):
    """The attribution block of one decision record (a dict; never raises on a malformed record: it reports UNATTRIBUTABLE with origin None)."""
    if not isinstance(record, dict):
        return _base(SOURCE_NONE, causes=[], reason="NOT_A_RECORD")
    fusion = record.get("fusion") or {}
    proposed = record.get("proposed_state")
    if record.get("status") == "EVALUATED" and fusion.get("hard_gate_applied") is True:
        return _base(SOURCE_IDENTITY, causes=[SOURCE_IDENTITY], proposed_state=proposed, reason="S_ID = 0: hard identity gate")
    if record.get("status") != "EVALUATED" or proposed not in SEVERITY:
        supplementary = ((record.get("behavior") or {}).get("supplementary")) or {}
        if supplementary.get("recommendation") == RESTRICT:
            return _base(SOURCE_LIVENESS, causes=[SOURCE_LIVENESS], proposed_state=RESTRICT, reason="silence beyond the liveness bound with complete observer coverage",
                         silent_ns=supplementary.get("silent_ns"), bound_ns=supplementary.get("bound_ns"))
        return _base(SOURCE_NONE, causes=[], proposed_state=None, reason="NO_EVALUATED_STATE")
    if proposed == FULL_ACCESS:
        return _base(SOURCE_NONE, causes=[], proposed_state=FULL_ACCESS, reason="FULL_ACCESS")
    try:
        alpha, beta, gamma = (_exact(fusion[k]) for k in ("alpha", "beta", "gamma"))
        s_id, s_b, s_c = (_exact(fusion[k]) for k in ("s_id", "s_b", "s_c"))
        tau_q, tau_r = _exact(fusion["tau_Q"]), _exact(fusion["tau_R"])
    except (KeyError, ValueError):
        out = _base(SOURCE_NONE, causes=[], proposed_state=proposed, reason="UNATTRIBUTABLE_FUSION_BLOCK")
        out["origin"] = None
        return out
    hundred = Fraction(100)
    behaviour_only = state_of(alpha * s_id + beta * s_b + gamma * hundred, tau_q, tau_r)
    context_only = state_of(alpha * s_id + beta * hundred + gamma * s_c, tau_q, tau_r)
    need = SEVERITY[proposed]
    b_ok, c_ok = SEVERITY[behaviour_only] >= need, SEVERITY[context_only] >= need
    counterfactual = dict(state_if_context_conforming=behaviour_only, state_if_behavior_healthy=context_only, behavior_sufficient=b_ok, context_sufficient=c_ok,
                          behavior_deficit=float(beta * (hundred - s_b)), context_deficit=float(gamma * (hundred - s_c)))
    if b_ok and not c_ok:
        return _base(SOURCE_AE, causes=[SOURCE_AE], proposed_state=proposed, counterfactual=counterfactual, reason="autoencoder behaviour alone is sufficient")
    if c_ok and not b_ok:
        return _base(SOURCE_CONTEXT, causes=[SOURCE_CONTEXT], proposed_state=proposed, counterfactual=counterfactual, reason="context alone is sufficient")
    kind = "OVERDETERMINED" if b_ok else "JOINT"
    return _base(SOURCE_MIXED, causes=[SOURCE_AE, SOURCE_CONTEXT], mixed_kind=kind, proposed_state=proposed, counterfactual=counterfactual,
                 reason="behaviour and context are each sufficient" if b_ok else "behaviour and context are jointly necessary")
