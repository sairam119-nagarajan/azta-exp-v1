"""Unified trust decision engine: evidence bundle -> COUNTERFACTUAL decision record (journal Algorithm 1 without the enforcement steps).

    1. S_ID from authoritative identity evidence (hard gate: S_ID = 0 forces T = 0 and the other components are not consulted).
    2. S_B from the frozen profile autoencoder and its accepted calibration.   3. S_C from the validated context criteria.
    4. T = alpha*S_ID + beta*S_B + gamma*S_C, then the strict/non-strict threshold mapping to QUARANTINE / RESTRICT / FULL_ACCESS.

The result is a LOG RECORD with `proposed_state`: what the policy WOULD be. It is never applied. The engine holds no broker handle, no
credential and no network access; `enforcement` is always "NONE" and `broker_policy_changes` always 0. Unavailable evidence is never a
healthy score: under the REFUSE policy the record is NOT_EVALUABLE with no proposal; under the explicit ZERO policy the unavailable
component scores 0 and the record says so. No parameter of the trust model is defaulted here: all come from the validated configuration.
"""
import copy
from fractions import Fraction

from trust.context import evaluate_context
from trust.evidence import EVALUATED, MISSING, score_float
from trust.fusion import composite_trust, policy_state
from trust.identity import evaluate_identity

ENGINE_VERSION = "gate5f-1"
DECISION_SCHEMA = "azta.gate5f.shadow_decision"
DECISION_SCHEMA_VERSION = 1
NOT_EVALUABLE, EVALUATED_STATUS = "NOT_EVALUABLE", "EVALUATED"


def _num(value):
    return None if value is None else float(value)


class DecisionEngine:
    def __init__(self, config, behavior):
        self.config, self.behavior = config, behavior
        self.reachability = config.reachability()

    def describe(self):
        return dict(engine_version=ENGINE_VERSION, config=self.config.to_dict(), config_sha256=self.config.sha256(),
                    reachability=self.reachability, behavior=self.behavior.provenance)

    def _apply(self, name, result):
        """(exact score or None, treatment): a MISSING component is refused or, only if configured, scored 0 and flagged."""
        if result.outcome == EVALUATED:
            return result.score, "NONE"
        if self.config.missing_policy[name] == "ZERO":
            return Fraction(0), "TREATED_AS_ZERO"
        return None, "REFUSED"

    @staticmethod
    def _block(result, treatment, score):
        return dict(result.detail, policy_treatment=treatment, score_used=score_float(score))

    def decide(self, bundle):
        cfg = self.config
        reasons, status, state, fusion = [], NOT_EVALUABLE, None, None
        identity = evaluate_identity(bundle.identity, evidence_mode=bundle.evidence_mode, decision_ns=bundle.decision_ns,
                                     max_age_ns=cfg.max_evidence_age_ns["identity"])
        s_id, id_treatment = self._apply("identity", identity)
        blocks = dict(identity=self._block(identity, id_treatment, s_id))
        why = "IDENTITY_UNRESOLVED" if s_id is None else "IDENTITY_HARD_GATE"
        gated = dict(outcome="NOT_EVALUATED", reasons=[why], policy_treatment="NOT_APPLICABLE", score_used=None)
        blocks["behavior"], blocks["context"] = dict(gated), dict(gated)
        reasons.append(f"identity: {','.join(identity.reasons)}"
                       + (" [treated as S_ID = 0 by policy]" if id_treatment == "TREATED_AS_ZERO" else ""))

        trust = None
        if s_id is None:
            reasons.append("identity not resolved from fresh authoritative evidence and policy is REFUSE: no composite trust and no AZTA "
                           "proposal; the broker's existing authorization is unchanged and remains authoritative")
        elif s_id == 0:
            trust = composite_trust(s_id, None, None, cfg.alpha, cfg.beta, cfg.gamma)  # hard gate: others are not consulted
            reasons.append("hard identity gate: S_ID = 0 forces T = 0 regardless of behavioural or contextual evidence (journal eq. 1)")
            fusion = dict(s_id=0.0, s_b=None, s_c=None, hard_gate_applied=True)
        else:
            expected = (bundle.identity["bound_username"], bundle.identity["bound_client_id"])
            behavior = self.behavior.evaluate(bundle.behavior, cfg, evidence_mode=bundle.evidence_mode,
                                              decision_ns=bundle.decision_ns, expected_identity=expected)
            context = evaluate_context(bundle.context, cfg, evidence_mode=bundle.evidence_mode, decision_ns=bundle.decision_ns)
            s_b, b_treatment = self._apply("behavior", behavior)
            s_c, c_treatment = self._apply("context", context)
            blocks["behavior"], blocks["context"] = self._block(behavior, b_treatment, s_b), self._block(context, c_treatment, s_c)
            for name, result, treatment in (("behavior", behavior, b_treatment), ("context", context, c_treatment)):
                if result.outcome == MISSING:
                    reasons.append(f"{name}: {';'.join(result.reasons)}"
                                   + (" [treated as score 0 by policy]" if treatment == "TREATED_AS_ZERO"
                                      else " [policy REFUSE: no AZTA proposal; existing broker controls unchanged]"))
            if behavior.outcome == EVALUATED:
                d = behavior.detail
                reasons.append(f"behavior: L = {d['loss']!r}, A = {d['anomaly_magnitude']!r}, S_B = {d['s_b']!r}")
            if context.outcome == EVALUATED:
                reasons.append(f"context: S_C = {context.detail['s_c']!r}")
            if s_b is not None and s_c is not None:
                trust = composite_trust(s_id, s_b, s_c, cfg.alpha, cfg.beta, cfg.gamma)
                fusion = dict(s_id=_num(s_id), s_b=_num(s_b), s_c=_num(s_c), hard_gate_applied=False)

        if trust is not None:
            status, state = EVALUATED_STATUS, policy_state(trust, cfg.tau_q, cfg.tau_r)
            below_q, below_r = trust < cfg.tau_q, trust < cfg.tau_r
            fusion.update(alpha=float(cfg.alpha), beta=float(cfg.beta), gamma=float(cfg.gamma), trust=float(trust),
                          tau_Q=float(cfg.tau_q), tau_R=float(cfg.tau_r), trust_lt_tau_Q=below_q, trust_lt_tau_R=below_r)
            reasons.append(f"T = {float(trust)!r}: " + (f"T < tau_Q ({float(cfg.tau_q)!r}) -> QUARANTINE" if below_q else
                           f"tau_Q ({float(cfg.tau_q)!r}) <= T < tau_R ({float(cfg.tau_r)!r}) -> RESTRICT" if below_r else
                           f"T >= tau_R ({float(cfg.tau_r)!r}) -> FULL_ACCESS") + " (exact comparison; a proposal only, not applied)")

        refused = [name for name in ("identity", "behavior", "context") if blocks[name].get("policy_treatment") == "REFUSED"]
        treated = [name for name in ("identity", "behavior", "context") if blocks[name].get("policy_treatment") == "TREATED_AS_ZERO"]
        missing_reasons = [f"{name}:{code}" for name in ("identity", "behavior", "context") if blocks[name].get("outcome") == "MISSING"
                           for code in blocks[name]["reasons"]]
        eligibility = dict(
            decision_eligible=status == EVALUATED_STATUS and not treated,
            azta_action="PROPOSAL_LOGGED_NOT_APPLIED" if status == EVALUATED_STATUS else "NO_PROPOSAL",
            refused_components=refused, counterfactually_treated_components=treated, missing_evidence_reasons=missing_reasons,
            existing_broker_controls="UNCHANGED_BY_AZTA",
            restoration="MANUAL_ADMINISTRATIVE_ONLY",
            note=("REFUSE means no new AZTA proposal; the broker's existing authentication and ACLs are neither relaxed nor disabled. "
                  "A FULL_ACCESS proposal is a counterfactual score outcome only: it never restores a quarantined or restricted client "
                  "(RESTORE is an explicit administrative operation, not a trust state and not automatic recovery)"))
        detail = blocks["behavior"]
        annotations = copy.deepcopy(bundle.annotations)
        window_index = (detail.get("window_ref") or {}).get("window_index")
        span = annotations.get("eligible_window_indices")
        edge = None
        if isinstance(window_index, int) and isinstance(span, list) and len(span) == 2 and all(type(v) is int for v in span):
            edge = min(window_index - span[0], span[1] - window_index)
        return dict(
            schema=DECISION_SCHEMA, schema_version=DECISION_SCHEMA_VERSION, record_kind="SHADOW_DECISION", engine_version=ENGINE_VERSION,
            evidence_id=bundle.evidence_id, evidence_mode=bundle.evidence_mode, clock_basis=bundle.clock_basis,
            decision_ns=bundle.decision_ns,
            evidence_scope=("SYNTHETIC_FIXTURE: engineering evidence only, not scientific evidence"
                            if bundle.evidence_mode == "SYNTHETIC_FIXTURE" else "TRUSTED_OFFLINE_REPLAY"),
            counterfactual=True, enforcement="NONE", broker_policy_changes=0,
            status=status, proposed_state=state, reasons=reasons, eligibility=eligibility,
            counterfactual_experiment_id=cfg.counterfactual_experiment_id,
            identity=blocks["identity"], behavior=blocks["behavior"], context=blocks["context"], fusion=fusion,
            stratum=dict(profile=detail.get("profile"), delivered_count=detail.get("delivered_count"), window_index=window_index,
                         edge_distance=edge),
            provenance=dict(config_id=cfg.config_id, config_status=cfg.config_status, config_sha256=cfg.sha256(),
                            reachability_findings=self.reachability["finding_codes"]),
            annotations=annotations)
