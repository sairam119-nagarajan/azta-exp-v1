"""Contextual trust S_C (journal section 4.1, eq. 3-4): S_C = 100 * sum_j(omega_j * c_j), c_j in [0, 1], omega_j >= 0, sum = 1.

Each configured criterion needs trusted, fresh, available conformity evidence. If any criterion with a non-zero weight is not
provided, is untrusted or stale, or has no conformity value, S_C is NOT computed: the component is MISSING and the configured
missing-evidence policy decides what that means (REFUSE: no decision; ZERO: the component scores 0). Unverifiable context never
becomes a healthy score, and evidence for a criterion the configuration does not define is a mismatch, never silently dropped.
A criterion with weight 0 cannot affect S_C; its absence is recorded but does not make the component missing.
"""
from fractions import Fraction

from trust.evidence import EVALUATED, MISSING, TRUSTED_EVIDENCE_PROVENANCE, ComponentResult, age_problem, provenance_trusted, \
    score_float
from trust.exact import to_fraction
from trust.fusion import aggregate_context


def evaluate_context(context, config, *, evidence_mode, decision_ns):
    max_age = config.max_evidence_age_ns["context"]
    provided = {} if context is None else {item["criterion_id"]: item for item in context["criteria"]}
    unknown = sorted(set(provided) - {c.criterion_id for c in config.criteria})
    rows, weights, conformities, blocking = [], [], [], []
    for criterion in config.criteria:
        item = provided.get(criterion.criterion_id)
        row = dict(id=criterion.criterion_id, weight=float(criterion.weight), conformity=None, outcome=EVALUATED, reasons=[],
                   provenance=None, observed_ns=None, source_ref=None)
        if context is None:
            row["reasons"].append("NO_CONTEXT_EVIDENCE")
        elif item is None:
            row["reasons"].append("CRITERION_NOT_PROVIDED")
        else:
            row.update(provenance=item["provenance"], observed_ns=item["observed_ns"], source_ref=item["source_ref"])
            if not provenance_trusted(item["provenance"], evidence_mode, TRUSTED_EVIDENCE_PROVENANCE):
                row["reasons"].append(f"UNTRUSTED_CONTEXT_PROVENANCE:{item['provenance']}")
            else:
                problem = age_problem(item["observed_ns"], decision_ns, max_age)
                if problem:
                    row["reasons"].append(f"{problem}_CONTEXT_EVIDENCE")
                elif item["conformity"] is None:
                    row["reasons"].append("CONFORMITY_UNAVAILABLE")
        if row["reasons"]:
            row["outcome"] = MISSING
            if criterion.weight > 0:
                blocking.append(f"{criterion.criterion_id}:{row['reasons'][0]}")
            else:
                row["ignored_zero_weight"] = True
            conformity = Fraction(0)  # weight 0 only reaches the sum multiplied by 0
        else:
            row["conformity"] = float(item["conformity"])
            conformity = to_fraction(item["conformity"], f"conformity {criterion.criterion_id}")
        rows.append(row)
        weights.append(criterion.weight)
        conformities.append(conformity)
    reasons = list(blocking)
    if unknown:
        reasons.append(f"CONTEXT_CRITERION_SET_MISMATCH:{','.join(unknown)}")
    if reasons:
        return ComponentResult(MISSING, None, tuple(reasons), dict(outcome=MISSING, reasons=reasons, s_c=None, criteria=rows,
                                                                   unknown_criteria=unknown))
    s_c = aggregate_context(weights, conformities)
    return ComponentResult(EVALUATED, s_c, ("CONTEXT_AGGREGATED",),
                           dict(outcome=EVALUATED, reasons=["CONTEXT_AGGREGATED"], s_c=score_float(s_c), criteria=rows,
                                unknown_criteria=[]))
