"""Composite trust and policy mapping, exactly as the journal states them (eq. 1-5, Algorithm 1 lines 3-21).

    S_C = 100 * sum_j(omega_j * c_j)                      (eq. 3-4)
    T   = 0                                if S_ID = 0    (eq. 1, hard identity gate)
    T   = alpha*S_ID + beta*S_B + gamma*S_C  otherwise    (eq. 1-2)
    T < tau_Q -> QUARANTINE;  tau_Q <= T < tau_R -> RESTRICT;  T >= tau_R -> FULL_ACCESS   (eq. 5, tau_Q < tau_R)

All arithmetic is exact (fractions.Fraction), so a score exactly on a threshold is classified by the strict inequalities, never by a
rounding accident. This module only returns a state label: it does not apply it anywhere.
"""
from fractions import Fraction

SCALE = Fraction(100)


def _score(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, Fraction)) or not 0 <= value <= SCALE:
        raise ValueError(f"{name} must be an exact score in [0, 100]")
    return Fraction(value)


def aggregate_context(weights, conformities):
    """S_C = 100 * sum_j(omega_j * c_j) with omega_j >= 0, sum omega_j = 1 and c_j in [0, 1] (all exact)."""
    if not weights or len(weights) != len(conformities):
        raise ValueError("one conformity per context weight is required (m >= 1)")
    weights, conformities = [Fraction(w) for w in weights], [Fraction(c) for c in conformities]
    if min(weights) < 0 or sum(weights) != 1:
        raise ValueError("context weights must be non-negative and sum to exactly 1")
    if min(conformities) < 0 or max(conformities) > 1:
        raise ValueError("context conformity must lie in [0, 1]")
    return SCALE * sum(w * c for w, c in zip(weights, conformities))


def composite_trust(s_id, s_b, s_c, alpha, beta, gamma):
    """T per eq. 1. When S_ID = 0 the other scores are not consulted at all (they may be None)."""
    alpha, beta, gamma = Fraction(alpha), Fraction(beta), Fraction(gamma)
    if min(alpha, beta, gamma) < 0 or alpha + beta + gamma != 1:
        raise ValueError("alpha, beta, gamma must be non-negative and sum to exactly 1")
    if _score(s_id, "S_ID") == 0:
        return Fraction(0)
    return alpha * s_id + beta * _score(s_b, "S_B") + gamma * _score(s_c, "S_C")


def policy_state(trust, tau_q, tau_r):
    """Eq. 5 with its strict and non-strict inequalities. Requires tau_Q < tau_R."""
    trust, tau_q, tau_r = Fraction(trust), Fraction(tau_q), Fraction(tau_r)
    if not tau_q < tau_r:
        raise ValueError("tau_Q must be strictly below tau_R")
    if trust < tau_q:
        return "QUARANTINE"
    if trust < tau_r:
        return "RESTRICT"
    return "FULL_ACCESS"
