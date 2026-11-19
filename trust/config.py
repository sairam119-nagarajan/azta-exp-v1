"""Gate 5F trust configuration: explicit, validated, never defaulted, never presented as calibrated.

Every operating parameter of the journal's trust model (alpha, beta, gamma, epsilon, lambda, tau_Q, tau_R, the context criteria and
their weights) and every freshness bound is supplied by the caller. This module owns no default for any of them; none is calibrated or
approved yet, so the only accepted configuration status is SYNTHETIC_TEST_UNAPPROVED and every decision record carries it.

Validation distinguishes three layers (see THRESHOLD_DOMAIN):
  * JOURNAL requirements: alpha, beta, gamma >= 0 summing to 1 (eq. 2); omega_j >= 0 summing to 1 (eq. 4); tau_Q < tau_R (eq. 5,
    Algorithm 1 and 2).
  * NUMERICAL safeguards named by the journal: epsilon > 0 (eq. 11) and lambda > 0 (eq. 12).
  * ADDED OPERATIONAL-DOMAIN RESTRICTION (Gate 5F.2, controller-accepted): 0 < tau_Q and tau_R <= 100. It is NOT in the journal. It
    ensures that a verified identity failure (hard gate, T = 0) always maps to QUARANTINE (T = 0 < tau_Q) and that FULL_ACCESS is
    attainable (T <= 100, so tau_R > 100 would make it impossible). It selects no numerical threshold.

A missing-evidence policy of ZERO is an explicit offline counterfactual choice: it is accepted only together with a
`counterfactual_experiment_id` naming the pre-registered experiment, and is recorded in every decision record. REFUSE is the
recommended fail-safe for unavailable behavioural or contextual evidence until a live policy is approved: it produces no AZTA proposal
and never disables an existing broker control.

`reachability()` reports which policy states a configuration can produce; it never changes a weight or threshold to hide a finding.
"""
from collections import namedtuple
from dataclasses import dataclass
from fractions import Fraction
import hashlib
import json
import math
import re

from trust.errors import ConfigError
from trust.exact import to_fraction

CONFIG_SCHEMA = "azta.gate5f.trust_config"
CONFIG_SCHEMA_VERSION = 1
ACCEPTED_CONFIG_STATUSES = ("SYNTHETIC_TEST_UNAPPROVED",)
COMPONENTS = ("identity", "behavior", "context")
MISSING_POLICIES = ("REFUSE", "ZERO")
STATES = ("QUARANTINE", "RESTRICT", "FULL_ACCESS")
SCALE = Fraction(100)
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
THRESHOLD_DOMAIN = dict(
    journal="tau_Q < tau_R (journal eq. 5, Algorithm 1 requirement, Algorithm 2 line 12)",
    added_restriction=("0 < tau_Q and tau_R <= 100: an operational-domain restriction added in Gate 5F.2, not stated in the journal; "
                       "it keeps a verified identity failure (T = 0) in QUARANTINE and FULL_ACCESS attainable"),
    selects_numerical_thresholds=False)
_TOP_KEYS = {"schema", "schema_version", "config_id", "config_status", "approval_ref", "trust_weights", "behavior", "thresholds",
             "context_criteria", "max_evidence_age_ns", "missing_evidence_policy", "counterfactual_experiment_id"}


@dataclass(frozen=True)
class ContextCriterion:
    criterion_id: str
    weight: Fraction


def _keys(data, expected, label):
    if not isinstance(data, dict) or set(data) != set(expected):
        raise ConfigError(f"{label}: unexpected or missing fields (expected {sorted(expected)})")


def _positive_float(value):
    """True when the exact value is > 0 and converts to a finite, strictly positive float (no underflow to 0, no overflow)."""
    try:
        return value > 0 and 0.0 < float(value) < math.inf
    except OverflowError:
        return False


def _positive_int(value, name):
    if type(value) is not int or value <= 0:
        raise ConfigError(f"{name}: a positive integer (nanoseconds) is required")
    return value


@dataclass(frozen=True)
class TrustConfig:
    config_id: str
    config_status: str
    approval_ref: object
    alpha: Fraction
    beta: Fraction
    gamma: Fraction
    epsilon: Fraction
    lam: Fraction
    tau_q: Fraction
    tau_r: Fraction
    criteria: tuple
    max_evidence_age_ns: dict
    missing_policy: dict
    counterfactual_experiment_id: object

    @classmethod
    def from_dict(cls, data):
        _keys(data, _TOP_KEYS, "config")
        if data["schema"] != CONFIG_SCHEMA or data["schema_version"] != CONFIG_SCHEMA_VERSION:
            raise ConfigError("config: schema or schema_version")
        config_id, status = data["config_id"], data["config_status"]
        if not isinstance(config_id, str) or not IDENTIFIER.fullmatch(config_id):
            raise ConfigError("config_id: identifier required")
        if status not in ACCEPTED_CONFIG_STATUSES:
            raise ConfigError(f"config_status {status!r} is not accepted; only {ACCEPTED_CONFIG_STATUSES} exist in Gate 5F "
                              "(no operating parameter has been calibrated or approved)")
        if data["approval_ref"] is not None:
            raise ConfigError("approval_ref must be null for a synthetic test configuration")

        _keys(data["trust_weights"], {"alpha", "beta", "gamma"}, "trust_weights")
        alpha, beta, gamma = (to_fraction(data["trust_weights"][k], f"trust_weights.{k}") for k in ("alpha", "beta", "gamma"))
        if min(alpha, beta, gamma) < 0:
            raise ConfigError("alpha, beta and gamma must be non-negative (journal eq. 2)")
        if alpha + beta + gamma != 1:
            raise ConfigError(f"alpha + beta + gamma must equal exactly 1 (journal eq. 2); got {alpha + beta + gamma}")

        _keys(data["behavior"], {"epsilon", "lambda"}, "behavior")
        epsilon, lam = to_fraction(data["behavior"]["epsilon"], "behavior.epsilon"), to_fraction(data["behavior"]["lambda"], "behavior.lambda")
        if not _positive_float(epsilon):
            raise ConfigError("epsilon must be strictly positive and representable as a positive float (journal eq. 11)")
        if not _positive_float(lam):
            raise ConfigError("lambda must be strictly positive and representable as a positive float (journal eq. 12)")

        _keys(data["thresholds"], {"tau_Q", "tau_R"}, "thresholds")
        tau_q, tau_r = to_fraction(data["thresholds"]["tau_Q"], "tau_Q"), to_fraction(data["thresholds"]["tau_R"], "tau_R")
        if not tau_q < tau_r:
            raise ConfigError(f"JOURNAL REQUIREMENT violated: {THRESHOLD_DOMAIN['journal']}; got tau_Q={tau_q}, tau_R={tau_r}")
        if not (tau_q > 0 and tau_r <= SCALE):
            raise ConfigError(f"ADDED OPERATIONAL-DOMAIN RESTRICTION violated (not a journal requirement): "
                              f"{THRESHOLD_DOMAIN['added_restriction']}; got tau_Q={tau_q}, tau_R={tau_r}")

        criteria_in = data["context_criteria"]
        if not isinstance(criteria_in, list) or not criteria_in:
            raise ConfigError("context_criteria: at least one criterion is required (journal eq. 3-4, m >= 1)")
        criteria = []
        for item in criteria_in:
            _keys(item, {"id", "weight"}, "context criterion")
            if not isinstance(item["id"], str) or not IDENTIFIER.fullmatch(item["id"]):
                raise ConfigError("context criterion id: identifier required")
            weight = to_fraction(item["weight"], f"context weight {item['id']}")
            if weight < 0:
                raise ConfigError("context weights must be non-negative (journal eq. 4)")
            criteria.append(ContextCriterion(item["id"], weight))
        if len({c.criterion_id for c in criteria}) != len(criteria):
            raise ConfigError("context criterion ids must be unique")
        if sum(c.weight for c in criteria) != 1:
            raise ConfigError(f"context weights must sum to exactly 1 (journal eq. 4); got {sum(c.weight for c in criteria)}")

        _keys(data["max_evidence_age_ns"], set(COMPONENTS), "max_evidence_age_ns")
        ages = {k: _positive_int(data["max_evidence_age_ns"][k], f"max_evidence_age_ns.{k}") for k in COMPONENTS}
        _keys(data["missing_evidence_policy"], set(COMPONENTS), "missing_evidence_policy")
        policy = dict(data["missing_evidence_policy"])
        if any(policy[k] not in MISSING_POLICIES for k in COMPONENTS):
            raise ConfigError(f"missing_evidence_policy values must be one of {MISSING_POLICIES}")
        experiment = data["counterfactual_experiment_id"]
        zeroed = [k for k in COMPONENTS if policy[k] == "ZERO"]
        if zeroed and not (isinstance(experiment, str) and IDENTIFIER.fullmatch(experiment)):
            raise ConfigError(f"missing_evidence_policy ZERO ({zeroed}) is an explicit offline counterfactual choice and needs a "
                              "counterfactual_experiment_id naming the pre-registered experiment")
        if not zeroed and experiment is not None:
            raise ConfigError("counterfactual_experiment_id must be null when every missing-evidence policy is REFUSE")
        return cls(config_id, status, None, alpha, beta, gamma, epsilon, lam, tau_q, tau_r, tuple(criteria), ages,
                   {k: policy[k] for k in COMPONENTS}, experiment)

    def to_dict(self):
        return dict(
            schema=CONFIG_SCHEMA, schema_version=CONFIG_SCHEMA_VERSION, config_id=self.config_id, config_status=self.config_status,
            approval_ref=self.approval_ref,
            trust_weights=dict(alpha=str(self.alpha), beta=str(self.beta), gamma=str(self.gamma)),
            behavior={"epsilon": str(self.epsilon), "lambda": str(self.lam)},
            thresholds=dict(tau_Q=str(self.tau_q), tau_R=str(self.tau_r)),
            context_criteria=[dict(id=c.criterion_id, weight=str(c.weight)) for c in self.criteria],
            max_evidence_age_ns=dict(self.max_evidence_age_ns), missing_evidence_policy=dict(self.missing_policy),
            counterfactual_experiment_id=self.counterfactual_experiment_id)

    def sha256(self):
        text = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), allow_nan=False)
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @property
    def epsilon_float(self):
        return float(self.epsilon)

    @property
    def lambda_float(self):
        return float(self.lam)

    def reachability(self):
        return reachability(self)


# ---------------------------------------------------------------- reachability (descriptive; never alters a parameter)
Interval = namedtuple("Interval", "lo lo_closed hi hi_closed")  # None bound = unbounded


def _meets(a, b):
    lo, lo_closed = a.lo, a.lo_closed
    if b.lo is not None and (lo is None or b.lo > lo or (b.lo == lo and not b.lo_closed)):
        lo, lo_closed = b.lo, b.lo_closed
    hi, hi_closed = a.hi, a.hi_closed
    if b.hi is not None and (hi is None or b.hi < hi or (b.hi == hi and not b.hi_closed)):
        hi, hi_closed = b.hi, b.hi_closed
    if lo is None or hi is None:
        return True
    return lo < hi or (lo == hi and lo_closed and hi_closed)


def _text(interval):
    lo = "-inf" if interval.lo is None else str(interval.lo)
    hi = "+inf" if interval.hi is None else str(interval.hi)
    return f"{'[' if interval.lo_closed else '('}{lo}, {hi}{']' if interval.hi_closed else ')'}"


def reachability(config):
    """Which policy states each evidence scenario can produce, by exact interval arithmetic on journal eq. 1 and eq. 5.

    S_B = 100*exp(-lambda*A) lies in (0, 100] (it approaches 0 but is never exactly 0 mathematically); S_C lies in [0, 100] because
    continuous conformity c_j in [0, 1] is allowed. With a valid identity (S_ID = 100):
      behaviour alone (context fully conforming):  T in (100*(1-beta), 100]   -> the floor 100*(1-beta) is not attained
      context alone (behaviour at baseline):       T in [100*(1-gamma), 100]
      both varying:                                T in (100*alpha, 100]
    A failed identity gives T = 0. Quarantine needs T < tau_Q (strict), so tau_Q <= the relevant floor makes it unreachable.
    """
    alpha, beta, gamma = config.alpha, config.beta, config.gamma
    scenarios = {
        "identity_failure": Interval(Fraction(0), True, Fraction(0), True),
        "behavior_alone_valid_identity_full_context":
            Interval(SCALE * (1 - beta), False, SCALE, True) if beta > 0 else Interval(SCALE, True, SCALE, True),
        "context_alone_valid_identity_baseline_behavior":
            Interval(SCALE * (1 - gamma), True, SCALE, True) if gamma > 0 else Interval(SCALE, True, SCALE, True),
        "behavior_and_context_valid_identity": Interval(SCALE * alpha, beta == 0, SCALE, True),
    }
    states = {
        "QUARANTINE": Interval(None, False, config.tau_q, False),
        "RESTRICT": Interval(config.tau_q, True, config.tau_r, False),
        "FULL_ACCESS": Interval(config.tau_r, True, None, False),
    }
    table = {name: dict(trust_range=_text(rng), reachable_states={state: _meets(rng, span) for state, span in states.items()})
             for name, rng in scenarios.items()}
    findings = []

    def add(code, detail):
        findings.append(dict(code=code, detail=detail))

    behavior = table["behavior_alone_valid_identity_full_context"]["reachable_states"]
    if not behavior["QUARANTINE"]:
        add("BEHAVIORAL_QUARANTINE_UNREACHABLE",
            f"with a valid identity and fully conforming context, T cannot fall below 100*(1-beta) = {SCALE * (1 - beta)}; "
            f"tau_Q = {config.tau_q} is not above it, so behaviour alone can never produce QUARANTINE (strict inequality)")
    if not behavior["RESTRICT"]:
        add("BEHAVIORAL_RESTRICT_UNREACHABLE", "behaviour alone (valid identity, fully conforming context) can never produce RESTRICT")
    if beta == 0:
        add("BEHAVIOR_WEIGHT_ZERO", "beta = 0: behavioural evidence cannot affect T")
    if gamma == 0:
        add("CONTEXT_WEIGHT_ZERO", "gamma = 0: contextual evidence cannot affect T")
    joint = table["behavior_and_context_valid_identity"]["reachable_states"]
    if not joint["QUARANTINE"]:
        add("VALID_IDENTITY_QUARANTINE_UNREACHABLE",
            f"with a valid identity T never falls below 100*alpha = {SCALE * alpha}; QUARANTINE arises only from an identity failure")
    if not joint["RESTRICT"]:
        add("VALID_IDENTITY_RESTRICT_UNREACHABLE", "with a valid identity no evidence combination yields RESTRICT")
    if not table["context_alone_valid_identity_baseline_behavior"]["reachable_states"]["QUARANTINE"]:
        add("CONTEXT_QUARANTINE_UNREACHABLE", f"context alone cannot push T below 100*(1-gamma) = {SCALE * (1 - gamma)} (informational)")
    return dict(scenarios=table, findings=findings, finding_codes=[f["code"] for f in findings], threshold_domain=THRESHOLD_DOMAIN,
                note="exact interval arithmetic on journal eq. 1 and eq. 5; descriptive only, no parameter is altered")
