"""Bounded parameter-search enumeration for the Shadow calibration design (journal Algorithm 2, phase 2 candidate sets).

This module ENUMERATES; it never evaluates, ranks or selects. The caller supplies an explicit, finite specification (the candidate sets
Λ for lambda, the (beta, gamma) pairs 𝒲, the threshold sets 𝒯, one fixed epsilon and a base configuration carrying every other required
field). Nothing here owns a candidate value. Every combination is built through the validated `TrustConfig`, so the journal constraints
(alpha = 1 - beta - gamma >= 0, tau_Q < tau_R) and the added domain rule are enforced exactly; combinations that fail are listed with
the reason, never silently dropped. Reachability findings are attached so that configurations in which behaviour alone cannot reach
QUARANTINE are visible. The size of the space is bounded by an explicit `max_candidates` that the caller must state.
"""
import copy
import hashlib
import itertools
import json

from trust.config import TrustConfig
from trust.errors import ConfigError
from trust.exact import to_fraction

_KEYS = {"base", "epsilon", "lambda", "beta_gamma", "tau_r", "tau_q", "max_candidates"}


def spec_digest(spec):
    return hashlib.sha256(json.dumps(spec, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


def enumerate_candidates(spec):
    """Returns dict(candidates=[{config_id, config (dict), digest, findings}], rejected=[{combination, reason}], spec_sha256, counts)."""
    if not isinstance(spec, dict) or set(spec) != _KEYS:
        raise ConfigError(f"search spec needs exactly the keys {sorted(_KEYS)}")
    limit = spec["max_candidates"]
    if type(limit) is not int or limit < 1:
        raise ConfigError("max_candidates must be an explicit positive integer")
    for name in ("lambda", "beta_gamma", "tau_r", "tau_q"):
        if not isinstance(spec[name], list) or not spec[name]:
            raise ConfigError(f"{name}: a non-empty explicit list is required")
    size = len(spec["lambda"]) * len(spec["beta_gamma"]) * len(spec["tau_r"]) * len(spec["tau_q"])
    if size > limit:
        raise ConfigError(f"the specified space has {size} combinations, above the stated bound max_candidates = {limit}")
    candidates, rejected = [], []
    for lam, (beta, gamma), tau_r, tau_q in itertools.product(spec["lambda"], spec["beta_gamma"], spec["tau_r"], spec["tau_q"]):
        combination = dict(lam=lam, beta=beta, gamma=gamma, tau_r=tau_r, tau_q=tau_q)
        try:
            alpha = 1 - to_fraction(beta, "beta") - to_fraction(gamma, "gamma")
            config = copy.deepcopy(spec["base"])
            config.update(config_id="cand-" + hashlib.sha256(json.dumps(combination, sort_keys=True).encode()).hexdigest()[:12])
            config["trust_weights"] = dict(alpha=str(alpha), beta=str(to_fraction(beta, "beta")), gamma=str(to_fraction(gamma, "gamma")))
            config["behavior"] = {"epsilon": str(to_fraction(spec["epsilon"], "epsilon")), "lambda": str(to_fraction(lam, "lambda"))}
            config["thresholds"] = dict(tau_Q=str(to_fraction(tau_q, "tau_Q")), tau_R=str(to_fraction(tau_r, "tau_R")))
            built = TrustConfig.from_dict(config)
        except ConfigError as exc:
            rejected.append(dict(combination=combination, reason=str(exc)))
            continue
        candidates.append(dict(config_id=config["config_id"], config=config, digest=built.sha256(),
                               findings=built.reachability()["finding_codes"]))
    flagged = sum("BEHAVIORAL_QUARANTINE_UNREACHABLE" in c["findings"] for c in candidates)
    return dict(candidates=candidates, rejected=rejected, spec_sha256=spec_digest(spec),
                counts=dict(combinations=size, valid=len(candidates), rejected=len(rejected),
                            behavioral_quarantine_unreachable=flagged))
