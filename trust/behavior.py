"""Behavioural trust S_B (journal section 4.2, eq. 8-12) from the frozen profile autoencoders and their accepted calibration.

    L = (1/p) * sum_i((x_i - x_hat_i)^2)            eq. 8, computed by the frozen model in its train-fitted z-score space (p = 6)
    A = max(0, (L - mu_L) / (sigma_L + epsilon))      eq. 11, mu_L and sample sigma_L (n-1) from the accepted calibration of THE SAME profile
    S_B = 100 * exp(-lambda * A)                      eq. 12

A window is scored only when it passes every compatibility rule: the pinned Gate 5B schema and observation configuration (so a window
from the expanded ten-device registry is SCHEMA_MISMATCH and is never forced through the registry-v1 models), the frozen 10 s window,
complete coverage with all six measures present (R1/R2), a trusted profile route, fresh evidence, an identity matching the
authenticated principal, and a loss that is finite. Anything else is MISSING with exactly one reason. Nothing is imputed, clipped,
zero-filled or borrowed from another window or the other profile, and a missing window never becomes a healthy S_B. Windows of the
reserved calibration partition, of invalidated runs and of any other run or session id the caller lists as reserved are refused.
"""
from dataclasses import dataclass
from fractions import Fraction
import math

from preprocessing.gate5d_data import FEATURES, PIN, PROFILES, classify_window
from trust.evidence import EVALUATED, MISSING, TRUSTED_ROUTE_PROVENANCE, ComponentResult, age_problem, provenance_trusted

FROZEN_WINDOW_NS = 10_000_000_000  # W = 10,000 ms, encoded in the pinned observation_config_sha256


@dataclass(frozen=True)
class Calibration:
    """Accepted benign calibration constants of one profile: mu_L, SAMPLE sigma_L (n_B - 1), and where they came from."""
    profile: str
    n_b: int
    mu_l: float
    sigma_l: float
    source: dict
    calibration_id: object = None          # version label of this calibration (e.g. "gate5e-v1"); None only in synthetic unit tests
    workload_versions: object = None       # workload versions whose benign windows this calibration describes; None = unconstrained (tests)

    def __post_init__(self):
        if self.profile not in PROFILES or type(self.n_b) is not int or self.n_b < 2:
            raise ValueError("calibration needs a known profile and n_B >= 2 (a sample SD is undefined below 2)")
        if not (math.isfinite(self.mu_l) and self.mu_l >= 0 and math.isfinite(self.sigma_l) and self.sigma_l > 0):
            raise ValueError("calibration needs finite mu_L >= 0 and sigma_L > 0 (degenerate calibration is refused, not repaired)")


def anomaly_magnitude(loss, mu_l, sigma_l, epsilon):
    """Journal eq. 11. epsilon is only the numerical safeguard; it is supplied by the configuration, never defaulted."""
    values = (loss, mu_l, sigma_l, epsilon)
    if not all(isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) for v in values) \
            or sigma_l < 0 or epsilon <= 0:
        raise ValueError("loss, mu_L, sigma_L and epsilon must be finite numbers with sigma_L >= 0 and epsilon > 0")
    return max(0.0, (float(loss) - float(mu_l)) / (float(sigma_l) + float(epsilon)))


def behavioral_trust(a, lam):
    """Journal eq. 12. Saturates to exactly 0.0 for very large A (exp underflow); never negative, never above 100."""
    if not (isinstance(a, (int, float)) and not isinstance(a, bool) and a >= 0.0) \
            or not (isinstance(lam, (int, float)) and not isinstance(lam, bool) and math.isfinite(lam) and lam > 0):
        raise ValueError("A must be a non-negative number and lambda a finite positive number")
    return 100.0 * math.exp(-float(lam) * float(a))


class BehaviorEvaluator:
    """models: {profile: object with .loss_for_vector(vector)}; calibrations: {profile: Calibration}; reserved_tokens: run and session
    ids whose windows must never be scored (reserved calibration, invalidated); provenance: JSON-ready description for the log."""

    def __init__(self, models, calibrations, *, reserved_tokens=(), provenance=None, cross_workload_experiment_id=None):
        self.models, self.calibrations = dict(models), dict(calibrations)
        self.reserved = frozenset(reserved_tokens)
        self.provenance = dict(provenance or {})
        self.cross_workload_experiment_id = cross_workload_experiment_id   # explicit, logged comparison of a calibration against another workload

    def with_reserved(self, tokens):
        """A copy that additionally refuses windows of the given run and session ids (e.g. the held-out final-test partition)."""
        extra = frozenset(tokens) - self.reserved
        provenance = dict(self.provenance, additional_reserved_token_count=self.provenance.get("additional_reserved_token_count", 0) + len(extra))
        return BehaviorEvaluator(self.models, self.calibrations, reserved_tokens=self.reserved | extra, provenance=provenance,
                                 cross_workload_experiment_id=self.cross_workload_experiment_id)

    def with_cross_workload_baseline(self, experiment_id):
        """A copy that may score windows of a workload the calibration does not describe, ONLY as a named comparison experiment (logged)."""
        if not (isinstance(experiment_id, str) and experiment_id):
            raise ValueError("a cross-workload comparison needs an experiment identifier")
        return BehaviorEvaluator(self.models, self.calibrations, reserved_tokens=self.reserved, provenance=self.provenance,
                                 cross_workload_experiment_id=experiment_id)

    def evaluate(self, behavior, config, *, evidence_mode, decision_ns, expected_identity):
        detail = dict(outcome=MISSING, reasons=[], profile=None, route_provenance=None, window_ref=None, observed_ns=None,
                      features=None, delivered_count=None, loss=None, mu_L=None, sigma_L=None, n_B=None,
                      epsilon=config.epsilon_float, lam=config.lambda_float, anomaly_magnitude=None,
                      anomaly_magnitude_overflow=False, s_b=None, workload_version=None, calibration_id=None,
                      cross_workload_baseline_experiment_id=None)

        def missing(reason):
            detail["reasons"] = [reason]
            return ComponentResult(MISSING, None, (reason,), detail)

        if behavior is None:
            return missing("NO_BEHAVIOR_EVIDENCE")
        window, profile = behavior["window"], behavior["bound_profile"]
        detail.update(profile=profile, route_provenance=behavior["route_provenance"], observed_ns=behavior["observed_ns"],
                      workload_version=behavior["workload_version"])
        if window is None:
            return missing("NO_WINDOW")
        run_id, session = window.get("collection_run_id"), window.get("observer_session_id")
        window_info = window.get("window") if isinstance(window.get("window"), dict) else {}
        detail["window_ref"] = dict(collection_run_id=run_id, observer_session_id=session, device=window.get("device"),
                                    window_index=window_info.get("index"), purpose=window.get("purpose"))
        if any(isinstance(token, str) and token in self.reserved for token in (run_id, session)):
            return missing("RESERVED_EVIDENCE_REFUSED")

        ready, reason, vector = classify_window(window, profile)  # R1/R2 incl. the pinned schema and configuration
        if ready and (window["identity"]["registry_sha256"] != PIN["registry_sha256"]
                      or window["window"]["duration_ns"] != FROZEN_WINDOW_NS):
            ready, reason = False, "SCHEMA_MISMATCH"
        if not ready:
            return missing(reason)
        detail.update(features=[float(v) for v in vector], delivered_count=int(vector[FEATURES.index("delivered_count")]))
        if not provenance_trusted(behavior["route_provenance"], evidence_mode, TRUSTED_ROUTE_PROVENANCE):
            return missing(f"UNTRUSTED_ROUTE_PROVENANCE:{behavior['route_provenance']}")
        problem = age_problem(behavior["observed_ns"], decision_ns, config.max_evidence_age_ns["behavior"])
        if problem:
            return missing(f"{problem}_BEHAVIOR_EVIDENCE")
        if expected_identity is None or (window["identity"]["bound_username"], window["identity"]["bound_client_id"]) != expected_identity:
            return missing("IDENTITY_BEHAVIOR_BINDING_MISMATCH")
        model, calibration = self.models.get(profile), self.calibrations.get(profile)
        if model is None:
            return missing("NO_MODEL_FOR_PROFILE")
        if calibration is None:
            return missing("NO_CALIBRATION_FOR_PROFILE")
        detail["calibration_id"] = calibration.calibration_id
        if calibration.workload_versions is not None and behavior["workload_version"] not in calibration.workload_versions:
            if self.cross_workload_experiment_id is None:     # the historical calibration is never silently applied to another workload
                return missing(f"CALIBRATION_NOT_VALID_FOR_WORKLOAD:{behavior['workload_version']}")
            detail["cross_workload_baseline_experiment_id"] = self.cross_workload_experiment_id
        try:
            loss = float(model.loss_for_vector(vector))
        except ValueError as exc:
            return missing(f"SCORING_REFUSED:{exc}")
        if not math.isfinite(loss) or loss < 0:
            return missing("NON_FINITE_LOSS")
        a = anomaly_magnitude(loss, calibration.mu_l, calibration.sigma_l, config.epsilon_float)
        s_b = behavioral_trust(a, config.lambda_float)
        overflow = math.isinf(a)  # a finite loss over a tiny denominator: S_B is exactly 0.0; A cannot be written in JSON
        detail.update(outcome=EVALUATED, reasons=["BEHAVIOR_SCORED"] + (["ANOMALY_MAGNITUDE_OVERFLOW"] if overflow else []),
                      loss=loss, mu_L=calibration.mu_l, sigma_L=calibration.sigma_l, n_B=calibration.n_b,
                      anomaly_magnitude=None if overflow else a, anomaly_magnitude_overflow=overflow, s_b=s_b)
        return ComponentResult(EVALUATED, Fraction(s_b), tuple(detail["reasons"]), detail)
