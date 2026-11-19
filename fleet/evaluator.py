"""Fleet behavioural evaluator: journal eq. 8-12 for the frozen S/V models AND provisional fleet profiles, over ten-device (registry v2) windows.

It is the frozen `trust.behavior.BehaviorEvaluator.evaluate` rule set, repeated with exactly three differences, each of them explicit and logged:

  1. PINS ARE PER PROFILE. The frozen evaluator accepts only registry-v1 windows because S and V were fitted and calibrated under registry v1. A ten-device observer cannot
     carry registry v1 (its registry digest is part of the observation-configuration digest), so a window of device01/device02 under registry v2 is scored by S/V ONLY when a
     hash-pinned compatibility record (`fleet.compat`) says the two observation configurations differ in the device list alone. Without that record the frozen refusal
     (SCHEMA_MISMATCH) stands. A provisional profile accepts exactly the pins it was fitted under.
  2. PROFILES ARE NOT LIMITED TO S AND V. Each profile has its own model, scaler (inside the model) and its own accepted-or-provisional calibration; nothing is borrowed from
     another profile, and a missing model or calibration is a precise MISSING reason, never a healthy score.
  3. THE CALIBRATION OF S/V IS THE UNCHANGED CAL_V2 RECORD. Its workload-version list is extended by the fleet workload version only through the compatibility record.

Everything else is identical: the 10 s window, complete coverage with all six measures present (R1/R2), a trusted route, fresh evidence, an identity matching the authenticated
principal, a finite loss, A = max(0, (L - mu_L)/(sigma_L + eps)) and S_B = 100 exp(-lambda A) with eps and lambda from the validated trust configuration. Nothing is imputed, clipped or
borrowed, and a missing window never becomes a healthy S_B.
"""
from dataclasses import dataclass
from fractions import Fraction
import math

from observation.schema import PREDICTOR_CANDIDATES, candidate_vector, validate_window
from trust.behavior import FROZEN_WINDOW_NS, BehaviorEvaluator, anomaly_magnitude, behavioral_trust
from trust.evidence import EVALUATED, MISSING, TRUSTED_ROUTE_PROVENANCE, ComponentResult, age_problem, provenance_trusted

REASON_PRECEDENCE = ("OBSERVER_UNAVAILABLE", "NO_MESSAGES", "INSUFFICIENT_MESSAGES", "NEVER_OBSERVED_IN_SESSION")


@dataclass(frozen=True)
class FleetCalibration:
    """The same fields the frozen `Calibration` carries, for any profile name. Validated like it: n_B >= 2, finite mu_L >= 0, finite sigma_L > 0."""
    profile: str
    n_b: int
    mu_l: float
    sigma_l: float
    source: dict
    calibration_id: object = None
    workload_versions: object = None
    status: str = "PROVISIONAL_UNAPPROVED"

    def __post_init__(self):
        if not isinstance(self.profile, str) or not self.profile or type(self.n_b) is not int or self.n_b < 2:
            raise ValueError("calibration needs a profile and n_B >= 2 (a sample SD is undefined below 2)")
        if not (math.isfinite(self.mu_l) and self.mu_l >= 0 and math.isfinite(self.sigma_l) and self.sigma_l > 0):
            raise ValueError("calibration needs finite mu_L >= 0 and sigma_L > 0 (degenerate calibration is refused, not repaired)")


def classify_fleet_window(window, profile, accepted_pins):
    """(ready, reason, vector) for one window of profile `profile`. `accepted_pins`: tuple of (registry_sha256, observation_config_sha256, schema_fingerprint) the profile may
    be scored under. Order of refusals follows the frozen reader: schema and pins first, then the route, then coverage and the six measures."""
    try:
        validate_window(window)
        pins = (window["identity"]["registry_sha256"], window["observation_config_sha256"], window["schema_fingerprint"])
        if pins not in accepted_pins:
            raise ValueError("pinned schema, registry or configuration mismatch")
    except (ValueError, TypeError, KeyError, AttributeError):
        return False, "SCHEMA_MISMATCH", None
    if profile is None:
        return False, "NO_APPROVED_PROFILE_ROUTE", None
    statuses = {window["measures"][name]["status"] for name in PREDICTOR_CANDIDATES}
    if window["coverage"]["state"] != "COMPLETE":
        return False, "OBSERVER_UNAVAILABLE", None
    for reason in REASON_PRECEDENCE[1:]:
        if reason in statuses:
            return False, reason, None
    values, mask = candidate_vector(window)
    if not all(mask):
        return False, "SCHEMA_MISMATCH", None
    return True, None, tuple(float(v) for v in values)


class FleetBehaviorEvaluator(BehaviorEvaluator):
    """models: {profile: object with .loss_for_vector(vector)}; calibrations: {profile: FleetCalibration}; accepted_pins: {profile: tuple of pin triples}."""

    def __init__(self, models, calibrations, *, accepted_pins, reserved_tokens=(), provenance=None, cross_workload_experiment_id=None):
        super().__init__(models, calibrations, reserved_tokens=reserved_tokens, provenance=provenance, cross_workload_experiment_id=cross_workload_experiment_id)
        self.accepted_pins = {profile: tuple(tuple(p) for p in pins) for profile, pins in accepted_pins.items()}

    def _copy(self, **changes):
        arguments = dict(accepted_pins=self.accepted_pins, reserved_tokens=self.reserved, provenance=self.provenance,
                         cross_workload_experiment_id=self.cross_workload_experiment_id)
        arguments.update(changes)
        return FleetBehaviorEvaluator(self.models, self.calibrations, **arguments)

    def with_reserved(self, tokens):
        extra = frozenset(tokens) - self.reserved
        provenance = dict(self.provenance, additional_reserved_token_count=self.provenance.get("additional_reserved_token_count", 0) + len(extra))
        return self._copy(reserved_tokens=self.reserved | extra, provenance=provenance)

    def with_cross_workload_baseline(self, experiment_id):
        if not (isinstance(experiment_id, str) and experiment_id):
            raise ValueError("a cross-workload comparison needs an experiment identifier")
        return self._copy(cross_workload_experiment_id=experiment_id)

    def evaluate(self, behavior, config, *, evidence_mode, decision_ns, expected_identity):
        detail = dict(outcome=MISSING, reasons=[], profile=None, route_provenance=None, window_ref=None, observed_ns=None, features=None, delivered_count=None, loss=None,
                      mu_L=None, sigma_L=None, n_B=None, epsilon=config.epsilon_float, lam=config.lambda_float, anomaly_magnitude=None, anomaly_magnitude_overflow=False,
                      s_b=None, workload_version=None, calibration_id=None, cross_workload_baseline_experiment_id=None, calibration_status=None)

        def missing(reason):
            detail["reasons"] = [reason]
            return ComponentResult(MISSING, None, (reason,), detail)

        if behavior is None:
            return missing("NO_BEHAVIOR_EVIDENCE")
        window, profile = behavior["window"], behavior["bound_profile"]
        detail.update(profile=profile, route_provenance=behavior["route_provenance"], observed_ns=behavior["observed_ns"], workload_version=behavior["workload_version"])
        if window is None:
            return missing("NO_WINDOW")
        run_id, session = window.get("collection_run_id"), window.get("observer_session_id")
        window_info = window.get("window") if isinstance(window.get("window"), dict) else {}
        detail["window_ref"] = dict(collection_run_id=run_id, observer_session_id=session, device=window.get("device"), window_index=window_info.get("index"),
                                    purpose=window.get("purpose"))
        if any(isinstance(token, str) and token in self.reserved for token in (run_id, session)):
            return missing("RESERVED_EVIDENCE_REFUSED")
        known = self.accepted_pins.get(profile) if profile is not None else None
        # pins are judged first, as in the frozen reader; a window with no (or an unknown) profile is judged against every pin set any profile accepts, so its precise reason
        # (no route / no model) is reported instead of a pin mismatch
        pins = known if known is not None else tuple({p for group in self.accepted_pins.values() for p in group})
        ready, reason, vector = classify_fleet_window(window, profile, pins)
        if ready and window["window"]["duration_ns"] != FROZEN_WINDOW_NS:
            ready, reason = False, "SCHEMA_MISMATCH"
        if not ready:
            return missing(reason)
        detail.update(features=[float(v) for v in vector], delivered_count=int(vector[PREDICTOR_CANDIDATES.index("delivered_count")]))
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
        detail.update(calibration_id=calibration.calibration_id, calibration_status=getattr(calibration, "status", None))
        if calibration.workload_versions is not None and behavior["workload_version"] not in calibration.workload_versions:
            if self.cross_workload_experiment_id is None:
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
        overflow = math.isinf(a)
        detail.update(outcome=EVALUATED, reasons=["BEHAVIOR_SCORED"] + (["ANOMALY_MAGNITUDE_OVERFLOW"] if overflow else []), loss=loss, mu_L=calibration.mu_l,
                      sigma_L=calibration.sigma_l, n_B=calibration.n_b, anomaly_magnitude=None if overflow else a, anomaly_magnitude_overflow=overflow, s_b=s_b)
        return ComponentResult(EVALUATED, Fraction(s_b), tuple(detail["reasons"]), detail)
