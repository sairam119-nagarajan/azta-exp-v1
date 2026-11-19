"""Behavioural-model inference as an explicit, separately labelled stage (engineering observability; it feeds nothing into trust).

The trust engine scores a window only when an accepted calibration describes it; otherwise the behaviour component is MISSING and the reconstruction loss
L (journal eq. 8) is never computed or logged. This stage closes that observability gap WITHOUT promoting any calibration: after the engine has decided,
it reads the engine's own verdict for the behaviour component and

  * EVALUATED   reports the loss the engine used (no second computation), with the calibration identifier it was scored under;
  * MISSING because ONLY the calibration blocked (CALIBRATION_NOT_VALID_FOR_WORKLOAD, NO_CALIBRATION_FOR_PROFILE), which the engine reaches only after the
                window, the route, the age and the identity binding all passed: computes L with the frozen model of the routed profile on the engine's
                validated six-feature vector and reports it as UNCALIBRATED_LOSS_ONLY: no mu_L, no sigma_L, no A, no S_B, `trust_input = false`;
  * any other MISSING or NOT_EVALUATED outcome: not inferred, with the engine's own reason. Nothing is imputed, clipped or borrowed from another profile.

Every inference record states that it is engineering telemetry. The decision it accompanies is unchanged: a window that was NOT_EVALUABLE stays
NOT_EVALUABLE with no proposal, whatever L says. The stage holds no calibration constant and no threshold and cannot produce a trust score.
"""
import math

INFERENCE_VERSION = "decision-pipeline-inference-1"
INFERRED_AND_SCORED = "INFERRED_AND_SCORED"
INFERRED_UNCALIBRATED = "INFERRED_UNCALIBRATED"
NOT_INFERRED = "NOT_INFERRED"
CALIBRATION_ONLY_REASONS = ("CALIBRATION_NOT_VALID_FOR_WORKLOAD", "NO_CALIBRATION_FOR_PROFILE")
NOTE = ("engineering telemetry: the loss of the frozen model for this window; it is not a trust input, carries no calibration and does not change "
        "the decision record it accompanies")


def _reason_code(reason):
    return str(reason).split(":", 1)[0]


class InferenceStage:
    """models: {profile: object with .loss_for_vector(vector)} (the engine's own frozen models); descriptors: {profile: {fit_id, weights_sha256, ...}}."""

    def __init__(self, models, descriptors):
        self.models, self.descriptors = dict(models), dict(descriptors)

    def _identity_of(self, profile):
        d = self.descriptors.get(profile) or {}
        return dict(profile=profile, model_id=d.get("fit_id"), weights_sha256=d.get("weights_sha256"), scaler_sha256=d.get("scaler_sha256"))

    def infer(self, record):
        behavior = record.get("behavior") or {}
        base = dict(version=INFERENCE_VERSION, status=NOT_INFERRED, reason=None, calibration_applied=False, trust_input=False, loss=None,
                    anomaly_magnitude=None, behavioral_trust=None, model=None, note=NOTE)
        outcome, reasons = behavior.get("outcome"), list(behavior.get("reasons") or [])
        if record.get("record_kind") != "SHADOW_DECISION":
            return dict(base, reason="NO_DECISION_RECORD:" + str(record.get("refusal_code")))
        profile = behavior.get("profile")
        if outcome == "EVALUATED":
            return dict(base, status=INFERRED_AND_SCORED, reason="SCORED_BY_THE_ENGINE", calibration_applied=True, trust_input=True,
                        loss=behavior.get("loss"), anomaly_magnitude=behavior.get("anomaly_magnitude"), behavioral_trust=behavior.get("s_b"),
                        model=self._identity_of(profile), calibration_id=behavior.get("calibration_id"))
        if outcome != "MISSING":
            return dict(base, reason=reasons[0] if reasons else "BEHAVIOR_NOT_EVALUATED")
        if not reasons or _reason_code(reasons[0]) not in CALIBRATION_ONLY_REASONS or not behavior.get("features"):
            return dict(base, reason=reasons[0] if reasons else "UNSPECIFIED")
        model = self.models.get(profile)
        if model is None:
            return dict(base, reason="NO_MODEL_FOR_PROFILE")
        try:
            loss = float(model.loss_for_vector(list(behavior["features"])))
        except ValueError as exc:
            return dict(base, reason=f"SCORING_REFUSED:{exc}")
        if not math.isfinite(loss) or loss < 0:
            return dict(base, reason="NON_FINITE_LOSS")
        return dict(base, status=INFERRED_UNCALIBRATED, reason=reasons[0], loss=loss, model=self._identity_of(profile),
                    features=[float(v) for v in behavior["features"]], delivered_count=behavior.get("delivered_count"))
