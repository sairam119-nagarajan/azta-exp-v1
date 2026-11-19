"""Gate 5D.2 profile-model inference with schema, route and readiness refusal (freeze document sections 4-6).

Computes ONE thing: the journal's per-window reconstruction loss L (eq 8) in transformed space. It computes no
calibration statistic, anomaly magnitude, behavioural trust score, threshold or decision, and it never imputes,
bounds inputs or falls back to the other profile's model. A window that is not score-ready is refused with its
R2 reason.
"""
import hashlib
import json
from pathlib import Path

import torch

from model.autoencoder import assert_zero_weights, model_from_weights, per_window_loss
from preprocessing.gate5d_data import FEATURES, PIN, PROFILES, classify_window
from preprocessing.scaler import PreprocessingRefused, ZScoreScaler


class ScoreRefused(ValueError):
    """The window or vector cannot be scored (R2 reason, wrong route, wrong schema)."""

    def __init__(self, reason, detail=""):
        super().__init__(f"{reason} {detail}".strip())
        self.reason = reason


class ProfileModel:
    def __init__(self, profile, scaler, model, schema_pins):
        self.profile, self.scaler, self.model, self.schema_pins = profile, scaler, model, schema_pins
        self.model.eval()

    @classmethod
    def load(cls, fit_dir):
        """Load a fit bundle, verifying the stored weights digest and the schema pins."""
        fit_dir = Path(fit_dir)
        bundle = json.loads((fit_dir / "bundle.json").read_text(encoding="utf-8"))
        weights_bytes = (fit_dir / bundle["weights_file"]).read_bytes()
        if hashlib.sha256(weights_bytes).hexdigest() != bundle["weights_sha256"]:
            raise ScoreRefused("WEIGHTS_DIGEST_MISMATCH", str(fit_dir))
        if bundle["status"] != "COMPLETED":
            raise ScoreRefused("FIT_NOT_COMPLETED", bundle["fit_id"])
        pins = bundle["schema_pins"]
        if pins["schema_fingerprint"] != PIN["schema_fingerprint"] \
                or pins["observation_config_sha256"] != PIN["observation_config_sha256"] \
                or tuple(pins["feature_order"]) != tuple(FEATURES):
            raise ScoreRefused("SCHEMA_MISMATCH", "stored pins differ from the frozen schema")
        scaler = ZScoreScaler.from_dict(bundle["scaler"])
        model = model_from_weights(bundle["k"], json.loads(weights_bytes.decode("utf-8")))
        assert_zero_weights(model, scaler.zero_variance_indices, "load")
        return cls(bundle["profile"], scaler, model, pins)

    def loss_for_vector(self, vector, feature_order=FEATURES):
        try:
            z = self.scaler.transform(vector, feature_order)
        except PreprocessingRefused as exc:
            raise ScoreRefused("SCHEMA_MISMATCH", str(exc)) from exc
        x = torch.tensor([z], dtype=torch.float64)
        return float(per_window_loss(self.model, x)[0])

    def score_window(self, window, bound_profile):
        """Per-window loss for one observation window, or ScoreRefused with the R2 reason / ROUTE_MISMATCH."""
        if bound_profile not in PROFILES:
            raise ScoreRefused("NO_APPROVED_PROFILE_ROUTE")
        if bound_profile != self.profile:
            raise ScoreRefused("ROUTE_MISMATCH", f"window routed to {bound_profile}, model is {self.profile}")
        ready, reason, vector = classify_window(window, bound_profile)
        if not ready:
            raise ScoreRefused(reason)
        return self.loss_for_vector(vector)
