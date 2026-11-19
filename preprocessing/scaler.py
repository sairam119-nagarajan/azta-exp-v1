"""Gate 5D.2 train-only z-score scaler with the accepted zero-variance rule (freeze document section 5.2).

For each feature j, over ONE profile's SCORE_READY B_train population:
    zero variance (min == max, i.e. population SD exactly 0): mu = the single observed value, s = 1 native unit
    otherwise:  mu = mean, s = population SD (denominator N), float64
    z = (x - mu) / s   (no clipping, no log transform, six dimensions always)
A fitted zero-variance set that differs from the pre-declared expected set refuses to fit.
"""
import math

import numpy as np

from observation.schema import PREDICTOR_CANDIDATES

FEATURES = PREDICTOR_CANDIDATES
EXPECTED_ZERO_VARIANCE = {"S": ("payload_bytes_mean", "payload_bytes_sd"), "V": ()}
UNIT_SCALE = 1.0  # one native unit of the Gate 5B feature (bytes for the payload features)


class PreprocessingRefused(ValueError):
    """Fitting or transforming is refused (non-finite data, unexpected zero variance, wrong shape)."""


def _check_vector(vector):
    if len(vector) != len(FEATURES):
        raise PreprocessingRefused(f"PREPROCESSING_REFUSED input length {len(vector)} != {len(FEATURES)}")
    if not all(isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) for v in vector):
        raise PreprocessingRefused("PREPROCESSING_REFUSED non-finite or non-numeric input")


class ZScoreScaler:
    def __init__(self, profile, mu, s, zero_variance, n_fit):
        self.profile, self.mu, self.s = profile, tuple(mu), tuple(s)
        self.zero_variance, self.n_fit = tuple(zero_variance), n_fit

    @classmethod
    def fit(cls, profile, vectors):
        if profile not in EXPECTED_ZERO_VARIANCE:
            raise PreprocessingRefused(f"PREPROCESSING_REFUSED unknown profile {profile!r}")
        for vector in vectors:
            _check_vector(vector)
        x = np.asarray(vectors, dtype=np.float64)
        if x.ndim != 2 or x.shape[1] != len(FEATURES) or x.shape[0] < 1:
            raise PreprocessingRefused("PREPROCESSING_REFUSED empty or mis-shaped training matrix")
        mu, s, zero = [], [], []
        for j, name in enumerate(FEATURES):
            column = x[:, j]
            if column.min() == column.max():  # population SD exactly 0
                mu.append(float(column[0]))
                s.append(UNIT_SCALE)
                zero.append(name)
                continue
            mean = float(column.mean())
            sigma = float(column.std(ddof=0))
            if not (math.isfinite(mean) and math.isfinite(sigma) and sigma > 0.0):
                raise PreprocessingRefused(f"PREPROCESSING_REFUSED non-finite or non-positive SD for {name}")
            mu.append(mean)
            s.append(sigma)
        if tuple(zero) != EXPECTED_ZERO_VARIANCE[profile]:
            raise PreprocessingRefused(f"PREPROCESSING_REFUSED zero_variance_set={tuple(zero)} differs from the "
                                       f"declared set {EXPECTED_ZERO_VARIANCE[profile]} for profile {profile}")
        return cls(profile, mu, s, zero, int(x.shape[0]))

    @property
    def zero_variance_indices(self):
        return tuple(FEATURES.index(name) for name in self.zero_variance)

    def transform(self, vector, feature_order=FEATURES):
        if tuple(feature_order) != tuple(FEATURES):
            raise PreprocessingRefused("PREPROCESSING_REFUSED feature order differs from the frozen schema")
        _check_vector(vector)
        return tuple((float(x) - m) / s for x, m, s in zip(vector, self.mu, self.s))

    def transform_many(self, vectors):
        for vector in vectors:
            _check_vector(vector)
        x = np.asarray(vectors, dtype=np.float64)
        return (x - np.asarray(self.mu)) / np.asarray(self.s)

    def to_dict(self):
        return dict(profile=self.profile, features=list(FEATURES), mu=list(self.mu), s=list(self.s),
                    sd_convention="population (denominator N), float64", n_fit=self.n_fit,
                    zero_variance_features=list(self.zero_variance),
                    zero_variance_unit_scale={name: (name in self.zero_variance) for name in FEATURES},
                    unit_scale=UNIT_SCALE)

    @classmethod
    def from_dict(cls, data):
        if tuple(data["features"]) != tuple(FEATURES):
            raise PreprocessingRefused("PREPROCESSING_REFUSED stored feature order differs from the frozen schema")
        return cls(data["profile"], data["mu"], data["s"], data["zero_variance_features"], data["n_fit"])
