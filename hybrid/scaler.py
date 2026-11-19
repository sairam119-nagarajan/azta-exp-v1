"""Tolerance-floored standardization (TFS): the documented handling of zero-variance AND near-zero-variance features for the Gate 6C candidates.

The accepted Gate 5D rule (freeze document section 5.2, D-ZV-2) handles only EXACT zero variance (min == max): mu = the observed value, s = 1 native unit, the input and output weights of that
feature are held at 0. A strictly periodic device has features that are constant to within the timing resolution of the measurement chain but not exactly constant (the inter-arrival mean of
a 4 s device is 3999.99 +/- 0.29 ms over 312 windows, relative SD 7e-5). Standardizing by the population SD of such a feature divides a perfectly ordinary millisecond of scheduling noise by
a fraction of a millisecond: the Gate 6B pilot showed the consequence (device05 read 3 to 5 ms of publisher jitter as a large reconstruction error; at 1 ms of timing displacement 6 percent of its windows
already crossed the RESTRICT threshold, see docs/gate6c/GATE_6C_STAGE1_F1_F2.md).

TFS: for every feature j of a profile,
    exact zero variance (min == max)       mu_j = the single value, s_j = 1 native unit       (unchanged D-ZV-2; the feature is in the zero-variance set, weights held at 0)
    otherwise                              mu_j = mean, s_j = max(population SD_j, delta_j)    delta_j = the declared TOLERANCE of feature j
delta_j is the resolution or tolerance of the measurement chain for that feature, declared in the observation contract BEFORE any fit, independent of the data's variance and of every attack
outcome: half a message for a count, one byte for a payload statistic, the timing tolerance of the chain (a contract value, 5 ms for the Gate 6C candidates) for the inter-arrival and last-
delivery features. A feature whose natural SD already exceeds its tolerance is untouched, so profiles with broad timing (S, V, FX, SU, SW) are unaffected by construction. The floor only
decides how many standard units a deviation counts for; it removes sensitivity to deviations smaller than the declared tolerance and nothing else. Disclosed consequence: a deviation smaller
than delta_j in a floored feature is not detectable by the autoencoder (the timing monitor is the instrument for timing, and its own tolerances are in its contract).
The fitted set of exactly-zero-variance features must equal the DECLARED set or fitting refuses, as before. Which features were floored is recorded in the bundle.
"""
import math

import numpy as np

from observation.schema import PREDICTOR_CANDIDATES

FEATURES = PREDICTOR_CANDIDATES
UNIT_SCALE = 1.0


class ScalerRefused(ValueError):
    pass


def mask_vector(vector, masked):
    """The six-feature vector with the `masked` features held at the constant 0.0 (Gate 6C pre-live amendment 1: a phase-nuisance feature carries no behavioural information; the scaler then sees a
    constant column and applies the frozen D-ZV-2 rule). The order and length of the vector never change."""
    if not masked:
        return tuple(vector)
    unknown = [name for name in masked if name not in FEATURES]
    if unknown:
        raise ScalerRefused(f"SCALER_REFUSED unknown masked feature {unknown}")
    return tuple(0.0 if name in masked else float(v) for name, v in zip(FEATURES, vector))


def _check(vector):
    if len(vector) != len(FEATURES) or not all(isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) for v in vector):
        raise ScalerRefused("SCALER_REFUSED input is not six finite numbers")


class FlooredScaler:
    def __init__(self, profile, mu, s, zero_variance, floored, floors, n_fit):
        self.profile, self.mu, self.s = profile, tuple(mu), tuple(s)
        self.zero_variance, self.floored, self.floors, self.n_fit = tuple(zero_variance), tuple(floored), dict(floors), n_fit

    @classmethod
    def fit(cls, profile, vectors, floors, declared_zero):
        if set(floors) != set(FEATURES) or not all(isinstance(v, (int, float)) and v > 0 and math.isfinite(v) for v in floors.values()):
            raise ScalerRefused("SCALER_REFUSED a positive finite tolerance must be declared for each of the six features")
        for vector in vectors:
            _check(vector)
        x = np.asarray(vectors, dtype=np.float64)
        if x.ndim != 2 or x.shape[1] != len(FEATURES) or x.shape[0] < 2:
            raise ScalerRefused("SCALER_REFUSED empty or mis-shaped training matrix")
        mu, s, zero, floored = [], [], [], []
        for j, name in enumerate(FEATURES):
            column = x[:, j]
            if column.min() == column.max():
                mu.append(float(column[0]))
                s.append(UNIT_SCALE)
                zero.append(name)
                continue
            sigma = float(column.std(ddof=0))
            mu.append(float(column.mean()))
            if sigma < floors[name]:
                floored.append(name)
            s.append(max(sigma, float(floors[name])))
        if tuple(zero) != tuple(f for f in FEATURES if f in declared_zero):
            raise ScalerRefused(f"SCALER_REFUSED zero_variance_set={tuple(zero)} differs from the declared set {tuple(declared_zero)} for profile {profile}")
        return cls(profile, mu, s, zero, floored, floors, int(x.shape[0]))

    @property
    def zero_variance_indices(self):
        return tuple(FEATURES.index(name) for name in self.zero_variance)

    def transform(self, vector):
        _check(vector)
        return tuple((float(v) - m) / s for v, m, s in zip(vector, self.mu, self.s))

    def transform_many(self, vectors):
        for vector in vectors:
            _check(vector)
        return (np.asarray(vectors, dtype=np.float64) - np.asarray(self.mu)) / np.asarray(self.s)

    def to_dict(self):
        return dict(profile=self.profile, features=list(FEATURES), mu=list(self.mu), s=list(self.s), method="TOLERANCE_FLOORED_STANDARDIZATION_1", sd_convention="population (denominator N), floored",
                    n_fit=self.n_fit, zero_variance_features=list(self.zero_variance), floored_features=list(self.floored), tolerances=dict(self.floors), unit_scale=UNIT_SCALE)

    @classmethod
    def from_dict(cls, data):
        if tuple(data["features"]) != tuple(FEATURES) or data.get("method") != "TOLERANCE_FLOORED_STANDARDIZATION_1":
            raise ScalerRefused("SCALER_REFUSED stored feature order or method differs")
        return cls(data["profile"], data["mu"], data["s"], data["zero_variance_features"], data["floored_features"], data["tolerances"], data["n_fit"])
