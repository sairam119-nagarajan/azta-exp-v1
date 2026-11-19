"""Device-specific baseline-relative normalisation (feature contracts FC-6.1N and FC-6.2R of protocol P1-FAM).

A `DeviceNormalizer` is the device-specific half of a behavioural-family model: the baseline b_d and the scale s_d of ONE device, fitted on that device's own TRAIN rows only,
    z_j = (x_j - b_j) / s_j        b = mean of the baseline set, s = max(population SD, declared tolerance)       (exactly the tolerance-floored standardisation of Gate 6C, per device)
    a feature that is exactly constant in the baseline set takes b = that value, s = 1 native unit         (the accepted D-ZV-2 rule, applied at the normalisation step)
FC-6.1N feeds z to the network. FC-6.2R feeds u = sign(z) ln(1 + |z|), a monotone bounded-influence map with no constant of its own. The fitted set of exactly constant features must lie
between the declared required set and required + permitted (the Gate 6C rule), else fitting refuses. A normaliser is bound to its device name: asking it for another device is refused, so
baselines cannot be confused across devices. Nothing here reads a run, a clock or a file.
"""
import hashlib
import json
import math

import numpy as np

from observation.schema import PREDICTOR_CANDIDATES

FEATURES = PREDICTOR_CANDIDATES
FC_N, FC_R = "FC-6.1N", "FC-6.2R"
CONTRACTS = (FC_N, FC_R)
UNIT_SCALE = 1.0


class NormalizerRefused(ValueError):
    pass


def compress(z):
    """u = sign(z) * ln(1 + |z|) (FC-6.2R); elementwise on a number, a sequence or an array."""
    return np.sign(z) * np.log1p(np.abs(z))


def _check(vector):
    if len(vector) != len(FEATURES) or not all(isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) for v in vector):
        raise NormalizerRefused("NORMALIZER_REFUSED input is not six finite numbers")


class DeviceNormalizer:
    def __init__(self, device, contract, mu, s, zero_variance, floored, floors, n_fit):
        if contract not in CONTRACTS:
            raise NormalizerRefused(f"NORMALIZER_REFUSED unknown feature contract {contract!r}")
        self.device, self.contract, self.mu, self.s = device, contract, tuple(float(v) for v in mu), tuple(float(v) for v in s)
        self.zero_variance, self.floored, self.floors, self.n_fit = tuple(zero_variance), tuple(floored), dict(floors), int(n_fit)
        if len(self.mu) != len(FEATURES) or len(self.s) != len(FEATURES) or not all(v > 0 and math.isfinite(v) for v in self.s):
            raise NormalizerRefused("NORMALIZER_REFUSED mean or scale is not six finite positive/finite numbers")

    @classmethod
    def fit(cls, device, contract, vectors, floors, *, required_zero=(), permitted_zero=()):
        """Fit on the device's baseline rows (TRAIN only: the caller's contract, enforced by the partition door of `family.assignment`)."""
        if contract not in CONTRACTS:
            raise NormalizerRefused(f"NORMALIZER_REFUSED unknown feature contract {contract!r}")
        if set(floors) != set(FEATURES) or not all(isinstance(v, (int, float)) and v > 0 and math.isfinite(v) for v in floors.values()):
            raise NormalizerRefused("NORMALIZER_REFUSED a positive finite tolerance must be declared for each of the six features")
        for vector in vectors:
            _check(vector)
        x = np.asarray(vectors, dtype=np.float64)
        if x.ndim != 2 or x.shape[1] != len(FEATURES) or x.shape[0] < 2:
            raise NormalizerRefused("NORMALIZER_REFUSED empty or mis-shaped baseline matrix")
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
        required, permitted = set(required_zero), set(permitted_zero)
        if not required <= set(zero) or not set(zero) <= required | permitted:
            raise NormalizerRefused(f"NORMALIZER_REFUSED zero_variance_set={tuple(zero)} outside the declared band required={tuple(sorted(required))} permitted={tuple(sorted(permitted))} for {device}")
        return cls(device, contract, mu, s, zero, floored, floors, x.shape[0])

    def _z(self, x):
        return (x - np.asarray(self.mu)) / np.asarray(self.s)

    def transform(self, vector):
        _check(vector)
        z = self._z(np.asarray(vector, dtype=np.float64))
        return tuple(float(v) for v in (compress(z) if self.contract == FC_R else z))

    def transform_many(self, vectors):
        for vector in vectors:
            _check(vector)
        z = self._z(np.asarray(vectors, dtype=np.float64))
        return compress(z) if self.contract == FC_R else z

    def independent_transform(self, vector):
        """The same transform with the standard library only (shares no numerical code with `transform`)."""
        z = [(float(v) - m) / s for v, m, s in zip(vector, self.mu, self.s)]
        if self.contract == FC_R:
            z = [math.copysign(math.log1p(abs(v)), v) for v in z]
        return z

    def to_dict(self):
        return dict(device=self.device, contract=self.contract, features=list(FEATURES), mu=list(self.mu), s=list(self.s), method="BASELINE_RELATIVE_TOLERANCE_FLOORED_1",
                    sd_convention="population (denominator N), floored", n_fit=self.n_fit, zero_variance_features=list(self.zero_variance), floored_features=list(self.floored),
                    tolerances=dict(self.floors), unit_scale=UNIT_SCALE)

    @classmethod
    def from_dict(cls, data):
        if tuple(data["features"]) != tuple(FEATURES) or data.get("method") != "BASELINE_RELATIVE_TOLERANCE_FLOORED_1":
            raise NormalizerRefused("NORMALIZER_REFUSED stored feature order or method differs")
        return cls(data["device"], data["contract"], data["mu"], data["s"], data["zero_variance_features"], data["floored_features"], data["tolerances"], data["n_fit"])

    @property
    def digest(self):
        return hashlib.sha256(json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
