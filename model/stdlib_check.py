"""Gate 5D.2 independent recomputation of a transformed vector and its loss using only the standard library.

Used as a verification cross-check of the torch implementation: it reads the stored scaler and weights JSON and
re-derives z and L (journal eq 8) with plain Python arithmetic. It shares no code with model.autoencoder.
"""
import math


def zscore(vector, mu, s):
    return [(x - m) / sd for x, m, sd in zip(vector, mu, s)]


def _linear(weights, name, x):
    w, b = weights[f"{name}.weight"]["data"], weights[f"{name}.bias"]["data"]
    return [sum(wij * xj for wij, xj in zip(row, x)) + bi for row, bi in zip(w, b)]


def forward(weights, z):
    h = [max(0.0, v) for v in _linear(weights, "enc1", z)]
    code = _linear(weights, "enc2", h)
    d = [max(0.0, v) for v in _linear(weights, "dec1", code)]
    return _linear(weights, "out", d)


def loss(weights, mu, s, vector):
    z = zscore(vector, mu, s)
    out = forward(weights, z)
    return math.fsum((o - x) ** 2 for o, x in zip(out, z)) / len(z)
