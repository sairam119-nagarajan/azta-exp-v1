"""Calibration statistics of a Phase 1 model on benign calibration windows, with the single-use marker.

mu_L = mean of the losses, sigma_L = SAMPLE standard deviation (denominator n - 1, journal equation 10), over the native, non-overlapping ready windows of the calibration run only.
Degenerate calibrations (n < 2, non-finite or zero spread) are refused, not repaired. The largest-window share of the squared deviation is reported with every calibration: a calibration
in which one window carries more than half of it is FRAGILE (its stream is ADVISORY by rule unless the protocol says otherwise). The marker is created EXCLUSIVELY before the calibration
run is opened: a second pass under the same calibration id is refused by the filesystem.
"""
import json
import math
from pathlib import Path

import numpy as np

FRAGILE_SHARE = 0.5


class CalibrationRefused(ValueError):
    pass


def single_use_marker(path, payload):
    """Create the marker exclusively; a second creation raises FileExistsError (the single pass is already spent)."""
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(payload, stream, sort_keys=True, indent=1)
        stream.write("\n")


def statistics(losses):
    losses = np.asarray(losses, dtype=np.float64)
    if losses.size < 2 or not np.all(np.isfinite(losses)):
        raise CalibrationRefused("calibration needs at least two finite losses")
    mu = float(losses.mean())
    sigma = float(losses.std(ddof=1))
    if not (math.isfinite(sigma) and sigma > 0):
        raise CalibrationRefused("calibration spread is zero or non-finite (degenerate calibration is refused, not repaired)")
    squares = (losses - mu) ** 2
    share = float(squares.max() / squares.sum())
    return dict(n_B=int(losses.size), mu_L=mu, sigma_L=sigma, largest_window_share=share, fragile=share > FRAGILE_SHARE, sd_convention="sample (n - 1)")


def pooled(per_device_losses):
    """The family-pooled scope (sensitivity analysis): the same statistics over the concatenated native windows of all member devices."""
    return statistics(np.concatenate([np.asarray(v, dtype=np.float64) for v in per_device_losses.values()]))
