"""Gate 6B fleet extension: behavioural profiles, scoring and live-session adapter for more than the two frozen S/V devices.

A separately versioned package OUTSIDE the frozen scientific sources (`trust/`, `experiments/`, `observation/`, `model/`, `preprocessing/`, `calibration/`), which it imports and
never edits. Nothing here changes the frozen S/V models, the accepted CAL_V2 constants, the trust configuration, a threshold, N, or the observer. New profile models and
calibrations are PROVISIONAL engineering candidates until a Controller approval record says otherwise.
"""
