"""Gate 6C hybrid behavioural monitoring: profile-aware multi-timescale observation, a calibrated timing/payload monitor and a documented fusion of behavioural evidence.

ENGINEERING / PROVISIONAL. Nothing in this package changes a frozen source (`trust/`, `observation/`, `model/`, `preprocessing/`, `calibration/`, `experiments/`), the S/V models, the CAL_V2
constants, the trust weights, the thresholds or N = 2: it reads the recorded observer events, re-windows them with the FROZEN `observation.windowing.measures` function, and adds separately
versioned candidates (a tolerance-floored scaler, new autoencoder candidates, a contract-based timing monitor, an evidence integrator) that are used only through the unchanged engine's
documented behaviour-evaluator interface.
"""
