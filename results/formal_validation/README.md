# AZTA-EXP-v1: experimental data for Adaptive Zero Trust Automation in MQTT-based IoT

> **In this repository** the frozen model files are at their original paths under `results/engineering/` (listed in `reproducibility/frozen_model_files_sha256.csv`), not under `models/`.

This dataset accompanies a journal article on Adaptive Zero Trust Automation (AZTA) for MQTT-based IoT. It contains the recorded outcomes of the formal experimental validation, the secondary analyses reported in the article, and the frozen autoencoder models that produced the behavioural scores.

## The experiment in brief

- **Testbed:** ten simulated IoT devices (Python/Paho MQTT clients, `device01`–`device10`) publish telemetry to an Eclipse Mosquitto broker. The broker's Dynamic Security plugin acts as the policy enforcement point (PEP). Everything runs in Docker on a single host (see `reproducibility/environment.json`).
- **Decision pipeline:** an observer builds fixed, non-overlapping telemetry windows for each device (10 s for devices 01–05 and 10, 20 s for 06–07, 90 s for 08, 180 s for 09). A policy decision point (PDP) evaluates them on a 10 s tick.
  - Identity (S_ID): a read-only binding audit.
  - Behaviour (S_B): a per-device autoencoder anomaly score.
  - Context (S_C): operating time and topic profile.
  - Fusion: the three scores are combined into a trust score T in [0, 100], which is mapped to FULL_ACCESS, RESTRICT or QUARANTINE.
- **Frozen operating point:** set before any formal data were collected and not changed afterwards:
  - α/β/γ = 0.2/0.5/0.3, λ = 0.1, τ_Q = 65, τ_R = 75;
  - N = 2 consecutive same-state windows before any request.

  The full record is in `reproducibility/frozen_operating_point.json`.
- **Runs:** 47 valid runs, collected on 12–14 November 2026:
  - **35 Shadow-Mode runs:** all ten devices, with proposed decisions logged and no policy changes. They cover benign operation, five behavioural anomaly types (rate, payload, burst, jitter, drop), silence (liveness), and withdrawn operating time (context).
  - **12 active runs on device02:** decisions are enforced through the broker and verified by read-back. Autoencoder-caused actions are automatic; credential-revocation (identity) and context actions go through operator review.

  One active run that stopped early was replaced under a protocol amendment fixed before aggregation; the replacement keeps its own run id (`exp-a14`).
- **Reserved TEST data:** held-out benign runs, scored once after the freeze (`data/reserved_test_scoring_copy.csv`).

## Contents

| Path | Contents |
| --- | --- |
| `data/` | 16 CSV files: headline metrics, per-device and per-anomaly summaries, every decision record (23,100 Shadow-Mode and 7,920 active), detection, context, identity and silence episodes, enforcement actions, Time-to-Contain and the run list. **Start with `data/DATA_DICTIONARY.md`.** |
| `analyses/01_rq3_sensitivity/` | One-factor-at-a-time sensitivity around the frozen point (14 configurations), the false-positive/recall trade-off over the effective anomaly threshold, and the article's sensitivity figure |
| `analyses/02_ablation/` | Ablation: identity-only, AE-only, liveness-only, identity + behaviour, identity + context, full AZTA |
| `analyses/03_decision_latency/` | Decision-latency decomposition (22,346 decisions) |
| `analyses/04_context_windows/` | The 135 context-violation windows and their states |
| `analyses/validation_checks.json` | The 12 checks that the replay reproduces every recorded state, the N = 2 confirmations and the frozen metrics exactly |
| `reproducibility/` | Frozen operating point, models and calibration constants per device, autoencoder hyperparameters and training outcomes, Python packages, host and Docker image digests, and SHA-256 digests of the model files |
| `models/` | The 573 frozen autoencoder files (architecture, weights, training history, selection records) |
| `SHA256SUMS.txt` | SHA-256 of every file in this dataset |

## How to read the data

- Timestamps are UTC nanoseconds since the Unix epoch. An empty cell means not applicable or not recorded.
- **Ground-truth labels per window:**
  - POSITIVE: at least half the window lies inside a commanded anomaly segment.
  - NEGATIVE: no overlap with any segment, and the window starts at least one window after the last segment ended.
  - TRANSITION: anything else; these windows are excluded from the metrics.
- Shadow-Mode states are proposals and were never applied.
- The sensitivity and ablation analyses are **counterfactual replays** of the recorded Shadow-Mode traces. Nothing was enforced, and **no parameter was selected from them**.
- Model file paths recorded in the CSVs begin with `results/engineering/`. That prefix corresponds to `models/` here, and `reproducibility/frozen_model_files_sha256.csv` lists both forms. Folder names such as `gate6b` or `p2` are development-stage labels.
- **Verifying integrity:** run `sha256sum -c SHA256SUMS.txt` (or the equivalent) inside this folder.

## Scope and limitations

- **A controlled simulation, not physical hardware.** Ten simulated devices ran on one workstation.
  - Containment is application-level MQTT enforcement through the broker. It is not network or IP isolation.
  - Time-to-Contain spans two clocks (host and PEP container), which differ by about 56 ppm.
- **Automatic enforcement is claimed for device02 only.** For devices 05, 07 and 08 the calibration is fragile: they are part of the detection results, but no automatic-enforcement claim is made for them.
- Devices 03–10 have no operations role, so RESTRICT changes no permission on them.
- N = 2 confirmation, the liveness rule and operator review are implementation extensions to the three-input trust equation. They are disclosed in the article.
- Weak or negative results are reported as measured. Censored, missed and failed episodes remain in the records.

## Not included

| Item | Reason |
| --- | --- |
| Raw broker and observer evidence (about 15 GB) | Size, and it contains broker infrastructure state. The derived records here were computed from it. |
| Implementation source code | Not part of this data release |
| Third-party public datasets used for the offline benchmarks (CICIoMT2024, N-BaIoT) | Their licences do not permit redistribution. Obtain them from the original providers. |
| Broker credentials, Dynamic Security state and internal project records | Security and privacy. The configuration records are summarised in `reproducibility/frozen_operating_point.json`, with the originals' SHA-256 digests. |

Further material may be requested from the corresponding author of the article.

## Licence

Creative Commons Attribution 4.0 International (CC BY 4.0); see `LICENSE.txt`. When using this dataset, please cite it using the citation shown on its repository record, together with the associated article.
