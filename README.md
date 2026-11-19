# AZTA-EXP-v1: Adaptive Zero Trust Automation for MQTT-based IoT (frozen release)

This repository contains the frozen experimental release **AZTA-EXP-v1** of Adaptive Zero Trust Automation (AZTA), together with the results of its formal experimental validation. It accompanies a journal article on AZTA.

AZTA continuously re-evaluates every connected IoT device and adapts its MQTT permissions:
- **Policy enforcement point (PEP):** an Eclipse Mosquitto broker with the Dynamic Security plugin.
- **Policy decision point (PDP):** fuses three scores into a trust score T in [0, 100]:
  - identity, S_ID (a read-only binding audit, used as a hard gate);
  - behaviour, S_B (per-device autoencoder anomaly scores on broker-delivered telemetry);
  - context, S_C (operating time and topic profile).
- **States:**
  - T ≥ τ_R: FULL_ACCESS
  - τ_Q ≤ T < τ_R: RESTRICT (operations role removed, telemetry kept)
  - T < τ_Q: QUARANTINE (client disabled, session ended, reconnection rejected)
- **Shadow Mode:** computes and logs the same decisions without changing any policy.

## What "frozen" means here

The release was frozen on 10 November 2026, before any formal data were collected:
- **Freeze manifest:** `configs/exp_v1/AZTA-EXP-v1_freeze_manifest.json` pins the SHA-256 of every source and configuration file the experiment used (344 files) and of the 573 trained model files.
- **Formal-addendum manifest:** `configs/formal/AZTA-EXP-v1_formal_addendum_manifest.json` pins the measurement scripts, the experiment matrix and the session plans (177 files). It was fixed before the reserved test data were opened.
- **Operating point:** α/β/γ = 0.2/0.5/0.3, λ = 0.1, τ_Q = 65, τ_R = 75, with N = 2 consecutive same-state windows before any request.

To check it:

```
git clone https://github.com/sairam119-nagarajan/azta-exp-v1.git
cd azta-exp-v1
python verify_freeze.py
```

On Windows, enable long paths before cloning (`git config --global core.longpaths true`), because one pinned model file has a long name.

The script recomputes every digest and reports what is byte-identical to the frozen release. Files that were changed for publication are listed in `REDACTIONS.md`:
- verbatim approval correspondence, withheld;
- a development-tool name in author fields, generalized.

Each listed file shows its original digest. Nothing else differs from the frozen release.

## Repository layout

| Path | Contents |
| --- | --- |
| `devices/` | Simulated IoT devices (Python/Paho MQTT publishers) |
| `pep/mosquitto/` | Broker configuration (credentials are not included) |
| `observation/` | Observer that builds per-device telemetry windows |
| `preprocessing/`, `model/`, `calibration/` | Feature scaling, autoencoders, benign calibration (μ_L and sample σ_L) |
| `trust/` | Trust decision engine (equations for S_B, S_C, T and the state mapping) |
| `family/`, `hybrid/` | Per-device behaviour profiles and routes |
| `core_runtime/`, `fleet/`, `engineering/` | Runtime PDP (`python -m core_runtime`), PEP service, approvals and safety guards |
| `enforcement/` | Dynamic Security PEP (four commands only) and the authority gate |
| `shadow_feed/`, `shadow_live/` | Shadow Mode feed and live session adapter |
| `decision_pipeline/`, `experiments/` | Collection plans and campaign tooling |
| `rehearsal_tools/` | Operator tools, the frozen measurement code (`exp_metrics.py`, `stb_decision_trace.py`) and the aggregation (`exp_aggregate.py`) |
| `configs/` | Frozen configuration, model registry and routes, experiment matrix, per-session plans |
| `docs/` | Formal experiment protocol and its addenda; supervised-session and calibration protocols |
| `results/engineering/` | The 573 frozen model files, at the paths the configuration references |
| `results/formal_validation/` | Results of the formal validation (47 runs): every decision record, episodes, metrics, sensitivity and ablation analyses, reproducibility records. Start with its `README.md` and `data/DATA_DICTIONARY.md`. |

## Results

`results/formal_validation/` holds the outcomes of the 47 valid formal runs:
- 35 Shadow-Mode runs on all ten devices;
- 12 active enforcement runs on device02.

The headline numbers are in `data/headline_metrics.csv`, and per-device results are in `data/per_device_summary.csv`. The sensitivity and ablation analyses are counterfactual replays of the recorded traces: nothing was enforced, and no parameter was selected from them.

## Running the system

The environment that produced the results:
- Windows 11, Docker 29.8.1;
- the `eclipse-mosquitto:2.1.2-alpine` image;
- Python 3.12.10 with the packages pinned in `requirements.txt` (`results/formal_validation/reproducibility/environment.json`).

A live run needs a provisioned broker. You must create the Dynamic Security identities and their password files under `pep/mosquitto/secrets/` (never committed) and start the Compose stack (`compose.yaml` with the engineering and pilot overlays). This repository records the exact frozen system and its results. It is not a one-command reproduction of the live campaign.

## Scope and limitations

- **A controlled simulation:** ten simulated devices on a single host. Containment is application-level MQTT enforcement, not network isolation.
- **Automatic enforcement scope:** claimed for device02 only. Other devices and causes go to operator review. Devices 05, 07 and 08 have fragile calibration and carry no automatic-enforcement claim.
- **Extensions to the trust equation:** N = 2 confirmation, the liveness rule and operator review. They are disclosed in the article.
- **Roles in the project records:**
  - the *project owner* ran the experiments;
  - the *supervisor* reviewed and approved the freeze and the protocol;
  - the *Main Controller* is the project's approval authority for engineering changes.

## Not included

- the raw broker and observer evidence (about 15 GB);
- broker credentials and Dynamic Security state;
- the third-party public datasets used for the offline benchmarks (CICIoMT2024, N-BaIoT), whose licences do not permit redistribution;
- the development history before the freeze.

## Licence

Code: MIT (`LICENSE`). Results: CC BY 4.0 (`results/formal_validation/LICENSE.txt`). Please cite the archived release (DOI on its Zenodo record) and the associated article.
