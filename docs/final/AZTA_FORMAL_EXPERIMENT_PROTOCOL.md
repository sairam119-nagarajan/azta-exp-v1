# AZTA formal experimental validation protocol (AZTA-EXP-v1)

**Written for:** the project owner, who runs the Experimental Validation work, and the supervisor, who reviews it.

**Status: FROZEN RELEASE BOUND, campaign not started.** This protocol is bound to the frozen release AZTA-EXP-v1:
- manifest `configs/exp_v1/AZTA-EXP-v1_freeze_manifest.json`, sha256 `221884e06340cc1a610791ea179c7b522ce8b6633a8442b58d123f115d3b5516`;
- source commit `42d739b1ed3acae2dbcdac3a0d55b3a8d0120c5b`;
- `verify`: 0 problems on 10 November 2026;
- the supervised verification was `stb-l05`, PASSED;
- the supervisor approved formal experimental validation on 11 November 2026;
- **addendum 1** (`docs/final/AZTA_FORMAL_PROTOCOL_ADDENDUM_1.md`) fixes the experiment matrix, the measurement scripts and the run rules, pinned in `configs/formal/AZTA-EXP-v1_formal_addendum_manifest.json` before the reserved TEST runs are opened. Where this protocol and addendum 1 differ, addendum 1 applies.
 It becomes executable only when the owner gives the separate authorization in `docs/final/approval_requests/FORMAL_TEST_AUTHORIZATION.md`. Nothing here has been run, and the reserved TEST data have not been opened.

## 1. Fixed before any formal data

| Item | Value |
| --- | --- |
| Release | AZTA-EXP-v1: the freeze manifest's source commit, every pinned file and model digest, and the operating point. `stb_freeze_exp_v1.py verify` must report 0 problems before each campaign day, and again before the final report. |
| Trust parameters | alpha 0.2, beta 0.5, gamma 0.3, lambda 0.1, epsilon 1e-6, **tau_Q 65**, tau_R 75; context weights: operating_time 0.9, topic_profile 0.1; N = 2; recovery rule POST_RESTORE_ONE_WINDOW_V1. These are development-stage choices (supervisor, 10 Nov 2026) and are disclosed as such. **No parameter changes after the reserved TEST data are opened.** |
| Population | Exactly ten simulated devices (device01–device10). |
| Automatic enforcement | **device02 only**, for AE causes only. All other devices and every context, mixed, liveness and identity cause go through operator review. The automatic-enforcement claim is scoped to device02. |
| Calibration limits | device05, 07 and 08 are FRAGILE: they are in the detection evaluation, with no automatic-enforcement claim. device03's elevated benign flag rate is reported as detector FPR and false-enforcement rate separately. |
| Windows | 10 s (devices 01–05, 10), 20 s (06, 07), 90 s (08), 180 s (09). The longer windows of devices 08 and 09 are reported with their detection delay and Time-to-Contain. |
| Measurement code | `rehearsal_tools/exp_metrics.py` and `rehearsal_tools/stb_decision_trace.py`, frozen in the manifest. |

## 2. Evidence partitions (never mixed)

| Partition | Runs | Use |
| --- | --- | --- |
| Development | every `stb-*`, `core-*` and `g6c-*` development or calibration run, including CAL5 (consumed) | Already used to build and select. **Never reported as an experimental result.** |
| Reserved TEST (offline) | `g6c-d07`, `g5d3a-fx-g6b09`, `g5d3a-fx-g6b17` | Opened **once**, after the freeze and the owner's authorization, and scored by the frozen release. Nothing is tuned on them. |
| Formal live runs | new run ids `exp-*`, collected after the freeze on the isolated pilot broker | Each live policy-changing session needs its own written owner authorization and the owner at the console. |

## 3. Scenarios

| Class | Ground truth |
| --- | --- |
| Benign | All ten devices at their normal workload law. Every window is NEGATIVE. |
| Behavioural anomalies | The frozen anomaly kinds `rate`, `payload`, `burst`, `jitter` and `drop`, at the frozen parameter ranges, per device. They are commanded through the workload control channel, so onset and stop are logged independently of AZTA. |
| Liveness | `silence` (connected, publishing nothing). |
| Context | A declared operating-time withdrawal. The expected response is RESTRICT, reviewed. |
| Identity | A declared revocation of the device's credential. The expected response is the hard gate (T = 0, QUARANTINE), reviewed. Because the revocation is itself a broker policy change, identity episodes run only in the supervised device02 sessions (addendum 1). |

**Repetitions:** at least **five** independent repetitions per scenario class, each with a fresh run id and seeds, as the reviewed plan requires. For the behavioural anomalies this is five per anomaly type **per device** (250 detection episodes), and five per type on device02 for enforcement (addendum 1). Incomplete, censored and failed runs stay in the record.

## 4. The six metrics (definitions fixed in `exp_metrics.py`)

| Metric | Unit and definition | Denominator and reporting |
| --- | --- | --- |
| 1 Trust-state accuracy | The share of windows whose recorded state (the engine's proposal under tau_Q 65 / tau_R 75) agrees with the oracle: NEGATIVE → FULL_ACCESS, POSITIVE → not FULL_ACCESS. There is **no continuous ground-truth trust**. | POSITIVE + NEGATIVE windows. TRANSITION and not-score-ready windows are excluded and counted; the T distribution is given per class. |
| 2 FPR, 3 FNR | Reported at three separate levels: (a) detector flag, A > 6.931; (b) AE-caused non-FULL decision; (c) verified enforcement per episode. | TP, FP, TN, FN and support are always shown. An undefined denominator stays undefined. Detection false positives are never merged with false enforcement. |
| 4 Time-to-Contain | From the logged anomaly onset (workload control channel) to the verified containment (broker read-back). | Per episode, with the containment rate. Misses are **censored**, not dropped. Decomposed into observation wait, PDP decision, operator authorization and broker enforcement. The container-versus-host clock difference (about 56 ppm) is stated. |
| 5 PDP decision latency | The decision instant minus the end of the window, on the host clock. | Median, p95 and max per device. It excludes observation, authorization and enforcement time. |
| 6 Enforcement success | Requests that asked for a change, counted against the broker read-back of the same request id (APPLIED_VERIFIED). NOOPs are reported apart. | Final states are probed. A submitted request alone never counts as a success. |

## 5. Reporting rules

- Weak or negative results are reported as measured.
- Per-device results are given for all ten devices, with the fragile-calibration and long-window qualifications beside them.
- Application-level MQTT quarantine is not network or IP isolation.
- Stabilization sessions are engineering verification, not results.

## 6. Order of work after authorization

1. Verify the freeze (0 problems).
2. Open the reserved TEST runs once, score them with the frozen release, and record their digests.
3. Run the formal live campaign, each policy-changing session under its own approval.
4. Run the `exp_metrics.py` evaluation.
5. Produce the report.
