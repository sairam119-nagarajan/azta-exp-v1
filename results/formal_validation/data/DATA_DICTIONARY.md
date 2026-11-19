# Data dictionary: final live-result datasets (AZTA-EXP-v1 formal validation)

All files come from the recorded formal evidence of the 47 VALID runs: 35 Shadow-Mode runs in batches S1 and S2, and 12 active device02 runs in batch A. They are UTF-8 CSV with a header row. Timestamps are UTC nanoseconds since the epoch. An empty cell means not applicable or not recorded.

## Headline and summaries (from the frozen aggregation, computed once on 14 November 2026)

| File | One row per | Key columns |
| --- | --- | --- |
| `headline_metrics.csv` | headline metric | `metric`, `value` (a fraction for rates; seconds or milliseconds where named), `numerator`, `denominator`, `population` |
| `per_device_summary.csv` | device | `trust_state_agreement` (Metric 1, behavioural windows); `decision_*` = decision-level confusion and rates (Metrics 2–3); `detector_flag_*` = A > 6.93 flag level; context window counts; PDP latency median and p95 (ms) |
| `per_kind_summary.csv` | anomaly type | episodes, episodes detected (decision level and flag level), median and p95 detection delay (s), window-level recall |
| `per_device_kind_summary.csv` | device × anomaly type | episodes, detected, median delay, window recall. A pair with no positive window (drop on devices 07–09) is absent here but counted in `per_kind_summary.csv` |
| `pdp_latency_summary.csv` | device (+ ALL) | Metric 5 (decision start minus window end, ms): n, min, median, p95, p99, max |
| `time_to_contain_episodes_device02.csv` | behavioural episode, active runs | `ttc_s_cross_clock` (onset on host UTC, verified containment on PEP UTC, about 56 ppm), `observation_delay_s`, `pdp_decision_ms`, `enforcement_ms`, `contained`, `censored` |
| `enforcement_success_per_run_device02.csv` | active run | requested, applied and verified, with broker read-back, NOOP, failed, success rate (Metric 6) |
| `context_episodes.csv` | context episode | detected, delay (s), first recommendation, whether any recommendation escalated to QUARANTINE, mode |
| `identity_episodes_device02.csv` | credential revocation | review opened, QUARANTINE verified, time to verified state (s) |
| `silence_episodes.csv` | silence episode | detected by the liveness rule, delay (s), recommendation |
| `reserved_test_scoring_copy.csv` | TEST run × device | copy of the single TEST scoring of 12 November (benign held-out data; not re-scored): score-ready windows, false flags, state counts |
| `runs.csv` | VALID run | batch, mode, component, scenario device, planned episodes, validity record and its SHA-256 |

## Per-window and per-episode records (for figures)

| File | One row per | Key columns |
| --- | --- | --- |
| `decisions_shadow.csv` | decision record of a Shadow-Mode run (23,100) | `label` (frozen oracle: POSITIVE, NEGATIVE, TRANSITION or NOT_SCORE_READY); `anomaly` (type covering a positive window); `context` (window of the device whose operating time was withdrawn, ending after the cut); `in_frozen_rows` (counted by the frozen metrics); `loss`; `a` (anomaly magnitude A); `mu_L`, `sigma_L`; `s_id`, `s_b`, `s_c`, `trust` (T); `proposed_state`; `recommendation`; `origin`; `decision_source`; `supplementary` (liveness recommendation); `conf_state` and `conf_count` (recorded N = 2 confirmation); `operating_time` and `topic_profile` (context conformities); `latency_ms` (Metric 5 basis) |
| `decisions_active_device02_runs.csv` | decision record of an active run (7,920) | same columns as above |
| `detection_episodes_shadow.csv` | behavioural episode of a Shadow-Mode run (225) | positive windows, detected (flag and decision level), delay (s), first recommended state; regenerated with the frozen episode-detection function, and the counts equal the consolidated results |

## Notes

- **Window labels:** the definitions of the frozen measurement code. A window is POSITIVE when at least half of it lies inside an executed behavioural segment. It is NEGATIVE when it overlaps no segment and starts at least one window after the device's last segment ended. Otherwise it is TRANSITION (excluded).
- **Trust states:** FULL_ACCESS, RESTRICT, QUARANTINE (journal equation 12; τ_Q 65, τ_R 75). Shadow-Mode states are proposals and were never applied.
- **Where the other outputs are:** the counterfactual sensitivity and ablation outputs are in `analyses/01_rq3_sensitivity` and `analyses/02_ablation`.
- **Paths in `runs.csv`:** `validity_record` gives the path of each active run's validity record in the original project; the records themselves are retained privately and `validity_record_sha256` identifies them.
