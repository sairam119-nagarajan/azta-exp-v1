# CAL5 — weak-device benign calibration protocol (stabilization requirement 3)

Declared 8 November 2026 (UTC), in the commit that adds this file and `configs/stabilization/cal5_partition_plan.json`, **before** any CAL5 run exists. A later change is a dated amendment at the end of this file, never an edit of an earlier section.

## 1. Purpose and boundary

The supervisor's direction plan (point 4) asks for more independent benign calibration evidence for Devices08 and 09 and for any device with unstable reconstruction-error thresholds. The aim is stable threshold behaviour across independent benign sessions. The sample count is an engineering target, not a publication threshold.

- **Models:** the deployed models are reused unchanged: the ten profiles of `configs/core_final/route_ae_primary_v1.json`, with the same feature definitions, masks, scalers and window widths. Nothing is trained, selected or tuned.
- **What CAL5 gives:** benign loss statistics only (`mu_L`, and `sigma_L` as the sample SD with denominator n − 1, journal eq. 10), plus their stability.
- **What CAL5 never gives:** detection evidence, FPR/FNR, or trust accuracy.
- **Data that are not opened:** reserved TEST (`g6c-d07`, `g5d3a-fx-g6b09`, `g5d3a-fx-g6b17`) is never opened. The consumed calibration runs (`g6c-d05`, `g6c-e01`, `g6c-f01`, `g6c-h01`, `g6c-h02`) are never re-scored.

## 2. Sessions

There are four whole ten-device benign runs, `g6c-s01` to `g6c-s04`, on the isolated engineering broker:

- the chain, profiles and observer are the same as for CAL2 (`g6c-e01`);
- each run has 900 eligible 10 s windows (2.5 h);
- each run is started by its own orchestrator invocation, with seeds derived from its own run id;
- the benign delivery conditions Q, N1 and N2 take 300 windows each, in a rotated order (partition plan);
- there are no declared reconnections and no stress segment, because CAL2 had neither.

Native non-overlapping windows expected per run: devices 01–05 and 10: 900; devices 06 and 07 (20 s): 450; device08 (90 s): 100; device09 (180 s): 50. Over the four sessions: device08 400 and device09 200. Both meet the 100–200 engineering target.

A session is usable only if:

- the orchestrator exits 0;
- every binding audit passes;
- the observer session is COMPLETE.

A failed run is renamed `-VOID-<reason>`, kept, and replaced by a substitute declared in an amendment. At least three usable sessions are required. Fewer than three makes requirement 3 BLOCKED, not passed.

Heavy host jobs (the full regression suite) can run during a session. When they do, they run at below-normal priority and their UTC start and end are logged in `docs/stabilization/HOST_ACTIVITY_LOG.md`.

## 3. Calibration rule (declared before data)

For every device and its deployed arm, on the score-ready native windows of each session:

- per-session `n`, `mu_L`, `sigma_L` (sample SD), loss quantiles, and the largest single-window share of the squared deviation;
- pooled over all usable sessions: `n_B`, `mu_L`, `sigma_L`;
- the loss thresholds implied by the unchanged trust parameters with S_ID = S_C = 100:
  - RESTRICT boundary: A > 10 ln 2 = 6.931, so `L_R = mu_L + 6.931 (sigma_L + 1e-6)`;
  - QUARANTINE boundary: A > 10 ln 2.5 = 9.163, so `L_Q = mu_L + 9.163 (sigma_L + 1e-6)`;
- leave-one-session-out (LOSO): for each held-out session k, `mu_L` and `sigma_L` are computed from the other sessions. The share of session k's benign windows above that `L_R` and above that `L_Q` is reported.

**Recalibration scope.** These devices take the pooled CAL5 constants in AZTA-EXP-v1:

- device05, whose calibration was unstable across sessions;
- devices 06 and 07, which were calibrated on a single session and documented as fragile;
- device08, which had 66 windows from one session;
- device09, which had 33 windows from one session.

Devices 01–04 and 10 keep their existing constants (CAL4, two sessions, n = 1,200 each, not fragile). Their CAL5 per-session statistics and LOSO results are reported as a stability check only, and nothing about them is changed on that basis.

**Classification per recalibrated device** (fixed now):

- **STABLE** requires all four of:
  1. at least 3 usable sessions;
  2. no single window carries more than 50 % of the pooled squared deviation (the existing FRAGILE rule);
  3. every per-session `sigma_L` is within a factor of 3 of the pooled `sigma_L`;
  4. the LOSO exceedance of `L_R` is at most 2 % of windows in every held-out session.
- **FRAGILE** means any of criteria 2–4 fails. The device keeps its constants but stays HUMAN_REVIEW_REQUIRED, and the failing criterion is reported.
- **BLOCKED** means fewer than 3 usable sessions.

**Authority:** no device's automatic-enforcement qualification changes in this campaign. The authority map keeps device02 as the only AUTO_ELIGIBLE device, and recalibration never relaxes a qualification rule. Qualifying further devices belongs to the separately authorized formal enforcement evaluation (direction plan point 9).

## 4. Outputs

The new calibration record is `configs/stabilization/cal5_calibration_record.json`. It is single-pass, with an exclusive marker created before the first CAL5 window is read, and has status `PROVISIONAL_UNAPPROVED`. The human-readable summary is `docs/final/AZTA_CALIBRATION_STABILITY.md`.

The derived EXP-v1 monitor-profile record changes only `mu_L`, `sigma_L`, `n_B` and `calibration_id` of the recalibrated arms, and carries a lineage pointer to the record above.

## Amendment 1 (8 November 2026, about 12:00 UTC, before any CAL5 window was read)

This is a clarification of section 3, made because the wording was ambiguous. It is not a change prompted by any data: no CAL5 window has been opened, and the single-use marker does not exist yet.

- "Keeps its constants" for a FRAGILE device means that it takes the pooled CAL5 constants like every recalibrated device. Four independent sessions are more benign evidence than the earlier single session. A FRAGILE device also stays HUMAN_REVIEW_REQUIRED, and the failing criterion is reported.
- A BLOCKED device (fewer than 3 usable sessions) keeps its earlier constants unchanged.
- The CAL5 constants enter AZTA-EXP-v1 through copies of the two constant-carrying records:
  - `configs/gate6c/core_monitor_profiles_provisional.json` for devices 06–09;
  - `configs/gate6c/p2_candidates_cal4.json`, arm `EA-C-PER+IM`, device05.
- In these copies only `mu_L`, `sigma_L`, `n_B` and `calibration_id` of the recalibrated device's deployed arm change, and a new route record pins the copies. The earlier records are never edited.
