# STABILIZATION_LIVE_1 (`stb-l01`): supervised live verification protocol

Declared 8 November 2026 (UTC), in the commit that adds this file, **before** the session exists. Any change is a dated amendment at the end, never an edit of an earlier section. The checks below are evaluated by `rehearsal_tools/stb_live_verdict.py`. If a check fails, it stays failed and on record: neither the check nor the data is adjusted afterwards.

Scope: stabilization requirements 1 (liveness), 2 (attribution and authorization), 4 (post-RESTORE recovery) and the live part of the final integration checks. This is engineering verification, not a formal experiment. Nothing measured here is a Time-to-Contain result, an FPR/FNR, or an enforcement-success rate.

## 1. Environment and scope

| Item | Value |
| --- | --- |
| Broker | The isolated pilot broker `azta-pilot-broker-1` (project `azta-pilot`, volume `azta-pilot_mosquitto_data`, no host port). Never the journal/research broker. |
| Devices | All ten simulated devices publish. Only **device01** and **device02** are in the written authority scope. |
| Permitted actions | device01: RESTRICT, QUARANTINE, RESTORE (automatic = false). device02: RESTRICT, QUARANTINE, RESTORE (automatic = true, for AE-caused actions only, by the authority rule). Devices 03–10: none. |
| Runtime | `core_runtime run --mode active-authorized`, with the post-stabilization PEP (attribution, AE-only automatic authority, recovery rule POST_RESTORE_ONE_WINDOW_V1) and unchanged trust parameters (alpha 0.2, beta 0.5, gamma 0.3, lambda 0.1, tau_Q 70, tau_R 75, N = 2). |
| Duration | 66 eligible 10 s windows (72 planned, about 720 s of coverage). `max_duration_s` 800, `clock_session_s` 880, review TTL 300 s. |
| Approval validity | 240 minutes from the owner's written answer. |
| Clock | The launcher measures the container-versus-host clock against criteria saved first: 880 s at a 100 ms budget. It refuses to start on a FAIL. |
| Baseline policy | The binding-audit policy digest equals `3e6c25881bc1846036fa27445001f0a69f39e6dd85bc5e137048a78c03179c7b` before and after the session. |
| Operator | The owner, signed in to the local operator console (loopback). The owner makes every approval and every RESTORE click; no script writes an intent. |

## 2. Scenario (driver `rehearsal_tools/stb_live_operator.py`)

1. **device02, AE QUARANTINE, then RESTORE (R4 cases 1–2).** A payload anomaly (1,024 B) produces an automatic QUARANTINE. The owner restores; the first post-RESTORE window is the recovery window; the device then reports normally for 40 s.
2. **device02, persistent anomaly across a RESTORE (R4 case 3).** The payload anomaly produces an automatic QUARANTINE. The owner restores **while the anomaly continues**. One window is held, then the device is re-quarantined automatically. The anomaly stops, and the owner restores.
3. **device01, complete silence (R1).** The device stays connected and authenticated but publishes nothing (traffic generator kind `silence`). The liveness rule (bound 40 s) opens a review with origin SUPPLEMENTARY_TIMING. The owner approves, RESTRICT is verified, and the silence stops. The device is left RESTRICTED and probed after the session.
4. **device02, operating time withdrawn (R2).** About 540 s into coverage, the declared withdrawal produces a context-caused RESTRICT. It must arrive as a review, never automatically. The owner approves, and the device is left RESTRICTED and probed after the session.
5. **Devices 03–10** stay benign for the whole session (the live negative control). Any review on device01/02 that the scenario did not plan is rejected and recorded as a false recommendation.

After the session the owner names the RESTOREs (device01 and device02), and `stb_live_session.py finish` applies and verifies them.

## 3. Pass checks (all must hold)

| Id | Check |
| --- | --- |
| L1 | A review for device01 with origin `SUPPLEMENTARY_TIMING` and decision source `LIVENESS` opens during the silence, after a recorded silence longer than the 40 s bound. |
| L2 | No automatic action on device01: its RESTRICT follows an owner APPROVE_ONCE (`REVIEW_RESOLVED` EXECUTED, the owner's operator reference). |
| L3 | The device01 RESTRICT outcome is `APPLIED_VERIFIED`. The broker read-back shows the operations role removed, the telemetry role kept, and the client not disabled. |
| L4 | The post-session restricted probe of device01: operations publish denied, telemetry publish allowed. |
| L5 | Liveness negative control: no liveness recommendation for devices 03–10 or for device02 in the whole session, and none for device01 outside its silence segment (plus one bound). |
| A1 | device02's AE QUARANTINEs are applied without a review, and their PEP record says decision source `AE_BEHAVIOR`. |
| R1 | Every verified operator RESTORE of a contained device opens a recovery window, and the window is closed by that device's next score-ready AE window. |
| R2 | After the case-1 RESTORE, device02 is not re-contained during the recovery window or the 40 s of normal reporting that follow. |
| R3 | In case 3, the first post-RESTORE window is held (`POST_RESTORE_RECOVERY_WINDOW`), and device02 is then re-quarantined automatically. |
| C1 | device02's context RESTRICT arrives as a review with origin `CONTEXT_POLICY`. No RESTRICT outcome precedes the owner's approval, and after approval it is `APPLIED_VERIFIED`, with the operations publish denied in the post-session probe. |
| G1 | `stb_decision_trace.py` links every non-RESTORE outcome to its decision record and authorization (no unlinked action). The cause recorded by the PEP equals the recomputed cause for every action. |
| G2 | No recommendation in the ledger is labelled `AE_PRIMARY` when its recomputed cause is not AE. |
| S1 | No PEP outcome on devices 03–10, and their PRE and POST probes are unchanged. |
| F1 | After `finish`: all ten devices are at FULL_ACCESS by broker read-back, the final binding-audit digest equals the baseline, the stack is down without `-v`, the volume is kept, and the protected fingerprints are unchanged. |

**Stop conditions** (from the driver): a PEP outcome outside the scope; a failed or unverified outcome; or the owner's console page not seen. Any of these stops every anomaly and tells the owner to press Stop new actions. A restoration failure stops all further mutation (`restoration_failed_STOP`) and keeps the stack up for diagnosis.

## 4. Not claimed

- The session demonstrates the paths once. It does not estimate rates.
- The onset-to-verified times are engineering observations, not formal Time-to-Contain measurements.
- The RESTRICT state is meaningful only on devices 01 and 02, the only devices with an operations entitlement.

## Amendment 1 (9 November 2026, before `stb-l02` exists): the retest STABILIZATION_LIVE_2

**Why.** `stb-l01` (STABILIZATION_LIVE_1, 8 November 2026) FAILED: 12 of 14 checks passed; **L5 and C1 failed**. At 21:36:14 UTC the workload container crashed with `PermissionError` while renaming `control/status.json` (`engineering/fleet_shards.py`). The rename went through the Windows bind mount while a host reader had the file open. That result stands, on record and unchanged (`results/engineering/stabilization/stb-l01_verdict.json`).

**What changes.**

1. **The workload's status writers.** They retry only the rename, 20 × 50 ms, the pattern of `engineering/handoff.py` (`engineering/attack_control.replace_status`). A persistent denial still fails the run. Neither the trust, AE, PDP or PEP code nor any parameter changes.
2. **The run id.** The retest is `stb-l02` under its own request, **STABILIZATION_LIVE_2**, with its own plan `configs/collection_plans/core_final_stb_l02.json` and session file `configs/stabilization/sessions/stb-l02.json`.

**What does not change.** Sections 1–4 apply unchanged to `stb-l02`, with `stb-l02` in place of `stb-l01`:

- the environment and scope;
- the scenario and its timings, including the device02 operating-time withdrawal at about 545 s;
- **all 14 pass checks**;
- the stop conditions.

All 14 checks must hold in `stb-l02` itself; results from `stb-l01` are not carried over. The verdict is computed by `stb_live_verdict.py --run stb-l02`.

## Amendment 2 (9 November 2026, before `stb-s02` and `stb-l03` exist): corrections after `stb-l02`, and STABILIZATION_LIVE_3

**Why.** `stb-l02` (STABILIZATION_LIVE_2) FAILED with 12 of 14 checks; **L5 and C1 failed**. That verdict stands, on record and unchanged (`results/engineering/stabilization/stb-l02_verdict.json`), and so does the `stb-l01` verdict. Neither is recomputed in place.

**Findings.**

1. **L5.** The `silence` anomaly emptied device01's schedule. Its per-device workload process then ended at once, because the publish loop stopped when nothing was due unless a device was contained (`engineering/interactive_workload.py`). device01 sent 50/50 messages and stopped. The driver's later commands went unanswered (`NO_OUTCOME`). The silence never got a recorded end, so the verdict counted all 24 device01 liveness records as stray. `stb-l01` shows the same missing stop event.
2. **C1.** At 14:22:20 UTC an operator RESTORE of device02 was submitted while device02 was already at FULL_ACCESS (`NOOP_ALREADY_IN_STATE`). `enforcement/authority.py` supersedes every review still pending for the device on **any** RESTORE, and records the reason `RESTORE_CHANGED_THE_GENERATION` even when nothing changed. So the declared context review was cancelled. A later context review was approved and verified, but the v1 verdict looked only at the first review. `stb-l01` also contains a no-op RESTORE of device02.
   - **Classification:** a workflow defect at the operator interface, together with an inaccurate reason label in the PEP. It is not an authorization bypass: a superseded review can only cause an action NOT to happen, and the next window raised the review again.
   - **The PEP is not changed** (no production authority change without a controller decision). It is reported for review: should a no-op RESTORE supersede pending reviews, and should the reason distinguish it?
   - The extra click followed a relay failure: the assistant's `tail -F` relay of the owner guide delivered nothing under Git Bash on Windows, so two instructions reached the owner late.

**Corrections.** No trust, autoencoder, PDP or PEP code and no parameter changes.

1. **Workload** (`engineering/interactive_workload.py`). While an anomaly is active and nothing is due (a silence), the loop keeps the MQTT connection serviced and keeps reading commands until the planned end. Its STOP is then applied and the benign schedule resumes. Each `COMMAND_APPLIED` event and the status file record the publisher's live MQTT connection state (`mqtt_connected`).
2. **Router** (`engineering/fleet_shards.py`). A command for a shard that has already ended is rejected (`SHARD_ENDED`) instead of being left unanswered.
3. **Console** (`core_runtime/console/server.py`, `static/app.js`). A RESTORE of a device with pending reviews is refused (`RESTORE_WOULD_CANCEL_PENDING_REVIEWS`) unless the operator acknowledges exactly the pending review ids it will cancel; the page asks before re-sending.
4. **Driver** (`rehearsal_tools/stb_live_operator.py`).
   - Every owner instruction is numbered and names the action, device, expected cause, scenario step and that it is inside the approved scope; review instructions name the review id.
   - Each is closed by `DONE [#n]` (verified at the broker) or `CANCELLED [#n]` (do NOT perform it any more).
   - The silence is ONE bounded segment of at most 450 s (150 s for the liveness review plus the 300 s review TTL), never renewed by stop and start: a renewal could let a message out between the two commands.
5. **Relay** (`rehearsal_tools/stb_guide_relay.py`). Byte-position polling of the owner guide, every complete line once and in order; a persistently unreadable file is reported.
6. **Verdict** (`rehearsal_tools/stb_live_verdict.py --rules v2`). The 14 checks of section 3 and their thresholds are unchanged. Two things are added:
   - **C1 is evaluated on the causal chain of the DECLARED review:** the first device02 CONTEXT_POLICY review opened at or after the declared time cut. Its EXECUTED approval with the owner's reference names the request id; the outcome of that request must be APPLIED_VERIFIED; the broker read-back of that request must show the operations role removed, telemetry kept and the client not disabled; the post-session probe must show operations denied. No device02 RESTRICT may come before the approval. A later review never stands in for a superseded, expired or rejected declared review.
   - **A scenario-integrity block I1–I6 is required for an overall pass:**

     | Id | Check |
     | --- | --- |
     | I1 | Exactly one device01 silence start and one stop are applied. |
     | I2 | The MQTT connection is recorded live at both. |
     | I3 | No device01 containment, and no rejected or unanswered device01 command. |
     | I4 | Nothing is published inside the silence, and publishing resumes after it. |
     | I5 | The workload ends COMPLETE. |
     | I6 | Every instruction is closed, and every operator RESTORE happened while a RESTORE instruction for that device was open. |

   v2 adds conditions only. Run with `--rules v1`, it reproduces the recorded stb-l02 checks exactly. Run with v2, it also fails stb-l01 and stb-l02, with the reasons above.

**Rehearsal `stb-s02`** (STABILIZATION_SHADOW_2: shadow mode on the pilot broker, no policy change, authorized by the owner's 9 November instruction, section 3). This is the same session as `stb-s01`, except that the scripted operator runs ONE `silence` on device01 (settle 60 s, duration 115 s) in place of the device02 payload anomaly. A host stress reader and the guide relay run alongside. It passes only if every check of `rehearsal_tools/stb_rehearsal_verdict.py`, fixed here, holds:

| Ids | Check |
| --- | --- |
| W1, W2, O1, A1, P1, R1, T1, X1 | As in stb-s01. |
| I1–I5 | As above, on live records. |
| LV1 | A device01 liveness recommendation later than the silence start plus 40 s, and not after the stop plus 40 s. |
| LV2 | The L5 rule on live records. |
| LV3 | device01 has SCORE_READY windows again after the stop plus 40 s. |
| G1 | The relay delivered every operator-log line once and in order. |

C1 and the owner sequence cannot be exercised without reviews, so they are proved offline:
- `tests/test_stb_rehearsal_replay.py` runs the real driver against a simulated PEP that writes records in the PEP's schema, then runs the v2 verdict on them. The intended sequence must pass, and the stb-l02 sequence (an extra RESTORE superseding the pending context review) must fail C1 and I6.
- `tests/test_stb_live_verdict_v2.py` covers each broken link.

**STABILIZATION_LIVE_3 (`stb-l03`).** Sections 1–4 apply unchanged, with `stb-l03` in place of `stb-l01`: the scope, the scenario and timings, all 14 checks and the stop conditions. It is judged by `stb_live_verdict.py --run stb-l03 --rules v2`: all 14 checks and I1–I6 must hold. It is requested only after `stb-s02`, the replay and the regression have passed.

## Amendment 3 (9 November 2026, after `stb-l03`, before any later session exists)

**`stb-l03` (STABILIZATION_LIVE_3) FAILED** under rules v2: checks A1 and C1, and integrity I3, I5 and I6. **L1–L5 all passed live.** The verdict stands, on record and unchanged (`results/engineering/stabilization/stb-l03_verdict.json`).

**Scientific finding (not a tooling defect; reported, nothing changed).** With the operating time withdrawn, S_C = 10 and T = 23 + 50·exp(−0.1·A). Benign autoencoder noise above A ≈ 0.62 in two consecutive windows drops T below τ_Q = 70.
- In `stb-l03`, windows 60–62 had A = 2.55, 1.45 and 0.86 with no anomaly running.
- The PEP superseded the declared context RESTRICT review (`A_MORE_RESTRICTIVE_RECOMMENDATION_ARRIVED`) with a MIXED (AE + context) QUARANTINE review. The owner approved it, and device02 ended quarantined.
- This explains C1, I5 (the workload ended with device02 contained) and I6 (#5 waited for a RESTRICT that never came).

The parameter decision is set out in `docs/final/AZTA_CONTEXT_ESCALATION_DECISION.md`.

**Tooling corrections (only for a later session; rules `v3`).** Each adds or makes precise a condition; none relaxes a section-3 threshold.

1. **A1.** Each device02 QUARANTINE is judged by its recomputed cause. AE-caused ones must be automatic; every other cause must have been reviewed, never automatic; and at least one must be AE-caused. Under v2, a correctly reviewed MIXED quarantine was miscounted as a failed AE quarantine.
2. **I3.** A device01 disconnection is exempt only when the device resumes within 2 s and a verified device01 RESTRICT outcome lies within 2 s of it. That is the broker closing the client's connection when its role changes (Dynamic Security, 59 ms after `removeClientRole` in `stb-l03`, resumed 8 ms later). Any other containment inside the silence still fails.
3. **Driver.**
   - When the instructed context review is SUPERSEDED, EXPIRED or REJECTED, its instruction is CANCELLED at once, and any new device02 review becomes an unplanned REJECT instruction.
   - Unplanned-review instructions are closed (DONE) when their review is resolved.
   - Any instruction still open at the session end is CANCELLED.
4. **Verdicts stand.** v2 reproduces the recorded `stb-l03` checks exactly. v3 on `stb-l03` still fails C1, I5 and I6, the consequences of the finding; on `stb-l02` it still fails as recorded.

A later live session needs a new approval request and a new run id. It is judged by `stb_live_verdict.py --rules v3`, with the 14 checks of section 3 unchanged.

## Amendment 4 (10 November 2026, before `stb-l04` exists): STABILIZATION_LIVE_4, the supervisor-directed AZTA-EXP-v1 verification

**Basis.** The supervisor's written response (conditional GO) adopted Option B: τ_Q = 65, τ_R = 75 kept. He asked for the full regression and **one supervised live context test**: a benign context violation must result in RESTRICT, and a strong behavioural anomaly must still result in QUARANTINE. Then the freeze follows. The owner authorized one bounded session for this on the isolated pilot broker, device02 only, on 10 November 2026. Records: `configs/exp_v1/trust_parameters_decision_exp_v1.json` and `configs/exp_v1/trust_config_exp_v1.json`; the runtime resolves the latter (`core_runtime/cli.py`).

**Environment.** As section 1, with these differences:

| Item | Value |
| --- | --- |
| Run id | `stb-l04` (request STABILIZATION_LIVE_4). A fresh id; no earlier run is reused. |
| Scope | **device02 only**: RESTRICT, QUARANTINE, RESTORE; automatic = true for AE-caused actions only, by the unchanged authority rule. device01 and devices 03–10: none. |
| Runtime | `core_runtime run --mode active-authorized` with the EXP-v1 trust configuration: alpha 0.2, beta 0.5, gamma 0.3, lambda 0.1, **tau_Q 65**, tau_R 75, N = 2; route, registry, models, calibration constants and authority map unchanged. |
| Timing | Plan `configs/collection_plans/core_final_stb_l04.json` (66 eligible 10 s windows, 72 planned). `max_duration_s` 800, `clock_session_s` 880, review TTL 300 s. Declared operating-time withdrawal of device02 at **400 s** into coverage. |
| Approval validity | 720 minutes from the recorded owner answer. |

**Scenario** (driver `ExpV1VerificationScenario` in `rehearsal_tools/stb_live_operator.py`):
1. **B, strong behavioural anomaly.** About 45 s into coverage, device02 runs the payload anomaly (1,024 B) until a QUARANTINE is verified (at most 60 s). By the authority rule this AE-caused QUARANTINE is automatic after N = 2. The anomaly stops. **Owner instruction #1: RESTORE device02.** The first post-RESTORE window is the recovery window, then 40 s of healthy reporting follow.
2. **A, benign context violation.** At 400 s the operating time is withdrawn (S_C = 10, behaviour benign). A context-caused RESTRICT must arrive as a review. **Owner instruction #2: APPROVE ONCE that review.** RESTRICT is verified by read-back. device02 then keeps publishing benignly while RESTRICTED until the session ends; this is the no-escalation observation. It is probed after the session.
3. device01 and devices 03–10 stay benign throughout. Any review the scenario did not plan becomes a numbered **REJECT** instruction. That includes an escalation of the RESTRICTED device02; it is recorded as a false recommendation, and C2 then fails.
4. After the session, `stb_live_session.py --session stb-l04 finish --restore device02` restores device02 under the owner's written authorization ("safely restore the isolated broker"), runs the POST probes and the final binding audit, and brings the stack down without `-v`.

**Pass checks: rules `v4`** (`stb_live_verdict.py --run stb-l04 --rules v4`). All must hold. A check that cannot be evaluated is false.

| Id | Check |
| --- | --- |
| P1 | Every recommendation carries the EXP-v1 configuration digest, and every evaluated decision records tau_Q 65 and tau_R 75. |
| B1 | At least one device02 QUARANTINE whose recomputed cause is AE_BEHAVIOR, applied automatically with T < 65. Every AE-caused device02 QUARANTINE is automatic; any other cause is reviewed. |
| B2 | That QUARANTINE was confirmed by N = 2: the immediately preceding device02 window is the CONFIRMING record (1 of 2). |
| B3 | The broker read-back of that request shows the QUARANTINE state with the client disabled. |
| B4 | device02's own client records its connection contained within 5 s of the verified QUARANTINE, and it resumes only after the owner's verified RESTORE. This is the in-session MQTT-level confirmation; no second client with device02's identity is run during the session. |
| B5 | The owner's RESTORE is verified; a recovery window opens and closes after it; device02 is not re-contained in the 40 s that follow. |
| C1 | The amendment 2 causal chain for the declared context review, unchanged: the owner's EXECUTED approval, the outcome of that request APPLIED_VERIFIED, the broker read-back (operations removed, telemetry kept, not disabled), no RESTRICT before the approval, and the post-session restricted probe (operations denied, telemetry allowed). |
| C2 | The declared review's decision is CONTEXT-caused, proposes RESTRICT, and records S_C < 100 and tau_Q 65. After the time cut device02 gets **no** QUARANTINE review, **no** QUARANTINE outcome and no automatic action. |
| G1, G2 | As in section 3. |
| L0 | No liveness recommendation on any device. No silence is scripted. |
| S1 | No PEP outcome on any device other than device02, and devices 01 and 03–10 probe identically before and after. |
| F1 | As in section 3. |
| I5 | The workload ends COMPLETE. |
| I6 | Every owner instruction is closed (DONE or CANCELLED), and every operator RESTORE happened while a RESTORE instruction for that device was open. |

**Stop conditions:** as in section 3, with the scope reduced to device02.

**One session only.** The owner's authorization covers this one bounded session. A failure is recorded as failed and diagnosed offline; no second policy-changing session runs under this approval.

**Freeze.** Only if the full regression and this verdict pass is the AZTA-EXP-v1 manifest written and verified.

**Not claimed.** As in section 4. The session demonstrates both paths once at the new operating point. It does not estimate an escalation rate; the development measurement in `docs/final/AZTA_CONTEXT_ESCALATION_DECISION.md` remains the basis for that.

## Amendment 4a (10 November 2026, after `stb-l04`): the unchanged repeat `stb-l05`

`stb-l04` FAILED under v4 because the owner's RESTORE (#1) was not made within its 180 s window (`STB_L04_RESULT.md`). That verdict stands.

The owner authorized one repeat in writing (`approval_requests/STABILIZATION_LIVE_5.md`). It runs as **`stb-l05`**:
- same scenario class (`ExpV1VerificationScenario`);
- same configuration, scope (device02 only), timings and checks (`--rules v4`);
- a freshly generated plan and perturbation (`core_final_stb_l05.json`, `stb-l05.json`; same content as stb-l04 apart from the run id and the planning commit).

Nothing in Amendment 4 is relaxed. One session only; no further retry under this approval.
