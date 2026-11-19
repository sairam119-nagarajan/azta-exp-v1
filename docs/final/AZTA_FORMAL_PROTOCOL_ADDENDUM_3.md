# AZTA-EXP-v1 Formal Protocol Addendum 3: replacement of exp-a06 by its spare exp-a14

**Date:** 14 November 2026. **Release:** AZTA-EXP-v1 (freeze manifest `221884e0…3b5516`, addendum manifest `8fd20030…`), unchanged.

## 1. Cause

- **What happened:** the supervised device02 session exp-a06 (episodes rate, payload, identity) completed its experiment part:
  - every planned episode started;
  - no owner instruction was cancelled;
  - the launcher and the driver exited 0.
- **Why it is STOP:** the post-session clean-up was run with `finish --restore device02`.
  - After an identity session, device02 had already been restored by the session itself, so the restore was a no-op (`NOOP_ALREADY_IN_STATE`).
  - `exp_session.py finish` counts anything other than `APPLIED_VERIFIED` as a restoration failure.
  - It therefore wrote `restoration_failed_STOP`, and `exp_validity.py` gave the verdict **STOP** (`no_restoration_failure` false).
  - That step made no permission change.
- **Review and completion:** the owner reviewed the STOP in writing (`FORMAL_STOP_REVIEW_A06`, commit `d9500a2`). The clean-up was then completed without a restore: baseline policy digest restored, probes and fingerprints passed, compose down without `-v`.
- **Cause of the STOP:** an operator command error in the clean-up step. It is unrelated to the session's results.

## 2. Change

- **The declared spare rule:** addendum 1, section 3 declared exp-a14 as the spare for a VOID active session without a context episode. It declared no spare for a STOP.
- **What this addendum adds:** a single, named replacement.
  - exp-a14 runs the exp-a06 scenario (`exp_session.py --run exp-a14 run --as exp-a06`): episodes rate, payload, identity, under the frozen anomaly parameters.
  - Its seeds come from its own run id, as for every run.
  - It needs a separate written owner approval, with the owner present at the operator console.
- **Verdicts:**
  - exp-a06 keeps its **STOP** verdict on record and is not relabelled.
  - exp-a14 receives its own verdict from the frozen `exp_validity.py --as exp-a06`.
  - If exp-a14 is not VALID, no further replacement is made. The device02 results then rest on the eleven VALID sessions, with exp-a06 reported separately as supplementary evidence.
- **Ledger rows:**
  - The supervised sessions were run one at a time with `exp_session.py`, not through `exp_campaign.py`, so they have no rows in `results/engineering/formal/campaign_ledger.jsonl`.
  - Before aggregation, one row per supervised session (`batch: "A"`) is appended with its recorded verdict: exp-a01 to exp-a12, with exp-a06 as STOP, and exp-a14 with `as_run: "exp-a06"`.
  - The frozen `exp_aggregate.py` then runs once and uses only VALID rows, as declared.

## 3. Unchanged

- No model, threshold, trust parameter, calibration, configuration or measurement script changes. The experiment matrix and the addendum manifest are byte-identical.
- The validity, void, stop and aggregation rules of addendum 1 are unchanged, apart from the single named replacement above.
- The reserved TEST runs are NOT re-scored.
- Automatic enforcement remains limited to device02, on the isolated pilot broker.

## 4. Reason the change is result-independent

- **Timing:** the replacement was decided before any metric of the formal campaign was computed.
- **Cause:** the STOP comes from a clean-up command, not from any outcome of exp-a06.
- **Disclosure:** exp-a06 stays in the record and is reported separately, so either result can be compared with the other.
