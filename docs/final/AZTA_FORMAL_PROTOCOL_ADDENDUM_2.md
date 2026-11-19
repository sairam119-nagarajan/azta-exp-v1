# AZTA-EXP-v1 formal protocol, addendum 2: jitter is not applicable to devices 05 to 09

**Written for:** the project owner, the supervisor and the Main Controller.

**Status:** declared on 12 November 2026 (UTC), after the first two formal detection sessions were VOID and **before any detection result was looked at**. It needs the owner's written acceptance (`exp_approve.py amend --number 2`) before any further formal run.

## 1. What happened

- **Batch S1 so far:**
  - the five benign sessions exp-s31 to s35 were VALID;
  - the reserved TEST runs were scored once.
- **The first detection session, exp-s01, was VOID** for two failed infrastructure checks: `no_rejected_command` and `every_planned_episode_applied`.
- **The cause** is the device09 workload, which refused the scheduled jitter command: `INVALID_ANOMALY: device09: a event_gap law has no jitter to change`.
- **exp-s02 hit the same refusal** on device08, a periodic law. The campaign's declared rule ("a second consecutive VOID with the same failed checks") stopped the campaign there.

**Root cause:** a defect in the addendum-1 matrix, not in AZTA.
- The frozen live workload (`engineering/fleet_workload.py`, `check_command_applicable`) accepts a jitter command only for a device whose legitimate law has a jitter fraction. On the frozen device laws, that means devices 01 to 04 (steady with jitter) and device10 (switching).
- Devices 05 to 08 are strictly periodic and device09 is event-gap, so there is no jitter for these laws to change.
- The workload refuses the command rather than emulating it, by design (`fleet/laws.py`).
- The addendum-1 matrix rotated all five kinds over all ten devices, so **every** detection session gave jitter to one of devices 05 to 09.
- The offline tests of addendum 1 used a simulated broker that did not apply this check, so they did not catch it.

## 2. The amendment

**Matrix change:**
- In a DETECTION session, a device whose frozen law cannot express jitter runs **no commanded episode** in its jitter slot. It stays benign for that session.
- Every other episode, parameter, onset, duration, seed, run id and batch is unchanged.
- Applicability is decided by the frozen device law (`fleet.laws.profile_of`). It is checked in the tests against the live workload's own `check_command_applicable` on every run's plan.

| | Addendum 1 | Addendum 2 |
| --- | --- | --- |
| Detection episodes | 250 | **225** |
| rate, payload, burst, drop | 5 per device, all ten devices | unchanged |
| jitter | 5 per device, all ten devices | 5 per device on devices 01, 02, 03, 04 and 10; **not applicable** on devices 05 to 09 (reported as such, with the reason) |
| Enforcement block (device02) | 5 jitter episodes | unchanged (device02 supports jitter) |
| Silence, context, identity, benign | — | unchanged |

**Tooling changes** (all re-pinned in the addendum manifest, which supersedes the addendum-1 manifest `38105d9e…b868621`):

| Script | Change |
| --- | --- |
| `exp_matrix.py` | Applicability rule; records the not-applicable cells in the matrix; may rewrite the matrix only in place of the exact addendum-1 matrix |
| `exp_campaign.py` | After a STOP, continues only with `--after-review REF` naming the owner's recorded written answer; a REVIEWED row is appended to the ledger |
| `exp_approve.py` | `amend` records the owner's acceptance of this addendum; later shadow batches are checked against the owner's latest recorded answer |
| `exp_addendum.py` | Pins this document; may supersede only the addendum-1 manifest |
| `tests/test_exp_formal.py` | New test: every planned start command of every run is accepted by the live workload's check on that run's own plan (the test that would have caught the defect); the counts are updated |

## 3. What does not change

- **AZTA-EXP-v1:** no frozen file, model, threshold, weight, calibration or authority rule changes. The freeze manifest `221884e0…3b5516` verifies unchanged.
- **The validity, void, stop and aggregation rules** of addendum 1 are unchanged.
- **The reserved TEST runs are not re-scored.** The single scoring made on 12 November 2026 stands.
- **exp-s01 and exp-s02 keep their VOID verdicts,** computed against the addendum-1 matrix. As addendum 1 declared, they are replaced by the spares exp-s36 and exp-s37, which run the amended exp-s01 and exp-s02 scenarios.
- **The S1 session approvals already written stay valid.** They pin the protocol, route and authority map, none of which changed.

## 4. Why this is not a change based on results

- The amendment follows from the frozen workload's refusal message, a machine-checked infrastructure fact.
- No detection metric, score, flag or decision of any formal run was computed or looked at before it was written.
- The TEST scoring covered benign data only and has no bearing on which anomaly a device can produce.
- **Reported limitation:** jitter detection is evaluated on five of the ten devices.
