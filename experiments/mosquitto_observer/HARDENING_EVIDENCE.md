# A1-H synthetic hardening evidence

Task AZTA-FOUNDATION-A1-H; 2026-10-04 (Asia/Dubai).
Status **SUCCESSFULLY RUN**, not INDEPENDENTLY VERIFIED. Synthetic only.

## Pre-state and changes

C:\Projects\AZTA; master; HEAD ed1cb9d30b0ee647da146a756d9c0b8c40db6d72.
Initial status: untracked experiments/broker_sessions.py,
experiments/mosquitto_observer/, tests/test_broker_sessions.py; tracked diff empty.
Gates 0–4, FE-01, A1-P accepted as supplied. A1-I remains blocked at review.

Changed inside experiments/mosquitto_observer only: observer.c, observer.so,
build.sh, README.md, broker-observer.conf, start_broker.sh, setup_dynsec.sh,
tests/synthetic_client.py, tests/run_poc.ps1. Added build-manifest.txt,
tests/edge_cases.c, this record. broker-baseline.conf preserved.
No FE-01, root Compose, real config, Gate 3/4 or credential changes.

## Build and execution

Exact build/test commands are in README.md and were executed from the root.
Base digest sha256:38c0da4f2ef84284d47b3b3eeea1cb3bdeabe81ee10caf0cd5c5ff61ee3ea408.
Mosquitto 2.1.2 source checksum (covers headers):
fd905380691ac65ea5a93779e8214941829e3d6e038d5edff9eac5fd74cbed02.
Observer source SHA-256:
351e0dddbd7e9b64b8bc33ffbae10ea2b64a6fcab8d090a857d0812a61991cf8.
Artifact SHA-256:
f0b3b4e7b354f01bb19d2c93811d24e721d5c49b765825f7f7591163fa1cf153.
GCC 15.2.0 (gcc-15.2.0-r2), musl 1.2.5 (musl/musl-dev-1.2.5-r23),
binutils-2.45.1-r0, build-base-0.5-r3, cjson-dev-1.7.19-r1.
Full packages: build-manifest.txt. Repositories are not snapshot-pinned;
byte-identical future binaries are not promised. No host/WSL installs.

Exact-header C harness printed:
EDGE_TESTS PASS null/unsupported/long/unsafe/logger-loss/limit/capacity/invalid-config/no-mutation.

Client local runtime ID:
sha256:02fdaf88ea83fd61383c12c7333160fb54afcf8845816740ae37c3dab4fec21c.
MQTT v5/QoS 1; four synthetic clients poc-a, poc-b, poc-reader, poc-admin.
Random synthetic credentials not printed/persisted in repo.
Internal network, no ports, tmpfs state, no real secrets or volume.

## Final rebuilt-artifact run

Each working mode attempted 204 publications: 200 intended shared-topic
(100 each of two legitimate clients), one unrelated principal shared publication,
one unrelated-topic publication, one overlong-topic publication, one denied.
203 PUBACKs allowed (0 or 16/no matching subscribers), one denied (135).
One subscription allowed (1), one denied (135). Actual receiver count 201.
Unrelated admin inbound is filtered, but its authorized message still produces
a scoped recipient MESSAGE_OUT: principal filtering is per callback, not an
end-to-end origin filter.

| Mode | Observed | Emitted EVENT | Filtered | Malformed | Cap drops | Receiver | Client elapsed ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Baseline | N/A | 0 | N/A | N/A | N/A | 201 | 58 |
| Observer | 489 | 409 | 80 | 0 | 0 | 201 | 71 |
| PUBLISH_IN only | 489 | 201 | 288 | 0 | 0 | 201 | 68 |
| Cap 10 | 489 | 10 | 80 | 0 | 399 | 201 | 98 |

409 = 3 CONNECT + 3 DISCONNECT + 200 shared PUBLISH_IN + 1 overlong-topic
PUBLISH_IN (topic null) + 201 MESSAGE_OUT + 1 SUBSCRIBE.
Normal mode adds one final COUNTERS. Cap mode: 10 EVENT + one LIMIT_REACHED +
one COUNTERS. All partition observed = emitted + filtered + malformed + dropped.
Control/admin activity is filtered. Timing covers client workload, not setup:
one moderate sanity check, not formal latency/performance measurement.
Invalid config exited nonzero with structured CONFIG_ERROR; default baseline
ran without observer. All authorization/delivery counts identical.

## Required test matrix

| Test | Result |
| --- | --- |
| 1 Intended principal | PASS: each device 100 distinct authenticated inbound records |
| 2 Unrelated client | PASS: no poc-admin EVENT; authorized publication still delivered |
| 3 Intended topic | PASS: shared inbound/pre-send events observed |
| 4 Unrelated topic | PASS: authorized poc/other absent |
| 5 Enabled events | PASS: all five observed in normal mode |
| 6 Disabled events | PASS: PUBLISH_IN-only emitted 201, no other event types |
| 7 Payload absent | PASS: device_id/payload-marker absent from all broker logs |
| 8 Password absent | PASS: all four generated passwords absent from logs |
| 9 Null/malformed | PASS: C harness null data/client/username/topic, invalid QoS, unsupported number; success returns |
| 10 Long metadata | PASS: live broker long topic null; C harness long client/topic bounded/null |
| 11 Distinct clients | PASS: username/client ID distinct; connect/disconnect session correlation |
| 12 DynSec baseline | PASS: allow/deny and receiver counts match all working modes |
| 13 Failure/cap neutral | PASS: capped broker handles full workload; discarded-output C stub returns success, event memcmp unchanged |
| 14 Counters | PASS: partition reconciles broker modes and C harness |

Malformed pointers are injected in standalone exact-header callbacks, not by
wire packets or memory corruption inside Mosquitto. The sink stub discards
output; it is not disk-full or indefinitely blocked logger fault injection.
No real broker fault-injection coverage is claimed.

Initial C test used an out-of-scope topic and was corrected. First baseline
fixture lacked admin shared-topic permission; only disposable policy corrected.
Final rebuilt artifact/full matrix passed. Failed runs cleaned up too.

## Limits and recommendation

ATTEMPT is the client action. PUBLISH_IN is write ACL allowed before distribution.
MESSAGE_OUT is recipient ACL allowed before send, **not delivery**; delivery is
separately counted by the test reader. No denied-attempt observer, payload ID
validation, trust scoring, ML, adaptive enforcement, Shadow Mode or A2.

191-byte output fields, fixed 256-session table, mandatory max cap, one limit
indication/final counters. No sampling. Logger synchronous/void: submitted !=
persisted; record cap does not bound blocked-sink time. Missing metadata/session
IDs must be respected. evidence_complete only reports cap completeness.
No production fault-isolation/liveness claim; abrupt death can lose counters.
Standard broker event-loop invocation targeted; third-party concurrent invocation
not validated.

README gives design-only optional overlay and future enable/rollback commands,
fail-fast missing mounts/options, unchanged default/persistent state.
No overlay/config created or applied. Retain isolated optional use; real
integration requires separate approval of sink-loss/backpressure/rollback risks.

## Cleanup and real final state

CLEANUP PASS no task containers/networks remain. Build containers --rm;
synthetic /tmp, /mosquitto/data, /mosquitto/log tmpfs; no synthetic state volume.
Only invocation-owned resources removed, no prune.

Real Docker metadata only:
ID 88c4e95e98c2c64c90d0bb9e9a8c2b49afb18d690b5a02da53462d9a3a0f493a;
running=true; StartedAt 2026-10-03T20:42:10.163396651Z;
image sha256:38c0da4f2ef84284d47b3b3eeea1cb3bdeabe81ee10caf0cd5c5ff61ee3ea408;
host ports {}. Same broker as pre-state. No real exec/log/state inspection,
restart, observer load, config/state/identity/ACL/credential changes.
No real Dynamic Security contents or checksum read.
No Windows/WSL change, commit/push, or A2.

Final tracked diff empty, HEAD unchanged. Untracked additions preserved:
experiments/broker_sessions.py, experiments/mosquitto_observer/,
tests/test_broker_sessions.py. A1-H edits confined to observer directory.
