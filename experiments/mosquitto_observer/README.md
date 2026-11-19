# Optional bounded Mosquitto observer (A1-H)

Status: **AZTA-FOUNDATION-A1-H: SUCCESSFULLY RUN; INDEPENDENTLY VERIFIED**, synthetic-only.
See [historical hardening evidence](HARDENING_EVIDENCE.md) and the later
[independent verification record](../../docs/FOUNDATION_INDEPENDENT_VERIFICATION.md)
dated 2026-10-05 (Asia/Dubai), which defines verification and its limits.
Real-broker integration is not claimed. A1-I remains blocked pending separate
review. Default AZTA operation does not use this plugin.

## Observation policy

2.1.2 plugin-v5 options follow the observer's global_plugin directive,
not the Dynamic Security directive. Disposable test example:

~~~conf
global_plugin /poc/observer.so
plugin_opt_usernames poc-a,poc-b,poc-reader
plugin_opt_client_id_prefix poc-
plugin_opt_topic_prefixes poc/shared,poc/long/
plugin_opt_events CONNECT,DISCONNECT,PUBLISH_IN,MESSAGE_OUT,SUBSCRIBE
plugin_opt_max_events 1000
~~~

Supported: usernames, username_prefix, client_ids, client_id_prefix,
topic_prefixes, events, max_events. Exact lists and prefixes are ORed within
each principal selector; username AND client-ID must match. Both scopes are
mandatory. Topics are literal prefixes, not MQTT wildcard filters. Lists accept
up to eight comma-separated entries, each 1–191 allowlisted ASCII bytes.
No spaces, empty entries, duplicate/unknown options, or unknown/duplicate events.
Topic scope, event list, and max_events (1–1,000,000) are mandatory.
CONNECT/DISCONNECT use only principal scope. Topics starting $ are always excluded.
Broker accessor usernames, not payload device_id, supply authenticated identities.
A client ID alone is not a trust assertion.

The five registered callbacks track lifecycle even when lifecycle output is
disabled. No authentication or ACL_CHECK callbacks. Every observation callback
returns success and leaves event data untouched. Dynamic Security authorizes.

## Records and volume bounds

Prefix AZTA_OBSERVER, JSON schema_version 2, observer_version a1-h-1.
EVENT fields: event_type, broker_event_classification, observer_timestamp_utc,
monotonic_elapsed_ms, username, client_id, session_id, topic, qos,
payload_length, disconnect_reason_code. Nonapplicable fields are null.
MESSAGE_OUT replaces the old POC label PUBLISH_OUT.

Payload pointers are never dereferenced. No passwords, auth tokens, state,
raw packets, or arbitrary broker text are copied. Output strings are at most
191 bytes, ASCII alphanumeric or _ - . / :. Null/unsafe/overlong values become
JSON null, not truncated identities. Credential-related marker words are
also rejected. This is not general secret detection: experiment principal and
topic names must themselves contain no sensitive information.

Fixed 256-entry session table, no per-event heap allocation. Full table or
missing CONNECT yields session_id null. IDs restart per process: externally
associate a run ID. EVENT records are under 1.5 KiB for this schema.

Filter before hard cap. No sampling. First excess emits one LIMIT_REACHED;
further eligible records are dropped; normal cleanup emits one COUNTERS.
Total submissions <= max_events + 2 (apart from startup CONFIG_ERROR).
No per-filter log. Counters partition callbacks:
observed = emitted + filtered + malformed_unsupported + dropped_limit.
Not MQTT attempt counts: denied operations do not reach post-ACL callbacks.
Summary/limit records are not counted as events_emitted.
evidence_complete means only *not omitted by the cap*, not all broker events,
complete fields, persisted logs, or delivery. After cap, evidence is incomplete.

## Failure behavior

Null callback data/client/required fields, invalid QoS, unsupported events:
increment malformed/unsupported and return success. Long/unsafe fields: null
output. Clock formatting failure: null timestamp. Initial monotonic clock
failure: optional startup fails. Invalid configuration: initialization fails
without displaying values; this can prevent experimental broker startup.

Mosquitto logging returns void: no sink-failure status. events_emitted means
submitted, not persisted. C tests discard output with unchanged return/data.
Logger loss, disk-full, abrupt death, and blocked sink can lose evidence.
Logging is synchronous; volume cap does NOT bound event-loop stall time.
No fail-open liveness or production-grade logging fault-isolation claim.
Real use requires separate acceptance of this risk or a reviewed nonblocking
export architecture. Standard 2.1.2 event-loop invocation is targeted; concurrent
third-party plugin invocation is not validated.

## What events prove

- CONNECT: accepted authenticated connection, not identity trust.
- PUBLISH_IN: write ACL passed, before distribution/storage.
- SUBSCRIBE: subscribe ACL passed, before application.
- MESSAGE_OUT: recipient receive ACL passed, before send, not receipt/ACK.
- DISCONNECT: closed session and reason code, origin unclassified.

Attempt, authorized/pre-distribution, pre-send, and actual receiver delivery are
different stages. Denied attempts come from client reason codes, not observer
events. No trust scoring, ML, Shadow Mode, adaptive enforcement, or A2.

## Build and synthetic tests

From C:\Projects\AZTA, existing local images:

~~~powershell
docker run --rm --pull never --user 0 --network bridge --mount 'type=bind,source=C:\Projects\AZTA\experiments\mosquitto_observer,target=/poc' --entrypoint sh eclipse-mosquitto:2.1.2-alpine@sha256:38c0da4f2ef84284d47b3b3eeea1cb3bdeabe81ee10caf0cd5c5ff61ee3ea408 /poc/build.sh
powershell -NoProfile -ExecutionPolicy Bypass -File experiments/mosquitto_observer/tests/run_poc.ps1
~~~

Compilation installs only in the removed container, verifies exact Mosquitto
2.1.2 source SHA-256 fd905380691ac65ea5a93779e8214941829e3d6e038d5edff9eac5fd74cbed02,
and uses -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared.
build-manifest.txt records base digest, compiler/musl/packages, source/artifact
hashes. Source tar checksum covers exact headers. Packages are not pinned to a
repository snapshot; future updates/removal can change toolchains. This is
source-based rebuilding, not guaranteed byte-identical output.

Build runs exact-header C edge tests. Broker harness uses five disposable modes
(baseline, observer, disabled, limit, invalid), unique internal network, no host
ports, synthetic credentials, tmpfs state/data/logs, read-only test mount and
no Python bytecode. No real secrets or volume. Finally removes only invocation-
owned resources. Python/Paho uses local azta-journal-runtime:gate3, no build/pull.

## Optional activation design — NOT APPLIED

No real overlay/config is created in this task. A future separately approved task:

1. Check exact broker digest, reviewed artifact hash, and existing persistent state.
2. Copy current real mosquitto.conf to broker-experiment.conf in this directory,
   preserve all DynSec/state/bootstrap settings, append observer and narrow filters.
3. Exact usernames/client IDs azta-device-01,azta-pdp; telemetry prefix
   azta/devices/device01/telemetry; reviewed events and max_events.
   Recheck actual client IDs for the intended run.
4. Create reviewed experiments/mosquitto_observer/compose.observer.yaml:

~~~yaml
services:
  broker:
    volumes:
      - type: bind
        source: ./experiments/mosquitto_observer/broker-experiment.conf
        target: /mosquitto/config/mosquitto.conf
        read_only: true
        bind:
          create_host_path: false
      - type: bind
        source: ./experiments/mosquitto_observer/observer.so
        target: /poc/observer.so
        read_only: true
        bind:
          create_host_path: false
~~~

Compose merges by container volume target; replace config only. Preserve data,
secrets, image, entrypoint; no host ports. Missing mounts fail fast, invalid
plugin/options can fail experimental startup; normal default stays independent.

Future commands, **not executed here**, after separate authorization and downtime plan:

~~~powershell
# Validation only.
docker compose -p azta-journal -f compose.yaml -f experiments/mosquitto_observer/compose.observer.yaml config --quiet
# Enable: recreates only broker.
docker compose -p azta-journal -f compose.yaml -f experiments/mosquitto_observer/compose.observer.yaml up -d --no-deps --no-build --pull never broker
# Disable/rollback: original observer-free configuration, same data.
docker compose -p azta-journal -f compose.yaml up -d --no-deps --no-build --pull never broker
~~~

Check resolved mounts, startup and authorization. Never down -v, delete state,
initialize identities, or retain overlay flags during rollback.

## Exact-version source references

[2.1.2 broker API](https://github.com/eclipse-mosquitto/mosquitto/blob/v2.1.2/include/mosquitto/broker.h):
void logger, accessors/callbacks. Reviewed handlers:
[connect](https://github.com/eclipse-mosquitto/mosquitto/blob/v2.1.2/src/plugin_connect.c),
[disconnect](https://github.com/eclipse-mosquitto/mosquitto/blob/v2.1.2/src/plugin_disconnect.c),
[message](https://github.com/eclipse-mosquitto/mosquitto/blob/v2.1.2/src/plugin_message.c),
[subscribe](https://github.com/eclipse-mosquitto/mosquitto/blob/v2.1.2/src/plugin_subscribe.c),
[ACL](https://github.com/eclipse-mosquitto/mosquitto/blob/v2.1.2/src/plugin_acl_check.c).
ACL callbacks can authorize/deny/defer; excluded rather than represented as a
passive final decision report.
