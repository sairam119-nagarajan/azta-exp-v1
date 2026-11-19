"""Gate 5F.3 non-mutating LEGACY-SUBSCRIPTION ISOLATION test plan, and its offline verifier. It connects to nothing and executes nothing.

Purpose of the future live check (separately authorized, never run here): show, with the broker's EXISTING permissions untouched, that
  * the historical `azta-pdp` identity may still read exactly the device01 and device02 telemetry topics and nothing else, so a
    subscription of azta-pdp to the device07 telemetry topic is DENIED (SUBACK 135), and
  * the dedicated receive-only `azta-observer` identity may read all ten literal telemetry topics,
and show it by ACTUAL MESSAGE RECEIPT (run id, sequence and exact payload hash), not by SUBACK alone. The legacy MQTT identity `azta-pdp` is
the historical broker principal; it is not the offline PDP trust engine (`trust/`), which holds no credential and subscribes to nothing.

The plan uses only identities and permissions that already exist (azta-pdp, azta-observer, azta-device-01, azta-device-07). It creates no
subscriber, widens no ACL, and sends no Dynamic Security command: it cannot even express one (the verifier refuses `$CONTROL` topics,
wildcards, unknown actors and any step kind other than the six below). Expected outcomes are DERIVED from the ACL specification (the
audited azta-pdp role of experiments/a3_policy.py and the observer proposal of configs/gate5d3/identity_spec.json), then compared with the
plan, so the plan cannot drift from the ACLs it claims to test.

    python -m experiments.gate5f3_isolation_plan build  --out configs/gate5f3/subscription_isolation_plan.json
    python -m experiments.gate5f3_isolation_plan verify --plan configs/gate5f3/subscription_isolation_plan.json
"""
import argparse
import json
from pathlib import Path
import sys

from observation.registry import DeviceRegistry

PLAN_SCHEMA = "azta.gate5f3.subscription_isolation_plan"
PLAN_SCHEMA_VERSION = 1
LEGACY_PDP, OBSERVER = "azta-pdp", "azta-observer"
ALLOWED_ACTORS = (LEGACY_PDP, OBSERVER, "azta-device-01", "azta-device-07")
STEP_KINDS = ("CONNECT", "SUBSCRIBE", "PUBLISH", "EXPECT_RECEIPT", "EXPECT_NO_RECEIPT", "DISCONNECT")
GRANTED, DENIED = "SUBACK_GRANTED_QOS1", "SUBACK_135_NOT_AUTHORIZED"
PROBE_DEVICES = ("device01", "device07")
DENIED_TOPIC_DEVICE = "device07"
REPO = Path(__file__).resolve().parents[1]
REGISTRY_V1 = "configs/observation/device_registry.json"
REGISTRY_V2 = "configs/observation/device_registry_v2.json"


def pdp_readable_topics(registry_v1):
    """Topics the audited azta-pdp role grants (subscribeLiteral + publishClientReceive, plus unsubscribeLiteral on device01): the two-device registry."""
    return tuple(entry.telemetry_topic for entry in registry_v1.devices)


def observer_readable_topics(registry_v2):
    """Topics of the dedicated observer role azta-observer-telemetry-read: the ten literal telemetry topics, nothing else."""
    return tuple(entry.telemetry_topic for entry in registry_v2.devices)


def _outcome(readable, topic):
    return GRANTED if topic in readable else DENIED


def build_plan(registry_v1, registry_v2):
    pdp, observer = pdp_readable_topics(registry_v1), observer_readable_topics(registry_v2)
    topic = {entry.device: entry.telemetry_topic for entry in registry_v2.devices}
    steps = []

    def add(kind, actor, **fields):
        steps.append(dict(step=len(steps) + 1, kind=kind, actor=actor, **fields))

    add("CONNECT", LEGACY_PDP, expect="CONNACK_0")
    add("SUBSCRIBE", LEGACY_PDP, topic=topic["device01"], qos=1, expect=_outcome(pdp, topic["device01"]))
    add("SUBSCRIBE", LEGACY_PDP, topic=topic["device07"], qos=1, expect=_outcome(pdp, topic["device07"]))
    add("CONNECT", OBSERVER, expect="CONNACK_0")
    add("SUBSCRIBE", OBSERVER, topic=topic["device01"], qos=1, expect=_outcome(observer, topic["device01"]))
    add("SUBSCRIBE", OBSERVER, topic=topic["device07"], qos=1, expect=_outcome(observer, topic["device07"]))
    add("CONNECT", "azta-device-01", expect="CONNACK_0")
    add("PUBLISH", "azta-device-01", topic=topic["device01"], qos=1, message="M1", expect="PUBACK_0_OR_16")
    add("EXPECT_RECEIPT", LEGACY_PDP, topic=topic["device01"], message="M1", correlate="run_id+sequence+sha256")
    add("EXPECT_RECEIPT", OBSERVER, topic=topic["device01"], message="M1", correlate="run_id+sequence+sha256")
    add("CONNECT", "azta-device-07", expect="CONNACK_0")
    add("PUBLISH", "azta-device-07", topic=topic["device07"], qos=1, message="M7", expect="PUBACK_0_OR_16")
    add("EXPECT_RECEIPT", OBSERVER, topic=topic["device07"], message="M7", correlate="run_id+sequence+sha256")
    add("EXPECT_NO_RECEIPT", LEGACY_PDP, topic=topic["device07"], message="M7", evidence_class="ABSENCE_EVIDENCE_AFTER_DECLARED_WAIT")
    for actor in ("azta-device-07", "azta-device-01", OBSERVER, LEGACY_PDP):
        add("DISCONNECT", actor)
    return dict(
        schema=PLAN_SCHEMA, schema_version=PLAN_SCHEMA_VERSION, status="PLAN_NOT_EXECUTED", non_mutating=True,
        registries=dict(legacy_two_device=REGISTRY_V1, ten_device=REGISTRY_V2, legacy_sha256=registry_v1.sha256, ten_sha256=registry_v2.sha256),
        scope="Existing permissions only. Retains azta-pdp read access to device01/device02 and azta-observer read access to the ten literal "
              "telemetry topics. Creates no subscriber, widens no ACL, sends no Dynamic Security command.",
        derived_from=dict(pdp="experiments/a3_policy.py audit(): azta-pdp-telemetry-read = subscribeLiteral+publishClientReceive on device01 and device02 "
                              "telemetry, unsubscribeLiteral on device01",
                          observer="configs/gate5d3/identity_spec.json observer_principal_proposal: azta-observer-telemetry-read on ten literal topics"),
        readable_topics=dict(legacy_pdp=list(pdp), observer=list(observer)),
        preconditions=["only the broker container of project azta-journal is running (no pdp, observation, workload or other AZTA container)",
                       "a read-only binding audit PASSES and its policy digest equals the campaign baseline (before and after)",
                       "device01 and device07 publishers use their own existing credentials only; no credential value is printed or stored",
                       "each client id has at most one live session at any time (the table below connects each exactly once)"],
        forbidden=["any Dynamic Security / $CONTROL topic or command", "wildcard subscriptions", "a new identity, role, group or ACL",
                   "widening azta-pdp or azta-observer", "concurrent sessions that share a client id", "docker restart/recreate of the broker"],
        message_rules="M1 and M7 are unique, labelled test messages (run id, sequence, payload sha256) published once each at QoS 1; receipt is "
                      "claimed only when run id, sequence and the exact payload hash match what was published. SUBACK/PUBACK alone prove nothing about delivery.",
        absence_rule="EXPECT_NO_RECEIPT is ABSENCE evidence after a wait declared before the run; the denial itself is proven by SUBACK 135, not by silence.",
        steps=steps,
        acceptance=[f"azta-pdp subscription to the device01 topic is {GRANTED} and the message M1 is actually received",
                    f"azta-pdp subscription to the device07 topic is {DENIED} and M7 is not received by azta-pdp",
                    f"azta-observer subscriptions to the device01 and device07 topics are {GRANTED} and M1 and M7 are actually received",
                    "the post-run audit digest equals the pre-run digest (no policy mutation)"])


def verify_plan(plan, registry_v1, registry_v2):
    """Problems (empty = conformant). Re-derives every expectation from the ACL specification and replays the connection ordering."""
    problems = []
    if not isinstance(plan, dict) or plan.get("schema") != PLAN_SCHEMA or plan.get("schema_version") != PLAN_SCHEMA_VERSION:
        return ["plan schema"]
    if plan.get("non_mutating") is not True or plan.get("status") != "PLAN_NOT_EXECUTED":
        problems.append("plan must be declared non-mutating and not executed")
    pdp, observer = pdp_readable_topics(registry_v1), observer_readable_topics(registry_v2)
    readable = {LEGACY_PDP: pdp, OBSERVER: observer}
    if plan.get("readable_topics") != dict(legacy_pdp=list(pdp), observer=list(observer)):
        problems.append("readable_topics differ from the ACL specification")
    own_topic = {f"azta-device-{entry.device[-2:]}": entry.telemetry_topic for entry in registry_v2.devices}
    granted = set()
    connected = set()
    published = {}
    steps = plan.get("steps")
    if not isinstance(steps, list) or not steps:
        return problems + ["no steps"]
    for number, step in enumerate(steps, start=1):
        kind, actor, topic = step.get("kind"), step.get("actor"), step.get("topic")
        if step.get("step") != number:
            problems.append(f"step {number}: numbering")
        if kind not in STEP_KINDS:
            problems.append(f"step {number}: unsupported step kind {kind!r}")
            continue
        if actor not in ALLOWED_ACTORS:
            problems.append(f"step {number}: actor {actor!r} is not an existing allowed identity")
            continue
        if topic is not None and (not isinstance(topic, str) or "#" in topic or "+" in topic or topic.startswith("$")):
            problems.append(f"step {number}: wildcard or control topic")
            continue
        if kind == "CONNECT":
            if actor in connected:
                problems.append(f"step {number}: {actor} would hold two concurrent sessions (client id collision)")
            connected.add(actor)
        elif actor not in connected:
            problems.append(f"step {number}: {actor} acts without a live session")
        if kind == "DISCONNECT":
            connected.discard(actor)
        elif kind == "SUBSCRIBE":
            if actor not in readable:
                problems.append(f"step {number}: only the two readers subscribe")
            elif step.get("expect") != _outcome(readable[actor], topic):
                problems.append(f"step {number}: expected outcome differs from the ACL specification ({_outcome(readable[actor], topic)})")
            elif step.get("expect") == GRANTED:
                granted.add((actor, topic))
        elif kind == "PUBLISH":
            if own_topic.get(actor) != topic:
                problems.append(f"step {number}: a publisher may publish only its own telemetry topic")
            published[step.get("message")] = topic
        elif kind == "EXPECT_RECEIPT":
            if (actor, topic) not in granted:
                problems.append(f"step {number}: receipt expected without a granted subscription")
            if published.get(step.get("message")) != topic or step.get("correlate") != "run_id+sequence+sha256":
                problems.append(f"step {number}: receipt must correlate a published message by run id, sequence and payload hash")
        elif kind == "EXPECT_NO_RECEIPT":
            if (actor, topic) in granted or published.get(step.get("message")) != topic:
                problems.append(f"step {number}: no-receipt expectation is only for an actor without a granted subscription to a published message")
            if step.get("evidence_class") != "ABSENCE_EVIDENCE_AFTER_DECLARED_WAIT":
                problems.append(f"step {number}: absence must be labelled as absence evidence")
    if connected:
        problems.append(f"sessions left open: {sorted(connected)}")
    pdp_topics = {step.get("topic"): step.get("expect") for step in steps if step.get("kind") == "SUBSCRIBE" and step.get("actor") == LEGACY_PDP}
    wanted = {own_topic["azta-device-01"]: GRANTED, own_topic["azta-device-07"]: DENIED}
    if pdp_topics != wanted:
        problems.append("the legacy identity must be shown granted on device01 and denied on device07")
    if not any(step.get("kind") == "EXPECT_RECEIPT" and step.get("actor") == OBSERVER and step.get("topic") == own_topic["azta-device-07"] for step in steps):
        problems.append("authorized observer receipt on device07 is missing")
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build")
    build.add_argument("--out", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--plan", required=True)
    args = parser.parse_args(argv)
    registry_v1, registry_v2 = DeviceRegistry.load(str(REPO / REGISTRY_V1)), DeviceRegistry.load(str(REPO / REGISTRY_V2))
    if args.command == "build":
        out = Path(args.out)
        if out.exists():
            print("REFUSED: output exists", file=sys.stderr)
            return 2
        plan = build_plan(registry_v1, registry_v2)
        out.write_text(json.dumps(plan, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        print(f"PLAN_WRITTEN {out}")
        return 0
    plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    problems = verify_plan(plan, registry_v1, registry_v2)
    print("PLAN_VERIFIED" if not problems else "PLAN_REJECTED " + "; ".join(problems))
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
