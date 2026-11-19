"""Gate 5D.3B operator-only LIVE authorization probes: the broker's actual outcomes, recorded, never assumed.

Runs the 48 expected denials of the reviewed Gate 5D.3 provisioning plan plus positive controls (every device publishes on
its own telemetry topic, the observer subscribes to its ten literal topics, the historical PDP still subscribes to its two)
and records, for each probe, the expected outcome, the outcome actually observed and a verdict. A "not authorized" outcome is any
reason code >= 128; whether the code equals the documented 135 is recorded separately and is not assumed.

Safety: operator-only test controller (like the A3 regression), never a PDP/receiver/publisher service. One connection per actor,
sequential, never two sessions with one client ID. Payloads are tiny non-secret markers; nothing is retained. Credentials are
read only by the unchanged A3 MQTTClient (or, for the foreign-client-ID probe, by one local read) and never logged. Importing the
module opens no connection. A denial observed as ALLOWED, or an undetermined outcome, makes the verdict FAIL and the process exits
non-zero so the caller can STOP.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sys

from experiments import gate5d3_provisioning_plan as gp
from observation.registry import DeviceRegistry

RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
ALLOWED_PUBACK = (0, 16)  # 16 = accepted, no matching subscribers
NOT_AUTHORIZED = 128  # MQTT v5 reason codes >= 128 are failures


def credential_for(actor, credentials_dir):
    name = "pdp_password" if actor == gp.PDP else f"{actor}-password"
    return Path(credentials_dir) / name


def positive_controls(plan, registry_v2):
    probes = []
    for entry in registry_v2.devices:
        probes.append(dict(actor=entry.username, action="publish", target=entry.telemetry_topic,
                           expected=dict(kind="PUBACK", allowed=True), why="a device may publish on its own telemetry topic"))
    for entry in registry_v2.devices:
        probes.append(dict(actor=gp.OBSERVER_IDENTITY, action="subscribe", target=entry.telemetry_topic,
                           expected=dict(kind="SUBACK", allowed=True), why="the observer receives the ten approved topics"))
    for entry in registry_v2.devices[:2]:
        probes.append(dict(actor=gp.PDP, action="subscribe", target=entry.telemetry_topic,
                           expected=dict(kind="SUBACK", allowed=True), why="the historical PDP keeps its two-topic subscription"))
    return probes


def build_probes(plan, registry_v2):
    denials = [dict(p, category="denial") for p in plan["expected_denials"]]
    positives = [dict(p, category="positive_control") for p in positive_controls(plan, registry_v2)]
    return positives + denials


def _outcome_verdict(probe, actual):
    """Return (verdict, detail). Denials need an observed not-authorized code; positives need an observed grant."""
    code, error = actual.get("code"), actual.get("error")
    if error is not None or code is None:
        return "UNDETERMINED", "no broker outcome observed"
    if probe["category"] == "denial":
        if code >= NOT_AUTHORIZED:
            return "PASS", "denied" if code == probe["expected"]["code"] else "denied_with_different_code"
        return "FAIL", "UNEXPECTEDLY_PERMITTED"
    if probe["expected"]["kind"] == "PUBACK":
        return ("PASS", "allowed") if code in ALLOWED_PUBACK else ("FAIL", "expected grant not observed")
    return ("PASS", "granted") if code in (0, 1, 2) else ("FAIL", "expected grant not observed")


def run_probes(plan, registry_v2, actor_factory, foreign_connect, *, marker="g5d3b-probe"):
    """actor_factory(identity) -> object(connect()->code, publish(topic, payload)->code, subscribe(topic)->[codes], close());
    foreign_connect(identity, client_id) -> CONNACK code. Probes are grouped by actor; one connection at a time."""
    probes = build_probes(plan, registry_v2)
    results = []
    actors = []
    for probe in probes:
        if probe["actor"] not in actors:
            actors.append(probe["actor"])
    for actor in actors:
        mine = [p for p in probes if p["actor"] == actor]
        session = actor_factory(actor)
        connected = None
        try:
            try:
                connected = session.connect()
            except Exception as exc:
                connected = None
                connect_error = type(exc).__name__
            results.append(dict(actor=actor, action="connect_own_client_id", target=actor, category="positive_control",
                                expected=dict(kind="CONNACK", allowed=True),
                                actual=dict(kind="CONNACK", code=connected, error=None if connected is not None else "connect_failed"),
                                verdict="PASS" if connected == 0 else "FAIL", detail="own identity and client ID"))
            for probe in mine:
                if probe["action"] == "connect_with_foreign_client_id":
                    continue
                if connected != 0:
                    actual = dict(kind=probe["expected"]["kind"], code=None, error="actor_not_connected")
                else:
                    try:
                        if probe["action"] == "publish":
                            actual = dict(kind="PUBACK", code=session.publish(probe["target"], json.dumps(
                                dict(probe=marker, actor=actor)).encode()))
                        else:
                            codes = session.subscribe(probe["target"])
                            actual = dict(kind="SUBACK", code=codes[0] if codes else None, codes=list(codes))
                    except Exception as exc:  # timeouts and client errors: undetermined, never "passed"
                        actual = dict(kind=probe["expected"]["kind"], code=None, error=type(exc).__name__)
                verdict, detail = _outcome_verdict(probe, actual)
                results.append(dict(probe, actual=actual, verdict=verdict, detail=detail))
        finally:
            try:
                session.close()
            except Exception:
                pass
    for probe in probes:
        if probe["action"] != "connect_with_foreign_client_id":
            continue
        try:
            actual = dict(kind="CONNACK", code=foreign_connect(probe["actor"], probe["target"]))
        except Exception as exc:
            actual = dict(kind="CONNACK", code=None, error=type(exc).__name__)
        verdict, detail = _outcome_verdict(probe, actual)
        results.append(dict(probe, actual=actual, verdict=verdict, detail=detail))
    denials = [r for r in results if r.get("category") == "denial"]
    summary = dict(
        probes=len(results), denial_probes=len(denials),
        denials_observed_denied=sum(r["verdict"] == "PASS" for r in denials),
        denials_with_exact_documented_code=sum(r["verdict"] == "PASS" and r["detail"] == "denied" for r in denials),
        unexpectedly_permitted=[dict(actor=r["actor"], action=r["action"], target=r["target"]) for r in denials
                                if r["verdict"] == "FAIL"],
        undetermined=sum(r["verdict"] == "UNDETERMINED" for r in results),
        positive_controls=sum(r.get("category") == "positive_control" for r in results),
        positive_controls_passed=sum(r.get("category") == "positive_control" and r["verdict"] == "PASS" for r in results))
    verdict = "PASS" if all(r["verdict"] == "PASS" for r in results) else "FAIL"
    return dict(schema="azta.gate5d3.probe_report", schema_version=1, plan_sha256=plan["plan_sha256"],
                registry_v2_sha256=registry_v2.sha256, verdict=verdict, summary=summary, results=results)


# ---------------------------------------------------------------- live clients (lazy imports; nothing opens at import time)
class LiveActor:
    def __init__(self, identity, credentials_dir, host):
        self.identity, self.path, self.host, self.inner = identity, credential_for(identity, credentials_dir), host, None

    def connect(self):
        from experiments.a3_mqtt import MQTTClient
        self.inner = MQTTClient(self.identity, self.path, lambda *a, **k: None, self.host)
        return self.inner.connect(3)

    def publish(self, topic, payload):
        from experiments.a3_mqtt import pump_until
        info = self.inner.publish(topic, payload, 1)
        pump_until([self.inner], lambda: info.mid in self.inner.acks, 3)
        return self.inner.acks.pop(info.mid)

    def subscribe(self, topic):
        return self.inner.subscribe(topic, 1, 3)

    def close(self):
        if self.inner is not None:
            self.inner.close()


def live_foreign_connect(credentials_dir, host):
    def connect(identity, client_id):
        import time
        import paho.mqtt.client as mqtt
        result = dict(code=None)
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id, protocol=mqtt.MQTTv5,
                             reconnect_on_failure=False)
        client.username_pw_set(identity, credential_for(identity, credentials_dir).read_text(encoding="utf-8").strip())
        client.on_connect = lambda c, u, f, reason, p: result.update(code=reason.value)
        client.connect(host, 1883, keepalive=15, clean_start=True)
        deadline = time.monotonic() + 3
        while result["code"] is None and time.monotonic() < deadline:
            if client.loop(timeout=0.005) != 0:
                break
        client.disconnect()
        return result["code"]
    return connect


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--credentials-dir", default="/run/secrets")
    parser.add_argument("--evidence-root", default="/results/gate5d3_probe")
    parser.add_argument("--host", default=os.getenv("MQTT_HOST", "broker"))
    parser.add_argument("--registry-v1", default="/app/configs/observation/device_registry.json")
    parser.add_argument("--registry-v2", default="/app/configs/observation/device_registry_v2.json")
    parser.add_argument("--identity-spec", default="/app/configs/gate5d3/identity_spec.json")
    args = parser.parse_args(argv)
    try:
        if not RUN_ID.fullmatch(args.run_id):
            raise ValueError("invalid run id")
        v1, v2 = DeviceRegistry.load(args.registry_v1), DeviceRegistry.load(args.registry_v2)
        plan = gp.build_plan(v1, v2, json.loads(Path(args.identity_spec).read_text(encoding="utf-8")))
        directory = Path(args.evidence_root) / args.run_id
        directory.parent.mkdir(parents=True, exist_ok=True)
        directory.mkdir(exist_ok=False)  # never overwrite prior evidence
        report = run_probes(plan, v2, lambda identity: LiveActor(identity, args.credentials_dir, args.host),
                            live_foreign_connect(args.credentials_dir, args.host))
        with (directory / "probe_report.json").open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
    except Exception as exc:
        print(f"GATE5D3_PROBE FAILED {type(exc).__name__}", file=sys.stderr)
        return 2
    s = report["summary"]
    print(f"GATE5D3_PROBE {report['verdict']} run_id={args.run_id} probes={s['probes']} denied={s['denials_observed_denied']}/"
          f"{s['denial_probes']} exact_135={s['denials_with_exact_documented_code']} permitted={len(s['unexpectedly_permitted'])} "
          f"undetermined={s['undetermined']} positives={s['positive_controls_passed']}/{s['positive_controls']}")
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
