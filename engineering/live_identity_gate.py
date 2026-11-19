"""Host-side driver of the live verification of the identity-gate enforcement repair (pre-push audit D-F4) on the ISOLATED engineering broker.

    python -m engineering.live_identity_gate --run-id ID

It generates hard identity-gate decisions with the UNCHANGED integrated trust engine from explicitly SYNTHETIC evidence (a modified read-only binding-audit snapshot run through the real analyzer and
the real producer; test fixtures supply the synthetic observer windows), hands them to the PEP container (the only holder of the administrative credential here) and, after every state change, checks
what the broker really ALLOWS with the data-plane probe controller. The records are synthetic fixtures: the repaired path under test is `--mode test-only-identity-gate`, whose guard runs the same
device-attribution checks as the operational identity-gate path, and the operational mode is shown to refuse the very same records because no approval exists.

Scenarios (each check is recorded with its expectation and the observed outcome in `live_identity_gate_report.json`):
  baseline                    binding audit PASS, the policy digest recorded, all ten devices FULL_ACCESS, the broker attested as the isolated engineering broker
  operational_still_blocked   the same genuine records, offered to the OPERATIONAL guard, are refused for the missing registry and configuration approvals (no calibration is asked for on the
                              identity path; an ordinary behavioural record is still refused for the missing calibration too); nothing is applied
  identity_quarantine         an attributable identity failure of device01 -> T = 0 -> QUARANTINE applied and broker-verified; its connection is refused; every other device is unchanged
  idempotence                 the same file re-read and a second REVOKED verdict for the same device send no further command
  attribution_refused         forged, unenrolled, rogue-principal, unattributed, behavioural, live-shaped and broker-wide-finding (UNAUTHORIZED for every device) records are refused; no device changes
  second_device               device02 quarantined independently; a held session is ended by the broker's server DISCONNECT; device01 stays quarantined, the others unchanged
  restore                     the administrative RESTORE returns both devices to FULL_ACCESS; the policy digest equals the baseline
It demonstrates enforcement mechanics for the repaired hand-off only; it demonstrates nothing about detection accuracy, calibrated trust scoring or attack containment, and no real broker, calibration,
registry or approval is used.
"""
import argparse
import json
from pathlib import Path
import sys
import time

from engineering import env
from engineering.live_enforcement import CHECKS, Run, Stream, last_json, matches, utc
from enforcement.guard import HARNESS_TOKEN

ROOT = env.ROOT
RETAINED_BASELINE_DIGEST = "997ecf392957c470073d1e8211e957f006a336a11d6e1b699a95f75fe94648d2"      # the engineering broker's accepted policy digest (MI2/MI3/audit records)
NS = 1_000_000_000


def fixtures():
    """The synthetic test fixtures (host side only; they are never mounted into a container)."""
    sys.path[:0] = [str(ROOT), str(ROOT / "tests")]
    import decision_pipeline_fixtures as dfx
    from experiments.binding_audit import analyze
    from test_binding_audit import REG as AUDIT_REGISTRY, snapshot
    from trust.evidence import parse_bundle
    from trust.producer import AuditSnapshot
    return dfx, analyze, AUDIT_REGISTRY, snapshot, parse_bundle, AuditSnapshot


def make_records(now_ns):
    """{name: record} of genuine integrated-engine decisions over synthetic evidence, decided at `now_ns` with the audit verdict taken 500 ns earlier: the synthetic engine configuration allows
    identity evidence to be at most 1000 ns old, so the verdict is fresh and nothing is stale-by-construction."""
    dfx, analyze, registry, snapshot, parse_bundle, AuditSnapshot = fixtures()
    taken = now_ns - 500

    def failed(kind, device):
        snap = snapshot()
        username = "azta-device-01" if device == "device01" else "azta-device-02"
        if kind == "REVOKED":
            snap["clients"][username]["disabled"] = True
        elif kind == "UNAUTHORIZED_BROKER_WIDE":     # a finding about the whole broker (default publish ACL not deny): the audit marks EVERY enrolled device UNAUTHORIZED
            for default in snap["defaults"]:
                if default["acltype"] == "publishClientSend":
                    default["allow"] = True
        return analyze(snap, registry)

    def decide(evidence_id, kind, device, *, calibrated=True, healthy=False):
        engine, _ = dfx.integrated(calibrated=calibrated)
        window = dfx.S_READY if device == "device01" else dfx.V_READY
        audits = [AuditSnapshot(analyze(snapshot(), registry) if healthy else failed(kind, device), taken, dfx.SYN)]
        _, built = dfx.bundle(window, producer_devices={} if device == "device01" else None, audits=audits, evidence_id=evidence_id, decision_ns=now_ns, observed=taken)
        return engine.decide(parse_bundle(built))

    records = dict(
        gate_d01=decide("idg-d01-revoked", "REVOKED", "device01"),
        gate_d01_second_verdict=decide("idg-d01-revoked-again", "REVOKED", "device01"),
        gate_d02=decide("idg-d02-revoked", "REVOKED", "device02"),
        behavioural=decide("idg-behavioural", None, "device01", calibrated=False, healthy=True))
    for name, record in records.items():
        assert record["decision_ns"] == now_ns, name
    broker_wide = {name: decide(f"idg-broker-wide-{name}", "UNAUTHORIZED_BROKER_WIDE", device) for name, device in (("d01", "device01"), ("d02", "device02"))}
    for record in broker_wide.values():
        assert (record["status"], record["proposed_state"], record["identity"]["status"], record["fusion"]["trust"]) == ("EVALUATED", "QUARANTINE", "UNAUTHORIZED", 0.0)   # the ENGINE still applies the gate
    gate = records["gate_d01"]
    assert (gate["status"], gate["proposed_state"], gate["fusion"]["trust"], gate["fusion"]["hard_gate_applied"]) == ("EVALUATED", "QUARANTINE", 0.0, True)
    assert records["behavioural"]["status"] == "NOT_EVALUABLE"

    def variant(evidence_id, mutate):
        import copy
        r = copy.deepcopy(gate)
        r["evidence_id"] = evidence_id
        mutate(r)
        return r

    note = lambda r: r["annotations"]["decision_pipeline"]
    forged = dict(
        broker_wide_finding_device01=broker_wide["d01"], broker_wide_finding_device02=broker_wide["d02"],
        forged_username_of_device02=variant("idg-forged-username", lambda r: r["identity"].update(bound_username="azta-device-02", bound_client_id="azta-device-02")),
        forged_route_device02=variant("idg-forged-route", lambda r: note(r)["route"].update(device="device02")),
        rogue_principal=variant("idg-rogue", lambda r: r["identity"].update(bound_username="rogue-client", bound_client_id="rogue-client")),
        unenrolled_device=variant("idg-unenrolled", lambda r: note(r)["route"].update(device="device99")),
        unattributed=variant("idg-unattributed", lambda r: note(r).update(route=dict(code="UNKNOWN_DEVICE", device=None))),
        live_shaped_evidence=variant("idg-live-shaped", lambda r: (r["identity"].update(provenance="BROKER_POLICY_AUDIT"), note(r)["evidence"].update({"class": "LIVE_OBSERVER_VERIFIED"}),
                                                                   note(r).update(synthetic=False))))
    return records, forged


class IdentityStream(Stream):
    def _run_args(self, mode, escalate, deescalate, age_s, policy, follow_s=None):
        args = super()._run_args(mode, escalate, deescalate, age_s, policy, follow_s)
        return args + ["--harness-token", HARNESS_TOKEN] if mode == "test-only-identity-gate" else args

    def write(self, records):
        self.append_lines([json.dumps(r, sort_keys=True) for r in records])

    def handled(self):
        return [e["body"] for e in self.run.audit_entries(self.audit) if e["kind"] == "RECORD_HANDLED"]


def docker_inventory():
    import subprocess
    containers = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}|{{.Status}}"], capture_output=True, text=True, timeout=60).stdout.splitlines()
    volumes = subprocess.run(["docker", "volume", "ls", "--format", "{{.Name}}"], capture_output=True, text=True, timeout=60).stdout.split()
    research = subprocess.run(["docker", "inspect", "--format", "{{.State.Status}} started={{.State.StartedAt}} finished={{.State.FinishedAt}}", "azta-journal-broker-1"],
                              capture_output=True, text=True, timeout=60).stdout.strip()
    return dict(containers=sorted(c.split("|")[0] for c in containers), volumes=sorted(volumes), research_broker=research)


def run_all(r):
    t0 = time.time()
    has_ops = lambda d: d in ("device01", "device02")
    records, forged = make_records(time.time_ns())
    gate, second, gate02, behavioural = (records[k] for k in ("gate_d01", "gate_d01_second_verdict", "gate_d02", "behavioural"))

    verdict, baseline = r.audit_digest("baseline")
    r.check("baseline", "read-only binding audit PASS under registry v2", verdict == "PASS", policy_sha256=baseline)
    r.check("baseline", "the policy digest equals the engineering broker's accepted digest recorded by earlier work", baseline == RETAINED_BASELINE_DIGEST, baseline=baseline)
    state = r.observe()
    r.check("baseline", "the PEP attests the isolated engineering broker and sees all ten devices in FULL_ACCESS",
            bool(state) and state["environment"] == "ENGINEERING_ISOLATED" and len(state["devices"]) == 10 and all("FULL_ACCESS" in d["states"] for d in state["devices"].values()))
    others = ("device02", "device03", "device05", "device10")
    for d in ("device01",) + others:
        r.check("baseline", f"{d} FULL_ACCESS data plane", matches(r.probe(d, "baseline"), "FULL_ACCESS", has_ops(d)))
    r.report["records"] = {k: dict(evidence_id=v["evidence_id"], status=v["status"], proposed_state=v["proposed_state"], trust=(v["fusion"] or {}).get("trust"), hard_gate=(v["fusion"] or {}).get("hard_gate_applied"),
                                   identity_status=v["identity"]["status"], identity_provenance=v["identity"]["provenance"], device=v["annotations"]["decision_pipeline"]["route"]["device"],
                                   evidence_class=v["annotations"]["decision_pipeline"]["evidence"]["class"]) for k, v in records.items()}
    r.report["records"]["note"] = "genuine integrated-engine output over SYNTHETIC evidence; the engine, its configuration and the hard gate are unchanged"

    # ---- the operational guard still refuses the very same records (no approval exists); the behaviour calibration is not asked for on the identity path
    s, op = "operational_still_blocked", IdentityStream(r, "op")
    op.write([gate, behavioural])
    res = op.process(mode="operational", policy="deny")
    handled = op.handled()
    r.check(s, "the operational guard refuses both records and the persistent process consumes them", res["code"] == 0 and res["counts"] == {"REFUSED": 2}, pep=res["counts"], stderr=res["stderr"])
    r.check(s, "the identity-gate record is refused for the missing registry and configuration approvals, NOT for a calibration",
            len(handled) == 2 and handled[0]["reason"] == "OPERATIONAL_APPROVALS_MISSING" and "ACCEPTED_CALIBRATION" not in handled[0].get("detail", "")
            and "CONTROLLER_APPROVED_DEVICE_REGISTRY" in handled[0].get("detail", ""), detail=handled[0].get("detail") if handled else None)
    r.check(s, "the ordinary behavioural record is still refused and still needs the calibration", len(handled) == 2 and handled[1]["reason"] == "OPERATIONAL_APPROVALS_MISSING"
            and "ACCEPTED_CALIBRATION" in handled[1].get("detail", ""), detail=handled[1].get("detail") if len(handled) > 1 else None)
    r.check(s, "no command was sent and the policy digest is unchanged", op.commands_sent() == 0 and r.audit_digest("after-operational") == (verdict, baseline))
    r.check(s, "device01 is still FULL_ACCESS", matches(r.probe("device01", "after-operational-refusal"), "FULL_ACCESS", True))

    # ---- the repaired path on the isolated broker
    s, ig = "identity_quarantine", IdentityStream(r, "ig")
    ig.write([gate])
    res = ig.process(mode="test-only-identity-gate", policy="deny")
    handled = ig.handled()
    r.check(s, "an attributable identity failure of device01 is applied as QUARANTINE and broker-verified", res["code"] == 0 and res["counts"] == {"APPLIED_VERIFIED": 1} and handled[0]["device"] == "device01"
            and handled[0]["desired_state"] == "QUARANTINE", pep=res["counts"], stderr=res["stderr"])
    r.check(s, "the broker refuses device01's connection (QUARANTINE data plane)", matches(r.probe("device01", "identity-quarantine"), "QUARANTINE", True))
    for d in others:
        r.check("unaffected_continuity", f"{d} unchanged while device01 is quarantined by the identity gate", matches(r.probe(d, "during-identity-quarantine"), "FULL_ACCESS", has_ops(d)))
    state = r.observe()
    r.check(s, "a fresh broker observation shows exactly device01 quarantined", bool(state) and state["devices"]["device01"]["states"] == ["QUARANTINE"]
            and all("FULL_ACCESS" in d["states"] for k, d in state["devices"].items() if k != "device01"))
    request = [e for e in r.audit_entries(ig.audit) if e["kind"] == "REQUEST_RECEIVED"]
    gate_ref = (request[0]["body"]["evidence_ref"] or {}).get("identity_gate") if request else None
    r.check(s, "the audit log carries the identity evidence that attributed the device (status, audit reference, policy digest, bound principal)",
            bool(gate_ref) and gate_ref["audit_ref"].endswith(":device01") and gate_ref["bound_username"] == "azta-device-01" and gate_ref["identity_status"] == "REVOKED", identity_gate=gate_ref)
    sent = ig.commands_sent()
    r.check(s, "exactly two commands were sent (disableClient, removeClientRole of the operations role)", sent == 2, commands_sent=sent)

    s = "idempotence"
    again = ig.process(mode="test-only-identity-gate", policy="deny")
    r.check(s, "re-reading the same file after a restart repeats nothing", again["code"] == 0 and again["counts"] == {}, pep=again["counts"])
    ig.write([gate, second])                                                           # the same evidence id again, then a second verdict (UNAUTHORIZED) for the same device
    res = ig.process(mode="test-only-identity-gate", policy="deny")
    r.check(s, "a repeated evidence id is skipped and a second REVOKED verdict for the already-quarantined device is held", res["counts"] == {"duplicate_skipped": 1, "HELD": 1}, pep=res["counts"])
    r.check(s, "no further command was sent", ig.commands_sent() == sent, commands_sent=ig.commands_sent())

    # ---- forged or untrusted attribution never changes any device
    s = "attribution_refused"
    before = r.audit_digest("before-forged")
    ig.write(list(forged.values()) + [behavioural])
    res = ig.process(mode="test-only-identity-gate", policy="deny")
    handled = ig.handled()[-len(forged) - 1:]
    expected = {"idg-forged-username": "ATTRIBUTION_BINDING_MISMATCH", "idg-forged-route": "ATTRIBUTION_BINDING_MISMATCH", "idg-rogue": "ATTRIBUTION_BINDING_MISMATCH",
                "idg-unenrolled": "ATTRIBUTION_DEVICE_NOT_ENROLLED", "idg-broker-wide-d01": "IDENTITY_FAILURE_NOT_DEVICE_ATTRIBUTABLE",
                "idg-broker-wide-d02": "IDENTITY_FAILURE_NOT_DEVICE_ATTRIBUTABLE", "idg-unattributed": "ATTRIBUTION_MISSING", "idg-live-shaped": "IDENTITY_PROVENANCE_NOT_ACCEPTED",
                "idg-behavioural": "RECORD_NOT_AN_IDENTITY_GATE_DECISION"}
    r.check(s, "all forged, unenrolled, rogue, unattributed, live-shaped, behavioural and broker-wide-finding (UNAUTHORIZED) records are refused with their specific reason",
            res["code"] == 0 and res["counts"] == {"REFUSED": len(expected)} and {h["evidence_id"]: h["reason"] for h in handled} == expected, pep=res["counts"],
            reasons={h["evidence_id"]: h["reason"] for h in handled})
    r.check(s, "no command was sent for any of them and the policy digest is unchanged", ig.commands_sent() == sent and r.audit_digest("after-forged") == before)
    for d in others:
        r.check(s, f"{d} (a target of the forgeries) still has its FULL_ACCESS data plane", matches(r.probe(d, "after-forged"), "FULL_ACCESS", has_ops(d)))
    state = r.observe()
    r.check(s, "the broker shows exactly device01 quarantined and nothing else changed", bool(state) and state["devices"]["device01"]["states"] == ["QUARANTINE"]
            and all("FULL_ACCESS" in d["states"] for k, d in state["devices"].items() if k != "device01"))

    # ---- a second device, with a held session that the broker must end
    s = "second_device"
    ready = r.run_dir / "probes" / "hold-ready.txt"
    holder = r.docker(["run", "--rm", "--no-deps", "-T", "eng-probe", "hold", "--device", "device02", "--seconds", "90", "--ready-file", "/results/probes/hold-ready.txt", "--out",
                       "/results/probes/hold-identity-quarantine.json"], profile="operator", popen=True)
    for _ in range(240):
        if ready.exists():
            break
        time.sleep(0.5)
    r.check(s, "a device02 session is established before its identity failure is enforced", ready.exists())
    ig.write([gate02])
    res = ig.process(mode="test-only-identity-gate", policy="deny")
    holder.communicate(timeout=180)
    out = r.run_dir / "probes" / "hold-identity-quarantine.json"
    held = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
    r.check(s, "device02's identity failure is applied and the broker ended its active session with a server DISCONNECT", res["counts"] == {"APPLIED_VERIFIED": 1}
            and held.get("ended_by") == "server_disconnect", pep=res["counts"], ended_by=held.get("ended_by"))
    r.check(s, "device02 is refused at connection", matches(r.probe("device02", "identity-quarantine"), "QUARANTINE", True))
    r.check(s, "device01 remains quarantined", matches(r.probe("device01", "still-quarantined"), "QUARANTINE", True))
    for d in ("device03", "device05", "device10"):
        r.check("unaffected_continuity", f"{d} unchanged while device01 and device02 are quarantined", matches(r.probe(d, "during-two-quarantines"), "FULL_ACCESS", has_ops(d)))

    # ---- administrative RESTORE and restoration
    s = "restore"
    for d in ("device01", "device02"):
        rest = ig.restore(d)
        r.check(s, f"the administrative RESTORE returns {d} to FULL_ACCESS, broker-verified", rest["code"] == 0 and rest["result"].get("status") == "APPLIED_VERIFIED", pep=rest["result"])
        r.check(s, f"the restored {d} has its baseline data plane", matches(r.probe(d, "restored"), "FULL_ACCESS", True))
    verdict, final = r.audit_digest("final")
    r.check("restoration", "the final binding audit PASSes", verdict == "PASS")
    r.check("restoration", "the broker policy digest equals the pre-test baseline (semantic restoration)", final == baseline, baseline=baseline, final=final)
    final_state = r.observe()
    r.check("restoration", "every device is back in FULL_ACCESS", bool(final_state) and all("FULL_ACCESS" in d["states"] for d in final_state["devices"].values()))
    return baseline, final, t0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)
    r = Run(args.run_id)
    inventory_before = docker_inventory()
    baseline, final, t0 = run_all(r)
    inventory_after = docker_inventory()
    r.check("integrity", "the preserved research broker's container state and the research volume are unchanged", inventory_before["research_broker"] == inventory_after["research_broker"]
            and "azta-journal_mosquitto_data" in inventory_after["volumes"])
    failed = [c for c in CHECKS if not c[2]]
    r.report.update(finished_utc=utc(), duration_s=round(time.time() - t0, 1), checks=len(CHECKS), failed=len(failed), baseline_policy_sha256=baseline, final_policy_sha256=final,
                    docker_before=inventory_before, docker_after=inventory_after,
                    claims="repaired identity-gate hand-off mechanics (synthetic decisions, isolated broker); not detection, not calibrated trust, not attack containment, no approval granted")
    (r.run_dir / "live_identity_gate_report.json").write_text(json.dumps(r.report, sort_keys=True, indent=1) + "\n", encoding="utf-8")
    print(f"LIVE_IDENTITY_GATE checks={len(CHECKS)} failed={len(failed)} report=results/engineering/runs/{args.run_id}/live_identity_gate_report.json")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
