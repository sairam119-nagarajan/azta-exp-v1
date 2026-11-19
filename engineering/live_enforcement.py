"""Host-side driver of the live TEST_ONLY enforcement verification on the isolated engineering broker (Path B).

    python -m engineering.live_enforcement --run-id ID [--real-decisions FILE]

It generates explicitly synthetic TEST_ONLY decision streams, hands them to the PEP container (the only holder of the administrative credential here), and after every state
change checks what the broker ALLOWS with the data-plane probe controller: the connection, a publication to the own telemetry topic, to the own operations topic and to another
device's topic, two subscriptions, and delivery to a receive-only observer and the operations receiver. It demonstrates that the PEP applies, verifies and restores permissions on a
real Mosquitto Dynamic Security broker; it demonstrates NOTHING about detection accuracy, calibrated trust scoring or attack containment. The decisions are synthetic, labelled
TEST_ONLY_SYNTHETIC_ENGINEERING and refused by the operational guard; the PEP refuses TEST_ONLY requests on any broker that lacks the isolation sentinel.

Scenarios (each check is recorded with its expectation and the observed outcome in `live_enforcement_report.json`):
  baseline                           every probed device's FULL_ACCESS data plane and the policy digest
  full_restrict_quarantine_restore   device01 (has an operations entitlement) through every transition and an administrative RESTORE, probed after each step
  telemetry_only_device              device03 (no operations entitlement): RESTRICT is a permission no-op (reported as such), QUARANTINE and an authorized return
  unaffected_continuity              other devices keep their exact data plane while device01 / device03 change
  persistence_window                 an explicit two-proposal confirmation window holds the first proposal and applies the second
  stale_and_duplicate                a stale decision is held; a repeated evidence id is applied once; re-reading the file after a restart repeats nothing
  restart_resume                     a second PEP process over the same audit log resumes at the cursor without repeating a command
  active_session_termination         a held session is ended by the broker's server DISCONNECT on QUARANTINE
  drift_reconciliation               an out-of-band operator change is detected at the next start and the belief is dropped
  real_decisions_refused             real shadow decision records are refused with OPERATIONAL_APPROVALS_MISSING and the policy digest is unchanged
  restoration                        the broker policy digest equals the pre-test baseline
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

from engineering import env
from enforcement.engineering import scenario
from enforcement.guard import HARNESS_TOKEN

ROOT = env.ROOT
COMPOSE = env.compose_prefix()
OPS = "device01,device02"
BROKER = "azta-eng-broker-1"
REGISTRY = "/app/configs/observation/device_registry_v2.json"
CHECKS = []


def utc():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def last_json(text):
    line = next((l for l in reversed(text.splitlines()) if l.startswith("{")), None)
    return json.loads(line) if line else None


class Run:
    def __init__(self, run_id):
        self.run_dir = env.make_run_dir(run_id)
        self.run_id = run_id
        self.report = dict(run_id=run_id, started_utc=utc(), scenarios={})
        self.counter = 0

    def docker(self, args, *, profile, timeout=600, popen=False):
        command = COMPOSE + ["--profile", profile] + list(args)
        environment = dict(os.environ, ENG_RUN_DIR="./" + self.run_dir.relative_to(ROOT).as_posix(), MSYS_NO_PATHCONV="1")
        if popen:
            return subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
        return subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=timeout, env=environment)

    # ------------------------------------------------------------------------------------------------------------ recording
    def check(self, scenario_name, label, ok, **detail):
        CHECKS.append((scenario_name, label, bool(ok)))
        self.report["scenarios"].setdefault(scenario_name, []).append(dict(check=label, ok=bool(ok), **detail))
        print(f"  [{'PASS' if ok else 'FAIL'}] {scenario_name}: {label}", flush=True)
        return ok

    # ------------------------------------------------------------------------------------------------------------ broker side
    def audit_digest(self, stage):
        out = self.docker(["run", "--rm", "--no-deps", "-T", "binding-audit", "--run-id", f"{self.run_id}-audit-{stage}", "--registry", REGISTRY], profile="operator")
        match = re.search(r"BINDING_AUDIT (\w+) run_id=\S+ policy_sha256=([0-9a-f]{64})", out.stdout)
        return (match.group(1), match.group(2)) if match else ("ERROR", out.stderr[-200:])

    def pep_args(self, command, audit=None):
        args = ["run", "--rm", "--no-deps", "-T", "eng-pep", command, "--registry", REGISTRY, "--operations-devices", OPS, "--credential-file", "/run/secrets/azta-pep-admin-credential",
                "--host", "broker", "--max-attempts", "3"]
        return args + (["--audit-log", f"/results/pep/{audit}"] if audit else [])

    def observe(self):
        return last_json(self.docker(self.pep_args("observe"), profile="enforce").stdout)

    def restore(self, device, audit):
        out = self.docker(self.pep_args("restore", audit) + ["--device", device, "--confirm-device", device, "--operator-ref", "engineering-test-restore"], profile="enforce")
        return dict(code=out.returncode, result=last_json(out.stdout) or {})

    def probe(self, device, phase):
        self.counter += 1
        name = f"{self.counter:03d}-{phase}-{device}.json"
        out = self.docker(["run", "--rm", "--no-deps", "-T", "eng-probe", "matrix", "--device", device, "--phase", phase, "--out", f"/results/probes/{name}"], profile="operator")
        path = self.run_dir / "probes" / name
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else dict(error=(out.stderr or out.stdout)[-200:])

    def drift(self, device, action):
        out = self.docker(["run", "--rm", "--no-deps", "-T", "eng-provision", "drift", "--device", device, "--drift-action", action], profile="operator")
        text = out.stdout.strip().replace("ENGINEERING_PROVISION DRIFT ", "")
        try:
            return out.returncode, json.loads(text.splitlines()[-1]) if text else None
        except ValueError:
            return out.returncode, None

    def broker_container(self, verb):
        """Stop or start the ONE isolated engineering broker container (never anything else): its label is verified first, and its data volume is untouched."""
        label = subprocess.run(["docker", "inspect", "--format", "{{index .Config.Labels \"com.azta.engineering\"}}", BROKER], capture_output=True, text=True, timeout=60)
        if label.stdout.strip() != "isolated-engineering-broker":
            raise RuntimeError("refusing to act on a container that is not the labelled isolated engineering broker")
        if verb not in ("stop", "start"):
            raise ValueError("only stop and start of the engineering broker are issued")
        return subprocess.run(["docker", verb, BROKER], capture_output=True, text=True, timeout=120).returncode

    def wait_for_broker(self, seconds=120):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            state = self.observe()
            if state:
                return state
            time.sleep(2)
        return None

    def stream(self, name):
        return Stream(self, name)

    def audit_entries(self, audit):
        path = self.run_dir / "pep" / audit
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


class Stream:
    """One append-only decision file and the audit log that follows it (the runner's cursor binds the two): the shape of a persistent enforcement run."""

    def __init__(self, run, name):
        self.run, self.name, self.appended = run, name, 0
        self.path = run.run_dir / "decisions" / f"{name}.jsonl"
        self.audit = f"audit-{name}.jsonl"

    def append(self, steps, *, age_ns=0, spacing_ns=1_000_000):
        self.appended += 1
        records = scenario(f"{self.name}-a{self.appended}", steps, time.time_ns() - age_ns, spacing_ns)
        with open(self.path, "a", encoding="utf-8", newline="\n") as stream:
            for record in records:
                stream.write(json.dumps(record, sort_keys=True) + "\n")

    def append_raw_copy_of_last_line(self):
        last = self.path.read_text(encoding="utf-8").splitlines()[-1]
        with open(self.path, "a", encoding="utf-8", newline="\n") as stream:
            stream.write(last + "\n")

    def _run_args(self, mode, escalate, deescalate, age_s, policy, follow_s=None):
        args = self.run.pep_args("run", self.audit) + ["--decisions", f"/results/decisions/{self.name}.jsonl", "--mode", mode, "--escalate-after", str(escalate),
                                                       "--deescalate-after", str(deescalate), "--max-decision-age-s", str(age_s), "--deescalation-policy", policy]
        if follow_s:
            args += ["--follow-seconds", str(follow_s), "--poll-interval-s", "0.5"]
        if mode == "test-only":
            args += ["--harness-token", HARNESS_TOKEN]
        return args

    def process(self, *, mode="test-only", escalate=1, deescalate=1, age_s=3600, policy="allow"):
        out = self.run.docker(self._run_args(mode, escalate, deescalate, age_s, policy), profile="enforce")
        parsed = last_json(out.stdout)
        return dict(code=out.returncode, counts=(parsed or {}).get("counts"), result=parsed, stderr=out.stderr[-300:] if out.returncode else "")

    def follow(self, seconds, *, mode="test-only", escalate=1, deescalate=1, age_s=3600, policy="allow"):
        """A persistent process: it keeps tailing the decision file for `seconds` while the host appends to it. Returns the running process."""
        return self.run.docker(self._run_args(mode, escalate, deescalate, age_s, policy, seconds), profile="enforce", popen=True)

    def append_lines(self, lines):
        with open(self.path, "a", encoding="utf-8", newline="\n") as stream:
            stream.write("".join(line if line.endswith("\n") else line + "\n" for line in lines))

    def restore(self, device):
        return self.run.restore(device, self.audit)

    def commands_sent(self):
        return sum(1 for e in self.run.audit_entries(self.audit) if e["kind"] == "COMMAND_SENT")


def matches(probe, state, has_ops):
    """The probe outcome equals the data plane the state must give: FULL_ACCESS allows the own telemetry (and operations if entitled) publications; RESTRICT only telemetry;
    QUARANTINE refuses the connection. Another device's topic and every subscription are denied in every state."""
    if "error" in probe:
        return False
    if state == "QUARANTINE":
        return probe.get("connack") not in (0, None) and not probe.get("publishes")
    if probe.get("connack") != 0:
        return False
    p, subs = probe["publishes"], probe["subscribes"]
    expected_ops = (0, True) if (state == "FULL_ACCESS" and has_ops) else (135, False)
    return ((p["own_telemetry"]["puback"], p["own_telemetry"]["delivered_to_listener"]) == (0, True) and (p["other_telemetry"]["puback"], p["other_telemetry"]["delivered_to_listener"]) == (135, False)
            and (p["own_operations"]["puback"], p["own_operations"]["delivered_to_listener"]) == expected_ops
            and (subs["own_telemetry"]["suback"], subs["wildcard"]["suback"]) == (135, 135))


def run_all(r, real_decisions):
    t0 = time.time()
    others = ("device02", "device04", "device10")

    def has_ops(device):
        return device in ("device01", "device02")

    verdict, baseline = r.audit_digest("baseline")
    r.check("baseline", "read-only binding audit PASS under registry v2", verdict == "PASS", policy_sha256=baseline)
    state = r.observe()
    r.check("baseline", "the PEP attests the isolated engineering broker and sees all ten devices in FULL_ACCESS",
            bool(state) and state["environment"] == "ENGINEERING_ISOLATED" and len(state["devices"]) == 10 and all("FULL_ACCESS" in d["states"] for d in state["devices"].values()))
    for d in ("device01", "device03") + others:
        r.check("baseline", f"{d} FULL_ACCESS data plane", matches(r.probe(d, "baseline"), "FULL_ACCESS", has_ops(d)))

    # ---- device01 through every transition and the administrative restore
    s, seq = "full_restrict_quarantine_restore", r.stream("seq")
    seq.append([("device01", "RESTRICT")])
    res = seq.process()
    r.check(s, "FULL_ACCESS -> RESTRICT applied and broker-verified", res["code"] == 0 and res["counts"] == {"APPLIED_VERIFIED": 1}, pep=res["counts"], stderr=res["stderr"])
    r.check(s, "RESTRICT: the operations publication is denied, telemetry is still delivered", matches(r.probe("device01", "restrict"), "RESTRICT", True))
    for d in others:
        r.check("unaffected_continuity", f"{d} unchanged while device01 is RESTRICT", matches(r.probe(d, "during-restrict"), "FULL_ACCESS", has_ops(d)))
    seq.append([("device01", "QUARANTINE")])
    res = seq.process()
    r.check(s, "RESTRICT -> QUARANTINE applied and broker-verified", res["code"] == 0 and res["counts"] == {"APPLIED_VERIFIED": 1}, pep=res["counts"], stderr=res["stderr"])
    r.check(s, "QUARANTINE: the broker refuses the connection", matches(r.probe("device01", "quarantine"), "QUARANTINE", True))
    for d in others:
        r.check("unaffected_continuity", f"{d} unchanged while device01 is QUARANTINE", matches(r.probe(d, "during-quarantine"), "FULL_ACCESS", has_ops(d)))
    seq.append([("device01", "FULL_ACCESS")])
    res = seq.process()
    r.check(s, "QUARANTINE -> FULL_ACCESS as a DECISION is refused (only the administrative RESTORE leaves quarantine)", res["code"] == 0 and res["counts"] == {"REFUSED": 1}, pep=res["counts"])
    r.check(s, "device01 is still quarantined after the refused return", matches(r.probe("device01", "after-refused-return"), "QUARANTINE", True))
    rest = seq.restore("device01")
    r.check(s, "the administrative RESTORE returns device01 to FULL_ACCESS, broker-verified", rest["code"] == 0 and rest["result"].get("status") == "APPLIED_VERIFIED", pep=rest["result"])
    r.check(s, "the restored device01 has its baseline data plane (operations delivered again)", matches(r.probe("device01", "restored"), "FULL_ACCESS", True))
    r.check(s, "exactly the four expected commands were sent (removeClientRole, disableClient, enableClient, addClientRole); the refused return sent none",
            seq.commands_sent() == 4, commands_sent=seq.commands_sent())

    # ---- a device with a telemetry-only entitlement
    s, tel = "telemetry_only_device", r.stream("tel")
    tel.append([("device03", "RESTRICT")])
    res = tel.process()
    r.check(s, "RESTRICT of a device without an operations entitlement changes no permission (NOOP, permission-equivalent)", res["code"] == 0 and res["counts"] == {"NOOP_ALREADY_IN_STATE": 1},
            pep=res["counts"])
    r.check(s, "device03 data plane is unchanged under RESTRICT", matches(r.probe("device03", "restrict"), "RESTRICT", False))
    tel.append([("device03", "QUARANTINE")])
    res = tel.process()
    r.check(s, "device03 QUARANTINE applied", res["code"] == 0 and res["counts"] == {"APPLIED_VERIFIED": 1}, pep=res["counts"])
    r.check(s, "the broker refuses device03's connection", matches(r.probe("device03", "quarantine"), "QUARANTINE", False))
    r.check("unaffected_continuity", "device04 and device02 unchanged while device03 is QUARANTINE",
            all(matches(r.probe(d, "during-d03-quarantine"), "FULL_ACCESS", has_ops(d)) for d in ("device04", "device02")))
    tel.append([("device03", "RESTRICT")])
    res = tel.process(policy="deny")
    r.check(s, "with de-escalation not authorized, the return is REFUSED and the device stays quarantined", res["counts"] == {"REFUSED": 1}
            and matches(r.probe("device03", "refused-return"), "QUARANTINE", False), pep=res["counts"])
    tel.append([("device03", "RESTRICT")])
    res = tel.process(policy="allow")
    r.check(s, "with de-escalation explicitly authorized, QUARANTINE -> RESTRICT re-enables only the client", res["code"] == 0 and res["counts"] == {"APPLIED_VERIFIED": 1}, pep=res["counts"])
    r.check(s, "device03 has its baseline data plane again", matches(r.probe("device03", "returned"), "FULL_ACCESS", False))

    # ---- persistence window, stale and duplicate decisions
    s, per = "persistence_window", r.stream("per")
    per.append([("device04", "QUARANTINE"), ("device04", "QUARANTINE")])
    res = per.process(escalate=2)
    r.check(s, "a two-proposal confirmation window holds the first proposal and applies the second", res["code"] == 0 and res["counts"] == {"CONFIRMING": 1, "APPLIED_VERIFIED": 1}, pep=res["counts"])
    r.check(s, "device04 is quarantined only after the confirmation", matches(r.probe("device04", "persisted"), "QUARANTINE", False))
    per.append([("device04", "RESTRICT")])
    per.process(escalate=2, deescalate=1)
    r.check(s, "device04 returned to its baseline data plane", matches(r.probe("device04", "persisted-restored"), "FULL_ACCESS", False))

    s, stale = "stale_and_duplicate", r.stream("stale")
    stale.append([("device10", "QUARANTINE")], age_ns=2 * 3600 * 1_000_000_000)
    res = stale.process(age_s=60)
    r.check(s, "a stale decision is HELD and never applied", res["counts"] == {"HELD": 1}, pep=res["counts"])
    r.check(s, "device10 is still FULL_ACCESS", matches(r.probe("device10", "after-stale"), "FULL_ACCESS", False))
    dup = r.stream("dup")
    dup.append([("device10", "QUARANTINE")])
    dup.append_raw_copy_of_last_line()
    res = dup.process()
    r.check(s, "a repeated evidence id is applied once and skipped the second time", res["counts"] == {"APPLIED_VERIFIED": 1, "duplicate_skipped": 1}, pep=res["counts"])
    res2 = dup.process()
    r.check(s, "re-reading the same file after a restart repeats nothing", res2["code"] == 0 and res2["counts"] == {}, pep=res2["counts"])
    r.check(s, "exactly one command was sent for the repeated decision", dup.commands_sent() == 1, commands_sent=dup.commands_sent())
    dup.append([("device10", "RESTRICT")])
    dup.process()
    r.check(s, "device10 returned to its baseline data plane", matches(r.probe("device10", "dup-restored"), "FULL_ACCESS", False))

    # ---- restart / resume over one decision stream and one audit log
    s, resume = "restart_resume", r.stream("res")
    resume.append([("device04", "QUARANTINE")])
    first = resume.process()
    resume.append([("device04", "RESTRICT")])
    second = resume.process()
    r.check(s, "the first process applied the quarantine; the restarted process handled only the NEW record", first["counts"] == {"APPLIED_VERIFIED": 1}
            and second["counts"] == {"APPLIED_VERIFIED": 1}, first=first["counts"], second=second["counts"])
    r.check(s, "no command was repeated across the restart (disable, then enable)", resume.commands_sent() == 2, commands_sent=resume.commands_sent())
    r.check(s, "device04 has its baseline permissions", matches(r.probe("device04", "resumed"), "RESTRICT", False))

    # ---- active session termination
    s, term = "active_session_termination", r.stream("term")
    ready = r.run_dir / "probes" / "hold-ready.txt"
    holder = r.docker(["run", "--rm", "--no-deps", "-T", "eng-probe", "hold", "--device", "device01", "--seconds", "90", "--ready-file", "/results/probes/hold-ready.txt", "--out",
                       "/results/probes/hold-quarantine.json"], profile="operator", popen=True)
    for _ in range(240):
        if ready.exists():
            break
        time.sleep(0.5)
    r.check(s, "a device session is established before the quarantine", ready.exists())
    term.append([("device01", "QUARANTINE")])
    res = term.process()
    holder.communicate(timeout=180)
    out = r.run_dir / "probes" / "hold-quarantine.json"
    held = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
    r.check(s, "the broker ended the active session with a server DISCONNECT when the device was quarantined", res["counts"] == {"APPLIED_VERIFIED": 1} and held.get("ended_by") == "server_disconnect",
            disconnect=held.get("disconnect"), ended_by=held.get("ended_by"))
    rest = term.restore("device01")
    r.check(s, "device01 restored after the session test", rest["result"].get("status") == "APPLIED_VERIFIED" and matches(r.probe("device01", "after-session-test"), "FULL_ACCESS", True))

    # ---- drift detected at the next start
    s, drift = "drift_reconciliation", r.stream("drift")
    drift.append([("device02", "RESTRICT")])
    drift.process()
    code, info = r.drift("device02", "add-operation-role")
    r.check(s, "an out-of-band operator change was injected (operations role re-added to a RESTRICT device)", code == 0 and info is not None and info.get("result") == "DRIFT_INJECTED", detail=info)
    drift.append([("device02", "RESTRICT")])
    res = drift.process()
    found = [e for e in r.audit_entries(drift.audit) if e["kind"] == "RECONCILIATION" and e["body"].get("drift")]
    r.check(s, "the next start detects the drift and drops the recorded belief", len(found) == 1 and found[0]["body"]["device"] == "device02" and found[0]["body"]["believed"] == "RESTRICT")
    r.check(s, "the next decision re-applies RESTRICT from the broker's real state", res["counts"] == {"APPLIED_VERIFIED": 1} and matches(r.probe("device02", "after-drift"), "RESTRICT", True),
            pep=res["counts"])
    rest = drift.restore("device02")
    r.check(s, "device02 restored", rest["result"].get("status") == "APPLIED_VERIFIED" and matches(r.probe("device02", "after-drift-restore"), "FULL_ACCESS", True))

    # ---- the broker is unavailable: the outcome is unknown and said so, nothing is lost, recovery applies the pending decision exactly once
    s, down = "broker_unavailable_and_restart", r.stream("outage")
    down.append([("device04", "QUARANTINE")])
    r.check(s, "the isolated engineering broker is stopped (its labelled container only; the data volume is untouched)", r.broker_container("stop") == 0)
    res = down.process()
    entries = r.audit_entries(down.audit)
    r.check(s, "with the broker down the PEP refuses to act (no authenticated control session), applies nothing and records no outcome", res["code"] == 2 and "CONTROL" in res["stderr"]
            and not [e for e in entries if e["kind"] in ("OUTCOME", "COMMAND_SENT")], stderr=res["stderr"])
    r.check(s, "the pending decision is not consumed: the cursor did not move", not [e for e in entries if e["kind"] == "CURSOR"])
    r.check(s, "the broker is started again and answers", r.broker_container("start") == 0 and r.wait_for_broker() is not None)
    verdict, digest = r.audit_digest("after-restart")
    r.check(s, "the policy survived the stop and start unchanged (digest equals the baseline)", (verdict, digest) == ("PASS", baseline), digest=digest)
    res = down.process()
    r.check(s, "the pending decision is applied exactly once after recovery", res["code"] == 0 and res["counts"] == {"APPLIED_VERIFIED": 1} and down.commands_sent() == 1, pep=res["counts"])
    r.check(s, "device04 is quarantined by the broker that was restarted", matches(r.probe("device04", "after-restart"), "QUARANTINE", False))
    state = r.wait_for_broker()
    r.check(s, "a fresh observation after the restart still shows exactly device04 quarantined", bool(state) and state["devices"]["device04"]["states"] == ["QUARANTINE"]
            and all("FULL_ACCESS" in d["states"] for k, d in state["devices"].items() if k != "device04"))
    restarted = r.broker_container("stop") == 0 and r.broker_container("start") == 0 and r.wait_for_broker() is not None      # a second outage, now WITH a recorded belief
    down.append([("device04", "RESTRICT")])
    res = down.process(policy="allow")
    r.check(s, "after a second restart the next start reconciles the recorded belief with the persisted broker state, and the authorized return applies",
            restarted and res["counts"] == {"APPLIED_VERIFIED": 1} and matches(r.probe("device04", "after-return"), "FULL_ACCESS", False), pep=res["counts"])
    reconciliations = [e for e in r.audit_entries(down.audit) if e["kind"] == "RECONCILIATION"]
    r.check(s, "the reconciliation compared a recorded QUARANTINE belief with the restarted broker and found no drift",
            len(reconciliations) >= 1 and reconciliations[-1]["body"]["believed"] == "QUARANTINE" and not reconciliations[-1]["body"]["drift"])

    # ---- real decisions are refused
    s = "real_decisions_refused"
    if real_decisions:
        lines = [l for l in Path(real_decisions).read_text(encoding="utf-8").splitlines() if l.strip()]
        real = r.stream("real")
        real.path.write_text("", encoding="utf-8")
        before = r.audit_digest("before-real")
        # a persistent process tails the growing file while the host appends the genuine decisions in batches (the shape of a continuous live feed)
        holder = real.follow(40, mode="operational", policy="deny", age_s=7 * 86400)
        time.sleep(6)
        batch = max(1, len(lines) // 6)
        for start in range(0, len(lines), batch):
            real.append_lines(lines[start:start + batch])
            time.sleep(2)
        out, err = holder.communicate(timeout=300)
        parsed = last_json(out)
        counts = (parsed or {}).get("counts") or {}
        total = sum(counts.values())
        r.check(s, "every genuine shadow decision, appended while the persistent process was already running, is consumed and refused; none is applied",
                holder.returncode == 0 and total == len(lines) and counts == {"REFUSED": len(lines)}, records=len(lines), pep=counts, stderr=err[-200:] if holder.returncode else "")
        handled = [e for e in r.audit_entries(real.audit) if e["kind"] == "RECORD_HANDLED"]
        expected_ids = [json.loads(l)["evidence_id"] for l in lines]
        r.check(s, "records were handled in file order, one per decision, none twice", len(handled) == len(lines) and [h["body"]["evidence_id"] for h in handled] == expected_ids)
        stamps = [h["body"]["timing"]["record_seen_utc_ns"] for h in handled]
        r.check(s, "every record carries its own processing timestamp and they never go backwards", len(stamps) == len(lines) and stamps == sorted(stamps) and stamps[-1] > stamps[0])
        cursors = [e for e in r.audit_entries(real.audit) if e["kind"] == "CURSOR"]
        r.check(s, "the recorded byte cursor ends exactly at the end of the decision file", bool(cursors) and cursors[-1]["body"]["offset"] == real.path.stat().st_size)
        reasons = {e["body"].get("reason") for e in handled}
        r.check(s, "the only refusal reason is OPERATIONAL_APPROVALS_MISSING", reasons == {"OPERATIONAL_APPROVALS_MISSING"}, reasons=sorted(str(x) for x in reasons))
        r.check(s, "no command was sent for any genuine decision", real.commands_sent() == 0)
        r.check(s, "the broker policy digest is unchanged by the genuine decisions", r.audit_digest("after-real") == before)
        again = real.process(mode="operational", policy="deny", age_s=7 * 86400)
        r.check(s, "a restarted process over the same audit log and file repeats nothing", again["code"] == 0 and again["counts"] == {}, pep=again["counts"])
    else:
        r.check(s, "no real decision file was supplied (check skipped, not passed)", True, skipped=True)

    # ---- restoration
    verdict, final = r.audit_digest("final")
    r.check("restoration", "the final binding audit PASSes", verdict == "PASS")
    r.check("restoration", "the broker policy digest equals the pre-test baseline (semantic restoration)", final == baseline, baseline=baseline, final=final)
    final_state = r.observe()
    r.check("restoration", "every device is back in FULL_ACCESS", bool(final_state) and all("FULL_ACCESS" in d["states"] for d in final_state["devices"].values()))
    return baseline, final, t0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--real-decisions", help="a decisions.jsonl of REAL shadow decisions (copied into the run) to be refused by the operational guard")
    args = parser.parse_args(argv)
    r = Run(args.run_id)
    baseline, final, t0 = run_all(r, args.real_decisions)
    failed = [c for c in CHECKS if not c[2]]
    r.report.update(finished_utc=utc(), duration_s=round(time.time() - t0, 1), checks=len(CHECKS), failed=len(failed), baseline_policy_sha256=baseline, final_policy_sha256=final,
                    claims="TEST_ONLY synthetic enforcement mechanics on an isolated broker; not detection, not calibrated trust, not attack containment")
    (r.run_dir / "live_enforcement_report.json").write_text(json.dumps(r.report, sort_keys=True, indent=1) + "\n", encoding="utf-8")
    print(f"LIVE_ENFORCEMENT checks={len(CHECKS)} failed={len(failed)} report=results/engineering/runs/{args.run_id}/live_enforcement_report.json")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
