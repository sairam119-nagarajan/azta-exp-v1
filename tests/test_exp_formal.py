"""Formal Experimental Validation (AZTA-EXP-v1, addendum 1), offline tests: the experiment matrix, the REAL formal drivers against a simulated PEP and owner (no broker, Docker or
network), the validity rules on synthetic run records, the reserved-run loader's equivalence with the frozen loader, the aggregator's consistency with the frozen metric tool, the
approval-record guards and the addendum's frozen-directory check."""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "rehearsal_tools"), str(ROOT / "tests")]

import exp_matrix                                # noqa: E402
import exp_operator as eo                        # noqa: E402
import exp_validity                              # noqa: E402
import exp_session                               # noqa: E402
from test_stb_rehearsal_replay import PepWorld, S, CONFIRM_S   # noqa: E402

MATRIX = json.loads((ROOT / exp_matrix.MATRIX).read_text(encoding="utf-8"))


class MatrixTests(unittest.TestCase):
    def test_the_committed_matrix_recomputes_identically(self):
        self.assertEqual((ROOT / exp_matrix.MATRIX).read_bytes(), exp_matrix.dump(exp_matrix.build()).encode("utf-8"))

    def test_five_repetitions_of_every_applicable_kind_on_every_device(self):
        """Addendum 2: jitter exists only for the devices whose frozen law has a jitter fraction (01-04, 10); devices 05-09 stay benign in their jitter slot."""
        counts, skipped = {}, {}
        jitter_devices = {"device01", "device02", "device03", "device04", "device10"}
        for r, spec in MATRIX["runs"].items():
            if spec["component"] == "DETECTION":
                for e in spec["episodes"]:
                    counts[(e["device"], e["kind"])] = counts.get((e["device"], e["kind"]), 0) + 1
                for n in spec["not_applicable"]:
                    skipped[(n["device"], n["kind"])] = skipped.get((n["device"], n["kind"]), 0) + 1
                self.assertEqual(sorted([e["device"] for e in spec["episodes"]] + [n["device"] for n in spec["not_applicable"]]), MATRIX["devices"], r)
        self.assertEqual(len(counts), 45)
        self.assertEqual(set(counts.values()), {5})
        self.assertEqual(sum(counts.values()), 225)
        self.assertEqual({d for d, k in counts if k == "jitter"}, jitter_devices)
        self.assertEqual(skipped, {(d, "jitter"): 5 for d in MATRIX["devices"] if d not in jitter_devices})
        self.assertEqual(MATRIX["counts"]["detection_episodes"], 225)

    def test_every_planned_start_is_accepted_by_the_live_workload_check(self):
        """The check the addendum-1 tests lacked (exp-s01/s02 VOID): the frozen live workload's own applicability rule, on each run's own plan, accepts every planned START."""
        from engineering import fleet_workload as fw
        for r, spec in MATRIX["runs"].items():
            for e in spec.get("episodes") or []:
                if e.get("device") is None or e["kind"] == "context":
                    continue
                plan = json.loads((ROOT / f"configs/collection_plans/core_final_{r.replace('-', '_')}.json").read_text(encoding="utf-8"))["runs"][r]
                fw.check_command_applicable(plan, e["device"], e["kind"])                # raises ControlRefused for an inapplicable START
            if spec["mode"] == "active-authorized" and spec.get("episodes"):
                plan = json.loads((ROOT / f"configs/collection_plans/core_final_{r.replace('-', '_')}.json").read_text(encoding="utf-8"))["runs"][r]
                for e in spec["episodes"]:
                    if e["kind"] in exp_matrix.KINDS:
                        fw.check_command_applicable(plan, "device02", e["kind"])
        for device in MATRIX["devices"]:                                                  # the matrix's rule agrees with the live check on every device
            plan = json.loads((ROOT / "configs/collection_plans/core_final_exp_s01.json").read_text(encoding="utf-8"))["runs"]["exp-s01"]
            try:
                fw.check_command_applicable(plan, device, "jitter")
                live = True
            except Exception:
                live = False
            self.assertEqual(exp_matrix.applicable(device, "jitter"), live, device)

    def test_episode_timings_fit_the_session_and_cover_two_native_windows(self):
        for spec in MATRIX["runs"].values():
            for e in spec.get("episodes") or []:
                if e.get("device") is None or e["duration_s"] is None:
                    continue
                width = MATRIX["widths_s"][e["device"]]
                self.assertLessEqual(e["onset_s"] + e["duration_s"], 640)
                if e["kind"] == "silence":
                    self.assertGreaterEqual(e["duration_s"], 3 * width + 10 + 60)          # past the liveness bound with a margin (stb-l03: review 10 s after the bound)
                else:
                    self.assertGreaterEqual(e["duration_s"], 2 * width)

    def test_sci_rotation_and_spares(self):
        sci = [s for s in MATRIX["runs"].values() if s["component"] == "SCI"]
        self.assertEqual(len(sci), 5)
        silent = [e["device"] for s in sci for e in s["episodes"] if e["kind"] == "silence"]
        cut = [s["time_cut_device"] for s in sci]
        self.assertEqual(len(set(silent + cut)), 10)
        for n in range(41, 46):
            self.assertEqual(MATRIX["runs"][f"exp-s{n}"]["time_cut_device"], MATRIX["runs"][f"exp-s{n - 15}"]["time_cut_device"])

    def test_active_block(self):
        active = [s for r, s in MATRIX["runs"].items() if s["mode"] == "active-authorized" and s["component"] == "ENFORCEMENT"]
        kinds = [e["kind"] for s in active for e in s["episodes"]]
        for k in exp_matrix.KINDS + ("context", "identity"):
            self.assertEqual(kinds.count(k), 5, k)
        for s in active:
            has_context = any(e["kind"] == "context" for e in s["episodes"])
            self.assertEqual(bool(s["time_cut_after_s"]), has_context)
            self.assertEqual(s["episodes"][-1]["kind"] in ("context", "identity"), any(e["kind"] in ("context", "identity") for e in s["episodes"]))

    def test_batches_cover_every_run_once(self):
        listed = [r for b in MATRIX["batches"].values() for r in b]
        self.assertEqual(sorted(listed), sorted(MATRIX["runs"]))
        self.assertEqual(len(listed), len(set(listed)))


class ShadowWorld:
    """A fake control channel and PEP log for the shadow driver."""

    def __init__(self, end_s=720.0, pep=None):
        self.now, self.end_s, self.events, self.timeline, self.said, self.pep = 0.0, end_s, [], [], [], list(pep or [])

    def offset_s(self):
        return self.now

    def owner_present(self):
        return True

    def running(self):
        return self.now < self.end_s

    def entries(self):
        return list(self.pep)

    def record(self, item):
        self.timeline.append(dict(item, utc_ns=int(self.now * S)))

    def say(self, text):
        self.said.append(text)

    def attack(self, action, device, anomaly, params):
        self.events.append(dict(t=self.now, action=action, device=device, anomaly=anomaly, params=params))
        return True, "ok"

    def sleep(self, seconds):
        self.now += seconds


class ShadowDriverTests(unittest.TestCase):
    def test_a_detection_session_runs_every_episode_on_time_with_renewals(self):
        spec = MATRIX["runs"]["exp-s01"]
        world = ShadowWorld()
        self.assertEqual(eo.ShadowScenario(world, episodes=spec["episodes"]).run(), 0)
        for e in spec["episodes"]:
            mine = [x for x in world.events if x["device"] == e["device"]]
            starts = [x for x in mine if x["action"] == "start"]
            self.assertAlmostEqual(starts[0]["t"], e["onset_s"], delta=1.5)
            self.assertTrue(all(x["anomaly"] == e["kind"] and x["params"] == e["params"] for x in starts))
            self.assertAlmostEqual(mine[-1]["t"] - starts[0]["t"], e["duration_s"], delta=2.5)
            self.assertEqual(mine[-1]["action"], "stop")
            gaps = [b["t"] - a["t"] for a, b in zip(starts, starts[1:])]
            self.assertTrue(all(g <= 120 for g in gaps))
        self.assertFalse([t for t in world.timeline if t["step"] == "TIME_CUT_DECLARED"])

    def test_silence_is_one_segment_and_the_context_cut_names_its_device(self):
        spec = MATRIX["runs"]["exp-s30"]
        world = ShadowWorld()
        eo.ShadowScenario(world, episodes=spec["episodes"], time_cut_utc_ns=123, time_cut_device=spec["time_cut_device"]).run()
        silent = [e for e in spec["episodes"] if e["kind"] == "silence"][0]
        mine = [x for x in world.events if x["device"] == silent["device"]]
        self.assertEqual([x["action"] for x in mine], ["start", "stop"])
        cut = [t for t in world.timeline if t["step"] == "TIME_CUT_DECLARED"]
        self.assertEqual(cut[0]["device"], spec["time_cut_device"])
        self.assertFalse([x for x in world.events if x["device"] == spec["time_cut_device"]], "the context device is never commanded")

    def test_any_pep_request_halts_a_shadow_session(self):
        world = ShadowWorld(pep=[dict(kind="REQUEST_RECEIVED", body={})])
        self.assertEqual(eo.ShadowScenario(world, episodes=MATRIX["runs"]["exp-s02"]["episodes"]).run(), 3)


class FormalWorld(PepWorld):
    """PepWorld for the formal device02 block: every behavioural kind but `drop` is contained automatically after CONFIRM_S; `drop` never (a censored episode); the declared
    revocation opens an IDENTITY_HARD_GATE QUARANTINE review."""

    def __init__(self, cut_s=None, **kw):
        super().__init__(**kw)
        self.next_context_at = (cut_s + CONFIRM_S) if cut_s else float("inf")
        self.revoked_at = None

    def revoke(self, device):
        self.revoked_at = self.now
        return 0

    def sleep(self, seconds):
        super().sleep(seconds)
        since = self.anomalous_since.get("device02")
        kind = self.anomaly.get("device02")
        if kind and kind not in ("payload", "drop") and since is not None and self.now - since >= CONFIRM_S and self.state["device02"] == "FULL_ACCESS" and "device02" not in self.recovery_until:
            self.n_req += 1
            self.apply("device02", "QUARANTINE", f"op-device02-w{self.n_req:03d}")
        if self.revoked_at is not None and self.now - self.revoked_at >= 30 and "device02" not in self.pending and self.state["device02"] == "FULL_ACCESS":
            self.open_review("device02", "QUARANTINE", "IDENTITY_HARD_GATE")
            self.revoked_at = None


def run_active(run_id):
    spec = MATRIX["runs"][run_id]
    cut = spec.get("time_cut_after_s")
    world = FormalWorld(cut_s=cut)
    code = eo.FormalActiveScenario(world, episodes=spec["episodes"], time_cut_utc_ns=int(cut * S) if cut else None, time_cut_offset_s=cut, episode_max_s=MATRIX["active"]["episode_max_s"]).run()
    return code, world, spec


class ActiveDriverTests(unittest.TestCase):
    def closed(self, world):
        told = {t["n"] for t in world.timeline if t["step"] == "INSTRUCTION"}
        done = {t["n"] for t in world.timeline if t["step"] == "INSTRUCTION_DONE"}
        cancelled = {t["n"] for t in world.timeline if t["step"] == "INSTRUCTION_CANCELLED"}
        return told, done, cancelled

    def test_a_context_session(self):
        code, world, spec = run_active("exp-a01")
        self.assertEqual(code, 0)
        told, done, cancelled = self.closed(world)
        self.assertEqual(told, done)
        self.assertFalse(cancelled)
        steps = [t["step"] for t in world.timeline]
        self.assertEqual(steps.count("EPISODE_START"), len(spec["episodes"]))
        self.assertEqual(world.state["device02"], "RESTRICT")
        self.assertIn("TIME_CUT_DECLARED", steps)
        self.assertNotIn("EPISODES_ABANDONED", steps)

    def test_an_identity_session_and_a_censored_drop(self):
        run_id = next(r for r, s in MATRIX["runs"].items() if s["component"] == "ENFORCEMENT" and any(e["kind"] == "identity" for e in s["episodes"]) and any(e["kind"] == "drop" for e in s["episodes"]))
        code, world, spec = run_active(run_id)
        self.assertEqual(code, 0)
        steps = [t["step"] for t in world.timeline]
        self.assertNotIn("TIME_CUT_DECLARED", steps, "a session without a context episode declares no withdrawal")
        self.assertIn("EPISODE_CENSORED", steps)
        self.assertIn("REVOCATION", steps)
        told, done, cancelled = self.closed(world)
        self.assertEqual(told, done)
        self.assertEqual(world.state["device02"], "FULL_ACCESS")
        self.assertEqual(steps.count("EPISODE_START"), len(spec["episodes"]))

    def test_a_missed_restore_abandons_the_remaining_episodes_and_is_recorded(self):
        spec = MATRIX["runs"]["exp-a11"]
        world = FormalWorld(owner_skips={1})
        code = eo.FormalActiveScenario(world, episodes=spec["episodes"], time_cut_utc_ns=None, time_cut_offset_s=None, episode_max_s=MATRIX["active"]["episode_max_s"]).run()
        steps = [t["step"] for t in world.timeline]
        self.assertIn("INSTRUCTION_CANCELLED", steps)
        self.assertIn("EPISODES_ABANDONED", steps)
        self.assertEqual(code, 0)


class ValidityTests(unittest.TestCase):
    def make(self, tmp, run_id, *, audits_ok=True, pep=(), applied=True, post_digest=exp_validity.BASELINE, cancelled=False):
        root = Path(tmp)
        (root / "configs/formal").mkdir(parents=True)
        shutil.copy(ROOT / exp_matrix.MATRIX, root / exp_matrix.MATRIX)
        spec = MATRIX["runs"][run_id]
        run_dir = root / "results/engineering/runs" / run_id
        (run_dir / "logs").mkdir(parents=True)
        digest = exp_validity.BASELINE if audits_ok else "0" * 64
        (run_dir / "logs/orchestrator.log").write_text(f"x audit-pre exit=0 BINDING_AUDIT PASS run_id=a policy_sha256={digest}\nx observer_failed=False observer_exit=0 workload_exit=0\n", encoding="utf-8")
        obs = run_dir / "observation/obs-1"
        obs.mkdir(parents=True)
        (obs / "session_summary.json").write_text(json.dumps(dict(state="COMPLETE")), encoding="utf-8")
        (run_dir / "control").mkdir()
        rows = [dict(kind="COMMAND_APPLIED", action="start", device=e.get("device", "device02"), anomaly=e["kind"]) for e in spec["episodes"] if e["kind"] not in ("context", "identity")] if applied else []
        (run_dir / "control/events.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        (run_dir / "pep").mkdir()
        (run_dir / "pep/continuous.jsonl").write_text("".join(json.dumps(r) + "\n" for r in pep), encoding="utf-8")
        out = root / "results/engineering/pilot" / run_id
        out.mkdir(parents=True)
        timeline = [dict(step="SCENARIO_ENDED", halted=False)] + ([dict(step="INSTRUCTION_CANCELLED")] if cancelled else [])
        (out / "operator_timeline.jsonl").write_text("".join(json.dumps(r) + "\n" for r in timeline), encoding="utf-8")
        (out / "post_state.json").write_text(json.dumps(dict(final_audit_policy_sha256=post_digest, final_audit_pass=True, down_exit=0, down_used_v=False, volume_kept=True,
                                                             protected_fingerprints_unchanged=True, post_probes_ok=True)), encoding="utf-8")
        side = root / "results/engineering/pilot" / f"{run_id}-session"
        side.mkdir(parents=True)
        (side / "session_run.json").write_text(json.dumps(dict(launcher_exit=0, driver_exit=0, coverage_reached=True, policy_changed_in_shadow=False)), encoding="utf-8")
        (root / "results/engineering/formal").mkdir(parents=True)
        (root / "results/engineering/formal" / f"preconditions_{run_id}.json").write_text(json.dumps(dict(all_pass=True)), encoding="utf-8")
        return root

    def test_valid_void_and_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(exp_validity.validity("exp-s01", root=self.make(tmp, "exp-s01"))["status"], "VALID")
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(exp_validity.validity("exp-s01", root=self.make(tmp, "exp-s01", applied=False))["status"], "VOID")
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(exp_validity.validity("exp-s01", root=self.make(tmp, "exp-s01", pep=[dict(kind="OUTCOME", body={})]))["status"], "STOP")
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(exp_validity.validity("exp-s01", root=self.make(tmp, "exp-s01", audits_ok=False))["status"], "STOP")
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(exp_validity.validity("exp-s01", root=self.make(tmp, "exp-s01", post_digest="1" * 64))["status"], "STOP")

    def test_a_cancelled_owner_instruction_voids_an_active_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.make(tmp, "exp-a11", cancelled=True)
            result = exp_validity.validity("exp-a11", root=root)
            self.assertEqual(result["status"], "VOID")
            self.assertIn("no_cancelled_owner_instruction", result["failed"])


class CampaignRuleTests(unittest.TestCase):
    def test_spares_follow_the_declared_rule(self):
        import exp_campaign as ec
        spares = MATRIX["batches"]["S2"]
        spares = [r for r in spares if MATRIX["runs"][r]["component"] == "SPARE"]
        self.assertEqual(ec.spare_for("exp-s27", MATRIX["runs"]["exp-s27"], spares, set()), "exp-s42")
        self.assertEqual(ec.spare_for("exp-s12", MATRIX["runs"]["exp-s12"], spares, set()), "exp-s39")
        self.assertEqual(ec.spare_for("exp-s12", MATRIX["runs"]["exp-s12"], spares, {"exp-s39", "exp-s40"}), None)
        self.assertIsNone(ec.spare_for("exp-s27", MATRIX["runs"]["exp-s27"], spares, {"exp-s42"}))

    def test_a_stop_continues_only_after_the_owners_recorded_review(self):
        """Addendum 2: a ledger ending with STOP refuses to continue without --after-review naming a recorded owner answer; with one, a REVIEWED row is appended first (here the
        stop file then halts before any run, so nothing is started)."""
        import exp_campaign as ec
        saved = ec.LEDGER, ec.STOP_FILE, ec.reviewed
        with tempfile.TemporaryDirectory() as d:
            ec.LEDGER, ec.STOP_FILE = Path(d) / "ledger.jsonl", Path(d) / "CAMPAIGN_STOP"
            ec.LEDGER.write_text(json.dumps(dict(run_id="exp-s01", status="VOID", failed=["x"])) + "\n" + json.dumps(dict(run_id="exp-s02", status="VOID", failed=["x"])) + "\n"
                                 + json.dumps(dict(run_id="exp-s02", status="STOP")) + "\n", encoding="utf-8")
            try:
                self.assertEqual(ec.main(["--batch", "S1", "--source-commit", "c"]), 4)
                self.assertEqual(ec.main(["--batch", "S1", "--source-commit", "c", "--after-review", "NO-SUCH-ANSWER"]), 4)
                self.assertEqual(len(exp_validity.jsonl(ec.LEDGER)), 3)
                ec.reviewed = lambda ref: dict(request="FORMAL_ADDENDUM_2", answer_ref=ref) if ref == "OWNER-REF" else None
                ec.STOP_FILE.write_text("halt before any run\n", encoding="utf-8")
                self.assertEqual(ec.main(["--batch", "S1", "--source-commit", "c", "--after-review", "OWNER-REF"]), 5)
                rows = exp_validity.jsonl(ec.LEDGER)
                self.assertEqual([r["status"] for r in rows[3:]], ["REVIEWED", "NOT_STARTED"])
                self.assertEqual(rows[3]["answer_ref"], "OWNER-REF")
            finally:
                ec.LEDGER, ec.STOP_FILE, ec.reviewed = saved


class SessionRuleTests(unittest.TestCase):
    def test_only_the_recorded_authorization_may_change_after_the_answer(self):
        self.assertTrue(exp_session.allowed_after_answer("configs/formal/approvals/FORMAL_SHADOW_S1/exp-s01/session_approval_exp-s01.json"))
        self.assertTrue(exp_session.allowed_after_answer("configs/formal/sessions/exp-a01.json"))
        self.assertFalse(exp_session.allowed_after_answer("configs/formal/sessions/exp-s01.json"))
        self.assertFalse(exp_session.allowed_after_answer("rehearsal_tools/exp_operator.py"))
        self.assertFalse(exp_session.allowed_after_answer("configs/exp_v1/trust_config_exp_v1.json"))


class SessionRunFlowTests(unittest.TestCase):
    """`exp_session.session_run` and `finish` with every outside effect replaced: no broker, Docker, process or network. Checks the launcher and driver command lines and the summary."""

    def test_a_shadow_run_and_its_finish(self):
        import stb_live_session as sls
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            launched = []

            class FakeProc:
                def __init__(self, command, **kw):
                    launched.append(command)
                    self.pid, self.command = 4242, command
                    if "core_runtime" in command:
                        log = root / "results/engineering/runs/exp-s26/logs"
                        log.mkdir(parents=True, exist_ok=True)
                        (log / "orchestrator.log").write_text("coverage start observed\n", encoding="utf-8")
                        out = root / "results/engineering/pilot/exp-s26"
                        out.mkdir(parents=True, exist_ok=True)
                        (out / "launch.json").write_text(json.dumps(dict(started_utc="2026-11-12T10:00:00.000000000Z")), encoding="utf-8")

                def poll(self):
                    return 0 if len(launched) >= 2 else None

                def wait(self):
                    return 0

                def kill(self):
                    pass

            formal = root / "results/engineering/formal"
            formal.mkdir(parents=True)
            approval = "configs/formal/approvals/FORMAL_SHADOW_S2/exp-s26/session_approval_exp-s26.json"
            (formal / "preconditions_exp-s26.json").write_text(json.dumps(dict(all_pass=True, approval=approval, approval_sha256="abc")), encoding="utf-8")
            saved = dict(ROOT=sls.ROOT, sha=sls.sha, containers=sls.containers, probe=sls.probe, enforced=sls.enforced_states, binding=sls.binding_audit, fp=sls.fingerprints, run=sls.run,
                         popen=subprocess.Popen, formal=exp_session.FORMAL_OUT, sroot=exp_session.ROOT)
            try:
                sls.ROOT, exp_session.ROOT, exp_session.FORMAL_OUT = root, root, formal
                (root / "configs/formal/sessions").mkdir(parents=True)
                shutil.copy(ROOT / "configs/formal/sessions/exp-s26.json", root / "configs/formal/sessions/exp-s26.json")
                (root / "configs/formal").joinpath("exp_matrix_v1.json").write_bytes((ROOT / exp_matrix.MATRIX).read_bytes())
                exp_session.bind("exp-s26")
                sls.sha = lambda path: "abc"
                sls.containers = lambda: [sls.BROKER]
                sls.probe = lambda phase, devices: (sls.SIDE.mkdir(parents=True, exist_ok=True), True)[1]
                sls.enforced_states = lambda: {d: dict(states=["FULL_ACCESS"]) for d in sls.DEVICES}
                sls.binding_audit = lambda ref: dict(passed=True, policy_sha256=sls.BASELINE, exit=0)
                sls.fingerprints = lambda: True
                sls.run = lambda command, **kw: type("R", (), dict(returncode=0, stdout="desktop-linux azta-pilot_mosquitto_data", stderr=""))()
                subprocess.Popen = FakeProc
                exp_session.time.sleep = lambda s: None
                args = type("A", (), dict(run="exp-s26", as_run=None, restore=None, answer_ref="X"))()
                self.assertEqual(exp_session.session_run(args), 0)
                launcher, driver = launched
                self.assertEqual(launcher[launcher.index("--mode") + 1], "shadow")
                self.assertEqual(launcher[launcher.index("--approval") + 1], approval)
                self.assertEqual(driver[driver.index("--mode") + 1], "shadow")
                self.assertIn("--time-cut-utc-ns", driver)
                self.assertNotIn("--presence-file", driver)
                summary = json.loads((sls.SIDE / "session_run.json").read_text(encoding="utf-8"))
                self.assertFalse(summary["policy_changed_in_shadow"])
                self.assertEqual(exp_session.finish(args), 0)
                post = json.loads((sls.OUT / "post_state.json").read_text(encoding="utf-8"))
                self.assertTrue(post["baseline_restored"])
                self.assertFalse(post["down_used_v"])
                args.restore = ["device02"]
                self.assertEqual(exp_session.finish(args), 2, "a shadow session restores nothing")
            finally:
                sls.ROOT, sls.sha, sls.containers, sls.probe, sls.enforced_states = saved["ROOT"], saved["sha"], saved["containers"], saved["probe"], saved["enforced"]
                sls.binding_audit, sls.fingerprints, sls.run, subprocess.Popen = saved["binding"], saved["fp"], saved["run"], saved["popen"]
                exp_session.FORMAL_OUT, exp_session.ROOT = saved["formal"], saved["sroot"]
                import time as _time
                exp_session.time.sleep = _time.sleep


class ReservedLoaderTests(unittest.TestCase):
    def test_the_reserved_loader_reads_a_readable_run_exactly_as_the_frozen_loader(self):
        import exp_test_score as ts
        from hybrid import events as ev
        if not (ev.RUNS / "g6c-d06").exists():
            self.skipTest("development run g6c-d06 not present")
        a = ev.load_prelive_assignment()
        frozen = ev.load_run("g6c-d06", a)
        mine = ts.load_reserved("g6c-d06", a)
        self.assertEqual(frozen, mine)

    def test_the_frozen_loader_still_refuses_the_reserved_role(self):
        from hybrid import events as ev
        with self.assertRaises(ev.RoleRefused):
            ev.role_of(ev.load_prelive_assignment(), "g6c-d07")


class AggregatorConsistencyTests(unittest.TestCase):
    def test_the_regrouped_windows_reproduce_the_frozen_tool_on_development_runs(self):
        import exp_aggregate as ag
        import exp_metrics as em
        widths = em.route_widths(ag.ROUTE)
        checked = 0
        for run_id in ("stb-l05", "stb-s02"):
            run_dir = ROOT / "results/engineering/runs" / run_id
            if not (run_dir / "service/inbox.jsonl").exists():
                continue
            cut = ag.time_cut(run_id)
            doc = em.evaluate(run_dir, widths, time_cut_ns=cut)
            rows, excluded, segs, latencies, recs = ag.windows_of(run_dir, widths, cut)
            self.assertEqual(doc["windows"], dict(positive=sum(w["label"] == "POSITIVE" for w in rows), negative=sum(w["label"] == "NEGATIVE" for w in rows), excluded=excluded))
            det = ag.confusion(rows, ag.flag)
            for k in ("tp", "fp", "tn", "fn"):
                self.assertEqual(det[k], doc["metric_2_3_fpr_fnr"]["a_detector_flag_windows"][k])
            dec = ag.confusion(rows, ag.decided)
            for k in ("tp", "fp", "tn", "fn"):
                self.assertEqual(dec[k], doc["metric_2_3_fpr_fnr"]["b_ae_decision_windows"][k])
            checked += 1
        if not checked:
            self.skipTest("no development run present")


class AddendumTests(unittest.TestCase):
    def test_nothing_was_added_to_a_frozen_directory(self):
        import exp_addendum
        self.assertEqual(exp_addendum.added_to_frozen_directories(), [])

    def test_every_new_script_is_pinned(self):
        import exp_addendum
        pinned = exp_addendum.pinned_paths()
        for name in ("exp_matrix", "exp_operator", "exp_session", "exp_validity", "exp_campaign", "exp_approve", "exp_test_score", "exp_aggregate", "exp_addendum"):
            self.assertIn(f"rehearsal_tools/{name}.py", pinned)
        self.assertIn(exp_matrix.MATRIX, pinned)


if __name__ == "__main__":
    unittest.main()
