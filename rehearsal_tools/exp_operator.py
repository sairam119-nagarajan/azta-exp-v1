"""Formal Experimental Validation (AZTA-EXP-v1, addendum 1): the scenario drivers of the formal sessions, built on the frozen operator machinery (`core_pilot_operator.Scenario`,
`RealIO`, and the amendment 3/4 instruction machinery of `stb_live_operator.StabilizationScenario`), with the episodes read from the committed experiment matrix.

    python -I -B rehearsal_tools/exp_operator.py --run-id exp-s01 --mode shadow [--time-cut-utc-ns N]
    python -I -B rehearsal_tools/exp_operator.py --run-id exp-a01 --mode active --time-cut-utc-ns N --presence-file FILE [--as exp-a03]

shadow  no owner and no policy change: each scheduled episode is started at its onset on the session's coverage clock and stopped after its duration (behavioural anomalies renewed
        within the 120 s segment limit; a silence is ONE segment, never renewed). Any PEP request or outcome is a stop condition (a shadow session changes nothing).
active  device02 only, the owner at the console: for each behavioural episode the anomaly runs until a verified automatic containment (or `episode_max_s`, then censored), the owner
        RESTOREs (numbered instruction), the recovery window closes and 40 s of healthy reporting follow; a context episode waits for the declared withdrawal and a reviewed RESTRICT the
        owner approves (left RESTRICTED, probed after the session); an identity episode is the declared revocation of device02, a reviewed QUARANTINE the owner approves, then RESTORE.
        `--as` runs a spare under the episodes of the VOID run it replaces.
It holds no console credential and writes no intent. Exit codes as the frozen drivers: 0 ran to its end, 3 a stop condition, 2 the run never reported RUNNING.
"""
import argparse
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "rehearsal_tools")]

import core_pilot_operator as op                   # noqa: E402
import stb_live_operator as sl                     # noqa: E402
from engineering import attack_control as ac       # noqa: E402

MATRIX = "configs/formal/exp_matrix_v1.json"
GAP_S = 20.0
IDENTITY_REVIEW_WAIT_S = 180.0
CONTEXT_REVIEW_WAIT_S = 200.0
NOT_BEFORE_IDENTITY_S = 400.0


def matrix(root=ROOT):
    return json.loads((root / MATRIX).read_text(encoding="utf-8"))


def spec_of(run_id, as_run=None, root=ROOT):
    m = matrix(root)
    spec = m["runs"][as_run or run_id]
    if spec.get("episodes") is None:
        raise SystemExit(f"{run_id} is a spare: give the VOID run it replaces with --as")
    return m, spec


class ShadowIO(op.RealIO):
    """No owner exists in a shadow session; nothing waits for one."""

    def owner_present(self):
        return True

    def revoke(self, device):
        raise RuntimeError("no revocation in a shadow session")


class ShadowScenario(op.Scenario):
    def __init__(self, io, *, episodes, time_cut_utc_ns=None, time_cut_device=None):
        super().__init__(io, time_cut_utc_ns=time_cut_utc_ns)
        self.scope = tuple(sorted({e["device"] for e in episodes}))
        self.time_cut_device = time_cut_device
        self.scripts = [self.episode(e) for e in episodes if e["kind"] != "context"]

    def watch(self):
        """A shadow session makes no request: any REQUEST_RECEIVED, COMMAND_SENT or OUTCOME halts the driver (it is a stop condition of the campaign as well)."""
        if not self.halted and any(x.get("kind") in ("REQUEST_RECEIVED", "COMMAND_SENT", "OUTCOME") for x in self.entries):
            self.halt("a PEP request or outcome in a shadow session")

    def episode(self, e):
        yield from self.at(e["onset_s"])
        spec = dict(anomaly=e["kind"], params=dict(e["params"]))
        self.note("EPISODE_START", device=e["device"], kind=e["kind"], planned_onset_s=e["onset_s"], planned_duration_s=e["duration_s"])
        if not self.start(e["device"], spec):
            self.note("EPISODE_NOT_STARTED", device=e["device"], kind=e["kind"])
            return
        began, segment = self.offset(), self.offset()
        while not self.halted and self.offset() - began < e["duration_s"]:
            if e["kind"] != "silence" and self.offset() - segment >= op.MAX_SEGMENT_S - 5:
                self.stop(e["device"])
                if not self.start(e["device"], spec):
                    self.note("EPISODE_RENEWAL_FAILED", device=e["device"], kind=e["kind"])
                    return
                segment = self.offset()
            yield
        self.stop(e["device"])
        self.note("EPISODE_END", device=e["device"], kind=e["kind"], ran_s=round(self.offset() - began, 1))

    def run(self):
        if self.time_cut_utc_ns:
            self.note("TIME_CUT_DECLARED", device=self.time_cut_device, effective_utc_ns=self.time_cut_utc_ns)
        scripts = list(self.scripts)
        while self.io.running():
            self.entries = self.io.entries()
            self.watch()
            for script in list(scripts):
                try:
                    next(script)
                except StopIteration:
                    scripts.remove(script)
            self.io.sleep(1.0)
        self.entries = self.io.entries()
        self.watch()
        for device in list(self.active):
            self.stop(device)
        self.note("SCENARIO_ENDED", halted=self.halted, unfinished=len(scripts))
        return 3 if self.halted else 0


class FormalActiveScenario(sl.StabilizationScenario):
    """device02 only; the episodes of one matrix entry, in order."""

    def __init__(self, io, *, episodes, time_cut_utc_ns, time_cut_offset_s, episode_max_s):
        super().__init__(io, time_cut_utc_ns=time_cut_utc_ns, time_cut_offset_s=time_cut_offset_s)
        self.scope = ("device02",)
        self.episodes, self.episode_max_s = episodes, episode_max_s
        self.has_context = any(e["kind"] == "context" for e in episodes)
        self.scripts = [self.device02_formal()]

    def run(self):
        """The frozen loop, except that a declared withdrawal is recorded only when the session has one: the frozen base always records one for device02, and the metric tool would
        then exempt every later device02 containment from the false-containment count. Open instructions are cancelled at the end (amendment 3)."""
        if self.has_context:
            self.note("TIME_CUT_DECLARED", device="device02", effective_utc_ns=self.time_cut_utc_ns)
        scripts = list(self.scripts)
        while self.io.running():
            self.entries = self.io.entries()
            self.watch()
            for script in list(scripts):
                try:
                    next(script)
                except StopIteration:
                    scripts.remove(script)
            self.io.sleep(1.0)
        self.entries = self.io.entries()
        self.watch()
        for device in list(self.active):
            self.stop(device)
        self.note("SCENARIO_ENDED", halted=self.halted, unfinished=len(scripts))
        for n in sorted(self.open_instructions):
            self.cancel(n, "the session ended before it was completed")
        return 3 if self.halted else 0

    def device02_formal(self):
        yield from self.at(45)
        for i, e in enumerate(self.episodes, start=1):
            if self.halted:
                return
            kind = e["kind"]
            if kind == "context":
                ok = yield from self.context_episode(i)
            elif kind == "identity":
                ok = yield from self.identity_episode(i)
            else:
                ok = yield from self.behavioural_episode(i, kind)
            if not ok:
                self.note("EPISODES_ABANDONED", after_episode=i, remaining=len(self.episodes) - i)
                return
            yield from self.pause(GAP_S)

    def behavioural_episode(self, i, kind):
        mark = len(self.entries)
        spec = dict(anomaly=kind, params=dict(matrix()["anomaly_parameters"][kind]))
        self.note("EPISODE_START", device="device02", kind=kind, index=i)
        hit = yield from self.anomaly_until("device02", spec, lambda: self.outcome_since("device02", mark, ("QUARANTINE", "RESTRICT")), self.episode_max_s)
        if not hit:
            self.note("EPISODE_CENSORED", device="device02", kind=kind, index=i, after_s=self.episode_max_s)
            return True
        state = hit["body"].get("desired_state")
        self.note("EPISODE_CONTAINED", device="device02", kind=kind, index=i, state=state, request_id=hit["body"].get("request_id"))
        yield from self.pause(sl.HOLD_S)
        if not (yield from self.restore_step("device02", mark, cause=f"its automatic AE {state} ({kind} anomaly, now stopped)", step=f"episode {i}: {kind}, restore")):
            return False
        mark = len(self.entries)
        closed = yield from self.wait_for(lambda: self.recovery_closed_since("device02", mark), 60)
        self.note("RECOVERY_WINDOW", device="device02", index=i, closed=bool(closed), a_ae=(closed or {}).get("body", {}).get("a_ae"))
        yield from self.pause(40)
        self.note("AFTER_RESTORE_HEALTHY", device="device02", index=i, recontained=bool(self.outcome_since("device02", mark, ("QUARANTINE", "RESTRICT"))))
        return True

    def context_episode(self, i):
        yield from self.at(self.time_cut_offset_s)
        mark = len(self.entries)
        self.expecting.add("device02")
        self.note("EPISODE_START", device="device02", kind="context", index=i)
        review = yield from self.wait_for(lambda: self.review_since("device02", mark, "CONTEXT_POLICY"), CONTEXT_REVIEW_WAIT_S)
        self.note("CONTEXT_REVIEW", device="device02", index=i, review=bool(review), applied_before_review=bool(self.outcome_kind_since("device02", mark, ("RESTRICT",))), review_id=(review or {}).get("review_id"))
        if not review:
            self.expecting.discard("device02")
            return True
        self.claimed.add(review["review_id"])
        n = self.instruct(action="APPROVE ONCE the RESTRICT review of device02", device="device02", cause="CONTEXT_POLICY (its operating time was withdrawn); check the cause shown is context",
                          step=f"episode {i}: context violation; do NOT restore device02 afterwards", review_id=review["review_id"])
        began, done = self.offset(), None
        while not self.halted and self.offset() - began < 280:
            done = self.outcome_since("device02", mark, ("RESTRICT",))
            if done:
                break
            lost = self.review_state(review["review_id"], ("SUPERSEDED", "EXPIRED", "REJECTED"))
            if lost:
                self.cancel(n, f"review {review['review_id']} was {lost.get('state')} ({lost.get('reason')})")
                self.expecting.discard("device02")
                self.note("CONTEXT_REVIEW_LOST", device="device02", index=i, review_id=review["review_id"], state=lost.get("state"))
                return False
            yield
        self.note("CONTEXT_RESTRICT", device="device02", index=i, verified=bool(done))
        if done:
            self.done(n, "the context RESTRICT of device02 is verified at the broker; it stays RESTRICTED until the session ends")
        else:
            self.cancel(n, "no verified context RESTRICT of device02 in time")
        self.expecting.discard("device02")
        return bool(done)

    def identity_episode(self, i):
        yield from self.at(NOT_BEFORE_IDENTITY_S)
        if self.halted:
            return False
        mark = len(self.entries)
        self.expecting.add("device02")
        code = self.io.revoke("device02")
        self.note("EPISODE_START", device="device02", kind="identity", index=i)
        self.note("REVOCATION", device="device02", index=i, exit=code)
        review = yield from self.wait_for(lambda: self.review_since("device02", mark, "IDENTITY_HARD_GATE"), IDENTITY_REVIEW_WAIT_S)
        self.note("IDENTITY_REVIEW", device="device02", index=i, review=bool(review), review_id=(review or {}).get("review_id"))
        if not review:
            self.expecting.discard("device02")
            return False
        self.claimed.add(review["review_id"])
        n = self.instruct(action="APPROVE ONCE the QUARANTINE review of device02", device="device02", cause="IDENTITY_HARD_GATE (its credential was revoked by the scenario)",
                          step=f"episode {i}: identity revocation", review_id=review["review_id"])
        done = yield from self.wait_for(lambda: self.outcome_since("device02", mark, ("QUARANTINE",)), 280)
        if done:
            self.done(n, "the identity QUARANTINE of device02 is verified at the broker")
        else:
            self.cancel(n, "no verified identity QUARANTINE of device02 in time")
            self.expecting.discard("device02")
            return False
        yield from self.pause(sl.HOLD_S)
        restored = yield from self.restore_step("device02", len(self.entries), cause="its identity quarantine (the declared revocation)", step=f"episode {i}: identity, restore")
        self.expecting.discard("device02")
        return bool(restored)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--mode", choices=("shadow", "active"), required=True)
    parser.add_argument("--time-cut-utc-ns", type=int, default=None)
    parser.add_argument("--presence-file", default=None)
    parser.add_argument("--as", dest="as_run", default=None, help="a spare runs the episodes of the VOID run it replaces")
    parser.add_argument("--wait-s", type=float, default=1800)
    args = parser.parse_args(argv)
    m, spec = spec_of(args.run_id, args.as_run)
    if (spec["mode"] == "shadow") != (args.mode == "shadow"):
        raise SystemExit("the mode does not match the matrix")
    out = ROOT / "results/engineering/pilot" / args.run_id
    if args.mode == "shadow":
        io = ShadowIO(args.run_id, out, out / "no_presence_in_shadow")
    else:
        if not args.presence_file:
            raise SystemExit("an active session needs --presence-file")
        if any(e["kind"] == "context" for e in spec["episodes"]) != (args.time_cut_utc_ns is not None):
            raise SystemExit("--time-cut-utc-ns is given exactly when the session has a context episode")
        io = op.RealIO(args.run_id, out, args.presence_file)
    deadline = time.monotonic() + args.wait_s
    while (ac.read_status(io.directory) or {}).get("phase") != "RUNNING":
        if time.monotonic() >= deadline:
            io.say("the run never reported RUNNING; nothing was sent")
            return 2
        time.sleep(1)
    if args.mode == "shadow":
        io.say(f"Formal shadow session {args.run_id} ({spec['component']}{' as ' + args.as_run if args.as_run else ''}) is running: no owner action and no policy change.")
        return ShadowScenario(io, episodes=spec["episodes"], time_cut_utc_ns=args.time_cut_utc_ns, time_cut_device=spec.get("time_cut_device")).run()
    cut_offset_s = io.offset_s() + (args.time_cut_utc_ns - time.time_ns()) / 1e9 if args.time_cut_utc_ns is not None else None
    kinds = ", ".join(e["kind"] for e in spec["episodes"])
    io.say(f"Formal device02 session {args.run_id}{' (as ' + args.as_run + ')' if args.as_run else ''} is running. Episodes: {kinds}. Act ONLY on an open numbered instruction; everything else is automatic.")
    return FormalActiveScenario(io, episodes=spec["episodes"], time_cut_utc_ns=args.time_cut_utc_ns, time_cut_offset_s=cut_offset_s, episode_max_s=m["active"]["episode_max_s"]).run()


if __name__ == "__main__":
    sys.exit(main())
