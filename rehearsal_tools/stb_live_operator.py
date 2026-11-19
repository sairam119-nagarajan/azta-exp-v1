"""Stabilization live sessions (`stb-l01`, `stb-l02`, `stb-l03`): the scenario driver. Same machinery, limits and stop conditions as `core_pilot_operator.py` (it reuses its `Scenario` loop, `RealIO`
and waits), with the stabilization scripts and a two-device scope.

    python -I -B rehearsal_tools/stb_live_operator.py --run-id stb-l03 --time-cut-utc-ns N --presence-file FILE

It holds no console credential and writes no intent: **every approval and RESTORE is the owner's own click at the console**; the automatic actions on device02 are the PEP's.
Scripts (offsets from the session's coverage start):
  device02  R4: AE payload anomaly -> automatic QUARANTINE -> owner RESTORE -> healthy (the first post-RESTORE window is the recovery window) ->
            a PERSISTENT payload anomaly -> automatic QUARANTINE -> owner RESTORE while the anomaly continues -> one window held, then automatic re-QUARANTINE -> stop -> owner RESTORE;
            R2: at the declared operating-time withdrawal -> a CONTEXT RESTRICT that must arrive as a REVIEW (never automatic) -> owner APPROVE -> left RESTRICTED, probed after the session
  device01  R1: complete SILENCE (connected, authenticated, publishing nothing) -> a LIVENESS review -> owner APPROVE -> RESTRICT verified -> silence stopped; left RESTRICTED, probed after the session
  others    benign for the whole session (the live negative control); they are outside the scope, so nothing can be enforced on them

Owner instructions (amendment 2, after stb-l02): every instruction is numbered and names the action, the device, the expected cause, the scenario step and that it is inside the approved
scope; the review instructions name the review id. Every instruction is closed by a `DONE [#n]` line (verified at the broker) or a `CANCELLED [#n]` line (do NOT perform it any more), each
telling the owner to wait for the next number. A stale instruction is therefore never left open (stb-l02: an extra RESTORE cancelled a pending context review).

The silence is ONE bounded segment (at most `SILENCE_MAX_S`), never renewed by a stop and a start: a renewal would let a benign message slip out between the two commands and break the
complete silence the liveness case needs. Every other anomaly keeps the 120 s segment limit of `core_pilot_operator`.
"""
import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "rehearsal_tools")]

import core_pilot_operator as op                   # noqa: E402
from engineering import attack_control as ac       # noqa: E402

SCOPE = ("device01", "device02")                   # the two devices of the written scope
SILENCE = dict(anomaly="silence", params={})
PAYLOAD = op.PAYLOAD
HOLD_S = op.HOLD_S
LIVENESS_WAIT_S = 150.0                            # the liveness review must open within this (bound 40 s plus scoring)
SILENCE_MAX_S = 450.0                              # LIVENESS_WAIT_S + the 300 s review TTL: the whole silence lifecycle, one segment
RESTORE_WAIT_S = 180.0
AUTHORIZED = "yes, inside the approved session scope"


class StabilizationScenario(op.Scenario):
    def __init__(self, io, *, time_cut_utc_ns, time_cut_offset_s):
        super().__init__(io, time_cut_utc_ns=time_cut_utc_ns)
        self.scope = SCOPE
        self.time_cut_offset_s = time_cut_offset_s
        self.scripts = [self.device02(), self.device01()]
        self.numbered = 0
        self.open_instructions = set()
        self.unplanned = {}

    def run(self):
        """The base loop; afterwards every instruction still open is CANCELLED, so none is left standing (amendment 3, stb-l03 #5)."""
        code = super().run()
        for n in sorted(self.open_instructions):
            self.cancel(n, "the session ended before it was completed")
        return code

    # ------------------------------------------------------------------------------------------------------------- facts
    def recovery_closed_since(self, device, mark):
        return next((x for x in self.entries[mark:] if x["kind"] == "RECOVERY_WINDOW_CLOSED" and x["body"].get("device") == device), None)

    def outcome_kind_since(self, device, mark, states):
        return next((x for x in self.entries[mark:] if x["kind"] == "OUTCOME" and x["body"].get("device") == device and x["body"].get("desired_state") in states), None)

    # ------------------------------------------------------------------------------------------------------------- owner instructions
    def instruct(self, *, action, device, cause, step, review_id=None):
        """One numbered instruction. The text keeps the action first, so the owner reads what to click before why."""
        self.numbered += 1
        n = self.numbered
        parts = [f"[#{n}] {action}", f"DEVICE: {device}", f"EXPECTED CAUSE: {cause}", f"STEP: {step}", f"AUTHORIZED: {AUTHORIZED}"]
        if review_id:
            parts.append(f"REVIEW: {review_id}")
        parts.append(f"THEN: wait for instruction #{n + 1}")
        self.owner(" | ".join(parts))
        self.note("INSTRUCTION", n=n, action=action, device=device, review_id=review_id, scenario_step=step)
        self.open_instructions.add(n)
        return n

    def done(self, n, what):
        self.open_instructions.discard(n)
        self.io.say(f"DONE [#{n}] {what}. Nothing to do now: WAIT for instruction #{n + 1}.")
        self.note("INSTRUCTION_DONE", n=n, what=what)

    def cancel(self, n, why):
        self.open_instructions.discard(n)
        self.io.say(f"CANCELLED [#{n}] {why}. Do NOT perform instruction #{n} any more. WAIT for instruction #{n + 1}.")
        self.note("INSTRUCTION_CANCELLED", n=n, why=why)

    def restore_step(self, device, mark, *, cause="its containment", step="restore"):
        n = self.instruct(action=f"RESTORE {device} at the console (pick it, type its name, submit)", device=device, cause=cause, step=step)
        seen = yield from self.wait_for(lambda: self.restore_since(device, mark), RESTORE_WAIT_S)
        if seen:
            self.done(n, f"RESTORE of {device} verified at the broker")
        else:
            self.cancel(n, f"no verified RESTORE of {device} within {RESTORE_WAIT_S:.0f} s")
        return seen

    def watch(self):
        """The base stop conditions, and any review nobody planned (a false recommendation: the owner rejects it, and it stays reported), as a numbered instruction."""
        if not self.halted and not self.io.owner_present():
            self.halt("the owner's console page has not been seen; no new anomaly starts without the owner present")
        outcomes = [x for x in self.entries if x["kind"] == "OUTCOME"]
        for x in outcomes[self.seen_outcomes:]:
            body = x["body"]
            self.note("PEP_OUTCOME", device=body.get("device"), desired_state=body.get("desired_state"), status=body.get("status"), kind=body.get("request_kind"))
            if body.get("device") not in self.scope:
                self.halt(f"a PEP outcome on {body.get('device')}, outside the scope")
            elif body.get("status") not in op.OK_STATUS:
                self.halt(f"a PEP outcome {body.get('status')} on {body.get('device')}" + ("; restoration_failed_STOP" if body.get("request_kind") == "RESTORE" else ""))
        self.seen_outcomes = len(outcomes)
        for review_id, n in list(self.unplanned.items()):          # amendment 3: an unplanned-review instruction is closed when that review is resolved
            resolved = self.review_state(review_id, ("REJECTED", "EXECUTED", "EXPIRED", "SUPERSEDED"))
            if resolved:
                del self.unplanned[review_id]
                self.done(n, f"review {review_id} is {resolved.get('state')}")
        for x in self.entries:
            body = x["body"]
            if x["kind"] == "REVIEW_OPENED" and body["review_id"] not in self.claimed and body["device"] not in self.active and body["device"] not in self.expecting:
                self.claimed.add(body["review_id"])
                self.note("UNPLANNED_REVIEW", device=body["device"], action=body["action"], origin=body.get("origin"), review_id=body["review_id"])
                self.unplanned[body["review_id"]] = self.instruct(action=f"REJECT the {body['action']} review of {body['device']}", device=body["device"],
                                                                  cause=f"none planned (origin {body.get('origin')}): a false recommendation, kept on record", step="unplanned review", review_id=body["review_id"])

    # ------------------------------------------------------------------------------------------------------------- the device scripts
    def device02(self):
        # --- R4 cases 1 and 2: automatic AE quarantine, RESTORE, healthy reporting with the recovery window
        yield from self.at(45)
        mark = len(self.entries)
        hit = yield from self.anomaly_until("device02", PAYLOAD, lambda: self.outcome_since("device02", mark, ("QUARANTINE",)), 60)
        if not hit:
            self.note("NO_AUTOMATIC_QUARANTINE", device="device02", case="R4-1")
            return
        self.note("AUTOMATIC_ACTION_SEEN", device="device02", desired_state="QUARANTINE", case="R4-1")
        yield from self.pause(HOLD_S)
        if not (yield from self.restore_step("device02", mark, cause="its automatic AE quarantine (the payload anomaly has stopped)", step="R4 case 1: restore, then healthy reporting")):
            return
        mark = len(self.entries)
        closed = yield from self.wait_for(lambda: self.recovery_closed_since("device02", mark), 60)
        self.note("RECOVERY_WINDOW", device="device02", case="R4-1/2", closed=bool(closed), suppressed_action=(closed or {}).get("body", {}).get("suppressed_action"), a_ae=(closed or {}).get("body", {}).get("a_ae"))
        yield from self.pause(40)
        requarantined = self.outcome_since("device02", mark, ("QUARANTINE", "RESTRICT"))
        self.note("AFTER_RESTORE_HEALTHY", device="device02", recontained=bool(requarantined))
        # --- R4 case 3: a persistent anomaly that continues across a RESTORE
        mark = len(self.entries)
        if not self.start("device02", PAYLOAD):
            return
        segment = self.offset()
        hit = None
        began = self.offset()
        while not self.halted and self.offset() - began < 60:
            hit = self.outcome_since("device02", mark, ("QUARANTINE",))
            if hit:
                break
            segment = self.keep_running("device02", PAYLOAD, segment)
            yield
        if not hit:
            self.stop("device02")
            self.note("NO_AUTOMATIC_QUARANTINE", device="device02", case="R4-3")
            return
        self.note("AUTOMATIC_ACTION_SEEN", device="device02", desired_state="QUARANTINE", case="R4-3 first containment")
        yield from self.pause(HOLD_S)
        restore_mark = len(self.entries)
        n = self.instruct(action="RESTORE device02 at the console NOW (pick it, type its name, submit)", device="device02",
                          cause="its automatic AE quarantine; the anomaly is DELIBERATELY still running, so one window is held and then it is re-quarantined automatically",
                          step="R4 case 3: persistent anomaly across a RESTORE")
        while not self.halted and not self.restore_since("device02", restore_mark) and self.offset() - began < 240:
            segment = self.keep_running("device02", PAYLOAD, segment)
            yield
        if not self.restore_since("device02", restore_mark):
            self.stop("device02")
            self.cancel(n, "no verified RESTORE of device02 in time")
            self.note("RESTORE_NOT_SEEN", device="device02", case="R4-3")
            return
        self.done(n, "RESTORE of device02 verified; the automatic re-quarantine follows by itself")
        mark = len(self.entries)
        again = None
        while not self.halted and self.offset() - began < 360:
            again = self.outcome_since("device02", mark, ("QUARANTINE",))
            if again:
                break
            segment = self.keep_running("device02", PAYLOAD, segment)
            yield
        self.stop("device02")
        self.note("PERSISTENT_ANOMALY", device="device02", case="R4-3", recontained=bool(again), recovery_window=bool(self.recovery_closed_since("device02", mark)))
        yield from self.pause(HOLD_S)
        if not (yield from self.restore_step("device02", len(self.entries), cause="its automatic AE re-quarantine (the anomaly has now stopped)", step="R4 case 3: final restore")):
            return
        # --- R2: the declared withdrawal of the operating time: a CONTEXT restriction, reviewed
        yield from self.at(self.time_cut_offset_s)
        mark = len(self.entries)
        self.expecting.add("device02")
        review = yield from self.wait_for(lambda: self.review_since("device02", mark, "CONTEXT_POLICY"), 200)
        automatic = self.outcome_kind_since("device02", mark, ("RESTRICT",))
        self.note("CONTEXT_REVIEW", device="device02", review=bool(review), applied_before_review=bool(automatic), review_id=(review or {}).get("review_id"))
        if not review:
            return
        self.claimed.add(review["review_id"])
        n = self.instruct(action="APPROVE ONCE the RESTRICT review of device02", device="device02", cause="CONTEXT_POLICY (its operating time was withdrawn); check the cause shown is context",
                          step="R2 context restriction: do NOT restore device02 afterwards, it is probed after the session", review_id=review["review_id"])
        began, done = self.offset(), None
        while not self.halted and self.offset() - began < 280:
            done = self.outcome_since("device02", mark, ("RESTRICT",))
            if done:
                break
            lost = self.review_state(review["review_id"], ("SUPERSEDED", "EXPIRED", "REJECTED"))
            if lost:         # amendment 3 (stb-l03): the instructed review is gone; any new device02 review is unplanned and is rejected through its own numbered instruction
                self.cancel(n, f"review {review['review_id']} was {lost.get('state')} ({lost.get('reason')})")
                self.expecting.discard("device02")
                self.note("CONTEXT_REVIEW_LOST", device="device02", review_id=review["review_id"], state=lost.get("state"), reason=lost.get("reason"))
                return
            yield
        self.note("CONTEXT_RESTRICT", device="device02", verified=bool(done))
        if done:
            self.done(n, "the context RESTRICT of device02 is verified at the broker")
        else:
            self.cancel(n, "no verified context RESTRICT of device02 in time")

    def device01(self):
        # --- R1: complete silence -> liveness -> reviewed RESTRICT; one bounded silence segment, never renewed
        yield from self.at(60)
        mark = len(self.entries)
        self.expecting.add("device01")
        if not self.start("device01", SILENCE):
            return
        began = self.offset()
        review = None
        while not self.halted and self.offset() - began < LIVENESS_WAIT_S:
            review = self.review_since("device01", mark, "SUPPLEMENTARY_TIMING")
            if review:
                break
            yield
        self.note("LIVENESS_REVIEW", device="device01", review=bool(review), silent_for_s=round(self.offset() - began, 1), review_id=(review or {}).get("review_id"))
        if not review:
            self.stop("device01")
            return
        self.claimed.add(review["review_id"])
        n = self.instruct(action="APPROVE ONCE the RESTRICT review of device01", device="device01", cause="SUPPLEMENTARY_TIMING / LIVENESS (it stopped publishing)",
                          step="R1 liveness: do NOT restore device01 afterwards, it is probed after the session", review_id=review["review_id"])
        done = None
        while not self.halted and self.offset() - began < SILENCE_MAX_S:
            done = self.outcome_since("device01", mark, ("RESTRICT",))
            if done:
                break
            yield
        self.stop("device01")
        self.note("LIVENESS_RESTRICT", device="device01", verified=bool(done), silence_s=round(self.offset() - began, 1))
        if done:
            self.done(n, "the liveness RESTRICT of device01 is verified at the broker; its silence has ended")
        else:
            self.cancel(n, f"no verified RESTRICT of device01 within the {SILENCE_MAX_S:.0f} s silence bound; the silence has ended")

    def keep_running(self, device, spec, segment_start):
        """Keep one behavioural anomaly running across the 120 s segment limit; returns the new segment start. Never used for the silence (see the module notes)."""
        if spec is SILENCE:
            raise ValueError("the silence is one bounded segment and is never renewed")
        if self.offset() - segment_start >= op.MAX_SEGMENT_S - 5 and device in self.active:
            self.stop(device)
            self.start(device, spec)
            return self.offset()
        return segment_start


class ExpV1VerificationScenario(StabilizationScenario):
    """Amendment 4 (`stb-l04`, the supervisor-directed AZTA-EXP-v1 verification with tau_Q 65): device02 ONLY.
      B  strong behavioural anomaly: the payload anomaly -> automatic AE QUARANTINE (N = 2) -> anomaly stopped -> owner RESTORE (instructed) -> the recovery window -> 40 s healthy;
      A  benign context violation: at the declared operating-time withdrawal -> a CONTEXT RESTRICT that must arrive as a REVIEW -> owner APPROVE -> verified RESTRICT -> device02 keeps
         reporting benignly RESTRICTED until the session ends (the no-escalation observation) and is probed after the session.
    No silence, no persistent-anomaly case, no other device. Every other mechanism (numbered instructions, DONE/CANCELLED, unplanned reviews rejected through their own instruction,
    open instructions cancelled at the end) is the amendment 3 machinery unchanged."""

    def __init__(self, io, *, time_cut_utc_ns, time_cut_offset_s):
        super().__init__(io, time_cut_utc_ns=time_cut_utc_ns, time_cut_offset_s=time_cut_offset_s)
        self.scope = ("device02",)
        self.scripts = [self.device02_v4()]

    def device02_v4(self):
        # --- B: strong behavioural anomaly -> automatic QUARANTINE -> owner RESTORE
        yield from self.at(45)
        mark = len(self.entries)
        hit = yield from self.anomaly_until("device02", PAYLOAD, lambda: self.outcome_since("device02", mark, ("QUARANTINE",)), 60)
        if not hit:
            self.note("NO_AUTOMATIC_QUARANTINE", device="device02", case="B")
        else:
            self.note("AUTOMATIC_ACTION_SEEN", device="device02", desired_state="QUARANTINE", case="B")
            yield from self.pause(HOLD_S)
            if (yield from self.restore_step("device02", mark, cause="its automatic AE quarantine (the payload anomaly has stopped)", step="B: strong behavioural anomaly, restore")):
                mark = len(self.entries)
                closed = yield from self.wait_for(lambda: self.recovery_closed_since("device02", mark), 60)
                self.note("RECOVERY_WINDOW", device="device02", case="B", closed=bool(closed), suppressed_action=(closed or {}).get("body", {}).get("suppressed_action"), a_ae=(closed or {}).get("body", {}).get("a_ae"))
                yield from self.pause(40)
                self.note("AFTER_RESTORE_HEALTHY", device="device02", recontained=bool(self.outcome_since("device02", mark, ("QUARANTINE", "RESTRICT"))))
        # --- A: the declared withdrawal of the operating time: a CONTEXT restriction, reviewed, then observed until the end
        yield from self.at(self.time_cut_offset_s)
        mark = len(self.entries)
        self.expecting.add("device02")
        review = yield from self.wait_for(lambda: self.review_since("device02", mark, "CONTEXT_POLICY"), 200)
        automatic = self.outcome_kind_since("device02", mark, ("RESTRICT",))
        self.note("CONTEXT_REVIEW", device="device02", review=bool(review), applied_before_review=bool(automatic), review_id=(review or {}).get("review_id"))
        if not review:
            return
        self.claimed.add(review["review_id"])
        n = self.instruct(action="APPROVE ONCE the RESTRICT review of device02", device="device02", cause="CONTEXT_POLICY (its operating time was withdrawn); check the cause shown is context",
                          step="A: benign context violation; do NOT restore device02 afterwards, it is probed after the session", review_id=review["review_id"])
        began, done = self.offset(), None
        while not self.halted and self.offset() - began < 280:
            done = self.outcome_since("device02", mark, ("RESTRICT",))
            if done:
                break
            lost = self.review_state(review["review_id"], ("SUPERSEDED", "EXPIRED", "REJECTED"))
            if lost:
                self.cancel(n, f"review {review['review_id']} was {lost.get('state')} ({lost.get('reason')})")
                self.expecting.discard("device02")
                self.note("CONTEXT_REVIEW_LOST", device="device02", review_id=review["review_id"], state=lost.get("state"), reason=lost.get("reason"))
                return
            yield
        self.note("CONTEXT_RESTRICT", device="device02", verified=bool(done))
        if done:
            self.done(n, "the context RESTRICT of device02 is verified at the broker; it now reports RESTRICTED until the session ends")
        else:
            self.cancel(n, "no verified context RESTRICT of device02 in time")
        self.expecting.discard("device02")        # from here any new device02 review is unplanned (an escalation) and is rejected through its own numbered instruction


SCENARIOS = {"stb-l04": ExpV1VerificationScenario, "stb-l05": ExpV1VerificationScenario}     # stb-l05: the unchanged repeat after stb-l04 (missed owner RESTORE)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--time-cut-utc-ns", required=True, type=int)
    parser.add_argument("--wait-s", type=float, default=1800)
    parser.add_argument("--presence-file", required=True)
    args = parser.parse_args(argv)
    io = op.RealIO(args.run_id, ROOT / "results/engineering/pilot" / args.run_id, args.presence_file)
    deadline = time.monotonic() + args.wait_s
    while (ac.read_status(io.directory) or {}).get("phase") != "RUNNING":
        if time.monotonic() >= deadline:
            io.say("the run never reported RUNNING; nothing was sent")
            return 2
        time.sleep(1)
    cut_offset_s = io.offset_s() + (args.time_cut_utc_ns - time.time_ns()) / 1e9       # the declared withdrawal instant on the session's own coverage clock
    io.say(f"The stabilization session is running. Benign settling first. Numbered instructions for you appear here; act only on an open numbered instruction, everything else is automatic. "
           f"(operating-time withdrawal of device02 at about {cut_offset_s:.0f} s)")
    return SCENARIOS.get(args.run_id, StabilizationScenario)(io, time_cut_utc_ns=args.time_cut_utc_ns, time_cut_offset_s=cut_offset_s).run()


if __name__ == "__main__":
    sys.exit(main())
