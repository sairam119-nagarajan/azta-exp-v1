"""Core completion: the scenario driver of the approved policy-changing session. It starts and stops the bounded catalogue anomalies, makes the one declared out-of-band revocation, and tells the OWNER what to do at the console. It writes the timeline the verdict reads.

    python -I -B rehearsal_tools/core_pilot_operator.py --run-id core-p03 --time-cut-utc-ns N --presence-file FILE

It holds no console credential and writes no intent: **every approval, rejection and RESTORE is the owner's own click at the console**, and the automatic action on device02 is the PEP's. It reads the run's PEP log and control status; it never touches the broker policy except the one declared `operator-disable`.

Limits, enforced here: at most three targets under anomaly at once; no anomaly segment longer than 120 s; nothing started on a device outside the scope; on any failed or unverified PEP outcome, or an outcome outside the scope, it stops every anomaly, tells the owner to press Stop new actions, and starts nothing more.

Exit codes: 0 the script ran to its end (the verdict decides whether it passed); 3 a stop condition was met; 2 the run never reported RUNNING.
"""
import argparse
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from engineering import attack_control as ac      # noqa: E402

MAX_ACTIVE, MAX_SEGMENT_S = 3, 120.0
SCOPE = ("device01", "device02", "device03", "device05", "device08")
PAYLOAD = dict(anomaly="payload", params=dict(bytes=1024))
JITTER = dict(anomaly="jitter", params=dict(fraction=0.46))
HOLD_S = 12.0
LAST_DEVICE02_START_S = 500.0
OK_STATUS = ("APPLIED_VERIFIED", "NOOP_ALREADY_IN_STATE")
PRESENCE_MAX_AGE_NS = 150_000_000_000


class Scenario:
    """Device scripts are generators: each `yield` gives the turn back to the one polling loop, so all five run together without threads. `io` is the outside world (real below, fake in the tests)."""

    def __init__(self, io, *, time_cut_utc_ns, resume=False):
        self.io, self.time_cut_utc_ns, self.resume = io, time_cut_utc_ns, resume
        self.scope = SCOPE                 # a subclass (the stabilization session) narrows it per instance, never by changing the module
        self.active, self.halted, self.entries, self.claimed, self.seen_outcomes, self.expecting = {}, False, [], set(), 0, set()
        self.scripts = [self.device02(), self.device08(), self.device03(), self.device05(), self.device01()]

    # ------------------------------------------------------------------------------------------------------------- facts
    def offset(self):
        return self.io.offset_s()

    def outcome_since(self, device, mark, states):
        return next((x for x in self.entries[mark:] if x["kind"] == "OUTCOME" and x["body"].get("device") == device and x["body"].get("desired_state") in states and x["body"].get("status") == "APPLIED_VERIFIED"), None)

    def restore_since(self, device, mark):
        return next((x for x in self.entries[mark:] if x["kind"] == "OUTCOME" and x["body"].get("device") == device and x["body"].get("request_kind") == "RESTORE" and x["body"].get("status") == "APPLIED_VERIFIED"), None)

    def review_since(self, device, mark, origin=None):
        return next((x["body"] for x in self.entries[mark:] if x["kind"] == "REVIEW_OPENED" and x["body"].get("device") == device and origin in (None, x["body"].get("origin"))), None)

    def review_state(self, review_id, states):
        return next((x["body"] for x in self.entries if x["kind"] == "REVIEW_RESOLVED" and x["body"].get("review_id") == review_id and x["body"].get("state") in states), None)

    # ------------------------------------------------------------------------------------------------------------- acts
    def note(self, step, **fields):
        self.io.record(dict(step=step, offset_s=round(self.offset(), 1), **fields))

    def owner(self, text):
        self.io.say("OWNER >>> " + text)
        self.note("OWNER_TOLD", text=text)

    def start(self, device, spec):
        if self.halted or device not in self.scope:
            return False
        ok, message = self.io.attack("start", device, spec["anomaly"], spec["params"])
        self.note("ANOMALY_START", device=device, anomaly=spec["anomaly"], params=spec["params"], ok=ok, message=str(message)[:200])
        if ok:
            self.active[device] = self.offset()
        return ok

    def stop(self, device):
        if device in self.active:
            ok, message = self.io.attack("stop", device, None, None)
            self.note("ANOMALY_STOP", device=device, ok=ok, message=str(message)[:200])
            del self.active[device]

    def halt(self, why):
        if self.halted:
            return
        self.halted = True
        for device in list(self.active):
            self.stop(device)
        self.note("STOP_CONDITION", why=why)
        self.io.say("OWNER >>> STOP CONDITION: " + why + ". Press Stop new actions at the console now. No more anomalies will start.")

    # ------------------------------------------------------------------------------------------------------------- waits, for the generators
    def at(self, offset_s):
        while self.offset() < offset_s and not self.halted:
            yield

    def pause(self, seconds):
        yield from self.at(self.offset() + seconds)

    def anomaly_until(self, device, spec, found, timeout_s):
        """Run one anomaly on one device, in segments of at most 120 s, until `found()` is truthy or the time is up. Waits for a free target slot first."""
        while len(self.active) >= MAX_ACTIVE and not self.halted:
            yield
        if not self.start(device, spec):
            return None
        began, segment = self.offset(), self.offset()
        while not self.halted:
            result = found()
            if result:
                self.stop(device)
                return result
            if self.offset() - began >= timeout_s:
                self.stop(device)
                self.note("ANOMALY_GAVE_NO_RESULT", device=device, anomaly=spec["anomaly"], after_s=round(self.offset() - began, 1))
                return None
            if self.offset() - segment >= MAX_SEGMENT_S - 5:
                self.stop(device)
                if not self.start(device, spec):
                    return None
                segment = self.offset()
            yield
        return None

    def wait_for(self, found, timeout_s):
        began = self.offset()
        while not self.halted:
            result = found()
            if result:
                return result
            if self.offset() - began >= timeout_s:
                return None
            yield
        return None

    def restore_step(self, device, mark):
        self.owner(f"RESTORE {device} at the console: pick it, type its name, submit.")
        return (yield from self.wait_for(lambda: self.restore_since(device, mark), 180))

    def review_cycle(self, device, spec, *, timeout_s, instruction="APPROVE ONCE"):
        """Anomaly -> review -> the owner approves -> verified QUARANTINE -> hold -> the owner restores."""
        mark = len(self.entries)
        review = yield from self.anomaly_until(device, spec, lambda: self.review_since(device, mark), timeout_s)
        if not review:
            self.note("NO_REVIEW", device=device)
            return False
        self.claimed.add(review["review_id"])
        self.owner(f"{instruction} the {review['action']} review of {device} at the console.")
        done = yield from self.wait_for(lambda: self.outcome_since(device, mark, ("QUARANTINE", "RESTRICT")), 280)
        if not done:
            self.note("REVIEW_NOT_EXECUTED", device=device, review_id=review["review_id"])
            return False
        yield from self.pause(HOLD_S)
        return bool((yield from self.restore_step(device, mark)))

    # ------------------------------------------------------------------------------------------------------------- the device scripts
    def device02(self):
        """Automatic: nobody clicks before the broker changes. Then a RESTORE, a jitter attempt sized for the narrow RESTRICT band (recorded whatever it gives), a repeat cycle if needed, and at the end the withdrawn operating time, whose RESTRICT is probed after the session."""
        quarantines = 0
        if self.resume:                           # the first driver already ran device02's first cycle: only its RESTORE and the F1 watch remain
            quarantines = 1
            if not (yield from self.restore_step("device02", 0)):
                self.note("RESTORE_NOT_SEEN", device="device02")
                return
            yield from self.pause(70)
        else:
            yield from self.at(45)
            mark = len(self.entries)
            hit = yield from self.anomaly_until("device02", PAYLOAD, lambda: self.outcome_since("device02", mark, ("QUARANTINE",)), 60)
            if hit:
                quarantines += 1
                self.note("AUTOMATIC_ACTION_SEEN", device="device02", desired_state="QUARANTINE")
                yield from self.pause(HOLD_S)
                if not (yield from self.restore_step("device02", mark)):
                    self.note("RESTORE_NOT_SEEN", device="device02")
                    return
                yield from self.pause(70)         # the F1 watch: a stale decision would re-contain it here
        mark = len(self.entries)
        hit = yield from self.anomaly_until("device02", JITTER, lambda: self.outcome_since("device02", mark, ("QUARANTINE", "RESTRICT")), 90)
        if hit:
            state = hit["body"]["desired_state"]
            quarantines += state == "QUARANTINE"
            self.note("AUTOMATIC_ACTION_SEEN", device="device02", desired_state=state, cause="jitter attempt")
            yield from self.pause(HOLD_S)
            if not (yield from self.restore_step("device02", mark)):
                self.note("RESTORE_NOT_SEEN", device="device02")
                return
            yield from self.pause(40)
        if quarantines < 2 and self.offset() < LAST_DEVICE02_START_S:
            mark = len(self.entries)
            hit = yield from self.anomaly_until("device02", PAYLOAD, lambda: self.outcome_since("device02", mark, ("QUARANTINE",)), 60)
            if hit:
                self.note("AUTOMATIC_ACTION_SEEN", device="device02", desired_state="QUARANTINE")
                yield from self.pause(HOLD_S)
                yield from self.restore_step("device02", mark)
        mark = len(self.entries)
        hit = yield from self.wait_for(lambda: self.outcome_since("device02", mark, ("RESTRICT", "QUARANTINE")), 1200)
        if hit:
            self.note("AUTOMATIC_ACTION_SEEN", device="device02", desired_state=hit["body"]["desired_state"], cause="withdrawn operating time")
            self.io.say("OWNER >>> device02 is now RESTRICTED. Do NOT restore it at the console: it is probed after the session and then restored on your word.")

    def device08(self):
        """Slow route: two disjoint 90 s windows. It may not confirm inside the session; that is reported."""
        yield from self.at(70)
        if self.resume:                           # the first driver left this anomaly running: one explicit stop, then the bounded segments again
            self.active["device08"] = self.offset()
            self.stop("device08")
        yield from self.review_cycle("device08", PAYLOAD, timeout_s=330)

    def device03(self):
        yield from self.at(120)
        mark = len(self.entries)
        review = yield from self.anomaly_until("device03", PAYLOAD, lambda: self.review_since("device03", mark), 70)
        if review:
            self.claimed.add(review["review_id"])
            self.owner("REJECT the QUARANTINE review of device03 at the console (the decline case). Nothing should change on the broker.")
            yield from self.wait_for(lambda: self.review_state(review["review_id"], ("REJECTED", "EXPIRED", "SUPERSEDED")), 290)
        yield from self.at(270)
        yield from self.review_cycle("device03", PAYLOAD, timeout_s=70)

    def device05(self):
        yield from self.at(120)
        mark = len(self.entries)
        review = yield from self.anomaly_until("device05", PAYLOAD, lambda: self.review_since("device05", mark), 70)
        if review:
            self.claimed.add(review["review_id"])
            self.owner("Do NOTHING with the QUARANTINE review of device05: leave it to expire in about 5 minutes (the expiry case).")
            expired = yield from self.wait_for(lambda: self.review_state(review["review_id"], ("EXPIRED", "REJECTED", "EXECUTED")), 330)
            self.note("DEVICE05_REVIEW_ENDED", state=(expired or {}).get("state"))
        yield from self.pause(5)
        yield from self.review_cycle("device05", PAYLOAD, timeout_s=70)

    def device01(self):
        yield from self.at(165)
        cycle = yield from self.review_cycle("device01", PAYLOAD, timeout_s=70)
        if not cycle:
            return
        yield from self.pause(60)
        yield from self.at(360)
        if self.halted:
            return
        mark = len(self.entries)
        self.expecting.add("device01")
        code = self.io.revoke("device01")
        self.note("REVOCATION", device="device01", exit=code)
        review = yield from self.wait_for(lambda: self.review_since("device01", mark, "IDENTITY_HARD_GATE"), 120)
        if not review:
            self.note("NO_REVIEW", device="device01", cause="revocation")
            return
        self.claimed.add(review["review_id"])
        self.owner("APPROVE ONCE the QUARANTINE review of device01 (identity hard gate, a genuine revocation), then wait.")
        done = yield from self.wait_for(lambda: self.outcome_since("device01", mark, ("QUARANTINE",)), 280)
        if done:
            yield from self.pause(HOLD_S)
            yield from self.restore_step("device01", mark)

    # ------------------------------------------------------------------------------------------------------------- the one loop
    def watch(self):
        """Stop conditions, and any review nobody planned (a false recommendation: the owner rejects it, and it stays reported)."""
        if not self.halted and not self.io.owner_present():
            self.halt("the owner's console page has not been seen; no new anomaly starts without the owner present")
        outcomes = [x for x in self.entries if x["kind"] == "OUTCOME"]
        for x in outcomes[self.seen_outcomes:]:
            body = x["body"]
            self.note("PEP_OUTCOME", device=body.get("device"), desired_state=body.get("desired_state"), status=body.get("status"), kind=body.get("request_kind"))
            if body.get("device") not in self.scope:
                self.halt(f"a PEP outcome on {body.get('device')}, outside the scope")
            elif body.get("status") not in OK_STATUS:
                self.halt(f"a PEP outcome {body.get('status')} on {body.get('device')}" + ("; restoration_failed_STOP" if body.get("request_kind") == "RESTORE" else ""))
        self.seen_outcomes = len(outcomes)
        for x in self.entries:
            if x["kind"] == "REVIEW_OPENED" and x["body"]["review_id"] not in self.claimed and x["body"]["device"] not in self.active and x["body"]["device"] not in self.expecting:
                self.claimed.add(x["body"]["review_id"])
                self.note("UNPLANNED_REVIEW", device=x["body"]["device"], action=x["body"]["action"], origin=x["body"].get("origin"))
                self.owner(f"UNPLANNED review of {x['body']['device']} ({x['body']['action']}): no anomaly is running on it. REJECT it. It stays on record as a false recommendation.")

    def run(self):
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
        return 3 if self.halted else 0


class RealIO:
    def __init__(self, run_id, out_dir, presence_file):
        self.run_id, self.presence_file = run_id, Path(presence_file)
        self.directory = ac.control_dir(run_id, ROOT)
        self.run_dir = ROOT / "results/engineering/runs" / run_id
        self.out = Path(out_dir)
        self.out.mkdir(parents=True, exist_ok=True)
        self.timeline = self.out / "operator_timeline.jsonl"
        self.guide = self.out / "owner_guide.log"
        self.console_guide = self.run_dir / "service" / "owner_guide.log"
        self.last_offset = 0.0
        self.unread = 0
        self.presence_misses = 0

    def owner_present(self):
        """A signed-in console page polled recently. Generous, because a browser slows the timers of a tab that is not in front."""
        try:
            seen = json.loads(self.presence_file.read_text(encoding="utf-8"))["utc_ns"]
        except (OSError, ValueError, KeyError):
            self.presence_misses += 1
            return self.presence_misses < 10          # a read can meet the replace; only a persistent failure is absence
        self.presence_misses = 0
        return time.time_ns() - seen <= PRESENCE_MAX_AGE_NS

    def offset_s(self):
        status = ac.read_status(self.directory)
        if isinstance(status, dict) and status.get("offset_ns") is not None:
            self.last_offset = status["offset_ns"] / 1e9 + status.get("age_s", 0.0)
        return self.last_offset

    def running(self):
        """False only when the run itself says ENDED, or after a long silence. The router reports STARTING for a moment whenever one shard's status file is being replaced, and a read can fail while the file is replaced; neither is an end (found live: `core-p01`, offsets 100 s and 389 s)."""
        status = ac.read_status(self.directory)
        if not isinstance(status, dict):
            self.unread += 1
            return self.unread < 60
        self.unread = 0
        return status.get("phase") != "ENDED"

    def attack(self, action, device, anomaly, params):
        for _ in range(10):
            ok, message = ac.perform(self.directory, action, device, anomaly, params, "core-pilot-operator")
            if ok or "not RUNNING" not in str(message):
                return ok, message
            time.sleep(0.5)
        return ok, message

    def entries(self):
        path = self.run_dir / "pep" / "continuous.jsonl"
        out = []
        if path.exists():
            for line in path.read_bytes().split(b"\n")[:-1]:
                try:
                    out.append(json.loads(line.decode("utf-8")))
                except ValueError:
                    break
        return out

    def revoke(self, device):
        import pilot_operator
        return pilot_operator.act(self.run_id, device, "disable")

    def record(self, item):
        with self.timeline.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(dict(item, utc_ns=time.time_ns()), sort_keys=True, default=str) + "\n")

    def say(self, text):
        line = f"{time.strftime('%H:%M:%SZ', time.gmtime())} [{self.last_offset:5.0f} s] {text}"
        for path in (self.guide, self.console_guide):
            with path.open("a", encoding="utf-8") as stream:
                stream.write(line + "\n")
        print(line, flush=True)

    def sleep(self, seconds):
        time.sleep(seconds)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--time-cut-utc-ns", required=True, type=int)
    parser.add_argument("--wait-s", type=float, default=1800)
    parser.add_argument("--out-dir", default=None)
    parser.add_argument("--presence-file", required=True)
    parser.add_argument("--resume", action="store_true", help="the same session after a driver failure: device02's first cycle is done and device08's anomaly is running")
    args = parser.parse_args(argv)
    sys.path.insert(0, str(ROOT / "rehearsal_tools"))
    io = RealIO(args.run_id, args.out_dir or ROOT / "results/engineering/pilot" / args.run_id, args.presence_file)
    deadline = time.monotonic() + args.wait_s
    while (ac.read_status(io.directory) or {}).get("phase") != "RUNNING":
        if time.monotonic() >= deadline:
            io.say("the run never reported RUNNING; nothing was sent")
            return 2
        time.sleep(1)
    io.say("The session is running. Benign settling first. Instructions for you appear here; everything else is automatic.")
    return Scenario(io, time_cut_utc_ns=args.time_cut_utc_ns, resume=args.resume).run()


if __name__ == "__main__":
    sys.exit(main())
