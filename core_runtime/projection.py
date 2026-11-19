"""Decisions -> recommendations ledger. Runs in the adapter worker after each projection to the enforcement inbox; it reads the committed inbox and appends one `azta.core.recommendation` per decision. A restart replays what is already
written (no duplicate, same confirmation counts) and continues. It never talks to the PEP: the PEP has its own filter and its own guard."""
import json
from pathlib import Path

from core_runtime import recommend as rc
from enforcement.policy import DecisionFilter, PersistencePolicy

DECISION_SCHEMA = "azta.gate5f.shadow_decision"


class Projector:
    def __init__(self, inbox, out, *, runtime_mode, authority_map, escalate_after, state_of=None):
        self.inbox, self.out, self.runtime_mode, self.authority_map = Path(inbox), Path(out), runtime_mode, authority_map
        self.tracker = rc.ConfirmationTracker(DecisionFilter(PersistencePolicy(escalate_after=escalate_after, deescalate_after=escalate_after)), state_of or (lambda _device: "FULL_ACCESS"))
        self.position = 0
        self.written = 0
        self.existing = sum(1 for line in self.out.read_bytes().split(b"\n") if line.strip()) if self.out.exists() else 0

    def poll(self):
        """Append the recommendations of the complete inbox lines not handled yet; returns how many were appended."""
        if not self.inbox.exists():
            return 0
        blob = self.inbox.read_bytes()
        end = blob.rfind(b"\n") + 1
        rows, appended = [], 0
        while self.position < end:
            nxt = blob.index(b"\n", self.position)
            line = blob[self.position:nxt]
            self.position = nxt + 1
            decision = json.loads(line.decode("utf-8"))
            if decision.get("schema") != DECISION_SCHEMA:
                continue
            device = rc.device_of(decision)
            recommendation, origin, _ = rc.recommendation_of(decision)
            confirmation = self.tracker.observe(device, recommendation, origin)
            self.written += 1
            if self.written <= self.existing:
                continue
            rows.append(json.dumps(rc.build(decision, runtime_mode=self.runtime_mode, authority_map=self.authority_map, confirmation=confirmation), sort_keys=True, allow_nan=False))
            appended += 1
        if rows:
            with self.out.open("ab") as stream:
                stream.write(("\n".join(rows) + "\n").encode("utf-8"))
        return appended
