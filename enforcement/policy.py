"""Persistence (confirmation-window) filter for decision-driven state changes. EXPLICIT parameters only: no deployment threshold or operational default exists here.

`PersistencePolicy(escalate_after, deescalate_after)` states how many consecutive, evaluated, fresh proposals of the SAME desired state are required before a request is
raised: escalate_after for a more restrictive state, deescalate_after for a less restrictive one (a value of 1 means no confirmation window). Both are required keyword
arguments; the engineering tests pass explicit fixture values and say so; no value is recommended or approved here.

Rules (each tested):
  * only an EVALUATED, fresh proposal counts; a missing, stale, not-evaluable or refused record is HELD: it neither escalates nor de-escalates and it RESETS the count, so a
    gap in evidence can never complete a confirmation window and silence is never treated as recovery (a quarantined device sends no telemetry, so no record can lift it);
  * a proposal equal to the device's current state clears any pending change;
  * a different proposal restarts the count for the new target;
  * the filter holds counters only; it never talks to the broker.
"""
from dataclasses import dataclass

from enforcement.model import SEVERITY, STATES


@dataclass(frozen=True)
class PersistencePolicy:
    escalate_after: int
    deescalate_after: int

    def __post_init__(self):
        for name in ("escalate_after", "deescalate_after"):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= 1000:
                raise ValueError(f"{name} must be an explicit integer in [1, 1000]")


class DecisionFilter:
    def __init__(self, policy):
        self.policy = policy
        self.pending = {}          # device -> (target state, consecutive count)

    def observe_missing(self, device):
        """A missing / stale / unevaluable record: hold, and break any confirmation run."""
        self.pending.pop(device, None)
        return dict(action="HOLD", reason="MISSING_OR_STALE_EVIDENCE", device=device)

    def observe(self, device, proposed, current):
        """proposed: the evaluated proposal; current: the device's last verified state label (None if unknown). Returns {action: HOLD|CONFIRM|REQUEST, ...}."""
        if proposed not in STATES:
            return self.observe_missing(device)
        if current is None:
            self.pending.pop(device, None)
            return dict(action="HOLD", reason="CURRENT_STATE_UNKNOWN", device=device)
        if proposed == current:
            self.pending.pop(device, None)
            return dict(action="HOLD", reason="ALREADY_IN_STATE", device=device)
        target, count = self.pending.get(device, (None, 0))
        count = count + 1 if target == proposed else 1
        self.pending[device] = (proposed, count)
        needed = self.policy.escalate_after if SEVERITY[proposed] > SEVERITY[current] else self.policy.deescalate_after
        if count >= needed:
            self.pending.pop(device, None)
            return dict(action="REQUEST", device=device, desired_state=proposed, confirmations=count, needed=needed)
        return dict(action="CONFIRM", device=device, desired_state=proposed, confirmations=count, needed=needed)
