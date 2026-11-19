"""TEST_ONLY engineering decisions: explicitly synthetic policy decisions for the isolated broker. They are NOT shadow decisions.

A record built here has its own schema (`azta.enforcement.test_only_decision`), the label `TEST_ONLY_SYNTHETIC_ENGINEERING`, a fixed statement that it exercises
enforcement mechanics only, and no behavioural, identity, context, calibration or model field at all, so it cannot be mistaken for, or converted into, a trust-engine
decision (the operational guard refuses its schema and the test guard refuses real decisions). `scenario()` expands a named transition list into deterministic records.
Nothing here is detection, calibrated trust scoring or a measured attack.
"""
from enforcement.guard import TEST_ONLY_LABEL, TEST_ONLY_SCHEMA, TEST_ONLY_STATEMENT
from enforcement.model import STATES


def test_only_decision(scenario_id, step, device, proposed_state, decision_ns):
    if proposed_state not in STATES:
        raise ValueError("unknown state")
    return dict(schema=TEST_ONLY_SCHEMA, schema_version=1, record_kind="TEST_ONLY_DECISION", scenario_id=scenario_id, step=step,
                evidence_id=f"{scenario_id}-s{step:03d}-{device}", device=device, proposed_state=proposed_state, decision_ns=decision_ns,
                evidence_class=TEST_ONLY_LABEL, statement=TEST_ONLY_STATEMENT, counterfactual=False)


test_only_decision.__test__ = False


def scenario(scenario_id, steps, start_ns, spacing_ns):
    """steps: [(device, state), ...] -> records with decision instants start_ns + i * spacing_ns."""
    return [test_only_decision(scenario_id, i, device, state, start_ns + i * spacing_ns) for i, (device, state) in enumerate(steps, 1)]
