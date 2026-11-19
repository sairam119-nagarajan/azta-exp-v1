"""Command line of the enforcement layer (run inside the dedicated PEP container, which alone holds the administrative credential).

    python -m enforcement observe   --registry R --operations-devices d1,d2 --credential-file F [--host H]
    python -m enforcement run       --registry R --operations-devices ... --credential-file F --audit-log L --decisions D --mode test-only|test-only-identity-gate|operational
                                    --escalate-after N --deescalate-after N --max-decision-age-s S --max-attempts N --deescalation-policy allow|deny
                                    [--follow-seconds T --poll-interval-s P] [--harness-token ...]
    python -m enforcement restore   ... --audit-log L --device DEVICE --confirm-device DEVICE --operator-ref REF
    python -m enforcement scenario  --scenario-id ID --steps device:STATE,... --out FILE --start-ns N --spacing-ns N

No parameter that selects a policy, a threshold, a window, an age or a retry bound has a default. `run --mode operational` builds the operational guard from the approvals that
exist; none exists today (no accepted calibration, no CONTROLLER_APPROVED registry or configuration), so every real decision is refused and logged and the broker is not touched.
`--mode test-only` needs the harness token AND a broker that carries the isolation sentinel; otherwise it refuses before reading a single record.
`--mode test-only-identity-gate` (same two requirements) accepts only a hard identity-gate decision built from SYNTHETIC evidence and runs the same device-attribution checks as the
operational identity-gate path; it exists to exercise the repaired hand-off on the isolated engineering broker (pre-push audit D-F4).
"""
import argparse
import json
import sys
import time

from enforcement.audit import AuditLog, StateTable
from enforcement.channel import MqttControlChannel
from enforcement.clock import SystemClock
from enforcement.engineering import scenario
from enforcement.errors import AuditIntegrityError, ControlUnavailable, EnforcementError
from enforcement.guard import REAL_DECISION_SCHEMA, TEST_ONLY_SCHEMA, AdministrativeGuard, ApprovalSet, OperationalGuard, TestOnlyGuard, TestOnlyIdentityGateGuard
from enforcement.model import Catalogue, classify
from enforcement.pep import ENV_ISOLATED, DynSecPEP
from enforcement.policy import DecisionFilter, PersistencePolicy
from enforcement.runner import EnforcementRunner, JsonlSource
from observation.registry import DeviceRegistry


def _bool_policy(value):
    return {"allow": True, "deny": False}[value]


def _parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("observe", "run", "restore"):
        p = sub.add_parser(name)
        p.add_argument("--registry", required=True)
        p.add_argument("--operations-devices", required=True, help="comma-separated devices that hold an operations entitlement (the accepted policy: device01,device02)")
        p.add_argument("--credential-file", required=True)
        p.add_argument("--host", required=True)
        p.add_argument("--max-attempts", required=True, type=int)
        if name != "observe":
            p.add_argument("--audit-log", required=True)
    run = sub.choices["run"]
    run.add_argument("--decisions", required=True)
    run.add_argument("--mode", required=True, choices=("test-only", "test-only-identity-gate", "operational"))
    run.add_argument("--escalate-after", required=True, type=int)
    run.add_argument("--deescalate-after", required=True, type=int)
    run.add_argument("--max-decision-age-s", required=True, type=float)
    run.add_argument("--deescalation-policy", required=True, choices=("allow", "deny"))
    run.add_argument("--harness-token")
    run.add_argument("--follow-seconds", type=float)
    run.add_argument("--poll-interval-s", type=float)
    restore = sub.choices["restore"]
    restore.add_argument("--device", required=True)
    restore.add_argument("--confirm-device", required=True)
    restore.add_argument("--operator-ref", required=True)
    s = sub.add_parser("scenario")
    s.add_argument("--scenario-id", required=True)
    s.add_argument("--steps", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--start-ns", required=True, type=int)
    s.add_argument("--spacing-ns", required=True, type=int)
    return parser


def _build(args, clock):
    registry = DeviceRegistry.load(args.registry)
    catalogue = Catalogue.from_registry(registry, [d for d in args.operations_devices.split(",") if d])
    channel = MqttControlChannel(args.host, args.credential_file)
    log = AuditLog.open_or_create(args.audit_log, clock) if getattr(args, "audit_log", None) else AuditLog(None, [], clock)
    table = StateTable(log)
    return channel, DynSecPEP(channel, catalogue, table, clock=clock, max_attempts=args.max_attempts), table


def main(argv=None):
    args = _parser().parse_args(argv)
    clock = SystemClock()
    try:
        if args.command == "scenario":
            steps = [tuple(item.split(":", 1)) for item in args.steps.split(",")]
            records = scenario(args.scenario_id, steps, args.start_ns, args.spacing_ns)
            with open(args.out, "x", encoding="utf-8", newline="\n") as stream:
                for record in records:
                    stream.write(json.dumps(record, sort_keys=True) + "\n")
            print(f"ENFORCEMENT_SCENARIO {args.scenario_id} records={len(records)}")
            return 0
        if args.command == "observe":
            args.audit_log = None
            channel, pep, table = _build(args, clock)
            try:
                pep.attest_environment()
                states = {}
                for device in pep.catalogue.devices:
                    cls = classify(pep.observe(device), pep.catalogue.get(device))
                    states[device] = dict(kind=cls.kind, states=sorted(cls.states), problems=list(cls.problems))
                print(json.dumps(dict(environment=pep.environment, devices=states), sort_keys=True))
            finally:
                channel.close()
            return 0
        channel, pep, table = _build(args, clock)
        try:
            pep.attest_environment()
            if args.command == "restore":
                if pep.environment == ENV_ISOLATED:
                    from enforcement.guard import HARNESS_TOKEN
                    request = TestOnlyGuard(harness_token=HARNESS_TOKEN, environment_isolated=True, deescalation_policy=True).authorize_restore(
                        args.device, args.operator_ref, f"{int(clock.utc_ns())}")
                else:
                    request = AdministrativeGuard().authorize_restore(args.device, args.operator_ref, confirm_device=args.confirm_device, request_id=f"{int(clock.utc_ns())}")
                outcome = pep.apply(request)
                print(json.dumps(dict(status=outcome["status"], device=args.device, states=outcome.get("final_states") or outcome.get("current_states")), sort_keys=True))
                return 0 if outcome["status"] in ("APPLIED_VERIFIED", "NOOP_ALREADY_IN_STATE") else 3
            guards = {REAL_DECISION_SCHEMA: OperationalGuard(ApprovalSet(), deescalation_policy=_bool_policy(args.deescalation_policy), catalogue=pep.catalogue)}
            if args.mode == "test-only":
                from enforcement.guard import HARNESS_TOKEN
                guards = {TEST_ONLY_SCHEMA: TestOnlyGuard(harness_token=args.harness_token, environment_isolated=pep.environment == ENV_ISOLATED,
                                                          deescalation_policy=_bool_policy(args.deescalation_policy))}
            elif args.mode == "test-only-identity-gate":
                guards = {REAL_DECISION_SCHEMA: TestOnlyIdentityGateGuard(harness_token=args.harness_token, environment_isolated=pep.environment == ENV_ISOLATED,
                                                                          catalogue=pep.catalogue, deescalation_policy=_bool_policy(args.deescalation_policy))}
            runner = EnforcementRunner(source=JsonlSource(args.decisions), pep=pep, table=table,
                                       filter_=DecisionFilter(PersistencePolicy(escalate_after=args.escalate_after, deescalate_after=args.deescalate_after)),
                                       guards=guards, clock=clock, max_decision_age_ns=int(args.max_decision_age_s * 1e9))
            runner.start()
            deadline = time.monotonic() + (args.follow_seconds or 0)
            while True:
                runner.process_available()
                if time.monotonic() >= deadline:
                    break
                time.sleep(args.poll_interval_s or 0.5)
            print(json.dumps(dict(mode=args.mode, environment=pep.environment, counts=runner.counts, audit_head=table.log.head), sort_keys=True))
            return 0
        finally:
            channel.close()
    except (EnforcementError, AuditIntegrityError, ControlUnavailable, OSError, ValueError, KeyError) as exc:
        code = getattr(exc, "code", type(exc).__name__)
        print(f"ENFORCEMENT_REFUSED {code}: {str(exc)[:200]}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
