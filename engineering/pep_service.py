"""Persistent operational refusal boundary; runs ONLY in the isolated PEP container.

No test guard or approval can be supplied by this service. Broker outages exit
75 for supervised reconnection; the existing audit cursor retains pending work.
"""
import json
from pathlib import Path
import sys
import time

from enforcement import cli
from enforcement.authority import AuthorityMap, AuthorityRunner, AuthorityScope
from enforcement.clock import SystemClock
from enforcement.errors import AuditIntegrityError, ControlUnavailable, EnforcementError
from enforcement.guard import OperationalGuard, REAL_DECISION_SCHEMA
from enforcement.pep import ENV_ISOLATED, ENV_PILOT
from enforcement.policy import DecisionFilter, PersistencePolicy
from enforcement.runner import EnforcementRunner, JsonlSource
from engineering import approvals
from engineering.ownership import Lease


# The enforcement target of the service. Absent = the engineering broker, where every operational request is refused by the PEP (the persistent refusal boundary). PILOT_BROKER = the
# dedicated isolated pilot broker, which needs the pilot sentinel; WITHOUT an approval it is the same refusal boundary as on the engineering broker (the guard holds an empty approval set and
# refuses every genuine decision), and an approval is accepted only if its scope is the pilot scope; the approval of the other target is refused in both directions.
TARGETS = {None: (ENV_ISOLATED, approvals.SCOPE), "PILOT_BROKER": (ENV_PILOT, approvals.PILOT_SCOPE), "PILOT_FLEET_BROKER": (ENV_PILOT, approvals.PILOT_FLEET_SCOPE), "PILOT_CORE_BROKER": (ENV_PILOT, approvals.PILOT_CORE_SCOPE)}


def build_runner(spec, **arguments):
    """The unchanged runner, or with `spec["authority"]` (AE_PRIMARY_AUTHORITY_V1, mode review or active-authorized) the authority runner. The map and the scope are read pinned from the service directory; a missing scope stays a refusal."""
    section = spec.get("authority")
    if section is None:
        return EnforcementRunner(**arguments)
    authority_map = AuthorityMap.load(section["map_path"], section["map_sha256"])
    scope = AuthorityScope.load(section["scope_path"], section["scope_sha256"]) if section.get("scope_path") else None
    return AuthorityRunner(mode=section["mode"], authority_map=authority_map, scope=scope, review_ttl_ns=int(section["review_ttl_s"] * 1e9), intents_path=section["intents_path"], **arguments)


def target_of(spec, *, now_ns):
    """(required environment, target) for this service, after checking that the approval's scope matches the target. Raises ValueError on anything else."""
    target = spec.get("pep_target")
    if target not in TARGETS:
        raise ValueError("unknown pep_target")
    environment, scope = TARGETS[target]
    section = spec.get("operational_approval")
    if section is not None and approvals.scope_of(section["approval"], authorized_approval_sha256=section["approval_sha256"], now_ns=now_ns) != scope:
        raise ValueError("the approval's scope does not match this enforcement target")
    return environment, target


def run(spec):
    args = cli._parser().parse_args(spec["pep_args"])
    if args.command != "run" or args.mode != "operational":
        raise ValueError("the continuous service only accepts operational records")
    clock = SystemClock()
    required_environment, _ = target_of(spec, now_ns=clock.utc_ns())
    channel, pep, table = cli._build(args, clock)
    try:
        pep.attest_environment()
        if pep.environment != required_environment:
            raise ValueError("the PEP target is not the attested broker (isolation sentinel mismatch)")
        changes = None
        if spec.get("policy_change_tolerance_ns") is not None:       # Gate 6B (F1): hold decisions made before this device's latest verified policy change
            from engineering.policy_changes import PolicyChangeFollower
            changes = PolicyChangeFollower(Path(args.audit_log).parent)
        runner = build_runner(spec, source=JsonlSource(args.decisions), pep=pep, table=table,
            policy_changes=changes, policy_change_tolerance_ns=spec.get("policy_change_tolerance_ns"),
            filter_=DecisionFilter(PersistencePolicy(escalate_after=args.escalate_after, deescalate_after=args.deescalate_after)),
            guards={REAL_DECISION_SCHEMA: OperationalGuard(approvals.from_spec(spec, now_ns=clock.utc_ns()), deescalation_policy=cli._bool_policy(args.deescalation_policy),
                                                           catalogue=pep.catalogue)},
            clock=clock, max_decision_age_ns=int(args.max_decision_age_s * 1e9))
        runner.start()
        heartbeat_due = time.monotonic() + 5.0  # transport liveness only; never an evidence-age or policy parameter
        while True:
            # The stop request is observed BEFORE the pass. The supervisor creates it only after the adapter has exited, i.e. after its last projection, so a pass that begins after the
            # request was seen reads everything that was handed off. Checking after the pass could strand records that landed while that pass was in flight (pre-push audit, P2).
            stopping = Path(spec["pep_stop_file"]).exists()
            runner.process_available()
            if stopping:
                break
            if time.monotonic() >= heartbeat_due:
                if pep.attest_environment() != required_environment:
                    raise ValueError("isolation sentinel changed")
                heartbeat_due = time.monotonic() + 5.0
            time.sleep(spec["supervisor_poll_s"])
        print(json.dumps(dict(counts=runner.counts, cursor=table.cursor, audit_head=table.log.head), sort_keys=True))
        return 0
    finally:
        channel.close()


def main():
    try:
        path = Path(sys.argv[1])
        with Lease(path.parent / "pep.owner.lock"):
            return run(json.loads(path.read_text(encoding="utf-8")))
    except ControlUnavailable as exc:
        print(f"PEP_SERVICE_RETRY {type(exc).__name__}", file=sys.stderr)
        return 75
    except (EnforcementError, AuditIntegrityError, OSError, ValueError, KeyError) as exc:
        print(f"PEP_SERVICE_REFUSED {getattr(exc, 'code', type(exc).__name__)}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
