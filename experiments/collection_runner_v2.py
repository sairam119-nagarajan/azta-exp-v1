"""Gate 5F.2 workload-v2 runner adapter (publisher-only, QoS 1, telemetry topics only). ENGINEERING CANDIDATE: not run, not approved.

Reuses the frozen v1 `WorkloadRunner` machinery (ledger, acknowledgements, coverage handling, summary) without editing it, and differs
in exactly one respect: the publishing schedule comes from `collection_workload_v2.schedule` (a post-roll window carries normal traffic
so that no eligible window is truncated). The v1 constructor binds the v1 schedule function, so this adapter repeats the short
constructor body with the v2 schedule; every other method is inherited unchanged.

Guards that the v1 runner did not need:
  * a plan must be a validated v2 plan (the v1 tools refuse it, and this tool refuses v1 plans);
  * a COLLECTION run additionally requires `approval_status == "APPROVED"` (a controller approval reference): an unapproved candidate
    plan can be planned and tested offline but can never be collected with this runner;
  * the run configuration must satisfy the v2 geometry rules (the end boundary lies beyond the last eligible window).
"""
import argparse
import os
from pathlib import Path
import sys
import time

from experiments import collection_plan as plans
from experiments import collection_plan_v2 as plans_v2
from experiments import collection_sessions_v2 as sessions_v2
from experiments import collection_workload as v1
from experiments import collection_workload_v2 as v2
from experiments.research_records import utc_now
from observation import manifest as manifest_module
from observation import manifest_v2
from observation.registry import DeviceRegistry


ATTEMPT_STAMP_BASIS = "WALL_CLOCK_BEFORE_PUBLISH"


class PreStampPublisher:
    """Delegating proxy that takes the wall-clock send stamp immediately BEFORE the publish call.

    The v1 ledger stamped `attempt_utc` after `publish()` returned and after its bookkeeping, so the stamp could be LATER than the moment
    the packet left and, for a sub-millisecond path, later than the observer's receipt (a negative wall-clock delivery latency was seen in
    the first functional rehearsal; the monotonic-domain latency was never negative). Taking the stamp first makes the wall-clock latency an
    upper bound that cannot be negative while both processes share one clock. Messages, schedule and observer features are unaffected.
    """
    def __init__(self, inner, runner):
        self._inner, self._runner = inner, runner

    def publish(self, topic, data):
        self._runner._pre_publish_wall_ns = self._runner.wall()
        return self._inner.publish(topic, data)

    def __getattr__(self, name):
        return getattr(self._inner, name)


class WorkloadRunnerV2(v1.WorkloadRunner):
    def __init__(self, *, config, purpose, output_root, publisher_factory, coverage_source, clock=time.monotonic_ns,
                 wall=time.time_ns, utc=utc_now, runtime=None, plan_ref=None, attestation=None,
                 coverage_timeout_ns=120_000_000_000, ack_timeout_ns=10_000_000_000, idle=time.sleep, session_boundary=None):
        if purpose not in v1.PURPOSES:
            raise ValueError("purpose must be FUNCTIONAL_TEST or COLLECTION")
        if config.get("generator_version") != v2.GENERATOR_VERSION or v2.config_problems(config):
            raise ValueError("the v2 runner needs a valid workload-v2 run configuration")
        if config["qos"] != v1.PUBLISH_QOS or config["retain"] is not False:
            raise ValueError("workload must be QoS 1 without retain")
        self.config, self.purpose, self.clock, self.wall, self.utc, self.idle = config, purpose, clock, wall, utc, idle
        self.run_id = config["run_id"]
        self.coverage_source = coverage_source
        self._pre_publish_wall_ns = None
        self.publisher_factory = lambda *args, **kwargs: PreStampPublisher(publisher_factory(*args, **kwargs), self)
        self.coverage_timeout_ns, self.ack_timeout_ns = coverage_timeout_ns, ack_timeout_ns
        self.path = Path(output_root) / "collection" / self.run_id
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.mkdir(exist_ok=False)  # never overwrite prior evidence
        self.devices = sorted(config["devices"])
        self.files = {}
        self.pending = {device: {} for device in self.devices}
        self.messages = {device: {} for device in self.devices}
        self.lifecycle = []
        self.publishers = {}
        self.failure = None
        self.coverage = None
        self.mono_coverage = None
        self.epoch_coverage = None
        self.schedules = {device: v2.schedule(config, device) for device in self.devices}   # the only change from the v1 constructor
        for device in self.devices:
            self.files[device] = (self.path / f"ledger_{device}.jsonl").open("x", encoding="utf-8", newline="\n")
        self.metadata = dict(
            schema=v1.SUMMARY_SCHEMA, schema_version=v1.SCHEMA_VERSION, record="WORKLOAD_METADATA", run_id=self.run_id,
            purpose=purpose, plan_kind=config["kind"], plan_ref=plan_ref, attestation=attestation,
            workload_config_sha256=plans.digest(config), generator_version=config["generator_version"],
            devices={d: dict(profile=config["devices"][d]["profile"], username=config["devices"][d]["username"],
                             client_id=config["devices"][d]["client_id"],
                             telemetry_topic=config["devices"][d]["telemetry_topic"],
                             planned_messages=len(self.schedules[d])) for d in self.devices},
            runtime=runtime or {}, utc_start=utc(), attempt_stamp_basis=ATTEMPT_STAMP_BASIS, preexisting_sessions=session_boundary,
            identity_note="ledger is corroborating evidence only; observer topic binding is authoritative")
        self._write_json("workload_metadata.json", self.metadata)

    def _ledger(self, device, **fields):
        """v1 ledger writer, except that an ATTEMPT carries the pre-publish wall stamp (never the post-publish one) and says so."""
        if fields.get("record_type") == "ATTEMPT":
            stamp = self._pre_publish_wall_ns
            if stamp is None:
                raise v1.WorkloadError("attempt_stamp_missing")
            fields["attempt_utc"] = v1.epoch_ns_to_utc(stamp)
            fields["attempt_utc_basis"] = ATTEMPT_STAMP_BASIS
            self._pre_publish_wall_ns = None
        super()._ledger(device, **fields)


def verify_collection_v2(manifest_path, run_id, plan, config):
    """The v1 in-container committed-plan check over the versioned (schema 2) manifest: clean committed checkpoint, unaltered digest, frozen
    partitions and the run's RUN_PLANNED digest bound to this run configuration."""
    attestation = manifest_v2.check_collection_allowed(
        manifest_path, run_id, expected_manifest_sha256=os.getenv("AZTA_MANIFEST_SHA256", ""),
        git_commit=os.getenv("AZTA_GIT_COMMIT"), git_state=os.getenv("AZTA_GIT_STATE"))
    state = manifest_v2.validate(manifest_v2.read_entries(manifest_path))
    plans.check_manifest_against_plan(state, plan)
    if state["planned"][run_id]["workload_config_sha256"] != plans.digest(config):
        raise ValueError("run config differs from the committed RUN_PLANNED digest")
    return attestation


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--purpose", required=True, choices=v1.PURPOSES)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--manifest", help="Required for COLLECTION (committed RUN_PLANNED).")
    parser.add_argument("--registry", default="/app/configs/observation/device_registry.json")
    parser.add_argument("--output-dir", default="/results")
    parser.add_argument("--host", default=os.getenv("MQTT_HOST", "broker"))
    parser.add_argument("--credentials", default="/run/secrets")
    parser.add_argument("--coverage-timeout-s", type=float, default=120.0)
    args = parser.parse_args(argv)
    try:
        registry = DeviceRegistry.load(args.registry)
        plan = plans_v2.validate_plan_v2(plans.load_plan(args.plan), registry)
        config = plan["runs"].get(args.run_id)
        if config is None:
            raise ValueError("run is not in the plan")
        attestation = None
        if args.purpose == "COLLECTION":
            if plan["approval_status"] != "APPROVED":
                raise ValueError("the plan is an UNAPPROVED_CANDIDATE: a COLLECTION run needs a controller approval reference")
            if plan["kind"] not in ("SCIENTIFIC", "WRAPPER_VALIDATION_NOT_DATA") or not args.manifest:
                raise ValueError("COLLECTION needs a collection plan and its committed manifest")
            attestation = verify_collection_v2(args.manifest, args.run_id, plan, config)
        elif plan["kind"] != "FUNCTIONAL_TEST" or args.manifest:
            raise ValueError("FUNCTIONAL_TEST uses only a FUNCTIONAL_TEST plan and no manifest")
        # The boundary between historical and new observer sessions is the ORCHESTRATOR's snapshot, taken before either container started. The
        # runner never takes its own: its start-up validation is slow enough for the observer to create its session first.
        coverage_source = sessions_v2.coverage_from_environment(args.output_dir, args.run_id, args.purpose, os.environ)
        boundary = dict(count=len(coverage_source.excluded), sha256=sessions_v2.snapshot_digest(coverage_source.excluded))
        runner = WorkloadRunnerV2(
            config=config, purpose=args.purpose, output_root=args.output_dir,
            publisher_factory=lambda username, on_ack, emit: v1.DevicePublisher(username, on_ack, emit, args.host, args.credentials),
            coverage_source=coverage_source, session_boundary=boundary, runtime=v1.runtime(),
            plan_ref=dict(plan_id=plan["plan_id"], plan_sha256=plans.digest(plan)), attestation=attestation,
            coverage_timeout_ns=int(args.coverage_timeout_s * 1e9))
    except (ValueError, OSError, KeyError, manifest_module.ManifestError) as exc:   # manifest_v2 raises the same ManifestError
        print(f"WORKLOAD_V2_REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    summary = runner.run()
    counts = " ".join(f'{d}={r["accepted"]}/{r["planned_messages"]}' for d, r in summary["devices_result"].items())
    print(f'WORKLOAD_V2_RUN {args.run_id} {summary["state"]} failure={summary["failure_code"]} accepted {counts}')
    return 0 if summary["state"] == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
