"""Fleet FUNCTIONAL_TEST plan: the run configuration of an N-device simulation under the registry-v2 observer, and the resolution of a live-session declaration against it.

The frozen collection-plan machinery is two-device and registry-v1 (`experiments.collection_plan_v2`: plans A/B swap S and V over device01/device02) and is not edited. A fleet plan is a
separate schema (`azta.gate6b.fleet_plan`) that carries, per run and device: the profile route label (the registry still decides routing, this label is only the producer's recorded
claim), the committed workload law (`experiments.gate5d3_workload` profile), the broker identity of the device from the registry-v2 file, and the seeds. A plan is always a
FUNCTIONAL_TEST plan: it joins no scientific partition, has no manifest and is never approved here.

`resolve_declaration` is the fleet counterpart of the functional branch of `shadow_live.declaration.resolve_declaration`: the same declaration schema and the same `LivePlan`, so the
unchanged live session, source, audits and ledger follow a fleet run. It opens no evidence.
"""
import copy
import hashlib
import json
from pathlib import Path

from experiments import collection_plan as plans
from experiments import collection_workload_v2 as v2
from experiments import gate5d3_workload as g
from fleet import laws, spec
from observation.schema import SCHEMA_FINGERPRINT, observation_config_sha256

LEAD_IN, ELIGIBLE, POST_ROLL = 1, 60, 1
MAX_POST_ROLL = 10


class PlanRefused(ValueError):
    pass


def _require(condition, message):
    if not condition:
        raise PlanRefused(message)


def shim_profile(law):
    """The steady-shaped view of a law that the unchanged v2 runner constructor validates. It is NOT the schedule: the fleet runner replaces every schedule with the committed law's."""
    if law["shape"] == "steady_jitter":
        return dict(nominal_gap_ns=law["nominal_gap_ns"], jitter_fraction=law["jitter_fraction"], payload=copy.deepcopy(law["payload"]))
    if law["shape"] == "event_gap":      # events come after a random gap in [gap_low_s, gap_high_s]: the shim carries the shorter bound (it is a validation view only, never the schedule)
        gap = int(law["gap_low_s"] * 1_000_000_000)
    else:
        gap = law.get("period_ns") or law["slow_gap_ns"]
    return dict(nominal_gap_ns=gap, jitter_fraction=law.get("jitter_fraction", 0.0), payload=copy.deepcopy(law["payload"]))


def _run_config(run_id, devices, registry, profile_of, *, eligible_windows, post_roll):
    """Deterministic configuration of one fleet run. `profile_of`: {device: profile label}. The shape is that of the v2 run configuration (so the unchanged runner and live adapter
    read it) with the generator version of the v2 workload; the fleet workload version is a separate field and the plan's own `generator_version`."""
    entries = {entry.device: entry for entry in registry.devices}
    total = LEAD_IN + eligible_windows + post_roll
    config_devices = {}
    for device in sorted(devices):
        _require(device in entries and device in profile_of, f"{device}: unknown device or no profile label")
        slot, entry = laws.slot_of(device), entries[device]
        law = copy.deepcopy(g.PROFILES[slot])
        seed = v2.device_seed(run_id, device)
        shim = shim_profile(law)
        config_devices[device] = dict(
            profile=profile_of[device], profile_definition=shim, law=law, slot=slot, username=entry.username, client_id=entry.client_id, telemetry_topic=entry.telemetry_topic,
            device_seed=seed, jitter_seed=plans.stream_seed(seed, "jitter"), size_seed=plans.stream_seed(seed, "size") if shim["payload"]["kind"] != "fixed" else None)
    config = dict(
        schema=v2.RUN_CONFIG_SCHEMA, schema_version=v2.SCHEMA_VERSION, generator_version=v2.GENERATOR_VERSION, fleet_workload_version=spec.FLEET_WORKLOAD_VERSION,
        kind="FUNCTIONAL_TEST", run_id=run_id, plan="FLEET", window_duration_ms=spec.WINDOW_MS, planned_window_count=total, lead_in_windows=LEAD_IN, eligible_windows=eligible_windows,
        post_roll_windows=post_roll, eligible_window_indices=[LEAD_IN, LEAD_IN + eligible_windows - 1],
        window_roles=dict(lead_in=[0, LEAD_IN - 1], eligible=[LEAD_IN, LEAD_IN + eligible_windows - 1], post_roll=[LEAD_IN + eligible_windows, total - 1]),
        qos=1, retain=False, registry_sha256=registry.sha256, schedule_rule=dict(
            law="the committed ten-slot law of experiments/gate5d3_workload.py for each device", windows="lead-in + eligible + post-roll; the generator end rule applies only at the end of the "
            "excluded post-roll", interactive="anomalies replace ONE device's schedule from the command instant (fleet.laws)"), seed_rule=v2.SEED_RULE, devices=config_devices)
    return config


def run_config(run_id, devices, registry, profile_of, *, eligible_windows=ELIGIBLE):
    """The deterministic run configuration with the SMALLEST post-roll (from POST_ROLL up to MAX_POST_ROLL windows) that the unchanged v2 configuration rules accept: a slow or event-driven
    device (08, 09) needs a post-roll longer than its maximum inter-message gap so that the generator end rule cannot shorten an eligible window. The post-roll is excluded from every role."""
    problems = []
    for post_roll in range(POST_ROLL, MAX_POST_ROLL + 1):
        config = _run_config(run_id, devices, registry, profile_of, eligible_windows=eligible_windows, post_roll=post_roll)
        problems = v2.config_problems(config)
        if not problems:
            return config
    raise PlanRefused("; ".join(problems))


def build_plan(plan_id, run_ids, devices, profile_of, *, registry, planning_base_commit, eligible_windows=ELIGIBLE):
    _require(isinstance(planning_base_commit, str) and len(planning_base_commit) == 40, "planning_base_commit must be a full commit hash")
    runs = {run: run_config(run, devices, registry, profile_of, eligible_windows=eligible_windows) for run in run_ids}
    any_config = next(iter(runs.values()))
    return dict(
        schema=spec.PLAN_SCHEMA, schema_version=1, plan_id=plan_id, kind="FUNCTIONAL_TEST", generator_version=spec.FLEET_WORKLOAD_VERSION, approval_status="UNAPPROVED_CANDIDATE",
        approval_ref=None, design_basis="Gate 6B fleet functional plan: engineering evidence only; joins no scientific partition", window_duration_ms=spec.WINDOW_MS,
        planned_window_count=any_config["planned_window_count"], eligible_windows=eligible_windows, post_roll_windows=any_config["post_roll_windows"], lead_in_windows=LEAD_IN,
        registry_sha256=registry.sha256, schema_fingerprint=SCHEMA_FINGERPRINT, subscription_qos=plans.SUBSCRIPTION_QOS,
        observation_config_sha256=observation_config_sha256(spec.WINDOW_NS, registry.sha256, plans.SUBSCRIPTION_QOS), planning_base_commit=planning_base_commit,
        device_profiles=dict(sorted(profile_of.items())), runs=runs)


def validate_plan(plan, registry):
    _require(isinstance(plan, dict) and plan.get("schema") == spec.PLAN_SCHEMA and plan.get("schema_version") == 1 and plan.get("kind") == "FUNCTIONAL_TEST", "not a fleet functional plan")
    _require(plan.get("generator_version") == spec.FLEET_WORKLOAD_VERSION, "workload version")
    _require(plan["approval_status"] == "UNAPPROVED_CANDIDATE" and plan["approval_ref"] is None, "a fleet plan is never approved here")
    _require(plan["registry_sha256"] == registry.sha256 and plan["schema_fingerprint"] == SCHEMA_FINGERPRINT, "registry or schema pins")
    _require(plan["window_duration_ms"] == spec.WINDOW_MS and plan["observation_config_sha256"] == observation_config_sha256(spec.WINDOW_NS, registry.sha256, plans.SUBSCRIPTION_QOS),
             "window duration or observation configuration digest")
    _require(plan["runs"], "no runs")
    for run, config in plan["runs"].items():
        devices = sorted(config["devices"])
        expected = run_config(run, devices, registry, {d: config["devices"][d]["profile"] for d in devices}, eligible_windows=plan["eligible_windows"])
        _require(config == expected, f"{run}: the run configuration differs from the deterministic rule")
        for device, item in config["devices"].items():
            bound = registry.bind(item["telemetry_topic"])
            _require(bound is not None and bound.device == device, f"{run}: topic/device mapping of {device}")
    return plan


def load_plan(path, registry):
    return validate_plan(json.loads(Path(path).read_text(encoding="utf-8")), registry)


def resolve_declaration(repo, declaration, *, declaration_file_sha256):
    """`LivePlan` of a FUNCTIONAL fleet declaration (opens no evidence). Refusals use the unchanged LiveRefused codes."""
    from shadow_live import declaration as decl            # imported here, not at module level: the plan helpers are also used by the fleet WORKLOAD container,
    from shadow_live.errors import LiveRefused             # which mounts neither `shadow_live` nor `trust` (the first Gate 6B live attempt crashed on that import)
    from trust import campaign as partition_protection
    repo = Path(repo).resolve()
    if declaration.partition != "FUNCTIONAL":
        raise LiveRefused("PARTITION_UNKNOWN", "a fleet live session is a FUNCTIONAL session")
    blob = (repo / declaration.plan_path).read_bytes()
    try:
        plan = json.loads(blob)
        registry = spec.registry_v2(repo)
        validate_plan(plan, registry)
    except (ValueError, KeyError, TypeError, OSError) as exc:
        raise LiveRefused("PLAN_INVALID", f"the fleet plan does not validate ({type(exc).__name__}: {str(exc)[:200]})") from None
    if plans.digest(plan) != declaration.plan_sha256:
        raise LiveRefused("PLAN_DIGEST_MISMATCH", "the declaration names a different plan")
    if declaration.run_id not in plan["runs"]:
        raise LiveRefused("RUN_NOT_PLANNED", f"{declaration.run_id} is not a run of the declared plan")
    reserved = set()
    for path, expected in declaration.reserve_manifests:
        data = (repo / path).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise LiveRefused("MANIFEST_DIGEST_MISMATCH", f"{path}: the declaration names a different reserve manifest")
        reserved |= partition_protection.reserved_tokens_from_manifest(repo / path, partitions=["D_test"])
    reserved = frozenset(reserved)
    if declaration.run_id in reserved:
        raise LiveRefused("RUN_RESERVED", f"{declaration.run_id} is reserved evidence")
    root = decl._evidence_root(repo, declaration)
    config = plan["runs"][declaration.run_id]
    return decl.LivePlan(
        declaration=declaration, declaration_file_sha256=declaration_file_sha256, repo=repo, plan=plan, plan_sha256=plans.digest(plan), manifest_sha256=None, reserved_tokens=reserved,
        evidence_root=root, purpose=decl.PURPOSE_OF[declaration.partition], planned_entry_sha256=None, run_config=config, devices=decl._routes(config),
        window_ns=plan["window_duration_ms"] * 1_000_000, planned_window_count=config["planned_window_count"], eligible=tuple(config["eligible_window_indices"]),
        workload_version=plan["generator_version"], registry_sha256=plan["registry_sha256"], observation_config_sha256=plan["observation_config_sha256"],
        schema_fingerprint=plan["schema_fingerprint"])


def load_declaration(repo, path, *, authorized_sha256):
    """Counterpart of `shadow_live.declaration.load_declaration` for a fleet plan."""
    from shadow_live import declaration as decl
    from shadow_live.errors import LiveRefused
    blob = Path(path).read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != authorized_sha256:
        raise LiveRefused("DECLARATION_DIGEST_MISMATCH", "the declaration file differs from the digest that was authorized")
    return resolve_declaration(repo, decl.parse_declaration(json.loads(blob.decode("utf-8"))), declaration_file_sha256=digest)
