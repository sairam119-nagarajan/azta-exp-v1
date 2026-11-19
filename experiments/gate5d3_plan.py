"""Gate 5D.3A functional-engineering fixture builder. NOT a Gate 5C-style plan.

Produces a deterministic, engineering-only description of the ten-slot workload for offline tests and for a
later, separately authorized provisioning/functional task. It assigns no partition, freezes no split, creates
no manifest entry, approves no model route and never touches a broker, credential or MQTT client.
"""
import argparse
from pathlib import Path
import sys

from experiments import gate5d3_workload as workload
from observation.registry import DeviceRegistry
from observation.schema import IDENTIFIER, SCHEMA_FINGERPRINT, canonical, observation_config_sha256, sha256_text

FIXTURE_SCHEMA = "azta.gate5d3.functional_fixture"
RUN_ID_PREFIX = "g5d3a-fx-"
DESIGN_W_NS = 10_000_000_000
DEFAULT_REGISTRY = Path(__file__).resolve().parents[1] / "configs" / "observation" / "device_registry_v2.json"
APPROVED_MODEL_ROUTES = {}  # Gate 5D.3A approves no S/V route for any v2 device; see the engineering contract


def approved_route(device):
    """Always None: no new route is approved. Gate 5D.1 routing stays plan-driven for the accepted 5C runs only."""
    return APPROVED_MODEL_ROUTES.get(device)


def build_fixture(run_id, *, registry=None, window_ns=DESIGN_W_NS, lead_in_windows=1, eligible_windows=60,
                  slots=workload.SLOTS):
    if not isinstance(run_id, str) or not IDENTIFIER.fullmatch(run_id) or not run_id.startswith(RUN_ID_PREFIX):
        raise ValueError(f"engineering fixture run ids must be valid identifiers starting with {RUN_ID_PREFIX!r}")
    registry = registry or DeviceRegistry.load(DEFAULT_REGISTRY)
    by_device = {entry.device: entry for entry in registry.devices}
    devices = {}
    for slot in slots:
        device = workload.device_for(slot)
        if device not in by_device:
            raise ValueError(f"{device} is not in the registry")
        built = workload.schedule(run_id, slot, window_ns=window_ns, lead_in_windows=lead_in_windows,
                                  eligible_windows=eligible_windows)
        entry = by_device[device]
        devices[device] = dict(
            slot=slot, username=entry.username, client_id=entry.client_id, telemetry_topic=entry.telemetry_topic,
            profile=workload.PROFILES[slot], planned_messages=len(built["items"]),
            planned_payload_bytes=sum(size for _, _, size in built["items"]),
            schedule_sha256=workload.schedule_sha256(built["items"]), meta=built["meta"],
            approved_model_route=approved_route(device))
    body = dict(
        schema=FIXTURE_SCHEMA, schema_version=1, kind="FUNCTIONAL_ENGINEERING_FIXTURE", scientific=False,
        spec_version=workload.SPEC_VERSION, run_id=run_id, partition=None, split_assignment=None,
        window_ns=window_ns, lead_in_windows=lead_in_windows, eligible_windows=eligible_windows,
        registry_version=registry.data["registry_version"], registry_sha256=registry.sha256,
        observation_schema_fingerprint=SCHEMA_FINGERPRINT,
        observation_config_sha256=observation_config_sha256(window_ns, registry.sha256, 1),
        engineering_conventions=workload.ENGINEERING_CONVENTIONS, devices=devices,
        disclaimer="Functional engineering only: not a scientific collection, not a Gate 5C plan, no model route approved.")
    body["fixture_sha256"] = sha256_text(canonical(body))
    return body


def attribute(registry, events):
    """Per-device attribution by exact delivered topic only. events: iterable of (topic, offset_ns, payload_bytes).
    Anything not matching a registry topic is counted as unbound and attributed to no device."""
    counts = {entry.device: dict(messages=0, payload_bytes=0) for entry in registry.devices}
    unbound = 0
    for topic, _, size in events:
        entry = registry.bind(topic)
        if entry is None:
            unbound += 1
            continue
        counts[entry.device]["messages"] += 1
        counts[entry.device]["payload_bytes"] += size
    return dict(per_device=counts, unbound=unbound)


def ideal_events(fixture):
    """Ideal one-for-one delivery of every planned message (receive offset = target offset). Test input only."""
    events = []
    for device, spec in fixture["devices"].items():
        built = workload.schedule(fixture["run_id"], spec["slot"], window_ns=fixture["window_ns"],
                                  lead_in_windows=fixture["lead_in_windows"],
                                  eligible_windows=fixture["eligible_windows"])
        events += [(spec["telemetry_topic"], offset, size) for _, offset, size in built["items"]]
    return sorted(events, key=lambda e: e[1])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", required=True, help="new file; an existing file is never overwritten")
    parser.add_argument("--eligible-windows", type=int, default=60, help="functional geometry; 1 lead-in and 1 lead-out window are added")
    parser.add_argument("--slots", help="comma-separated slot numbers (default: all ten)")
    args = parser.parse_args(argv)
    try:
        slots = tuple(int(x) for x in args.slots.split(",")) if args.slots else workload.SLOTS
        fixture = build_fixture(args.run_id, eligible_windows=args.eligible_windows, slots=slots)
        with Path(args.output).open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(canonical(fixture) + "\n")
    except (ValueError, OSError) as exc:
        print(f"GATE5D3_FIXTURE_REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(f"GATE5D3_FIXTURE fixture_sha256={fixture['fixture_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
