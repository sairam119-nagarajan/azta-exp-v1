"""Gate 5F.3 observer entry point for versioned (schema 2) collection manifests. ENGINEERING CANDIDATE: not run, not approved.

The accepted observer (observation/observer.py) checks a COLLECTION against the v1 manifest and is not edited. This entry point reuses its
session, windowing, binding rules and MQTT adapter unchanged and differs in exactly one respect: the committed-plan check uses the versioned
manifest (`observation.manifest_v2`), whose vocabulary has the new CAL_V2 partition and whose rules additionally require frozen partitions
before collection. Observation parameters stay those of the frozen contract: W is given explicitly (10,000 ms in the v2 plan), the same
six-feature windowing, the same registry and observation-configuration digest as the model pins.

The default observer principal is the historical `azta-pdp` MQTT identity (device01/device02 read permission only) so that the two-device
v2 evidence is gathered exactly as the v1 evidence was. That identity is an MQTT principal name; it is NOT the offline PDP trust engine,
which holds no broker identity at all. A dedicated `azta-observer` principal can be selected with the same two options as in v1 and is
required for any registry wider than two devices.
"""
import argparse
import os
import sys

from experiments.a3_mqtt import ProbeError
from observation import manifest as manifest_module
from observation import manifest_v2
from observation.observer import DEFAULT_REGISTRY, SUBSCRIPTION_QOS, ObserverSession, PahoAdapter, resolve_observer, runtime
from observation.registry import DeviceRegistry
from observation.schema import PURPOSES, observation_config_sha256


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--purpose", required=True, choices=PURPOSES)
    parser.add_argument("--collection-run-id", required=True)
    parser.add_argument("--window-duration-ms", required=True, type=int, help="Required; there is no default.")
    parser.add_argument("--window-count", required=True, type=int)
    parser.add_argument("--registry", default=DEFAULT_REGISTRY)
    parser.add_argument("--binding-audit-ref")
    parser.add_argument("--manifest", help="Required for COLLECTION (committed, frozen RUN_PLANNED in a schema-2 manifest).")
    parser.add_argument("--output-dir", default="/results")
    parser.add_argument("--host", default=os.getenv("MQTT_HOST", "broker"))
    parser.add_argument("--observer-identity", help="Dedicated receive-only observer principal (azta-observer...); default: historical azta-pdp.")
    parser.add_argument("--credential-file", help="Credential file of the dedicated observer; required with --observer-identity.")
    args = parser.parse_args(argv)
    try:
        if args.window_duration_ms <= 0:
            raise ValueError("window duration must be positive")
        registry = DeviceRegistry.load(args.registry)
        identity, credential_file = resolve_observer(registry, args.observer_identity, args.credential_file)
        attestation = None
        if args.purpose == "COLLECTION":
            if not args.manifest or not args.binding_audit_ref:
                raise ValueError("COLLECTION requires --manifest and --binding-audit-ref")
            attestation = manifest_v2.check_collection_allowed(
                args.manifest, args.collection_run_id, expected_manifest_sha256=os.getenv("AZTA_MANIFEST_SHA256", ""),
                git_commit=os.getenv("AZTA_GIT_COMMIT"), git_state=os.getenv("AZTA_GIT_STATE"))
            if (attestation["window_duration_ns"] != args.window_duration_ms * 1_000_000
                    or attestation["planned_window_count"] != args.window_count
                    or attestation["observation_config_sha256"]
                    != observation_config_sha256(args.window_duration_ms * 1_000_000, registry.sha256, SUBSCRIPTION_QOS)):
                raise ValueError("collection parameters differ from the committed plan")
        session = ObserverSession(
            registry=registry, duration_ns=args.window_duration_ms * 1_000_000, window_count=args.window_count, purpose=args.purpose,
            collection_run_id=args.collection_run_id, output_root=args.output_dir, binding_audit_ref=args.binding_audit_ref,
            runtime=runtime(), collection_attestation=attestation, observer_identity=identity,
            client_factory=lambda emit: PahoAdapter(emit, args.host, identity=identity, credential_file=credential_file))
    except (ValueError, OSError, manifest_module.ManifestError, ProbeError) as exc:
        print(f"OBSERVATION_V2_REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    summary = session.run()
    print(f'OBSERVATION_V2_SESSION {summary["observer_session_id"]} {summary["state"]} failure={summary["failure_code"]}')
    return 0 if summary["state"] == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
