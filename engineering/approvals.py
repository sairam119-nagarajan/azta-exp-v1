"""Operational approval loader (audit follow-up F3): turns ONE controller-issued approval record into the `ApprovalSet` the operational guard needs. It approves nothing by itself.

    python -m engineering.approvals digests --registry R.json --config C.json [--calibration K.json]
    python -m engineering.approvals verify  --approval A.json --approval-sha256 H --registry R.json --config C.json [--calibration K.json]

An approval is an explicit act of the Main Controller, recorded in a JSON file (`azta.enforcement.operational_approval`) that names, by digest, exactly what is approved:
the device-profile registry (its canonical record digest), the operating configuration (the digest of the parsed configuration) and, separately and optionally, an accepted behaviour
calibration (the SHA-256 of its record file). The operator passes the SHA-256 of the approval file on the command line, as stated by the Controller (the same digest-pin pattern as the
registry and the frozen artifacts; it is not a signature and there is no PKI). The loader then re-derives every digest from the artifacts themselves, and ANY mismatch, malformed or
unknown field, wrong role, missing artifact, registry that is not CONTROLLER_APPROVED, calibration that is not CONTROLLER_ACCEPTED, or validity window that does not contain `now` refuses
the whole approval (`ApprovalRefused`): there is no partial approval and no default. The behaviour calibration is its own section: without it `ApprovalSet.calibration_id` stays None and
behavioural decisions stay refused (the identity hard gate does not need it).

The pinned configuration parser can only write the label SYNTHETIC_TEST_UNAPPROVED into decision records, so the approval binds the configuration by DIGEST and names that label; the guard
accepts a record only when both its configuration digest and its label equal the approved ones. Accepting a CONTROLLER_APPROVED label in the parser is a separate, pinned-source change
that needs a new freeze and is not made here (`docs/gate5f/F1_F3_APPROVAL_AND_ATTRIBUTION_RECORD.md`).
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import time

from enforcement.errors import ApprovalRefused, EnforcementError
from enforcement.guard import ApprovalSet

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "azta.enforcement.operational_approval"
SCOPE = "OPERATIONAL_ENFORCEMENT"
PILOT_SCOPE = "PILOT_TWO_DEVICE_ENFORCEMENT"      # an approval that is valid ONLY for the dedicated isolated pilot broker (device01 and device02): never accepted for any other target
PILOT_FLEET_SCOPE = "PILOT_FLEET_ENFORCEMENT"     # Gate 6B: valid ONLY for the dedicated isolated pilot broker and the fleet registry (more than two devices, provisional profile models); never accepted for another target
PILOT_CORE_SCOPE = "PILOT_CORE_FINAL_ENFORCEMENT"  # AE_PRIMARY_AUTHORITY_V1: valid ONLY for the pilot broker and the final integration version; an authority scope is needed in addition (`enforcement.authority`)
SCOPES = (SCOPE, PILOT_SCOPE, PILOT_FLEET_SCOPE, PILOT_CORE_SCOPE)
APPROVER_ROLE = "MAIN_CONTROLLER"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_TOP = {"schema", "schema_version", "approval_id", "scope", "approver_role", "approver_ref", "issued_utc_ns", "expires_utc_ns", "registry", "configuration", "calibration"}


def _refuse(code, text):
    raise ApprovalRefused(code, text)


def _read(path, label):
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        _refuse("APPROVAL_ARTIFACT_UNREADABLE", f"{label}: {exc.__class__.__name__}")


def _json(blob, label):
    def reject(constant):
        raise ValueError(constant)
    try:
        return json.loads(blob.decode("utf-8"), parse_constant=reject)
    except (ValueError, UnicodeDecodeError):
        _refuse("APPROVAL_ARTIFACT_NOT_JSON", label)


def _registry(path, repo_root, fleet_catalog=None):
    """`fleet_catalog` (Gate 6B): {profile: {model_id, weights_sha256}} of the fleet profiles, taken from the approved calibration record; when given, the registry is parsed against the frozen
    S/V catalog EXTENDED by it and against the registry-v2 pins (otherwise exactly as before)."""
    try:
        from decision_pipeline.errors import ModelVersionMismatch, RegistryRefused
        from decision_pipeline.registry import model_catalog_from_freeze, parse_registry
        from preprocessing.gate5d_data import PIN
        from trust import artifacts
    except ImportError as exc:       # e.g. the PEP container, which mounts none of these packages: a durable refusal, never a crash-and-retry loop
        _refuse("APPROVAL_LOADER_UNAVAILABLE", f"the registry loader needs the engine packages ({exc.__class__.__name__}); verify on the host (see HOST_SUPERVISOR_PRE_LAUNCH)")
    catalog = model_catalog_from_freeze(artifacts.load_freeze(Path(repo_root)))
    pins = {k: PIN[k] for k in ("registry_sha256", "observation_config_sha256")}
    if fleet_catalog is not None:
        from fleet import spec as fleet_spec
        catalog.update({profile: dict(item) for profile, item in fleet_catalog.items() if profile not in catalog})
        v2 = fleet_spec.v2_pins(repo_root)
        pins = {k: v2[k] for k in ("registry_sha256", "observation_config_sha256")}
    try:
        return parse_registry(_json(_read(path, "registry"), "registry"), model_catalog=catalog, model_pins=pins)
    except (RegistryRefused, ModelVersionMismatch) as exc:
        _refuse("APPROVAL_REGISTRY_INVALID", str(exc)[:160])


def _config(path):
    try:
        from trust.config import ConfigError, TrustConfig
    except ImportError as exc:
        _refuse("APPROVAL_LOADER_UNAVAILABLE", f"the configuration loader needs the engine packages ({exc.__class__.__name__}); verify on the host (see HOST_SUPERVISOR_PRE_LAUNCH)")
    try:
        return TrustConfig.from_dict(_json(_read(path, "configuration"), "configuration"))
    except ConfigError as exc:
        _refuse("APPROVAL_CONFIGURATION_INVALID", str(exc)[:160])


def digests(registry_path, config_path, calibration_path=None, *, repo_root=ROOT):
    """What the Controller writes into an approval record, derived from the artifacts themselves (read-only helper)."""
    blob = record = None
    if calibration_path is not None:
        blob = _read(calibration_path, "calibration")
        record = _json(blob, "calibration")
    registry, config = _registry(registry_path, repo_root, fleet_catalog_of(record) or None), _config(config_path)      # a fleet calibration record carries the fleet model catalog the registry is parsed against
    out = dict(registry=dict(sha256=registry.sha256, status=registry.status), configuration=dict(sha256=config.sha256(), record_label=config.config_status))
    if calibration_path is not None:
        out["calibration"] = dict(calibration_id=record.get("calibration_id") if isinstance(record, dict) else None, record_sha256=hashlib.sha256(blob).hexdigest(),
                                  status=record.get("status") if isinstance(record, dict) else None)
    return out


def _parse_approval(approval_path, authorized_approval_sha256, now_ns):
    """Every check that needs only the approval file itself (stdlib only): pin, schema, role, scope, identifiers, window and the shape of its sections. Returns the record."""
    if type(now_ns) is not int:
        _refuse("APPROVAL_CLOCK_REQUIRED", "the current instant must be supplied as integer nanoseconds")
    if not (isinstance(authorized_approval_sha256, str) and HEX64.fullmatch(authorized_approval_sha256)):
        _refuse("APPROVAL_NOT_PINNED", "the approval file must be named together with its SHA-256 as stated by the Main Controller")
    blob = _read(approval_path, "approval")
    if hashlib.sha256(blob).hexdigest() != authorized_approval_sha256:
        _refuse("APPROVAL_DIGEST_MISMATCH", "the approval file is not the one the Main Controller pinned")
    data = _json(blob, "approval")
    if not isinstance(data, dict) or set(data) != _TOP:
        _refuse("APPROVAL_FIELDS", "unexpected or missing fields")
    if data["schema"] != SCHEMA or data["schema_version"] != 1 or data["scope"] not in SCOPES or data["approver_role"] != APPROVER_ROLE:
        _refuse("APPROVAL_SCHEMA_OR_ROLE", f"schema, scope in {SCOPES!r} and approver role {APPROVER_ROLE!r} are required")
    if not (isinstance(data["approval_id"], str) and IDENTIFIER.fullmatch(data["approval_id"]) and isinstance(data["approver_ref"], str) and IDENTIFIER.fullmatch(data["approver_ref"])):
        _refuse("APPROVAL_IDENTITY", "approval_id and approver_ref must be identifiers")
    issued, expires = data["issued_utc_ns"], data["expires_utc_ns"]
    if type(issued) is not int or type(expires) is not int or not 0 <= issued < expires:
        _refuse("APPROVAL_WINDOW_MALFORMED", "issued_utc_ns < expires_utc_ns, both integer nanoseconds")
    if now_ns < issued:
        _refuse("APPROVAL_NOT_YET_VALID", "the approval is dated in the future")
    if now_ns >= expires:
        _refuse("APPROVAL_EXPIRED", "the approval has expired")
    reg, cfg = data["registry"], data["configuration"]
    if not (isinstance(reg, dict) and set(reg) == {"sha256", "status"} and reg["status"] == "CONTROLLER_APPROVED" and isinstance(reg["sha256"], str) and HEX64.fullmatch(reg["sha256"])):
        _refuse("APPROVAL_REGISTRY_SECTION", "registry: {sha256, status: CONTROLLER_APPROVED}")
    if not (isinstance(cfg, dict) and set(cfg) == {"sha256", "status", "record_label"} and cfg["status"] == "CONTROLLER_APPROVED" and isinstance(cfg["sha256"], str)
            and HEX64.fullmatch(cfg["sha256"]) and isinstance(cfg["record_label"], str) and cfg["record_label"]):
        _refuse("APPROVAL_CONFIGURATION_SECTION", "configuration: {sha256, status: CONTROLLER_APPROVED, record_label}")
    section = data["calibration"]
    if section is not None and not (isinstance(section, dict) and set(section) == {"calibration_id", "record_sha256", "status"} and section["status"] == "CONTROLLER_ACCEPTED"
                                    and isinstance(section["calibration_id"], str) and IDENTIFIER.fullmatch(section["calibration_id"]) and isinstance(section["record_sha256"], str)
                                    and HEX64.fullmatch(section["record_sha256"])):
        _refuse("APPROVAL_CALIBRATION_SECTION", "calibration: null or {calibration_id, record_sha256, status: CONTROLLER_ACCEPTED}")
    return data


def scope_of(approval_path, *, authorized_approval_sha256, now_ns):
    """The scope of a pinned, schema-valid, currently valid approval file (stdlib only). The caller decides which scope its target accepts."""
    return _parse_approval(approval_path, authorized_approval_sha256, now_ns)["scope"]


def fleet_catalog_of(record):
    """{profile: {model_id, weights_sha256}} of the NON-frozen profiles named by a fleet calibration record's `models` section (None when the record carries none)."""
    models = record.get("models") if isinstance(record, dict) else None
    if not isinstance(models, dict):
        return None
    return {profile: dict(model_id=item["model_id"], weights_sha256=item["weights_sha256"]) for profile, item in models.items() if profile not in ("S", "V")}


def load_approvals(approval_path, *, authorized_approval_sha256, registry_path, config_path, calibration_path=None, now_ns, repo_root=ROOT):
    """The `ApprovalSet` for one valid, digest-pinned approval record, or `ApprovalRefused`. Every argument is explicit; nothing is discovered or defaulted."""
    data = _parse_approval(approval_path, authorized_approval_sha256, now_ns)
    issued, expires, reg, cfg = data["issued_utc_ns"], data["expires_utc_ns"], data["registry"], data["configuration"]
    fleet_catalog = None
    if data["scope"] in (PILOT_FLEET_SCOPE, PILOT_CORE_SCOPE):       # the fleet scope reads its model catalog from the (separately pinned) calibration record and needs that record
        if calibration_path is None or data["calibration"] is None:
            _refuse("APPROVAL_FLEET_NEEDS_CALIBRATION", "a fleet approval names a calibration record, which carries the fleet model catalog")
        fleet_catalog = fleet_catalog_of(_json(_read(calibration_path, "calibration"), "calibration"))
        if not fleet_catalog:
            _refuse("APPROVAL_FLEET_CATALOG_MISSING", "the calibration record names no fleet models")
    registry, config = _registry(registry_path, repo_root, fleet_catalog), _config(config_path)
    if registry.status != "CONTROLLER_APPROVED":
        _refuse("APPROVAL_REGISTRY_NOT_APPROVED", f"the registry file has status {registry.status}")
    if registry.sha256 != reg["sha256"]:
        _refuse("APPROVAL_REGISTRY_DIGEST_MISMATCH", "the registry file is not the one the approval names")
    if config.sha256() != cfg["sha256"] or config.config_status != cfg["record_label"]:
        _refuse("APPROVAL_CONFIGURATION_DIGEST_MISMATCH", "the configuration file (or the label its decisions will carry) is not the one the approval names")
    calibration_id = None
    section = data["calibration"]
    if section is not None:
        if calibration_path is None:
            _refuse("APPROVAL_CALIBRATION_ARTIFACT_MISSING", "the approval names a calibration but its record file was not supplied")
        blob_c = _read(calibration_path, "calibration")
        record = _json(blob_c, "calibration")
        if (hashlib.sha256(blob_c).hexdigest() != section["record_sha256"] or not isinstance(record, dict) or record.get("calibration_id") != section["calibration_id"]
                or record.get("status") != "CONTROLLER_ACCEPTED"):
            _refuse("APPROVAL_CALIBRATION_MISMATCH", "the calibration record is not the accepted one the approval names")
        calibration_id = section["calibration_id"]
    elif calibration_path is not None:
        _refuse("APPROVAL_CALIBRATION_NOT_APPROVED", "a calibration file was supplied but the approval does not approve one")
    return ApprovalSet(calibration_id, registry.sha256, "CONTROLLER_APPROVED", config.sha256(), "CONTROLLER_APPROVED", config_record_label=config.config_status,
                       approval_id=data["approval_id"], valid_from_ns=issued, valid_until_ns=expires - 1)


HOST_VERIFIED = "HOST_SUPERVISOR_PRE_LAUNCH"


def load_host_verified(approval_path, *, authorized_approval_sha256, now_ns):
    """The `ApprovalSet` for an approval whose ARTIFACTS were already re-derived and compared on the host by `load_approvals` before the service was launched (stdlib only: the PEP
    container mounts none of the engine packages that derivation needs). This function re-checks everything the approval file itself carries: the Controller's pin, schema, role, scope, window
    and sections. It does NOT re-derive the registry, configuration or calibration digests; those are enforced independently on EVERY decision, because the guard refuses a record whose
    registry digest, configuration digest/label or calibration id differs from the ones this approval names (a decision made under any other artifact can not be authorized)."""
    data = _parse_approval(approval_path, authorized_approval_sha256, now_ns)
    calibration = data["calibration"]
    return ApprovalSet(calibration["calibration_id"] if calibration else None, data["registry"]["sha256"], "CONTROLLER_APPROVED", data["configuration"]["sha256"], "CONTROLLER_APPROVED",
                       config_record_label=data["configuration"]["record_label"], approval_id=data["approval_id"], valid_from_ns=data["issued_utc_ns"], valid_until_ns=data["expires_utc_ns"] - 1)


def from_spec(spec, *, now_ns, repo_root=ROOT):
    """The service configuration's optional `operational_approval` section -> ApprovalSet. Absent means NO approvals (enforcement stays off); present but unusable refuses to start.
    Two forms: the full form (all artifacts re-derived in this process) and `artifact_verification: HOST_SUPERVISOR_PRE_LAUNCH` (only the pinned approval file, for a process that cannot
    import the engine; the supervisor has already run the full form)."""
    section = spec.get("operational_approval")
    if section is None:
        return ApprovalSet()
    if isinstance(section, dict) and "artifact_verification" in section:
        if set(section) != {"approval", "approval_sha256", "artifact_verification"} or section["artifact_verification"] != HOST_VERIFIED:
            _refuse("APPROVAL_SPEC", f"operational_approval with artifact_verification: exactly approval, approval_sha256 and artifact_verification = {HOST_VERIFIED}")
        return load_host_verified(section["approval"], authorized_approval_sha256=section["approval_sha256"], now_ns=now_ns)
    required, allowed = {"approval", "approval_sha256", "registry", "config"}, {"approval", "approval_sha256", "registry", "config", "calibration"}
    if not isinstance(section, dict) or not required <= set(section) or set(section) - allowed:
        _refuse("APPROVAL_SPEC", "operational_approval: approval, approval_sha256, registry, config and optionally calibration")
    return load_approvals(section["approval"], authorized_approval_sha256=section["approval_sha256"], registry_path=section["registry"], config_path=section["config"],
                          calibration_path=section.get("calibration"), now_ns=now_ns, repo_root=repo_root)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("digests", "verify"):
        p = sub.add_parser(name)
        p.add_argument("--registry", required=True)
        p.add_argument("--config", required=True)
        p.add_argument("--calibration")
    verify = sub.choices["verify"]
    verify.add_argument("--approval", required=True)
    verify.add_argument("--approval-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "digests":
            print(json.dumps(digests(args.registry, args.config, args.calibration), sort_keys=True, indent=1))
        else:
            approvals = load_approvals(args.approval, authorized_approval_sha256=args.approval_sha256, registry_path=args.registry, config_path=args.config,
                                       calibration_path=args.calibration, now_ns=time.time_ns())
            print(json.dumps(dict(result="APPROVAL_VALID", approval_id=approvals.approval_id, registry_sha256=approvals.registry_sha256, config_sha256=approvals.config_sha256,
                                  config_record_label=approvals.config_record_label, calibration_id=approvals.calibration_id,
                                  behavioural_decisions_enabled=bool(approvals.calibration_id), still_missing=approvals.missing(),
                                  note="verification only: nothing was enabled"), sort_keys=True, indent=1))
        return 0
    except EnforcementError as exc:
        print(f"APPROVAL_REFUSED {getattr(exc, 'code', type(exc).__name__)}: {str(exc)[:200]}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
