"""Versioned, auditable device-to-profile registry with model identity (decision pipeline, stage "device/profile routing").

One JSON record (schema `azta.decision.device_profile_registry`) states, for every broker principal the observer can bind, which frozen behavioural
model (profile S or V) may score its windows, with what approval, and why not when it may not. It is a ROUTING authority only:

  * a device is routed only when its row is APPROVED, and a row can only be APPROVED when every provenance condition the trust engine enforces already
    holds (the registry and observation-configuration pins equal the ones the models were fitted and calibrated under, the model named is exactly the
    frozen one, the traffic law is the law the model learned, an approval reference exists) - so a registry can never launder a ten-device principal, an
    experimental model (S k = 4), an unscorable device or an unapproved assignment into scoring;
  * the device is the observer's broker-bound identity (`window["device"]`, set by the exact-topic binding against audited exclusive publish ACLs).
    A payload, a `device_id` field or any publisher assertion has no parameter anywhere in this module;
  * many devices may share one model: nothing assumes one trained model per device; ten simulated devices need two profile models at most today, and
    every device whose law has no frozen model stays explicitly unrouted with its blockers;
  * `registry_version`, `supersedes_sha256` and the append-only `change_log` make every change auditable; the record's SHA-256 is written into every
    decision record that used it;
  * the four statuses are never interchangeable: ENGINEERING_CANDIDATE_UNAPPROVED routes nothing, SYNTHETIC_ENGINEERING_FIXTURE routes only for
    SYNTHETIC_FIXTURE bundles (it can never route real evidence), ENGINEERING_FUNCTIONAL_UNAPPROVED routes only windows whose observer-stated purpose is
    FUNCTIONAL_TEST (a non-scientific run: it can never route a COLLECTION window, a scientific partition or a synthetic bundle, and it carries no
    approval), and CONTROLLER_APPROVED needs a controller approval reference per routed row.

Pure functions and a loader that reads one named file: no network, no broker, no write.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re

from decision_pipeline.errors import ModelVersionMismatch, RegistryRefused

SCHEMA = "azta.decision.device_profile_registry"
SCHEMA_VERSION = 1
STATUSES = ("ENGINEERING_CANDIDATE_UNAPPROVED", "SYNTHETIC_ENGINEERING_FIXTURE", "ENGINEERING_FUNCTIONAL_UNAPPROVED", "CONTROLLER_APPROVED")
ROUTE_STATUS = ("NOT_APPROVED", "APPROVED")
SCORABILITY = ("SCORABLE", "PARTIAL", "UNSCORABLE")
SYNTHETIC_APPROVAL = "SYNTHETIC_ENGINEERING_FIXTURE"
FUNCTIONAL_APPROVAL = "ENGINEERING_FUNCTIONAL_UNAPPROVED"   # marker in a functional engineering registry: explicitly NOT a controller approval
FUNCTIONAL_PURPOSE = "FUNCTIONAL_TEST"                     # the observer-stated purpose of a non-scientific functional run (window["purpose"])
SYNTHETIC_LABEL = "SYNTHETIC_FIXTURE"                     # the only route provenance a synthetic bundle may carry (trust.evidence)
TRUSTED_LABEL = "VERSIONED_PROFILE_ASSIGNMENT"            # a trusted route provenance for non-synthetic bundles (trust.evidence)
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_TOP = {"schema", "schema_version", "registry_version", "status", "supersedes_sha256", "pins", "models", "devices", "change_log"}
_PINS = {"registry_sha256", "observation_config_sha256"}
_MODEL = {"model_id", "weights_sha256"}
_ROW = {"device", "law_class", "frozen_model_law_equivalent", "scorability", "route", "blockers"}
_ROUTE = {"profile", "status", "approval_ref"}
_LOG = {"registry_version", "summary", "author_role", "approval_ref"}

# stable resolution codes
ROUTED = "ROUTED"
UNKNOWN_DEVICE = "UNKNOWN_DEVICE"
PIN_MISMATCH = "PIN_MISMATCH"
ROUTE_NOT_APPROVED = "ROUTE_NOT_APPROVED"
NO_FROZEN_MODEL_FOR_LAW = "NO_FROZEN_MODEL_FOR_LAW"
UNSCORABLE = "UNSCORABLE_AT_WINDOW_DEFINITION"
EVIDENCE_CLASS_MISMATCH = "EVIDENCE_CLASS_MISMATCH"
REGISTRY_NOT_SUPPLIED = "REGISTRY_NOT_SUPPLIED"
WINDOW_UNREADABLE = "WINDOW_PINS_UNREADABLE"
ROUTE_CONFLICT = "ROUTE_CONFLICT"                       # set by the integrated engine: the registry and a trusted producer route disagree


def _require(condition, code, message):
    if not condition:
        raise RegistryRefused(code, message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def record_sha256(data):
    return hashlib.sha256(canonical(data).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RouteResolution:
    device: object
    profile: object            # S, V or None
    code: str                  # ROUTED or the refusal code
    route_label: object        # the route provenance a bundle may carry (None when not routed)
    registry_version: object
    registry_sha256: object
    model_id: object
    model_weights_sha256: object
    blockers: tuple = ()

    @property
    def routed(self):
        return self.code == ROUTED

    def to_dict(self):
        return dict(device=self.device, profile=self.profile, code=self.code, route_label=self.route_label, registry_version=self.registry_version,
                    registry_sha256=self.registry_sha256, model_id=self.model_id, model_weights_sha256=self.model_weights_sha256,
                    blockers=list(self.blockers))


@dataclass(frozen=True)
class DeviceProfileRegistry:
    data: dict
    sha256: str
    rows: dict

    @property
    def status(self):
        return self.data["status"]

    @property
    def version(self):
        return self.data["registry_version"]

    @property
    def synthetic(self):
        return self.status == "SYNTHETIC_ENGINEERING_FIXTURE"

    @property
    def functional(self):
        return self.status == "ENGINEERING_FUNCTIONAL_UNAPPROVED"

    def describe(self):
        routed = sorted(d for d, r in self.rows.items() if r["route"]["status"] == "APPROVED")
        return dict(schema=SCHEMA, registry_version=self.version, status=self.status, sha256=self.sha256, supersedes_sha256=self.data["supersedes_sha256"],
                    pins=dict(self.data["pins"]), models=json.loads(canonical(self.data["models"])), devices=len(self.rows), routed_devices=routed,
                    unrouted_devices=sorted(set(self.rows) - set(routed)), change_log_entries=len(self.data["change_log"]))

    def resolve(self, device, *, window_registry_sha256, window_config_sha256, evidence_mode, window_purpose):
        """The routing decision for ONE window's authenticated device, with the exact reason for any refusal. Nothing is defaulted."""
        pins = self.data["pins"]

        def result(code, profile=None, label=None, blockers=(), row=None):
            model = self.data["models"].get(profile) if profile else None
            return RouteResolution(device, profile, code, label, self.version, self.sha256, model["model_id"] if model else None,
                                   model["weights_sha256"] if model else None, tuple(blockers))

        if not (isinstance(window_registry_sha256, str) and isinstance(window_config_sha256, str)):
            return result(WINDOW_UNREADABLE)
        row = self.rows.get(device) if isinstance(device, str) else None
        if row is None:
            return result(UNKNOWN_DEVICE)
        blockers = row["blockers"]
        if (window_registry_sha256, window_config_sha256) != (pins["registry_sha256"], pins["observation_config_sha256"]):
            return result(PIN_MISMATCH, blockers=("the window was observed under another registry or observation configuration than the one this "
                                                  "registry and its models were fitted under; no route is carried across pins", *blockers))
        synthetic_bundle = evidence_mode == "SYNTHETIC_FIXTURE"
        if synthetic_bundle != self.synthetic or (self.functional and window_purpose != FUNCTIONAL_PURPOSE):
            return result(EVIDENCE_CLASS_MISMATCH, blockers=("a synthetic registry routes only synthetic bundles and a synthetic bundle only uses a synthetic "
                                                             "registry; a functional engineering registry routes only windows of a FUNCTIONAL_TEST run",))
        if row["route"]["status"] != "APPROVED":
            if row["scorability"] == "UNSCORABLE":
                return result(UNSCORABLE, blockers=blockers)
            if row["frozen_model_law_equivalent"] is None:
                return result(NO_FROZEN_MODEL_FOR_LAW, blockers=blockers)
            return result(ROUTE_NOT_APPROVED, blockers=blockers)
        return result(ROUTED, profile=row["route"]["profile"], label=SYNTHETIC_LABEL if self.synthetic else TRUSTED_LABEL)

    def verify_loaded_models(self, descriptors):
        """The loaded frozen models must be exactly the ones this registry names. `descriptors` = {profile: {fit_id, weights_sha256, ...}}."""
        for profile, named in self.data["models"].items():
            loaded = descriptors.get(profile)
            if loaded is None:
                raise ModelVersionMismatch(f"the registry names a {profile} model but none is loaded")
            if (loaded["fit_id"], loaded["weights_sha256"]) != (named["model_id"], named["weights_sha256"]):
                raise ModelVersionMismatch(f"{profile}: the loaded model {loaded['fit_id']} ({loaded['weights_sha256'][:12]}...) is not the registry's "
                                           f"{named['model_id']} ({named['weights_sha256'][:12]}...)")
        return True


def _check_text_list(values, code, label):
    _require(isinstance(values, list) and all(isinstance(v, str) and v for v in values), code, label)


def parse_registry(data, *, model_catalog, model_pins):
    """Validate one registry record. `model_catalog` = {profile: {model_id, weights_sha256}} of the FROZEN models; `model_pins` = the registry and
    observation-configuration digests those models were fitted and calibrated under. Raises RegistryRefused on anything inconsistent."""
    _require(isinstance(data, dict) and set(data) == _TOP, "REGISTRY_FIELDS", "unexpected or missing fields")
    _require(data["schema"] == SCHEMA and data["schema_version"] == SCHEMA_VERSION, "REGISTRY_SCHEMA", "schema or schema_version")
    version, status = data["registry_version"], data["status"]
    _require(type(version) is int and version >= 1 and status in STATUSES, "REGISTRY_VERSION_OR_STATUS", "registry_version >= 1 and a known status")
    sup = data["supersedes_sha256"]
    _require((sup is None) == (version == 1) and (sup is None or (isinstance(sup, str) and HEX64.fullmatch(sup))), "REGISTRY_LINEAGE",
             "version 1 supersedes nothing; every later version names the SHA-256 of the record it supersedes")
    pins = data["pins"]
    _require(isinstance(pins, dict) and set(pins) == _PINS and all(isinstance(v, str) and HEX64.fullmatch(v) for v in pins.values()),
             "REGISTRY_PINS", "pins")
    models = data["models"]
    _require(isinstance(models, dict) and models and set(models) <= set(model_catalog), "REGISTRY_MODELS", "models must name known frozen profiles")
    for profile, named in models.items():
        _require(isinstance(named, dict) and set(named) == _MODEL, "REGISTRY_MODELS", f"{profile}: model fields")
        frozen = model_catalog[profile]
        if (named["model_id"], named["weights_sha256"]) != (frozen["model_id"], frozen["weights_sha256"]):
            raise ModelVersionMismatch(f"{profile}: {named['model_id']} is not the frozen model {frozen['model_id']}; an experimental or other model "
                                       "is never routable (a model change is a controller decision with a new calibration and freeze)")
    pinned = tuple(pins[k] for k in ("registry_sha256", "observation_config_sha256")) == tuple(model_pins[k] for k in ("registry_sha256",
                                                                                                                         "observation_config_sha256"))
    rows = {}
    for row in data["devices"]:
        _require(isinstance(row, dict) and set(row) == _ROW, "ROW_FIELDS", "device row: unexpected or missing fields")
        device = row["device"]
        _require(isinstance(device, str) and IDENTIFIER.fullmatch(device) and device not in rows, "ROW_DEVICE", f"device identifier / duplicate {device!r}")
        _require(row["frozen_model_law_equivalent"] in (None, *models), "ROW_LAW", f"{device}: unknown frozen model law")
        _require(row["scorability"] in SCORABILITY and isinstance(row["law_class"], str) and row["law_class"], "ROW_SCORABILITY", f"{device}: scorability")
        route = row["route"]
        _require(isinstance(route, dict) and set(route) == _ROUTE and route["status"] in ROUTE_STATUS, "ROW_ROUTE", f"{device}: route")
        _check_text_list(row["blockers"], "ROW_BLOCKERS", f"{device}: blockers")
        if route["status"] == "APPROVED":
            _require(status != "ENGINEERING_CANDIDATE_UNAPPROVED", "ROUTE_IN_UNAPPROVED_REGISTRY", f"{device}: a candidate registry routes nothing")
            _require(route["profile"] in models and route["profile"] == row["frozen_model_law_equivalent"], "ROUTE_LAW_MISMATCH",
                     f"{device}: a route needs a frozen model whose training law equals the device's law")
            _require(row["scorability"] == "SCORABLE", "ROUTE_NOT_SCORABLE", f"{device}: only a fully scorable device can be routed")
            _require(pinned, "PIN_MISMATCH", f"{device}: the models were fitted and calibrated under another registry/configuration; a route "
                                             "cannot be approved by relabelling")
            ref = route["approval_ref"]
            markers = {"SYNTHETIC_ENGINEERING_FIXTURE": SYNTHETIC_APPROVAL, "ENGINEERING_FUNCTIONAL_UNAPPROVED": FUNCTIONAL_APPROVAL}
            if status in markers:
                _require(ref == markers[status], "ROUTE_APPROVAL", f"{device}: a {status} route carries exactly {markers[status]!r} (not an approval)")
            else:
                _require(isinstance(ref, str) and IDENTIFIER.fullmatch(ref) and ref not in markers.values(), "ROUTE_APPROVAL",
                         f"{device}: a controller approval reference is required")
            _require(not row["blockers"], "ROUTE_BLOCKERS", f"{device}: a routed device cannot carry blockers")
        else:
            _require(route["profile"] is None and route["approval_ref"] is None, "ROUTE_UNAPPROVED_FIELDS", f"{device}: an unapproved route names no profile")
            _require(row["blockers"], "ROUTE_BLOCKERS", f"{device}: an unapproved device must state its blockers")
        rows[device] = row
    _require(rows, "NO_DEVICES", "no devices")
    log = data["change_log"]
    _require(isinstance(log, list) and log and all(isinstance(e, dict) and set(e) == _LOG for e in log), "CHANGE_LOG", "change_log entries")
    versions = [e["registry_version"] for e in log]
    _require(all(type(v) is int for v in versions) and versions == sorted(set(versions)) and versions[-1] == version, "CHANGE_LOG",
             "change_log is append-only, strictly ascending and ends at registry_version")
    _require(all(isinstance(e["summary"], str) and e["summary"] and isinstance(e["author_role"], str) and e["author_role"] for e in log), "CHANGE_LOG",
             "change_log summary and author_role")
    if status == "CONTROLLER_APPROVED":
        _require(all(isinstance(e["approval_ref"], str) and e["approval_ref"] for e in log[-1:]), "CHANGE_LOG", "the latest change needs an approval reference")
    return DeviceProfileRegistry(data, record_sha256(data), rows)


def load_registry(path, *, authorized_file_sha256, model_catalog, model_pins):
    """Read ONE named registry file, require its bytes to equal the authorized SHA-256, then validate it. No default path, no discovery."""
    _require(isinstance(authorized_file_sha256, str) and HEX64.fullmatch(authorized_file_sha256), "REGISTRY_AUTHORIZATION",
             "the registry file must be named together with its authorized SHA-256")
    blob = Path(path).read_bytes()
    actual = hashlib.sha256(blob).hexdigest()
    _require(actual == authorized_file_sha256, "REGISTRY_DIGEST", f"registry file SHA-256 {actual} differs from the authorized {authorized_file_sha256}")
    try:
        data = json.loads(blob.decode("utf-8"), parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
    except ValueError as exc:
        raise RegistryRefused("REGISTRY_JSON", f"not valid JSON ({exc.__class__.__name__})") from exc
    return parse_registry(data, model_catalog=model_catalog, model_pins=model_pins)


def model_catalog_from_freeze(freeze):
    """{profile: {model_id, weights_sha256}} of the frozen candidates, from the digest-verified Gate 5E freeze record (`trust.artifacts.load_freeze`)."""
    fits = freeze["candidates"]["fits"]
    return {profile: dict(model_id=spec["fit_id"], weights_sha256=spec["weights_sha256"]) for profile, spec in fits.items()}


def registry_from_coverage(coverage, *, registry_version, model_catalog, summary, author_role):
    """A CANDIDATE registry (routes nothing) built from a validated `trust.coverage` record: the same per-device law, scorability and blockers,
    plus model identity, version and change log. It can never carry an approved route."""
    _require(isinstance(coverage, dict) and coverage.get("schema") == "azta.gate5f.model_coverage", "COVERAGE_RECORD", "not a model coverage record")
    rows = []
    for row in coverage["devices"]:
        rows.append(dict(device=row["device"], law_class=row["law_class"], frozen_model_law_equivalent=row["frozen_model_law_equivalent"],
                         scorability=row["scorability"], route=dict(profile=None, status="NOT_APPROVED", approval_ref=None),
                         blockers=list(row["blockers"]) or ["NO_APPROVED_ROUTE"]))
    return dict(schema=SCHEMA, schema_version=SCHEMA_VERSION, registry_version=registry_version, status="ENGINEERING_CANDIDATE_UNAPPROVED",
                supersedes_sha256=None, pins=dict(registry_sha256=coverage["registry_sha256"], observation_config_sha256=coverage["observation_config_sha256"]),
                models={p: dict(model_catalog[p]) for p in coverage["frozen_models"]}, devices=rows,
                change_log=[dict(registry_version=registry_version, summary=summary, author_role=author_role, approval_ref=None)])
