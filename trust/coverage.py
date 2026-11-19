"""Device-to-model coverage (Gate 5F): which devices of a registry a frozen behavioural model may score, and why the others may not.

A coverage record is a typed, digest-bound statement per registry device. It is NOT a route by itself: a device is routed to a model only
when its row says APPROVED, and a row can only be APPROVED when every provenance condition the engine enforces already holds, so the
record can never be used to launder an incompatible device into scoring:

  * PIN       the record's registry and observation-configuration digests equal the ones the model was fitted AND calibrated under
              (a ten-device registry has a different digest, so no row of such a record can be approved today);
  * LAW       the device's traffic law is the law the model was trained on (`frozen_model_law_equivalent` names the model, else null);
  * SCORABLE  the six-feature, 10 s observation definition yields score-ready windows for that law (sparse devices do not: they stay
              REFUSED, they are never padded, interpolated or given a longer window here - changing the observation definition is a
              scientific decision outside this module);
  * APPROVAL  a controller approval reference is present.

The engine still re-checks the pins on every window (`preprocessing.gate5d_data.classify_window`); nothing here replaces that check.
`assignment()` returns a ProfileAssignment containing ONLY approved routes, so every other device reaches the engine with no profile and is
refused as NO_APPROVED_PROFILE_ROUTE. Pure functions; no file is opened and no evidence is read.
"""
from dataclasses import dataclass
import re

from trust.errors import ArtifactRefused
from trust.producer import ProfileAssignment

COVERAGE_SCHEMA = "azta.gate5f.model_coverage"
COVERAGE_SCHEMA_VERSION = 1
STATUSES = ("ENGINEERING_CANDIDATE_UNAPPROVED", "CONTROLLER_APPROVED")
SCORABILITY = ("SCORABLE", "PARTIAL", "UNSCORABLE")
ROUTE_STATUS = ("NOT_APPROVED", "APPROVED")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_TOP = {"schema", "schema_version", "status", "registry_sha256", "observation_config_sha256", "frozen_models", "devices", "basis"}
_ROW = {"device", "law_class", "frozen_model_law_equivalent", "eligible_windows", "planned_score_ready_windows", "scorability",
        "route", "blockers"}
_ROUTE = {"profile", "status", "approval_ref"}


def _require(condition, message):
    if not condition:
        raise ArtifactRefused(f"model coverage: {message}")


@dataclass(frozen=True)
class RouteDecision:
    device: str
    profile: object
    reason: str          # "ROUTED" or the refusal code


@dataclass(frozen=True)
class Coverage:
    status: str
    registry_sha256: str
    observation_config_sha256: str
    rows: dict
    frozen_models: dict


def scorability_of(eligible, ready):
    return "SCORABLE" if ready == eligible and eligible > 0 else "UNSCORABLE" if ready == 0 else "PARTIAL"


def parse_coverage(data, *, model_pins):
    """Validate one coverage record. `model_pins` = {profile: {registry_sha256, observation_config_sha256}} the frozen models were fitted and
    calibrated under. Raises ArtifactRefused on anything inconsistent; an approved row for an incompatible pin can never be parsed."""
    _require(isinstance(data, dict) and set(data) == _TOP, "unexpected or missing fields")
    _require(data["schema"] == COVERAGE_SCHEMA and data["schema_version"] == COVERAGE_SCHEMA_VERSION, "schema")
    _require(data["status"] in STATUSES, "status")
    for key in ("registry_sha256", "observation_config_sha256"):
        _require(isinstance(data[key], str) and HEX64.fullmatch(data[key]), key)
    _require(isinstance(data["frozen_models"], list) and data["frozen_models"] and set(data["frozen_models"]) <= set(model_pins),
             "frozen_models must name known frozen profiles")
    rows = {}
    for row in data["devices"]:
        _require(isinstance(row, dict) and set(row) == _ROW, "device row: unexpected or missing fields")
        device = row["device"]
        _require(isinstance(device, str) and IDENTIFIER.fullmatch(device) and device not in rows, f"device identifier / duplicate {device!r}")
        _require(row["frozen_model_law_equivalent"] in (None, *data["frozen_models"]), f"{device}: unknown frozen model law")
        eligible, ready = row["eligible_windows"], row["planned_score_ready_windows"]
        _require(type(eligible) is int and type(ready) is int and 0 <= ready <= eligible, f"{device}: window counts")
        _require(row["scorability"] == scorability_of(eligible, ready), f"{device}: scorability disagrees with the planned window counts")
        route = row["route"]
        _require(isinstance(route, dict) and set(route) == _ROUTE and route["status"] in ROUTE_STATUS, f"{device}: route")
        _require(isinstance(row["blockers"], list) and all(isinstance(b, str) and b for b in row["blockers"]), f"{device}: blockers")
        if route["status"] == "APPROVED":
            profile = route["profile"]
            _require(profile in data["frozen_models"] and profile == row["frozen_model_law_equivalent"],
                     f"{device}: a route needs a frozen model whose training law equals the device's law")
            _require(row["scorability"] == "SCORABLE", f"{device}: only a fully scorable device can be approved")
            pins = model_pins[profile]
            _require(data["registry_sha256"] == pins["registry_sha256"] and data["observation_config_sha256"] == pins["observation_config_sha256"],
                     f"{device}: PIN_MISMATCH - the model was fitted and calibrated under another registry/configuration; "
                     "no route can be approved by relabelling")
            _require(isinstance(route["approval_ref"], str) and IDENTIFIER.fullmatch(route["approval_ref"]), f"{device}: approval reference")
            _require(data["status"] == "CONTROLLER_APPROVED", f"{device}: routes are only valid in a controller-approved record")
            _require(not row["blockers"], f"{device}: an approved route cannot carry blockers")
        else:
            _require(route["profile"] is None and route["approval_ref"] is None, f"{device}: an unapproved route names no profile")
            _require(row["blockers"], f"{device}: an unapproved device must state its blockers")
        rows[device] = row
    _require(rows, "no devices")
    return Coverage(data["status"], data["registry_sha256"], data["observation_config_sha256"], rows, {p: model_pins[p] for p in data["frozen_models"]})


def route(coverage, device):
    """The routing decision for one device, with the precise reason for any refusal. Unknown or unapproved devices are never defaulted."""
    row = coverage.rows.get(device)
    if row is None:
        return RouteDecision(device, None, "UNKNOWN_DEVICE")
    if row["route"]["status"] == "APPROVED":
        return RouteDecision(device, row["route"]["profile"], "ROUTED")
    if row["scorability"] == "UNSCORABLE":
        return RouteDecision(device, None, "UNSCORABLE_AT_WINDOW_DEFINITION")
    if row["frozen_model_law_equivalent"] is None:
        return RouteDecision(device, None, "NO_FROZEN_MODEL_FOR_TRAFFIC_LAW")
    return RouteDecision(device, None, "ROUTE_NOT_APPROVED")


def assignment(coverage, *, version=1):
    """A profile assignment containing only approved routes, bound to the coverage record's registry and configuration digests."""
    routed = {d: r["route"]["profile"] for d, r in coverage.rows.items() if r["route"]["status"] == "APPROVED"}
    return ProfileAssignment(version, coverage.registry_sha256, coverage.observation_config_sha256, "VERSIONED_PROFILE_ASSIGNMENT", routed, {})


def summarize(coverage):
    """Counts the controller needs: routed devices, reusable frozen laws, distinct new traffic laws, and what is structurally unscorable."""
    rows = list(coverage.rows.values())
    needs_model = [r for r in rows if r["frozen_model_law_equivalent"] is None and r["scorability"] != "UNSCORABLE"]
    return dict(
        devices=len(rows), routed=sum(r["route"]["status"] == "APPROVED" for r in rows),
        devices_with_a_frozen_traffic_law=sorted(r["device"] for r in rows if r["frozen_model_law_equivalent"]),
        distinct_new_traffic_laws_needing_benign_training=sorted({r["law_class"] for r in needs_model}),
        devices_needing_a_new_model_or_a_validated_shared_one=sorted(r["device"] for r in needs_model),
        structurally_unscorable_at_the_10s_six_feature_definition=sorted(r["device"] for r in rows if r["scorability"] == "UNSCORABLE"),
        partially_scorable=sorted(r["device"] for r in rows if r["scorability"] == "PARTIAL"))
