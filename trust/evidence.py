"""Gate 5F evidence bundle: the single offline input of the trust engine, and the rules shared by all three components.

A bundle holds, for one decision instant, the identity evidence, the behavioural observation window (a Gate 5B window record), the
contextual evidence, and free-form annotations that the engine never reads. Provenance is explicit: evidence counts only when its
provenance label is trusted for the bundle's evidence mode. A SYNTHETIC_FIXTURE bundle may only carry SYNTHETIC_FIXTURE provenance, so a
fixture can never pass for audited evidence; a TRUSTED_OFFLINE_REPLAY bundle may never carry it. Anything else (publisher assertions,
payload claims, unknown labels) is not evidence. Times are integer nanoseconds on the bundle's single declared clock.
"""
from dataclasses import dataclass
from fractions import Fraction
import math
import re

from trust.errors import BundleRefused

BUNDLE_SCHEMA = "azta.gate5f.evidence_bundle"
BUNDLE_SCHEMA_VERSION = 1
EVIDENCE_MODES = ("SYNTHETIC_FIXTURE", "TRUSTED_OFFLINE_REPLAY")
SYNTHETIC_PROVENANCE = "SYNTHETIC_FIXTURE"
TRUSTED_EVIDENCE_PROVENANCE = ("BROKER_POLICY_AUDIT", "VERSIONED_REGISTRY", "VERSIONED_CONFIGURATION", "TRUSTED_INSTRUMENTATION")
TRUSTED_ROUTE_PROVENANCE = ("FROZEN_PLAN", "VERSIONED_PROFILE_ASSIGNMENT")
IDENTITY_STATUSES = ("VALID_AUTHORIZED", "INVALID", "UNKNOWN", "EXPIRED", "REVOKED", "UNAUTHORIZED", "UNAVAILABLE")
IDENTITY_FAILURE_STATUSES = ("INVALID", "UNKNOWN", "EXPIRED", "REVOKED", "UNAUTHORIZED")
EVALUATED, MISSING = "EVALUATED", "MISSING"
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_BUNDLE_KEYS = {"schema", "schema_version", "evidence_id", "evidence_mode", "clock_basis", "decision_ns", "identity", "behavior",
                "context"}
_IDENTITY_KEYS = {"status", "provenance", "bound_username", "bound_client_id", "policy_sha256", "audit_ref", "observed_ns"}
_BEHAVIOR_KEYS = {"window", "bound_profile", "route_provenance", "observed_ns", "workload_version"}
_CRITERION_KEYS = {"criterion_id", "conformity", "provenance", "observed_ns", "source_ref"}


@dataclass(frozen=True)
class ComponentResult:
    """outcome EVALUATED carries an exact score in [0, 100]; MISSING carries reasons and no score. `detail` is the JSON log block."""
    outcome: str
    score: object
    reasons: tuple
    detail: dict


@dataclass(frozen=True)
class EvidenceBundle:
    evidence_id: str
    evidence_mode: str
    clock_basis: str
    decision_ns: int
    identity: object
    behavior: object
    context: object
    annotations: dict


def provenance_trusted(label, evidence_mode, trusted):
    if evidence_mode == "SYNTHETIC_FIXTURE":
        return label == SYNTHETIC_PROVENANCE
    return label in trusted


def age_problem(observed_ns, decision_ns, max_age_ns):
    """None when the evidence is usable at the decision instant, else the reason code. Exactly max_age_ns old is still fresh."""
    if observed_ns > decision_ns:
        return "EVIDENCE_FROM_FUTURE"
    if decision_ns - observed_ns > max_age_ns:
        return "STALE"
    return None


def _check(condition, message):
    if not condition:
        raise BundleRefused(message)


def _keys(data, expected, label):
    _check(isinstance(data, dict) and set(data) == set(expected), f"{label}: unexpected or missing fields")


def _ns(value, name):
    _check(type(value) is int and value >= 0, f"{name}: a non-negative integer (ns) is required")
    return value


def _opt_text(value, name):
    _check(value is None or (isinstance(value, str) and 0 < len(value) <= 256), f"{name}: non-empty string or null")
    return value


def parse_bundle(data):
    """Strict structural validation. Component-level problems (missing, stale, untrusted) are NOT refusals here: they become
    MISSING outcomes in the engine so that every well-formed bundle yields an inspectable decision record."""
    _check(isinstance(data, dict) and set(data) - {"annotations"} == _BUNDLE_KEYS, "bundle: unexpected or missing fields")
    _check(data["schema"] == BUNDLE_SCHEMA and data["schema_version"] == BUNDLE_SCHEMA_VERSION, "bundle: schema")
    _check(isinstance(data["evidence_id"], str) and IDENTIFIER.fullmatch(data["evidence_id"]), "evidence_id: identifier required")
    _check(data["evidence_mode"] in EVIDENCE_MODES, f"evidence_mode must be one of {EVIDENCE_MODES}")
    _check(isinstance(data["clock_basis"], str) and 0 < len(data["clock_basis"]) <= 64, "clock_basis: string required")
    decision_ns = _ns(data["decision_ns"], "decision_ns")
    annotations = data.get("annotations", {})
    _check(isinstance(annotations, dict), "annotations: object required")

    identity = data["identity"]
    if identity is not None:
        _keys(identity, _IDENTITY_KEYS, "identity")
        _check(identity["status"] in IDENTITY_STATUSES, f"identity.status must be one of {IDENTITY_STATUSES}")
        _check(isinstance(identity["provenance"], str) and identity["provenance"], "identity.provenance: string required")
        for key in ("bound_username", "bound_client_id", "policy_sha256", "audit_ref"):
            _opt_text(identity[key], f"identity.{key}")
        _ns(identity["observed_ns"], "identity.observed_ns")
        if identity["status"] == "VALID_AUTHORIZED":
            _check(identity["bound_username"] and identity["bound_client_id"],
                   "identity: VALID_AUTHORIZED requires the bound username and client id")

    behavior = data["behavior"]
    if behavior is not None:
        _keys(behavior, _BEHAVIOR_KEYS, "behavior")
        _check(behavior["window"] is None or isinstance(behavior["window"], dict), "behavior.window: object or null")
        _opt_text(behavior["bound_profile"], "behavior.bound_profile")
        _check(isinstance(behavior["route_provenance"], str) and behavior["route_provenance"], "behavior.route_provenance: string")
        _ns(behavior["observed_ns"], "behavior.observed_ns")
        _opt_text(behavior["workload_version"], "behavior.workload_version")

    context = data["context"]
    if context is not None:
        _keys(context, {"criteria"}, "context")
        _check(isinstance(context["criteria"], list), "context.criteria: list required")
        seen = set()
        for item in context["criteria"]:
            _keys(item, _CRITERION_KEYS, "context criterion")
            _check(isinstance(item["criterion_id"], str) and item["criterion_id"], "context criterion_id: string required")
            _check(item["criterion_id"] not in seen, f"duplicate context criterion {item['criterion_id']!r}")
            seen.add(item["criterion_id"])
            value = item["conformity"]
            _check(value is None or (isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
                                     and 0 <= value <= 1), "context conformity must be null or a finite number in [0, 1]")
            _check(isinstance(item["provenance"], str) and item["provenance"], "context provenance: string required")
            _opt_text(item["source_ref"], "context source_ref")
            _ns(item["observed_ns"], "context observed_ns")
    return EvidenceBundle(data["evidence_id"], data["evidence_mode"], data["clock_basis"], decision_ns, identity, behavior, context,
                          annotations)


def score_float(value):
    """An exact score as a float for logging (never used for a decision); None stays None."""
    return None if value is None else float(Fraction(value))
