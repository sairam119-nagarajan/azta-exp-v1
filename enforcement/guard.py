"""Authorization boundary: the only places an `AuthorizedRequest` (the only thing the PEP will act on) can be minted.

Three guards, deliberately separate and non-interchangeable; none can be switched into another and none takes an override flag:

  OperationalGuard   decisions derived from real evidence. It authorizes a record ONLY if every one of these is independently approved AND the record names exactly
                     those approvals: a controller-accepted calibration, a CONTROLLER_APPROVED device-profile registry, a CONTROLLER_APPROVED operating configuration, and
                     live-observer evidence with verified provenance; the record itself must be an EVALUATED, decision-eligible, non-counterfactual-by-policy shadow
                     decision. The approvals are objects loaded from digest-pinned artifacts (`ApprovalSet`); a missing one makes the guard refuse EVERY record with the
                     list of what is missing. Today none exists (no calibration is accepted, no registry or configuration is CONTROLLER_APPROVED, and the frozen trust
                     configuration parser accepts only SYNTHETIC_TEST_UNAPPROVED), so this guard cannot authorize anything. An uncalibrated reconstruction loss is not an
                     input to it at all: a record whose behaviour component was not scored under an accepted calibration is refused.
                     ONE narrow, separately-approved exception exists (pre-push audit D-F4, `docs/gate5f/IDENTITY_GATE_ENFORCEMENT_REPAIR_RECORD.md`): the journal's hard
                     identity gate (S_ID = 0 -> T = 0 -> QUARANTINE whatever the behaviour evidence). A hard-gate record never has a behaviour score, so the calibration
                     approval does not apply to it and is not asked for; every OTHER requirement stays (CONTROLLER_APPROVED registry and operating configuration, verified
                     live-observer evidence, a fresh authoritative broker-policy-audit verdict, the enforcement guard itself) and the DEVICE must be attributed to the
                     record's own authenticated evidence and independently confirmed against the PEP's catalogue (see `verify_identity_gate`). The exception can only ever
                     request QUARANTINE of the one attributed device; it cannot relax, restore or touch another principal, and it never accepts a behavioural decision.
  TestOnlyGuard      explicitly identified synthetic engineering decisions (schema `azta.enforcement.test_only_decision`) for an ISOLATED engineering broker only: the
                     PEP must have attested the isolation sentinel, the harness token must match, and the record must carry the TEST_ONLY label. It refuses every real
                     shadow decision. It demonstrates enforcement mechanics; it demonstrates nothing about detection, calibrated trust or attack containment.
  AdministrativeGuard  an operator's explicit RESTORE of one device to its maximum entitlement. It needs an operator reference and is never reachable from a decision stream.

`AuthorizedRequest` can be built only with the module-private mint token (direct construction raises), and carries its origin; the PEP re-checks the origin against the
environment it attested (TEST_ONLY needs an isolated broker). In-process Python cannot make forgery impossible; this is defence in depth, backed by tests that every
direct construction, cross-guard hand-over and missing approval is refused.
"""
from dataclasses import dataclass, field
import hashlib
import json
import re

from enforcement.errors import GuardRefused
from enforcement.model import FULL_ACCESS, RESTRICT, QUARANTINE, SEVERITY, STATES

_MINT = object()
ORIGINS = ("OPERATIONAL", "TEST_ONLY", "ADMINISTRATIVE")
KINDS = ("STATE_CHANGE", "RESTORE")
REAL_DECISION_SCHEMA = "azta.gate5f.shadow_decision"
TEST_ONLY_SCHEMA = "azta.enforcement.test_only_decision"
TEST_ONLY_LABEL = "TEST_ONLY_SYNTHETIC_ENGINEERING"
TEST_ONLY_STATEMENT = ("explicitly synthetic engineering decision: it exercises broker enforcement mechanics only and is NOT detection accuracy, calibrated trust "
                       "scoring, a measured attack or a scientific result")
HARNESS_TOKEN = "AZTA_ENGINEERING_TEST_ONLY_HARNESS_V1"
OPERATIONAL_EVIDENCE_CLASSES = ("LIVE_OBSERVER_VERIFIED",)       # replay, synthetic and unknown classes never enforce
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
# identity hard gate (journal eq. 1). These literals mirror trust.evidence / trust.identity; the enforcement layer may not import the trust package, so a test pins them equal.
IDENTITY_FAILURE_STATUSES = ("INVALID", "UNKNOWN", "EXPIRED", "REVOKED", "UNAUTHORIZED")
# Of the failure statuses only these two are derived from the DEVICE'S OWN broker principal by the audit-based verdict (`trust.identity.identity_from_binding_audit`): UNKNOWN = the bound client does not exist,
# REVOKED = it exists and is disabled. UNAUTHORIZED is "any other failed check" and ALSO results from a broker-wide finding (default ACL not deny, a role referenced but missing, admin able to publish
# telemetry), which marks EVERY enrolled device UNAUTHORIZED; the record does not say which, so UNAUTHORIZED cannot be attributed to the device and is refused here (remaining blocker, see the record).
# INVALID and EXPIRED are never produced from a broker-policy audit at all.
DEVICE_ATTRIBUTABLE_IDENTITY_STATUSES = ("REVOKED", "UNKNOWN")
IDENTITY_AUDIT_PROVENANCE = "BROKER_POLICY_AUDIT"
SYNTHETIC_PROVENANCE = "SYNTHETIC_FIXTURE"
IDENTITY_GATE_PATH = "IDENTITY_HARD_GATE"
UNRESOLVED_ROUTE_CODES = ("UNKNOWN_DEVICE", "WINDOW_PINS_UNREADABLE", "REGISTRY_NOT_SUPPLIED", "NO_WINDOW_TO_ROUTE", "EVIDENCE_CLASS_MISMATCH")   # decision_pipeline.registry codes: the device was NOT resolved


def digest_of(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuthorizedRequest:
    request_id: str
    device: str
    desired_state: str
    kind: str
    origin: str
    deescalation_authorized: bool
    evidence_ref: dict
    authorization: dict
    decision_ns: object
    _mint: object = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        if self._mint is not _MINT:
            raise GuardRefused("REQUEST_NOT_MINTED_BY_A_GUARD", "an AuthorizedRequest can only be created by a guard")
        if (self.origin not in ORIGINS or self.kind not in KINDS or self.desired_state not in STATES or not IDENTIFIER.fullmatch(self.request_id or "")
                or not isinstance(self.device, str) or not isinstance(self.evidence_ref, dict)):
            raise GuardRefused("REQUEST_MALFORMED", "origin, kind, state, id or evidence reference is invalid")
        if self.kind == "RESTORE" and (self.desired_state != FULL_ACCESS or self.origin == "OPERATIONAL"):
            raise GuardRefused("RESTORE_SHAPE", "RESTORE is an administrative return to FULL_ACCESS and never an operational decision")
        if self.origin == "ADMINISTRATIVE" and self.kind != "RESTORE":
            raise GuardRefused("ADMINISTRATIVE_SCOPE", "the administrative origin only restores")

    def content_digest(self):
        return digest_of(dict(device=self.device, desired_state=self.desired_state, kind=self.kind, origin=self.origin,
                              deescalation_authorized=self.deescalation_authorized, evidence_ref=self.evidence_ref))


def _mint(**fields):
    return AuthorizedRequest(_mint=_MINT, **fields)


@dataclass(frozen=True)
class ApprovalSet:
    """Independently loaded approvals. Every field is None until a real, digest-verified artifact exists; nothing is defaulted or inferred from a decision record."""
    calibration_id: object = None            # id of a controller-accepted calibration record (trust.calibration.parse_record status CONTROLLER_ACCEPTED)
    registry_sha256: object = None           # digest of a CONTROLLER_APPROVED device-profile registry
    registry_status: object = None
    config_sha256: object = None             # digest of a CONTROLLER_APPROVED operating configuration
    config_status: object = None
    # Set only by the approval loader (`engineering/approvals.py`) from a digest-pinned controller approval record; every one defaults to "not set" so a hand-built set behaves as before.
    config_record_label: str = "CONTROLLER_APPROVED"   # the status label the ENGINE writes into a decision record made under the approved configuration. The pinned configuration parser
    #                                                    can only write SYNTHETIC_TEST_UNAPPROVED today, so the approval binds the configuration by its DIGEST and names the label it will carry
    approval_id: object = None               # the controller approval record that produced this set (audit reference)
    valid_from_ns: object = None             # decisions made outside [valid_from_ns, valid_until_ns] are not covered (checked against the record's own decision instant)
    valid_until_ns: object = None

    def missing(self):
        out = []
        if not self.calibration_id:
            out.append("ACCEPTED_CALIBRATION")
        if not (self.registry_sha256 and self.registry_status == "CONTROLLER_APPROVED"):
            out.append("CONTROLLER_APPROVED_DEVICE_REGISTRY")
        if not (self.config_sha256 and self.config_status == "CONTROLLER_APPROVED"):
            out.append("CONTROLLER_APPROVED_OPERATING_CONFIGURATION")
        return out

    def check_window(self, record):
        """Refuse a decision made before the approval was issued or after it expired. A set without a window (hand-built) has no time bound."""
        if self.valid_from_ns is None and self.valid_until_ns is None:
            return
        instant = record.get("decision_ns") if isinstance(record, dict) else None
        if type(instant) is not int:
            raise GuardRefused("RECORD_MALFORMED", "the decision instant is needed to check the approval window")
        if self.valid_from_ns is not None and instant < self.valid_from_ns:
            raise GuardRefused("APPROVAL_NOT_YET_VALID", "the decision was made before the approval was issued")
        if self.valid_until_ns is not None and instant > self.valid_until_ns:
            raise GuardRefused("APPROVAL_EXPIRED", "the decision was made after the approval expired")

    def missing_for_identity_gate(self):
        """The approvals that apply to a hard identity-gate decision: the behaviour calibration is NOT one of them (no behaviour score exists for it); the others are."""
        return [name for name in self.missing() if name != "ACCEPTED_CALIBRATION"]


def _is_zero(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value == 0


def is_identity_gate_claim(record):
    """True when a real shadow decision claims the hard identity gate. A claim is only a routing decision for the guard: `verify_identity_gate` must still confirm it."""
    return (isinstance(record, dict) and record.get("schema") == REAL_DECISION_SCHEMA and record.get("record_kind") == "SHADOW_DECISION"
            and isinstance(record.get("fusion"), dict) and record["fusion"].get("hard_gate_applied") is True)


def verify_identity_gate(record, catalogue, *, provenance):
    """Confirm that a hard identity-gate decision is genuine and attributable to ONE enrolled device; returns (device, evidence). Raises GuardRefused otherwise.

    Nothing here trusts a single claim. The device is attributed by three roots that must name the same enrolled device, and one of them is independent of the record:
      1. the registry route: the device the observer bound to the window (exact-topic binding against audited exclusive publish ACLs; never a payload field),
      2. the broker-policy audit that gave the identity verdict (`identity.audit_ref` = binding_audit:<policy digest>:<device>, provenance BROKER_POLICY_AUDIT),
      3. the PEP's own catalogue (built from the observation device registry, not from the record): the verdict's bound username AND client id must equal the catalogue's
         binding of that device.
    A record that names no device, an unenrolled device, another device in its audit reference, a username or client id the catalogue does not bind to that device, or a
    verdict that is not a fresh authoritative failure from `provenance` is refused. Only REVOKED and UNKNOWN verdicts are accepted: they are derived from the device's own principal,
    whereas UNAUTHORIZED can also be the result of a broker-wide finding that would name every enrolled device (DEVICE_ATTRIBUTABLE_IDENTITY_STATUSES). Connection attempts of unknown or unauthenticated clients are denied by the broker itself and are
    not an input of any AZTA evidence stream: no failed login can name a device here. The PEP then re-reads the real broker record of that one catalogue principal before it acts.
    """
    def refuse(code, text):
        raise GuardRefused(code, text)

    if catalogue is None:
        refuse("ATTRIBUTION_CATALOGUE_UNAVAILABLE", "the device cannot be confirmed without the PEP's entitlement catalogue; nothing is attributed by assumption")
    fusion, identity = record.get("fusion") or {}, record.get("identity") or {}
    if (record.get("status") != "EVALUATED" or record.get("proposed_state") != QUARANTINE or not _is_zero(fusion.get("trust")) or not _is_zero(fusion.get("s_id"))
            or fusion.get("hard_gate_applied") is not True):
        refuse("IDENTITY_GATE_RECORD_INCONSISTENT", "an identity-gate record is an evaluated T = 0 QUARANTINE proposal")
    elig = record.get("eligibility") or {}
    if elig.get("decision_eligible") is not True or elig.get("counterfactually_treated_components") or elig.get("refused_components"):
        refuse("NOT_DECISION_ELIGIBLE", "a component was refused or treated as zero by policy")
    if ((record.get("behavior") or {}).get("outcome") != "NOT_EVALUATED" or (record.get("context") or {}).get("outcome") != "NOT_EVALUATED"
            or (record.get("behavior") or {}).get("window_ref") is not None):
        refuse("IDENTITY_GATE_RECORD_INCONSISTENT", "behaviour and context are not consulted by the hard gate")
    if (identity.get("outcome") != "EVALUATED" or identity.get("assessment") != "FRESH_AUTHORITATIVE_NEGATIVE" or identity.get("status") not in IDENTITY_FAILURE_STATUSES
            or identity.get("policy_treatment") != "NONE" or not _is_zero(identity.get("s_id")) or not _is_zero(identity.get("score_used"))):
        refuse("IDENTITY_NOT_A_FRESH_AUTHORITATIVE_FAILURE", "only a fresh authoritative failure verdict, scored as it was found, is a hard-gate decision")
    if identity.get("provenance") != provenance:
        refuse("IDENTITY_PROVENANCE_NOT_ACCEPTED", f"identity provenance {identity.get('provenance')!r} is not {provenance!r}")
    if identity["status"] not in DEVICE_ATTRIBUTABLE_IDENTITY_STATUSES:
        refuse("IDENTITY_FAILURE_NOT_DEVICE_ATTRIBUTABLE", f"the failure verdict {identity['status']} does not prove a fault of this device's own principal (a broker-wide audit finding yields the same "
                                                           "verdict for every enrolled device); no device is quarantined on it")
    note = (record.get("annotations") or {}).get("decision_pipeline") or {}
    route, registry = note.get("route") or {}, note.get("registry") or {}
    device = route.get("device")
    if not isinstance(device, str) or not IDENTIFIER.fullmatch(device) or route.get("code") in UNRESOLVED_ROUTE_CODES:
        refuse("ATTRIBUTION_MISSING", "the registry did not resolve an authenticated device for this decision")
    if not (isinstance(route.get("registry_sha256"), str) and HEX64.fullmatch(route["registry_sha256"]) and route["registry_sha256"] == registry.get("sha256")):
        refuse("ATTRIBUTION_REGISTRY_INCONSISTENT", "the route was not resolved by the registry the record names")
    if record.get("device") not in (None, device):
        refuse("ATTRIBUTION_CONFLICT", "the record carries a second, different device claim")
    entry = catalogue.by_device.get(device)
    if entry is None:
        refuse("ATTRIBUTION_DEVICE_NOT_ENROLLED", "the attributed device is not in the PEP's entitlement catalogue; nothing was sent")
    if not (isinstance(identity.get("bound_username"), str) and isinstance(identity.get("bound_client_id"), str)
            and (identity["bound_username"], identity["bound_client_id"]) == (entry.username, entry.client_id)):
        refuse("ATTRIBUTION_BINDING_MISMATCH", "the verdict's bound username and client id are not the catalogue's binding of the attributed device")
    policy = identity.get("policy_sha256")
    if not (isinstance(policy, str) and HEX64.fullmatch(policy) and identity.get("audit_ref") == f"binding_audit:{policy}:{device}"):
        refuse("ATTRIBUTION_AUDIT_REFERENCE_MISMATCH", "the broker-policy audit reference does not name this device and a policy digest")
    if not isinstance(record.get("evidence_id"), str) or type(record.get("decision_ns")) is not int:
        refuse("RECORD_MALFORMED", "evidence id or decision instant missing")
    return device, dict(path=IDENTITY_GATE_PATH, identity_status=identity["status"], identity_provenance=provenance, audit_ref=identity["audit_ref"], policy_sha256=policy,
                        bound_username=entry.username, bound_client_id=entry.client_id, route_registry_sha256=route["registry_sha256"],
                        attribution="registry-route device = broker-audit device = catalogue binding (username and client id)")


class OperationalGuard:
    def __init__(self, approvals=None, *, deescalation_policy, catalogue=None):
        """deescalation_policy: an explicit bool (no default): whether a persisted decision toward a less restrictive state may be applied automatically.
        catalogue: the PEP's entitlement catalogue, used ONLY to confirm the device of a hard identity-gate decision; without it such a decision is refused."""
        if not isinstance(deescalation_policy, bool):
            raise GuardRefused("POLICY_NOT_EXPLICIT", "the de-escalation policy must be stated")
        self.approvals = approvals or ApprovalSet()
        self.deescalation_policy = deescalation_policy
        self.catalogue = catalogue

    def _authorize_identity_gate(self, record):
        missing = self.approvals.missing_for_identity_gate()
        if missing:
            raise GuardRefused("OPERATIONAL_APPROVALS_MISSING", ",".join(missing))
        self.approvals.check_window(record)
        device, finding = verify_identity_gate(record, self.catalogue, provenance=IDENTITY_AUDIT_PROVENANCE)
        prov, note = record.get("provenance") or {}, (record.get("annotations") or {}).get("decision_pipeline") or {}
        if prov.get("config_status") != self.approvals.config_record_label or prov.get("config_sha256") != self.approvals.config_sha256:
            raise GuardRefused("CONFIGURATION_NOT_THE_APPROVED_ONE", "the decision was not made under the approved operating configuration")
        registry, evidence = note.get("registry") or {}, note.get("evidence") or {}
        if registry.get("status") != "CONTROLLER_APPROVED" or registry.get("sha256") != self.approvals.registry_sha256:
            raise GuardRefused("REGISTRY_NOT_THE_APPROVED_ONE", "the device was not resolved by the approved registry")
        if evidence.get("class") not in OPERATIONAL_EVIDENCE_CLASSES or note.get("synthetic") is not False:
            raise GuardRefused("EVIDENCE_NOT_LIVE_VERIFIED", f"evidence class {evidence.get('class')!r} cannot enforce")
        return _mint(request_id=f"op-{record['evidence_id']}", device=device, desired_state=QUARANTINE, kind="STATE_CHANGE", origin="OPERATIONAL",
                     deescalation_authorized=self.deescalation_policy,
                     evidence_ref=dict(evidence_id=record["evidence_id"], evidence_class=evidence["class"], registry_sha256=registry["sha256"], calibration_id=None,
                                       config_sha256=self.approvals.config_sha256, approval_id=self.approvals.approval_id, identity_gate=finding),
                     authorization=dict(guard="OperationalGuard", approvals="registry,configuration,live-evidence", path=IDENTITY_GATE_PATH,
                                        calibration="NOT_APPLICABLE: the hard identity gate does not consult behaviour"), decision_ns=record["decision_ns"])

    def authorize(self, record):
        if is_identity_gate_claim(record):
            return self._authorize_identity_gate(record)
        missing = self.approvals.missing()
        if missing:
            raise GuardRefused("OPERATIONAL_APPROVALS_MISSING", ",".join(missing))
        self.approvals.check_window(record)
        if not isinstance(record, dict) or record.get("schema") != REAL_DECISION_SCHEMA or record.get("record_kind") != "SHADOW_DECISION":
            raise GuardRefused("RECORD_NOT_AN_OPERATIONAL_DECISION", "only a trust-engine shadow decision record can be considered")
        if record.get("status") != "EVALUATED" or record.get("proposed_state") not in STATES:
            raise GuardRefused("NOT_EVALUABLE", "no evaluated proposal")
        elig = record.get("eligibility") or {}
        if elig.get("decision_eligible") is not True or elig.get("counterfactually_treated_components"):
            raise GuardRefused("NOT_DECISION_ELIGIBLE", "a component was refused or treated as zero by policy")
        behavior, prov = record.get("behavior") or {}, record.get("provenance") or {}
        note = (record.get("annotations") or {}).get("decision_pipeline") or {}
        evidence = note.get("evidence") or {}
        if behavior.get("outcome") != "EVALUATED" or behavior.get("calibration_id") != self.approvals.calibration_id:
            raise GuardRefused("CALIBRATION_NOT_THE_APPROVED_ONE", "behaviour was not scored under the approved calibration")
        if prov.get("config_status") != self.approvals.config_record_label or prov.get("config_sha256") != self.approvals.config_sha256:
            raise GuardRefused("CONFIGURATION_NOT_THE_APPROVED_ONE", "the decision was not made under the approved operating configuration")
        registry = note.get("registry") or {}
        if registry.get("status") != "CONTROLLER_APPROVED" or registry.get("sha256") != self.approvals.registry_sha256 or (note.get("route") or {}).get("code") != "ROUTED":
            raise GuardRefused("REGISTRY_NOT_THE_APPROVED_ONE", "the route was not resolved by the approved registry")
        if evidence.get("class") not in OPERATIONAL_EVIDENCE_CLASSES or note.get("synthetic") is not False:
            raise GuardRefused("EVIDENCE_NOT_LIVE_VERIFIED", f"evidence class {evidence.get('class')!r} cannot enforce")
        if not isinstance(record.get("evidence_id"), str) or not isinstance(record.get("decision_ns"), int):
            raise GuardRefused("RECORD_MALFORMED", "evidence id or decision instant missing")
        device = (behavior.get("window_ref") or {}).get("device")
        if not isinstance(device, str):
            raise GuardRefused("RECORD_MALFORMED", "the record does not name its authenticated device")
        return _mint(request_id=f"op-{record['evidence_id']}", device=device, desired_state=record["proposed_state"], kind="STATE_CHANGE", origin="OPERATIONAL",
                     deescalation_authorized=self.deescalation_policy, evidence_ref=dict(evidence_id=record["evidence_id"], evidence_class=evidence["class"],
                                                                                         registry_sha256=registry["sha256"], calibration_id=self.approvals.calibration_id,
                                                                                         config_sha256=self.approvals.config_sha256, approval_id=self.approvals.approval_id),
                     authorization=dict(guard="OperationalGuard", approvals="calibration,registry,configuration,live-evidence"), decision_ns=record["decision_ns"])


    def authorize_supplementary(self, record, *, operator_ref, review_id):
        """AE_PRIMARY_AUTHORITY_V1: one exact operator approval of a supplementary liveness recommendation (`enforcement.authority`). It is not a behavioural score and needs no accepted calibration; every
        other approval stays. It can only ever ask for RESTRICT, it is labelled with its own path, and it is reachable only through a review the operator approved."""
        missing = self.approvals.missing_for_identity_gate()
        if missing:
            raise GuardRefused("OPERATIONAL_APPROVALS_MISSING", ",".join(missing))
        self.approvals.check_window(record)
        if not isinstance(record, dict) or record.get("schema") != REAL_DECISION_SCHEMA or record.get("record_kind") != "SHADOW_DECISION":
            raise GuardRefused("RECORD_NOT_AN_OPERATIONAL_DECISION", "only a trust-engine record can be considered")
        behavior, prov, identity = record.get("behavior") or {}, record.get("provenance") or {}, record.get("identity") or {}
        note = (record.get("annotations") or {}).get("decision_pipeline") or {}
        supplementary = behavior.get("supplementary") or {}
        if supplementary.get("recommendation") != RESTRICT or identity.get("assessment") != "FRESH_AUTHORITATIVE_POSITIVE":
            raise GuardRefused("NOT_A_SUPPLEMENTARY_RECOMMENDATION", "a RESTRICT liveness recommendation with a fresh valid identity is required")
        if prov.get("config_status") != self.approvals.config_record_label or prov.get("config_sha256") != self.approvals.config_sha256:
            raise GuardRefused("CONFIGURATION_NOT_THE_APPROVED_ONE", "the decision was not made under the approved operating configuration")
        registry, evidence = note.get("registry") or {}, note.get("evidence") or {}
        if registry.get("status") != "CONTROLLER_APPROVED" or registry.get("sha256") != self.approvals.registry_sha256 or (note.get("route") or {}).get("code") != "ROUTED":
            raise GuardRefused("REGISTRY_NOT_THE_APPROVED_ONE", "the route was not resolved by the approved registry")
        if evidence.get("class") not in OPERATIONAL_EVIDENCE_CLASSES or note.get("synthetic") is not False:
            raise GuardRefused("EVIDENCE_NOT_LIVE_VERIFIED", f"evidence class {evidence.get('class')!r} cannot enforce")
        device = (behavior.get("window_ref") or {}).get("device")
        if not isinstance(device, str) or not isinstance(record.get("evidence_id"), str) or not isinstance(operator_ref, str) or not IDENTIFIER.fullmatch(operator_ref):
            raise GuardRefused("RECORD_MALFORMED", "device, evidence id or operator reference missing")
        return _mint(request_id=f"op-sup-{record['evidence_id']}", device=device, desired_state=RESTRICT, kind="STATE_CHANGE", origin="OPERATIONAL", deescalation_authorized=False,
                     evidence_ref=dict(evidence_id=record["evidence_id"], evidence_class=evidence["class"], path="SUPPLEMENTARY_LIVENESS", review_id=review_id, operator_ref=operator_ref, approval_id=self.approvals.approval_id),
                     authorization=dict(guard="OperationalGuard", path="SUPPLEMENTARY_LIVENESS", approvals="registry,configuration,live-evidence,operator-review"), decision_ns=record["decision_ns"])


class TestOnlyGuard:
    __test__ = False        # not a pytest/unittest case

    def __init__(self, *, harness_token, environment_isolated, deescalation_policy):
        if harness_token != HARNESS_TOKEN:
            raise GuardRefused("HARNESS_TOKEN_INVALID", "the TEST_ONLY pathway needs the engineering harness token")
        if environment_isolated is not True:
            raise GuardRefused("ENVIRONMENT_NOT_ISOLATED", "the PEP has not attested the isolated engineering broker; TEST_ONLY decisions are refused")
        if not isinstance(deescalation_policy, bool):
            raise GuardRefused("POLICY_NOT_EXPLICIT", "the de-escalation policy must be stated")
        self.deescalation_policy = deescalation_policy

    def authorize(self, record):
        if not isinstance(record, dict) or record.get("schema") != TEST_ONLY_SCHEMA:
            raise GuardRefused("REAL_DECISION_NOT_ACCEPTED_BY_THE_TEST_GUARD" if isinstance(record, dict) and record.get("schema") == REAL_DECISION_SCHEMA
                               else "RECORD_NOT_A_TEST_ONLY_DECISION", "the TEST_ONLY pathway accepts only explicitly labelled synthetic engineering decisions")
        if (record.get("evidence_class") != TEST_ONLY_LABEL or record.get("statement") != TEST_ONLY_STATEMENT or record.get("proposed_state") not in STATES
                or not isinstance(record.get("device"), str) or not isinstance(record.get("evidence_id"), str) or not isinstance(record.get("decision_ns"), int)):
            raise GuardRefused("TEST_ONLY_RECORD_MALFORMED", "label, statement, state, device, id or instant is invalid")
        return _mint(request_id=f"test-{record['evidence_id']}", device=record["device"], desired_state=record["proposed_state"], kind="STATE_CHANGE", origin="TEST_ONLY",
                     deescalation_authorized=self.deescalation_policy, evidence_ref=dict(evidence_id=record["evidence_id"], evidence_class=TEST_ONLY_LABEL,
                                                                                         scenario_id=record.get("scenario_id")),
                     authorization=dict(guard="TestOnlyGuard", note="synthetic engineering decision on an isolated broker"), decision_ns=record["decision_ns"])

    def authorize_restore(self, device, operator_ref, request_id):
        return _mint(request_id=f"test-restore-{request_id}", device=device, desired_state=FULL_ACCESS, kind="RESTORE", origin="TEST_ONLY", deescalation_authorized=True,
                     evidence_ref=dict(evidence_class=TEST_ONLY_LABEL, operator_ref=operator_ref), authorization=dict(guard="TestOnlyGuard", operation="RESTORE"),
                     decision_ns=None)


class TestOnlyIdentityGateGuard:
    """The isolated-engineering counterpart of the identity-gate exception: it accepts ONLY a real-schema hard identity-gate decision built from SYNTHETIC_FIXTURE evidence, runs the same
    attribution checks as the operational path (`verify_identity_gate`), and mints a TEST_ONLY request that only an attested isolated broker acts on. It refuses behavioural decisions, real
    (non-synthetic) evidence and every other state. It exists so the repaired hand-off can be exercised on the engineering broker without any approval; it demonstrates mechanics only."""
    __test__ = False

    def __init__(self, *, harness_token, environment_isolated, catalogue, deescalation_policy):
        if harness_token != HARNESS_TOKEN:
            raise GuardRefused("HARNESS_TOKEN_INVALID", "the TEST_ONLY pathway needs the engineering harness token")
        if environment_isolated is not True:
            raise GuardRefused("ENVIRONMENT_NOT_ISOLATED", "the PEP has not attested the isolated engineering broker; TEST_ONLY decisions are refused")
        if not isinstance(deescalation_policy, bool):
            raise GuardRefused("POLICY_NOT_EXPLICIT", "the de-escalation policy must be stated")
        self.catalogue, self.deescalation_policy = catalogue, deescalation_policy

    def authorize(self, record):
        if not is_identity_gate_claim(record):
            raise GuardRefused("RECORD_NOT_AN_IDENTITY_GATE_DECISION", "this guard accepts only a hard identity-gate decision from synthetic evidence")
        device, finding = verify_identity_gate(record, self.catalogue, provenance=SYNTHETIC_PROVENANCE)
        note = (record.get("annotations") or {}).get("decision_pipeline") or {}
        if (note.get("evidence") or {}).get("class") != SYNTHETIC_PROVENANCE or note.get("synthetic") is not True or record.get("evidence_mode") != SYNTHETIC_PROVENANCE:
            raise GuardRefused("REAL_EVIDENCE_NOT_ACCEPTED_BY_THE_TEST_GUARD", "the TEST_ONLY identity-gate pathway accepts only synthetic fixture evidence")
        return _mint(request_id=f"test-ig-{record['evidence_id']}", device=device, desired_state=QUARANTINE, kind="STATE_CHANGE", origin="TEST_ONLY",
                     deescalation_authorized=self.deescalation_policy,
                     evidence_ref=dict(evidence_id=record["evidence_id"], evidence_class=SYNTHETIC_PROVENANCE, label=TEST_ONLY_LABEL, identity_gate=finding),
                     authorization=dict(guard="TestOnlyIdentityGateGuard", path=IDENTITY_GATE_PATH, note="synthetic identity-gate decision on an isolated broker"),
                     decision_ns=record["decision_ns"])


class AdministrativeGuard:
    """An operator's explicit RESTORE of one device to its maximum entitlement. Needs an operator reference and the device named twice (confirmation)."""

    def authorize_restore(self, device, operator_ref, *, confirm_device, request_id):
        if device != confirm_device:
            raise GuardRefused("RESTORE_NOT_CONFIRMED", "the confirmation must repeat the device being restored")
        if not isinstance(operator_ref, str) or not IDENTIFIER.fullmatch(operator_ref):
            raise GuardRefused("OPERATOR_REFERENCE_REQUIRED", "an administrative restore needs an operator reference")
        return _mint(request_id=f"admin-restore-{request_id}", device=device, desired_state=FULL_ACCESS, kind="RESTORE", origin="ADMINISTRATIVE", deescalation_authorized=True,
                     evidence_ref=dict(operator_ref=operator_ref), authorization=dict(guard="AdministrativeGuard", operation="RESTORE"), decision_ns=None)
