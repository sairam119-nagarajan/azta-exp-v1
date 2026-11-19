"""Identity trust S_ID (journal section 4.1, eq. 1, Algorithm 1 lines 3-5): a hard admission condition.

A valid and currently authorized MQTT identity gives S_ID = 100. An unknown, invalid, expired, revoked or otherwise unauthorized
identity gives S_ID = 0, which forces T = 0 regardless of every other component. "Currently" matters in BOTH directions, so the status
must come from authoritative evidence (a broker policy audit or trusted instrumentation, or a labelled synthetic fixture) that is
FRESH at the decision instant, whether it is positive or negative. Gate 5F.2 distinguishes:

  FRESH_AUTHORITATIVE_POSITIVE  valid and authorized, fresh          -> EVALUATED, S_ID = 100
  FRESH_AUTHORITATIVE_NEGATIVE  invalid/unknown/expired/revoked/unauthorized, fresh -> EVALUATED, S_ID = 0 (hard gate)
  UNKNOWN_OR_UNAVAILABLE        the evidence source could not say     -> MISSING
  STALE_POSITIVE                a valid verdict older than the bound  -> MISSING (never a current "valid")
  STALE_NEGATIVE                a failure verdict older than the bound -> MISSING (never a current "invalid": the identity may have
                                been restored since; AZTA cannot know without re-validation)
  FUTURE / UNTRUSTED / ABSENT   evidence from after the decision instant, from an untrusted source, or not supplied -> MISSING

A MISSING identity is handled by the configured missing-evidence policy: REFUSE gives no AZTA proposal (the broker's own existing
authorization stays independently authoritative and is never touched); ZERO is an explicit offline counterfactual. The freshness bound
(`max_evidence_age_ns.identity`) is a required configuration value; none is invented here. A publisher's or payload's own assertion of
who it is carries no weight and yields no score.
"""
from fractions import Fraction

from trust.evidence import EVALUATED, IDENTITY_FAILURE_STATUSES, MISSING, TRUSTED_EVIDENCE_PROVENANCE, ComponentResult, age_problem, \
    provenance_trusted

AUDIT_SCHEMA = "azta.observation.binding_audit"
ASSESSMENTS = ("FRESH_AUTHORITATIVE_POSITIVE", "FRESH_AUTHORITATIVE_NEGATIVE", "UNKNOWN_OR_UNAVAILABLE", "STALE_POSITIVE",
               "STALE_NEGATIVE", "FUTURE", "UNTRUSTED", "ABSENT")


def _missing(assessment, reasons, detail=None):
    return ComponentResult(MISSING, None, tuple(reasons), dict(outcome=MISSING, reasons=list(reasons), assessment=assessment,
                                                               **(detail or {})))


def evaluate_identity(identity, *, evidence_mode, decision_ns, max_age_ns):
    if identity is None:
        return _missing("ABSENT", ["NO_IDENTITY_EVIDENCE"])
    base = dict(status=identity["status"], provenance=identity["provenance"], bound_username=identity["bound_username"],
                bound_client_id=identity["bound_client_id"], policy_sha256=identity["policy_sha256"],
                audit_ref=identity["audit_ref"], observed_ns=identity["observed_ns"])
    if not provenance_trusted(identity["provenance"], evidence_mode, TRUSTED_EVIDENCE_PROVENANCE):
        return _missing("UNTRUSTED", [f"UNTRUSTED_IDENTITY_PROVENANCE:{identity['provenance']}"], base)
    status = identity["status"]
    if status == "UNAVAILABLE":
        return _missing("UNKNOWN_OR_UNAVAILABLE", ["IDENTITY_STATUS_UNAVAILABLE"], base)
    problem = age_problem(identity["observed_ns"], decision_ns, max_age_ns)  # the same bound for positive and negative evidence
    if problem == "EVIDENCE_FROM_FUTURE":
        return _missing("FUTURE", ["EVIDENCE_FROM_FUTURE_IDENTITY_EVIDENCE"], base)
    if problem == "STALE":
        negative = status in IDENTITY_FAILURE_STATUSES
        return _missing("STALE_NEGATIVE" if negative else "STALE_POSITIVE",
                        ["STALE_NEGATIVE_IDENTITY_EVIDENCE" if negative else "STALE_POSITIVE_IDENTITY_EVIDENCE"], base)
    if status in IDENTITY_FAILURE_STATUSES:
        return ComponentResult(EVALUATED, Fraction(0), (f"IDENTITY_{status}",),
                               dict(outcome=EVALUATED, reasons=[f"IDENTITY_{status}"], assessment="FRESH_AUTHORITATIVE_NEGATIVE",
                                    s_id=0.0, **base))
    return ComponentResult(EVALUATED, Fraction(100), ("IDENTITY_VALID_AUTHORIZED",),
                           dict(outcome=EVALUATED, reasons=["IDENTITY_VALID_AUTHORIZED"], assessment="FRESH_AUTHORITATIVE_POSITIVE",
                                s_id=100.0, **base))


def identity_from_binding_audit(audit, device, *, bound_client_id, observed_ns, provenance, registry_sha256):
    """Identity evidence for the bundle from one Gate 5B read-only binding audit record (the binding audit's `analyze` output).

    `bound_client_id` is the registry's client id for the device; the audit's own `client_id_bound` check proves the broker's client
    carries it. VALID_AUTHORIZED only when the audit as a whole raised no reason, this device's verdict is PASS (bound client present
    with that client id, expected publish role, sole publisher of its exact topic) and the bound client is enabled. A client that does
    not exist is UNKNOWN; one that exists but is disabled is REVOKED; any other failed check is UNAUTHORIZED. An audit that is not the
    read-only audit schema, that performed a mutation, or that was made against a different registry is UNAVAILABLE evidence.
    `observed_ns` is the instant at which the audit snapshot was taken: freshness is judged from it, never from the file's age.
    """
    base = dict(provenance=provenance, bound_username=None, bound_client_id=None, policy_sha256=None, audit_ref=None,
                observed_ns=observed_ns)
    if not isinstance(audit, dict) or audit.get("schema") != AUDIT_SCHEMA or audit.get("schema_version") != 1 \
            or audit.get("mutation_performed") is not False or audit.get("registry_sha256") != registry_sha256:
        return dict(base, status="UNAVAILABLE")
    base["policy_sha256"] = audit.get("policy_sha256")
    entry = audit.get("devices", {}).get(device)
    if not isinstance(entry, dict):
        return dict(base, status="UNKNOWN")
    principal = entry.get("expected_principal", "")
    username = principal.split(":", 1)[1] if principal.startswith("client:") else None
    checks = entry.get("checks", {})
    base.update(bound_username=username, bound_client_id=bound_client_id,
                audit_ref=f"binding_audit:{audit.get('policy_sha256')}:{device}")
    if not checks.get("bound_client_present"):
        return dict(base, status="UNKNOWN")
    if not entry.get("bound_client_enabled"):
        return dict(base, status="REVOKED")
    if audit.get("verdict") == "PASS" and not audit.get("reasons") and entry.get("verdict") == "PASS":
        return dict(base, status="VALID_AUTHORIZED")
    return dict(base, status="UNAUTHORIZED")
