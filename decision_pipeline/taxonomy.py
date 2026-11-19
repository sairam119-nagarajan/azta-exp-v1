"""Stable failure classification of decision records (engineering observability; it changes no decision).

Every Shadow decision record is either EVALUATED or NOT_EVALUABLE; a NOT_EVALUABLE record names its reasons per component in free text codes. This module
maps those codes to a small fixed vocabulary so a run can be summarised by WHY evidence was unusable (identity, routing, observation window, model,
calibration, timing, context, stream accounting, reserved evidence) without parsing prose. Unknown codes map to OTHER, never to a healthy class.
"""

TAXONOMY_VERSION = "decision-pipeline-taxonomy-1"
CLASSES = ("EVALUATED", "RESERVED_EVIDENCE", "IDENTITY", "ROUTING", "OBSERVATION_WINDOW", "MODEL", "CALIBRATION", "EVIDENCE_TIMING", "CONTEXT",
           "STREAM_ACCOUNTING", "PRODUCER", "OTHER")
PRECEDENCE = {name: i for i, name in enumerate(CLASSES)}   # the earliest class of a record is its primary one

_BEHAVIOR = {
    "NO_APPROVED_PROFILE_ROUTE": "ROUTING", "UNTRUSTED_ROUTE_PROVENANCE": "ROUTING",
    "SCHEMA_MISMATCH": "OBSERVATION_WINDOW", "NO_MESSAGES": "OBSERVATION_WINDOW", "INSUFFICIENT_MESSAGES": "OBSERVATION_WINDOW",
    "NEVER_OBSERVED_IN_SESSION": "OBSERVATION_WINDOW", "OBSERVER_UNAVAILABLE": "OBSERVATION_WINDOW", "NO_WINDOW": "OBSERVATION_WINDOW",
    "NO_BEHAVIOR_EVIDENCE": "OBSERVATION_WINDOW",
    "STALE_BEHAVIOR_EVIDENCE": "EVIDENCE_TIMING", "EVIDENCE_FROM_FUTURE_BEHAVIOR_EVIDENCE": "EVIDENCE_TIMING",
    "IDENTITY_BEHAVIOR_BINDING_MISMATCH": "IDENTITY",
    "NO_MODEL_FOR_PROFILE": "MODEL", "SCORING_REFUSED": "MODEL", "NON_FINITE_LOSS": "MODEL",
    "NO_CALIBRATION_FOR_PROFILE": "CALIBRATION", "CALIBRATION_NOT_VALID_FOR_WORKLOAD": "CALIBRATION",
    "RESERVED_EVIDENCE_REFUSED": "RESERVED_EVIDENCE",
}
_GATES = {"IDENTITY_HARD_GATE", "IDENTITY_UNRESOLVED"}   # behaviour/context were not consulted because of identity: the identity class explains it


def _code(reason):
    return str(reason).split(":", 1)[0]


def _context_class(reason):
    return "EVIDENCE_TIMING" if "STALE" in reason or "EVIDENCE_FROM_FUTURE" in reason else "CONTEXT"


def classify_record(record):
    """{primary, classes, reasons} for one decision or refusal record. EVALUATED is its own class; everything else is a reason-derived class."""
    if record.get("record_kind") == "BUNDLE_REFUSED":
        code = record.get("refusal_code") or ""
        cls = "PRODUCER" if code.startswith("PRODUCER") else "STREAM_ACCOUNTING" if code.startswith(("WINDOW", "SOURCE", "LINE", "OBSERVER", "STREAM",
                                                                                                    "ADAPTER")) else "OTHER"
        return dict(primary=cls, classes=[cls], reasons=[record.get("refusal_code") or record.get("reason") or "UNSPECIFIED"])
    if record.get("status") == "EVALUATED":
        return dict(primary="EVALUATED", classes=["EVALUATED"], reasons=[])
    classes, reasons = set(), []
    identity = record.get("identity") or {}
    if identity.get("outcome") == "MISSING":
        classes.add("IDENTITY")
        reasons += [f"identity:{r}" for r in identity.get("reasons", [])]
    behavior = record.get("behavior") or {}
    if behavior.get("outcome") == "MISSING":
        for reason in behavior.get("reasons", []):
            classes.add(_BEHAVIOR.get(_code(reason), "OTHER"))
            reasons.append(f"behavior:{reason}")
    context = record.get("context") or {}
    if context.get("outcome") == "MISSING":
        for reason in context.get("reasons", []):
            classes.add(_context_class(str(reason)))
            reasons.append(f"context:{reason}")
    if not classes:
        classes.add("OTHER")
        reasons.append("UNCLASSIFIED_NOT_EVALUABLE")
    ordered = sorted(classes, key=PRECEDENCE.get)
    return dict(primary=ordered[0], classes=ordered, reasons=reasons)


def summarize(classifications):
    """Counts by primary class and by any class, for a list of `classify_record` results."""
    primary, anyc = {}, {}
    for c in classifications:
        primary[c["primary"]] = primary.get(c["primary"], 0) + 1
        for name in c["classes"]:
            anyc[name] = anyc.get(name, 0) + 1
    return dict(taxonomy=TAXONOMY_VERSION, records=len(classifications), by_primary_class=dict(sorted(primary.items())),
                by_any_class=dict(sorted(anyc.items())))
