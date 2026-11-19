"""Gate 5B observation contract: schema IDs, field order, statuses, fingerprints, validators.

Observation only. Nothing here defines a trust value, policy decision or enforcement.
Identity, context, labels, partition and window metadata are never model predictors.
"""
import hashlib
import json
import math
import re

SCHEMA_VERSION = 1
OBSERVER_VERSION = "gate5b-1"
EVENT_SCHEMA = "azta.observation.event"
WINDOW_SCHEMA = "azta.observation.window"
HEALTH_SCHEMA = "azta.observation.health"
BINDING_BASIS = "registry_exact_topic_with_audited_exclusive_publish_acl"
PURPOSES = ("FUNCTIONAL_TEST", "COLLECTION")
STATUSES = ("VALUE", "NO_MESSAGES", "INSUFFICIENT_MESSAGES", "NEVER_OBSERVED_IN_SESSION",
            "OBSERVER_UNAVAILABLE")
DISPOSITIONS = ("COUNTED", "EXCLUDED_UNBOUND", "EXCLUDED_PRE_COVERAGE", "EXCLUDED_POST_COVERAGE",
                "EXCLUDED_RETAINED", "EXCLUDED_DUPLICATE")
BINDING_STATUSES = ("BOUND", "UNBOUND_TOPIC")
COVERAGE_STATES = ("COMPLETE", "PARTIAL", "NONE")
HEALTH_KINDS = ("SESSION_START", "CONNACK", "SUBACK", "COVERAGE_START", "HEARTBEAT", "EVENT_ERROR",
                "DISCONNECT", "COVERAGE_END", "SESSION_END")

# Ordered future model-candidate measures. min_messages is the delivered count needed for VALUE.
MEASURES = (
    dict(name="delivered_count", type="int", unit="messages", min_messages=0,
         definition="non-DUP, non-retained application messages delivered on the bound topic"),
    dict(name="payload_bytes_mean", type="float", unit="bytes", min_messages=1,
         definition="mean payload length of counted messages"),
    dict(name="payload_bytes_sd", type="float", unit="bytes", min_messages=2,
         definition="sample standard deviation (n-1) of counted payload lengths"),
    dict(name="interarrival_mean_ms", type="float", unit="ms", min_messages=2,
         definition="mean gap between consecutive counted receive offsets inside the window"),
    dict(name="interarrival_sd_ms", type="float", unit="ms", min_messages=3,
         definition="sample standard deviation (n-1) of those gaps"),
    dict(name="last_delivery_age_ms", type="float", unit="ms", min_messages=None,
         definition="window end minus the last counted receive offset since coverage start in this session"),
)
PREDICTOR_CANDIDATES = tuple(m["name"] for m in MEASURES)

EVENT_FIELDS = (
    ("schema", "str"), ("schema_version", "int"), ("schema_fingerprint", "sha256"),
    ("observer_session_id", "session_id"), ("record_seq", "int"), ("receive_offset_ns", "int"),
    ("receive_utc", "utc"), ("topic", "str"), ("binding_status", "enum"),
    ("bound_device", "str?"), ("bound_username", "str?"), ("bound_client_id", "str?"),
    ("binding_basis", "str?"), ("binding_audit_ref", "str?"), ("registry_sha256", "sha256"),
    ("qos", "int"), ("dup", "bool"), ("retain", "bool"), ("payload_bytes", "int"),
    ("payload_sha256", "sha256"), ("window_index", "int?"), ("disposition", "enum"),
)
WINDOW_FIELDS = (
    ("schema", "str"), ("schema_version", "int"), ("schema_fingerprint", "sha256"),
    ("observation_config_sha256", "sha256"), ("observer_version", "str"), ("purpose", "enum"),
    ("observer_session_id", "session_id"), ("collection_run_id", "identifier"), ("device", "str"),
    ("identity", "object"), ("window", "object"), ("coverage", "object"), ("measures", "object"),
    ("qc", "object"), ("enforcement", "str"),
)
IDENTITY_FIELDS = ("bound_username", "bound_client_id", "binding_basis", "binding_audit_ref", "registry_sha256")
WINDOW_INDEX_FIELDS = ("index", "start_offset_ns", "end_offset_ns", "duration_ns")
COVERAGE_FIELDS = ("state", "covered_ns")
QC_FIELDS = ("counted_events_raw", "dup_flagged_count", "retained_excluded_count")
HEALTH_FIELDS = ("schema", "schema_version", "schema_fingerprint", "observer_session_id", "record_seq",
                 "offset_ns", "utc", "kind", "details")

# Everything that must never appear in a future autoencoder predictor vector.
FORBIDDEN_PREDICTOR_FIELDS = frozenset(
    [name for name, _ in EVENT_FIELDS] + [name for name, _ in WINDOW_FIELDS] + list(IDENTITY_FIELDS)
    + list(WINDOW_INDEX_FIELDS) + list(COVERAGE_FIELDS) + list(QC_FIELDS)
    + ["scenario", "scenario_designation", "label", "attack", "partition", "intended_partition",
       "workload_profile_id", "authorization", "context", "acl", "role", "trust", "utc", "timestamp"])

SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SESSION_ID = re.compile(r"obs-[0-9a-f]{32}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z\Z")


def canonical(value):
    """Deterministic serialization used for every digest in Gate 5B."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _spec():
    return dict(
        schema_version=SCHEMA_VERSION, event_schema=EVENT_SCHEMA, window_schema=WINDOW_SCHEMA,
        health_schema=HEALTH_SCHEMA, event_fields=EVENT_FIELDS, window_fields=WINDOW_FIELDS,
        identity_fields=IDENTITY_FIELDS, window_index_fields=WINDOW_INDEX_FIELDS,
        coverage_fields=COVERAGE_FIELDS, qc_fields=QC_FIELDS, health_fields=HEALTH_FIELDS,
        measures=MEASURES, statuses=STATUSES, dispositions=DISPOSITIONS,
        binding_statuses=BINDING_STATUSES, coverage_states=COVERAGE_STATES, health_kinds=HEALTH_KINDS,
        binding_basis=BINDING_BASIS, window_grid="monotonic; [start, end); coverage-anchored",
    )


SCHEMA_FINGERPRINT = sha256_text(canonical(_spec()))


def observation_config_sha256(duration_ns, registry_sha256, subscription_qos=1):
    """Compatibility fingerprint: different W or registry must never look compatible."""
    return sha256_text(canonical(dict(
        duration_ns=duration_ns, registry_sha256=registry_sha256, subscription_qos=subscription_qos,
        schema_fingerprint=SCHEMA_FINGERPRINT, observer_version=OBSERVER_VERSION)))


def _check(condition, message):
    if not condition:
        raise ValueError(message)


def _is_int(value, low=None):
    return type(value) is int and (low is None or value >= low)


def _typed(name, kind, value):
    if kind == "str":
        _check(isinstance(value, str) and 0 < len(value) <= 256, f"{name}: string required")
    elif kind == "str?":
        _check(value is None or (isinstance(value, str) and 0 < len(value) <= 256), f"{name}: string/null")
    elif kind == "int":
        _check(_is_int(value, 0), f"{name}: non-negative integer required")
    elif kind == "int?":
        _check(value is None or _is_int(value, 0), f"{name}: non-negative integer/null")
    elif kind == "bool":
        _check(type(value) is bool, f"{name}: boolean required")
    elif kind == "sha256":
        _check(isinstance(value, str) and SHA256.fullmatch(value), f"{name}: sha256 hex required")
    elif kind == "session_id":
        _check(isinstance(value, str) and SESSION_ID.fullmatch(value), f"{name}: session id required")
    elif kind == "identifier":
        _check(isinstance(value, str) and IDENTIFIER.fullmatch(value), f"{name}: identifier required")
    elif kind == "utc":
        _check(isinstance(value, str) and UTC.fullmatch(value), f"{name}: UTC Z timestamp required")
    elif kind == "object":
        _check(isinstance(value, dict), f"{name}: object required")


def _keys(record, expected, label):
    _check(isinstance(record, dict) and set(record) == set(expected), f"{label}: unexpected or missing fields")


def validate_event(record):
    _keys(record, [n for n, _ in EVENT_FIELDS], "event")
    for name, kind in EVENT_FIELDS:
        if kind != "enum":
            _typed(name, kind, record[name])
    _check(record["schema"] == EVENT_SCHEMA and record["schema_version"] == SCHEMA_VERSION, "event schema")
    _check(record["schema_fingerprint"] == SCHEMA_FINGERPRINT, "event fingerprint mismatch")
    _check(record["record_seq"] >= 1 and record["qos"] in (0, 1, 2), "event seq/qos")
    _check(record["binding_status"] in BINDING_STATUSES and record["disposition"] in DISPOSITIONS, "event enum")
    bound = record["binding_status"] == "BOUND"
    bound_values = [record[k] for k in ("bound_device", "bound_username", "bound_client_id", "binding_basis")]
    _check(all(v is not None for v in bound_values) if bound else all(v is None for v in bound_values),
           "binding fields inconsistent with binding status")
    _check(not bound or record["binding_basis"] == BINDING_BASIS, "binding basis")
    disposition = record["disposition"]
    _check((disposition == "EXCLUDED_UNBOUND") == (not bound), "unbound disposition")
    if disposition in ("EXCLUDED_UNBOUND", "EXCLUDED_PRE_COVERAGE", "EXCLUDED_POST_COVERAGE"):
        _check(record["window_index"] is None, "excluded event must not carry a window")
    else:
        _check(record["window_index"] is not None, "in-coverage event needs a window")
    if disposition == "COUNTED":
        _check(not record["dup"] and not record["retain"], "DUP/retained message cannot be counted")
    _check(disposition != "EXCLUDED_DUPLICATE" or (record["dup"] and not record["retain"]), "duplicate rule")
    _check(disposition != "EXCLUDED_RETAINED" or record["retain"], "retained rule")
    return record


def expected_status(name, count, coverage_complete, has_history):
    if not coverage_complete:
        return "OBSERVER_UNAVAILABLE"
    if name == "last_delivery_age_ms":
        return "VALUE" if has_history else "NEVER_OBSERVED_IN_SESSION"
    minimum = next(m["min_messages"] for m in MEASURES if m["name"] == name)
    if count >= minimum:
        return "VALUE"
    return "NO_MESSAGES" if count == 0 else "INSUFFICIENT_MESSAGES"


def validate_window(record):
    _keys(record, [n for n, _ in WINDOW_FIELDS], "window")
    for name, kind in WINDOW_FIELDS:
        if kind != "enum":
            _typed(name, kind, record[name])
    _check(record["schema"] == WINDOW_SCHEMA and record["schema_version"] == SCHEMA_VERSION, "window schema")
    _check(record["schema_fingerprint"] == SCHEMA_FINGERPRINT, "window fingerprint mismatch")
    _check(record["observer_version"] == OBSERVER_VERSION and record["purpose"] in PURPOSES, "window version/purpose")
    _check(record["enforcement"] == "NONE", "observation records never carry enforcement")
    identity, window, coverage, measures, qc = (record[k] for k in ("identity", "window", "coverage", "measures", "qc"))
    _keys(identity, IDENTITY_FIELDS, "identity")
    for key in ("bound_username", "bound_client_id"):
        _typed(key, "str", identity[key])
    _check(identity["binding_basis"] == BINDING_BASIS, "identity binding basis")
    _typed("binding_audit_ref", "str?", identity["binding_audit_ref"])
    _typed("registry_sha256", "sha256", identity["registry_sha256"])
    _keys(window, WINDOW_INDEX_FIELDS, "window index")
    for key in WINDOW_INDEX_FIELDS:
        _typed(key, "int", window[key])
    _check(window["duration_ns"] > 0 and window["end_offset_ns"] - window["start_offset_ns"] == window["duration_ns"],
           "window bounds")
    _keys(coverage, COVERAGE_FIELDS, "coverage")
    _check(coverage["state"] in COVERAGE_STATES and _is_int(coverage["covered_ns"], 0)
           and coverage["covered_ns"] <= window["duration_ns"], "coverage")
    _check((coverage["state"] == "COMPLETE") == (coverage["covered_ns"] == window["duration_ns"])
           and (coverage["state"] == "NONE") == (coverage["covered_ns"] == 0), "coverage state/duration")
    _keys(qc, QC_FIELDS, "qc")
    for key in QC_FIELDS:
        _typed(key, "int", qc[key])
    _keys(measures, PREDICTOR_CANDIDATES, "measures")
    complete = coverage["state"] == "COMPLETE"
    count_entry = measures["delivered_count"]
    count = count_entry.get("value") if isinstance(count_entry, dict) else None
    if complete:
        _check(_is_int(count, 0) and count == qc["counted_events_raw"], "delivered_count")
    age = measures["last_delivery_age_ms"]
    has_history = isinstance(age, dict) and age.get("status") == "VALUE"
    for spec in MEASURES:
        entry = measures[spec["name"]]
        _keys(entry, ("value", "status"), spec["name"])
        status = entry["status"]
        _check(status in STATUSES, f'{spec["name"]}: status')
        expected = expected_status(spec["name"], count if complete else 0, complete, has_history)
        _check(status == expected, f'{spec["name"]}: status {status} violates contract ({expected})')
        if status == "VALUE":
            value = entry["value"]
            if spec["type"] == "int":
                _check(_is_int(value, 0), f'{spec["name"]}: integer value')
            else:
                _check(type(value) is float and math.isfinite(value) and value >= 0, f'{spec["name"]}: finite float')
        else:
            _check(entry["value"] is None, f'{spec["name"]}: unavailable value must be null, never a placeholder')
    return record


def validate_health(record):
    _keys(record, HEALTH_FIELDS, "health")
    _check(record["schema"] == HEALTH_SCHEMA and record["schema_fingerprint"] == SCHEMA_FINGERPRINT, "health schema")
    _typed("observer_session_id", "session_id", record["observer_session_id"])
    _check(_is_int(record["record_seq"], 1) and record["kind"] in HEALTH_KINDS, "health seq/kind")
    _check(record["offset_ns"] is None or _is_int(record["offset_ns"], 0), "health offset")
    _typed("utc", "utc", record["utc"])
    _check(isinstance(record["details"], dict), "health details")
    canonical(record)
    return record


def candidate_vector(window):
    """(values, mask) in PREDICTOR_CANDIDATES order. No imputation: unavailable stays None."""
    validate_window(window)
    entries = [window["measures"][name] for name in PREDICTOR_CANDIDATES]
    return (tuple(e["value"] if e["status"] == "VALUE" else None for e in entries),
            tuple(e["status"] == "VALUE" for e in entries))


assert not FORBIDDEN_PREDICTOR_FIELDS.intersection(PREDICTOR_CANDIDATES)
