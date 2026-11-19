"""AE_PRIMARY_AUTHORITY_V1: authority over the PEP, separate from every score and recommendation (stdlib only, it runs in the PEP container).

A confirmed request (N = 2 by the unchanged `DecisionFilter`, minted by the unchanged `OperationalGuard`) reaches the PEP only when the gate says so:

  AUTO_ELIGIBLE device + mode active-authorized + a valid written scope that names this device with automatic = true and this action  -> applied now
  everything else with a valid scope that names the device and the action                                                            -> PENDING_REVIEW: an exact, single-use, expiring review
  no valid scope                                                                                                                     -> REFUSED

`AUTO_ELIGIBLE` is qualification and never authorization. Approving a review approves that one decision: device, action, evidence ids, digests and policy generation are pinned and rechecked at execution
against the broker. There is no "approve everything" and no default. Reviews live in the PEP's own hash-chained audit log, so a restart rebuilds them; operators reach this process only through typed
intents (`azta.core.intent`) in a hash-chained file written by the console, processed here by the single PEP writer. The console holds no broker credential and sends no command.
"""
import hashlib
import json
from pathlib import Path
import re

from enforcement.audit import AuditLog
from enforcement.errors import AuditIntegrityError, ControlUnavailable, EnforcementError, GuardRefused, PepRefused
from enforcement.guard import AdministrativeGuard
from enforcement.model import QUARANTINE, RESTRICT, SEVERITY
from enforcement.pep import APPLIED, FAILED_UNCHANGED, NOOP, PARTIAL, UNKNOWN
from enforcement.runner import EnforcementRunner

CONTRACT = "AE_PRIMARY_AUTHORITY_V1"
MAP_SCHEMA = "azta.core.authority_map"
SCOPE_SCHEMA = "azta.enforcement.authority_scope"
INTENT_SCHEMA = "azta.core.intent"
SHADOW_ONLY, REVIEW_REQUIRED, AUTO_ELIGIBLE = "SHADOW_ONLY", "HUMAN_REVIEW_REQUIRED", "AUTO_ELIGIBLE"
MODES = ("review", "active-authorized")
APPROVER_ROLES = ("OWNER", "MAIN_CONTROLLER")
ACTIONS = ("RESTRICT", "QUARANTINE", "RESTORE")
INTENT_KINDS = ("APPROVE_ONCE", "REJECT", "DEFER", "RESTORE", "STOP_NEW_ACTIONS", "RESUME_ACTIONS")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}\Z")
from enforcement import attribution as attr
ORIGIN_AE, ORIGIN_IDENTITY, ORIGIN_SUPPLEMENTARY, ORIGIN_CONTEXT, ORIGIN_MIXED = attr.ORIGIN_AE, attr.ORIGIN_IDENTITY, attr.ORIGIN_SUPPLEMENTARY, attr.ORIGIN_CONTEXT, attr.ORIGIN_MIXED
ORIGIN_UNATTRIBUTED = "UNATTRIBUTED"
RECOVERY_RULE = "POST_RESTORE_ONE_WINDOW_V1"
RECOVERY_SUPPRESSED_SOURCES = (attr.SOURCE_AE, attr.SOURCE_MIXED, attr.SOURCE_NONE)
EXECUTION_STATUS = {APPLIED: "APPLIED_VERIFIED", NOOP: "APPLIED_VERIFIED", FAILED_UNCHANGED: "FAILED_UNCHANGED", PARTIAL: "PARTIAL_UNVERIFIED", UNKNOWN: "UNKNOWN", "REFUSED": "REFUSED"}


class AuthorityRefused(EnforcementError):
    def __init__(self, code, message=""):
        super().__init__(f"{code}: {message}")
        self.code = code


def _refuse(code, text):
    raise AuthorityRefused(code, text)


def _load(path, sha256, label):
    if not (isinstance(sha256, str) and HEX64.fullmatch(sha256)):
        _refuse("NOT_PINNED", f"{label} must be named with its SHA-256")
    try:
        blob = Path(path).read_bytes()
    except OSError as exc:
        _refuse("UNREADABLE", f"{label}: {exc.__class__.__name__}")
    if hashlib.sha256(blob).hexdigest() != sha256:
        _refuse("DIGEST_MISMATCH", f"{label} is not the pinned file")
    try:
        return json.loads(blob.decode("utf-8"))
    except ValueError:
        _refuse("NOT_JSON", label)


class AuthorityMap:
    def __init__(self, data):
        if not isinstance(data, dict) or data.get("schema") != MAP_SCHEMA or data.get("contract") != CONTRACT or not isinstance(data.get("devices"), dict):
            _refuse("MAP_SCHEMA", "not an AE_PRIMARY_AUTHORITY_V1 authority map")
        for device, entry in data["devices"].items():
            if entry.get("mode") not in (REVIEW_REQUIRED, AUTO_ELIGIBLE):
                _refuse("MAP_MODE", device)
        self.data = data

    @classmethod
    def load(cls, path, sha256):
        return cls(_load(path, sha256, "authority map"))

    def mode(self, device):
        entry = self.data["devices"].get(device)
        return entry["mode"] if entry else REVIEW_REQUIRED

    def entry(self, device):
        return self.data["devices"].get(device) or {}


class AuthorityScope:
    """A written, digest-pinned, expiring scope for ONE session on ONE broker: which device may receive which action, and which may do so automatically. Issued by the owner or Controller, never by this code."""
    _TOP = {"schema", "schema_version", "scope_id", "mode", "approver_role", "approver_ref", "issued_utc_ns", "expires_utc_ns", "environment", "session_run_id", "artifacts", "devices"}

    def __init__(self, data):
        if not isinstance(data, dict) or set(data) != self._TOP or data["schema"] != SCOPE_SCHEMA or data["schema_version"] != 1:
            _refuse("SCOPE_SCHEMA", "unexpected or missing fields")
        if data["approver_role"] not in APPROVER_ROLES or not IDENTIFIER.fullmatch(str(data["approver_ref"])) or not IDENTIFIER.fullmatch(str(data["scope_id"])):
            _refuse("SCOPE_APPROVER", "approver role and references are required")
        if data["mode"] not in MODES or not IDENTIFIER.fullmatch(str(data["session_run_id"])) or not isinstance(data["environment"], str):
            _refuse("SCOPE_SESSION", "mode, session and environment are required")
        issued, expires = data["issued_utc_ns"], data["expires_utc_ns"]
        if type(issued) is not int or type(expires) is not int or not 0 <= issued < expires:
            _refuse("SCOPE_WINDOW", "issued_utc_ns < expires_utc_ns")
        artifacts = data["artifacts"]
        if not isinstance(artifacts, dict) or set(artifacts) != {"registry_sha256", "config_sha256", "route_sha256", "authority_map_sha256"} or not all(isinstance(v, str) and HEX64.fullmatch(v) for v in artifacts.values()):
            _refuse("SCOPE_ARTIFACTS", "registry, configuration, route and authority map digests are required")
        for device, entry in data["devices"].items():
            if not isinstance(entry, dict) or set(entry) != {"actions", "automatic"} or not set(entry["actions"]) <= set(ACTIONS) or type(entry["automatic"]) is not bool:
                _refuse("SCOPE_DEVICE", str(device))
            if entry["automatic"] and data["mode"] != "active-authorized":
                _refuse("SCOPE_AUTOMATIC_IN_REVIEW_MODE", str(device))
        self.data = data

    @classmethod
    def load(cls, path, sha256):
        return cls(_load(path, sha256, "authority scope"))

    @property
    def scope_id(self):
        return self.data["scope_id"]

    def problem(self, *, now_ns, environment, device=None, action=None, record=None):
        """None, or the exact reason this scope does not cover this action now."""
        data = self.data
        if now_ns < data["issued_utc_ns"]:
            return "SCOPE_NOT_YET_VALID"
        if now_ns >= data["expires_utc_ns"]:
            return "SCOPE_EXPIRED"
        if environment != data["environment"]:
            return "SCOPE_OTHER_BROKER"
        if device is not None:
            entry = data["devices"].get(device)
            if entry is None:
                return "SCOPE_DEVICE_NOT_NAMED"
            if action is not None and action not in entry["actions"]:
                return "SCOPE_ACTION_NOT_NAMED"
        if record is not None:
            prov, note = record.get("provenance") or {}, (record.get("annotations") or {}).get("decision_pipeline") or {}
            if prov.get("config_sha256") != data["artifacts"]["config_sha256"]:
                return "SCOPE_OTHER_CONFIGURATION"
            if (note.get("registry") or {}).get("sha256") != data["artifacts"]["registry_sha256"]:
                return "SCOPE_OTHER_REGISTRY"
            window = (record.get("behavior") or {}).get("window_ref") or {}
            if window.get("collection_run_id") not in (None, data["session_run_id"]):
                return "SCOPE_OTHER_SESSION"
        return None

    def automatic(self, device):
        entry = self.data["devices"].get(device)
        return bool(entry and entry["automatic"] and self.data["mode"] == "active-authorized")


def origin_of(record):
    """The ACTUAL cause of a proposed state (`enforcement.attribution`): IDENTITY_HARD_GATE, AE_PRIMARY, CONTEXT_POLICY, MIXED_AE_CONTEXT or SUPPLEMENTARY_TIMING; UNATTRIBUTED when the
    record cannot be attributed (it is then reviewed, never automatic). Before stabilization every non-identity record was called AE_PRIMARY (the core-p03 context RESTRICT defect)."""
    return attr.attribute(record).get("origin") or ORIGIN_UNATTRIBUTED


def decision_fields(record, attribution, previous_state):
    """The reconstruction block written into every RECORD_HANDLED and REVIEW_OPENED entry (requirement 2): which run, device and window; the four trust values; the AE evidence; the actual cause."""
    record = record if isinstance(record, dict) else {}
    fusion, behavior = record.get("fusion") or {}, record.get("behavior") or {}
    window, primary = behavior.get("window_ref") or {}, behavior.get("ae_primary") or {}
    return dict(run_id=window.get("collection_run_id"), window_index=window.get("window_index"), decision_ns=record.get("decision_ns"), engine_status=record.get("status"),
                s_id=fusion.get("s_id"), s_b=fusion.get("s_b"), s_c=fusion.get("s_c"), trust=fusion.get("trust"), behavior_source=primary.get("behavior_source"), ae_status=primary.get("ae_status"),
                ae_loss=primary.get("ae_loss"), a_ae=primary.get("a_ae"), decision_source=attribution.get("decision_source"), origin=attribution.get("origin") or ORIGIN_UNATTRIBUTED,
                causes=attribution.get("causes"), mixed_kind=attribution.get("mixed_kind"), counterfactual=attribution.get("counterfactual"), previous_state=previous_state,
                proposed_state=attribution.get("proposed_state", record.get("proposed_state")))


def decide_authority(*, mode, authority_map, scope, device, action, origin, now_ns, environment, record=None, stopped=False):
    """(verdict, reason, authority_mode): verdict APPLY, PENDING_REVIEW or REFUSED. A pure function: it reads no score and changes none.
    Only an AE_PRIMARY cause may use the device's AUTO_ELIGIBLE qualification; context, mixed, liveness and unattributed causes are always reviewed."""
    qualified = authority_map.mode(device) if origin == ORIGIN_AE else REVIEW_REQUIRED
    if stopped:
        return "REFUSED", "ACTIONS_STOPPED_BY_OPERATOR", qualified
    if scope is None:
        return "REFUSED", "NO_AUTHORITY_SCOPE", qualified
    problem = scope.problem(now_ns=now_ns, environment=environment, device=device, action=action, record=record)
    if problem:
        return "REFUSED", problem, qualified
    if mode == "active-authorized" and qualified == AUTO_ELIGIBLE and scope.automatic(device):
        return "APPLY", "AUTO_ELIGIBLE_WITH_VALID_SCOPE", qualified
    return "PENDING_REVIEW", "AUTO_ELIGIBLE_WITHOUT_AUTOMATIC_SCOPE" if qualified == AUTO_ELIGIBLE else "HUMAN_REVIEW_REQUIRED", qualified


def review_digests(record):
    prov, note = record.get("provenance") or {}, (record.get("annotations") or {}).get("decision_pipeline") or {}
    primary = (record.get("behavior") or {}).get("ae_primary") or {}
    route = note.get("route") or {}
    return dict(config_sha256=prov.get("config_sha256"), registry_sha256=(note.get("registry") or {}).get("sha256"), model_id=route.get("model_id"), model_sha256=route.get("model_weights_sha256") or route.get("weights_sha256"),
                calibration_id=(record.get("behavior") or {}).get("calibration_id"), ae_loss=primary.get("ae_loss"), a_ae=primary.get("a_ae"), s_b_ae=primary.get("s_b_ae"), trust=(record.get("fusion") or {}).get("trust"))


def make_intent(kind, *, operator_ref, idempotency_key, device=None, review_id=None, action=None, evidence_ids=None, generation=None, confirm_device=None, note=None):
    if kind not in INTENT_KINDS:
        _refuse("INTENT_KIND", str(kind))
    if not (isinstance(operator_ref, str) and IDENTIFIER.fullmatch(operator_ref)) or not (isinstance(idempotency_key, str) and IDENTIFIER.fullmatch(idempotency_key)):
        _refuse("INTENT_IDENTIFIERS", "operator reference and idempotency key are required")
    return dict(intent_schema=INTENT_SCHEMA, intent_kind=kind, operator_ref=operator_ref, idempotency_key=idempotency_key, device=device, review_id=review_id, action=action, evidence_ids=evidence_ids, generation=generation,
                confirm_device=confirm_device, note=note)


class AuthorityRunner(EnforcementRunner):
    """The enforcement runner with the authority gate in front of `pep.apply`, the review lifecycle and the typed intents. It is still the ONE decision loop and the one writer of the PEP audit log."""

    def __init__(self, *, mode, authority_map, scope, review_ttl_ns, intents_path, **arguments):
        super().__init__(**arguments)
        if mode not in MODES:
            raise ValueError("the authority runner needs mode review or active-authorized")
        if type(review_ttl_ns) is not int or review_ttl_ns <= 0:
            raise ValueError("review_ttl_ns must be an explicit positive integer")
        self.mode, self.authority_map, self.scope, self.review_ttl_ns, self.intents_path = mode, authority_map, scope, review_ttl_ns, Path(intents_path)
        self.reviews, self.handled_intents, self.idempotency, self.stopped = {}, set(), {}, False
        self.published_generation = {}
        self.recovery = {}            # device -> the RECOVERY_WINDOW_OPENED body still waiting for its one post-RESTORE observation window (rebuilt from the log on restart)
        self._in_flight = None        # (evidence id, decision fields) of the record being handled, so every RECORD_HANDLED entry carries its reconstruction block
        for entry in self.table.log.entries:
            body = entry["body"]
            if entry["kind"] == "RECOVERY_WINDOW_OPENED":
                self.recovery[body["device"]] = body
            elif entry["kind"] == "RECOVERY_WINDOW_CLOSED":
                self.recovery.pop(body["device"], None)
            elif entry["kind"] == "GENERATION":
                self.published_generation[body["device"]] = body["generation"]
            elif entry["kind"] == "REVIEW_OPENED":
                self.reviews[body["review_id"]] = dict(body, state="PENDING")
            elif entry["kind"] == "REVIEW_RESOLVED":
                self.reviews[body["review_id"]].update(state=body["state"], resolution=body)
            elif entry["kind"] == "INTENT_HANDLED":
                self.handled_intents.add(body["intent_seq"])
                self.idempotency[body["idempotency_key"]] = body["result"]
            elif entry["kind"] == "ACTIONS_STOPPED":
                self.stopped = bool(body["stopped"])

    # ------------------------------------------------------------------------------------------------------------- generation
    def generation(self, device):
        """The current policy generation of a device: the last verified change in this log and in the read-only feed of the other PEP logs. Any later change makes a review stale."""
        last = None
        for entry in self.table.log.entries:
            if entry["kind"] == "OUTCOME" and entry["body"]["device"] == device and entry["body"]["status"] == APPLIED:
                last = entry["seq"]
        feed = None
        if self.policy_changes is not None:
            try:
                self.policy_changes.poll()
                feed = self.policy_changes.last_change_ns(device)
            except (OSError, ValueError):
                return "UNKNOWN"
        return f"{last}:{feed}"

    def _open_review(self, *, device, action, origin, record, evidence_id, reason, qualified):
        review_id = "rv-" + hashlib.sha256(f"{evidence_id}|{action}|{origin}".encode("utf-8")).hexdigest()[:24]
        if review_id in self.reviews:
            return self.reviews[review_id]
        now = self.clock.utc_ns()
        entry = self.authority_map.entry(device)
        try:                    # the review pins the broker's state NOW, not the last belief: a genuine revocation has already changed it, and the approval compares against this
            self.pep.refresh(device)
        except (ControlUnavailable, PepRefused):
            self._count("refresh_unavailable")
        body = dict(review_id=review_id, device=device, action=action, origin=origin, decision=decision_fields(record, attr.attribute(record), self._current_label(device)),
                    evidence_ids=[evidence_id], reason=reason, authority_mode=qualified, generation=self.generation(device),
                    current_state=self._current_label(device), opened_utc_ns=now, expires_utc_ns=now + self.review_ttl_ns, digests=review_digests(record), risk=dict(screen_failed=entry.get("screen_failed"), forced_review=entry.get("forced_review"),
                    restrict_is_permission_noop=entry.get("restrict_is_permission_noop")), decision_record=record, scope_id=self.scope.scope_id if self.scope else None)
        self.table.record("REVIEW_OPENED", **body)
        self.reviews[review_id] = dict(body, state="PENDING")
        return self.reviews[review_id]

    def _resolve(self, review, state, **fields):
        body = dict(review_id=review["review_id"], device=review["device"], action=review["action"], state=state, **fields)
        self.table.record("REVIEW_RESOLVED", **body)
        review.update(state=state, resolution=body)

    def _pending_for(self, device):
        return [r for r in self.reviews.values() if r["state"] == "PENDING" and r["device"] == device]

    def _expire_reviews(self):
        now = self.clock.utc_ns()
        for review in list(self.reviews.values()):
            if review["state"] == "PENDING" and now >= review["expires_utc_ns"]:
                self._resolve(review, "EXPIRED", execution_status="HELD", reason="REVIEW_EXPIRED")

    # ------------------------------------------------------------------------------------------------------------- the gate
    def _confirmation_origins(self, device):
        """The causes of the records that built the current confirmation run of `device`: the CONFIRMING entries since its last non-confirming entry (from the PEP's own log)."""
        out = []
        for entry in reversed(self.table.log.entries):
            if entry["body"].get("device") != device:
                continue
            if entry["kind"] in ("OUTCOME", "RECOVERY_WINDOW_CLOSED"):          # a verified change or a recovery window also reset the PEP's count
                break
            if entry["kind"] != "RECORD_HANDLED":
                continue
            if entry["body"].get("disposition") != "CONFIRMING":
                break
            out.append(((entry["body"].get("decision") or {}).get("origin")) or ORIGIN_UNATTRIBUTED)
        return out

    def _deliver(self, request, evidence_id, device, timing, decision_ns, record):
        origin = origin_of(record)
        if origin == ORIGIN_AE and any(o != ORIGIN_AE for o in self._confirmation_origins(device)):
            origin = ORIGIN_MIXED          # an automatic AE action needs every window of its confirmation run to be AE-caused; a run that a context window helped build is reviewed
        now = self.clock.utc_ns()
        verdict, reason, qualified = decide_authority(mode=self.mode, authority_map=self.authority_map, scope=self.scope, device=device, action=request.desired_state, origin=origin, now_ns=now,
                                                      environment=self.pep.environment, record=record, stopped=self.stopped)
        if verdict == "REFUSED":
            self._finish("REFUSED", evidence_id, device, timing, reason=reason, authority_mode=qualified, desired_state=request.desired_state)
            return
        if verdict == "PENDING_REVIEW":
            self._expire_reviews()
            pending = self._pending_for(device)
            same = [r for r in pending if r["action"] == request.desired_state]
            if same:         # the open review already covers this: the operator's decision is not raced away by a continuing anomaly
                self._finish("HELD", evidence_id, device, timing, reason="REVIEW_ALREADY_PENDING", review_id=same[0]["review_id"])
                return
            for older in pending:
                if SEVERITY[request.desired_state] > SEVERITY[older["action"]]:
                    self._resolve(older, "SUPERSEDED", execution_status="HELD", reason="A_MORE_RESTRICTIVE_RECOMMENDATION_ARRIVED")
                else:
                    self._finish("HELD", evidence_id, device, timing, reason="A_MORE_RESTRICTIVE_REVIEW_IS_PENDING", review_id=older["review_id"])
                    return
            review = self._open_review(device=device, action=request.desired_state, origin=origin, record=record, evidence_id=evidence_id, reason=reason, qualified=qualified)
            self._finish("PENDING_REVIEW", evidence_id, device, timing, review_id=review["review_id"], authority_mode=qualified, desired_state=request.desired_state, reason=reason)
            return
        super()._deliver(request, evidence_id, device, timing, decision_ns, record)

    def _handle(self, raw):
        """A decision with a supplementary liveness recommendation opens its own review (never automatic); the record then takes the unchanged path, where the guard refuses it as NOT_EVALUABLE."""
        try:
            record = json.loads(raw.decode("utf-8"), parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
            supplementary = (record.get("behavior") or {}).get("supplementary") if isinstance(record, dict) else None
        except (ValueError, UnicodeDecodeError):
            record, supplementary = None, None
        evidence_id = record.get("evidence_id") if isinstance(record, dict) else None
        device = ((record.get("behavior") or {}).get("window_ref") or {}).get("device") if isinstance(record, dict) else None
        attribution = attr.attribute(record)
        self._in_flight = (evidence_id, decision_fields(record, attribution, self._current_label(device) if isinstance(device, str) else None)) if isinstance(evidence_id, str) else None
        try:
            if self._recovery_window(record, evidence_id, device, attribution):
                return
            self._handle_inner(raw, record, supplementary)
        finally:
            self._in_flight = None

    def _recovery_window(self, record, evidence_id, device, attribution):
        """Stabilization requirement 4, rule POST_RESTORE_ONE_WINDOW_V1 (supervisor option A): after a verified operator RESTORE, the device's FIRST score-ready autoencoder window is a
        recovery window. It is recorded in full (scores, A_AE, attribution) but it is held: it neither requests nor counts toward the N = 2 confirmation (the run is reset), so a
        reconnection transient alone cannot re-contain the device. A genuinely persistent anomaly is confirmed by the next two windows as usual. An identity hard-gate decision and a
        context-only decision are NOT suppressed (they are not reconnection transients); liveness has its own generation rule. Returns True when this record was the recovery window."""
        if not isinstance(device, str) or device not in self.recovery or not isinstance(evidence_id, str) or evidence_id in self.table.decided:
            return False
        primary = ((record.get("behavior") or {}).get("ae_primary")) or {}
        if record.get("status") != "EVALUATED" or primary.get("ae_status") != "SCORE_READY" or attribution.get("decision_source") not in RECOVERY_SUPPRESSED_SOURCES:
            return False
        opened = self.recovery.pop(device)
        self.filter.observe_missing(device)
        self.table.record("RECOVERY_WINDOW_CLOSED", device=device, rule=RECOVERY_RULE, evidence_id=evidence_id, restore_request_id=opened.get("restore_request_id"),
                          proposed_state=record.get("proposed_state"), a_ae=primary.get("a_ae"), suppressed_action=record.get("proposed_state") not in (None, "FULL_ACCESS"))
        self._finish("HELD", evidence_id, device, dict(record_seen_utc_ns=self.clock.utc_ns(), decision_ns=record.get("decision_ns")), reason="POST_RESTORE_RECOVERY_WINDOW",
                     recovery_rule=RECOVERY_RULE, recovery_window=True)
        return True

    def _finish(self, disposition, evidence_id, device, timing, **fields):
        if self._in_flight is not None and evidence_id == self._in_flight[0] and "decision" not in fields:
            fields["decision"] = self._in_flight[1]
        super()._finish(disposition, evidence_id, device, timing, **fields)

    def _handle_inner(self, raw, record, supplementary):
        if isinstance(supplementary, dict) and supplementary.get("recommendation") == RESTRICT and record.get("status") != "EVALUATED" and record.get("evidence_id") not in self.table.decided:
            device = ((record.get("behavior") or {}).get("window_ref") or {}).get("device")
            if isinstance(device, str) and not self._pending_for(device) and self.scope is not None and not self.stopped:
                if self.scope.problem(now_ns=self.clock.utc_ns(), environment=self.pep.environment, device=device, action=RESTRICT, record=record) is None and self._current_label(device) not in (RESTRICT, QUARANTINE):
                    self._open_review(device=device, action=RESTRICT, origin=ORIGIN_SUPPLEMENTARY, record=record, evidence_id=record["evidence_id"], reason="SUPPLEMENTARY_LIVENESS", qualified=REVIEW_REQUIRED)
        super()._handle(raw)

    # ------------------------------------------------------------------------------------------------------------- intents
    def process_available(self):
        handled = super().process_available()
        self._expire_reviews()
        self.process_intents()
        self._publish_generations()
        return handled

    def _publish_generations(self):
        """The current generation of each device, in the audit log, so an operator's RESTORE can name the state it saw (the console holds no broker or feed access of its own)."""
        for device in self.pep.catalogue.devices:
            generation = self.generation(device)
            if self.published_generation.get(device) != generation:
                self.table.record("GENERATION", device=device, generation=generation)
                self.published_generation[device] = generation

    def process_intents(self):
        if not self.intents_path.exists():
            return 0
        try:
            log = AuditLog.open_existing(self.intents_path, self.clock)
        except AuditIntegrityError as exc:
            self.table.record("INTENT_LOG_REFUSED", reason=exc.code if hasattr(exc, "code") else str(exc)[:120])
            raise
        done = 0
        for entry in log.entries:
            if entry["seq"] in self.handled_intents:
                continue
            body = entry["body"]
            key = body.get("idempotency_key")
            if key in self.idempotency:
                result = dict(status="DUPLICATE_IGNORED", first_result=self.idempotency[key])
            else:
                try:
                    result = self._intent(body)
                except (GuardRefused, AuthorityRefused, PepRefused) as exc:
                    result = dict(status="REFUSED", reason=getattr(exc, "code", type(exc).__name__))
                except ControlUnavailable as exc:
                    result = dict(status="UNKNOWN", reason=getattr(exc, "code", "CONTROL_UNAVAILABLE"))
            self.table.record("INTENT_HANDLED", intent_seq=entry["seq"], idempotency_key=key, intent_kind=body.get("intent_kind"), device=body.get("device"), operator_ref=body.get("operator_ref"), result=result)
            self.handled_intents.add(entry["seq"])
            if key is not None and key not in self.idempotency:
                self.idempotency[key] = result
            done += 1
        return done

    def _intent(self, body):
        if body.get("intent_schema") != INTENT_SCHEMA or body.get("intent_kind") not in INTENT_KINDS:
            _refuse("INTENT_MALFORMED", "schema or kind")
        kind = body["intent_kind"]
        if kind == "STOP_NEW_ACTIONS" or kind == "RESUME_ACTIONS":
            self.stopped = kind == "STOP_NEW_ACTIONS"
            self.table.record("ACTIONS_STOPPED", stopped=self.stopped, operator_ref=body["operator_ref"])
            return dict(status="ACCEPTED", stopped=self.stopped)
        if kind == "RESTORE":
            return self._restore(body)
        review = self.reviews.get(body.get("review_id"))
        if review is None:
            _refuse("REVIEW_UNKNOWN", str(body.get("review_id")))
        if review["state"] != "PENDING":
            _refuse("REVIEW_NOT_PENDING", review["state"])
        if body.get("device") != review["device"] or body.get("action") != review["action"] or body.get("evidence_ids") != review["evidence_ids"] or body.get("generation") != review["generation"]:
            _refuse("REVIEW_PINS_DIFFER", "device, action, evidence ids and generation must equal the review's")
        if kind == "DEFER":
            self.table.record("REVIEW_DEFERRED", review_id=review["review_id"], operator_ref=body["operator_ref"], note=body.get("note"))
            return dict(status="DEFERRED", expires_utc_ns=review["expires_utc_ns"])
        if kind == "REJECT":
            self._resolve(review, "REJECTED", execution_status="HELD", operator_ref=body["operator_ref"], note=body.get("note"))
            return dict(status="REJECTED")
        return self._approve(review, body)

    def _approve(self, review, body):
        now = self.clock.utc_ns()
        device, action, record = review["device"], review["action"], review["decision_record"]

        def stale(reason):
            self._resolve(review, "STALE", execution_status="REFUSED", reason=reason, operator_ref=body["operator_ref"])
            return dict(status="REFUSED", reason=reason)

        if self.stopped:
            return dict(status="REFUSED", reason="ACTIONS_STOPPED_BY_OPERATOR")
        if now >= review["expires_utc_ns"]:
            return stale("REVIEW_EXPIRED")
        if self.scope is None:
            return stale("NO_AUTHORITY_SCOPE")
        problem = self.scope.problem(now_ns=now, environment=self.pep.environment, device=device, action=action, record=record)
        if problem:
            return stale(problem)
        if self.generation(device) != review["generation"]:
            return stale("POLICY_GENERATION_CHANGED")
        self.pep.refresh(device)                                # read-back before acting; an unreadable broker raises and the review stays pending with the outcome UNKNOWN
        if self._current_label(device) != review["current_state"]:
            return stale("BROKER_STATE_CHANGED")
        if review["origin"] == ORIGIN_SUPPLEMENTARY:
            request = self.guards[record["schema"]].authorize_supplementary(record, operator_ref=body["operator_ref"], review_id=review["review_id"])
        else:
            request = self.guards[record["schema"]].authorize(record)
        if request.desired_state != action or request.device != device:
            return stale("GUARD_DISAGREES_WITH_THE_REVIEW")
        started = self.clock.utc_ns()
        outcome = self.pep.apply(request)
        status = EXECUTION_STATUS.get(outcome["status"], "UNKNOWN")
        self._resolve(review, "EXECUTED", execution_status=status, pep_status=outcome["status"], operator_ref=body["operator_ref"], request_id=request.request_id, approved_utc_ns=started,
                      operator_delay_ns=started - review["opened_utc_ns"], permission_equivalent=outcome.get("permission_equivalent"))
        self.filter.pending.pop(device, None)
        return dict(status=status, pep_status=outcome["status"], request_id=request.request_id)

    def _restore(self, body):
        device = body.get("device")
        if self.scope is None:
            _refuse("NO_AUTHORITY_SCOPE", "RESTORE needs a session scope that names it")
        problem = self.scope.problem(now_ns=self.clock.utc_ns(), environment=self.pep.environment, device=device, action="RESTORE")
        if problem:
            _refuse(problem, "RESTORE is outside the scope")
        if body.get("generation") != self.generation(device):
            _refuse("POLICY_GENERATION_CHANGED", "the operator's view is stale; read the state again")
        request = AdministrativeGuard().authorize_restore(device, body["operator_ref"], confirm_device=body.get("confirm_device"), request_id=body["idempotency_key"])
        self.pep.refresh(device)
        outcome = self.pep.apply(request)
        status = EXECUTION_STATUS.get(outcome["status"], "UNKNOWN")
        self.filter.pending.pop(device, None)
        for review in self._pending_for(device):
            self._resolve(review, "SUPERSEDED", execution_status="HELD", reason="RESTORE_CHANGED_THE_GENERATION")
        if status == "APPLIED_VERIFIED" and outcome["status"] == APPLIED:      # a verified change back to FULL_ACCESS: the next score-ready AE window is the recovery window
            body = dict(device=device, rule=RECOVERY_RULE, restore_request_id=request.request_id, opened_utc_ns=self.clock.utc_ns())
            self.table.record("RECOVERY_WINDOW_OPENED", **body)
            self.recovery[device] = body
        return dict(status=status, pep_status=outcome["status"], generation=self.generation(device), request_id=request.request_id)
