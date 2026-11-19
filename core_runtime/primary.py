"""AE_PRIMARY_AUTHORITY_V1 behaviour: the autoencoder is the source of S_B on every score-ready observation; timing, block and drift evidence are computed and recorded but never counted.

The evaluator is a `hybrid.engine.HybridBehaviorEvaluator` whose monitor profiles are rebuilt with every non-AE stream ADVISORY (rule H7: recorded, never counted, never confirming), so there is no second
implementation of the mathematics: `AeStream.magnitude` gives A_AE (journal eq. 11), `hybrid.evidence.DeviceFusion` applies the unchanged HBE-2 distinctness, S_B = 100 exp(-lambda A) (eq. 12) and the
unchanged `trust.engine.DecisionEngine` fuses it (eq. 1, 2, 5). A plain-path device (01-04, 10) is scored by the inherited fleet evaluator. Nothing here reads a clock or a file.

What this adds is the record: every decision's behaviour block carries `ae_primary` with the actual loss, A_AE, S_B_AE, the digests and the AE status, and `supplementary` with the timing magnitudes and the
liveness rule. A slow window (06-09) is fresh once and carried only while confirmed by a disjoint anomalous observation; between completions the status is AWAITING_WINDOW and no proposal exists, which
resets the N = 2 counter and cannot complete it. The historical max(A_AE, A_T) fusion stays in `hybrid` as the versioned rollback.
"""
import dataclasses
import math

from core_runtime import CONTRACT
from hybrid.engine import HybridBehaviorEvaluator, MonitorProfileModel
from trust.evidence import EVALUATED

NON_AE_STREAMS = ("BLOCK", "TIMING_MSG", "TIMING_TICK")
SCORE_READY, AWAITING_WINDOW, INSUFFICIENT, INVALID, NO_EVIDENCE, EXPLAINED = "SCORE_READY", "AWAITING_WINDOW", "INSUFFICIENT_OBSERVATIONS", "INVALID", "NO_EVIDENCE", "CONNECTION_EXPLAINED"
_INSUFFICIENT_REASONS = ("NO_MESSAGES", "INSUFFICIENT_MESSAGES", "NEVER_OBSERVED_IN_SESSION", "OBSERVER_UNAVAILABLE", "NO_WINDOW")
SUPPLEMENTARY_ORIGIN = "SUPPLEMENTARY_TIMING"
SUPPLEMENTARY_ACTION = "RESTRICT"


class RecordingAeStream:
    """An `AeStream` that remembers the loss and vector of its latest score: `magnitude` is its own (same bytes of arithmetic); the memo only makes the loss visible to the decision record."""

    def __init__(self, stream):
        self.stream = stream
        self.name, self.width_s, self.mu_l, self.sigma_l, self.epsilon, self.model = stream.name, stream.width_s, stream.mu_l, stream.sigma_l, stream.epsilon, stream.model
        self.last_loss = None
        inner = stream.model

        class Recording:
            def loss_for_vector(_self, vector):
                self.last_loss = float(inner.loss_for_vector(vector))
                return self.last_loss
        self._stream = dataclasses.replace(stream, model=Recording())

    def magnitude(self, measures):
        self.last_loss = None
        return self._stream.magnitude(measures)


def status_of_reason(reason):
    if reason == "NO_ADMISSIBLE_EVIDENCE":
        return AWAITING_WINDOW
    if reason == EXPLAINED:
        return EXPLAINED
    if reason in _INSUFFICIENT_REASONS:
        return INSUFFICIENT
    if reason in ("NO_BEHAVIOR_EVIDENCE",):
        return NO_EVIDENCE
    return INVALID


def liveness_bound_ns(width_s):
    """Protocol CORE-FINAL-1 section 5, frozen: 3 x the AE window (at least the largest benign gap on every declared law) + 10 s."""
    return (3 * int(width_s) + 10) * 1_000_000_000


class Liveness:
    """The supplementary rule of one device: silence with complete observer coverage, after a delivery seen in the current policy generation, longer than the frozen bound. It yields a recommendation
    with its own origin, no trust score and no AE field. An observer outage or an RC-1 explained interval resets nothing and recommends nothing."""

    def __init__(self, bound_ns):
        self.bound_ns = bound_ns
        self.last_delivery_ns = None

    def tick(self, tick_ns, delivered, *, coverage_complete, generation_start_ns, explained):
        if delivered:
            self.last_delivery_ns = tick_ns
        seen = self.last_delivery_ns is not None and (generation_start_ns is None or self.last_delivery_ns >= generation_start_ns)
        silent_ns = tick_ns - self.last_delivery_ns if seen else None
        active = bool(seen and not delivered and coverage_complete and not explained and silent_ns > self.bound_ns)
        return dict(origin=SUPPLEMENTARY_ORIGIN, non_journal_extension=True, auxiliary_trust_mapping=None, observer_coverage_complete=coverage_complete, rc1_explained=bool(explained),
                    silent_ns=silent_ns, bound_ns=self.bound_ns, recommendation=SUPPLEMENTARY_ACTION if active else None)


def _delivered(window):
    measure = (window.get("measures") or {}).get("delivered_count") or {}
    return measure.get("status") == "VALUE" and (measure.get("value") or 0) > 0


class PrimaryAeEvaluator(HybridBehaviorEvaluator):
    """`routes`: {device: {arm, kind, width_s, ...}} for the record only. Built by `from_hybrid`; `timing_profiles` hold monitors in which only the AE stream counts."""

    def __init__(self, models, calibrations, *, routes, **arguments):
        super().__init__(models, calibrations, **arguments)
        self.routes = routes
        self.liveness = {device: Liveness(liveness_bound_ns(route["width_s"])) for device, route in routes.items()}
        self.slow_memo = {}

    @classmethod
    def from_hybrid(cls, hybrid, routes):
        models, descriptors, profiles = dict(hybrid.models), dict(hybrid.provenance["models"]), {}
        for profile, item in hybrid.timing_profiles.items():
            spec = item.get("monitor")
            if spec is None:
                continue
            if (spec.ae_fast is None) == (spec.ae_slow is None):
                raise ValueError(f"{profile}: a primary-AE monitor needs exactly one autoencoder stream")
            slot = "ae_fast" if spec.ae_fast is not None else "ae_slow"
            new_spec = dataclasses.replace(spec, advisory=NON_AE_STREAMS, **{slot: RecordingAeStream(getattr(spec, slot))})
            definition = dict(item["model"].descriptor["definition"], authority_contract=CONTRACT, counted_streams=[getattr(spec, slot).name], advisory_streams=list(NON_AE_STREAMS))
            model = MonitorProfileModel(profile, new_spec, definition)
            models[profile], descriptors[profile] = model, dict(model.descriptor, origin="CANDIDATE_UNAPPROVED")
            profiles[profile] = dict(item, model=model, monitor=new_spec, advisory=new_spec.advisory)
        provenance = dict(hybrid.provenance, models=descriptors, authority_contract=CONTRACT)
        return cls(models, hybrid.calibrations, routes=routes, timing_profiles=profiles, accepted_pins=hybrid.accepted_pins, reserved_tokens=hybrid.reserved, provenance=provenance,
                   cross_workload_experiment_id=hybrid.cross_workload_experiment_id, connection=hybrid.connection)

    def _copy(self, **changes):
        arguments = dict(routes=self.routes, timing_profiles=self.timing_profiles, accepted_pins=self.accepted_pins, reserved_tokens=self.reserved, provenance=self.provenance,
                         cross_workload_experiment_id=self.cross_workload_experiment_id, connection=self.connection)
        arguments.update(changes)
        copy = PrimaryAeEvaluator(self.models, self.calibrations, **arguments)
        copy.fusions, copy.alive, copy.generation, copy.monitors, copy.liveness, copy.slow_memo = self.fusions, self.alive, self.generation, self.monitors, self.liveness, self.slow_memo
        return copy

    def _spec_of(self, profile):
        return (self.timing_profiles.get(profile) or {}).get("monitor")

    def _ae_block(self, device, profile, result):
        detail = result.detail
        spec = self._spec_of(profile)
        route = self.routes.get(device) or {}
        block = dict(contract=CONTRACT, route_arm=route.get("arm"), route_kind=route.get("kind"), width_s=route.get("width_s"), behavior_source="MISSING", ae_status=None, ae_loss=None, a_ae=None, s_b_ae=None,
                     mu_L=detail.get("mu_L"), sigma_L=detail.get("sigma_L"), n_B=detail.get("n_B"), basis=None, confirmed=None)
        if spec is not None:
            stream = spec.ae_fast if spec.ae_fast is not None else spec.ae_slow
            block.update(mu_L=stream.mu_l, sigma_L=stream.sigma_l)
            hybrid = detail.get("hybrid") or {}
            part = (hybrid.get("monitor") or {}).get("ae_fast" if spec.ae_fast is not None else "ae_slow")
            if part is not None and part.get("a") is not None:         # a window completed at this tick: remember its loss under its item id
                index = part.get("index", (detail.get("window_ref") or {}).get("window_index"))
                self.slow_memo[(device, f"{stream.name}:{index}")] = stream.last_loss
            block.update(basis=hybrid.get("basis"), confirmed=hybrid.get("confirmed"))
            if result.outcome == EVALUATED:
                block.update(behavior_source="AE", ae_status=SCORE_READY, ae_loss=self.slow_memo.get((device, hybrid.get("basis"))), a_ae=detail.get("anomaly_magnitude"), s_b_ae=detail.get("s_b"))
                detail["loss"], detail["mu_L"], detail["sigma_L"] = block["ae_loss"], stream.mu_l, stream.sigma_l
            else:
                block["ae_status"] = status_of_reason(result.reasons[0] if result.reasons else None)
        elif result.outcome == EVALUATED:
            block.update(behavior_source="AE", ae_status=SCORE_READY, ae_loss=detail.get("loss"), a_ae=detail.get("anomaly_magnitude"), s_b_ae=detail.get("s_b"))
        else:
            block["ae_status"] = status_of_reason(result.reasons[0] if result.reasons else None)
        return block

    def _supplementary(self, device, behavior, result, decision_ns):
        window = behavior.get("window") if isinstance(behavior, dict) else None
        if not isinstance(window, dict) or device not in self.liveness:
            return None
        info = window.get("window") or {}
        end = info.get("end_offset_ns")
        tick_ns = behavior.get("observed_ns")
        if type(tick_ns) is not int:
            return None
        explained = bool(self.connection and isinstance(end, int) and self.connection.explains(device, end - info.get("duration_ns", 0), end))
        complete = (window.get("coverage") or {}).get("state") == "COMPLETE"
        out = self.liveness[device].tick(tick_ns, _delivered(window), coverage_complete=complete, generation_start_ns=self.generation.get(device), explained=explained)
        hybrid = result.detail.get("hybrid") or {}
        out["timing_advisory"] = {k: v for k, v in (hybrid.get("advisory") or {}).items() if v is None or math.isfinite(v)}
        return out

    def evaluate(self, behavior, config, *, evidence_mode, decision_ns, expected_identity):
        result = super().evaluate(behavior, config, evidence_mode=evidence_mode, decision_ns=decision_ns, expected_identity=expected_identity)
        profile = behavior.get("bound_profile") if isinstance(behavior, dict) else None
        window = behavior.get("window") if isinstance(behavior, dict) else None
        device = window.get("device") if isinstance(window, dict) else None
        result.detail["ae_primary"] = self._ae_block(device, profile, result)
        result.detail["supplementary"] = self._supplementary(device, behavior, result, decision_ns)
        return result

    def with_reserved(self, tokens):
        extra = frozenset(tokens) - self.reserved
        return self._copy(reserved_tokens=self.reserved | extra, provenance=dict(self.provenance, additional_reserved_token_count=self.provenance.get("additional_reserved_token_count", 0) + len(extra)))
