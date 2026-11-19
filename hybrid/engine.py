"""The hybrid behaviour evaluator: HBE-1 evidence behind the UNCHANGED trust engine's behaviour-evaluator interface.

`HybridBehaviorEvaluator` is a `fleet.evaluator.FleetBehaviorEvaluator`. For a profile with an autoencoder model it behaves exactly as the fleet evaluator does (the engine, the routing, the calibration
and every check are inherited; nothing is re-implemented). For a TIMING profile, whose "model" is the digest of a timing contract (so the registry-authoritative route, the model catalog and the
loaded-model verification of `decision_pipeline` work unchanged), it keeps the same checks that precede scoring (reserved tokens, schema and registry pins, a trusted route, fresh evidence, the
identity-to-principal binding, complete observer coverage) but replaces the six-measure readiness rule, which a three-message window can never meet, by the contract-based monitor TM-1, and fuses its
items per device with `hybrid.evidence.DeviceFusion` (rules H1 to H7). The behaviour component the engine receives is the usual one: EVALUATED with S_B = 100 exp(-lambda A_B), or MISSING with the exact
reason; weights, thresholds, hard identity gate, missing-evidence policies and the persistence of the enforcement layer are untouched.

Per-device state (fusion, carried items) lives here and is a pure function of the decisions made so far in the order they are made. It is NOT persisted: after an adapter restart the carried items are forgotten, which is fail-safe (an anomaly that was carried and unconfirmed is not counted again, never the reverse) but lengthens confirmation by up to one confirmation horizon; replaying the ledger into the evaluator is not implemented. The start of a device's
current policy generation (the last PEP-verified change, from the identity-barrier annotation of the bundle) is passed in by `GenerationAwareEngine`, so the silence of a quarantined and restored device is
never read as a missing report. Nothing here is calibrated, accepted or enforced; all of it is PROVISIONAL.
"""
from fractions import Fraction
import hashlib
import json

from fleet.evaluator import FleetBehaviorEvaluator
from hybrid import evidence as he, timing as tm
from hybrid.monitor import DeviceMonitor
from observation.schema import validate_window
from trust.behavior import FROZEN_WINDOW_NS
from trust.evidence import EVALUATED, MISSING, TRUSTED_ROUTE_PROVENANCE, ComponentResult, age_problem, provenance_trusted

TIMING_MODEL_KIND = "TM-1"
MONITOR_MODEL_KIND = "MP-1"


def contract_digest(contract):
    return hashlib.sha256(json.dumps(contract.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


class TimingProfileModel:
    """Stands where an autoencoder stands in the engine's model catalog: an identity (the digest of the timing contract), never a loss."""

    def __init__(self, profile, contract):
        self.profile, self.contract = profile, contract
        self.fit_id = f"{TIMING_MODEL_KIND}-{contract.device}-{contract_digest(contract)[:12]}"
        self.weights_sha256 = contract_digest(contract)
        self.descriptor = dict(fit_id=self.fit_id, weights_sha256=self.weights_sha256, scaler_sha256=None, kind=TIMING_MODEL_KIND, contract=contract.to_dict())

    def loss_for_vector(self, vector):
        raise ValueError("a timing profile has no reconstruction loss")


class MonitorProfileModel:
    """Stands where an autoencoder stands in the engine's model catalog for a pre-live monitor profile: an identity (the digest of the COMPLETE profile definition: every contract, every
    constituent model digest, every calibration constant, every stream status), never a loss."""

    def __init__(self, profile, monitor_spec, definition):
        self.profile, self.monitor_spec, self.contract = profile, monitor_spec, monitor_spec.tm
        digest = hashlib.sha256(json.dumps(definition, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        self.fit_id = f"{MONITOR_MODEL_KIND}-{monitor_spec.device}-{digest[:12]}"
        self.weights_sha256 = digest
        self.descriptor = dict(fit_id=self.fit_id, weights_sha256=digest, scaler_sha256=None, kind=MONITOR_MODEL_KIND, definition=definition)

    def loss_for_vector(self, vector):
        raise ValueError("a monitor profile has no reconstruction loss")


class HybridBehaviorEvaluator(FleetBehaviorEvaluator):
    """timing_profiles: {profile: dict(model=TimingProfileModel, advisory=tuple of stream names, calibration_id=str)}."""

    def __init__(self, models, calibrations, *, timing_profiles, accepted_pins, reserved_tokens=(), provenance=None, cross_workload_experiment_id=None, connection=None):
        super().__init__(models, calibrations, accepted_pins=accepted_pins, reserved_tokens=reserved_tokens, provenance=provenance,
                         cross_workload_experiment_id=cross_workload_experiment_id)
        self.timing_profiles = dict(timing_profiles)
        self.fusions, self.alive, self.generation, self.monitors = {}, {}, {}, {}
        # Phase 2 (RC-1): an optional broker-connection evidence provider (`explains(device, start_ns, end_ns)`, `filter_items(device, items)` on the window clock); None = unchanged
        self.connection = connection

    def _copy(self, **changes):
        arguments = dict(timing_profiles=self.timing_profiles, accepted_pins=self.accepted_pins, reserved_tokens=self.reserved, provenance=self.provenance,
                         cross_workload_experiment_id=self.cross_workload_experiment_id, connection=self.connection)
        arguments.update(changes)
        copy = HybridBehaviorEvaluator(self.models, self.calibrations, **arguments)
        copy.fusions, copy.alive, copy.generation, copy.monitors = self.fusions, self.alive, self.generation, self.monitors       # one stream of decisions, one state
        return copy

    def with_connection(self, provider):
        """A NEW evaluator that applies RC-1 with `provider` (the argument is not changed; not calling this is the rollback). Its monitors are created fresh, so it must be built before the
        first decision of a session."""
        out = self._copy(connection=provider)
        out.fusions, out.alive, out.generation, out.monitors = {}, {}, {}, {}
        return out

    def evaluate(self, behavior, config, *, evidence_mode, decision_ns, expected_identity):
        profile = behavior.get("bound_profile") if isinstance(behavior, dict) else None
        if profile not in self.timing_profiles:
            result = super().evaluate(behavior, config, evidence_mode=evidence_mode, decision_ns=decision_ns, expected_identity=expected_identity)
            window = behavior.get("window") if isinstance(behavior, dict) else None
            if self.connection is not None and result.outcome == EVALUATED and isinstance(window, dict) and isinstance(window.get("window"), dict):
                end = window["window"].get("end_offset_ns")
                if isinstance(end, int) and self.connection.explains(window.get("device"), end - FROZEN_WINDOW_NS, end):
                    detail = dict(result.detail, outcome=MISSING, reasons=["CONNECTION_EXPLAINED"], s_b=None)
                    return ComponentResult(MISSING, None, ("CONNECTION_EXPLAINED",), detail)
            return result
        return self._evaluate_timing(profile, behavior, config, evidence_mode=evidence_mode, decision_ns=decision_ns, expected_identity=expected_identity)

    def _evaluate_timing(self, profile, behavior, config, *, evidence_mode, decision_ns, expected_identity):
        spec = self.timing_profiles[profile]
        contract = spec["model"].contract
        window = behavior["window"]
        detail = dict(outcome=MISSING, reasons=[], profile=profile, route_provenance=behavior["route_provenance"], window_ref=None, observed_ns=behavior["observed_ns"], features=None,
                      delivered_count=None, loss=None, mu_L=None, sigma_L=None, n_B=None, epsilon=config.epsilon_float, lam=config.lambda_float, anomaly_magnitude=None,
                      anomaly_magnitude_overflow=False, s_b=None, workload_version=behavior["workload_version"], calibration_id=spec["calibration_id"],
                      calibration_status=spec.get("calibration_status", "PROVISIONAL_UNAPPROVED"), cross_workload_baseline_experiment_id=None, hybrid=None)

        def missing(reason):
            detail["reasons"] = [reason]
            return ComponentResult(MISSING, None, (reason,), detail)

        if window is None:
            return missing("NO_WINDOW")
        info = window.get("window") if isinstance(window.get("window"), dict) else {}
        detail["window_ref"] = dict(collection_run_id=window.get("collection_run_id"), observer_session_id=window.get("observer_session_id"), device=window.get("device"),
                                    window_index=info.get("index"), purpose=window.get("purpose"))
        if any(isinstance(t, str) and t in self.reserved for t in (window.get("collection_run_id"), window.get("observer_session_id"))):
            return missing("RESERVED_EVIDENCE_REFUSED")
        pins = self.accepted_pins.get(profile, ())
        try:
            validate_window(window)
            if (window["identity"]["registry_sha256"], window["observation_config_sha256"], window["schema_fingerprint"]) not in pins:
                raise ValueError("pins")
            if window["window"]["duration_ns"] != FROZEN_WINDOW_NS:
                raise ValueError("duration")
        except (ValueError, TypeError, KeyError, AttributeError):
            return missing("SCHEMA_MISMATCH")
        if not provenance_trusted(behavior["route_provenance"], evidence_mode, TRUSTED_ROUTE_PROVENANCE):
            return missing(f"UNTRUSTED_ROUTE_PROVENANCE:{behavior['route_provenance']}")
        problem = age_problem(behavior["observed_ns"], decision_ns, config.max_evidence_age_ns["behavior"])
        if problem:
            return missing(f"{problem}_BEHAVIOR_EVIDENCE")
        if expected_identity is None or (window["identity"]["bound_username"], window["identity"]["bound_client_id"]) != expected_identity:
            return missing("IDENTITY_BEHAVIOR_BINDING_MISMATCH")
        device, tick_ns = window["device"], behavior["observed_ns"]
        n = window["measures"]["delivered_count"]
        detail["delivered_count"] = n["value"] if n["status"] == "VALUE" else None
        monitor_spec = spec.get("monitor")
        if monitor_spec is not None:
            # the pre-live per-device monitor (TM-1 + BM-1/DR-1 + AE streams under HBE-2): ONE implementation shared with the offline studies (`hybrid.monitor`)
            if device not in self.monitors:
                monitor = DeviceMonitor(monitor_spec)
                if self.connection is not None:            # RC-1: the fusion sees the items with every explained one turned MISSING (the monitor and its streams are unchanged)
                    inner, provider = monitor.fusion.tick, self.connection
                    monitor.fusion.tick = lambda t, items, _d=device: inner(t, provider.filter_items(_d, items))
                self.monitors[device] = monitor
            monitor = self.monitors[device]
            record = monitor.tick(window, tick_ns=tick_ns, generation_start_ns=self.generation.get(device))
            tdetail = record["detail"]
        else:
            status, _, tdetail = tm.evaluate(contract, window["measures"], coverage_complete=window["coverage"]["state"] == "COMPLETE", window_end_ns=tick_ns,
                                             generation_start_ns=self.generation.get(device))
            fusion = self.fusions.setdefault(device, he.DeviceFusion(confirm_horizon_ns=he.confirm_horizon_ns(contract), advisory=tuple(spec.get("advisory", ()))))
            alive = [i for i in self.alive.get(device, []) if i.expires_ns >= tick_ns] + he.timing_items(contract, tdetail, status, tick_ns, info["index"])
            self.alive[device] = alive
            record = fusion.tick(tick_ns, alive)
        detail["hybrid"] = dict(rule=record["rule"], monitor=tdetail, status=record["status"], fresh=record["fresh"], carried=record["carried"], missing=record["missing"],
                                confirmed=record["confirmed"], contradictory=record["contradictory"], basis=record["basis"], contributing=record["contributing"], advisory=record["advisory"])
        if record["status"] != "EVALUATED":
            return missing(record["reasons"][0] if record["reasons"] else next(iter(record["missing"].values()), "NO_ADMISSIBLE_EVIDENCE"))
        a = record["a"]
        s_b = he.s_b(a, config.lambda_float)
        detail.update(outcome=EVALUATED, reasons=["BEHAVIOR_SCORED_HYBRID" if monitor_spec is not None else "BEHAVIOR_SCORED_TIMING"], anomaly_magnitude=a, s_b=s_b)
        return ComponentResult(EVALUATED, Fraction(s_b), tuple(detail["reasons"]), detail)


class GenerationAwareEngine:
    """Hands each device's latest PEP-verified policy-change instant (the identity barrier's annotation) to the evaluator before the unchanged engine decides, and forwards everything else."""

    def __init__(self, engine, evaluator):
        self.engine, self.evaluator = engine, evaluator

    def __getattr__(self, name):
        return getattr(self.engine, name)

    def decide(self, bundle):
        behavior = getattr(bundle, "behavior", None)
        barrier = (getattr(bundle, "annotations", None) or {}).get("identity_barrier") or {}
        if isinstance(behavior, dict) and isinstance(behavior.get("window"), dict) and barrier.get("policy_change_ns") is not None:
            self.evaluator.generation[behavior["window"].get("device")] = barrier["policy_change_ns"]
        return self.engine.decide(bundle)
