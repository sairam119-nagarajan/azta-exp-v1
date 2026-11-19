"""The integrated decision engine: registry-authoritative routing + the UNCHANGED trust engine + a separate uncalibrated inference stage.

    observer window (six features, authenticated device)  ->  [routing]   registry resolves device -> profile (or a precise refusal)
                                                          ->  [trust]     the unchanged engine: identity hard gate, behaviour, context, fusion, state
                                                          ->  [inference] the model's loss for windows only the calibration blocked (telemetry, not trust)
                                                          ->  [record]    one decision record with provenance, route, inference and failure class

It wraps an object with the engine's `decide(bundle)` / `describe()` interface, so it plugs into every existing pipeline (offline Shadow, replay
stream, live session) as the engine, and its additions travel inside `annotations.decision_pipeline` of the existing decision record: the existing
logging, hash-chained ledger and summaries are reused and no parallel output format exists. What it adds, and what it cannot do:

  * ROUTING IS THE REGISTRY'S. The profile the engine sees is the registry's resolution for the window's authenticated device (observer-bound, never a
    payload field). An unknown device, an unapproved or unscorable route, a pin mismatch (a ten-device window against the registry-v1 models) or an
    evidence-class mismatch reaches the engine as "no route", i.e. NO_APPROVED_PROFILE_ROUTE. A route the evidence producer already carried (for example a
    run-scoped FROZEN_PLAN route of a counterbalanced collection run) is never used on its own authority: where it names another profile than the
    registry, both authorities disagree and the window is refused as ROUTE_CONFLICT; where it is absent, the registry decides alone (a deployment).
  * NO TRUST PARAMETER OR CALIBRATION LIVES HERE. Weights, thresholds, epsilon, lambda and the calibration all come from the wrapped engine; this wrapper
    changes no component outcome except by withholding a route. It cannot make a MISSING behaviour component evaluable.
  * SYNTHETIC AND OBSERVED EVIDENCE STAY APART. A synthetic fixture registry only routes SYNTHETIC_FIXTURE bundles, a non-synthetic registry never routes
    a synthetic bundle, and every record carries `synthetic` and the engine's own `evidence_scope`.
  * NOTHING IS APPLIED. The wrapper has no broker handle, no credential, no network and no file output; the record keeps `enforcement NONE`.
"""
import dataclasses

from decision_pipeline import taxonomy
from decision_pipeline.inference import InferenceStage
from decision_pipeline.registry import REGISTRY_NOT_SUPPLIED, ROUTE_CONFLICT

PIPELINE_VERSION = "decision-pipeline-1"
LIVE_EVIDENCE_CLASS = "LIVE_PROVISIONAL"       # the class the live-session adapter writes into annotations.live_provenance (tested equal to shadow_live.declaration.EVIDENCE_CLASS)
LIVE_VERIFIED, LIVE_UNVERIFIED, OFFLINE_REPLAY, SYNTHETIC = "LIVE_OBSERVER_VERIFIED", "LIVE_PROVENANCE_UNVERIFIED", "OFFLINE_REPLAY", "SYNTHETIC_FIXTURE"
LIVE_SCOPE = ("LIVE_OBSERVER_VERIFIED: windows read byte-exact from an UNFINISHED observer session whose run, session, partition and window-artifact digest were cross-checked; "
              "the engine's evidence mode TRUSTED_OFFLINE_REPLAY is only the technical label of the frozen vocabulary (its only non-synthetic mode). Provisional engineering "
              "evidence, never an accepted scientific result, and the evidence-class label grants no trust and no enforcement")
UNVERIFIED_SCOPE = ("LIVE_PROVENANCE_UNVERIFIED: the bundle claims live provenance that did not cross-check; treated as non-enforceable replay-like evidence")
SEPARATION = ("a decision record with synthetic = true is an engineering fixture and never a measurement; a record with synthetic = false is built from "
              "an observer window and is still a counterfactual Shadow proposal, not an applied policy and not an accepted scientific result unless "
              "its run says so")


def _evidence_class(bundle):
    """(class, detail) of the bundle's evidence. A live label is given ONLY when the live-adapter provenance cross-checks against the producer's run provenance and the window itself;
    the label never changes the engine's decision and is never sufficient for enforcement (the operational guard needs independent approvals as well)."""
    if bundle.evidence_mode == "SYNTHETIC_FIXTURE":
        return SYNTHETIC, dict(verified=True)
    notes = bundle.annotations or {}
    live = notes.get("live_provenance")
    if live is None:
        return OFFLINE_REPLAY, dict(verified=True)
    window = (bundle.behavior or {}).get("window") if isinstance(bundle.behavior, dict) else None
    try:
        run = notes["producer"]["run_provenance"]
        artifact = live["windows_artifact"]
        if live["timing"]["read_after_session_summary"] is True:
            return OFFLINE_REPLAY, dict(verified=True, reason="window first read after the observer session ended")
        checks = dict(
            adapter_class=live["evidence_class"] == LIVE_EVIDENCE_CLASS, unfinished_prefix=artifact["state"] == "UNFINISHED_PREFIX",
            artifact_digest=isinstance(run["windows_artifact_sha256"], str) and len(run["windows_artifact_sha256"]) == 64
                and all(c in "0123456789abcdef" for c in run["windows_artifact_sha256"]) and run["windows_artifact_sha256"] == artifact["prefix_sha256"],
            read_while_active=live["timing"]["read_after_session_summary"] is False,
            run_id=window is not None and live["run_id"] == run["collection_run_id"] == window["collection_run_id"],
            session=window is not None and live["observer_session_id"] == run["observer_session_id"] == window["observer_session_id"],
            partition=live["partition_role"] == run["partition"])
        timing = dict(cross_domain_mapping_validated=live["timing"]["cross_domain_mapping_validated"], window_end_basis=live["timing"]["window_end_basis"])
    except (KeyError, TypeError):
        return LIVE_UNVERIFIED, dict(verified=False, reason="live provenance fields missing or malformed")
    if all(checks.values()):
        return LIVE_VERIFIED, dict(verified=True, checks=checks, timing=timing)
    return LIVE_UNVERIFIED, dict(verified=False, failed=sorted(k for k, v in checks.items() if not v))


class IntegratedEngine:
    def __init__(self, engine, registry, *, models, descriptors):
        if not callable(getattr(engine, "decide", None)) or not callable(getattr(engine, "describe", None)):
            raise TypeError("a decision engine with decide() and describe() is required")
        registry.verify_loaded_models(descriptors)          # an incompatible model version stops the wiring before any window is decided
        self.engine, self.registry = engine, registry
        self.inference = InferenceStage(models, descriptors)
        self.descriptors = dict(descriptors)

    def describe(self):
        base = self.engine.describe()
        return dict(base, decision_pipeline=dict(version=PIPELINE_VERSION, registry=self.registry.describe(), taxonomy=taxonomy.TAXONOMY_VERSION,
                                                inference_version=self.inference.__class__.__name__, separation=SEPARATION,
                                                routing="registry-authoritative: a producer route is recorded and never used on its own authority; a differing trusted producer route is refused as ROUTE_CONFLICT"))

    def _route(self, bundle):
        """(bundle for the engine, resolution dict or None, producer route audit or None)."""
        behavior = bundle.behavior
        if behavior is None or not isinstance(behavior.get("window"), dict):
            return bundle, None, None
        window = behavior["window"]
        identity = window.get("identity") if isinstance(window.get("identity"), dict) else {}
        resolution = self.registry.resolve(window.get("device"), window_registry_sha256=identity.get("registry_sha256"),
                                           window_config_sha256=window.get("observation_config_sha256"), evidence_mode=bundle.evidence_mode,
                                           window_purpose=window.get("purpose"))
        producer_profile = behavior.get("bound_profile")
        audit = dict(producer_profile=producer_profile, producer_route_label=behavior.get("route_provenance"), used=False,
                     reason="the registry's resolution replaces the producer's route; a differing producer route is a conflict")
        if resolution.routed and producer_profile is not None and producer_profile != resolution.profile:
            resolution = dataclasses.replace(resolution, profile=None, code=ROUTE_CONFLICT, route_label=None, model_id=None, model_weights_sha256=None,
                                             blockers=(f"the registry routes this device to {resolution.profile} but the evidence producer's trusted route "
                                                       f"names {producer_profile}; two authorities disagree, so no route is used",))
            audit["conflict"] = True
        routed = dict(behavior, bound_profile=resolution.profile, route_provenance=resolution.route_label or "ABSENT")
        return dataclasses.replace(bundle, behavior=routed), resolution.to_dict(), audit

    def decide(self, bundle):
        routed_bundle, resolution, audit = self._route(bundle)
        record = self.engine.decide(routed_bundle)
        inference = self.inference.infer(record)
        failure = taxonomy.classify_record(record)
        evidence_class, evidence_detail = _evidence_class(bundle)
        if evidence_class == LIVE_VERIFIED:
            record["evidence_scope"] = LIVE_SCOPE
        elif evidence_class == LIVE_UNVERIFIED:
            record["evidence_scope"] = UNVERIFIED_SCOPE
        record["annotations"] = dict(record.get("annotations") or {})
        record["annotations"]["decision_pipeline"] = dict(evidence=dict(note="the class labels provenance only; it grants no trust and no enforcement",
                                                                        engine_mode=bundle.evidence_mode, detail=evidence_detail, **{"class": evidence_class}),
            version=PIPELINE_VERSION, synthetic=bundle.evidence_mode == "SYNTHETIC_FIXTURE", separation=SEPARATION,
            registry=dict(version=self.registry.version, status=self.registry.status, sha256=self.registry.sha256),
            route=resolution or dict(code=REGISTRY_NOT_SUPPLIED if bundle.behavior is None else "NO_WINDOW_TO_ROUTE", profile=None),
            producer_route=audit, inference=inference, failure=failure)
        return record
