"""Composition of the integrated engine from the existing, digest-verified components. Opens only the files it is told to open.

`wrap_engine` takes a trust `DecisionEngine` that was already built from a validated configuration, one explicitly chosen calibration and the frozen S/V
models (`trust.artifacts.load_frozen_behavior`) and adds the registry-authoritative routing and the inference stage. Nothing is chosen here: no registry
default, no calibration, no parameter. The registry file must be named together with its authorized SHA-256 and it must name exactly the frozen models
the engine has loaded.
"""
from pathlib import Path

from decision_pipeline.integrated import IntegratedEngine
from decision_pipeline.registry import load_registry, model_catalog_from_freeze


def wrap_engine(engine, *, repo_root, registry_path, registry_sha256):
    from preprocessing.gate5d_data import PIN
    from trust import artifacts
    behavior = engine.behavior
    descriptors = behavior.provenance.get("models")
    if not descriptors:
        from decision_pipeline.errors import RegistryRefused
        raise RegistryRefused("ENGINE_WITHOUT_FROZEN_MODELS", "the engine's behaviour evaluator carries no frozen-model descriptors")
    catalog = model_catalog_from_freeze(artifacts.load_freeze(Path(repo_root)))
    registry = load_registry(registry_path, authorized_file_sha256=registry_sha256, model_catalog=catalog,
                             model_pins={k: PIN[k] for k in ("registry_sha256", "observation_config_sha256")})
    return IntegratedEngine(engine, registry, models=behavior.models, descriptors=descriptors)
