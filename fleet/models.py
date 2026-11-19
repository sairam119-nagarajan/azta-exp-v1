"""Fleet profile models: training with the frozen Gate 5D training loop, bundles, verified loading, and an independent standard-library loss.

The training loop is `model.autoencoder.train_fit` and the scaler is `preprocessing.scaler.ZScoreScaler`, both UNCHANGED: the frozen S/V allowlists (`ae.PROFILES`,
`scaler.EXPECTED_ZERO_VARIANCE`) are extended for the duration of one call and restored afterwards (`extended_profile`), so a provisional profile is fitted by exactly the code that
fitted S and V, with the same architecture (6-8-k-8-6, k in {2, 3}, three preregistered seeds), the same hyperparameters and the same selection rule (lowest mean best-epoch validation
loss of the three seeds, exact tie to k = 2, primary = seed 0). The zero-variance set of a profile is DECLARED beforehand (`fleet_profiles.json`) and the fit refuses when the data
disagree, exactly as for S. Nothing here calibrates, scores a window against a threshold, or promotes a model.
"""
import contextlib
import hashlib
import json
from pathlib import Path

from model import autoencoder as ae
from model import stdlib_check
from preprocessing import scaler as scaler_module
from preprocessing.scaler import ZScoreScaler

from observation.schema import PREDICTOR_CANDIDATES


class FleetModelRefused(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha256_bytes(blob):
    return hashlib.sha256(blob).hexdigest()


def write_json(path, value):
    """Exclusive create (evidence is never overwritten); returns the SHA-256 of the written bytes."""
    blob = (ae.dumps(value) + "\n").encode("utf-8")
    with Path(path).open("xb") as stream:
        stream.write(blob)
    return sha256_bytes(blob)


@contextlib.contextmanager
def extended_profile(profile, expected_zero_variance):
    """Temporarily admit `profile` to the frozen allowlists. Restores them even on error; refuses a name the frozen sources already own."""
    if profile in ("S", "V") or profile in ae.PROFILES or profile in scaler_module.EXPECTED_ZERO_VARIANCE:
        raise FleetModelRefused(f"{profile!r} is a frozen profile name")
    unknown = set(expected_zero_variance) - set(PREDICTOR_CANDIDATES)
    if unknown:
        raise FleetModelRefused(f"unknown features in the declared zero-variance set: {sorted(unknown)}")
    previous = ae.PROFILES
    ae.PROFILES = tuple(previous) + (profile,)
    scaler_module.EXPECTED_ZERO_VARIANCE[profile] = tuple(f for f in PREDICTOR_CANDIDATES if f in expected_zero_variance)
    try:
        yield
    finally:
        ae.PROFILES = previous
        scaler_module.EXPECTED_ZERO_VARIANCE.pop(profile, None)


def train_profile(profile, expected_zero_variance, train_vectors, val_vectors, val_devices, val_runs, out_dir, *, schema_pins, config=None):
    """Fit the six preregistered candidates (k in {2, 3} x seeds 0..2) of ONE profile on its TRAIN windows, early-stop on its VAL windows, select, write the bundles.

    Returns the selection record. Every fit is retained, including failed ones. `out_dir/fits/<fit_id>/{weights.json,bundle.json}` are written exclusively."""
    ae.configure_determinism()
    config = config or ae.TrainConfig()
    out = Path(out_dir)
    with extended_profile(profile, expected_zero_variance):
        fitted = ZScoreScaler.fit(profile, train_vectors)
        train_z, val_z = fitted.transform_many(train_vectors), fitted.transform_many(val_vectors)
        results = {}
        for k in ae.KS:
            for seed_index in ae.SEED_INDICES:
                result, weights = ae.train_fit(profile=profile, k=k, seed_index=seed_index, train_z=train_z, val_z=val_z, val_devices=list(val_devices),
                                               val_runs=list(val_runs), zero_idx=fitted.zero_variance_indices, config=config)
                fit_dir = out / "fits" / result["fit_id"]
                fit_dir.mkdir(parents=True, exist_ok=False)
                bundle = dict(result, schema_pins=dict(schema_pins), scaler=fitted.to_dict(), hyperparameters=vars(config), weights_file=None, weights_sha256=None)
                if weights is not None:
                    bundle["weights_sha256"] = write_json(fit_dir / "weights.json", weights)
                    bundle["weights_file"] = "weights.json"
                bundle["bundle_sha256_note"] = "the digest of this file is recorded outside it (fleet_models record)"
                write_json(fit_dir / "bundle.json", bundle)
                results[result["fit_id"]] = bundle
        selection = ae.select_primary(list(results.values()))
    write_json(out / "selection_record.json", selection)
    return selection, results


class FleetProfileModel:
    """A verified fleet model: weights digest checked, scaler restored, zero weights asserted, loss in the train-fitted z-score space (journal eq. 8)."""

    def __init__(self, profile, fit_id, scaler, model, weights, descriptor):
        self.profile, self.fit_id, self.scaler, self.model, self.weights, self.descriptor = profile, fit_id, scaler, model, weights, descriptor
        self.model.eval()

    @classmethod
    def load(cls, fit_dir, *, expected_weights_sha256, expected_bundle_sha256=None, expected_profile=None):
        fit_dir = Path(fit_dir)
        bundle_blob = (fit_dir / "bundle.json").read_bytes()
        if expected_bundle_sha256 is not None and sha256_bytes(bundle_blob) != expected_bundle_sha256:
            raise FleetModelRefused(f"bundle digest differs from the pinned one: {fit_dir}")
        bundle = json.loads(bundle_blob.decode("utf-8"))
        weights_blob = (fit_dir / bundle["weights_file"]).read_bytes()
        digest = sha256_bytes(weights_blob)
        if digest != bundle["weights_sha256"] or digest != expected_weights_sha256:
            raise FleetModelRefused(f"weights digest mismatch: {fit_dir}")
        if bundle["status"] != "COMPLETED" or (expected_profile is not None and bundle["profile"] != expected_profile):
            raise FleetModelRefused(f"fit not completed or another profile: {fit_dir}")
        if tuple(bundle["schema_pins"]["feature_order"]) != tuple(PREDICTOR_CANDIDATES):
            raise FleetModelRefused("stored feature order differs from the frozen schema")
        weights = json.loads(weights_blob.decode("utf-8"))
        fitted = ZScoreScaler.from_dict(bundle["scaler"])
        model = ae.model_from_weights(bundle["k"], weights)
        ae.assert_zero_weights(model, fitted.zero_variance_indices, "load")
        descriptor = dict(fit_id=bundle["fit_id"], k=bundle["k"], seed=bundle["seed"], weights_sha256=digest, bundle_sha256=sha256_bytes(bundle_blob),
                          scaler_sha256=sha256_bytes(canonical(bundle["scaler"]).encode("utf-8")), architecture=bundle["architecture"],
                          zero_variance_features=bundle["scaler"]["zero_variance_features"], scaler_n_fit=bundle["scaler"]["n_fit"],
                          schema_pins=bundle["schema_pins"])
        return cls(bundle["profile"], bundle["fit_id"], fitted, model, weights, descriptor)

    def loss_for_vector(self, vector):
        import torch
        try:
            z = self.scaler.transform(vector)
        except scaler_module.PreprocessingRefused as exc:
            raise ValueError(f"SCHEMA_MISMATCH {exc}") from exc
        return float(ae.per_window_loss(self.model, torch.tensor([z], dtype=torch.float64))[0])

    def independent_loss(self, vector):
        """The same loss recomputed with the standard library only (shares no code with model.autoencoder)."""
        return stdlib_check.loss(self.weights, self.scaler.mu, self.scaler.s, vector)
