"""Candidate autoencoders on the tolerance-floored scaler: training with the FROZEN Gate 5D loop, verified loading, and an independent standard-library loss.

Everything but the scaler is the accepted procedure, byte for byte: `model.autoencoder.train_fit` (architecture 6-8-k-8-6, k in {2, 3}, seeds 0 to 2, unchanged hyperparameters and early
stopping), the D-ZV-2 held-at-zero weights for exactly-constant features, the selection rule (lowest mean best-epoch VAL loss over the three seeds, exact tie to k = 2, primary = seed 0
of the selected k) and the loss of journal equation 8 in the train-fitted standardized space. A candidate name that a frozen source already owns is refused. Nothing here calibrates,
scores against a threshold or promotes a model.
"""
import contextlib
import hashlib
import json
from pathlib import Path

from model import autoencoder as ae
from model import stdlib_check
from observation.schema import PREDICTOR_CANDIDATES

from fleet.models import canonical, sha256_bytes, write_json
from hybrid.scaler import FlooredScaler


class CandidateRefused(ValueError):
    pass


@contextlib.contextmanager
def extended_profile(profile):
    if profile in ae.PROFILES:
        raise CandidateRefused(f"{profile!r} is a name already owned by a frozen or fleet profile")
    previous = ae.PROFILES
    ae.PROFILES = tuple(previous) + (profile,)
    try:
        yield
    finally:
        ae.PROFILES = previous


def train_candidate(profile, declared_zero, floors, train_vectors, val_vectors, val_devices, val_runs, out_dir, *, contract, config=None):
    """Fit the six preregistered fits of ONE candidate, write the bundles exclusively under out_dir/fits/<fit_id>/, return (selection, results). Every fit is retained."""
    ae.configure_determinism()
    config = config or ae.TrainConfig()
    out = Path(out_dir)
    with extended_profile(profile):
        fitted = FlooredScaler.fit(profile, train_vectors, floors, declared_zero)
        train_z, val_z = fitted.transform_many(train_vectors), fitted.transform_many(val_vectors)
        results = {}
        for k in ae.KS:
            for seed_index in ae.SEED_INDICES:
                result, weights = ae.train_fit(profile=profile, k=k, seed_index=seed_index, train_z=train_z, val_z=val_z, val_devices=list(val_devices), val_runs=list(val_runs),
                                               zero_idx=fitted.zero_variance_indices, config=config)
                fit_dir = out / "fits" / result["fit_id"]
                fit_dir.mkdir(parents=True, exist_ok=False)
                bundle = dict(result, contract=contract, scaler=fitted.to_dict(), hyperparameters=vars(config), weights_file=None, weights_sha256=None,
                              schema_pins=dict(feature_order=list(PREDICTOR_CANDIDATES)))
                if weights is not None:
                    bundle["weights_sha256"] = write_json(fit_dir / "weights.json", weights)
                    bundle["weights_file"] = "weights.json"
                write_json(fit_dir / "bundle.json", bundle)
                results[result["fit_id"]] = bundle
        selection = ae.select_primary(list(results.values()))
    write_json(out / "selection_record.json", selection)
    return selection, results


class CandidateModel:
    """A verified candidate: weights digest checked, scaler restored, zero weights asserted, loss in the floored standardized space (journal equation 8)."""

    def __init__(self, profile, fit_id, scaler, model, weights, descriptor):
        self.profile, self.fit_id, self.scaler, self.model, self.weights, self.descriptor = profile, fit_id, scaler, model, weights, descriptor
        self.model.eval()

    @classmethod
    def load(cls, fit_dir, *, expected_weights_sha256, expected_bundle_sha256=None, expected_profile=None):
        fit_dir = Path(fit_dir)
        bundle_blob = (fit_dir / "bundle.json").read_bytes()
        if expected_bundle_sha256 is not None and sha256_bytes(bundle_blob) != expected_bundle_sha256:
            raise CandidateRefused(f"bundle digest differs from the pinned one: {fit_dir}")
        bundle = json.loads(bundle_blob.decode("utf-8"))
        if bundle["status"] != "COMPLETED" or not bundle.get("weights_file") or (expected_profile is not None and bundle["profile"] != expected_profile):
            raise CandidateRefused(f"fit not completed or another candidate: {fit_dir}")
        weights_blob = (fit_dir / bundle["weights_file"]).read_bytes()
        digest = sha256_bytes(weights_blob)
        if digest != bundle["weights_sha256"] or digest != expected_weights_sha256:
            raise CandidateRefused(f"weights digest mismatch: {fit_dir}")
        if bundle["status"] != "COMPLETED" or (expected_profile is not None and bundle["profile"] != expected_profile):
            raise CandidateRefused(f"fit not completed or another candidate: {fit_dir}")
        weights = json.loads(weights_blob.decode("utf-8"))
        fitted = FlooredScaler.from_dict(bundle["scaler"])
        model = ae.model_from_weights(bundle["k"], weights)
        ae.assert_zero_weights(model, fitted.zero_variance_indices, "load")
        descriptor = dict(fit_id=bundle["fit_id"], k=bundle["k"], seed=bundle["seed"], weights_sha256=digest, bundle_sha256=sha256_bytes(bundle_blob),
                          scaler_sha256=sha256_bytes(canonical(bundle["scaler"]).encode("utf-8")), contract=bundle["contract"], zero_variance_features=bundle["scaler"]["zero_variance_features"],
                          floored_features=bundle["scaler"]["floored_features"], n_fit=bundle["scaler"]["n_fit"])
        return cls(bundle["profile"], bundle["fit_id"], fitted, model, weights, descriptor)

    def loss_for_vector(self, vector):
        import torch
        z = self.scaler.transform(vector)
        return float(ae.per_window_loss(self.model, torch.tensor([z], dtype=torch.float64))[0])

    def losses(self, vectors):
        import torch
        z = self.scaler.transform_many(vectors)
        return [float(v) for v in ae.per_window_loss(self.model, torch.tensor(z, dtype=torch.float64))]

    def independent_loss(self, vector):
        return stdlib_check.loss(self.weights, self.scaler.mu, self.scaler.s, vector)


class EnsembleModel:
    """Seed procedure E3 (protocol CORE-P1 section 3.3): the scoring loss is the MEAN of the reconstruction losses of the members, the three seeds (0, 1, 2) of the architecture the frozen selection rule chose.

    Each member's loss is the journal's L (equation 8) in its own fitted standardized space; the mean is a variance-reduction device over seeds, not a new journal equation, and the ensemble is
    calibrated as ONE model (mu_L and the sample sigma_L of the ensemble loss on the calibration windows). The members must belong to one contract (device and duration); the order of the
    members never changes the loss or the digest."""

    def __init__(self, members):
        members = tuple(members)
        if len(members) < 2:
            raise CandidateRefused("an ensemble needs at least two members")
        contracts = {json.dumps(m.descriptor["contract"], sort_keys=True) for m in members}
        if len(contracts) != 1 or len({m.profile for m in members}) != 1 or len({m.fit_id for m in members}) != len(members):
            raise CandidateRefused("the members of an ensemble must be distinct fits of ONE contract")
        self.members = tuple(sorted(members, key=lambda m: m.fit_id))
        self.profile, self.fit_id = self.members[0].profile, "E" + str(len(self.members)) + "-" + self.members[0].profile
        weights = sha256_bytes(canonical([m.descriptor["weights_sha256"] for m in self.members]).encode("utf-8"))
        bundles = sha256_bytes(canonical([m.descriptor["bundle_sha256"] for m in self.members]).encode("utf-8"))
        self.descriptor = dict(fit_id=self.fit_id, ensemble_members=[m.descriptor["fit_id"] for m in self.members], weights_sha256=weights, bundle_sha256=bundles,
                               contract=self.members[0].descriptor["contract"], rule="E3 mean of the member losses",
                               zero_variance_features=self.members[0].descriptor["zero_variance_features"], n_fit=self.members[0].descriptor["n_fit"])

    @classmethod
    def load(cls, items, *, expected_weights_sha256=None, expected_bundle_sha256=None):
        """`items` = [{"model_dir", "weights_sha256", "bundle_sha256"}, ...]; every member is digest-verified by `CandidateModel.load`, then the combined digests are checked when given."""
        ensemble = cls([CandidateModel.load(item["model_dir"], expected_weights_sha256=item["weights_sha256"], expected_bundle_sha256=item["bundle_sha256"]) for item in items])
        if expected_weights_sha256 is not None and ensemble.descriptor["weights_sha256"] != expected_weights_sha256:
            raise CandidateRefused("the combined member weights digest differs from the pinned one")
        if expected_bundle_sha256 is not None and ensemble.descriptor["bundle_sha256"] != expected_bundle_sha256:
            raise CandidateRefused("the combined member bundle digest differs from the pinned one")
        return ensemble

    def loss_for_vector(self, vector):
        return sum(m.loss_for_vector(vector) for m in self.members) / len(self.members)

    def losses(self, vectors):
        per_member = [m.losses(vectors) for m in self.members]
        return [sum(column) / len(per_member) for column in zip(*per_member)]


def file_sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
