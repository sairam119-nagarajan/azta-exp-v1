"""Verified loading and scoring of a behavioural-family model: ONE set of learned parameters (the E3 ensemble of an arm) viewed through a device-specific baseline normaliser.

`FamilyNetworks` is the shared part: the three seeds of the selected architecture of an arm, weights digest-verified, scoring loss = the MEAN of their reconstruction losses (journal equation 8
per member, in the input space the arm was trained in). `FamilyDeviceModel` binds those networks to ONE device's `DeviceNormalizer`; it is the object the rest of the system sees (it has
`loss_for_vector`, the same duck-typed interface as `hybrid.models.CandidateModel`, so `hybrid.monitor.AeStream` and `fleet.evaluator.FleetBehaviorEvaluator` use it unchanged). Two devices of a
family hold the SAME `FamilyNetworks` object, which is the checkable meaning of "shared parameters" (`shared_digest` is the same, `networks is networks`). A model refuses a vector of another
device-contract: the normaliser carries its device name, and a scoring call that names another device is refused, so baselines cannot be confused across devices.
"""
import hashlib
import json
from pathlib import Path

import numpy as np

from fleet.models import canonical, sha256_bytes
from family import devices as dev
from family.normalize import FEATURES
from model import autoencoder as ae
from model import stdlib_check


class FamilyModelRefused(ValueError):
    pass


class FamilyNetworks:
    """The shared learned parameters of one arm: members = the three seeds of the selected k, each (fit_id, k, torch model, weights JSON, weights digest, bundle digest)."""

    def __init__(self, arm, contract, devices, members):
        if len(members) != 3 or len({m["fit_id"] for m in members}) != 3:
            raise FamilyModelRefused(f"{arm}: an E3 ensemble needs three distinct fits")
        self.arm, self.contract, self.devices = arm, contract, tuple(devices)
        self.members = tuple(sorted(members, key=lambda m: m["fit_id"]))
        self.weights_sha256 = sha256_bytes(canonical([m["weights_sha256"] for m in self.members]).encode("utf-8"))
        self.bundle_sha256 = sha256_bytes(canonical([m["bundle_sha256"] for m in self.members]).encode("utf-8"))
        self.parameters = sum(sum(p.numel() for p in m["model"].parameters()) for m in self.members)

    @classmethod
    def load(cls, arm_dir, items, *, arm, contract, devices):
        """`items` = [{"fit_id", "weights_sha256", "bundle_sha256"}, ...] (three); every member's bundle and weights files are digest-verified against the record before use."""
        import torch
        if torch.get_default_dtype() != torch.float64:
            ae.configure_determinism()
        members = []
        for item in items:
            fit_dir = Path(arm_dir) / "fits" / item["fit_id"]
            bundle_blob = (fit_dir / "bundle.json").read_bytes()
            if sha256_bytes(bundle_blob) != item["bundle_sha256"]:
                raise FamilyModelRefused(f"bundle digest differs from the pinned one: {fit_dir}")
            bundle = json.loads(bundle_blob.decode("utf-8"))
            weights_blob = (fit_dir / bundle["weights_file"]).read_bytes()
            digest = sha256_bytes(weights_blob)
            if digest != bundle["weights_sha256"] or digest != item["weights_sha256"]:
                raise FamilyModelRefused(f"weights digest mismatch: {fit_dir}")
            if bundle["status"] != "COMPLETED" or bundle["arm"] != arm or bundle["contract"] != contract or tuple(bundle["members"]) != tuple(devices):
                raise FamilyModelRefused(f"fit not completed or another arm: {fit_dir}")
            if tuple(bundle["schema_pins"]["feature_order"]) != tuple(FEATURES):
                raise FamilyModelRefused("stored feature order differs from the frozen schema")
            weights = json.loads(weights_blob.decode("utf-8"))
            model = ae.model_from_weights(bundle["k"], weights)
            model.eval()
            members.append(dict(fit_id=bundle["fit_id"], k=bundle["k"], model=model, weights=weights, weights_sha256=digest, bundle_sha256=item["bundle_sha256"], normalizers=bundle["normalizers"]))
        return cls(arm, contract, devices, members)

    def losses_z(self, z, mask_idx=()):
        """Mean over the members of the per-window reconstruction loss of the rows of `z` (an (n, 6) array in the arm's input space). `mask_idx` (Phase 2 input masking, IM): those inputs
        are fed as 0.0 (the value every TRAIN row of the device has there) while the reconstruction target keeps the observed value, exactly the D-ZV-2 idea at the input instead of the
        weights; empty = the unchanged loss."""
        import torch
        tensor = torch.tensor(np.asarray(z, dtype=np.float64).reshape(-1, len(FEATURES)), dtype=torch.float64)
        if not mask_idx:
            per_member = [ae.per_window_loss(m["model"], tensor).numpy() for m in self.members]
            return np.mean(per_member, axis=0)
        fed = tensor.clone()
        fed[:, list(mask_idx)] = 0.0
        with torch.no_grad():
            per_member = [((m["model"](fed) - tensor) ** 2).mean(dim=1).numpy() for m in self.members]
        return np.mean(per_member, axis=0)

    def member_losses_z(self, z, mask_idx=()):
        """The per-member losses, shape (3, n): the seeds of the selected architecture scored separately (seed-sensitivity studies; the scoring loss of the arm is their mean)."""
        import torch
        tensor = torch.tensor(np.asarray(z, dtype=np.float64).reshape(-1, len(FEATURES)), dtype=torch.float64)
        if not mask_idx:
            return np.vstack([ae.per_window_loss(m["model"], tensor).numpy() for m in self.members])
        fed = tensor.clone()
        fed[:, list(mask_idx)] = 0.0
        with torch.no_grad():
            return np.vstack([((m["model"](fed) - tensor) ** 2).mean(dim=1).numpy() for m in self.members])

    def independent_loss_z(self, z, mask_idx=()):
        import math
        fed = [0.0 if i in mask_idx else x for i, x in enumerate(z)]
        return math.fsum(math.fsum((o - x) ** 2 for o, x in zip(stdlib_check.forward(m["weights"], fed), z)) / len(z) for m in self.members) / len(self.members)


class FamilyDeviceModel:
    """One device viewed through the shared networks. `profile`/`fit_id` identify the (arm, device) pair; `descriptor` carries every digest the loader and the pipeline verify."""

    def __init__(self, device, networks, normalizer, *, input_mask=False):
        if normalizer.device != device or normalizer.contract != networks.contract or device not in networks.devices:
            raise FamilyModelRefused(f"{device}: the normaliser or the networks belong to another device or contract")
        self.device, self.networks, self.normalizer = device, networks, normalizer
        # Phase 2 IM: the features that are EXACTLY constant in this device's TRAIN rows (the normaliser's zero-variance set) are fed as 0.0; their reconstruction error still counts
        self.mask_idx = tuple(FEATURES.index(f) for f in normalizer.zero_variance) if input_mask else ()
        suffix = "+IM" if input_mask else ""
        self.profile = f"FAM-{networks.arm}{suffix}-{device}"
        self.fit_id = f"{networks.arm}{suffix}:E3:{device}"
        self.descriptor = dict(fit_id=self.fit_id, weights_sha256=networks.weights_sha256, bundle_sha256=networks.bundle_sha256, scaler_sha256=normalizer.digest, kind="FAMILY-E3",
                               arm=networks.arm, contract=dict(device=device, width_s=dev.SPECS[device].width_s, feature_contract=networks.contract), shared_with=list(networks.devices),
                               members=[m["fit_id"] for m in networks.members], parameters=networks.parameters, zero_variance_features=list(normalizer.zero_variance), n_fit=normalizer.n_fit,
                               input_mask=[FEATURES[i] for i in self.mask_idx])

    def loss_for_vector(self, vector):
        try:
            z = self.normalizer.transform(vector)
        except ValueError as exc:
            raise ValueError(f"SCHEMA_MISMATCH {exc}") from exc
        return float(self.networks.losses_z([z], self.mask_idx)[0])

    def losses(self, vectors):
        if not len(vectors):
            return []
        return [float(v) for v in self.networks.losses_z(self.normalizer.transform_many(vectors), self.mask_idx)]

    def independent_loss(self, vector):
        """The same loss with the standard library only: normaliser and forward pass share no numerical code with the torch path."""
        return self.networks.independent_loss_z(self.normalizer.independent_transform(vector), self.mask_idx)


def file_sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
