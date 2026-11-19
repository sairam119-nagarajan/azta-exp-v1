"""Training of one Phase 1 arm: the frozen Gate 5D loop on baseline-relative inputs, for ONE network shared by the member devices (or one device).

For every member device a `DeviceNormalizer` is fitted on that device's own TRAIN rows; the transformed rows of all members are pooled; the six preregistered fits (k in {2, 3} x seeds 0 to 2,
seeds derived from the arm name) are trained by `model.autoencoder.train_fit` UNCHANGED (loop, hyperparameters, early stopping on the pooled VAL rows, strict best-epoch restore) at one cap;
the selection is the frozen `select_primary` (lowest mean best-epoch VAL loss over the three seeds, exact tie to k = 2). No weight is held at zero (the zero-variance set differs between the
members of a family; D-ZV-2 acts at the normalisation step). Every fit, failed ones included, is retained under `<out>/<arm>/fits/<fit_id>/`. Nothing here calibrates, scores a window against
a threshold, or promotes a model.
"""
from pathlib import Path
import time

import numpy as np

from fleet.models import write_json
from family import devices as dev
from family.normalize import DeviceNormalizer, FEATURES
from hybrid import models as hm
from hybrid.scaler import mask_vector
from model import autoencoder as ae


class ArmRefused(ValueError):
    pass


def train_arm(arm, contract, members, train_rows, val_rows, out_dir, *, max_epochs=1000, masked=()):
    """`train_rows`: {device: [vector, ...]}; `val_rows`: {device: [(run, vector), ...]}. Returns the arm record (selection, normalisers, per-device VAL statistics of every fit)."""
    members = tuple(members)
    if not members or set(members) - set(dev.DEVICES) or set(train_rows) != set(members) or set(val_rows) != set(members):
        raise ArmRefused(f"{arm}: members, TRAIN rows and VAL rows must name the same declared devices")
    started = time.perf_counter()
    masked = tuple(masked)
    normalizers, train_parts, val_parts, val_devices, val_runs = {}, [], [], [], []
    for device in members:
        spec = dev.SPECS[device]
        vectors = [mask_vector(v, masked) for v in train_rows[device]]
        normalizers[device] = DeviceNormalizer.fit(device, contract, vectors, dev.TOLERANCES, required_zero=tuple(spec.required_zero) + masked, permitted_zero=spec.permitted_zero)
        train_parts.append(normalizers[device].transform_many(vectors))
        val_vectors = [mask_vector(v, masked) for _, v in val_rows[device]]
        val_parts.append(normalizers[device].transform_many(val_vectors))
        val_devices += [device] * len(val_vectors)
        val_runs += [run for run, _ in val_rows[device]]
    train_z, val_z = np.vstack(train_parts), np.vstack(val_parts)
    ae.configure_determinism()
    out = Path(out_dir) / arm
    out.mkdir(parents=True, exist_ok=False)
    results, config = {}, ae.TrainConfig(max_epochs=max_epochs)
    with hm.extended_profile(arm):
        for k in ae.KS:
            for seed_index in ae.SEED_INDICES:
                result, weights = ae.train_fit(profile=arm, k=k, seed_index=seed_index, train_z=train_z, val_z=val_z, val_devices=val_devices, val_runs=val_runs, zero_idx=(), config=config)
                fit_dir = out / "fits" / result["fit_id"]
                fit_dir.mkdir(parents=True, exist_ok=False)
                bundle = dict(result, arm=arm, contract=contract, members=list(members), masked_features=list(masked), normalizers={d: n.to_dict() for d, n in normalizers.items()},
                              hyperparameters=vars(config), weights_file=None, weights_sha256=None, schema_pins=dict(feature_order=list(FEATURES)))
                if weights is not None:
                    bundle["weights_sha256"] = write_json(fit_dir / "weights.json", weights)
                    bundle["weights_file"] = "weights.json"
                write_json(fit_dir / "bundle.json", bundle)
                results[result["fit_id"]] = bundle
        selection = ae.select_primary(list(results.values()))
    write_json(out / "selection_record.json", selection)
    summary = dict(arm=arm, contract=contract, members=list(members), masked_features=list(masked), n_train={d: len(train_rows[d]) for d in members}, n_val={d: len(val_rows[d]) for d in members},
                   selection=selection, normalizer_digests={d: n.digest for d, n in normalizers.items()}, cap=max_epochs, wall_seconds=time.perf_counter() - started,
                   fits={f: dict(status=r["status"], k=r["k"], seed_index=r["seed_index"], best_epoch=r.get("best_epoch"), epochs_run=r.get("epochs_run"), stop_reason=r.get("stop_reason"),
                                 best_val_loss=r["validation"]["best_val_loss"] if r["status"] == "COMPLETED" else None, per_device_val=r["validation"]["per_device"] if r["status"] == "COMPLETED" else None,
                                 weights_sha256=r["weights_sha256"], failure=r.get("failure_reason"), parameters=r["parameters"]) for f, r in sorted(results.items())})
    write_json(out / "arm_summary.json", summary)
    return summary
