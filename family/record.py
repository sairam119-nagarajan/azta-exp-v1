"""The candidate record of protocol P1-FAM and its digest-verified loading.

`build_record` (used once, by `rehearsal_tools/p1_calibrate.py`) reads the trained arms of one model run, calibrates every (arm, device) pair on the calibration windows it is handed, and returns
the record; `load_models` rebuilds `FamilyDeviceModel` objects from it, verifying every weights and bundle digest against the record and the normaliser against its recorded digest. A device is
only ever paired with ITS OWN normaliser (the record stores one per device), so baselines cannot be confused; two devices of a family share ONE `FamilyNetworks` object per load.
"""
import json
from pathlib import Path

from fleet.models import sha256_bytes
from family import calibrate as cal, devices as dev
from family.model import FamilyDeviceModel, FamilyModelRefused, FamilyNetworks
from family.normalize import DeviceNormalizer
from hybrid.scaler import mask_vector

SCHEMA = "azta.gate6c.p1_candidates"


def _load_json(path):
    blob = Path(path).read_bytes()
    return json.loads(blob.decode("utf-8")), sha256_bytes(blob)


def arm_fits(arm_dir):
    """(selected k, [{fit_id, weights_sha256, bundle_sha256}] of the three seeds, normalisers {device: dict}) of a trained arm, read from its files."""
    selection, _ = _load_json(Path(arm_dir) / "selection_record.json")
    if selection.get("outcome") != "SELECTED":
        raise FamilyModelRefused(f"{arm_dir}: no architecture was selected ({selection.get('outcome')})")
    k, items, normalizers = selection["selected_k"], [], None
    for seed in (0, 1, 2):
        fit_dir = Path(arm_dir) / "fits" / f"A-{Path(arm_dir).name}-k{k}-seed{seed}"
        bundle, bundle_sha = _load_json(fit_dir / "bundle.json")
        if bundle["status"] != "COMPLETED":
            raise FamilyModelRefused(f"{fit_dir}: fit not completed")
        items.append(dict(fit_id=bundle["fit_id"], weights_sha256=bundle["weights_sha256"], bundle_sha256=bundle_sha))
        normalizers = normalizers or bundle["normalizers"]
        if bundle["normalizers"] != normalizers:
            raise FamilyModelRefused(f"{fit_dir}: the seeds of one arm disagree on the normalisers")
    return k, items, normalizers


def build_record(models_dir, arms, cal_vectors, *, calibration_id, models_run, extra_devices=None):
    """`arms`: the declared table (`family.arms.ARMS`); `cal_vectors`: {device: [vector, ...]} native ready calibration windows; `extra_devices`: {arm: [held-out device, ...]} (LODO).
    Returns the record. The normaliser of a held-out device is the one of its device-specific counterpart under the same contract (a function of the device's own TRAIN rows only)."""
    record = dict(schema=SCHEMA, schema_version=1, status="CANDIDATE_UNAPPROVED", calibration_id=calibration_id, models_run=models_run, arms={})
    cache = {}
    for name, arm in arms.items():
        network = arm.get("network", name)                  # Phase 2: a candidate may reuse the networks of another (already trained) arm, e.g. "C-PER+IM" scores with the networks of "C-PER"
        arm_dir = Path(arm.get("models_dir", models_dir)) / network
        k, items, normalizers = arm_fits(arm_dir)
        networks = FamilyNetworks.load(arm_dir, items, arm=network, contract=arm["contract"], devices=arm["members"])
        entry = dict(network=network, models_dir=arm.get("models_dir_rel"), contract=arm["contract"], members=list(arm["members"]), masked_features=list(arm["masked"]), input_mask=bool(arm.get("input_mask")), selected_k=k, fits=items, networks_weights_sha256=networks.weights_sha256,
                     networks_bundle_sha256=networks.bundle_sha256, parameters=networks.parameters, normalizers={}, calibration={}, member_calibration={}, held_out={})
        losses = {}
        masked = tuple(arm["masked"])
        scored = lambda device: [mask_vector(v, masked) for v in cal_vectors[device]]          # the arm is scored exactly as it was trained and as `AeStream` scores it
        for device in arm["members"]:
            n = DeviceNormalizer.from_dict(normalizers[device])
            entry["normalizers"][device] = n.digest
            losses[device] = FamilyDeviceModel(device, networks, n, input_mask=bool(arm.get("input_mask"))).losses(scored(device))
            entry["calibration"][device] = cal.statistics(losses[device])
            # the same single pass, member by member (seed-sensitivity studies need each seed's own constants; no window is read twice)
            per_member = networks.member_losses_z(n.transform_many(scored(device)), FamilyDeviceModel(device, networks, n, input_mask=bool(arm.get("input_mask"))).mask_idx)
            entry["member_calibration"].setdefault(device, {})
            for member, member_losses in zip(networks.members, per_member):
                entry["member_calibration"][device][member["fit_id"]] = cal.statistics(member_losses)
        entry["calibration_pooled"] = cal.pooled(losses)
        for device in (extra_devices or {}).get(name, ()):
            twin = f"IND-{'B' if arm['contract'] == 'FC-6.1N' else 'C'}-{device}"
            twin_dir = Path(models_dir) / twin
            _, _, twin_norms = cache.setdefault(twin, arm_fits(twin_dir))
            n = DeviceNormalizer.from_dict(twin_norms[device])
            held = FamilyDeviceModel(device, FamilyNetworks(name, arm["contract"], tuple(arm["members"]) + (device,), networks.members), n)
            entry["held_out"][device] = dict(normalizer_from=twin, normalizer_sha256=n.digest, calibration=cal.statistics(held.losses(scored(device))))
        record["arms"][name] = entry
    return record


def load_models(root, record, models_dir, arm, devices=None, *, input_mask=None):
    """{device: (FamilyDeviceModel, calibration dict)} of an arm. Every digest of the record is verified; the networks are one shared object across the devices."""
    entry = record["arms"][arm]
    network = entry.get("network", arm)
    arm_dir = (Path(root) / entry["models_dir"] if entry.get("models_dir") else Path(models_dir)) / network
    networks = FamilyNetworks.load(arm_dir, entry["fits"], arm=network, contract=entry["contract"], devices=entry["members"])
    if networks.weights_sha256 != entry["networks_weights_sha256"] or networks.bundle_sha256 != entry["networks_bundle_sha256"]:
        raise FamilyModelRefused(f"{arm}: the combined digests differ from the record")
    bundle = json.loads((arm_dir / "fits" / entry["fits"][0]["fit_id"] / "bundle.json").read_text(encoding="utf-8"))
    out = {}
    for device in (devices or entry["members"]):
        if device in entry["normalizers"]:
            n = DeviceNormalizer.from_dict(bundle["normalizers"][device])
            if n.digest != entry["normalizers"][device]:
                raise FamilyModelRefused(f"{arm}/{device}: the normaliser differs from its recorded digest")
            out[device] = (FamilyDeviceModel(device, networks, n, input_mask=bool(entry.get("input_mask")) if input_mask is None else input_mask), entry["calibration"][device])
        elif device in entry["held_out"]:
            held = entry["held_out"][device]
            twin_bundle = json.loads((Path(models_dir) / held["normalizer_from"] / "fits" / f"A-{held['normalizer_from']}-k{json.loads((Path(models_dir) / held['normalizer_from'] / 'selection_record.json').read_text(encoding='utf-8'))['selected_k']}-seed0" / "bundle.json").read_text(encoding="utf-8"))
            n = DeviceNormalizer.from_dict(twin_bundle["normalizers"][device])
            if n.digest != held["normalizer_sha256"]:
                raise FamilyModelRefused(f"{arm}/{device}: the held-out normaliser differs from its recorded digest")
            out[device] = (FamilyDeviceModel(device, FamilyNetworks(arm, entry["contract"], tuple(entry["members"]) + (device,), networks.members), n), held["calibration"])
        else:
            raise FamilyModelRefused(f"{arm}: {device} is neither a member nor a recorded held-out device")
    return out
