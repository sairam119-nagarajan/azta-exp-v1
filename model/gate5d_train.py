"""Gate 5D.2 campaign driver: 12 preregistered candidate fits, per-profile selection, verification, provenance.

Usage (project-local venv, from the repository root):
    .venv\\Scripts\\python.exe -B model\\gate5d_train.py --run-id <id>          # the one authorized campaign
    .venv\\Scripts\\python.exe -B model\\gate5d_train.py --dry-run               # loads data and fits scalers only

There is deliberately no hyperparameter, seed or partition option. Reads only accepted B_train/B_val evidence.
Calibration, B_cal, trust, thresholds, enforcement and Docker are out of scope.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import numpy as np  # noqa: E402
import torch  # noqa: E402

from model import autoencoder as ae  # noqa: E402
from model import stdlib_check  # noqa: E402
from model.inference import ProfileModel  # noqa: E402
from observation.schema import MEASURES  # noqa: E402
from preprocessing import gate5d_data as data  # noqa: E402
from preprocessing.scaler import ZScoreScaler  # noqa: E402

# Verified populations (freeze document section 3). A mismatch means the evidence or code changed: stop.
EXPECTED_ACCOUNTING = {
    "B_train|S|DESIGN_EXCLUDED": 20, "B_train|S|SCORE_READY": 600,
    "B_train|V|DESIGN_EXCLUDED": 20, "B_train|V|SCORE_READY": 600,
    "B_val|S|DESIGN_EXCLUDED": 12, "B_val|S|SCORE_READY": 360,
    "B_val|V|DESIGN_EXCLUDED": 12, "B_val|V|SCORE_READY": 360,
}
CODE_FILES = ("preprocessing/gate5d_data.py", "preprocessing/scaler.py", "model/autoencoder.py",
              "model/inference.py", "model/stdlib_check.py", "model/gate5d_train.py")


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def peak_working_set_bytes():
    try:
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes

            class Counters(ctypes.Structure):
                _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + \
                           [(n, ctypes.c_size_t) for n in ("PeakWorkingSetSize", "WorkingSetSize",
                                                           "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage",
                                                           "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage",
                                                           "PagefileUsage", "PeakPagefileUsage")]
            kernel32, psapi = ctypes.WinDLL("kernel32"), ctypes.WinDLL("psapi")
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
            counters = Counters()
            counters.cb = ctypes.sizeof(Counters)
            if psapi.GetProcessMemoryInfo(kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
                return int(counters.PeakWorkingSetSize)
            return None
        import resource
        return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024
    except Exception:  # best effort; recorded as null when unavailable
        return None


class ProfileData:
    """One profile's transformed B_train/B_val matrices, built from SCORE_READY records only."""

    def __init__(self, profile, train_records, val_records):
        ready = lambda rows: [r for r in rows if r.profile == profile and r.category == data.SCORE_READY]
        self.profile = profile
        self.train, self.val = ready(train_records), ready(val_records)
        self.scaler = ZScoreScaler.fit(profile, [r.vector for r in self.train])  # B_train only
        self.train_z = self.scaler.transform_many([r.vector for r in self.train])
        self.val_vectors = [r.vector for r in self.val]
        self.val_z = self.scaler.transform_many(self.val_vectors)  # B_train scaler, never refitted
        self.val_devices = [r.device for r in self.val]
        self.val_runs = [r.run for r in self.val]

    def describe(self):
        count = lambda rows, key: {k: sum(1 for r in rows if key(r) == k) for k in sorted({key(r) for r in rows})}
        return dict(n_train=len(self.train), n_val=len(self.val), scaler=self.scaler.to_dict(),
                    train_runs=count(self.train, lambda r: r.run), val_runs=count(self.val, lambda r: r.run),
                    train_devices=count(self.train, lambda r: r.device), val_devices=count(self.val, lambda r: r.device),
                    val_order=[[r.run, r.device, r.index] for r in self.val])


def load_profile_data(repo_root, results_root):
    """Verified campaign, guarded evidence reads, expected-population guard and per-profile data."""
    campaign = data.load_campaign(repo_root)
    reader = data.EvidenceReader(results_root, campaign)
    try:  # exercise the live guard: B_cal must be refused without opening any file
        data.load_partition(campaign, reader, data.RESERVED_PARTITION)
        raise data.DataContractError("B_cal partition was NOT refused")
    except data.PartitionRefused:
        pass
    train = data.load_partition(campaign, reader, "B_train")
    val = data.load_partition(campaign, reader, "B_val")
    summary = data.summarize_accounting(train + val)
    if summary != EXPECTED_ACCOUNTING:
        raise data.DataContractError(f"accounting differs from the verified populations: {summary}")
    profiles = {p: ProfileData(p, train, val) for p in ae.PROFILES}
    return campaign, reader, train, val, summary, profiles


def git(*args):
    try:
        return subprocess.run(("git", *args), cwd=ROOT, capture_output=True, text=True, check=False).stdout.strip()
    except OSError:
        return None


def environment_record():
    lock = ROOT / "requirements-gate5d.lock.txt"
    return dict(
        python=sys.version, executable=sys.executable, platform=platform.platform(), machine=platform.machine(),
        processor=platform.processor(), cpu_count=os.cpu_count(), numpy=np.__version__, torch=torch.__version__,
        torch_num_threads=torch.get_num_threads(), default_dtype=str(torch.get_default_dtype()),
        deterministic_algorithms=torch.are_deterministic_algorithms_enabled(),
        distributions=sorted(f"{d.metadata['Name']}=={d.version}" for d in importlib.metadata.distributions()),
        lock_file_sha256=hashlib.sha256(lock.read_bytes()).hexdigest() if lock.exists() else None)


def write_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    blob = (ae.dumps(obj) + "\n").encode("utf-8")
    path.write_bytes(blob)
    return hashlib.sha256(blob).hexdigest()


def schema_pins():
    return dict(schema_fingerprint=data.PIN["schema_fingerprint"],
                observation_config_sha256=data.PIN["observation_config_sha256"],
                registry_sha256=data.PIN["registry_sha256"], feature_order=list(data.FEATURES),
                units={m["name"]: m["unit"] for m in MEASURES})


def run_campaign(profiles, out_dir, context, config=ae.TrainConfig()):
    """Run all 12 preregistered fits in fixed order, retain every result, select per profile, verify."""
    ae.configure_determinism()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=False)  # never overwrite prior evidence
    started, t0 = utc_now(), time.perf_counter()
    plan = [(p, k, s) for p in ae.PROFILES for k in ae.KS for s in ae.SEED_INDICES]
    write_json(out / "run_started.json", dict(started_utc=started, planned_fits=[f"A-{p}-k{k}-seed{s}" for p, k, s in plan],
                                              hyperparameters=vars(config), context=context))
    files, results, weights_by_id, halted = {}, {}, {}, False
    for profile, k, seed_index in plan:
        fit_id = f"A-{profile}-k{k}-seed{seed_index}"
        if halted:
            result = dict(fit_id=fit_id, profile=profile, k=k, seed_index=seed_index,
                          seed=ae.preregistered_seed(profile, seed_index), status="NOT_RUN",
                          failure_reason="CAMPAIGN_HALTED_BY_ZERO_WEIGHT_VIOLATION", halt_campaign=False)
            weights = None
        else:
            pd = profiles[profile]
            result, weights = ae.train_fit(profile=profile, k=k, seed_index=seed_index, train_z=pd.train_z,
                                           val_z=pd.val_z, val_devices=pd.val_devices, val_runs=pd.val_runs,
                                           zero_idx=pd.scaler.zero_variance_indices, config=config)
            halted = result["halt_campaign"]
        fit_dir = out / "fits" / fit_id
        bundle = dict(result, schema_pins=schema_pins(), scaler=profiles[profile].scaler.to_dict(),
                      hyperparameters=vars(config), weights_file=None, weights_sha256=None,
                      peak_working_set_bytes_at_end=peak_working_set_bytes())
        if weights is not None:
            bundle["weights_sha256"] = write_json(fit_dir / "weights.json", weights)
            bundle["weights_file"] = "weights.json"
            files[f"fits/{fit_id}/weights.json"] = bundle["weights_sha256"]
            weights_by_id[fit_id] = weights
        files[f"fits/{fit_id}/bundle.json"] = write_json(fit_dir / "bundle.json", bundle)
        results[fit_id] = bundle

    selection = {p: ae.select_primary([r for r in results.values() if r["profile"] == p]) for p in ae.PROFILES}
    files["selection_record.json"] = write_json(out / "selection_record.json", selection)

    verification = dict(reproducibility={}, stdlib_recomputation={}, load_check={})
    for profile in ae.PROFILES:
        primary = selection[profile]["primary_fit_id"]
        if primary is None:
            continue
        pd, first = profiles[profile], results[primary]
        rerun, rerun_weights = ae.train_fit(profile=profile, k=first["k"], seed_index=0, train_z=pd.train_z,
                                            val_z=pd.val_z, val_devices=pd.val_devices, val_runs=pd.val_runs,
                                            zero_idx=pd.scaler.zero_variance_indices, config=config)
        verification["reproducibility"][primary] = dict(
            rerun_status=rerun["status"],
            identical_weights=json.dumps(rerun_weights, sort_keys=True) == json.dumps(weights_by_id[primary], sort_keys=True),
            identical_history=rerun["history"] == first["history"],
            identical_best_val_loss=rerun["validation"]["best_val_loss"] == first["validation"]["best_val_loss"])
        loaded = ProfileModel.load(out / "fits" / primary)
        vector = pd.val_vectors[0]
        independent = stdlib_check.loss(weights_by_id[primary], pd.scaler.mu, pd.scaler.s, vector)
        via_model = loaded.loss_for_vector(vector)
        stored = first["validation"]["window_losses"][0]
        verification["stdlib_recomputation"][primary] = dict(
            vector=list(vector), stdlib_loss=independent, torch_loss=via_model, stored_val_loss=stored,
            max_relative_difference=max(abs(independent - via_model), abs(independent - stored)) / max(abs(independent), 1e-300))
        verification["load_check"][primary] = dict(loaded_profile=loaded.profile, zero_weights_exact=True)
    files["verification.json"] = write_json(out / "verification.json", verification)

    ended = utc_now()
    manifest = dict(run_id=out.name, started_utc=started, ended_utc=ended, wall_seconds=time.perf_counter() - t0,
                    peak_working_set_bytes=peak_working_set_bytes(), hyperparameters=vars(config), context=context,
                    fits={fid: dict(status=r["status"], failure_reason=r["failure_reason"], seed=r["seed"],
                                    best_epoch=r.get("best_epoch"), epochs_run=r.get("epochs_run"),
                                    stop_reason=r.get("stop_reason"),
                                    best_val_loss=(r.get("validation") or {}).get("best_val_loss"))
                          for fid, r in results.items()},
                    selection=selection, verification=verification, artifact_sha256=files)
    write_json(out / "run_manifest.json", manifest)
    (out / "summary.txt").write_text(summary_text(results, selection, verification), encoding="utf-8")
    return manifest


def summary_text(results, selection, verification):
    lines = ["Gate 5D.2 reconstruction-loss summary (benign B_val; not detection performance)"]
    for profile in ae.PROFILES:
        lines.append(f"\nProfile {profile}")
        for fid, r in sorted(results.items()):
            if r["profile"] != profile:
                continue
            if r["status"] != "COMPLETED":
                lines.append(f"  {fid}: {r['status']} {r['failure_reason']}")
                continue
            v = r["validation"]
            lines.append(f"  {fid}: epochs={r['epochs_run']} best={r['best_epoch']} stop={r['stop_reason']} "
                         f"train={r['training']['train_loss_at_best']:.6g} val_mean={v['best_val_loss']:.6g} "
                         f"val_sd={v['sd_sample']:.6g} "
                         + " ".join(f"{d}={s['mean']:.6g}" for d, s in v["per_device"].items()))
        lines.append(f"  selection: {selection[profile]['outcome']} k={selection[profile].get('selected_k')} "
                     f"primary={selection[profile].get('primary_fit_id')}")
    lines.append("\nVerification: " + json.dumps(verification, sort_keys=True)[:4000])
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", default=str(ROOT))
    parser.add_argument("--run-id")
    parser.add_argument("--dry-run", action="store_true", help="load data and fit scalers only; train nothing")
    args = parser.parse_args(argv)
    root = Path(args.repo_root)
    campaign, reader, train, val, summary, profiles = load_profile_data(root, root / "results" / "raw")
    if args.dry_run:
        print(ae.dumps(dict(accounting=summary, evidence_reads=len(reader.reads), refusals=reader.refusals,
                            profiles={p: {k: v for k, v in pd.describe().items() if k != "val_order"}
                                      for p, pd in profiles.items()})))
        return 0
    run_id = args.run_id or datetime.now(timezone.utc).strftime("g5d2-%Y%m%dT%H%M%SZ")
    ae.configure_determinism()  # before the environment is recorded, so the record shows the training settings
    context = dict(
        git_head=git("rev-parse", "HEAD"), git_status_porcelain=git("status", "--porcelain=v1", "-uall"),
        code_sha256={f: hashlib.sha256((ROOT / f).read_bytes()).hexdigest() for f in CODE_FILES},
        environment=environment_record(), pins=data.PIN, schema_pins=schema_pins(),
        campaign=dict(manifest_sha256=campaign.manifest_sha256, plan_sha256=campaign.plan_sha256,
                      routing_cross_checks=list(campaign.cross_checks), invalidated_excluded=list(campaign.invalidated),
                      membership={p: [dict(run=r.run, plan=r.plan_letter, session=r.session_id) for r in campaign.accepted[p]]
                                  for p in data.TRAINING_PARTITIONS},
                      reserved_partition=data.RESERVED_PARTITION,
                      reserved_run_ids=[r.run for r in campaign.accepted[data.RESERVED_PARTITION]]),
        accounting_summary=summary, accounting=data.account(train + val),
        profile_data={p: pd.describe() for p, pd in profiles.items()},
        evidence_files_read=reader.reads, evidence_refusals=reader.refusals,
        reserved_or_unaccepted_evidence_files_opened=sum(
            1 for r in reader.reads if any(token in r["path"] for token in campaign.reserved_tokens)))
    manifest = run_campaign(profiles, root / "results" / "gate5d" / run_id, context)
    print(f"run {manifest['run_id']} complete; summary in results/gate5d/{manifest['run_id']}/summary.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
