"""Gate 5D.2b bounded convergence comparison (secondary, post-hoc, validation-informed amendment).

Specified by docs/gate5d/GATE_5D2B_CONVERGENCE_AMENDMENT.md, whose SHA-256 is pinned below. The training pipeline
of the original Gate 5D.2 campaign is reused unchanged; the only difference is TrainConfig.max_epochs = 1000.

Usage (project-local venv, from the repository root):
    .venv\\Scripts\\python.exe -B model\\gate5d_convergence.py train      # the 12 authorized secondary fits
    .venv\\Scripts\\python.exe -B model\\gate5d_convergence.py compare    # fair comparison with the 500-epoch baseline

Deliberately no hyperparameter, seed, run-id or partition options. Only B_val losses decide anything.
"""
import argparse
import hashlib
import json
import platform
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import numpy as np  # noqa: E402
import torch  # noqa: E402

from model import autoencoder as ae  # noqa: E402
from model import gate5d_train as driver  # noqa: E402
from preprocessing import gate5d_data as data  # noqa: E402

PROTOCOL_REL = "docs/gate5d/GATE_5D2B_CONVERGENCE_AMENDMENT.md"
PROTOCOL_SHA256 = "289373071c9dac01c70f5286e7a4fe64264d10c99a9e8b4b2ff68aec956561e8"
BASELINE_RUN_ID = "g5d2-20261019-01"
BASELINE_FILE_PINS = {
    "run_started.json": "3c16de142f40a176d4f544726de2fc18c3c26906ffcd7dd8f02e47b671cd9b07",
    "run_manifest.json": "89e5ef3cb40a06d8aa8b338274b61e39dc9c3a5858a34fa19b8ff657262f2bc5",
    "selection_record.json": "a27c5ecae60a27117c35e9fcc13eeb417bbf48dbd05d178a2b5bb5e1508cf8d0",
    "verification.json": "04081e569d3f9e7ba4e67011c78502ecf9b2337eabf782d3781bcfa471503920",
    "summary.txt": "672b2a38d4db42292b0d53c70cb0807d432e0e7471eb0599d1335702cf57edd6",
}
SECONDARY_RUN_ID = "g5d2b-20261019-01"
COMPARE_RUN_ID = "g5d2b-compare-20261019-01"
CONFIG = ae.TrainConfig(max_epochs=1000)  # the single frozen change; every other value is the baseline default
EXPECTED_VERSIONS = dict(python="3.12.10", numpy="2.1.3", torch="2.5.1+cpu")
SNAPSHOT_EPOCHS = (1, 10, 50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000)
SELF = "model/gate5d_convergence.py"


class ConvergenceStop(RuntimeError):
    """A pre-condition or integrity check failed: stop and report, never repair."""


def file_sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def runs_dir(root):
    return Path(root) / "results" / "gate5d"


def verify_protocol(root):
    actual = file_sha256(Path(root) / PROTOCOL_REL)
    if actual != PROTOCOL_SHA256:
        raise ConvergenceStop(f"protocol SHA-256 {actual} differs from the frozen pin")
    return actual


def verify_run_artifacts(run_dir):
    manifest = json.loads((Path(run_dir) / "run_manifest.json").read_text(encoding="utf-8"))
    bad = [rel for rel, digest in manifest["artifact_sha256"].items() if file_sha256(Path(run_dir) / rel) != digest]
    statuses = {fid: f["status"] for fid, f in manifest["fits"].items()}
    return dict(artifacts=len(manifest["artifact_sha256"]), mismatches=bad, fits=len(statuses),
                all_completed=all(s == "COMPLETED" for s in statuses.values()))


def verify_baseline(root):
    run_dir = runs_dir(root) / BASELINE_RUN_ID
    for name, digest in BASELINE_FILE_PINS.items():
        if file_sha256(run_dir / name) != digest:
            raise ConvergenceStop(f"baseline file {name} differs from its recorded hash")
    result = verify_run_artifacts(run_dir)
    if result["mismatches"] or result["artifacts"] != 26 or result["fits"] != 12 or not result["all_completed"]:
        raise ConvergenceStop(f"baseline integrity check failed: {result}")
    return result


def baseline_context(root):
    return json.loads((runs_dir(root) / BASELINE_RUN_ID / "run_started.json").read_text(encoding="utf-8"))


def verify_environment(root):
    base = baseline_context(root)
    versions = dict(python=platform.python_version(), numpy=np.__version__, torch=torch.__version__)
    if versions != EXPECTED_VERSIONS:
        raise ConvergenceStop(f"environment versions {versions} differ from the pinned {EXPECTED_VERSIONS}")
    record = driver.environment_record()
    if record["distributions"] != base["context"]["environment"]["distributions"]:
        raise ConvergenceStop("installed distributions differ from the baseline environment")
    if record["lock_file_sha256"] != base["context"]["environment"]["lock_file_sha256"]:
        raise ConvergenceStop("lock file differs from the baseline environment")
    expected = {k: v for k, v in json.loads(json.dumps(vars(ae.TrainConfig()))).items() if k != "max_epochs"}
    got = {k: v for k, v in json.loads(json.dumps(vars(CONFIG))).items() if k != "max_epochs"}
    recorded = {k: v for k, v in base["hyperparameters"].items() if k != "max_epochs"}
    if not (expected == got == recorded) or CONFIG.max_epochs != 1000 or base["hyperparameters"]["max_epochs"] != 500:
        raise ConvergenceStop("hyperparameters differ from the baseline in more than max_epochs")
    return versions


def train(root):
    root = Path(root)
    protocol = verify_protocol(root)
    baseline = verify_baseline(root)
    versions = verify_environment(root)
    ae.configure_determinism()
    campaign, reader, train_rec, val_rec, summary, profiles = driver.load_profile_data(root, root / "results" / "raw")
    base = baseline_context(root)["context"]
    same_membership = {p: [dict(run=r.run, plan=r.plan_letter, session=r.session_id) for r in campaign.accepted[p]]
                       for p in data.TRAINING_PARTITIONS} == base["campaign"]["membership"]
    same_scalers = all(profiles[p].describe()["scaler"] == base["profile_data"][p]["scaler"] for p in ae.PROFILES)
    if summary != base["accounting_summary"] or not same_membership or not same_scalers:
        raise ConvergenceStop("accepted data membership, populations or fitted scalers differ from the baseline")
    code_files = driver.CODE_FILES + (SELF,)
    context = dict(
        amendment=dict(id="GATE_5D2B", nature="secondary post-hoc validation-informed convergence comparison",
                       protocol_path=PROTOCOL_REL, protocol_sha256=protocol, baseline_run_id=BASELINE_RUN_ID,
                       baseline_file_pins=BASELINE_FILE_PINS, baseline_verification=baseline,
                       max_epochs=CONFIG.max_epochs, verified_versions=versions,
                       data_identical_to_baseline=True),
        git_head=driver.git("rev-parse", "HEAD"), git_status_porcelain=driver.git("status", "--porcelain=v1", "-uall"),
        code_sha256={f: file_sha256(root / f) for f in code_files},
        environment=driver.environment_record(), pins=data.PIN, schema_pins=driver.schema_pins(),
        campaign=base["campaign"], accounting_summary=summary, accounting=data.account(train_rec + val_rec),
        profile_data={p: pd.describe() for p, pd in profiles.items()},
        evidence_files_read=reader.reads, evidence_refusals=reader.refusals,
        reserved_or_unaccepted_evidence_files_opened=sum(
            1 for r in reader.reads if any(token in r["path"] for token in campaign.reserved_tokens)))
    manifest = driver.run_campaign(profiles, runs_dir(root) / SECONDARY_RUN_ID, context, CONFIG)
    print(f"run {manifest['run_id']} complete; summary in results/gate5d/{manifest['run_id']}/summary.txt")
    return manifest


def fit_info(bundle, manifest_hashes, fit_id):
    cap = bundle["hyperparameters"]["max_epochs"]
    base = dict(status=bundle["status"], cap=cap)
    if bundle["status"] != "COMPLETED":
        return dict(base, failure_reason=bundle.get("failure_reason"))
    history = bundle["history"]
    curves = {str(e): [history[e - 1]["train_loss"], history[e - 1]["val_loss"]]
              for e in SNAPSHOT_EPOCHS if e <= len(history)}
    return dict(base, epochs_run=bundle["epochs_run"], best_epoch=bundle["best_epoch"], stop_reason=bundle["stop_reason"],
                train_loss_at_best=bundle["training"]["train_loss_at_best"],
                best_val_loss=bundle["validation"]["best_val_loss"], val_sd_sample=bundle["validation"]["sd_sample"],
                cap_limited=bundle["stop_reason"] == "epoch_cap_reached",
                best_at_cap=bundle["best_epoch"] == cap, best_in_last_20=bundle["best_epoch"] > cap - 20,
                weights_sha256=manifest_hashes[f"fits/{fit_id}/weights.json"], curves=curves)


def decide(baseline_selection, secondary_selection):
    """Section 5 of the protocol: the secondary wins only on a strictly lower selected-architecture mean B_val loss."""
    if baseline_selection.get("selected_k") is None or secondary_selection.get("selected_k") is None:
        return dict(outcome="NOT_COMPARABLE_STOP_AND_REPORT", winner=None)
    metric_500 = baseline_selection["candidates"][f"k{baseline_selection['selected_k']}"]["metric"]
    metric_1000 = secondary_selection["candidates"][f"k{secondary_selection['selected_k']}"]["metric"]
    winner = "secondary_1000" if metric_1000 < metric_500 else "baseline_500"  # exact tie keeps the baseline
    return dict(outcome="DECIDED", winner=winner, metric_500=metric_500, metric_1000=metric_1000,
                difference_1000_minus_500=metric_1000 - metric_500, tie=metric_1000 == metric_500)


def seed_disclosure(selection, profile):
    k = selection["selected_k"]
    candidate = selection["candidates"][f"k{k}"]
    losses = candidate["seed_best_val_losses"]
    seed0 = losses[f"A-{profile}-k{k}-seed0"]
    best_id = min(losses, key=losses.get)
    return dict(selected_k=k, seed0_loss=seed0, selection_mean=candidate["metric"],
                seed0_minus_mean=seed0 - candidate["metric"], lowest_seed_fit=best_id, lowest_seed_loss=losses[best_id])


def compare_runs(base_dir, sec_dir):
    base_dir, sec_dir = Path(base_dir), Path(sec_dir)
    manifests = {k: json.loads((d / "run_manifest.json").read_text(encoding="utf-8")) for k, d in
                 (("baseline", base_dir), ("secondary", sec_dir))}
    selections = {k: json.loads((d / "selection_record.json").read_text(encoding="utf-8")) for k, d in
                  (("baseline", base_dir), ("secondary", sec_dir))}
    bundles, fits = {}, {}
    for fid in sorted(manifests["baseline"]["fits"]):
        pair = {}
        for key, d in (("baseline", base_dir), ("secondary", sec_dir)):
            pair[key] = json.loads((d / "fits" / fid / "bundle.json").read_text(encoding="utf-8"))
        bundles[fid] = pair
        b, s = pair["baseline"], pair["secondary"]
        record = dict(baseline=fit_info(b, manifests["baseline"]["artifact_sha256"], fid),
                      secondary=fit_info(s, manifests["secondary"]["artifact_sha256"], fid))
        if b["status"] == "COMPLETED" and s["status"] == "COMPLETED":
            n = len(b["history"])
            record["prefix_identical"] = s["epochs_run"] >= n and s["history"][:n] == b["history"]
            record["baseline_stopped_early"] = b["stop_reason"] == "early_stopping"
            record["identical_in_full"] = (s["epochs_run"], s["best_epoch"], s["weights_sha256"], s["validation"]["best_val_loss"]) \
                == (b["epochs_run"], b["best_epoch"], b["weights_sha256"], b["validation"]["best_val_loss"])
            record["continued_beyond_baseline_cap"] = s["epochs_run"] > b["epochs_run"]
        fits[fid] = record
    expectations = dict(
        prefix_identical_all=all(r.get("prefix_identical") is True for r in fits.values()),
        early_stopped_baseline_fits_identical_in_full=all(
            r["identical_in_full"] for r in fits.values() if r.get("baseline_stopped_early")),
        capped_baseline_fits_continued=all(
            r["continued_beyond_baseline_cap"] for r in fits.values() if r.get("baseline_stopped_early") is False))
    profiles = {}
    for p in ae.PROFILES:
        decision = decide(selections["baseline"][p], selections["secondary"][p])
        entry = dict(baseline_selection=dict(k=selections["baseline"][p]["selected_k"],
                                             primary=selections["baseline"][p]["primary_fit_id"],
                                             k_metrics={k: c["metric"] for k, c in selections["baseline"][p]["candidates"].items()}),
                     secondary_selection=dict(k=selections["secondary"][p]["selected_k"],
                                              primary=selections["secondary"][p]["primary_fit_id"],
                                              k_metrics={k: c["metric"] for k, c in selections["secondary"][p]["candidates"].items()}),
                     decision=decision)
        if decision["outcome"] == "DECIDED":
            key = "secondary" if decision["winner"] == "secondary_1000" else "baseline"
            directory = sec_dir if key == "secondary" else base_dir
            fid = selections[key][p]["primary_fit_id"]
            bundle = bundles[fid][key]
            entry["disclosure"] = dict(baseline=seed_disclosure(selections["baseline"][p], p),
                                       secondary=seed_disclosure(selections["secondary"][p], p))
            entry["recommended_primary"] = dict(
                campaign=decision["winner"], run_id=directory.name, fit_id=fid, k=bundle["k"],
                weights_sha256=manifests[key]["artifact_sha256"][f"fits/{fid}/weights.json"],
                bundle_sha256=manifests[key]["artifact_sha256"][f"fits/{fid}/bundle.json"],
                epochs_run=bundle["epochs_run"], best_epoch=bundle["best_epoch"], stop_reason=bundle["stop_reason"],
                b_val_mean_loss=bundle["validation"]["best_val_loss"], b_val_sd_sample=bundle["validation"]["sd_sample"],
                per_device=bundle["validation"]["per_device"], per_run=bundle["validation"]["per_run"],
                cap_limited=fits[fid][key]["cap_limited"], best_at_cap=fits[fid][key]["best_at_cap"],
                best_in_last_20=fits[fid][key]["best_in_last_20"])
        profiles[p] = entry
    return dict(protocol_sha256=PROTOCOL_SHA256, baseline_run=base_dir.name, secondary_run=sec_dir.name,
                use="model development on B_val; not independent final evaluation; no detection claim",
                pre_registered_expectations=expectations, fits=fits, profiles=profiles,
                secondary_cap_status=dict(
                    fits_cap_limited=sorted(f for f, r in fits.items() if r["secondary"].get("cap_limited")),
                    fits_best_at_cap=sorted(f for f, r in fits.items() if r["secondary"].get("best_at_cap")),
                    fits_best_in_last_20=sorted(f for f, r in fits.items() if r["secondary"].get("best_in_last_20"))))


def summary_text(result):
    lines = ["Gate 5D.2b convergence comparison (500-epoch baseline vs 1,000-epoch secondary)",
             "Model development on B_val; not independent final evaluation; no detection claim.",
             f"Pre-registered expectations: {json.dumps(result['pre_registered_expectations'])}", ""]
    for fid, r in result["fits"].items():
        row = []
        for key in ("baseline", "secondary"):
            i = r[key]
            row.append(f"{key[:3]} {i['status']}" if i["status"] != "COMPLETED" else
                       f"{key[:3]} ep={i['epochs_run']} best={i['best_epoch']} {i['stop_reason']} val={i['best_val_loss']:.6g}"
                       + (" CAP-LIMITED" if i["cap_limited"] and key == "secondary" else ""))
        lines.append(f"{fid}: " + " | ".join(row) + f" | prefix_identical={r.get('prefix_identical')}")
    for p, e in result["profiles"].items():
        lines += ["", f"Profile {p}: {json.dumps(e['decision'])}"]
        if "recommended_primary" in e:
            rp = e["recommended_primary"]
            lines.append(f"  recommended primary {rp['fit_id']} ({rp['campaign']}) weights {rp['weights_sha256']}")
    return "\n".join(lines) + "\n"


def compare(root):
    root = Path(root)
    verify_protocol(root)
    verify_baseline(root)
    secondary_dir = runs_dir(root) / SECONDARY_RUN_ID
    check = verify_run_artifacts(secondary_dir)
    if check["mismatches"] or check["artifacts"] != 26 or check["fits"] != 12:
        raise ConvergenceStop(f"secondary run integrity check failed: {check}")
    started = json.loads((secondary_dir / "run_started.json").read_text(encoding="utf-8"))
    if started["context"]["amendment"]["protocol_sha256"] != PROTOCOL_SHA256 or started["hyperparameters"]["max_epochs"] != 1000:
        raise ConvergenceStop("secondary run was not executed under the frozen protocol")
    result = compare_runs(runs_dir(root) / BASELINE_RUN_ID, secondary_dir)
    out = runs_dir(root) / COMPARE_RUN_ID
    out.mkdir(parents=True, exist_ok=False)
    blob = (ae.dumps(result) + "\n").encode("utf-8")
    (out / "comparison.json").write_bytes(blob)
    text = summary_text(result)
    (out / "summary.txt").write_text(text, encoding="utf-8")
    print(text)
    print("comparison.json sha256", hashlib.sha256(blob).hexdigest(),
          "| summary.txt sha256", hashlib.sha256(text.encode("utf-8")).hexdigest())
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("train", "compare"))
    parser.add_argument("--repo-root", default=str(ROOT))
    args = parser.parse_args(argv)
    try:
        {"train": train, "compare": compare}[args.command](args.repo_root)
    except ConvergenceStop as exc:
        print(f"CONVERGENCE_STOP {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
