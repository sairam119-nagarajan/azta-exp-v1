"""Gate 5E benign calibration of the two frozen profile autoencoders (journal equations 8-10 only).

Computes, per profile, the number of score-ready reserved-calibration (B_cal) windows, the mean mu_L and the SAMPLE standard
deviation sigma_L (denominator n-1) of the per-window reconstruction loss of the frozen candidate model, together with
descriptive diagnostics. It selects NO epsilon, lambda, anomaly multiplier, trust weight or threshold and computes no
A or S_B. It fits nothing: models and train-fitted scalers are loaded and verified, never changed.

Access boundary. Exactly one kind of reserved evidence is ever opened: the `observer_windows` artifact of each accepted B_cal run
of the frozen Gate 5C manifest (eight files), digest-verified against the manifest before parsing and logged. Every other path
is refused. An interpreter audit hook independently logs every file open under the results tree, and the run fails if that log
differs from the allowlist. The mode `dry-run` opens no evidence at all. B_cal is single-use: a marker is created exclusively
before the first read, so a second calibration attempt is refused.

Importing this module has no side effect (the audit hook is installed only by a real run).
"""
import argparse
from collections import Counter
from decimal import Decimal, getcontext
from fractions import Fraction
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from model import autoencoder as ae  # noqa: E402
from model import stdlib_check  # noqa: E402
from model.inference import ProfileModel  # noqa: E402
from observation.schema import MEASURES  # noqa: E402
from preprocessing import gate5d_data as data  # noqa: E402

PROTOCOL_ID = "gate5e-calibration-protocol-v1"
PROTOCOL_REL = "docs/gate5e/GATE_5E_CALIBRATION_PROTOCOL.md"
FREEZE_REL = "configs/gate5e/calibration_freeze.json"
OUTPUT_ROOT_REL = "results/gate5e"
ISSUED_MARKER = "CALIBRATION_ISSUED.json"
RAW_REL = "results/raw"
CANDIDATE_RUN = "g5d2b-20261019-01"
CANDIDATES = {
    "S": dict(fit_id="A-S-k3-seed0", weights_sha256="1ff19602dcb2c5ff1c93b8e5ec054df44207fa20fed4ec2be84684b4f1dd534a",
              bundle_sha256="2e2b29a734400581879a2103ff365105c64646cb528ef790002aae7c8514ab69", k=3, seed=3411798344),
    "V": dict(fit_id="A-V-k3-seed0", weights_sha256="d5b0cfedc1144b48e1594ac39e3f8abbc965d89360a6d12019769900f4714aaa",
              bundle_sha256="163d20da485a1027e0188a527aaf94503e67503e99f8c26a9ab9153de0f630a9", k=3, seed=1195763328),
}
EXPECTED_BCAL_RUNS = ("g5c-r01", "g5c-r07", "g5c-r10", "g5c-r11", "g5c-r13", "g5c-r14", "g5c-r19", "g5c-r22")
EXPECTED_PLANNED_ELIGIBLE = {"S": 480, "V": 480}  # planned counts, NOT guaranteed score-ready support
EXPECTED_ELIGIBLE_RANGE = (1, 60)
EXPECTED_RECORDS_PER_DEVICE = 62  # window 0 lead-in, 1-60 eligible, 61 lead-out
READ_ROLE = "observer_windows"
PROFILES = ("S", "V")
ENV_PIN = dict(python="3.12.10", numpy="2.1.3", torch="2.5.1+cpu")
TOLERANCES = dict(loss_abs_plus_rel=1e-10, statistic_relative=1e-12)  # fixed before any B_cal access
QUANTILES = (0.0, 0.5, 0.9, 0.95, 0.99, 1.0)
LIMITATIONS = (
    "B_cal is a benign calibration set, not an attack test: nothing here estimates detection, recall or an independent false-positive rate",
    "windows within a run share environment and are not independent; the SD treats them as exchangeable (journal eq. 10); per-run and leave-one-run-out values are descriptive only",
    "the benign loss distribution may be heavy-tailed; mu_L and sigma_L are reported as the journal defines them, with no robust replacement and no threshold chosen",
    "epsilon, lambda, anomaly multipliers, trust weights and thresholds are not part of this gate",
    "B_val development evidence remains validation-informed development evidence, not independent test evidence",
)
NOT_COMPUTED = ("epsilon", "lambda", "anomaly_magnitude_A", "behavioral_trust_S_B", "thresholds_tau_Q_tau_R", "trust_weights",
                "attack_detection_metrics", "D_shadow_or_D_test_results")


class CalibrationRefused(Exception):
    """A frozen-protocol, evidence-integrity or environment check failed: stop and report; never repair or retry silently."""


def _require(condition, message):
    if not condition:
        raise CalibrationRefused(message)


def sha256_bytes(blob):
    return hashlib.sha256(blob).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ---------------------------------------------------------------- independent interpreter-level access log
class AuditLog:
    """Records every file open / directory listing under watched roots via sys.addaudithook (installed only by a real run)."""

    def __init__(self, watched_roots):
        self.watched = tuple(str(Path(r).resolve()).lower().replace("\\", "/") for r in watched_roots)
        self.events, self.active = [], False

    def handle(self, event, args):
        if not self.active or event not in ("open", "os.listdir", "os.scandir", "os.rename", "os.remove", "os.mkdir"):
            return
        target = args[0] if args else None
        if isinstance(target, bytes):
            target = os.fsdecode(target)
        if not isinstance(target, (str, os.PathLike)):
            return
        try:
            resolved = str(Path(target).resolve()).lower().replace("\\", "/")
        except (OSError, ValueError):
            return
        if any(resolved == w or resolved.startswith(w + "/") for w in self.watched):
            mode = args[1] if event == "open" and len(args) > 1 else None
            self.events.append(dict(event=event, path=resolved, mode=mode if isinstance(mode, str) else None))

    def install(self):
        sys.addaudithook(self.handle)  # hooks cannot be removed; `active` gates it
        self.active = True

    def opened_paths(self, under, events=("open",)):
        under = str(Path(under).resolve()).lower().replace("\\", "/")
        return sorted({e["path"] for e in self.events if e["event"] in events and e["path"].startswith(under + "/")})


# ---------------------------------------------------------------- reserved-evidence reader
class CalibrationReader:
    """Allowlisted, digest-verifying, logging access to the `observer_windows` artifact of accepted B_cal runs ONLY."""

    def __init__(self, results_root, campaign, partition=data.RESERVED_PARTITION):
        self.root = Path(results_root)
        self.partition = partition
        self.allowed = {a["path"]: a["sha256"] for run in campaign.accepted[partition]
                        for a in run.artifacts if a["role"] == READ_ROLE}
        tokens = set(campaign.invalidated)
        for other in (*data.TRAINING_PARTITIONS, data.RESERVED_PARTITION):
            if other == partition:
                continue
            for run in campaign.accepted[other]:
                tokens |= {run.run, run.session_id}
        tokens |= {collected["observer_session_id"] for collected in campaign.entries
                   if isinstance(collected, dict) and collected.get("entry_type") == "RUN_COLLECTED"
                   and collected["collection_run_id"] in campaign.invalidated}
        self.forbidden_tokens = tuple(sorted(tokens))
        self.reads, self.refusals = [], []

    def refuse(self, message):
        self.refusals.append(message)
        raise data.PartitionRefused(message)

    def read(self, rel_path):
        if any(token in rel_path for token in self.forbidden_tokens):
            self.refuse(f"REFUSED training-partition or invalidated evidence: {rel_path}")
        if rel_path not in self.allowed:
            self.refuse(f"REFUSED path outside the accepted B_cal observer_windows allowlist: {rel_path}")
        blob = (self.root / rel_path).read_bytes()
        digest = sha256_bytes(blob)
        if digest != self.allowed[rel_path]:
            raise CalibrationRefused(f"artifact digest mismatch: {rel_path}")
        self.reads.append(dict(path=rel_path, sha256=digest, bytes=len(blob), utc=utc_now()))
        return blob


# ---------------------------------------------------------------- candidates
def load_candidates(results_root, candidates=None, run=None):
    """Verify and load the two frozen candidates. Opens no observation evidence."""
    candidates = candidates or CANDIDATES
    base = Path(results_root) / "gate5d" / (run or CANDIDATE_RUN) / "fits"
    models, descriptors = {}, {}
    for profile, spec in candidates.items():
        directory = base / spec["fit_id"]
        weights, bundle_bytes = (directory / "weights.json").read_bytes(), (directory / "bundle.json").read_bytes()
        _require(sha256_bytes(weights) == spec["weights_sha256"], f"{profile}: weights digest differs from the frozen candidate")
        _require(sha256_bytes(bundle_bytes) == spec["bundle_sha256"], f"{profile}: bundle digest differs from the frozen candidate")
        bundle = json.loads(bundle_bytes.decode("utf-8"))
        _require((bundle["profile"], bundle["fit_id"], bundle["k"], bundle["status"], bundle["seed"])
                 == (profile, spec["fit_id"], spec["k"], "COMPLETED", spec["seed"]), f"{profile}: bundle identity differs")
        _require(bundle["architecture"] == [6, 8, spec["k"], 8, 6], f"{profile}: architecture differs")
        _require(tuple(bundle["scaler"]["features"]) == tuple(data.FEATURES), f"{profile}: scaler feature order differs")
        _require(bundle["schema_pins"]["schema_fingerprint"] == data.PIN["schema_fingerprint"]
                 and bundle["schema_pins"]["observation_config_sha256"] == data.PIN["observation_config_sha256"],
                 f"{profile}: schema pins differ")
        model = ProfileModel.load(directory)  # re-verifies the weights digest, pins, D-ZV-2 zero weights
        _require(model.profile == profile, f"{profile}: loaded model profile differs")
        models[profile] = (model, weights, bundle)
        descriptors[profile] = dict(spec, bundle_k=bundle["k"], parameters=bundle["parameters"], best_epoch=bundle["best_epoch"],
                                    epochs_run=bundle["epochs_run"], scaler_sha256=sha256_bytes(canonical(bundle["scaler"]).encode()),
                                    zero_variance_features=bundle["scaler"]["zero_variance_features"],
                                    scaler_n_fit=bundle["scaler"]["n_fit"], max_epochs=bundle["hyperparameters"]["max_epochs"])
    return models, descriptors


def check_environment():
    ae.configure_determinism()
    import torch
    seen = dict(python=sys.version.split()[0], numpy=np.__version__, torch=torch.__version__)
    _require(seen == ENV_PIN, f"environment differs from the frozen pin: {seen}")
    _require(str(torch.get_default_dtype()) == "torch.float64" and torch.are_deterministic_algorithms_enabled()
             and torch.get_num_threads() == 1, "determinism settings are not in force")
    return dict(seen, default_dtype="float64", deterministic_algorithms=True, torch_num_threads=1, platform=sys.platform)


# ---------------------------------------------------------------- B_cal windows
def check_membership(campaign, expected_runs=None, expected_planned=None, geometry=None):
    expected_runs = expected_runs or EXPECTED_BCAL_RUNS
    expected_planned = expected_planned or EXPECTED_PLANNED_ELIGIBLE
    geometry = geometry or (*EXPECTED_ELIGIBLE_RANGE, EXPECTED_RECORDS_PER_DEVICE)
    runs = tuple(sorted(r.run for r in campaign.accepted[data.RESERVED_PARTITION]))
    _require(runs == tuple(expected_runs), f"accepted B_cal membership differs from the frozen list: {runs}")
    planned = Counter()
    for run in runs:
        spec = campaign.plan["runs"][run]
        low, high = spec["eligible_window_indices"]
        _require((low, high, spec["planned_window_count"]) == tuple(geometry), f"{run}: window geometry differs")
        for device, entry in spec["devices"].items():
            planned[campaign.routes[run][device]] += high - low + 1
            _require(entry["profile"] == campaign.routes[run][device], f"{run}/{device}: route differs from the plan")
    _require(dict(planned) == dict(expected_planned), f"planned eligible populations differ: {dict(planned)}")
    _require(len({r.session_id for r in campaign.accepted[data.RESERVED_PARTITION]}) == len(runs), "B_cal sessions are not distinct")
    return runs, dict(planned)


def load_bcal_windows(campaign, reader, partition=data.RESERVED_PARTITION):
    """Window records of the accepted runs of ONE partition (B_cal for a calibration; B_val only for the rehearsal), with the
    same checks as the Gate 5D loader. Returns (records, raw bytes)."""
    records, raw_by_run = [], {}
    for run in campaign.accepted[partition]:
        artifact = next(a for a in run.artifacts if a["role"] == READ_ROLE)
        blob = reader.read(artifact["path"])
        raw_by_run[run.run] = blob
        spec = campaign.plan["runs"][run.run]
        low, high = spec["eligible_window_indices"]
        seen = Counter()
        for line in blob.decode("utf-8").splitlines():
            window = json.loads(line)
            device, index = window["device"], window["window"]["index"]
            _require(window["collection_run_id"] == run.run and window["observer_session_id"] == run.session_id
                     and window["purpose"] == "COLLECTION", f"{run.run}: window header differs from its manifest entry")
            _require(device in spec["devices"] and window["identity"]["bound_client_id"] == spec["devices"][device]["client_id"]
                     and window["identity"]["registry_sha256"] == data.PIN["registry_sha256"],
                     f"{run.run}: window device binding differs from the plan and registry")
            seen[device] += 1
            profile = data.route_for(campaign, run.run, device)
            if not low <= index <= high:
                records.append(data.WindowRecord(run.run, partition, profile, device, index, data.DESIGN_EXCLUDED, None, None))
                continue
            ready, reason, vector = data.classify_window(window, profile)
            records.append(data.WindowRecord(run.run, partition, profile, device, index,
                                             data.SCORE_READY if ready else data.NOT_SCORE_READY, reason, vector))
        _require(set(seen.values()) == {spec["planned_window_count"]} and set(seen) == set(spec["devices"]),
                 f"{run.run}: window record count differs from the plan")
    records.sort(key=lambda r: (r.run, r.index, r.device))
    return records, raw_by_run


# ---------------------------------------------------------------- scoring and statistics
def score(records, models):
    """Per-window loss for every SCORE_READY record with the frozen model of ITS OWN profile. Non-finite losses refuse."""
    rows = []
    for record in records:
        if record.category != data.SCORE_READY:
            continue
        loss = models[record.profile][0].loss_for_vector(record.vector)
        _require(math.isfinite(loss) and loss >= 0.0, f"non-finite or negative loss for {record.run}/{record.device}/{record.index}")
        rows.append(dict(profile=record.profile, run=record.run, device=record.device, index=record.index, loss=loss,
                         loss_hex=float(loss).hex(), vector=list(record.vector)))
    return rows


def calibration_statistics(losses):
    """mu_L and SAMPLE sigma_L (denominator n-1). Insufficient or degenerate support is reported, never repaired."""
    n = len(losses)
    out = dict(n=n, mu_L=None, sigma_L=None, status="OK")
    if n < 2:
        out["status"] = "INSUFFICIENT_SUPPORT"  # the sample SD is undefined for n < 2
        if n == 1:
            out["mu_L"] = float(losses[0])
        return out
    arr = np.asarray(losses, dtype=np.float64)
    out["mu_L"], out["sigma_L"] = float(arr.mean()), float(arr.std(ddof=1))
    if not (math.isfinite(out["mu_L"]) and math.isfinite(out["sigma_L"])):
        out["status"] = "NONFINITE_STATISTIC"
    elif out["sigma_L"] == 0.0:
        out["status"] = "DEGENERATE_ZERO_SD"
    return out


def diagnostics(rows):
    """Descriptive only: distribution shape, per-run / per-device values and leave-one-run-out stability. No thresholds."""
    losses = np.asarray([r["loss"] for r in rows], dtype=np.float64)
    if losses.size == 0:
        return dict(n=0)
    mean = losses.mean()
    centered = losses - mean
    m2 = float((centered ** 2).mean())
    top = max(1, math.ceil(0.01 * losses.size))
    ordered = np.sort(losses)[::-1]
    out = dict(
        n=int(losses.size), quantiles={str(q): float(np.quantile(losses, q)) for q in QUANTILES}, minimum=float(losses.min()),
        maximum=float(losses.max()), median=float(np.median(losses)),
        max_over_median=float(losses.max() / np.median(losses)) if np.median(losses) > 0 else None,
        sample_skewness=float((centered ** 3).mean() / m2 ** 1.5) if m2 > 0 else None,
        fraction_below_mean=float((losses < mean).mean()), top_one_percent_count=int(top),
        top_one_percent_share_of_loss_sum=float(ordered[:top].sum() / losses.sum()) if losses.sum() > 0 else None,
        top_one_percent_share_of_squared_deviation=float(((ordered[:top] - mean) ** 2).sum() / (centered ** 2).sum())
        if (centered ** 2).sum() > 0 else None)
    runs = sorted({r["run"] for r in rows})
    out["per_run"] = {run: calibration_statistics([r["loss"] for r in rows if r["run"] == run]) for run in runs}
    out["per_device_slot_in_run"] = {f"{run}/{dev}": calibration_statistics([r["loss"] for r in rows if r["run"] == run and r["device"] == dev])
                                     for run in runs for dev in sorted({r["device"] for r in rows if r["run"] == run})}
    out["leave_one_run_out"] = {run: calibration_statistics([r["loss"] for r in rows if r["run"] != run]) for run in runs}
    return out


def accounting(records):
    """R4: every record counted by run, profile, device and category/reason (design-excluded windows kept separate)."""
    counts = Counter((r.run, r.profile, r.device, r.category, r.reason or "") for r in records)
    per_profile = Counter((r.profile, r.category, r.reason or "") for r in records)
    return dict(
        by_record=[dict(run=run, profile=p, device=d, category=c, reason=reason or None, count=n)
                   for (run, p, d, c, reason), n in sorted(counts.items())],
        by_profile=[dict(profile=p, category=c, reason=reason or None, count=n) for (p, c, reason), n in sorted(per_profile.items())],
        total_records=len(records))


# ---------------------------------------------------------------- independent numerical verification (stdlib only)
def _exact_statistics(values):
    getcontext().prec = 80
    fractions = [Fraction(v) for v in values]
    n = len(fractions)
    mean = sum(fractions) / n
    ssd = sum((v - mean) ** 2 for v in fractions)
    variance = ssd / (n - 1)
    sd = (Decimal(variance.numerator) / Decimal(variance.denominator)).sqrt()
    return float(Decimal(mean.numerator) / Decimal(mean.denominator)), float(sd)


def _within(a, b, tol):
    return abs(a - b) <= tol * max(1.0, abs(b))


def independent_verification(raw_by_run, campaign, descriptors, models, rows, stats, partition=data.RESERVED_PARTITION):
    """Recompute everything with no numpy/torch/project loader: re-parse the SAME in-memory bytes (no second file access),
    re-derive readiness, transform and loss with plain Python, and recompute mu_L and sigma_L in exact rational arithmetic."""
    names = [m["name"] for m in MEASURES]
    independent_ready, independent_rows = {}, {}
    for run in campaign.accepted[partition]:
        spec = campaign.plan["runs"][run.run]
        low, high = spec["eligible_window_indices"]
        for line in raw_by_run[run.run].decode("utf-8").splitlines():
            window = json.loads(line)
            index = window["window"]["index"]
            if not low <= index <= high:
                continue
            measures = window["measures"]
            ok = window["coverage"]["state"] == "COMPLETE" and all(measures[n]["status"] == "VALUE" for n in names)
            values = [measures[n]["value"] for n in names]
            ok = ok and all(isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and v >= 0 for v in values)
            key = (run.run, window["device"], index)
            independent_ready[key] = ok
            if ok:
                profile = campaign.routes[run.run][window["device"]]
                weights = json.loads(models[profile][1].decode("utf-8"))
                scaler = models[profile][2]["scaler"]
                independent_rows[key] = (profile, stdlib_check.loss(weights, scaler["mu"], scaler["s"], values))
    primary_ready = {(r["run"], r["device"], r["index"]) for r in rows}
    report = dict(readiness_identical=set(k for k, v in independent_ready.items() if v) == primary_ready,
                  independent_ready=sum(independent_ready.values()), primary_ready=len(primary_ready))
    worst = 0.0
    loss_ok = report["readiness_identical"]
    for r in rows:
        profile, other = independent_rows.get((r["run"], r["device"], r["index"]), (None, None))
        if other is None or profile != r["profile"] or not _within(r["loss"], other, TOLERANCES["loss_abs_plus_rel"]):
            loss_ok = False
            continue
        worst = max(worst, abs(r["loss"] - other) / max(1.0, abs(other)))
    report.update(losses_agree_within_tolerance=loss_ok, worst_loss_difference=worst,
                  loss_tolerance=TOLERANCES["loss_abs_plus_rel"], per_profile={})
    for profile in PROFILES:
        values = [r["loss"] for r in rows if r["profile"] == profile]
        entry = dict(n=len(values))
        if len(values) >= 2:
            mu, sigma = _exact_statistics(values)
            primary = stats[profile]
            entry.update(exact_mu=mu, exact_sigma=sigma, mu_difference=abs(primary["mu_L"] - mu),
                         sigma_difference=abs(primary["sigma_L"] - sigma),
                         mu_agrees=_within(primary["mu_L"], mu, TOLERANCES["statistic_relative"]),
                         sigma_agrees=_within(primary["sigma_L"], sigma, TOLERANCES["statistic_relative"]))
        report["per_profile"][profile] = entry
    report["all_agree"] = bool(report["losses_agree_within_tolerance"] and all(
        e.get("mu_agrees", True) and e.get("sigma_agrees", True) for e in report["per_profile"].values()))
    report["statistic_tolerance"] = TOLERANCES["statistic_relative"]
    return report


# ---------------------------------------------------------------- freeze record and repository state
def git(*args, repo=ROOT):
    try:
        return subprocess.run(("git", *args), cwd=repo, capture_output=True, text=True, check=False).stdout.strip()
    except OSError:
        return None


def code_files():
    return ("calibration/gate5e_calibrate.py", "calibration/__init__.py", "model/autoencoder.py", "model/inference.py",
            "model/stdlib_check.py", "preprocessing/gate5d_data.py", "preprocessing/scaler.py", "observation/schema.py",
            "observation/manifest.py", "requirements-gate5d.lock.txt")


def freeze_content(repo=ROOT):
    return dict(
        schema="azta.gate5e.calibration_freeze", schema_version=1, protocol_id=PROTOCOL_ID, protocol_file=PROTOCOL_REL,
        protocol_sha256=sha256_bytes(Path(repo, PROTOCOL_REL).read_bytes()),
        code_sha256={f: sha256_bytes(Path(repo, f).read_bytes()) for f in code_files()},
        candidates=dict(run=CANDIDATE_RUN, fits=CANDIDATES), pins=data.PIN, environment=ENV_PIN, tolerances=TOLERANCES,
        expected_b_cal_runs=list(EXPECTED_BCAL_RUNS), expected_planned_eligible=EXPECTED_PLANNED_ELIGIBLE,
        read_role=READ_ROLE, expected_read_files=len(EXPECTED_BCAL_RUNS), not_computed=list(NOT_COMPUTED))


def verify_freeze(repo=ROOT, require_committed=True):
    """The frozen record must equal the current protocol and code bytes and, for a real run, be committed in a clean tree."""
    path = Path(repo, FREEZE_REL)
    _require(path.is_file(), "calibration freeze record does not exist")
    recorded = json.loads(path.read_text(encoding="utf-8"))
    expected = freeze_content(repo)
    _require(recorded == expected, "the freeze record differs from the current protocol/code/pins")
    info = dict(freeze_record_sha256=sha256_bytes(path.read_bytes()))
    if require_committed:
        _require(git("ls-files", "--error-unmatch", FREEZE_REL, repo=repo) == FREEZE_REL, "freeze record is not tracked by Git")
        _require(git("status", "--porcelain=v1", "-uall", repo=repo) == "", "the working tree is not clean (a committed freeze is required)")
        info.update(git_head=git("rev-parse", "HEAD", repo=repo), freeze_commit=git("log", "-1", "--format=%H", "--", FREEZE_REL, repo=repo))
        _require(info["git_head"] and info["freeze_commit"], "Git state could not be established")
    return info


# ---------------------------------------------------------------- orchestration
def write_exclusive(path, blob):
    with open(path, "xb") as stream:
        stream.write(blob)
    os.chmod(path, stat.S_IREAD)
    return sha256_bytes(blob)


def dry_run(repo=ROOT):
    """Everything except opening reserved evidence: freeze/pins/candidates/membership/environment/allowlist."""
    campaign = data.load_campaign(repo)
    runs, planned = check_membership(campaign)
    env = check_environment()
    models, descriptors = load_candidates(Path(repo) / "results")
    reader = CalibrationReader(Path(repo) / RAW_REL, campaign)
    return dict(
        status="DRY_RUN_NO_EVIDENCE_OPENED", manifest_sha256=campaign.manifest_sha256, plan_sha256=campaign.plan_sha256,
        b_cal_runs=list(runs), planned_eligible=planned, allowlist_files=len(reader.allowed),
        allowlist_roles=sorted({a["role"] for r in campaign.accepted[data.RESERVED_PARTITION] for a in r.artifacts if a["path"] in reader.allowed}),
        refused_run_and_session_tokens=len(reader.forbidden_tokens), environment=env, candidates=descriptors,
        evidence_files_opened=len(reader.reads))


def rehearse(repo=ROOT):
    """Pipeline rehearsal on ALREADY-OPENED B_val development evidence (never B_cal): re-scores the accepted B_val windows with the
    same code and compares with the retained Gate 5D.2b validation statistics of the same candidates. Writes nothing; changes
    nothing; the numbers are development evidence and never calibration or test evidence."""
    repo = Path(repo)
    campaign = data.load_campaign(repo)
    check_environment()
    models, _ = load_candidates(repo / "results")
    reader = CalibrationReader(repo / RAW_REL, campaign, partition="B_val")
    audit = AuditLog([repo / RAW_REL])
    audit.install()
    records, raw = load_bcal_windows(campaign, reader, partition="B_val")
    audit.active = False
    rows = score(records, models)
    opened = audit.opened_paths(repo / RAW_REL)
    allowed_abs = sorted(str((repo / RAW_REL / p).resolve()).lower().replace("\\", "/") for p in reader.allowed)
    out = dict(partition="B_val", files_opened=len(opened), allowlist_exact=opened == allowed_abs,
               b_cal_tokens_refused=len(reader.forbidden_tokens), profiles={})
    for profile in PROFILES:
        losses = [r["loss"] for r in rows if r["profile"] == profile]
        retained = models[profile][2]["validation"]
        mean, sd = float(np.mean(losses)), float(np.std(losses, ddof=1))
        out["profiles"][profile] = dict(
            n=len(losses), retained_n=retained["n"], mean=mean, retained_mean=retained["mean"],
            sample_sd=sd, retained_sample_sd=retained.get("sd_sample"),
            mean_matches=_within(mean, retained["mean"], 1e-12) and len(losses) == retained["n"],
            sd_matches=retained.get("sd_sample") is not None and _within(sd, retained["sd_sample"], 1e-12))
    verification = independent_verification(raw, campaign, {}, models, rows, {
        p: calibration_statistics([r["loss"] for r in rows if r["profile"] == p]) for p in PROFILES}, partition="B_val")
    out["independent_verification_all_agree"] = verification["all_agree"]
    out["all_match"] = bool(out["allowlist_exact"] and verification["all_agree"] and all(
        v["mean_matches"] and v["sd_matches"] for v in out["profiles"].values()))
    return out


def run_calibration(repo, run_id, *, authorized_freeze_sha256):
    repo = Path(repo)
    freeze = verify_freeze(repo)
    _require(authorized_freeze_sha256 == freeze["freeze_record_sha256"], "the authorization names a different freeze record")
    campaign = data.load_campaign(repo)
    runs, planned = check_membership(campaign)
    env = check_environment()
    models, descriptors = load_candidates(repo / "results")
    out_root = repo / OUTPUT_ROOT_REL
    out_root.mkdir(parents=True, exist_ok=True)
    out_dir = out_root / run_id
    reader = CalibrationReader(repo / RAW_REL, campaign)
    audit = AuditLog([repo / RAW_REL])
    # single-use marker BEFORE the first read: a second attempt can never silently reuse B_cal
    marker = dict(run_id=run_id, issued_utc=utc_now(), freeze=freeze, authorized_freeze_sha256=authorized_freeze_sha256)
    try:
        marker_sha = write_exclusive(out_root / ISSUED_MARKER, (json.dumps(marker, indent=2, sort_keys=True) + "\n").encode())
    except FileExistsError:
        raise CalibrationRefused("a calibration was already issued: B_cal is single-use; a new attempt needs a controller decision") from None
    out_dir.mkdir(exist_ok=False)
    try:
        audit.install()
        started = utc_now()
        records, raw_by_run = load_bcal_windows(campaign, reader)
        audit.active = False
        rows = score(records, models)
        stats = {p: calibration_statistics([r["loss"] for r in rows if r["profile"] == p]) for p in PROFILES}
        diag = {p: diagnostics([r for r in rows if r["profile"] == p]) for p in PROFILES}
        acct = accounting(records)
        verification = independent_verification(raw_by_run, campaign, descriptors, models, rows, stats)
        opened = audit.opened_paths(repo / RAW_REL)
        allowed_abs = sorted(str((repo / RAW_REL / p).resolve()).lower().replace("\\", "/") for p in reader.allowed)
        listings = sorted({e["path"] for e in audit.events if e["event"] in ("os.listdir", "os.scandir")})
        access = dict(reader_log=reader.reads, refusals=reader.refusals, interpreter_opened_paths_under_results_raw=opened,
                      interpreter_directory_listings_under_results_raw=listings, matches_allowlist_exactly=opened == allowed_abs,
                      allowlist_files=len(allowed_abs), role=READ_ROLE)
        support = {p: dict(planned_eligible=planned[p], score_ready=sum(1 for r in rows if r["profile"] == p),
                           not_score_ready=sum(1 for r in records if r.profile == p and r.category == data.NOT_SCORE_READY),
                           design_excluded=sum(1 for r in records if r.profile == p and r.category == data.DESIGN_EXCLUDED))
                   for p in PROFILES}
        record = dict(
            schema="azta.gate5e.calibration_record", schema_version=1, run_id=run_id, protocol_id=PROTOCOL_ID,
            started_utc=started, ended_utc=utc_now(), freeze=freeze, git_status_clean=True, marker_sha256=marker_sha,
            code_sha256={f: sha256_bytes((repo / f).read_bytes()) for f in code_files()}, environment=env, pins=data.PIN,
            candidates=descriptors, b_cal_runs=list(runs), support=support, statistics=stats, diagnostics=diag,
            accounting_summary=acct["by_profile"], independent_verification=verification, access=access,
            limitations=list(LIMITATIONS), not_computed=list(NOT_COMPUTED))
        failures = []
        if not access["matches_allowlist_exactly"]:
            failures.append("interpreter-level access log differs from the allowlist")
        if listings or any(e["event"] in ("os.rename", "os.remove", "os.mkdir") for e in audit.events):
            failures.append("a directory listing or a filesystem change occurred under the reserved evidence tree")
        if access["refusals"] or len(reader.reads) != len(EXPECTED_BCAL_RUNS):
            failures.append("reader log differs from the expected eight reads")
        if not verification["all_agree"]:
            failures.append("independent numerical verification disagrees")
        record["integrity_failures"] = failures
        record["calibration_valid"] = (not failures) and all(s["status"] == "OK" for s in stats.values())
        files = {}
        files["calibration_record.json"] = write_exclusive(out_dir / "calibration_record.json", (json.dumps(record, indent=2, sort_keys=True) + "\n").encode())
        for profile in PROFILES:
            payload = [dict(run=r["run"], device=r["device"], index=r["index"], loss=r["loss"], loss_hex=r["loss_hex"])
                       for r in rows if r["profile"] == profile]
            files[f"losses_{profile}.json"] = write_exclusive(out_dir / f"losses_{profile}.json", (json.dumps(payload, indent=1) + "\n").encode())
        files["window_accounting.json"] = write_exclusive(out_dir / "window_accounting.json", (json.dumps(acct, indent=1, sort_keys=True) + "\n").encode())
        files["access_log.jsonl"] = write_exclusive(out_dir / "access_log.jsonl", "".join(
            json.dumps(e, sort_keys=True) + "\n" for e in [*({"source": "reader", **r} for r in reader.reads),
                                                           *({"source": "interpreter_audit_hook", **e} for e in audit.events)]).encode())
        summary = "\n".join([f"Gate 5E calibration {run_id} ({PROTOCOL_ID})", f"calibration_valid={record['calibration_valid']}",
                             *(f"{p}: n={stats[p]['n']} mu_L={stats[p]['mu_L']!r} sigma_L={stats[p]['sigma_L']!r} status={stats[p]['status']}"
                               for p in PROFILES), f"independent verification all_agree={verification['all_agree']}",
                             f"access allowlist exact match={access['matches_allowlist_exactly']}", ""]).encode()
        files["summary.txt"] = write_exclusive(out_dir / "summary.txt", summary)
        write_exclusive(out_dir / "record_manifest.json", (json.dumps(dict(files=files), indent=2, sort_keys=True) + "\n").encode())
    except BaseException as exc:  # preserve the failure and the access log; never repair or retry silently
        failure = dict(run_id=run_id, utc=utc_now(), error=type(exc).__name__, message=str(exc)[:500],
                       reader_log=list(reader.reads), reader_refusals=list(reader.refusals), audit_events=list(audit.events),
                       note="B_cal is single-use: this failed attempt is preserved and needs a controller decision")
        audit.active = False
        write_exclusive(out_dir / "failure_record.json", (json.dumps(failure, indent=2, sort_keys=True) + "\n").encode())
        raise
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=("dry-run", "rehearse-on-b-val", "freeze-record", "calibrate"))
    parser.add_argument("--repo-root", default=str(ROOT))
    parser.add_argument("--run-id")
    parser.add_argument("--output", help="freeze-record: new file path")
    parser.add_argument("--authorized-freeze-sha256", help="calibrate: SHA-256 of the committed freeze record the user authorized")
    parser.add_argument("--confirm-bcal-access", action="store_true", help="calibrate: explicit, user-authorized reserved-evidence access")
    args = parser.parse_args(argv)
    repo = Path(args.repo_root)
    try:
        if args.action == "dry-run":
            print(json.dumps(dry_run(repo), indent=2, sort_keys=True))
            return 0
        if args.action == "rehearse-on-b-val":
            result = rehearse(repo)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["all_match"] else 1
        if args.action == "freeze-record":
            _require(args.output, "--output is required")
            write_exclusive(Path(args.output), (json.dumps(freeze_content(repo), indent=2, sort_keys=True) + "\n").encode())
            print("FREEZE_RECORD_WRITTEN", args.output)
            return 0
        _require(args.confirm_bcal_access and args.authorized_freeze_sha256 and args.run_id,
                 "calibration needs --run-id, --authorized-freeze-sha256 and --confirm-bcal-access")
        record = run_calibration(repo, args.run_id, authorized_freeze_sha256=args.authorized_freeze_sha256)
    except (CalibrationRefused, data.DataContractError, data.PartitionRefused, OSError, KeyError, ValueError) as exc:
        print(f"GATE5E_REFUSED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(f"GATE5E_CALIBRATION run_id={record['run_id']} calibration_valid={record['calibration_valid']} "
          f"S_n={record['statistics']['S']['n']} V_n={record['statistics']['V']['n']}")
    return 0 if record["calibration_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
