"""Gate 5E post-hoc investigation of the S-model end-of-run artifact: a reproducible, read-only analysis (docs/gate5e addendum).

What it reads: (1) accepted B_train / B_val observation files ONLY, through preprocessing.gate5d_data.EvidenceReader (digest-pinned allowlist
that refuses B_cal, the invalidated run and anything unlisted); (2) the SAVED Gate 5E derived losses (losses_S.json, losses_V.json,
calibration_record.json); (3) the committed Gate 5C plan and the frozen candidate models. It NEVER opens a B_cal observation file, never
calls the Gate 5E calibration reader, trains nothing, changes no model, scaler, statistic or record, and chooses no epsilon, lambda,
weight or threshold. Alternative sigmas it prints are EXPLORATORY and are not proposed replacements. Predicted vectors are SYNTHETIC
(schedule-derived), never observations. An interpreter audit hook proves which files were opened; the run fails if any B_cal or
invalidated path was touched. The output is a new, exclusively created JSON file outside every accepted-evidence directory.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import statistics
import stat
import sys

import numpy as np
import torch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from calibration import gate5e_calibrate as g5e  # noqa: E402  (read-only use: candidate verification and environment check)
from experiments import collection_plan as plans  # noqa: E402
from experiments import collection_workload as v1  # noqa: E402
from experiments import collection_workload_v2 as v2  # noqa: E402
from observation.schema import PREDICTOR_CANDIDATES  # noqa: E402
from preprocessing import gate5d_data as data  # noqa: E402

W_NS = 10_000_000_000
ANALYSIS_ID = "gate5e-s-artifact-analysis-v1"
SHIFT_MS, NOISE_MS, ENSEMBLE_SEED = 1.55, 0.6, 20261020  # median receive shift of the 16 development runs; per-message noise; fixed seed
FORBIDDEN_OUTPUT_DIRS = ("results/gate5e", "results/gate5d", "results/raw")
A_TABLE_LOSSES = (0.001, 0.01, 0.03, 0.1, 0.3, 0.5307, 1.0, 5.0, 50.0)
EXPOSURE_LEVELS = (0.5, 1, 2, 3, 5, 10)
ILLUSTRATIVE_LAMBDAS = (0.05, 0.25)  # illustration only; lambda is NOT chosen


# ---------------------------------------------------------------- pure helpers
def a_value(loss, mu, sigma):
    """Journal equation 9 with epsilon -> 0 (epsilon is not chosen here): max(0, (L - mu) / sigma)."""
    return max(0.0, (loss - mu) / sigma)


def exposure(losses, mu, sigma, levels=EXPOSURE_LEVELS):
    a = np.maximum(0.0, (np.asarray(losses, dtype=np.float64) - mu) / sigma)
    return {str(level): float(np.mean(a > level)) for level in levels}, float(a.max())


def summary(values):
    x = np.asarray(values, dtype=np.float64)
    return dict(n=int(x.size), mean=float(x.mean()), sample_sd=float(x.std(ddof=1)) if x.size > 1 else None, median=float(np.median(x)),
                p90=float(np.quantile(x, 0.9)), p99=float(np.quantile(x, 0.99)), maximum=float(x.max()))


def average_ranks(values):
    x = np.asarray(values, dtype=np.float64)
    order = np.argsort(x, kind="mergesort")
    ranks = np.empty(x.size)
    i = 0
    while i < x.size:
        j = i
        while j + 1 < x.size and x[order[j + 1]] == x[order[i]]:
            j += 1
        ranks[order[i:j + 1]] = (i + j) / 2.0
        i = j + 1
    return ranks


def spearman(a, b):
    return float(np.corrcoef(average_ranks(a), average_ranks(b))[0, 1])


def top_window_share(losses):
    x = np.asarray(losses, dtype=np.float64)
    dev = (x - x.mean()) ** 2
    return float(dev.max() / dev.sum())


def output_path_allowed(path, repo=ROOT):
    """The analysis may write only a NEW file outside every accepted-evidence directory."""
    target = Path(path).resolve()
    if target.exists():
        return False
    for rel in FORBIDDEN_OUTPUT_DIRS:
        base = (Path(repo) / rel).resolve()
        if target == base or base in target.parents:
            return False
    return True


class AuditLog:
    """Interpreter-level record of every file opened under results/raw (installed only by a real run)."""

    def __init__(self, watched):
        self.watched = str(Path(watched).resolve()).lower().replace("\\", "/")
        self.opened, self.active = [], False

    def handle(self, event, args):
        if not self.active or event != "open" or not args or not isinstance(args[0], (str, bytes, os.PathLike)):
            return
        target = os.fsdecode(args[0])
        try:
            resolved = str(Path(target).resolve()).lower().replace("\\", "/")
        except (OSError, ValueError):
            return
        if resolved.startswith(self.watched + "/"):
            self.opened.append(resolved)

    def install(self):
        sys.addaudithook(self.handle)
        self.active = True


# ---------------------------------------------------------------- scoring
class Scorer:
    def __init__(self, models):
        self.models = {profile: models[profile][0] for profile in models}

    def loss(self, profile, vector):
        return None if vector is None else self.models[profile].loss_for_vector(vector)

    def batch(self, profile, vectors):
        model = self.models[profile]
        x = torch.tensor(model.scaler.transform_many(vectors), dtype=torch.float64)
        with torch.no_grad():
            return ((model.model(x) - x) ** 2).mean(dim=1).numpy()

    def residual_shares(self, profile, vector):
        model = self.models[profile]
        z = torch.tensor([model.scaler.transform(vector)], dtype=torch.float64)
        with torch.no_grad():
            res = ((model.model(z) - z) ** 2)[0].numpy()
        return (res / res.sum()).tolist() if res.sum() > 0 else [0.0] * len(res)


# ---------------------------------------------------------------- development evidence (B_train / B_val only)
def development_rows(campaign, reader, scorer):
    """Observed vs plan-reconstructed windows 1-60 of every device of every accepted B_train / B_val run."""
    rows, shifts = [], {}
    for partition in data.TRAINING_PARTITIONS:
        for run in campaign.accepted[partition]:
            art = {a["role"]: a["path"] for a in run.artifacts}
            windows = [json.loads(line) for line in reader.read(art["observer_windows"]).decode("utf-8").splitlines()]
            events = [json.loads(line) for line in reader.read(art["observer_events"]).decode("utf-8").splitlines()]
            config = campaign.plan["runs"][run.run]
            for device, profile in campaign.routes[run.run].items():
                mine = {w["window"]["index"]: w for w in windows if w["device"] == device}
                cov0 = mine[0]["window"]["start_offset_ns"]
                observed = sorted(e["receive_offset_ns"] - cov0 for e in events
                                  if e.get("bound_device") == device and e["disposition"] == "COUNTED")
                old = v1.schedule(config, device)
                new = v2.schedule(v2.counterfactual_config(config), device)
                shift = round(statistics.median(o - p for o, (_, p, _) in zip(observed, old)))
                shifts[(run.run, device)] = dict(planned=len(old), observed=len(observed), shift_ms=shift / 1e6)
                feats_old = v2.planned_window_features([p + shift for _, p, _ in old], [z for _, _, z in old], 62, W_NS)
                feats_new = v2.planned_window_features([p + shift for _, p, _ in new], [z for _, _, z in new], 62, W_NS)
                for k in range(1, 61):
                    ready, _, observed_vector = data.classify_window(mine[k], profile)
                    vec_old, vec_new = v2.planned_vector(feats_old[k]), v2.planned_vector(feats_new[k])
                    rows.append(dict(
                        partition=partition, run=run.run, device=device, profile=profile, index=k,
                        observed=list(observed_vector) if ready else None, loss_observed=scorer.loss(profile, observed_vector) if ready else None,
                        planned_v1=vec_old, loss_planned_v1=scorer.loss(profile, vec_old),
                        planned_v2=vec_new, loss_planned_v2=scorer.loss(profile, vec_new)))
    return rows, shifts


def plan_vs_observation(rows, shifts):
    ok = [r for r in rows if r["observed"] and r["planned_v1"]]
    count_ok = np.mean([r["observed"][0] == r["planned_v1"][0] for r in ok])
    out = dict(runs_with_equal_message_counts=sum(1 for s in shifts.values() if s["planned"] == s["observed"]), run_devices=len(shifts),
               median_shift_ms=statistics.median(s["shift_ms"] for s in shifts.values()),
               shift_ms_range=[min(s["shift_ms"] for s in shifts.values()), max(s["shift_ms"] for s in shifts.values())],
               windows_compared=len(ok), delivered_count_agreement=float(count_ok),
               count_mismatches=[(r["run"], r["device"], r["index"], r["observed"][0], r["planned_v1"][0]) for r in ok
                                 if r["observed"][0] != r["planned_v1"][0]])
    for profile in ("S", "V"):
        big = [r for r in ok if r["profile"] == profile and r["loss_observed"] > 1e-3]
        rel = [abs(r["loss_planned_v1"] - r["loss_observed"]) / r["loss_observed"] for r in big]
        out[f"loss_relative_error_where_loss_gt_1e-3_{profile}"] = dict(n=len(rel), median=float(np.median(rel)), p90=float(np.quantile(rel, 0.9)),
                                                                          maximum=float(max(rel)))
        last = [r for r in big if r["index"] == 60]
        out[f"loss_relative_error_index_60_{profile}"] = dict(
            n=len(last), median=float(np.median([abs(r["loss_planned_v1"] - r["loss_observed"]) / r["loss_observed"] for r in last])) if last else None)
    return out


def tail_structure(rows, scorer, mu, sigma):
    s_rows = [r for r in rows if r["profile"] == "S" and r["observed"]]
    out = dict(by_partition={p: summary([r["loss_observed"] for r in s_rows if r["partition"] == p]) for p in data.TRAINING_PARTITIONS})
    counts = sorted({int(r["observed"][0]) for r in s_rows})
    total = sum(r["loss_observed"] for r in s_rows)
    out["by_delivered_count"] = {str(c): dict(summary([r["loss_observed"] for r in s_rows if int(r["observed"][0]) == c]),
                                              share_of_total_loss=float(sum(r["loss_observed"] for r in s_rows if int(r["observed"][0]) == c) / total))
                                 for c in counts}
    groups = {"1": (1, 1), "2-59": (2, 59), "60": (60, 60)}
    out["by_window_index"] = {name: dict(summary([r["loss_observed"] for r in s_rows if lo <= r["index"] <= hi]),
                                         share_above_0_01=float(np.mean([r["loss_observed"] > 0.01 for r in s_rows if lo <= r["index"] <= hi])))
                              for name, (lo, hi) in groups.items()}
    shares = np.array([scorer.residual_shares("S", r["observed"]) for r in s_rows])
    weights = np.array([r["loss_observed"] for r in s_rows])[:, None]
    out["residual_share_by_feature_loss_weighted"] = {n: float(v) for n, v in zip(PREDICTOR_CANDIDATES, (shares * weights).sum(0) / weights.sum())}
    for p in data.TRAINING_PARTITIONS:
        sub = [r for r in s_rows if r["partition"] == p]
        out[f"index_60_share_of_total_loss_{p}"] = float(sum(r["loss_observed"] for r in sub if r["index"] == 60) / sum(r["loss_observed"] for r in sub))
        out[f"count_9_among_index_60_{p}"] = [int(sum(1 for r in sub if r["index"] == 60 and r["observed"][0] == 9)), int(sum(1 for r in sub if r["index"] == 60))]
        out[f"count_9_share_elsewhere_{p}"] = float(np.mean([r["observed"][0] == 9 for r in sub if r["index"] != 60]))
    out["top_windows"] = [dict(partition=r["partition"], run=r["run"], index=r["index"], loss=r["loss_observed"], delivered_count=r["observed"][0],
                               last_delivery_age_ms=r["observed"][5]) for r in sorted(s_rows, key=lambda r: -r["loss_observed"])[:6]]
    return out


def counterfactual_rows(rows):
    """Window 60 under the v1 stop rule versus the same jitter streams continued through the post-roll (SYNTHETIC reconstruction)."""
    out = {}
    for profile in ("S", "V"):
        last = [r for r in rows if r["profile"] == profile and r["index"] == 60 and r["planned_v1"]]
        out[profile] = dict(
            windows=len(last),
            mean_planned_loss_stop_rule=float(np.mean([r["loss_planned_v1"] for r in last])), mean_planned_loss_continued=float(np.mean([r["loss_planned_v2"] for r in last])),
            share_above_0_01_stop_rule=float(np.mean([r["loss_planned_v1"] > 0.01 for r in last])),
            share_above_0_01_continued=float(np.mean([r["loss_planned_v2"] > 0.01 for r in last])),
            mean_age_ms_stop_rule=float(np.mean([r["planned_v1"][5] for r in last])), mean_age_ms_continued=float(np.mean([r["planned_v2"][5] for r in last])),
            count_9_stop_rule=int(sum(r["planned_v1"][0] == 9 for r in last)) if profile == "S" else None,
            count_9_continued=int(sum(r["planned_v2"][0] == 9 for r in last)) if profile == "S" else None)
        interior = [r for r in rows if r["profile"] == profile and 2 <= r["index"] <= 59 and r["observed"]]
        out[profile]["observed_mean_loss_interior_2_59"] = float(np.mean([r["loss_observed"] for r in interior]))
        out[profile]["observed_mean_loss_index_60"] = float(np.mean([r["loss_observed"] for r in rows if r["profile"] == profile and r["index"] == 60 and r["observed"]]))
        out[profile]["observed_mean_age_ms_interior"] = float(np.mean([r["observed"][5] for r in interior]))
        out[profile]["observed_mean_age_ms_index_60"] = float(np.mean([r["observed"][5] for r in rows if r["profile"] == profile and r["index"] == 60 and r["observed"]]))
    return out


# ---------------------------------------------------------------- Gate 5E derived outputs and the plan (no B_cal observation file)
def saved_vs_plan(campaign, scorer, saved_s, shift_ms):
    pairs = []
    for run in campaign.accepted[data.RESERVED_PARTITION]:  # configuration only: run ids, routes and the frozen plan
        device = next(d for d, p in campaign.routes[run.run].items() if p == "S")
        items = v1.schedule(campaign.plan["runs"][run.run], device)
        feats = v2.planned_window_features([o + round(shift_ms * 1e6) for _, o, _ in items], [z for _, _, z in items], 62, W_NS)
        for k in range(1, 61):
            vector = v2.planned_vector(feats[k])
            pairs.append((run.run, device, k, saved_s[(run.run, device, k)], scorer.loss("S", vector), vector))
    saved = np.array([p[3] for p in pairs])
    predicted = np.array([p[4] for p in pairs])
    big = saved > 1e-3
    top = sorted(pairs, key=lambda p: -p[3])[:6]
    return dict(
        windows=len(pairs), spearman=spearman(saved, predicted),
        pooled_mean=dict(saved=float(saved.mean()), predicted=float(predicted.mean())),
        pooled_sample_sd=dict(saved=float(saved.std(ddof=1)), predicted=float(predicted.std(ddof=1))),
        pooled_max=dict(saved=float(saved.max()), predicted=float(predicted.max())),
        relative_error_where_saved_gt_1e_3=dict(n=int(big.sum()), median=float(np.median(np.abs(predicted - saved)[big] / saved[big])),
                                               p90=float(np.quantile(np.abs(predicted - saved)[big] / saved[big], 0.9))),
        windows_above_0_01=dict(saved=int((saved > 0.01).sum()), predicted=int((predicted > 0.01).sum()), both=int(((saved > 0.01) & (predicted > 0.01)).sum())),
        largest_saved_windows=[dict(run=r, device=d, index=k, saved_loss=s, planned_loss=p, planned_vector=v) for r, d, k, s, p, v in top],
        planned_count_9_share=float(np.mean([p[5][0] == 9 for p in pairs])))


def exposures_and_alternatives(saved_s, saved_v, dev_rows, mu, sigma, mu_v, sigma_v):
    ls = np.array(list(saved_s.values()))
    idx = np.array([k[2] for k in saved_s])
    drop_max = np.delete(ls, int(np.argmax(ls)))
    alternatives = {"accepted_all_480": (mu, sigma, int(ls.size)),
                    "exploratory_excluding_the_single_largest_window": (float(drop_max.mean()), float(drop_max.std(ddof=1)), int(drop_max.size)),
                    "exploratory_excluding_all_index_60_windows": (float(ls[idx != 60].mean()), float(ls[idx != 60].std(ddof=1)), int((idx != 60).sum()))}
    out = dict(alternatives={k: dict(mu=m, sigma=s, n=n, sigma_ratio_to_accepted=s / sigma) for k, (m, s, n) in alternatives.items()})
    out["a_table_for_hypothetical_losses"] = [{"loss": loss, **{k: a_value(loss, m, s) for k, (m, s, _) in alternatives.items()}} for loss in A_TABLE_LOSSES]
    out["loss_for_given_a_under_accepted_statistics"] = {str(a): mu + a * sigma for a in (1, 2, 3, 5, 10)}
    out["illustrative_s_b_100_exp_minus_lambda_a"] = {str(lam): {str(a): 100 * math.exp(-lam * a) for a in (0.5, 1, 2, 5, 10, 21)} for lam in ILLUSTRATIVE_LAMBDAS}
    lv = np.array(list(saved_v.values()))
    out["benign_a_exposure_accepted_statistics"] = {
        "S_B_cal_derived": dict(zip(("share_above", "max_a"), exposure(ls, mu, sigma))),
        "V_B_cal_derived": dict(zip(("share_above", "max_a"), exposure(lv, mu_v, sigma_v))),
        "S_B_val": dict(zip(("share_above", "max_a"), exposure([r["loss_observed"] for r in dev_rows if r["profile"] == "S" and r["partition"] == "B_val" and r["observed"]], mu, sigma))),
        "S_B_train": dict(zip(("share_above", "max_a"), exposure([r["loss_observed"] for r in dev_rows if r["profile"] == "S" and r["partition"] == "B_train" and r["observed"]], mu, sigma))),
        "S_B_cal_under_exploratory_sigma_excluding_single_max": dict(zip(("share_above", "max_a"), exposure(ls, *alternatives["exploratory_excluding_the_single_largest_window"][:2])))}
    out["fraction_of_calibration_windows_with_a_equal_zero"] = dict(S=float(np.mean(ls <= mu)), V=float(np.mean(lv <= mu_v)))
    out["single_largest_window_share_of_squared_deviation_S"] = top_window_share(ls)
    return out


# ---------------------------------------------------------------- synthetic ensemble of the benign S workload
def ensemble(scorer, runs, seed=ENSEMBLE_SEED):
    rng = np.random.RandomState(seed)
    seeds = rng.randint(1, 2 ** 62, size=runs, dtype=np.int64)
    definition = plans.PROFILES["S"]
    results = {}
    for label, post_roll in (("stop_rule", 0), ("post_roll", 1)):
        vectors, counts = [], []
        for jitter_seed in seeds:
            config = dict(devices={"d": dict(profile_definition=definition, jitter_seed=int(jitter_seed), size_seed=None)},
                          window_duration_ms=10_000, lead_in_windows=1, eligible_windows=60, post_roll_windows=post_roll)
            items = v2.schedule(config, "d")
            offsets = [o + round((SHIFT_MS + rng.normal(0, NOISE_MS)) * 1e6) for _, o, _ in items]
            feats = v2.planned_window_features(offsets, [128] * len(items), 62, W_NS)
            vectors.extend(v2.planned_vector(feats[k]) for k in range(1, 61))
        losses = scorer.batch("S", vectors).reshape(runs, 60)
        counts = np.array([v[0] for v in vectors]).reshape(runs, 60)
        ages = np.array([v[5] for v in vectors]).reshape(runs, 60)
        results[label] = (losses, counts, ages)
    max_gap_ms = v2.max_gap_ns(definition) / 1e6
    out = {}
    for label, (losses, counts, ages) in results.items():
        flat = losses.ravel()
        out[label] = dict(
            pooled=dict(summary(flat), share_count_9=float(np.mean(counts == 9)), share_count_11=float(np.mean(counts == 11))),
            index_60=dict(mean_loss=float(losses[:, 59].mean()), share_above_0_01=float(np.mean(losses[:, 59] > 0.01)), share_above_0_1=float(np.mean(losses[:, 59] > 0.1)),
                          share_count_9=float(np.mean(counts[:, 59] == 9)), mean_age_ms=float(ages[:, 59].mean()),
                          share_age_above_one_maximum_gap=float(np.mean(ages[:, 59] > max_gap_ms + 1e-3))),
            index_2_59=dict(mean_age_ms=float(ages[:, 1:59].mean()), share_age_above_one_maximum_gap=float(np.mean(ages[:, 1:59] > max_gap_ms + 1e-3))),
            index_1_59=dict(mean_loss=float(losses[:, :59].mean()), sample_sd=float(losses[:, :59].ravel().std(ddof=1)), share_above_0_01=float(np.mean(losses[:, :59] > 0.01))))
    sets = 4000
    for label, drop60 in (("stop_rule", False), ("stop_rule_excluding_index_60", True), ("post_roll", False)):
        losses = results["stop_rule" if label.startswith("stop_rule") else label][0]  # (losses, counts, ages)
        mus, sds, tops = [], [], []
        for _ in range(sets):
            chosen = losses[rng.choice(runs, size=8, replace=False)]
            x = (chosen[:, :59] if drop60 else chosen).ravel()
            mus.append(x.mean()); sds.append(x.std(ddof=1)); tops.append(top_window_share(x))
        q = lambda a, p: float(np.quantile(a, p))
        out[f"calibration_sets_{label}"] = dict(
            sets=sets, mu_L=dict(p05=q(mus, .05), median=q(mus, .5), p95=q(mus, .95)), sigma_L=dict(p05=q(sds, .05), p25=q(sds, .25), median=q(sds, .5), p75=q(sds, .75), p95=q(sds, .95)),
            share_sigma_at_least_accepted=float(np.mean(np.array(sds) >= 0.0252)), largest_window_share_median=q(tops, .5),
            share_largest_window_over_half=float(np.mean(np.array(tops) > 0.5)), share_largest_window_over_90_percent=float(np.mean(np.array(tops) > 0.9)))
    return out


# ---------------------------------------------------------------- model structure and the remaining count-9 / count-11 limitation
def model_probe(dev_rows, scorer):
    """Linear PCA is a STRUCTURE PROBE only: nothing is trained or changed."""
    train = [r for r in dev_rows if r["profile"] == "S" and r["partition"] == "B_train" and r["observed"]]
    x = np.array([r["observed"] for r in train])
    z = scorer.models["S"].scaler.transform_many(x.tolist())
    centred = z - z.mean(0)
    _, sv, vt = np.linalg.svd(centred, full_matrices=False)
    eig = sv ** 2 / (len(z) - 1)
    out = dict(covariance_eigenvalues=[float(e) for e in eig], cumulative_share=[float(c) for c in np.cumsum(eig) / eig.sum()])
    for k in (3, 4):
        err = ((centred - centred @ vt[:k].T @ vt[:k]) ** 2).mean(1)
        out[f"linear_pca_k{k}_median_reconstruction_mse_by_count"] = {str(c): float(np.median(err[x[:, 0] == c])) for c in (9, 10, 11)}
    out["b_train_count_mix"] = {str(c): float(np.mean(x[:, 0] == c)) for c in (9, 10, 11)}
    out["b_train_mean_age_ms_by_count"] = {str(c): float(x[x[:, 0] == c, 5].mean()) for c in (9, 10, 11)}
    out["frozen_ae_in_sample_loss_by_count"] = {str(c): dict(median=float(np.median([r["loss_observed"] for r in train if r["observed"][0] == c])),
                                                            mean=float(np.mean([r["loss_observed"] for r in train if r["observed"][0] == c]))) for c in (9, 10, 11)}
    return out


def artifact_free_assessment(dev_rows, mu, sigma):
    """After accounting for the termination artifact: observed windows 1-59 plus the continued-stream (post-roll) reconstruction of window 60."""
    pool = [(r["observed"][0], r["loss_observed"]) for r in dev_rows if r["profile"] == "S" and r["observed"] and r["index"] != 60]
    pool += [(r["planned_v2"][0], r["loss_planned_v2"]) for r in dev_rows if r["profile"] == "S" and r["index"] == 60 and r["planned_v2"]]
    losses = np.array([p[1] for p in pool])
    counts = np.array([p[0] for p in pool])
    total_ss = float(((losses - losses.mean()) ** 2).sum())
    out = dict(windows=int(losses.size), pooled=summary(losses),
               share_above=dict(zip(("0.01", "0.03", "0.1"), (float(np.mean(losses > t)) for t in (0.01, 0.03, 0.1)))),
               a_exposure_accepted_statistics=dict(zip(("share_above", "max_a"), exposure(losses, mu, sigma))))
    out["by_count"] = {str(c): dict(summary(losses[counts == c]), share_above_0_01=float(np.mean(losses[counts == c] > 0.01)),
                                    share_of_squared_deviation=float(((losses[counts == c] - losses.mean()) ** 2).sum() / total_ss))
                       for c in sorted(set(counts.tolist()))}
    out["median_loss_ratio_count_9_to_10"] = float(np.median(losses[counts == 9]) / np.median(losses[counts == 10]))
    return out


def v_profile_check(dev_rows, saved_v):
    v_rows = [r for r in dev_rows if r["profile"] == "V" and r["observed"]]
    idx60 = [r["loss_observed"] for r in v_rows if r["index"] == 60]
    rest = [r["loss_observed"] for r in v_rows if r["index"] != 60]
    ages = lambda sel: float(np.mean([r["observed"][5] for r in v_rows if sel(r)]))
    return dict(development=dict(mean_loss_index_60=float(np.mean(idx60)), mean_loss_other=float(np.mean(rest)),
                                 mean_age_ms_index_60=ages(lambda r: r["index"] == 60), mean_age_ms_interior=ages(lambda r: 2 <= r["index"] <= 59)),
                saved_b_cal_derived=dict(mean_loss_index_60=float(np.mean([v for k, v in saved_v.items() if k[2] == 60])),
                                         mean_loss_other=float(np.mean([v for k, v in saved_v.items() if k[2] != 60]))))


def synthetic_perturbations(dev_rows, scorer, mu, sigma, alt_mu, alt_sigma):
    """HYPOTHETICAL, attack-like or unusual-but-benign changes of a REAL benign B_train window (synthetic inputs; labelled)."""
    train = [r for r in dev_rows if r["profile"] == "S" and r["partition"] == "B_train" and r["observed"]]
    base = sorted(train, key=lambda r: r["loss_observed"])[len(train) // 2]["observed"]
    cases = [("payload +1 B", [base[0], 129.0, 0.0, base[3], base[4], base[5]]), ("payload +2 B", [base[0], 130.0, 0.0, base[3], base[4], base[5]]),
             ("payload +8 B", [base[0], 136.0, 0.0, base[3], base[4], base[5]]), ("payload size SD 5 B", [base[0], 128.0, 5.0, base[3], base[4], base[5]])]
    for n in (11, 12, 15, 20):
        g = 10000.0 / n
        cases.append((f"{n} messages per window", [float(n), 128.0, 0.0, g, 0.0577 * g, g / 2]))
    for n in (9, 8, 6):
        g = 10000.0 / n
        cases.append((f"{n} messages per window", [float(n), 128.0, 0.0, g, 0.0577 * g, g / 2]))
    for sd in (100.0, 200.0, 400.0):
        cases.append((f"gap SD {sd:.0f} ms", [base[0], 128.0, 0.0, base[3], sd, base[5]]))
    cases.append(("last delivery 1.5 s ago", [10.0, 128.0, 0.0, base[3], base[4], 1500.0]))
    rows = []
    for name, vector in cases:
        loss = scorer.loss("S", vector)
        rows.append(dict(case=name, loss=loss, a_accepted=a_value(loss, mu, sigma), a_exploratory=a_value(loss, alt_mu, alt_sigma)))
    return dict(base_window=base, base_loss=scorer.loss("S", base), cases=rows)


# ---------------------------------------------------------------- orchestration
def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(repo, ensemble_runs):
    repo = Path(repo)
    campaign = data.load_campaign(repo)
    environment = g5e.check_environment()
    models, descriptors = g5e.load_candidates(repo / "results")
    scorer = Scorer(models)
    record_dir = repo / "results" / "gate5e" / "g5e-20261020-01"
    record = json.loads((record_dir / "calibration_record.json").read_text(encoding="utf-8"))
    mu, sigma = record["statistics"]["S"]["mu_L"], record["statistics"]["S"]["sigma_L"]
    mu_v, sigma_v = record["statistics"]["V"]["mu_L"], record["statistics"]["V"]["sigma_L"]
    load = lambda name: {(r["run"], r["device"], r["index"]): r["loss"] for r in json.loads((record_dir / name).read_text(encoding="utf-8"))}
    saved_s, saved_v = load("losses_S.json"), load("losses_V.json")
    reader = data.EvidenceReader(repo / "results" / "raw", campaign)
    audit = AuditLog(repo / "results" / "raw")
    audit.install()
    rows, shifts = development_rows(campaign, reader, scorer)
    audit.active = False
    bcal_tokens = {t for r in campaign.accepted[data.RESERVED_PARTITION] for t in (r.run, r.session_id)} | set(campaign.invalidated)
    touched = sorted({p for p in audit.opened if any(t.lower() in p for t in bcal_tokens)})
    if touched or reader.refusals:
        raise RuntimeError(f"a reserved or unaccepted path was touched or refused: {touched} {reader.refusals}")
    shift_ms = statistics.median(s["shift_ms"] for s in shifts.values())
    explore = exposures_and_alternatives(saved_s, saved_v, rows, mu, sigma, mu_v, sigma_v)
    alt = explore["alternatives"]["exploratory_excluding_the_single_largest_window"]
    return dict(
        analysis_id=ANALYSIS_ID, environment=environment, candidates={p: dict(weights_sha256=d["weights_sha256"], bundle_sha256=d["bundle_sha256"]) for p, d in descriptors.items()},
        inputs=dict(manifest_sha256=campaign.manifest_sha256, plan_sha256=campaign.plan_sha256,
                    gate5e_calibration_record_sha256=sha256_file(record_dir / "calibration_record.json"),
                    gate5e_losses_S_sha256=sha256_file(record_dir / "losses_S.json"), gate5e_losses_V_sha256=sha256_file(record_dir / "losses_V.json")),
        accepted_statistics=dict(S=dict(mu_L=mu, sigma_L=sigma), V=dict(mu_L=mu_v, sigma_L=sigma_v)),
        assumptions=dict(receive_shift_ms=SHIFT_MS, per_message_noise_ms=NOISE_MS, ensemble_seed=ENSEMBLE_SEED, ensemble_runs=ensemble_runs,
                         note="planned/synthetic values are schedule-derived reconstructions, never observations"),
        access_audit=dict(files_opened_under_results_raw=len(set(audit.opened)), roles=sorted({Path(p).name for p in audit.opened}),
                          bcal_or_invalidated_paths_opened=touched, evidence_reader_refusals=list(reader.refusals),
                          note="B_cal observation files were not opened; Gate 5E derived losses were read from results/gate5e"),
        plan_vs_observation=plan_vs_observation(rows, shifts),
        tail_structure=tail_structure(rows, scorer, mu, sigma),
        window_60_counterfactual=counterfactual_rows(rows),
        saved_gate5e_vs_plan=saved_vs_plan(campaign, scorer, saved_s, shift_ms),
        consequences=explore,
        synthetic_perturbations=synthetic_perturbations(rows, scorer, mu, sigma, alt["mu"], alt["sigma"]),
        model_probe=model_probe(rows, scorer),
        artifact_free_assessment=artifact_free_assessment(rows, mu, sigma),
        v_profile_check=v_profile_check(rows, saved_v),
        ensemble=ensemble(scorer, ensemble_runs))


def write_exclusive(path, value):
    blob = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    with open(path, "xb") as stream:
        stream.write(blob)
    os.chmod(path, stat.S_IREAD)
    return hashlib.sha256(blob).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", required=True, help="new JSON file; never inside results/gate5e, results/gate5d or results/raw")
    parser.add_argument("--repo-root", default=str(ROOT))
    parser.add_argument("--ensemble-runs", type=int, default=3000)
    args = parser.parse_args(argv)
    if not output_path_allowed(args.output, args.repo_root):
        print("ANALYSIS_REFUSED output must be a NEW file outside results/gate5e, results/gate5d and results/raw", file=sys.stderr)
        return 2
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    result = run(args.repo_root, args.ensemble_runs)
    print(f"ANALYSIS_WRITTEN {args.output} sha256={write_exclusive(args.output, result)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
