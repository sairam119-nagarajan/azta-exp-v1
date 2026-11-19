"""Gate 5D.2 lightweight six-input autoencoder, training and selection (freeze document sections 5.3, 5.2.1, 7).

Architecture 6 -> 8 -> k -> 8 -> 6 (ReLU after both 8-unit layers; linear bottleneck and output), k in {2, 3}.
D-ZV-2: first-layer weights fed by a train-zero-variance input start at exactly 0.0 and are asserted to stay 0.0
after every epoch and after best-epoch restore (no gradient masking, hooks or re-zeroing). Loss is the journal's
per-window MSE over all six transformed inputs. Fits nothing but its own weights, on one profile's B_train; B_val
is used only for early stopping and the k selection. No calibration, threshold, trust score or B_cal use.
"""
from dataclasses import dataclass
import hashlib
import json
import math
import time
import traceback

import numpy as np
import torch
from torch import nn

WIDTH = 8
INPUT_DIM = 6
KS = (2, 3)
SEED_INDICES = (0, 1, 2)
PROFILES = ("S", "V")


@dataclass(frozen=True)
class TrainConfig:
    """Accepted hyperparameters (freeze document section 7). Only tests may construct non-default values."""
    learning_rate: float = 1e-3
    betas: tuple = (0.9, 0.999)
    eps: float = 1e-8
    weight_decay: float = 0.0
    batch_size: int = 64
    max_epochs: int = 500
    patience: int = 20


class ZeroWeightViolation(RuntimeError):
    """A D-ZV-2 zero weight is not exactly 0.0."""


class NonFiniteLoss(RuntimeError):
    """A loss became non-finite."""


class RestoreMismatch(RuntimeError):
    """The restored best-epoch weights do not reproduce the recorded validation loss exactly."""


def preregistered_seed(profile, seed_index):
    """int(sha256("g5d-v1|model-a/<P>|seed<i>")[:8], 16) (freeze document section 5.3)."""
    return int(hashlib.sha256(f"g5d-v1|model-a/{profile}|seed{seed_index}".encode("utf-8")).hexdigest()[:8], 16)


def configure_determinism():
    torch.set_default_dtype(torch.float64)
    torch.use_deterministic_algorithms(True)
    torch.set_num_threads(1)


class Autoencoder(nn.Module):
    def __init__(self, k):
        super().__init__()
        self.k = k
        self.enc1 = nn.Linear(INPUT_DIM, WIDTH)
        self.enc2 = nn.Linear(WIDTH, k)
        self.dec1 = nn.Linear(k, WIDTH)
        self.out = nn.Linear(WIDTH, INPUT_DIM)

    def forward(self, x):
        h = torch.relu(self.enc1(x))
        z = self.enc2(h)
        d = torch.relu(self.dec1(z))
        return self.out(d)


def parameter_count(k):
    return sum(p.numel() for p in Autoencoder(k).parameters())


def per_window_loss(model, x):
    """Journal eq 8 per window: mean over the six transformed inputs of the squared reconstruction error."""
    with torch.no_grad():
        return ((model(x) - x) ** 2).mean(dim=1)


def assert_zero_weights(model, zero_idx, where):
    if zero_idx and not bool((model.enc1.weight[:, list(zero_idx)] == 0.0).all()):
        raise ZeroWeightViolation(f"D-ZV-2 zero weights are not exactly 0.0 ({where})")


def weights_to_json(model):
    return {name: dict(shape=list(t.shape), data=t.detach().tolist()) for name, t in model.state_dict().items()}


def model_from_weights(k, weights):
    model = Autoencoder(k)
    model.load_state_dict({name: torch.tensor(w["data"], dtype=torch.float64) for name, w in weights.items()})
    return model


def _stats(values):
    arr = np.asarray(values, dtype=np.float64)
    return dict(n=int(arr.size), mean=float(arr.mean()), sd_sample=float(arr.std(ddof=1)) if arr.size > 1 else None)


def _grouped(losses, labels):
    out = {}
    for label in sorted(set(labels)):
        out[label] = _stats([v for v, l in zip(losses, labels) if l == label])
    return out


def train_fit(*, profile, k, seed_index, train_z, val_z, val_devices, val_runs, zero_idx, config=TrainConfig()):
    """One candidate fit. Returns (result, weights_json_or_None). Failures are recorded, never retried."""
    if profile not in PROFILES or k not in KS or seed_index not in SEED_INDICES:
        raise ValueError("candidate outside the preregistered budget")
    zero_idx = tuple(zero_idx)
    train_z, val_z = np.asarray(train_z, dtype=np.float64), np.asarray(val_z, dtype=np.float64)
    if train_z.shape[1] != INPUT_DIM or val_z.shape[1] != INPUT_DIM or len(val_devices) != len(val_z) \
            or len(val_runs) != len(val_z):
        raise ValueError("training or validation matrix does not match the six-feature schema")
    if zero_idx and not bool((train_z[:, list(zero_idx)] == 0.0).all()):
        raise ValueError("a zero-variance input is not exactly 0.0 in the transformed training matrix")
    if torch.get_default_dtype() != torch.float64 or not torch.are_deterministic_algorithms_enabled():
        raise RuntimeError("call configure_determinism() first")
    seed = preregistered_seed(profile, seed_index)
    result = dict(fit_id=f"A-{profile}-k{k}-seed{seed_index}", profile=profile, k=k, seed_index=seed_index, seed=seed,
                  status="COMPLETED", failure_reason=None, halt_campaign=False, parameters=parameter_count(k),
                  architecture=[INPUT_DIM, WIDTH, k, WIDTH, INPUT_DIM], n_train=int(len(train_z)),
                  n_val=int(len(val_z)), zero_variance_indices=list(zero_idx))
    started = time.perf_counter()
    weights = None
    try:
        torch.manual_seed(seed)
        model = Autoencoder(k)
        generator = torch.Generator()
        generator.manual_seed(seed)
        if zero_idx:
            with torch.no_grad():
                model.enc1.weight[:, list(zero_idx)] = 0.0
        assert_zero_weights(model, zero_idx, "initialization")
        optimizer = torch.optim.Adam(model.parameters(), lr=config.learning_rate, betas=config.betas, eps=config.eps,
                                     weight_decay=config.weight_decay)
        train_t, val_t = torch.from_numpy(train_z), torch.from_numpy(val_z)
        history, best, best_epoch, best_state, since, epochs_checked = [], math.inf, 0, None, 0, 0
        stop_reason = "epoch_cap_reached"
        for epoch in range(1, config.max_epochs + 1):
            model.train()
            order = torch.randperm(len(train_t), generator=generator)
            batch_losses = []
            for start in range(0, len(train_t), config.batch_size):
                batch = train_t[order[start:start + config.batch_size]]
                optimizer.zero_grad()
                loss = ((model(batch) - batch) ** 2).mean()
                loss.backward()
                optimizer.step()
                batch_losses.append(float(loss))
            model.eval()
            train_loss = float(per_window_loss(model, train_t).mean())
            val_loss = float(per_window_loss(model, val_t).mean())
            history.append(dict(epoch=epoch, batch_train_loss_mean=float(np.mean(batch_losses)),
                                train_loss=train_loss, val_loss=val_loss))
            if not (math.isfinite(train_loss) and math.isfinite(val_loss)):
                raise NonFiniteLoss(f"non-finite loss at epoch {epoch}")
            assert_zero_weights(model, zero_idx, f"after epoch {epoch}")
            epochs_checked += 1
            if val_loss < best:  # strict improvement, no min-delta
                best, best_epoch, since = val_loss, epoch, 0
                best_state = {name: t.detach().clone() for name, t in model.state_dict().items()}
            else:
                since += 1
            if since >= config.patience:
                stop_reason = "early_stopping"
                break
        model.load_state_dict(best_state)
        model.eval()
        assert_zero_weights(model, zero_idx, "after best-epoch restore")
        val_losses = per_window_loss(model, val_t)
        if float(val_losses.mean()) != best:
            raise RestoreMismatch("restored weights do not reproduce the best validation loss exactly")
        train_losses = per_window_loss(model, train_t)
        with torch.no_grad():
            val_sq = ((model(val_t) - val_t) ** 2).numpy()
            train_out = model(train_t).numpy()
        train_sq = (train_out - train_z) ** 2
        v = val_losses.numpy()
        result.update(
            epochs_run=len(history), best_epoch=best_epoch, stop_reason=stop_reason, history=history,
            validation=dict(best_val_loss=best, window_losses=v.tolist(), **_stats(v),
                            per_device=_grouped(v.tolist(), list(val_devices)),
                            per_run=_grouped(v.tolist(), list(val_runs)),
                            per_feature_mse=val_sq.mean(axis=0).tolist()),
            training=dict(train_loss_at_best=float(train_losses.mean()), **_stats(train_losses.numpy()),
                          per_feature_mse=train_sq.mean(axis=0).tolist()),
            zero_variance_outputs={str(j): dict(yhat_mean=float(train_out[:, j].mean()),
                                                yhat_min=float(train_out[:, j].min()),
                                                yhat_max=float(train_out[:, j].max()),
                                                train_mse=float(train_sq[:, j].mean())) for j in zero_idx},
            zero_weight_check=dict(indices=list(zero_idx), initialization_verified=True, epochs_checked=epochs_checked,
                                   restore_verified=True,
                                   final_values=model.enc1.weight[:, list(zero_idx)].tolist() if zero_idx else []))
        weights = weights_to_json(model)
    except ZeroWeightViolation as exc:
        result.update(status="FAILED", failure_reason="ZERO_WEIGHT_VIOLATION", failure_detail=str(exc), halt_campaign=True)
    except NonFiniteLoss as exc:
        result.update(status="FAILED", failure_reason="NON_FINITE_LOSS", failure_detail=str(exc))
    except RestoreMismatch as exc:
        result.update(status="FAILED", failure_reason="RESTORE_MISMATCH", failure_detail=str(exc))
    except Exception as exc:  # recorded, never swallowed silently; the fit is retained as FAILED
        result.update(status="FAILED", failure_reason=f"EXCEPTION:{type(exc).__name__}",
                      failure_detail=traceback.format_exc(limit=5))
    result["wall_seconds"] = time.perf_counter() - started
    return result, weights


def select_primary(fits):
    """Section 5.3 selection for ONE profile. Returns the selection record (all fits are retained by the caller)."""
    by_k = {k: sorted((f for f in fits if f["k"] == k), key=lambda f: f["seed_index"]) for k in KS}
    record = dict(rule="mean over the three seeds of best-epoch own-profile B_val mean per-window loss; lowest wins; "
                       "exact tie goes to k=2; primary artifact is seed0 of the selected k",
                  candidates={})
    eligible = {}
    for k, group in by_k.items():
        complete = len(group) == len(SEED_INDICES) and all(f["status"] == "COMPLETED" for f in group)
        metric = float(np.mean([f["validation"]["best_val_loss"] for f in group])) if complete else None
        record["candidates"][f"k{k}"] = dict(eligible=complete, metric=metric,
                                             statuses={f["fit_id"]: f["status"] for f in group},
                                             seed_best_val_losses={f["fit_id"]: f["validation"]["best_val_loss"]
                                                                   for f in group if f["status"] == "COMPLETED"})
        if complete:
            eligible[k] = metric
    if not eligible:
        record.update(selected_k=None, primary_fit_id=None, outcome="NO_ELIGIBLE_K_STOP_AND_REPORT")
        return record
    best_metric = min(eligible.values())
    selected = min(k for k, m in eligible.items() if m == best_metric)  # exact tie -> smaller k (k=2)
    record.update(selected_k=selected, primary_fit_id=f"A-{fits[0]['profile']}-k{selected}-seed0",
                  outcome="SELECTED", tie=len([k for k, m in eligible.items() if m == best_metric]) > 1)
    return record


def jsonable(value):
    """Make a result JSON-serializable: non-finite floats become strings, never silently dropped."""
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    return value


def dumps(value):
    return json.dumps(jsonable(value), sort_keys=True, indent=1, allow_nan=False)
