"""Stabilization requirement 3: the SINGLE-PASS CAL5 benign calibration of the DEPLOYED models (protocol docs/stabilization/CAL5_PROTOCOL.md, declared before collection).

    python -B -I rehearsal_tools/stb_cal5_calibrate.py --calibration-id stb-cal5-01 --out configs/stabilization/cal5_calibration_record.json
    python -B -I rehearsal_tools/stb_cal5_calibrate.py --dry-run g6c-d01 --out <scratch file>        # plumbing check on a TRAIN run: no marker, labelled DRY_RUN, never a calibration

The recorded 10 s observer windows of each CAL5 session are replayed through the REAL digest-verified evaluator (`core_runtime.loader.load_primary`, the route record's models, masks, scalers
and window composition) and the unchanged `DecisionEngine`, with a fresh evaluator per session and device, exactly as `core_ae_proof.py` does. The loss of every NATIVE (non-overlapping)
score-ready AE window is collected: for the 10 s devices one per tick, for the slow devices one per completed composed window (the evaluator's own window memo, keyed by window id).
The loss does not depend on mu_L or sigma_L, so the replay uses the existing constants and nothing is circular. Statistics: mean, SAMPLE SD (n - 1, journal eq. 10), quantiles, the largest
window's share of the squared deviation, per session and pooled, and leave-one-session-out exceedance of L_R = mu + 6.931 (sigma + 1e-6) and L_Q = mu + 9.163 (sigma + 1e-6).
Classification (protocol section 3) for the recalibrated devices 05-09; a stability check only for 01-04 and 10. Single pass: an exclusive marker is created before the first CAL5 window is read.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "rehearsal_tools"))

import core_ae_proof as proof                                          # noqa: E402
from core_runtime import loader as cl                                  # noqa: E402
from hybrid import events as ev                                        # noqa: E402
from model import autoencoder as ae                                    # noqa: E402
from trust.config import TrustConfig                                   # noqa: E402
from trust.engine import DecisionEngine                                # noqa: E402

PLAN = "configs/stabilization/cal5_partition_plan.json"
MARKER_DIR = ROOT / "results/engineering/stabilization"
RECALIBRATED = ("device05", "device06", "device07", "device08", "device09")
A_R, A_Q, EPS = math.log(2.0) / 0.1, math.log(2.5) / 0.1, 1e-6
SCHEMA = "azta.stabilization.cal5_calibration"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def cal5_assignment(dry_run=None):
    plan = json.loads((ROOT / PLAN).read_text(encoding="utf-8"))
    if plan.get("schema") != ev.PRELIVE_SCHEMA:
        raise SystemExit("the CAL5 partition plan is not a pre-live partition plan")
    if dry_run:
        a = ev.load_prelive_assignment()
        return a, [dry_run], plan
    eligible = plan["eligible_windows"]
    roles = {run: x["role"] for run, x in plan["runs"].items()}
    a = dict(schema=ev.PRELIVE_SCHEMA, roles=roles, excluded_window_indices=[0] + list(range(eligible + 1, eligible + 12)), eligible_windows=eligible, conditions={r: x["segments"] for r, x in plan["runs"].items()})
    return a, sorted(roles), plan


def session_losses(evaluator, config, run, assignment, device, profile):
    """[(window id, loss)] of every native score-ready AE window of `device` in one session, in order."""
    indices = sorted(set(run.recorded_windows[device]) - set(assignment["excluded_window_indices"]))
    engine = DecisionEngine(config, proof.fresh(evaluator))
    behavior = engine.behavior
    identity = (f"azta-device-{device[-2:]}", f"azta-device-{device[-2:]}")
    seen, out = set(), []
    for i in indices:
        decision = engine.decide(proof.bundle(device, run.recorded_windows[device][i], profile, identity))
        primary = (decision.get("behavior") or {}).get("ae_primary") or {}
        memo = {k: v for k, v in behavior.slow_memo.items() if k[0] == device}
        if memo:                                                  # a monitor profile: every completed native window's loss, by window id
            for key, loss in memo.items():
                if key not in seen and loss is not None:
                    seen.add(key)
                    out.append((key[1], loss))
        elif primary.get("ae_status") == "SCORE_READY" and primary.get("ae_loss") is not None:
            out.append((f"{run.run}:{i}", primary["ae_loss"]))
    return out


def stats(losses):
    if len(losses) < 2:
        return dict(n=len(losses), degenerate=True)
    mu, sigma = statistics.fmean(losses), statistics.stdev(losses)
    total = sum((x - mu) ** 2 for x in losses)
    ordered = sorted(losses)
    q = lambda p: ordered[int(p * (len(ordered) - 1))]
    return dict(n=len(losses), mu_L=mu, sigma_L=sigma, sd_convention="sample (denominator n-1)", loss_min=ordered[0], loss_median=statistics.median(losses), loss_p95=q(0.95), loss_p99=q(0.99), loss_max=ordered[-1],
                largest_window_share=(max((x - mu) ** 2 for x in losses) / total) if total else None, L_R=mu + A_R * (sigma + EPS), L_Q=mu + A_Q * (sigma + EPS))


def analyse(per_session, deployed):
    pooled_losses = [l for s in per_session.values() for _, l in s]
    sessions = {run: stats([l for _, l in rows]) for run, rows in per_session.items()}
    pooled = stats(pooled_losses)
    loso = {}
    for run, rows in per_session.items():
        rest = [l for r, s in per_session.items() if r != run for _, l in s]
        ref = stats(rest)
        held = [l for _, l in rows]
        if ref.get("degenerate") or not held:
            loso[run] = dict(degenerate=True)
            continue
        loso[run] = dict(n=len(held), above_L_R=sum(l > ref["L_R"] for l in held), above_L_Q=sum(l > ref["L_Q"] for l in held), share_above_L_R=sum(l > ref["L_R"] for l in held) / len(held),
                         share_above_L_Q=sum(l > ref["L_Q"] for l in held) / len(held), reference_mu_L=ref["mu_L"], reference_sigma_L=ref["sigma_L"])
    current = dict(n_B=deployed.get("n_B"), mu_L=deployed.get("mu_L"), sigma_L=deployed.get("sigma_L"))
    current_exceed = None
    if isinstance(current["mu_L"], float) and isinstance(current["sigma_L"], float):
        lr = current["mu_L"] + A_R * (current["sigma_L"] + EPS)
        current_exceed = dict(L_R=lr, share_of_cal5_above_L_R=sum(l > lr for l in pooled_losses) / len(pooled_losses) if pooled_losses else None,
                              per_session={run: (sum(l > lr for _, l in rows) / len(rows) if rows else None) for run, rows in per_session.items()})
    return dict(sessions=sessions, pooled=pooled, loso=loso, deployed_constants=current, deployed_constants_on_cal5=current_exceed)


def classify(result, usable_sessions):
    if usable_sessions < 3:
        return "BLOCKED", ["fewer than 3 usable sessions"]
    pooled, failed = result["pooled"], []
    if pooled.get("degenerate") or not pooled.get("sigma_L", 0) > 0:
        return "FRAGILE", ["degenerate pooled sigma_L"]
    if pooled["largest_window_share"] is not None and pooled["largest_window_share"] > 0.5:
        failed.append(f"one window carries {pooled['largest_window_share']:.2f} of the pooled squared deviation (> 0.50)")
    for run, s in result["sessions"].items():
        if s.get("degenerate") or not (pooled["sigma_L"] / 3 <= s["sigma_L"] <= 3 * pooled["sigma_L"]):
            failed.append(f"{run}: session sigma_L {s.get('sigma_L')} outside a factor of 3 of the pooled {pooled['sigma_L']:.6g}")
    for run, x in result["loso"].items():
        if x.get("degenerate") or x["share_above_L_R"] > 0.02:
            failed.append(f"{run}: leave-one-session-out exceedance of L_R {x.get('share_above_L_R')} > 0.02")
    return ("STABLE" if not failed else "FRAGILE"), failed


def deployed_constants(evaluator, device, profile):
    spec = (evaluator.timing_profiles.get(profile) or {}).get("monitor")
    if spec is not None:
        stream = spec.ae_fast if spec.ae_fast is not None else spec.ae_slow
        return dict(mu_L=stream.mu_l, sigma_L=stream.sigma_l, n_B=None, stream=stream.name, width_s=stream.width_s)
    c = evaluator.calibrations.get(profile)
    return dict(mu_L=c.mu_l, sigma_L=c.sigma_l, n_B=c.n_b, stream="PLAIN") if c else {}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--calibration-id")
    parser.add_argument("--out", required=True)
    parser.add_argument("--dry-run", help="a TRAIN run id: plumbing check only; no marker; the output is labelled DRY_RUN")
    args = parser.parse_args(argv)
    out_path = Path(args.out) if Path(args.out).is_absolute() else ROOT / args.out
    if out_path.exists():
        raise SystemExit("REFUSED: the output exists; nothing is overwritten")
    assignment, runs, plan = cal5_assignment(args.dry_run)
    if args.dry_run is None:
        if not args.calibration_id:
            raise SystemExit("REFUSED: --calibration-id is required")
        for run in runs:                                          # every refusal that can be checked before the marker
            ev.accept_live_path_run(ev.RUNS / run, run)
        marker = MARKER_DIR / f"cal_marker_{args.calibration_id}.json"
        MARKER_DIR.mkdir(parents=True, exist_ok=True)
        with marker.open("x", encoding="utf-8") as stream:
            json.dump(dict(calibration_id=args.calibration_id, runs=runs, utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), note="CAL5 is opened by this pass and by no other calibration"), stream)
    ae.configure_determinism()
    evaluator = cl.load_primary(ROOT, route_path=ROOT / proof.ROUTE, route_sha256=proof.sha(proof.ROUTE))
    config = TrustConfig.from_dict(json.loads((ROOT / proof.CONFIG).read_text(encoding="utf-8")))
    route = json.loads((ROOT / proof.ROUTE).read_text(encoding="utf-8"))["devices"]
    loaded = {run: ev.load_run(run, assignment) for run in runs}
    devices = {}
    for device, item in sorted(route.items()):
        per_session = {}
        for run in runs:
            try:
                per_session[run] = session_losses(evaluator, config, loaded[run], assignment, device, item["profile"])
            except Exception as exc:                              # recorded, never retried: the pass is consumed
                per_session[run] = []
                print(f"{device} {run}: ERROR {type(exc).__name__}: {exc}", flush=True)
        result = analyse(per_session, deployed_constants(evaluator, device, item["profile"]))
        usable = sum(1 for rows in per_session.values() if len(rows) >= 2)
        result.update(profile=item["profile"], arm=item["arm"], width_s=item["width_s"], role="RECALIBRATED" if device in RECALIBRATED else "STABILITY_CHECK_ONLY",
                      usable_sessions=usable, windows_per_session={r: len(rows) for r, rows in per_session.items()})
        if device in RECALIBRATED:
            result["classification"], result["failed_criteria"] = classify(result, usable)
        devices[device] = result
        p = result["pooled"]
        print(f"{device} {item['arm']:16} n={p.get('n')} sessions={result['windows_per_session']} mu={p.get('mu_L', float('nan')):.5g} sigma={p.get('sigma_L', float('nan')):.5g} top={p.get('largest_window_share') or 0:.2f} "
              f"LOSO>L_R={[round(x.get('share_above_L_R', -1), 4) for x in result['loso'].values()]} -> {result.get('classification', 'check only')}", flush=True)
    record = dict(schema=SCHEMA, schema_version=1, record_id=args.calibration_id or f"DRY_RUN-{args.dry_run}", status="DRY_RUN_NOT_A_CALIBRATION" if args.dry_run else "PROVISIONAL_UNAPPROVED",
                  runs=runs, partition_plan=PLAN, partition_plan_sha256=sha(ROOT / PLAN), protocol="docs/stabilization/CAL5_PROTOCOL.md", route_sha256=proof.sha(proof.ROUTE),
                  thresholds=dict(A_R=A_R, A_Q=A_Q, epsilon=EPS, note="the boundaries of the unchanged trust parameters with S_ID = S_C = 100"), devices=devices,
                  generated_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(record, stream, indent=1, sort_keys=True)
        stream.write("\n")
    print("written", out_path, sha(out_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
