"""Core completion, Stage F: baseline adapters and comparison exporters for the LATER formal campaign, with one measurement contract. Only a synthetic smoke test runs here (`--smoke`); no public dataset is opened, no journal experiment is launched and every result says so.

    python -B rehearsal_tools/core_baselines.py --smoke --out results/engineering/core_final/baselines_smoke_v1.json
    python -B rehearsal_tools/core_baselines.py --export-comparison --out results/engineering/core_final/ablation_export_v1.json     # AE-only, timing-only, historical hybrid and the parameter-sensitivity table, from existing derived files

Adapters take the same input per device and tick (`Tick`: identity status, the six measures or None, the AE magnitude or None, context score) and answer one of FULL_ACCESS, RESTRICT, QUARANTINE or NONE:
  static_acl        identity only: valid means FULL_ACCESS; never reacts to behaviour (what the broker's static identity and ACL give)
  ml_only           the AE magnitude alone against the journal mapping with identity and context ignored; NONE when the AE is missing
  rule_only         a fixed rate and payload rule on the six measures with declared bounds; no learned model
  azta              journal eq. 1, 2, 5, 12 with the owner's constants and the hard identity gate, through `trust.fusion`
"""
import argparse
from dataclasses import dataclass
from fractions import Fraction
import json
import math
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "rehearsal_tools"))

from trust import behavior, fusion                              # noqa: E402

ALPHA, BETA, GAMMA, LAMBDA, TAU_Q, TAU_R = Fraction(1, 5), Fraction(1, 2), Fraction(3, 10), 0.1, 70, 75
METRICS_CONTRACT = ("tp", "fp", "tn", "fn", "support", "precision", "recall", "f1", "fpr", "fnr", "n2_requests", "operator_approvals", "actual_restrictions", "exposure_hours", "censored_misses", "time_to_contain_s", "decision_latency_ms")


@dataclass(frozen=True)
class Tick:
    identity_valid: object       # True, False, or None when the evidence is missing
    measures: object             # dict of the six measures or None
    a_ae: object                 # float or None
    s_c: object                  # number in [0, 100] or None
    declared_rate_per_window: float = 1.0
    declared_payload: float = 128.0


def static_acl(t):
    return "NONE" if t.identity_valid is None else "FULL_ACCESS" if t.identity_valid else "QUARANTINE"


def ml_only(t):
    if t.a_ae is None:
        return "NONE"
    return fusion.policy_state(fusion.composite_trust(100, Fraction(behavior.behavioral_trust(t.a_ae, LAMBDA)), 100, ALPHA, BETA, GAMMA), TAU_Q, TAU_R)


def rule_only(t, *, rate_factor=2.0, payload_factor=1.5):
    if t.measures is None:
        return "NONE"
    if t.measures["delivered_count"] > rate_factor * t.declared_rate_per_window or t.measures["payload_bytes_mean"] > payload_factor * t.declared_payload:
        return "RESTRICT"
    return "FULL_ACCESS"


def azta(t):
    if t.identity_valid is None:
        return "NONE"
    if t.identity_valid is False:
        return fusion.policy_state(fusion.composite_trust(0, None, None, ALPHA, BETA, GAMMA), TAU_Q, TAU_R)
    if t.a_ae is None or t.s_c is None:
        return "NONE"
    return fusion.policy_state(fusion.composite_trust(100, Fraction(behavior.behavioral_trust(t.a_ae, LAMBDA)), Fraction(t.s_c), ALPHA, BETA, GAMMA), TAU_Q, TAU_R)


ADAPTERS = dict(static_acl=static_acl, ml_only=ml_only, rule_only=rule_only, azta=azta)


def confusion(rows):
    """rows = [(oracle anomalous?, restrictive?)]. Undefined denominators stay None; counts and support always come with the rates."""
    tp = sum(o and p for o, p in rows)
    fp = sum(not o and p for o, p in rows)
    tn = sum(not o and not p for o, p in rows)
    fn = sum(o and not p for o, p in rows)
    ratio = lambda a, b: None if b == 0 else a / b
    precision, recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
    return dict(tp=tp, fp=fp, tn=tn, fn=fn, support=len(rows), precision=precision, recall=recall, f1=None if not precision or not recall else 2 * precision * recall / (precision + recall), fpr=ratio(fp, fp + tn), fnr=ratio(fn, fn + tp))


def smoke():
    measures = dict(delivered_count=1, payload_bytes_mean=128.0)
    cases = [("valid, normal", Tick(True, measures, 0.0, 100), False), ("valid, payload anomaly", Tick(True, dict(measures, payload_bytes_mean=400.0), 20.0, 100), True), ("revoked", Tick(False, measures, 0.0, 100), True), ("AE missing", Tick(True, None, None, 100), False), ("valid, mild", Tick(True, measures, 7.5, 100), False)]
    outcomes = {name: {case: fn(tick) for case, tick, _ in cases} for name, fn in ADAPTERS.items()}
    metrics = {name: confusion([(oracle, fn(tick) in ("RESTRICT", "QUARANTINE")) for _, tick, oracle in cases]) for name, fn in ADAPTERS.items()}
    expected = dict(static_acl_ignores_behaviour=outcomes["static_acl"]["valid, payload anomaly"] == "FULL_ACCESS", identity_gate=outcomes["azta"]["revoked"] == "QUARANTINE", ml_only_misses_identity=outcomes["ml_only"]["revoked"] == "FULL_ACCESS", missing_is_none=outcomes["azta"]["AE missing"] == "NONE" and outcomes["ml_only"]["AE missing"] == "NONE",
                    boundary_mild_is_restrict=outcomes["azta"]["valid, mild"] == "RESTRICT")
    return dict(schema="azta.core.baselines_smoke", label="tooling smoke test on five hand-made ticks; these counts are NOT results of any kind", metrics_contract=list(METRICS_CONTRACT), outcomes=outcomes, confusion_smoke=metrics, checks=expected, all_pass=all(expected.values()))


def export_comparison():
    import core_select as cs
    import p2_decide as pd
    import p2r_decide as rd
    selection = json.loads((ROOT / "configs/core_final/selection_v1.json").read_text(encoding="utf-8"))
    record = json.loads(cs.CANDIDATES.read_text(encoding="utf-8"))
    f = pd.Facts(record, cs.EVAL)
    rows = {}
    for device, route in selection["routes"].items():
        configs = dict(ae_only=route["ae_only"]["config"])
        if device in cs.INCUMBENT:
            configs.update(timing_only="H:TM2", historical_hybrid=f"H:HYB[{cs.INCUMBENT[device]}]")
        rows[device] = {name: dict(config=cfg, pooled=f.pool(cfg, device), false_before_onset=f.fb(cfg, device), requests=rd.false_requests(f, cfg, device), median_delay_s=cs.delays(f, cfg, device).get("median_delay_s"), p90_delay_s=cs.delays(f, cfg, device).get("p90_delay_s")) for name, cfg in configs.items()}
    sensitivity = [dict(lambda_=lam, beta=float(beta), a_restrict=(math.log(100 * float(beta) / (75 - 100 * (1 - float(beta)))) / lam if 75 > 100 * (1 - float(beta)) else None), a_quarantine=(math.log(100 * float(beta) / (70 - 100 * (1 - float(beta)))) / lam if 70 > 100 * (1 - float(beta)) else None), behaviour_alone_can_quarantine=100 * (1 - float(beta)) < 70)
                   for lam in (0.05, 0.1, 0.2) for beta in (Fraction(3, 10), Fraction(1, 2), Fraction(7, 10))]
    return dict(schema="azta.core.ablation_export", label="existing P2R development evidence; informed selection; not final values. Parameter sensitivity here is arithmetic on the fixed form; an evaluated sensitivity study is for the later campaign.", comparison=rows, parameter_arithmetic=sensitivity, fixed_operating_point=dict(alpha=0.2, beta=0.5, gamma=0.3, lambda_=0.1, tau_Q=70, tau_R=75))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--export-comparison", action="store_true")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    if args.smoke == args.export_comparison:
        raise SystemExit("exactly one of --smoke and --export-comparison")
    out = ROOT / args.out
    if out.exists():
        raise SystemExit(f"{args.out} exists; nothing is overwritten")
    document = smoke() if args.smoke else export_comparison()
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(document, stream, indent=1, sort_keys=True, default=str)
        stream.write("\n")
    print(json.dumps(document.get("checks", {"written": str(args.out)}), indent=1))
    return 0 if document.get("all_pass", True) else 1


if __name__ == "__main__":
    sys.exit(main())
