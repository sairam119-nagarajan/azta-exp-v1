"""Stabilization requirement 6: the AZTA-EXP-v1 experimental freeze, and its verification. The engineering freeze v2 (`configs/core_final/freeze_manifest_v2.json`, tag
`azta-engineering-freeze-v2`) is never edited; this is a new, separate manifest.

    python -B -I rehearsal_tools/stb_freeze_exp_v1.py write  --route configs/exp_v1/route_ae_primary_exp_v1.json --out configs/exp_v1/AZTA-EXP-v1_freeze_manifest.json
    python -B -I rehearsal_tools/stb_freeze_exp_v1.py verify --manifest configs/exp_v1/AZTA-EXP-v1_freeze_manifest.json

`write` refuses on a dirty tree. It records:
  * the raw-byte SHA-256 of every source file of the runtime packages and of every configuration the runtime resolves (the freeze v2 set plus the EXP-v1 records and the stabilization
    protocols), the dependency lock files, and every Git-ignored model file referenced by the route's input records (results/... paths; raw evidence, TEST and calibration
    partitions are never listed);
  * the resolved operating point, read back through the real loaders: per device the profile, arm, model id and weights digest, window, masks, mu_L, sigma_L, n_B and calibration id,
    liveness bound, authority mode; the trust configuration (alpha, beta, gamma, lambda, tau_Q, tau_R, epsilon, context weights); the confirmation rule; the recovery rule; the
    authorization rule; the automatic-enforcement qualification (Screen R); the training seeds of every model; Python and package versions; the Docker image ids.
`verify` re-hashes every listed file, reloads the runtime and compares the resolved operating point, and reports every difference. Nothing reads the reserved TEST runs.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

RELEASE = "AZTA-EXP-v1"
SOURCES = ("core_runtime", "enforcement", "family", "hybrid", "fleet", "engineering", "shadow_live", "shadow_feed", "decision_pipeline", "trust", "model", "preprocessing", "observation", "calibration",
           "experiments")
CONFIGS = ("configs/core_final", "configs/exp_v1", "configs/stabilization", "configs/pilot/trust_config_cand-1ac5637401a5-ctx2.json", "configs/gate6c/core_monitor_profiles_provisional.json",
           "configs/gate6c/core_fleet_models_provisional.json", "configs/gate6c/p2_candidates_cal4.json", "configs/gate6b/registry_v2_compat_record.json", "configs/dshadow/g5f-cal-v2-01-accepted-1.json",
           "configs/observation/device_registry_v2.json", "requirements.txt", "requirements-gate5d.txt", "requirements-gate5d.lock.txt", "Dockerfile", "compose.engineering.yaml", "compose.pilot.yaml",
           "docs/stabilization/CAL5_PROTOCOL.md", "docs/stabilization/STB_LIVE_SESSION_PROTOCOL.md",
           "configs/observation", "configs/collection_plans/core_final_stb_l03.json", "configs/dev_perturbations/stb-l03.json",
           "configs/collection_plans/core_final_stb_l04.json", "configs/dev_perturbations/stb-l04.json",
           "configs/collection_plans/core_final_stb_l05.json", "configs/dev_perturbations/stb-l05.json")
# The evaluation, scenario and measurement scripts (amendment 2): the verdicts, the decision trace (latency components), the scenario drivers, the session gate, the probes, the
# confirmation-rule source, the calibration and window-review tools, and this freeze tool itself. The workload generators live in `experiments` (SOURCES).
EVALUATION = ("rehearsal_tools/stb_live_verdict.py", "rehearsal_tools/stb_rehearsal_verdict.py", "rehearsal_tools/stb_shadow_verdict.py", "rehearsal_tools/stb_decision_trace.py",
              "rehearsal_tools/stb_live_operator.py", "rehearsal_tools/core_pilot_operator.py", "rehearsal_tools/core_shadow_operator.py", "rehearsal_tools/stb_live_session.py",
              "rehearsal_tools/stb_guide_relay.py", "rehearsal_tools/core_final_approve.py", "rehearsal_tools/pilot_probe.py", "rehearsal_tools/fleet_run.py", "rehearsal_tools/core_acceptance.py",
              "rehearsal_tools/core_baselines.py", "rehearsal_tools/stb_cal5_calibrate.py", "rehearsal_tools/stb_window_review.py", "rehearsal_tools/stb_console_counter_check.py",
              "rehearsal_tools/stb_freeze_exp_v1.py", "rehearsal_tools/exp_metrics.py")
NEVER = re.compile(r"(results/raw|g6c-d07|g5d3a-fx-g6b09|g5d3a-fx-g6b17|/runs/)")
CONFIG = "configs/exp_v1/trust_config_exp_v1.json"         # tau_Q 65 (supervisor Option B); must equal core_runtime.cli.CONFIG, checked by the tests
DECISION = "configs/exp_v1/trust_parameters_decision_exp_v1.json"
AUTHORITY = "configs/core_final/authority_map_v1.json"
REGISTRY = "configs/exp_v1/registry_ae_primary_exp_v1.json"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True).stdout.strip()


def model_paths(route):
    found = set()

    def walk(o):
        if isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
        elif isinstance(o, str) and o.startswith("results/") and not NEVER.search(o):
            found.add(o)
    for item in route["inputs"].values():
        walk(json.loads((ROOT / item["path"]).read_text(encoding="utf-8")))
    return sorted(found)


def file_set(route):
    files = {}
    for source in SOURCES:
        for path in sorted((ROOT / source).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                files[path.relative_to(ROOT).as_posix()] = sha(path)
    for item in CONFIGS:
        path = ROOT / item
        for f in ([path] if path.is_file() else sorted(path.rglob("*"))):
            if f.is_file() and "AZTA-EXP-v1_freeze_manifest" not in f.name:
                files[f.relative_to(ROOT).as_posix()] = sha(f)
    for item in EVALUATION:
        files[item] = sha(ROOT / item)            # a missing listed script raises: the freeze never silently omits one
    models = {}
    for p in model_paths(route):
        path = ROOT / p
        for f in ([path] if path.is_file() else sorted(path.rglob("*"))):
            if f.is_file() and "__pycache__" not in f.parts:
                models[f.relative_to(ROOT).as_posix()] = sha(f)
    return files, models


def operating_point(route_path):
    from core_runtime import loader as cl
    from core_runtime.primary import liveness_bound_ns
    from enforcement import authority as au
    from model import autoencoder as ae
    from trust.config import TrustConfig
    ae.configure_determinism()
    route = json.loads((ROOT / route_path).read_text(encoding="utf-8"))
    evaluator = cl.load_primary(ROOT, route_path=ROOT / route_path, route_sha256=sha(ROOT / route_path))
    authority = au.AuthorityMap.load(ROOT / AUTHORITY, sha(ROOT / AUTHORITY))
    config_doc = json.loads((ROOT / CONFIG).read_text(encoding="utf-8"))
    config = TrustConfig.from_dict(config_doc)
    devices = {}
    for device, item in sorted(route["devices"].items()):
        profile = item["profile"]
        spec = (evaluator.timing_profiles.get(profile) or {}).get("monitor")
        if spec is not None:
            stream = spec.ae_fast if spec.ae_fast is not None else spec.ae_slow
            inner = getattr(stream, "stream", stream)              # core_runtime.primary.RecordingAeStream wraps the loaded AeStream
            mu, sigma, masked = stream.mu_l, stream.sigma_l, list(inner.masked or ())
            cal_id = (evaluator.timing_profiles.get(profile) or {}).get("calibration_id")
            n_b = None
        else:
            c = evaluator.calibrations[profile]
            mu, sigma, n_b, cal_id, masked = c.mu_l, c.sigma_l, c.n_b, c.calibration_id, []
        descriptor = evaluator.provenance["models"].get(profile) or {}
        devices[device] = dict(profile=profile, arm=item["arm"], kind=item["kind"], width_s=item["width_s"], liveness_bound_s=liveness_bound_ns(item["width_s"]) // 10**9, masked_features=masked,
                               model_id=descriptor.get("fit_id"), weights_sha256=descriptor.get("weights_sha256"), mu_L=mu, sigma_L=sigma, n_B_plain=n_b, calibration_id=cal_id,
                               authority_mode=authority.mode(device), screen_failed=authority.entry(device).get("screen_failed"), forced_review=authority.entry(device).get("forced_review"),
                               restrict_is_permission_noop=authority.entry(device).get("restrict_is_permission_noop"))
    seeds = sorted({m for m in re.findall(r"seed(\d+)", json.dumps(route) + "".join((ROOT / v["path"]).read_text(encoding="utf-8") for v in route["inputs"].values()))})
    return dict(route=route_path, route_sha256=sha(ROOT / route_path), contract=route["contract"], devices=devices,
                trust=dict(config=CONFIG, config_sha256=config.sha256(), config_status=config.config_status, document=config_doc,
                           thresholds=dict(tau_Q=str(config.tau_q), tau_R=str(config.tau_r)), weights=dict(alpha=str(config.alpha), beta=str(config.beta), gamma=str(config.gamma), lam=str(config.lam)),
                           decision_record=DECISION, decision_record_sha256=sha(ROOT / DECISION)),
                confirmation_rule=dict(escalate_after=2, deescalate_after=2, deescalation="deny", source="rehearsal_tools/fleet_run.py (fixed, not an option)"),
                liveness_policy=dict(rule="RESTRICT recommendation when silent longer than 3 x AE window + 10 s with complete observer coverage, after a delivery in the current policy generation; RC-1-explained intervals and observer outages never count; no trust score; always operator review",
                                     source="core_runtime/primary.py Liveness, liveness_bound_ns"),
                recovery_rule=dict(name="POST_RESTORE_ONE_WINDOW_V1", rule="after a verified operator RESTORE the device's first score-ready AE window is recorded and held (no request, confirmation run reset); identity and context-only decisions are not suppressed", source="enforcement/authority.py"),
                authorization_rule=dict(rule="automatic only for AE_PRIMARY causes on AUTO_ELIGIBLE devices named automatic in a valid written scope in mode active-authorized, and only if every window of the confirmation run is AE-caused; context, mixed, liveness, identity and unattributed causes are operator-reviewed; RESTORE is always a manual operator action",
                                        source="enforcement/authority.py decide_authority, _deliver; enforcement/attribution.py"),
                qualification=dict(rule="Screen R (R1-R6) as recorded in the authority map; unchanged in the stabilization campaign", authority_map=AUTHORITY, authority_map_sha256=sha(ROOT / AUTHORITY), auto_eligible=[d for d, v in devices.items() if v["authority_mode"] == "AUTO_ELIGIBLE"]),
                registry=REGISTRY, registry_sha256=sha(ROOT / REGISTRY), training_seeds_named_in_the_model_records=seeds, determinism="model.autoencoder.configure_determinism()")


def environment():
    freeze = subprocess.run([str(ROOT / ".venv/Scripts/python.exe"), "-m", "pip", "freeze"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    images = {n: subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", n], capture_output=True, text=True).stdout.strip() for n in ("eclipse-mosquitto:2.1.2-alpine", "azta-journal-runtime:gate3")}
    return dict(python=platform.python_version(), platform=platform.platform(), pip_freeze=freeze, docker_images=images)


def write(args):
    if git("status", "--porcelain"):
        raise SystemExit("REFUSED: the working tree is not clean; the freeze names one commit")
    out = ROOT / args.out
    if out.exists():
        raise SystemExit("REFUSED: the manifest exists")
    from core_runtime import cli
    if cli.CONFIG != CONFIG or cli.ROUTE != args.route:
        raise SystemExit(f"REFUSED: the runtime resolves {cli.CONFIG} / {cli.ROUTE}, the freeze would name {CONFIG} / {args.route}")
    evidence = []
    for path in args.evidence or ():
        if re.search(r"(results/raw|g6c-d07|g5d3a-fx-g6b09|g5d3a-fx-g6b17)", path.replace("\\", "/")):
            raise SystemExit(f"REFUSED: {path} is a protected path")
        evidence.append(dict(path=path.replace("\\", "/"), sha256=sha(ROOT / path)))
    route = json.loads((ROOT / args.route).read_text(encoding="utf-8"))
    files, models = file_set(route)
    document = dict(schema="azta.exp_freeze_manifest", release=RELEASE, created_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), source_commit=git("rev-parse", "HEAD"), branch=git("rev-parse", "--abbrev-ref", "HEAD"),
                    previous_engineering_freeze=dict(path="configs/core_final/freeze_manifest_v2.json", sha256=sha(ROOT / "configs/core_final/freeze_manifest_v2.json"), tag="azta-engineering-freeze-v2"),
                    status=args.status, operating_point=operating_point(args.route), environment=environment(), files=files, model_files=models, verification_evidence=evidence,
                    rules=["no parameter is tuned on formal-test results", "no parameter changes after the reserved TEST data are opened (supervisor, 10 Nov 2026)",
                           "a change after this freeze needs a new release identifier and a documented critical defect", "reserved TEST runs were not opened"])
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("xb") as stream:
        stream.write((json.dumps(document, indent=1, sort_keys=True, default=str) + "\n").encode("utf-8"))
    print(json.dumps(dict(written=args.out, sha256=sha(out), files=len(files), model_files=len(models), source_commit=document["source_commit"]), indent=1))
    return 0


def verify(args):
    manifest = json.loads((ROOT / args.manifest).read_text(encoding="utf-8"))
    problems = []
    for group in ("files", "model_files"):
        for path, digest in manifest[group].items():
            p = ROOT / path
            if not p.exists():
                problems.append(f"MISSING {path}")
            elif sha(p) != digest:
                problems.append(f"CHANGED {path}")
    point = operating_point(manifest["operating_point"]["route"])
    expected = manifest["operating_point"]
    for key in ("route_sha256", "contract", "registry_sha256"):
        if point[key] != expected[key]:
            problems.append(f"OPERATING_POINT {key}")
    for device, item in expected["devices"].items():
        for key, value in item.items():
            if json.loads(json.dumps(point["devices"][device][key], default=str)) != value:
                problems.append(f"OPERATING_POINT {device}.{key}: {value} -> {point['devices'][device][key]}")
    for key in ("config", "config_sha256", "thresholds", "weights", "decision_record_sha256"):
        if key in expected["trust"] and point["trust"].get(key) != expected["trust"][key]:
            problems.append(f"OPERATING_POINT trust {key}")
    from core_runtime import cli
    if cli.CONFIG != expected["trust"]["config"]:
        problems.append(f"RUNTIME CONFIG {cli.CONFIG} is not the frozen {expected['trust']['config']}")
    for item in manifest.get("verification_evidence", []):
        p = ROOT / item["path"]
        if not p.exists() or sha(p) != item["sha256"]:
            problems.append(f"EVIDENCE {item['path']}")
    result = dict(manifest=args.manifest, manifest_sha256=sha(ROOT / args.manifest), files=len(manifest["files"]), model_files=len(manifest["model_files"]), problems=problems, verified=not problems, head=git("rev-parse", "HEAD"))
    print(json.dumps(result, indent=1))
    return 0 if not problems else 3


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    w = sub.add_parser("write")
    w.add_argument("--route", required=True)
    w.add_argument("--out", required=True)
    w.add_argument("--evidence", action="append", help="a Git-ignored verification record (verdict, post state) whose digest the manifest pins")
    w.add_argument("--status", default="FROZEN_EXPERIMENT_CANDIDATE; the exact configuration intended for the separately authorized formal evaluation. Not a supervisor acceptance")
    v = sub.add_parser("verify")
    v.add_argument("--manifest", required=True)
    args = parser.parse_args(argv)
    return dict(write=write, verify=verify)[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
