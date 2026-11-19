"""Core completion: turn ONE written owner or Controller answer into the pinned records of ONE live request. It runs only to record an answer the owner or Controller actually gave: silence, an earlier campaign or an expired record is no answer.

    python -B rehearsal_tools/core_final_approve.py --request RC1_READONLY|FUNCTIONAL_NO_MUTATION|FUNCTIONAL_RETEST|PILOT_ENFORCEMENT|PILOT_ENFORCEMENT_2 --approved-by NAME --approver-role OWNER|MAIN_CONTROLLER --answer-ref REFERENCE --valid-minutes N --out-dir configs/core_final/approvals/REQUEST-ID

It writes: the session approval (every request); and for PILOT_ENFORCEMENT the approved registry (`CONTROLLER_APPROVED`, canonical), the calibration bundle (`CONTROLLER_ACCEPTED` for this pilot scope only: one identifier over the unchanged constituent calibrations, carrying no constants), the operational approval and the authority scope that names exactly `AUTOMATIC` devices as automatic and the rest as reviewed.
Exclusive creation. The digests it prints go into the session file. Nothing here starts a session.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core_runtime import cli, loader as cl                       # noqa: E402
from decision_pipeline.registry import canonical, record_sha256  # noqa: E402
from enforcement.pep import ENV_PILOT                            # noqa: E402
from engineering import approvals                                # noqa: E402
from trust.config import TrustConfig                             # noqa: E402

REQUESTS = dict(RC1_READONLY=dict(mode=None, runs=("core-r01", "core-r02")), FUNCTIONAL_NO_MUTATION=dict(mode="shadow", runs=("core-s01",)), FUNCTIONAL_RETEST=dict(mode="shadow", runs=("core-s02",)), PILOT_ENFORCEMENT=dict(mode="active-authorized", runs=("core-p01",)), PILOT_ENFORCEMENT_2=dict(mode="active-authorized", runs=("core-p03",)),
                STABILIZATION_SHADOW_1=dict(mode="shadow", runs=("stb-s01",), protocol="docs/stabilization/STB_LIVE_SESSION_PROTOCOL.md"),
                STABILIZATION_SHADOW_2=dict(mode="shadow", runs=("stb-s02",), protocol="docs/stabilization/STB_LIVE_SESSION_PROTOCOL.md"),     # amendment 2 rehearsal, no policy change
                STABILIZATION_LIVE_1=dict(mode="active-authorized", runs=("stb-l01",), protocol="docs/stabilization/STB_LIVE_SESSION_PROTOCOL.md",
                                          scope_actions={"device01": ["RESTRICT", "QUARANTINE", "RESTORE"], "device02": ["RESTRICT", "QUARANTINE", "RESTORE"]}),
                STABILIZATION_LIVE_2=dict(mode="active-authorized", runs=("stb-l02",), protocol="docs/stabilization/STB_LIVE_SESSION_PROTOCOL.md",     # the retest of LIVE_1: same protocol and scope
                                          scope_actions={"device01": ["RESTRICT", "QUARANTINE", "RESTORE"], "device02": ["RESTRICT", "QUARANTINE", "RESTORE"]}),
                STABILIZATION_LIVE_3=dict(mode="active-authorized", runs=("stb-l03",), protocol="docs/stabilization/STB_LIVE_SESSION_PROTOCOL.md",     # amendment 2: same scope and 14 checks
                                          scope_actions={"device01": ["RESTRICT", "QUARANTINE", "RESTORE"], "device02": ["RESTRICT", "QUARANTINE", "RESTORE"]}),
                STABILIZATION_LIVE_4=dict(mode="active-authorized", runs=("stb-l04",), protocol="docs/stabilization/STB_LIVE_SESSION_PROTOCOL.md",     # amendment 4: EXP-v1 verification (tau_Q 65), device02 only
                                          scope_actions={"device02": ["RESTRICT", "QUARANTINE", "RESTORE"]}),
                STABILIZATION_LIVE_5=dict(mode="active-authorized", runs=("stb-l05",), protocol="docs/stabilization/STB_LIVE_SESSION_PROTOCOL.md",     # amendment 4, unchanged repeat of stb-l04
                                          scope_actions={"device02": ["RESTRICT", "QUARANTINE", "RESTORE"]}))
PROTOCOL = "docs/final/CORE_COMPLETION_PROTOCOL.md"
AUTOMATIC = ("device02",)
SCOPE_ACTIONS = {"device01": ["RESTRICT", "QUARANTINE", "RESTORE"], "device02": ["RESTRICT", "QUARANTINE", "RESTORE"], "device03": ["QUARANTINE", "RESTORE"], "device05": ["QUARANTINE", "RESTORE"], "device08": ["QUARANTINE", "RESTORE"]}


def write(path, document):
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(document, stream, indent=1, sort_keys=True)
        stream.write("\n")
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def enforcement_records(out, *, role, approved_by, answer_ref, issued, expires, run_id, mode, automatic=AUTOMATIC, scope_actions=SCOPE_ACTIONS, root=ROOT):
    from model import autoencoder as ae
    ae.configure_determinism()
    route_sha = cli.sha(root / cli.ROUTE)
    evaluator = cl.load_primary(root, route_path=root / cli.ROUTE, route_sha256=route_sha)
    models = {p: dict(model_id=d["fit_id"], weights_sha256=d["weights_sha256"]) for p, d in evaluator.provenance["models"].items()}
    calibration_id = f"core-final-pilot-{run_id}"
    bundle_sha = write(out / "calibration_bundle.json", dict(schema=cl.BUNDLE_SCHEMA, status="CONTROLLER_ACCEPTED", calibration_id=calibration_id, acceptance_ref=answer_ref, acceptance_scope=f"PILOT_ONLY:{run_id}", models=models,
                                                             note="one identifier over the unchanged constituent calibrations (fragile ones stay fragile); it carries no constants and accepts nothing beyond this pilot"))
    registry = json.loads((root / cli.REGISTRY).read_text(encoding="utf-8"))
    registry["supersedes_sha256"] = record_sha256(registry)
    registry["registry_version"] += 1
    registry["status"] = "CONTROLLER_APPROVED"
    for row in registry["devices"]:
        row["route"]["approval_ref"] = answer_ref
    registry["change_log"].append(dict(approval_ref=answer_ref, author_role="Owner or Controller answer, written by core_final_approve.py", registry_version=registry["registry_version"], summary=f"Approved for the pilot session {run_id} only"))
    registry_record = record_sha256(registry)
    with (out / "registry_approved.json").open("x", encoding="utf-8", newline="\n") as stream:      # canonical: the live adapter pins the file's digest, which must equal the record digest in the approval
        stream.write(canonical(registry))
    config = TrustConfig.from_dict(json.loads((root / cli.CONFIG).read_text(encoding="utf-8")))
    approval_role = "MAIN_CONTROLLER"           # the record's field: the existing loader names this one role; the approver's own role is in the session approval and the scope
    approval_sha = write(out / "operational_approval.json", dict(schema=approvals.SCHEMA, schema_version=1, approval_id=f"CORE-FINAL-{run_id}", scope=approvals.PILOT_CORE_SCOPE, approver_role=approval_role, approver_ref=answer_ref, issued_utc_ns=issued, expires_utc_ns=expires,
                                                                 registry=dict(sha256=registry_record, status="CONTROLLER_APPROVED"), configuration=dict(sha256=config.sha256(), status="CONTROLLER_APPROVED", record_label=config.config_status), calibration=dict(calibration_id=calibration_id, record_sha256=bundle_sha, status="CONTROLLER_ACCEPTED")))
    scope_sha = write(out / "authority_scope.json", dict(schema="azta.enforcement.authority_scope", schema_version=1, scope_id=f"scope-{run_id}", mode=mode, approver_role=role, approver_ref=answer_ref, issued_utc_ns=issued, expires_utc_ns=expires, environment=ENV_PILOT, session_run_id=run_id,
                                                         artifacts=dict(registry_sha256=registry_record, config_sha256=config.sha256(), route_sha256=route_sha, authority_map_sha256=cli.sha(root / cli.AUTHORITY)),
                                                         devices={d: dict(actions=list(a), automatic=d in automatic and mode == "active-authorized") for d, a in scope_actions.items()}))
    return dict(operational_approval_sha256=approval_sha, authority_scope_sha256=scope_sha, calibration_bundle_sha256=bundle_sha, registry_record_sha256=registry_record, approved_by=approved_by)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--request", choices=REQUESTS, required=True)
    parser.add_argument("--approved-by", required=True)
    parser.add_argument("--approver-role", choices=("OWNER", "MAIN_CONTROLLER"), required=True)
    parser.add_argument("--answer-ref", required=True)
    parser.add_argument("--valid-minutes", type=int, required=True)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args(argv)
    if not 1 <= args.valid_minutes <= 720:
        raise SystemExit("--valid-minutes must be between 1 and 720")
    out = ROOT / args.out_dir
    out.mkdir(parents=True, exist_ok=False)
    issued, expires = time.time_ns() - 1_000_000_000, time.time_ns() + args.valid_minutes * 60 * 1_000_000_000
    item = REQUESTS[args.request]
    printed = {}
    for run_id in item["runs"]:
        printed[run_id] = write(out / f"session_approval_{run_id}.json", dict(schema=cli.APPROVAL_SCHEMA, request_id=f"{args.request}:{args.answer_ref}", purpose=args.request, mode=item["mode"], run_id=run_id, approved_by=args.approved_by, approved_utc_ns=issued, expires_utc_ns=expires,
                                                                               protocol_sha256=cli.sha(ROOT / item.get("protocol", PROTOCOL)), route_sha256=cli.sha(ROOT / cli.ROUTE), authority_map_sha256=cli.sha(ROOT / cli.AUTHORITY)))
    if args.request.startswith(("PILOT_ENFORCEMENT", "STABILIZATION_LIVE")):
        printed.update(enforcement_records(out, role=args.approver_role, approved_by=args.approved_by, answer_ref=args.answer_ref, issued=issued, expires=expires, run_id=item["runs"][0], mode=item["mode"],
                                           scope_actions=item.get("scope_actions", SCOPE_ACTIONS)))
    print(json.dumps(printed, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
