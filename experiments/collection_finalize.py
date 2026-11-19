"""Gate 5C finalize: append exactly one RUN_COLLECTED (ACCEPT) or RUN_VOIDED (VOID) per reconciled run.

Append-only through observation.manifest.append(), which re-validates the whole chain and every
artifact digest. Evidence is never deleted or rewritten; a voided run ID is never reused. A
NOT_STARTED run (no observer session, no publish attempt) records nothing and stays planned.
`invalidate` appends a controller-decided RUN_INVALIDATED for an already collected run (post-collection
scientific invalidation); the RUN_COLLECTED entry and its evidence stay unchanged.
Also builds the final benign data inventory. No model, scaling, imputation or threshold here.

Effective scientific state: RUN_PLANNED only = pending; RUN_COLLECTED without a later RUN_INVALIDATED =
accepted; RUN_COLLECTED + RUN_INVALIDATED = preserved but excluded from accepted counts; RUN_VOIDED =
pre/post-run failure (never collected).
"""
import argparse
import json
from pathlib import Path
import sys

from experiments import collection_plan as plans
from experiments.collection_reconcile import audit_paths
from observation import manifest as manifest_module
from observation.records import file_sha256
from observation.registry import DeviceRegistry
from observation.schema import SCHEMA_FINGERPRINT

INVENTORY_SCHEMA = "azta.collection.inventory"


def utc_now():
    from experiments.research_records import utc_now as now
    return now()


def _json(path):
    with Path(path).open(encoding="utf-8") as stream:
        return json.load(stream)


def artifacts(root, run_id, session_id, devices):
    root = Path(root)
    items = [(f"observer_{name.split('.')[0]}", f"observation/{session_id}/{name}")
             for name in ("session_metadata.json", "session_summary.json", "events.jsonl", "windows.jsonl", "health.jsonl")]
    items += [("workload_metadata", f"collection/{run_id}/workload_metadata.json"),
              ("workload_summary", f"collection/{run_id}/workload_summary.json")]
    items += [(f"publisher_ledger_{d}", f"collection/{run_id}/ledger_{d}.jsonl") for d in sorted(devices)]
    items += [("reconciliation", f"collection/{run_id}/reconciliation.json")]
    items += [(f"binding_audit_{stage}", path.relative_to(root).as_posix()) for stage, path in audit_paths(root, run_id).items()]
    return [dict(role=role, path=path, sha256=file_sha256(root / path)) for role, path in items]


def record(*, manifest_path, plan, run_id, root, now=None):
    """Append the result entry dictated by the run's reconciliation report. Returns the entry or None."""
    root = Path(root)
    now = now or utc_now()
    report_path = root / "collection" / run_id / "reconciliation.json"
    report = _json(report_path)
    if report.get("run_id") != run_id or report.get("purpose") != "COLLECTION":
        raise ValueError("reconciliation report does not belong to this COLLECTION run")
    if report.get("plan_sha256") != plans.digest(plan):
        raise ValueError("reconciliation report was made against a different plan")
    state = manifest_module.validate(manifest_module.read_entries(manifest_path), root)
    plans.check_manifest_against_plan(state, plan)
    planned = state["planned"].get(run_id)
    if planned is None or run_id in state["collected"] or run_id in state["voided"]:
        raise ValueError("run is not planned, or already collected/voided")
    verdict = report.get("verdict")
    if verdict == "NOT_STARTED":
        return None
    report_sha = file_sha256(report_path)
    if verdict == "ACCEPT":
        session = root / "observation" / report["observer_session_id"]
        meta, summary = _json(session / "session_metadata.json"), _json(session / "session_summary.json")
        attestation = meta["collection_attestation"]
        audits = report["binding_audits"]
        body = dict(
            collection_run_id=run_id, planned_entry_sha256=planned["entry_sha256"],
            observer_session_id=report["observer_session_id"], observation_purpose=meta["purpose"],
            collection_git_commit=attestation["git_commit"], collection_git_state=meta["runtime"]["git_state"],
            manifest_sha256_at_collection=attestation["manifest_sha256"],
            observation_schema_fingerprint=SCHEMA_FINGERPRINT, observation_config_sha256=meta["observation_config_sha256"],
            artifacts=artifacts(root, run_id, report["observer_session_id"], plan["runs"][run_id]["devices"]),
            binding_audit_pre=audits["pre"], binding_audit_post=audits["post"], session_state=summary["state"],
            collected_utc=now)
        return manifest_module.append(manifest_path, "RUN_COLLECTED", body, artifact_root=root)
    if verdict == "VOID":
        reason = (f"VOID: failed checks [{', '.join(report.get('reasons') or ['unspecified'])}]; "
                  f"campaign_stop={report.get('campaign_stop')}; observer_session={report.get('observer_session_id')}; "
                  f"report collection/{run_id}/reconciliation.json sha256={report_sha}; all evidence preserved")
        return manifest_module.append(manifest_path, "RUN_VOIDED", dict(collection_run_id=run_id, reason=reason,
                                                                        voided_utc=now), artifact_root=root)
    raise ValueError(f"unknown verdict {verdict!r}")


def _relative_evidence(root, items):
    evidence = []
    for role, path in items:
        relative = str(path).replace("\\", "/")
        if not manifest_module.RELATIVE_PATH.fullmatch(relative) or not manifest_module.EVIDENCE_ROLE.fullmatch(role):
            raise ValueError(f"evidence must be role=relative/path under the results root: {role}={path}")
        target = Path(root) / relative
        if not target.is_file():
            raise ValueError(f"evidence file missing: {relative}")
        evidence.append(dict(role=role, path=relative, sha256=file_sha256(target)))
    return evidence


def invalidate(*, manifest_path, plan, run_id, reason_code, reason, evidence, replacement_run_id, root, now=None):
    """Append RUN_INVALIDATED for a collected run (controller scientific-validity decision only).

    evidence: [(role, path relative to root)]. replacement_run_id: a preplanned SUBSTITUTE cell with the
    same partition AND plan (A/B) as the invalidated run, or None. Nothing is rewritten or deleted.
    """
    root = Path(root)
    state = manifest_module.validate(manifest_module.read_entries(manifest_path), root)
    plans.check_manifest_against_plan(state, plan)
    cells = {c["run_id"]: c for c in plan["cells"]}
    if run_id not in state["collected"]:
        raise ValueError("only a RUN_COLLECTED run can be invalidated")
    if run_id in state["invalidated"]:
        raise ValueError("run already invalidated")
    if replacement_run_id is not None:
        original, substitute = cells[run_id], cells.get(replacement_run_id)
        if substitute is None or substitute["role"] != "SUBSTITUTE":
            raise ValueError("replacement must be a preplanned SUBSTITUTE cell")
        if (substitute["intended_partition"], substitute["plan"]) != (original["intended_partition"], original["plan"]):
            raise ValueError(f"replacement {replacement_run_id} is {substitute['intended_partition']}/{substitute['plan']}; "
                             f"{run_id} needs {original['intended_partition']}/{original['plan']}")
        if replacement_run_id in state["replacements"]:
            raise ValueError("substitute already replaces another run")
        if replacement_run_id in state["voided"] or replacement_run_id in state["invalidated"]:
            raise ValueError("substitute is voided or invalidated")
    body = dict(collection_run_id=run_id, collected_entry_sha256=state["collected"][run_id]["entry_sha256"],
                decision_authority=manifest_module.INVALIDATION_AUTHORITY, reason_code=reason_code, reason=reason,
                evidence=_relative_evidence(root, evidence), replacement_run_id=replacement_run_id,
                invalidated_utc=now or utc_now())
    return manifest_module.append(manifest_path, "RUN_INVALIDATED", body, artifact_root=root)


def _jsonl(path):
    with Path(path).open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def _replacement_map(state, cells):
    """One substitute per excluded original: explicit RUN_INVALIDATED links first, then voided originals
    take the first unassigned SUBSTITUTE cell of the same partition and plan (plan order)."""
    assigned, rows = {}, []
    for run, entry in state["invalidated"].items():
        if entry["replacement_run_id"] is not None:
            assigned[entry["replacement_run_id"]] = run
    substitutes = [c for c in cells.values() if c["role"] == "SUBSTITUTE"]
    for run in list(state["invalidated"]) + list(state["voided"]):
        cell = cells[run]
        if run in state["invalidated"] and state["invalidated"][run]["replacement_run_id"] is not None:
            rows.append(dict(original=run, substitute=state["invalidated"][run]["replacement_run_id"], basis="EXPLICIT"))
            continue
        match = next((c["run_id"] for c in substitutes if c["run_id"] not in assigned and c["run_id"] != run
                      and (c["intended_partition"], c["plan"]) == (cell["intended_partition"], cell["plan"])), None)
        if match is not None:
            assigned[match] = run
        rows.append(dict(original=run, substitute=match, basis="IMPLICIT_CELL_MATCH" if match else "NO_SUBSTITUTE_AVAILABLE"))
    return rows, assigned


def inventory(*, manifest_path, plan, root):
    """Final benign data inventory derived ONLY from the manifest; unreferenced sessions are listed.

    Invalidated runs stay visible with all counts but never enter the accepted totals."""
    root = Path(root)
    state = manifest_module.validate(manifest_module.read_entries(manifest_path), root)
    plans.check_manifest_against_plan(state, plan)
    cells = {c["run_id"]: c for c in plan["cells"]}
    first, last = plan["window_roles"]["eligible"]
    runs, referenced = [], set()
    totals = {}

    def status(run_id):
        if run_id in state["invalidated"]:
            return "INVALIDATED"
        if run_id in state["collected"]:
            return "ACCEPTED"
        return "VOIDED" if run_id in state["voided"] else "PENDING"
    for run_id, entry in state["collected"].items():
        cell = cells[run_id]
        session = entry["observer_session_id"]
        referenced.add(session)
        windows = _jsonl(root / "observation" / session / "windows.jsonl")
        events = _jsonl(root / "observation" / session / "events.jsonl")
        eligible = [w for w in windows if first <= w["window"]["index"] <= last]
        devices = sorted({w["device"] for w in windows})
        row = dict(run_id=run_id, role=cell["role"], intended_partition=cell["intended_partition"], plan=cell["plan"],
                   status=status(run_id), collected_entry_sha256=entry["entry_sha256"], observer_session_id=session,
                   collection_git_commit=entry["collection_git_commit"],
                   policy_sha256=dict(pre=entry["binding_audit_pre"]["policy_sha256"],
                                      post=entry["binding_audit_post"]["policy_sha256"]),
                   device_window_records=len(windows), eligible_device_window_records=len(eligible),
                   per_device={d: dict(counted_events=sum(1 for e in events if e["bound_device"] == d
                                                          and e["disposition"] == "COUNTED"),
                                       eligible_windows=sum(1 for w in eligible if w["device"] == d),
                                       eligible_windows_complete=sum(1 for w in eligible if w["device"] == d
                                                                     and w["coverage"]["state"] == "COMPLETE"))
                               for d in devices})
        invalid = state["invalidated"].get(run_id)
        if invalid is not None:
            row["invalidation"] = dict(entry_sha256=invalid["entry_sha256"], reason_code=invalid["reason_code"],
                                       reason=invalid["reason"], decision_authority=invalid["decision_authority"],
                                       replacement_run_id=invalid["replacement_run_id"])
        runs.append(row)
        if row["status"] != "ACCEPTED":
            continue
        bucket = totals.setdefault(cell["intended_partition"], dict(runs=0, eligible_device_window_records=0, plans={}))
        bucket["runs"] += 1
        bucket["eligible_device_window_records"] += len(eligible)
        bucket["plans"][cell["plan"]] = bucket["plans"].get(cell["plan"], 0) + 1
    replacements, assigned = _replacement_map(state, cells)
    for item in replacements:
        item["substitute_status"] = status(item["substitute"]) if item["substitute"] else None
    unassigned = sorted(run for run, cell in cells.items() if cell["role"] == "SUBSTITUTE"
                        and status(run) == "ACCEPTED" and run not in assigned)
    required = plan.get("allocation")
    accepted_counts = {part: dict(bucket["plans"]) for part, bucket in totals.items()}
    unused = sorted(set(cells) - set(state["collected"]) - set(state["voided"]))
    sessions = sorted(p.name for p in (root / "observation").glob("obs-*") if p.is_dir())
    return dict(schema=INVENTORY_SCHEMA, schema_version=2, plan_id=plan["plan_id"], plan_sha256=plans.digest(plan),
                manifest_id=state["header"]["manifest_id"], eligible_window_indices=[first, last], collected=runs,
                voided={r: e["reason"] for r, e in state["voided"].items()},
                invalidated={r: e["reason_code"] for r, e in state["invalidated"].items()},
                replacements=replacements, unassigned_accepted_substitutes=unassigned, planned_unused=unused,
                accepted_partition_totals=totals, required_allocation=required,
                accepted_counts_match_required=(accepted_counts == required) if required is not None else None,
                unreferenced_observer_sessions=[s for s in sessions if s not in referenced],
                note=("Only manifest-referenced RUN_COLLECTED sessions without a later RUN_INVALIDATED are accepted "
                      "Gate 5C data; invalidated runs are preserved and listed but excluded; everything else is not data."))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    rec = sub.add_parser("record")
    rec.add_argument("--run-id", required=True)
    inv = sub.add_parser("inventory")
    inv.add_argument("--out", required=True)
    bad = sub.add_parser("invalidate", help="controller scientific-validity decision only")
    bad.add_argument("--run-id", required=True)
    bad.add_argument("--reason-code", required=True)
    bad.add_argument("--reason", required=True)
    bad.add_argument("--evidence", action="append", default=[], required=True,
                     help="role=path relative to --root (repeatable)")
    bad.add_argument("--replacement-run-id")
    for item in (rec, inv, bad):
        item.add_argument("--manifest", required=True)
        item.add_argument("--plan", required=True)
        item.add_argument("--registry", default="/app/configs/observation/device_registry.json")
        item.add_argument("--root", default="/results")
    args = parser.parse_args(argv)
    try:
        registry = DeviceRegistry.load(args.registry)
        plan = plans.validate_plan(plans.load_plan(args.plan), registry)
        if args.action == "record":
            entry = record(manifest_path=args.manifest, plan=plan, run_id=args.run_id, root=args.root)
            manifest_module.validate(manifest_module.read_entries(args.manifest), args.root)
            kind = entry["entry_type"] if entry else "NOTHING_RECORDED_NOT_STARTED"
            print(f"FINALIZED {args.run_id} {kind}" + (f" entry_sha256={entry['entry_sha256']}" if entry else ""))
            return 0 if entry and kind == "RUN_COLLECTED" else 4 if entry else 3
        if args.action == "invalidate":
            pairs = []
            for text in args.evidence:
                role, sep, path = text.partition("=")
                if not sep:
                    raise ValueError("evidence must be role=path")
                pairs.append((role, path))
            entry = invalidate(manifest_path=args.manifest, plan=plan, run_id=args.run_id, reason_code=args.reason_code,
                               reason=args.reason, evidence=pairs, replacement_run_id=args.replacement_run_id,
                               root=args.root)
            manifest_module.validate(manifest_module.read_entries(args.manifest), args.root)
            print(f"INVALIDATED {args.run_id} replacement={args.replacement_run_id} entry_sha256={entry['entry_sha256']}")
            return 0
        result = inventory(manifest_path=args.manifest, plan=plan, root=args.root)
        with Path(args.out).open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write("\n")
        print(f"INVENTORY {args.out} collected={len(result['collected'])} voided={len(result['voided'])}")
        return 0
    except (ValueError, OSError, KeyError, manifest_module.ManifestError) as exc:
        print(f"FINALIZE_ERROR {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
