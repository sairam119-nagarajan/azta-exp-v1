"""Formal Experimental Validation (AZTA-EXP-v1, addendum 1): the validity verdict of ONE formal run, from its own durable records, under the void and stop rules declared in the
experiment matrix BEFORE any formal data. It reads no metric and no prediction: a run is never voided because of its results.

    python -B -I rehearsal_tools/exp_validity.py --run exp-s01 [--as exp-sNN] [--out FILE]

VALID  every check holds.
VOID   an infrastructure check failed (preconditions, launcher/driver/workload/observer, binding audits, an unapplied scenario command, or, in an active run, a cancelled owner
       instruction or abandoned episodes). The run is kept and reported, and replaced once by its spare.
STOP   a safety check failed: enforcement in a shadow run, a PEP outcome outside device02 or a failed outcome, the final policy is not the baseline, a restoration failure, or a
       changed protected fingerprint. The campaign does not continue.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "rehearsal_tools")]

MATRIX = "configs/formal/exp_matrix_v1.json"
BASELINE = "3e6c25881bc1846036fa27445001f0a69f39e6dd85bc5e137048a78c03179c7b"


def jsonl(path):
    path = Path(path)
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out


def load(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def validity(run_id, as_run=None, root=ROOT):
    m = json.loads((root / MATRIX).read_text(encoding="utf-8"))
    spec = m["runs"][as_run or run_id]
    shadow = spec["mode"] == "shadow"
    run_dir = root / "results/engineering/runs" / run_id
    out_dir = root / "results/engineering/pilot" / run_id
    side = root / "results/engineering/pilot" / f"{run_id}-session"
    pre = load(root / "results/engineering/formal" / f"preconditions_{run_id}.json")
    summary = load(side / "session_run.json")
    post = load(out_dir / "post_state.json") or load(side / "post_state.json")
    log_path = run_dir / "logs" / "orchestrator.log"
    log = log_path.read_text(encoding="utf-8", errors="replace").splitlines() if log_path.exists() else []
    audits = [line for line in log if " audit-" in line]
    sessions = [p for p in (run_dir / "observation").iterdir() if p.is_dir()] if (run_dir / "observation").is_dir() else []
    observer_complete = len(sessions) == 1 and load(sessions[0] / "session_summary.json").get("state") == "COMPLETE"
    events = jsonl(run_dir / "control" / "events.jsonl")
    applied = [(e.get("device"), e.get("anomaly")) for e in events if e.get("kind") == "COMMAND_APPLIED" and e.get("action") == "start"]
    rejected = [e for e in events if e.get("kind") == "COMMAND_REJECTED"]
    timeline = jsonl(out_dir / "operator_timeline.jsonl")
    ended = [t for t in timeline if t.get("step") == "SCENARIO_ENDED"]
    pep = jsonl(run_dir / "pep" / "continuous.jsonl")
    outcomes = [e for e in pep if e.get("kind") == "OUTCOME"]
    planned = [(e["device"], e["kind"]) for e in spec["episodes"] if e["kind"] not in ("context",)] if shadow else []
    infra = dict(
        preconditions_verified=pre.get("all_pass") is True,
        launcher_and_driver_exit_0=summary.get("launcher_exit") == 0 and summary.get("driver_exit") == 0 and summary.get("coverage_reached") is True,
        workload_and_observer_clean=any("observer_failed=False observer_exit=0 workload_exit=0" in line for line in log),
        every_binding_audit_passed=bool(audits) and all("BINDING_AUDIT PASS" in line for line in audits),
        observer_session_complete=observer_complete,
        scenario_driver_not_halted=bool(ended) and ended[-1].get("halted") is False,
        no_rejected_command=not rejected)
    if shadow:
        infra["every_planned_episode_applied"] = all(p in applied for p in planned)
    else:
        starts = [t for t in timeline if t.get("step") == "EPISODE_START"]
        infra.update(every_planned_episode_started=len(starts) == len(spec["episodes"]),
                     no_cancelled_owner_instruction=not any(t.get("step") == "INSTRUCTION_CANCELLED" for t in timeline),
                     no_abandoned_episodes=not any(t.get("step") == "EPISODES_ABANDONED" for t in timeline))
    safety = dict(
        final_policy_is_the_baseline=post.get("final_audit_policy_sha256") == BASELINE and post.get("final_audit_pass") is True,
        stack_down_volume_kept=post.get("down_exit") == 0 and post.get("down_used_v") is False and post.get("volume_kept") is True,
        protected_fingerprints_unchanged=post.get("protected_fingerprints_unchanged") is True,
        no_restoration_failure=not (out_dir / "restoration_failed_STOP.json").exists() and not (side / "restoration_failed_STOP.json").exists())
    if shadow:
        safety["every_audit_digest_is_the_baseline"] = all(f"policy_sha256={BASELINE}" in line for line in audits)    # vacuous when no traffic ran (e.g. a refused clock certificate): that run is VOID, not STOP
        safety["zero_enforcement_in_shadow"] = not any(e.get("kind") in ("REQUEST_RECEIVED", "COMMAND_SENT", "OUTCOME") for e in pep) and summary.get("policy_changed_in_shadow") is False
    else:
        safety.update(outcomes_only_on_device02=all((o.get("body") or {}).get("device") == "device02" for o in outcomes),
                      no_failed_outcome=all((o.get("body") or {}).get("status") in ("APPLIED_VERIFIED", "NOOP_ALREADY_IN_STATE") for o in outcomes))
    probes_ok = post.get("post_probes_ok") is True
    status = "STOP" if not all(safety.values()) else "VOID" if not (all(infra.values()) and probes_ok) else "VALID"
    return dict(schema="azta.formal.run_validity", run_id=run_id, as_run=as_run, component=spec["component"], mode=spec["mode"], status=status,
                failed=[k for k, v in {**infra, **safety}.items() if not v] + ([] if probes_ok else ["post_probes_ok"]), infrastructure=infra, safety=safety, post_probes_ok=probes_ok)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", required=True)
    parser.add_argument("--as", dest="as_run", default=None)
    parser.add_argument("--out", default=None)
    args = parser.parse_args(argv)
    result = validity(args.run, args.as_run)
    if args.out:
        with (ROOT / args.out).open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(result, stream, indent=1, sort_keys=True)
            stream.write("\n")
    print(json.dumps(result, indent=1, sort_keys=True))
    return 0 if result["status"] == "VALID" else 1 if result["status"] == "VOID" else 4


if __name__ == "__main__":
    sys.exit(main())
