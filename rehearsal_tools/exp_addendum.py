"""Formal Experimental Validation (AZTA-EXP-v1, addendum 1): the manifest that fixes the measurement scripts and the experiment matrix BEFORE the reserved TEST runs are opened
(the supervisor's condition, 11 November 2026), and the combined release check.

    python -B -I rehearsal_tools/exp_addendum.py write      # configs/formal/AZTA-EXP-v1_formal_addendum_manifest.json (exclusive)
    python -B -I rehearsal_tools/exp_addendum.py verify     # freeze manifest + addendum manifest + no file added to a frozen directory + the matrix recomputes identically

The frozen release AZTA-EXP-v1 is not changed: every new script lives outside its pinned directories and files. The freeze manifest's own `verify` detects changed and missing files;
`verify_all` adds the check it lacks, a file ADDED to a frozen directory.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "rehearsal_tools")]

MANIFEST = "configs/formal/AZTA-EXP-v1_formal_addendum_manifest.json"
FREEZE = "configs/exp_v1/AZTA-EXP-v1_freeze_manifest.json"
SCRIPTS = ["rehearsal_tools/exp_matrix.py", "rehearsal_tools/exp_operator.py", "rehearsal_tools/exp_session.py", "rehearsal_tools/exp_validity.py", "rehearsal_tools/exp_campaign.py",
           "rehearsal_tools/exp_approve.py", "rehearsal_tools/exp_test_score.py", "rehearsal_tools/exp_aggregate.py", "rehearsal_tools/exp_addendum.py", "tests/test_exp_formal.py"]
DOCS = ["docs/final/AZTA_FORMAL_EXPERIMENT_PROTOCOL.md", "docs/final/AZTA_FORMAL_PROTOCOL_ADDENDUM_1.md", "docs/final/AZTA_FORMAL_PROTOCOL_ADDENDUM_2.md"]
ADDENDUM_1_SHA256 = "38105d9e5fbdfcf7d0a4b6f467f9d4801ab2c9ccc40bea171b0b11f59b868621"   # the manifest named by FORMAL_TEST_AUTHORIZATION (12 November 2026)
MATRIX = "configs/formal/exp_matrix_v1.json"
PY = str(ROOT / ".venv" / "Scripts" / "python.exe")


def sha(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def pinned_paths():
    m = json.loads((ROOT / MATRIX).read_text(encoding="utf-8"))
    paths = list(SCRIPTS) + list(DOCS) + [MATRIX]
    for run_id, spec in sorted(m["runs"].items()):
        paths += [f"configs/collection_plans/core_final_{run_id.replace('-', '_')}.json", f"configs/dev_perturbations/{run_id}.json"]
        if spec["mode"] == "shadow":
            paths.append(f"configs/formal/sessions/{run_id}.json")
    return paths


def freeze_check():
    out = subprocess.run([PY, "-B", "-I", "rehearsal_tools/stb_freeze_exp_v1.py", "verify", "--manifest", FREEZE], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
    text = out.stdout
    try:
        return json.loads(text[text.index("{"):])
    except ValueError:
        return dict(verified=False, problems=[f"freeze verify produced no result (exit {out.returncode})"])


def added_to_frozen_directories():
    import stb_freeze_exp_v1 as fz
    manifest = json.loads((ROOT / FREEZE).read_text(encoding="utf-8"))
    files, models = fz.file_set(json.loads((ROOT / manifest["operating_point"]["route"]).read_text(encoding="utf-8")))
    return sorted(set(files) - set(manifest["files"])) + sorted(set(models) - set(manifest["model_files"]))


def verify_all():
    problems = []
    freeze = freeze_check()
    problems += [f"FREEZE {p}" for p in freeze.get("problems", [])] + ([] if freeze.get("verified") else ["FREEZE not verified"] if not freeze.get("problems") else [])
    problems += [f"ADDED_TO_FROZEN {p}" for p in added_to_frozen_directories()]
    manifest_path = ROOT / MANIFEST
    if not manifest_path.exists():
        problems.append("ADDENDUM manifest missing")
    else:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest["freeze_manifest_sha256"] != sha(FREEZE):
            problems.append("ADDENDUM names another freeze manifest")
        for path, digest in manifest["files"].items():
            p = ROOT / path
            if not p.exists():
                problems.append(f"ADDENDUM MISSING {path}")
            elif sha(path) != digest:
                problems.append(f"ADDENDUM CHANGED {path}")
        unpinned = sorted(set(pinned_paths()) - set(manifest["files"]))
        problems += [f"ADDENDUM UNPINNED {p}" for p in unpinned]
    import exp_matrix
    if (ROOT / MATRIX).read_bytes() != exp_matrix.dump(exp_matrix.build()).encode("utf-8"):
        problems.append("MATRIX does not recompute identically")
    return dict(problems=problems, verified=not problems, freeze_manifest_sha256=sha(FREEZE), addendum_manifest_sha256=sha(MANIFEST) if manifest_path.exists() else None)


def write(supersede=None):
    """Exclusive creation; with `supersede`, the existing manifest is replaced only if it is exactly the addendum-1 manifest the owner's test authorization named (it stays in Git history)."""
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    files = {p: sha(p) for p in pinned_paths()}
    path = ROOT / MANIFEST
    if supersede and (supersede != ADDENDUM_1_SHA256 or not path.exists() or sha(MANIFEST) != supersede):
        raise SystemExit("REFUSED: --supersede must name the current manifest, and only the addendum-1 manifest may be superseded")
    document = dict(schema="azta.formal.addendum_manifest", schema_version=2 if supersede else 1, release="AZTA-EXP-v1",
                    addendum="formal experimental validation, addendum 2 (supersedes addendum-1 manifest " + supersede + ")" if supersede else "formal experimental validation, addendum 1",
                    freeze_manifest=FREEZE, freeze_manifest_sha256=sha(FREEZE), created_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), base_commit=head,
                    condition="fixed before the reserved TEST runs are opened; from then on no model, threshold or configuration change based on the experimental results",
                    files=files, **(dict(supersedes_sha256=supersede, amendment="docs/final/AZTA_FORMAL_PROTOCOL_ADDENDUM_2.md") if supersede else {}))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb" if supersede else "xb") as stream:
        stream.write((json.dumps(document, indent=1, sort_keys=True) + "\n").encode("utf-8"))
    print(json.dumps(dict(written=MANIFEST, sha256=sha(MANIFEST), files=len(files)), indent=1))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("write", "verify"))
    parser.add_argument("--supersede", default=None, help="write: replace the addendum-1 manifest of this sha256 (addendum 2)")
    args = parser.parse_args(argv)
    if args.command == "write":
        return write(args.supersede)
    result = verify_all()
    print(json.dumps(result, indent=1, sort_keys=True))
    return 0 if result["verified"] else 3


if __name__ == "__main__":
    sys.exit(main())
