"""Check that this repository is the frozen AZTA-EXP-v1 release.

    python verify_freeze.py

Recomputes the SHA-256 of every file pinned by the freeze manifest and the formal-addendum manifest, and of every frozen model file, and
compares them with the pinned digests. Files deliberately changed for publication are listed in REDACTIONS.json with their original
digests and are reported separately. Exit code 0 means every other pinned file is byte-identical to the frozen release.
"""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def entries(files):
    if isinstance(files, dict):
        return {k: (v if isinstance(v, str) else v["sha256"]) for k, v in files.items()}
    return {x["path"]: x["sha256"] for x in files}


def main():
    red = json.loads((ROOT / "REDACTIONS.json").read_text(encoding="utf-8"))
    freeze_path, addendum_path = ROOT / red["freeze_manifest"], ROOT / red["addendum_manifest"]
    problems = []
    man = red["manifests"]
    for path in (freeze_path, addendum_path):
        rec = man[path.relative_to(ROOT).as_posix()]
        if sha(path) != rec["published_sha256"]:
            problems.append(f"MANIFEST CHANGED {path.relative_to(ROOT).as_posix()}")
    freeze_original = man[red["freeze_manifest"]]["original_sha256"]
    freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
    addendum = json.loads(addendum_path.read_text(encoding="utf-8"))
    if addendum.get("freeze_manifest_sha256") not in (None, freeze_original):
        problems.append("ADDENDUM DOES NOT BIND THIS FREEZE MANIFEST")
    pinned = entries(freeze["files"])
    pinned.update(entries(addendum["files"]))
    counts = dict(identical=0, redacted=0, withheld=0)
    for rel, want in sorted(pinned.items()):
        p = ROOT / rel
        r = red["files"].get(rel)
        if r and r["action"] == "WITHHELD":
            counts["withheld"] += 1
            if p.exists():
                problems.append(f"WITHHELD FILE PRESENT {rel}")
            continue
        if not p.exists():
            problems.append(f"MISSING {rel}")
            continue
        got = sha(p)
        if r and r["action"] == "REDACTED":
            counts["redacted"] += 1
            if r["original_sha256"] != want or got != r["published_sha256"]:
                problems.append(f"REDACTED FILE DIFFERS FROM ITS RECORD {rel}")
        elif got == want:
            counts["identical"] += 1
        else:
            problems.append(f"CHANGED {rel}")
    models_ok = 0
    for rel, want in sorted(freeze["model_files"].items()):
        p = ROOT / rel
        if p.exists() and sha(p) == want:
            models_ok += 1
        else:
            problems.append(f"MODEL {rel}")
    print(f"release            : {freeze.get('release')}  (original freeze manifest sha256 {freeze_original})")
    if man[red["freeze_manifest"]].get("reason"):
        print(f"freeze manifest    : published with one redaction ({man[red['freeze_manifest']]['reason']})")
    print(f"pinned files       : {len(pinned)}")
    print(f"  byte-identical   : {counts['identical']}")
    print(f"  redacted (listed): {counts['redacted']}")
    print(f"  withheld (listed): {counts['withheld']}")
    print(f"frozen model files : {models_ok} of {len(freeze['model_files'])} byte-identical")
    print(f"verification records pinned by the freeze but not published (raw evidence): {len(freeze.get('verification_evidence', []))}")
    for p in problems:
        print("PROBLEM:", p)
    print("RESULT:", "VERIFIED" if not problems else "NOT VERIFIED")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
