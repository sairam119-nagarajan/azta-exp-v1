"""Read-only verification of finished live ledgers: the hash chain end to end (the adapter's own `LiveLedger.open_existing`), the exported views re-derived from
the ledger byte for byte, and `live_manifest.json` against both. Nothing is written, no observation is opened and no Docker is touched.

usage: python -I -B rehearsal_tools/verify_ledgers.py <live_dir> [<live_dir> ...]      (prints one JSON report; exit 0 only if every ledger is intact)
"""
import hashlib
import json
from collections import Counter
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO)]

from shadow_live.errors import LiveIntegrityFailure, LiveRefused    # noqa: E402
from shadow_live.ledger import LiveLedger                            # noqa: E402
from shadow_live.session import _blob                                # noqa: E402  (the exact serialiser of the exported views)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def verify(directory):
    directory = Path(directory)
    try:
        ledger = LiveLedger.open_existing(directory)
    except (LiveIntegrityFailure, LiveRefused) as exc:
        return dict(live_dir=str(directory), chain="BROKEN", error=f"{type(exc).__name__}: {exc}", ok=False)
    ledger_bytes = (directory / "ledger.jsonl").read_bytes()
    report = dict(live_dir=str(directory), chain="INTACT", entries=len(ledger.entries), entry_kinds=dict(Counter(e["kind"] for e in ledger.entries)),
                  head_sha256=ledger.head_sha256, ledger_file_sha256=sha256(ledger_bytes), ledger_bytes=len(ledger_bytes), ended=bool(ledger.of_kind("SESSION_ENDED")))
    checks = {}
    manifest_path = directory / "live_manifest.json"
    if ledger.of_kind("SESSION_ENDED") and manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        outputs = [item for entry in ledger.entries if entry["kind"] in ("POLL", "SESSION_ENDED") for item in entry["body"]["outputs"]]
        derived = {"decisions.jsonl": _blob(outputs, "record"), "timing.jsonl": _blob(outputs, "timing")}
        checks["manifest_ledger_entries"] = manifest["ledger"]["entries"] == len(ledger.entries)
        checks["manifest_ledger_head"] = manifest["ledger"]["head_sha256"] == ledger.head_sha256
        checks["manifest_ledger_file_sha256"] = manifest["ledger"]["file_sha256"] == report["ledger_file_sha256"]
        checks["manifest_record_count"] = manifest["record_count"] == len(outputs)
        for name, info in manifest["outputs"].items():
            data = (directory / name).read_bytes()
            checks[f"{name}_matches_manifest"] = (sha256(data), len(data)) == (info["sha256"], info["bytes"])
            if name in derived:
                checks[f"{name}_equals_re_derivation_from_ledger"] = data == derived[name]
        checks["end_reason_matches"] = manifest["end"]["reason"] == ledger.of_kind("SESSION_ENDED")[0]["body"]["reason"]
        report["end_reason"] = manifest["end"]["reason"]
        report["record_count"] = manifest["record_count"]
    report["checks"] = checks
    report["ok"] = all(checks.values())
    return report


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    reports = [verify(directory) for directory in argv]
    print(json.dumps(reports, indent=1, sort_keys=True))
    return 0 if all(r["ok"] for r in reports) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
