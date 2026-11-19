"""Durable, byte-preserving projection of committed live-ledger outputs.

The Shadow adapter keeps its null sink. Only outputs already committed with
their source cursor enter the separate enforcement inbox. Atomic replacement
repairs an interrupted projection without truncating a consumed prefix.
"""
import json
import os
from pathlib import Path
import time

from shadow_live.errors import LiveIntegrityFailure


def project(ledger, inbox):
    records = [out["record"] for entry in ledger.entries
               if entry["kind"] in ("POLL", "SESSION_ENDED")
               for out in entry["body"]["outputs"]]
    blob = b"".join((json.dumps(r, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8") for r in records)
    inbox = Path(inbox)
    previous = inbox.read_bytes() if inbox.exists() else b""
    if not blob.startswith(previous) or (previous and not previous.endswith(b"\n")):
        raise LiveIntegrityFailure("HANDOFF_PREFIX_CHANGED", "the inbox is not a complete prefix of committed ledger outputs")
    if previous == blob and inbox.exists():
        return len(records)
    temporary = inbox.with_suffix(inbox.suffix + ".tmp")
    with open(temporary, "wb") as stream:
        stream.write(blob)
        stream.flush()
        os.fsync(stream.fileno())
    # Docker Desktop/Windows readers can briefly deny FILE_SHARE_DELETE.
    # Retry only the atomic rename, never append duplicate bytes or advance a
    # separate cursor. A persistent denial remains a visible terminal failure.
    for attempt in range(20):
        try:
            os.replace(temporary, inbox)
            break
        except PermissionError:
            if attempt == 19:
                raise
            time.sleep(0.05)
    return len(records)
