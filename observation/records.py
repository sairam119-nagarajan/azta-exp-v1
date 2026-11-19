"""Exclusive per-session evidence directory with flushed, validated JSONL streams."""
import hashlib
import json
from pathlib import Path

from observation.schema import validate_event, validate_health, validate_window

STREAMS = {"events": validate_event, "windows": validate_window, "health": validate_health}


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 16), b""):
            digest.update(block)
    return digest.hexdigest()


class ObservationRecords:
    def __init__(self, root, session_id):
        self.path = Path(root) / "observation" / session_id
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.mkdir(exist_ok=False)
        self.files = {}
        self.counts = {name: 0 for name in STREAMS}
        try:
            for name in STREAMS:
                self.files[name] = (self.path / f"{name}.jsonl").open("x", encoding="utf-8", newline="\n")
        except BaseException:
            self.close()
            raise

    def write(self, stream, record):
        STREAMS[stream](record)
        self.files[stream].write(json.dumps(record, sort_keys=True, allow_nan=False) + "\n")
        self.files[stream].flush()
        self.counts[stream] += 1

    def write_json(self, name, value):
        with (self.path / name).open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")

    def close(self):
        for stream in self.files.values():
            if not stream.closed:
                stream.close()

    def digests(self, names=("session_metadata.json", "events.jsonl", "windows.jsonl", "health.jsonl")):
        self.close()
        return {name: file_sha256(self.path / name) for name in names if (self.path / name).exists()}
