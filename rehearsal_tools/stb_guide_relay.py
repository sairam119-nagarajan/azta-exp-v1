"""Relay of the owner guide (amendment 2, after stb-l02): prints every new complete line of `owner_guide.log`, exactly once and in order, by polling the file by byte position.

    python -I -B rehearsal_tools/stb_guide_relay.py --file results/engineering/pilot/stb-l03/owner_guide.log [--interval-s 1] [--max-s 1800]

Why polling: in stb-l02 a `tail -F` pipe under Git Bash on Windows delivered nothing while the driver appended to the file, so two instructions were relayed late. This reader opens the file
read-only for each poll (never holding it open, so it cannot lock out the writer), keeps the byte position, holds back a partial last line until its newline arrives, and treats a
missing or momentarily locked file as "nothing new yet". A file that stays unreadable is reported on stdout (`RELAY_WARNING`), so silence is never mistaken for "no instruction".
It reads only the guide; it writes nothing and acts on nothing.
"""
import argparse
from pathlib import Path
import sys
import time


class Relay:
    def __init__(self, path, *, warn_after=10):
        self.path, self.position, self.tail, self.failures, self.warn_after, self.warned = Path(path), 0, b"", 0, warn_after, False

    def poll(self):
        """New complete lines since the last poll (decoded, without the newline). A shrunk file (rotation) restarts from its beginning."""
        try:
            size = self.path.stat().st_size
            if size < self.position:
                self.position, self.tail = 0, b""
            with open(self.path, "rb") as stream:
                stream.seek(self.position)
                data = stream.read()
        except FileNotFoundError:
            return []
        except OSError:
            self.failures += 1
            if self.failures >= self.warn_after and not self.warned:
                self.warned = True
                return [f"RELAY_WARNING: {self.path.name} unreadable for {self.failures} polls"]
            return []
        self.failures, self.warned = 0, False
        self.position += len(data)
        *lines, self.tail = (self.tail + data).split(b"\n")
        return [line.rstrip(b"\r").decode("utf-8", "replace") for line in lines if line.strip()]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--file", required=True)
    parser.add_argument("--interval-s", type=float, default=1.0)
    parser.add_argument("--max-s", type=float, default=1800.0)
    args = parser.parse_args(argv)
    relay, deadline = Relay(args.file), time.monotonic() + args.max_s
    while time.monotonic() < deadline:
        for line in relay.poll():
            print(line, flush=True)
        time.sleep(args.interval_s)
    print("RELAY_ENDED max-s reached", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
