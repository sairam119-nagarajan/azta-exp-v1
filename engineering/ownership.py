"""Process-lifetime OS lease; stale files do not imply a live owner."""
import os


class Lease:
    def __init__(self, path):
        self.path, self.handle = path, None

    def __enter__(self):
        self.handle = open(self.path, "a+b")
        self.handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.handle.close()
            self.handle = None
            raise ValueError("another process owns this worker's durable state") from None
        return self

    def __exit__(self, *exc):
        if self.handle:
            self.handle.close()
            self.handle = None
