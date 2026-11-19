"""Clocks. Only DIFFERENCES of the monotonic reading are meaningful (its origin is arbitrary); the UTC reading is the adjustable host clock."""
import time


class SystemClock:
    kind = "SYSTEM"

    def utc_ns(self):
        return time.time_ns()

    def monotonic_ns(self):
        return time.perf_counter_ns()


class SyntheticClock:
    kind = "SYNTHETIC"

    def __init__(self, utc_ns, monotonic_ns=0):
        self._utc, self._mono = int(utc_ns), int(monotonic_ns)

    def advance(self, ns):
        self._utc += ns
        self._mono += ns

    def utc_ns(self):
        return self._utc

    def monotonic_ns(self):
        return self._mono
