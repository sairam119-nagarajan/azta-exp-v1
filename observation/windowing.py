"""Pure, deterministic device-time windowing over observer monotonic receive offsets.

Grid: window k is [coverage_start + k*W, coverage_start + (k+1)*W). W has no default and no
scientific value is selected in Gate 5B. Windows are a pure function of the event log, the
coverage interval, W and the window count, so replay() reproduces the live window records.
"""
from dataclasses import dataclass
import statistics

from observation.schema import BINDING_BASIS, MEASURES, OBSERVER_VERSION, SCHEMA_FINGERPRINT, SCHEMA_VERSION, \
    WINDOW_SCHEMA, expected_status, validate_window


@dataclass(frozen=True)
class WindowConfig:
    duration_ns: int
    window_count: int

    def __post_init__(self):
        if type(self.duration_ns) is not int or self.duration_ns <= 0:
            raise ValueError("window duration must be an explicit positive integer (ns); there is no default")
        if type(self.window_count) is not int or not 1 <= self.window_count <= 1_000_000:
            raise ValueError("window count must be an explicit integer in [1, 1000000]")


def classify(entry, retain, dup, offset_ns, coverage_start_ns, config, coverage_open=True):
    """Return (disposition, window_index). Precedence: unbound, coverage, retained, DUP, counted."""
    if entry is None:
        return "EXCLUDED_UNBOUND", None
    if coverage_start_ns is None or offset_ns < coverage_start_ns:
        return "EXCLUDED_PRE_COVERAGE", None
    index = (offset_ns - coverage_start_ns) // config.duration_ns
    if index >= config.window_count or not coverage_open:
        return "EXCLUDED_POST_COVERAGE", None
    if retain:
        return "EXCLUDED_RETAINED", index
    if dup:
        return "EXCLUDED_DUPLICATE", index
    return "COUNTED", index


def _entry(name, value, count, complete, has_history):
    status = expected_status(name, count, complete, has_history)
    return dict(value=value if status == "VALUE" else None, status=status)


def measures(counted, window_end_ns, last_offset_ns, complete):
    """counted: sorted [(offset_ns, payload_bytes)] in the window; last_offset_ns: latest counted
    offset before window end in this session (or None). Unavailable statistics stay None."""
    n = len(counted)
    sizes = [size for _, size in counted]
    gaps = [(b[0] - a[0]) / 1e6 for a, b in zip(counted, counted[1:])]
    values = dict(
        delivered_count=n,
        payload_bytes_mean=float(statistics.fmean(sizes)) if n >= 1 else None,
        payload_bytes_sd=float(statistics.stdev(sizes)) if n >= 2 else None,
        interarrival_mean_ms=float(statistics.fmean(gaps)) if n >= 2 else None,
        interarrival_sd_ms=float(statistics.stdev(gaps)) if n >= 3 else None,
        last_delivery_age_ms=(window_end_ns - last_offset_ns) / 1e6 if last_offset_ns is not None else None,
    )
    has_history = last_offset_ns is not None
    return {spec["name"]: _entry(spec["name"], values[spec["name"]], n, complete, has_history) for spec in MEASURES}


class WindowEngine:
    def __init__(self, registry, config, coverage_start_ns, header):
        self.registry, self.config, self.start = registry, config, coverage_start_ns
        self.header = dict(header)
        self.coverage_end_ns = None
        self.next_index = 0
        self.last = {entry.device: None for entry in registry.devices}
        self.pending = {}

    def bounds(self, index):
        start = self.start + index * self.config.duration_ns
        return start, start + self.config.duration_ns

    def add(self, event):
        if event["binding_status"] != "BOUND" or event["window_index"] is None:
            return
        if event["window_index"] < self.next_index:
            raise ValueError("event for an already closed window")
        bucket = self.pending.setdefault((event["window_index"], event["bound_device"]),
                                         dict(counted=[], dup=0, retained=0))
        if event["dup"]:
            bucket["dup"] += 1
        if event["disposition"] == "EXCLUDED_RETAINED":
            bucket["retained"] += 1
        elif event["disposition"] == "COUNTED":
            bucket["counted"].append((event["receive_offset_ns"], event["payload_bytes"]))

    def end_coverage(self, offset_ns):
        if self.coverage_end_ns is None:
            self.coverage_end_ns = max(offset_ns, self.start)

    def close(self, index):
        if index != self.next_index or index >= self.config.window_count:
            raise ValueError("windows close in order, once")
        start, end = self.bounds(index)
        covered_until = end if self.coverage_end_ns is None else min(end, self.coverage_end_ns)
        covered = max(0, covered_until - start)
        state = "COMPLETE" if covered == self.config.duration_ns else "NONE" if covered == 0 else "PARTIAL"
        records = []
        for entry in self.registry.devices:
            bucket = self.pending.pop((index, entry.device), dict(counted=[], dup=0, retained=0))
            counted = sorted(bucket["counted"])
            if counted:
                self.last[entry.device] = counted[-1][0]
            record = dict(
                schema=WINDOW_SCHEMA, schema_version=SCHEMA_VERSION, schema_fingerprint=SCHEMA_FINGERPRINT,
                observer_version=OBSERVER_VERSION, enforcement="NONE", device=entry.device,
                identity=dict(bound_username=entry.username, bound_client_id=entry.client_id,
                              binding_basis=BINDING_BASIS, binding_audit_ref=self.header["binding_audit_ref"],
                              registry_sha256=self.registry.sha256),
                window=dict(index=index, start_offset_ns=start, end_offset_ns=end,
                            duration_ns=self.config.duration_ns),
                coverage=dict(state=state, covered_ns=covered),
                measures=measures(counted, end, self.last[entry.device], state == "COMPLETE"),
                qc=dict(counted_events_raw=len(counted), dup_flagged_count=bucket["dup"],
                        retained_excluded_count=bucket["retained"]),
                **{k: self.header[k] for k in ("observation_config_sha256", "purpose", "observer_session_id",
                                               "collection_run_id")},
            )
            records.append(validate_window(record))
        self.next_index += 1
        return records


def replay(events, registry, config, coverage_start_ns, coverage_end_ns, header):
    """Recompute every window from the retained event log (determinism evidence)."""
    engine = WindowEngine(registry, config, coverage_start_ns, header)
    for event in sorted(events, key=lambda e: e["record_seq"]):
        engine.add(event)
    if coverage_end_ns is not None:
        engine.end_coverage(coverage_end_ns)
    windows = []
    for index in range(config.window_count):
        windows.extend(engine.close(index))
    return windows
