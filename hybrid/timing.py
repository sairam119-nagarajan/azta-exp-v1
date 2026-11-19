"""Contract-based timing and payload monitor TM-1: lightweight, interpretable evidence for devices whose traffic is too sparse for a three-message window.

It reads the six Gate 5B measures of an ordinary 10 s window (so it needs no new observer output and runs on the live window stream) and compares them with the device's BENIGN ENVELOPE, a
timing contract derived from the TRAIN and VAL events only. Six categories, each an explicit relative exceedance E >= 0 of one bound (0 inside the envelope):

  rate                  E_rate  = max(0, n / n_hi - 1)                          n = messages in the window, n_hi = largest benign count per window
  short gap / burst     E_short = max(0, L / g - 1), L = (1 - rho) g_lo          n >= 2: g = mean inter-arrival of the window (an exact gap when n = 2), g_lo = smallest benign gap
  timing variability    E_var   = max(0, sd / sd_cap - 1)                       n >= 3: sd_cap = max((1 + rho) x largest benign window SD, tolerance)
  payload               E_pay   = max(0, p / p_hi - 1, p_lo / p - 1)            p = mean payload of the window, [p_lo, p_hi] the benign payload range
  long gap / missing    E_over  = max(0, age_eff / U - 1), U = (1 + rho) g_hi + tolerance  age_eff = time since the last delivery of THIS policy generation (see below)
  (variability of sparse devices is not observable at n < 3: stated, not hidden)

E = max over the SCORED indicators and A_T = kappa x E (kappa = 10: exceeding the benign envelope by a factor of two corresponds to A = 10, beyond the QUARANTINE-equivalent magnitude 9.16 of the
unchanged weights; a documented scale constant, not fitted). S_B = 100 exp(-lambda A_T) exactly as for the autoencoder, so the engine, the weights, the thresholds and N = 2 are unchanged.
rho (envelope margin) and tolerance are explicit contract values declared before the evaluation; they are not fitted to any attack outcome.

SILENCE IS NOT AUTOMATICALLY EVIDENCE. `silence_policy` is part of the contract. OVERDUE_IS_EVIDENCE is allowed only for a device whose contract bounds the gap (a scheduled sensor, or an event law with a declared maximum
gap); INFORMATIONAL reports the overdue ratio but does not score it (a genuinely event-triggered sensor may stay silent for hours). Silence is also never evidence when it is not the device's own:
a window with incomplete observer coverage is MISSING (observer outage), a device with no delivery yet in the session is MISSING (start-up), and the age is measured from the later of the last
delivery and the start of the device's current policy generation (the last PEP-verified policy change for it), so the silence of a quarantined and then restored device is not a "missing report".
MQTT keep-alive packets are not application deliveries and are not counted by the observer.
"""
from dataclasses import dataclass
import math
import statistics

KAPPA = 10.0
OVERDUE_IS_EVIDENCE, INFORMATIONAL = "OVERDUE_IS_EVIDENCE", "INFORMATIONAL"
NS = 1_000_000_000


@dataclass(frozen=True)
class TimingContract:
    device: str
    gap_lo_ms: float
    gap_hi_ms: float
    count_hi: int
    sd_cap_ms: float
    payload_lo: float
    payload_hi: float
    silence_policy: str
    rho: float
    tolerance_ms: float
    kappa: float = KAPPA

    def __post_init__(self):
        if self.silence_policy not in (OVERDUE_IS_EVIDENCE, INFORMATIONAL):
            raise ValueError("unknown silence policy")
        if not (0 < self.rho < 1 and self.tolerance_ms > 0 and self.kappa > 0 and self.gap_lo_ms > 0 and self.gap_hi_ms >= self.gap_lo_ms and self.count_hi >= 1):
            raise ValueError("invalid timing contract")

    def to_dict(self):
        return {k: getattr(self, k) for k in ("device", "gap_lo_ms", "gap_hi_ms", "count_hi", "sd_cap_ms", "payload_lo", "payload_hi", "silence_policy", "rho", "tolerance_ms", "kappa")}


def derive_contract(device, runs, windows, *, silence_policy, rho, tolerance_ms):
    """The benign envelope of `device` from TRAIN/VAL ONLY: `runs` = hybrid.events.Run objects, `windows` = their 10 s hybrid.windows.Window records for the device."""
    gaps, sizes = [], []
    for run in runs:
        rows = run.events.get(device, [])
        gaps += [(b[0] - a[0]) / 1e6 for a, b in zip(rows, rows[1:])]
        sizes += [s for _, s in rows]
    if len(gaps) < 3 or not sizes:
        raise ValueError(f"{device}: too few benign deliveries to derive an envelope")
    sds = [w.measures["interarrival_sd_ms"]["value"] for w in windows if w.measures["interarrival_sd_ms"]["status"] == "VALUE"]
    return TimingContract(device, min(gaps), max(gaps), max(w.count for w in windows), max(max(sds) * (1 + rho) if sds else 0.0, tolerance_ms), float(min(sizes)), float(max(sizes)),
                          silence_policy, rho, tolerance_ms)


def _value(m, name):
    item = m[name]
    return item["value"] if item["status"] == "VALUE" else None


def evaluate(contract, m, *, coverage_complete=True, window_end_ns=None, generation_start_ns=None):
    """(status, A_T, detail) for one 10 s window's measures `m`. status: EVALUATED or MISSING (with the exact reason in detail["reason"])."""
    detail = dict(monitor="TM-1", device=contract.device, indicators={}, informational={}, reason=None)
    if not coverage_complete:
        detail["reason"] = "OBSERVER_UNAVAILABLE"
        return "MISSING", None, detail
    n = _value(m, "delivered_count")
    if n is None:
        detail["reason"] = "COUNT_UNAVAILABLE"
        return "MISSING", None, detail
    c, rho, tol = contract, contract.rho, contract.tolerance_ms
    ind = detail["indicators"]
    ind["rate"] = max(0.0, n / c.count_hi - 1.0)
    p = _value(m, "payload_bytes_mean")
    if p is not None:
        ind["payload"] = max(0.0, p / c.payload_hi - 1.0, c.payload_lo / p - 1.0 if p > 0 else math.inf)
    g = _value(m, "interarrival_mean_ms")
    if g is not None:
        ind["short_gap"] = max(0.0, (1.0 - rho) * c.gap_lo_ms / g - 1.0) if g > 0 else math.inf
    sd = _value(m, "interarrival_sd_ms")
    if sd is not None:
        ind["variability"] = max(0.0, sd / c.sd_cap_ms - 1.0)
    age = _value(m, "last_delivery_age_ms")
    if age is None:
        if c.silence_policy == OVERDUE_IS_EVIDENCE:
            detail["reason"] = "NEVER_OBSERVED_IN_SESSION"
            return "MISSING", None, detail
    else:
        if generation_start_ns is not None and window_end_ns is not None:
            age = min(age, max(0.0, (window_end_ns - generation_start_ns) / 1e6))
        overdue = max(0.0, age / ((1.0 + rho) * c.gap_hi_ms + tol) - 1.0)
        (ind if c.silence_policy == OVERDUE_IS_EVIDENCE else detail["informational"])["overdue"] = overdue
    worst = max(ind.values())
    detail.update(e=worst, dominant=max(ind, key=ind.get) if worst > 0 else None)
    return "EVALUATED", c.kappa * worst, detail
