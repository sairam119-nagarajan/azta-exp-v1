"""Block-level timing monitor BM-1 and slow-drift detector DR-1 (Gate 6C pre-live campaign): TM-1 over longer, NON-OVERLAPPING blocks of consecutive 10 s observer windows.

TM-1 (`hybrid.timing`) judges one 10 s window against the device's benign envelope. That is blind to anything that needs more than a window to see: a moderate rate change of a sparse device (a
30 s sensor sends at most one message per window), a partial drop, the variability of a device with fewer than three messages per window, and small shifts that only accumulate. A BLOCK is
H seconds (a multiple of 10 s) composed EXACTLY from K = H / 10 consecutive windows (`hybrid.compose`), with the block grid anchored at the first window of an unbroken, fully covered stretch.
At each completed block (one item per block, so overlapping horizons never count one underlying event twice):

  rate    E_hi  = max(0, n / hi_eff - 1)            n = messages in the block, hi_eff = ceil(count_hi x (1 + rho_c))
  drop    E_lo  = max(0, lo_eff / max(n, 1/2) - 1)  lo_eff = floor(count_lo x (1 - rho_c)); defined only when lo_eff >= 1 (a device that may be silent for a block has no drop bound)
  payload E_pay = max(0, p / p_hi_eff - 1, p_lo_eff / p - 1)         p = mean payload of the block
  jitter  E_jit = max(0, MAD / mad_cap - 1)                          MAD = median absolute deviation of the block's gap observations (robust: a single stall moves it by nothing);
                                                                    mad_cap = max((1 + rho_c) x the largest benign block MAD, tolerance)
  A_block = kappa x max(E_hi, E_lo, E_pay, E_jit)  (kappa = 10 as in TM-1: a statistic outside its benign envelope by a factor of two gives A = 10)

DR-1 accumulates the standardized rate deviation of successive blocks, z = (n / n_ref - 1) / sigma_x (n_ref = the benign median block count, sigma_x = max(the benign SD of n / n_ref, tolerance_rel)),
with the one-sided CUSUM recursion S+ = max(0, S+ + z - k), S- = max(0, S- - z - k), k = 1/2; its magnitude is A_drift = kappa x max(0, max(S+, S-) / h - 1) with h = 16.9 (the S that makes the
magnitude reach the RESTRICT-equivalent 6.93 after one factor-of-two excess). A block with incomplete observer coverage neither updates nor resets the sums (missing evidence is neither healthy nor
malicious); a restore of the device (new policy generation) resets them. All constants are declared values or derived from the benign TRAIN/VAL runs; none is fitted to any attack outcome.
"""
from dataclasses import dataclass
import math
import statistics

from hybrid import compose as hc

KAPPA = 10.0
RHO_COUNT = 0.10          # relative margin on the benign block-count and payload envelopes (declared)
TOLERANCE_REL = 0.05      # smallest relative standard deviation assumed for the block count (declared; the half-message boundary quantisation of a 60 s block of a 3 s device is about 0.025)
TOLERANCE_MAD_MS = 5.0    # the timing tolerance of the observation chain, as in TM-1
CUSUM_K = 0.5
CUSUM_H = 16.9
BLOCK_RATE_FLOOR = 8      # a block should hold at least this many messages in the benign median for its rate statistics to mean anything (else it is lengthened up to the cap)
BLOCK_MIN_S, BLOCK_MAX_S = 60, 300


@dataclass(frozen=True)
class BlockContract:
    device: str
    width_s: int
    count_lo: int
    count_hi: int
    count_ref: float
    sigma_x: float
    payload_lo: float
    payload_hi: float
    mad_cap_ms: float
    rho_c: float = RHO_COUNT
    kappa: float = KAPPA
    cusum_k: float = CUSUM_K
    cusum_h: float = CUSUM_H

    def __post_init__(self):
        if not (self.width_s >= 10 and self.width_s % 10 == 0 and self.count_hi >= self.count_lo >= 0 and self.count_ref > 0 and self.sigma_x > 0 and self.mad_cap_ms > 0 and 0 < self.rho_c < 1):
            raise ValueError("invalid block contract")

    def to_dict(self):
        return {k: getattr(self, k) for k in ("device", "width_s", "count_lo", "count_hi", "count_ref", "sigma_x", "payload_lo", "payload_hi", "mad_cap_ms", "rho_c", "kappa", "cusum_k", "cusum_h")}

    @property
    def k_windows(self):
        return self.width_s // 10

    @property
    def hi_eff(self):
        return math.ceil(self.count_hi * (1.0 + self.rho_c))

    @property
    def lo_eff(self):
        return math.floor(self.count_lo * (1.0 - self.rho_c))


def block_width_s(median_count_per_10s):
    """The declared block-length rule: the shortest multiple of 10 s, at least 60 s, whose benign median message count reaches BLOCK_RATE_FLOOR, at most 300 s."""
    for width in range(BLOCK_MIN_S, BLOCK_MAX_S + 1, 10):
        if median_count_per_10s * width / 10.0 >= BLOCK_RATE_FLOOR:
            return width
    return BLOCK_MAX_S


def gap_observations(records):
    """The block's gap observations for the robust jitter statistic: every boundary gap between consecutive non-empty windows (exact) and the mean of each window's intra-window gaps (one observation per window).
    Windows are the 10 s records of `hybrid.compose`."""
    out, last_seen = [], None
    for position, record in enumerate(records):
        m = record["measures"]
        n = m["delivered_count"]["value"]
        if not n:
            continue
        end = (position + 1) * 10_000.0
        last = end - m["last_delivery_age_ms"]["value"]
        mean = m["interarrival_mean_ms"]["value"]
        first = last - (n - 1) * mean if n >= 2 else last
        if last_seen is not None:
            out.append(first - last_seen)
        if n >= 2:
            out.append(mean)
        last_seen = last
    return out


def mad(values):
    if len(values) < 3:
        return None
    centre = statistics.median(values)
    return statistics.median(abs(v - centre) for v in values)


def block_statistics(records):
    """(measures, complete, mad_ms) of one block of 10 s records."""
    measures, complete = hc.compose(records)
    return measures, complete, (mad(gap_observations(records)) if complete else None)


def derive_block_contract(device, streams, *, rho_c=RHO_COUNT, tolerance_rel=TOLERANCE_REL, tolerance_mad_ms=TOLERANCE_MAD_MS, width_s=None):
    """The benign block envelope from TRAIN/VAL streams: `streams` = lists of consecutive 10 s window records (dicts with window/coverage/measures) of ONE device, one list per benign run.
    Every sliding start (step 10 s) of every run contributes a block, so the envelope covers all phases."""
    counts10 = [r["measures"]["delivered_count"]["value"] for stream in streams for r in stream if r["measures"]["delivered_count"]["value"] is not None]
    if not counts10:
        raise ValueError(f"{device}: no benign windows")
    width_s = width_s or block_width_s(statistics.median(counts10))
    k = width_s // 10
    counts, payloads, mads = [], [], []
    for stream in streams:
        for start in range(0, len(stream) - k + 1):
            records = stream[start:start + k]
            if any(r["coverage"]["state"] != "COMPLETE" for r in records):
                continue
            measures, complete, spread = block_statistics(records)
            counts.append(measures["delivered_count"]["value"])
            if measures["payload_bytes_mean"]["value"] is not None:
                payloads.append(measures["payload_bytes_mean"]["value"])
            if spread is not None:
                mads.append(spread)
    if len(counts) < 10 or not payloads:
        raise ValueError(f"{device}: too few benign blocks ({len(counts)}) to derive a {width_s} s envelope")
    ref = statistics.median(counts)
    sigma = statistics.pstdev([c / ref for c in counts]) if ref > 0 else 1.0
    return BlockContract(device, width_s, min(counts), max(counts), float(ref), max(sigma, tolerance_rel), float(min(payloads)), float(max(payloads)),
                         max((1.0 + rho_c) * max(mads) if mads else 0.0, tolerance_mad_ms), rho_c)


def block_indicators(contract, measures, spread_ms):
    """{name: E >= 0} of the block's defined indicators."""
    c, ind = contract, {}
    n = measures["delivered_count"]["value"]
    ind["rate"] = max(0.0, n / c.hi_eff - 1.0)
    if c.lo_eff >= 1:
        ind["drop"] = max(0.0, c.lo_eff / max(n, 0.5) - 1.0)
    p = measures["payload_bytes_mean"]["value"]
    if p is not None:
        ind["payload"] = max(0.0, p / (c.payload_hi * (1.0 + c.rho_c)) - 1.0, (c.payload_lo * (1.0 - c.rho_c)) / p - 1.0 if p > 0 else math.inf)
    if spread_ms is not None:
        ind["jitter"] = max(0.0, spread_ms / c.mad_cap_ms - 1.0)
    return ind


class Cusum:
    """DR-1: the two one-sided sums of the standardized block-count deviation."""

    def __init__(self):
        self.up = self.down = 0.0

    def update(self, contract, n):
        z = (n / contract.count_ref - 1.0) / contract.sigma_x
        self.up = max(0.0, self.up + z - contract.cusum_k)
        self.down = max(0.0, self.down - z - contract.cusum_k)
        return max(0.0, max(self.up, self.down) / contract.cusum_h - 1.0)

    def reset(self):
        self.up = self.down = 0.0


class Stretch:
    """Accumulates consecutive, fully covered 10 s records into blocks of `k` windows, anchored at the first window of an unbroken stretch. `push` returns (records, interrupted): the completed block (or
    None) and whether an unfinished block was just discarded because coverage broke or a tick was skipped (the caller then reports the block MISSING, never healthy)."""

    def __init__(self, k):
        self.k, self.block = k, []

    def restart(self):
        had = bool(self.block)
        self.block = []
        return had

    def push(self, record):
        if record["coverage"]["state"] != "COMPLETE":
            return None, self.restart()
        interrupted = False
        if self.block and record["window"]["index"] != self.block[-1]["window"]["index"] + 1:
            interrupted = self.restart()
        self.block.append(record)
        if len(self.block) < self.k:
            return None, interrupted
        records, self.block = self.block, []
        return records, interrupted


class BlockMonitor:
    """The stateful per-device BM-1 / DR-1 evaluator. `push(record, generation_changed)` takes ONE 10 s window record per tick and returns None until a block completes (or is interrupted); then
    (block_index, status, a_block, a_drift, detail). status MISSING means the block could not be judged (reason in detail) and never carries a magnitude."""

    def __init__(self, contract):
        self.contract, self.stretch, self.cusum, self.blocks_done = contract, Stretch(contract.k_windows), Cusum(), 0

    def push(self, record, *, generation_changed=False):
        c = self.contract
        if generation_changed:
            self.cusum.reset()
            self.stretch.restart()
        records, interrupted = self.stretch.push(record)
        if records is None:
            return (self.blocks_done, "MISSING", None, None, dict(reason="OBSERVER_UNAVAILABLE")) if interrupted else None
        try:
            measures, _, spread = block_statistics(records)
        except hc.NotComposable as exc:
            return (self.blocks_done, "MISSING", None, None, dict(reason=f"COMPOSE_REFUSED:{exc}"))
        ind = block_indicators(c, measures, spread)
        e = max(ind.values())
        item = (self.blocks_done, "EVALUATED", c.kappa * e, c.kappa * self.cusum.update(c, measures["delivered_count"]["value"]),
                dict(indicators=ind, dominant=max(ind, key=ind.get) if e > 0 else None, n=measures["delivered_count"]["value"], mad_ms=spread, cusum_up=self.cusum.up, cusum_down=self.cusum.down,
                     first_window=records[0]["window"]["index"]))
        self.blocks_done += 1
        return item
