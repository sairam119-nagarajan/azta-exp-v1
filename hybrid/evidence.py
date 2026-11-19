"""Hybrid behavioural-evidence integration HBE-1: how autoencoder evidence and timing evidence become ONE behavioural trust score without changing the engine, the weights, the thresholds
or the N = 2 persistence of the enforcement layer.

Quantities (all per device; every score keeps the unchanged form of journal equations 9 and 10):
    A_AE   anomaly magnitude of an autoencoder window  A = max(0, (L - mu_L) / (sigma_L + eps))   (calibrated on that contract's own benign CAL windows)
    A_T    anomaly magnitude of the timing monitor      A_T = kappa x E                            (TM-1, `hybrid.timing`)
    S_B    = 100 exp(-lambda A_B)   with   A_B = max over the ADMISSIBLE evidence items of their A     (the worst calibrated evidence determines behavioural trust; S_B is then the
           minimum of the per-item scores 100 exp(-lambda A_i), because exp is monotone)
Each evidence ITEM has an identity (stream, index), an observation instant, an expiry, a magnitude and a freshness flag. Rules:

  H1 combination     simultaneous admissible items: A_B = max A_i; the dominant item and every contributing id are recorded; no item is averaged away and none is added twice.
  H2 missing         an item that is missing (window not score-ready, observer outage, no history, no model) is NEVER a healthy or a malicious score: it contributes nothing and its reason is
                     recorded. If no item is admissible the behaviour component is MISSING (the engine's missing-evidence policy decides; REFUSE gives no proposal). A profile may REQUIRE a
                     stream (`required`); then its absence makes the component MISSING instead of silently relying on the other stream.
  H3 expiry          a fast item (an ordinary 10 s window) is valid for its own decision tick only. A slow item (a long autoencoder window of W seconds) is valid until observed + 2W.
  H4 no double count A slow item is FRESH at the one tick that completes it and CARRIED afterwards. A carried item never raises the confirmation count by itself: it contributes to A_B only
                     while it is CONFIRMED, i.e. while at least two DISTINCT anomalous items (A_i >= A_flag) lie within the confirmation horizon. Two ticks that look at the same slow item are
                     therefore one observation, not two. The enforcement layer's N = 2 consecutive proposals then confirms either two distinct fast items, or a carried item together with the
                     distinct item that confirmed it.
  H5 contradiction   when fresh admissible items disagree (one anomalous, one normal) the worst wins and the record says CONTRADICTORY; an unconfirmed carried item can NOT override a fresh normal
                     item (it stays counted in the confirmation horizon, so a later distinct anomalous item confirms it). Disagreement is reported, never averaged.
  H6 cadence         the decision tick is the fast cadence (10 s); slow items enter at their completion tick. N = 2 is unchanged and counts distinct fresh proposals as above.
  H7 advisory        a stream that has FAILED its robustness screen (a confirmed false request on benign streams with 3 ms of timing noise, or on the held-aside benign runs) is ADVISORY: its items are
                     recorded in every fusion record with their magnitudes but are never counted, never confirm anything and never raise A_B. Admission is a per-profile configuration decided from the
                     screen, not from attack outcomes, and every advisory stream is listed in the profile record. This is what prevents one brittle detector from overriding a robust one.
A_flag is the magnitude at which the unchanged weights first leave FULL_ACCESS for a conforming-context device (equation 12 with S_ID = S_C = 100: A > 6.93); it is derived, not chosen.
"""
from dataclasses import dataclass
import math

LAMBDA = 0.1
ALPHA, BETA, GAMMA = 0.2, 0.5, 0.3
TAU_R, TAU_Q = 75.0, 70.0
A_FLAG = math.log(100.0 * BETA / (TAU_R - 100.0 * (ALPHA + GAMMA))) / LAMBDA        # S_B = 50: the first magnitude that leaves FULL_ACCESS when identity and context conform
A_QUARANTINE = math.log(100.0 * BETA / (TAU_Q - 100.0 * (ALPHA + GAMMA))) / LAMBDA


def s_b(a, lam=LAMBDA):
    return 100.0 * math.exp(-lam * a)


def state_for(a, *, s_id=100.0, s_c=100.0):
    """The engine's proposal for an anomaly magnitude when identity and context are as stated (equations 11 and 12 with the pilot weights). Offline studies only."""
    t = ALPHA * s_id + BETA * s_b(a) + GAMMA * s_c
    return "QUARANTINE" if t < TAU_Q else "RESTRICT" if t < TAU_R else "FULL_ACCESS"


@dataclass(frozen=True)
class Item:
    stream: str            # "AE_FAST", "AE_SLOW" or "TIMING"
    index: int
    observed_ns: int
    expires_ns: int
    a: object              # float magnitude, or None when missing
    reason: object = None  # why it is missing
    slow: bool = False
    start_ns: object = None    # start of the observation interval [start_ns, observed_ns) (HBE-2 distinctness); None = a point at observed_ns

    @property
    def item_id(self):
        return f"{self.stream}:{self.index}"


class DeviceFusion:
    """The per-device state of HBE-1. `required` = streams whose absence makes the component MISSING; `confirm_horizon_ns` = the span in which distinct anomalous items confirm each other."""

    def __init__(self, *, required=(), advisory=(), confirm_horizon_ns, a_flag=A_FLAG, distinct="IDS"):
        # distinct: "IDS" (HBE-1: two anomalous items with different identities confirm each other) or "INTERVALS" (HBE-2: only anomalous items whose observation intervals are pairwise DISJOINT
        # count as distinct, so two indicators of the SAME window, or a long window and a 10 s window inside it, are one observation)
        if distinct not in ("IDS", "INTERVALS"):
            raise ValueError("unknown distinctness rule")
        self.required, self.advisory, self.horizon, self.a_flag, self.distinct = tuple(required), tuple(advisory), confirm_horizon_ns, a_flag, distinct
        self.anomalous = {}                   # item_id -> Item, distinct anomalous items seen inside the horizon
        self.introduced = {}                  # item id -> expiry: pruned each tick, so a long-lived evaluator holds only the live items

    def distinct_count(self):
        """The number of distinct anomalous observations inside the horizon under the configured rule."""
        if self.distinct == "IDS":
            return len(self.anomalous)
        spans = sorted(((i.observed_ns, i.observed_ns - 1 if i.start_ns is None else i.start_ns) for i in self.anomalous.values()))
        count, last_end = 0, None
        for end, start in spans:                    # interval scheduling: the largest set of pairwise disjoint observations
            if last_end is None or start >= last_end:
                count, last_end = count + 1, end
        return count

    def tick(self, tick_ns, items):
        """The fusion record for one decision tick. `items`: the items that were produced or are still alive at this tick (fresh = introduced at this tick for the first time)."""
        every = [i for i in items if i.expires_ns >= tick_ns]
        advisory = {i.item_id: i.a for i in every if i.stream in self.advisory}
        alive = [i for i in every if i.stream not in self.advisory]
        fresh = [i for i in alive if i.item_id not in self.introduced]
        self.introduced = {k: e for k, e in self.introduced.items() if e >= tick_ns}
        for i in fresh:
            self.introduced[i.item_id] = i.expires_ns
        self.anomalous = {k: v for k, v in self.anomalous.items() if tick_ns - v.observed_ns <= self.horizon}
        for i in alive:
            if i.a is not None and i.a >= self.a_flag:
                self.anomalous.setdefault(i.item_id, i)
        confirmed = self.distinct_count() >= 2
        missing = {i.item_id: i.reason for i in alive if i.a is None}
        streams_present = {i.stream for i in alive if i.a is not None}
        absent_required = [s for s in self.required if s not in streams_present]
        counted = []
        for i in alive:
            if i.a is None:
                continue
            if i in fresh or not i.slow or (i.item_id in self.anomalous and confirmed):
                counted.append(i)
        record = dict(rule="HBE-2" if self.distinct == "INTERVALS" else "HBE-1", tick_ns=tick_ns, fresh=[i.item_id for i in fresh], carried=[i.item_id for i in alive if i not in fresh], missing=missing, confirmed=confirmed,
                      contradictory=False, a=None, s_b=None, basis=None, contributing=[], status="MISSING", reasons=[], advisory=advisory)
        if absent_required:
            record["reasons"] = [f"REQUIRED_STREAM_ABSENT:{s}" for s in absent_required]
            return record
        if not counted:
            record["reasons"] = ["NO_ADMISSIBLE_EVIDENCE"]
            return record
        worst = max(counted, key=lambda i: i.a)
        flags = [i.a >= self.a_flag for i in counted if i in fresh]
        record.update(status="EVALUATED", a=worst.a, s_b=s_b(worst.a), basis=worst.item_id, contributing=[i.item_id for i in counted], contradictory=bool(flags) and any(flags) and not all(flags))
        return record


# ------------------------------------------------------------------------------------------------------------------------------ item builders
TICK_INDICATORS = ("rate", "overdue")                   # defined at EVERY decision tick, whether or not a message arrived
MESSAGE_INDICATORS = ("payload", "short_gap", "variability")      # exist only in a window that holds the messages they describe: the evidence of a sparse device arrives at message rate


def timing_items(contract, detail, status, tick_ns, index):
    """The two timing items of one tick from a `hybrid.timing.evaluate` result: a TICK item (valid for this tick only) and, when the window carried message-driven indicators, a MESSAGE item that
    stays alive until the next message could have arrived ((1 + rho) x the largest benign gap + the tolerance + one tick) so that it is CARRIED, not re-observed, at the ticks in between."""
    if status != "EVALUATED":
        return [Item("TIMING_TICK", index, tick_ns, tick_ns, None, detail["reason"])]
    kappa, ind = contract.kappa, detail["indicators"]
    items = [Item("TIMING_TICK", index, tick_ns, tick_ns, kappa * max([ind.get(k, 0.0) for k in TICK_INDICATORS] + [0.0]))]
    message = [ind[k] for k in MESSAGE_INDICATORS if k in ind]
    if message:
        alive = int(((1.0 + contract.rho) * contract.gap_hi_ms + contract.tolerance_ms) * 1e6) + 10_000_000_000
        items.append(Item("TIMING_MSG", index, tick_ns, tick_ns + alive, kappa * max(message), slow=True))
    return items


def confirm_horizon_ns(contract):
    """Two message-driven observations must lie within about two maximal benign gaps (plus two ticks) to confirm each other."""
    return int(2 * ((1.0 + contract.rho) * contract.gap_hi_ms + contract.tolerance_ms) * 1e6) + 20_000_000_000
