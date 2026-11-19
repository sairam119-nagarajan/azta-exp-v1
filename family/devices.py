"""The ten devices as the Phase 1 protocol sees them: window width, nominal period (for the declared phase augmentation), the declared exactly-constant features, and the groupings.

Everything is DECLARED from the committed laws (`fleet.laws.profile_of`, the ten-slot law of `experiments/gate5d3_workload.py`) and the Gate 6C observation contracts
(`configs/gate6c/observation_contracts_core.json`, `observation_contracts_prelive.json`) BEFORE any candidate is trained; `tests/test_family.py` checks the table against the laws, so a
change of a law cannot silently change a contract. Nothing is derived from any evaluation outcome.
"""
from collections import namedtuple

DeviceSpec = namedtuple("DeviceSpec", "device width_s period_ms required_zero permitted_zero law_class")

PAYLOAD_CONSTANT = ("payload_bytes_mean", "payload_bytes_sd")
TOLERANCES = {"delivered_count": 0.5, "payload_bytes_mean": 1.0, "payload_bytes_sd": 1.0, "interarrival_mean_ms": 5.0, "interarrival_sd_ms": 5.0, "last_delivery_age_ms": 5.0}   # observation_contracts_core.json, unchanged
AGE = "last_delivery_age_ms"

# device: (width_s, nominal period in ms for the 12-grid phase augmentation or None, fixed payload?, whole-period window (count may be constant)?, law class)
_TABLE = {
    "device01": (10, None, True, False, "steady_jitter 1 s"),
    "device02": (10, None, False, False, "steady_jitter 0.2 s"),
    "device03": (10, None, True, False, "steady_jitter 0.2 s"),
    "device04": (10, None, False, False, "steady_jitter 1 s"),
    "device05": (10, 3000, True, False, "periodic 3 s"),
    "device06": (20, 4000, False, True, "periodic 4 s"),
    "device07": (20, 5000, True, True, "periodic 5 s"),
    "device08": (90, 30000, True, True, "periodic 30 s"),
    "device09": (180, None, True, False, "event_gap 20-60 s"),
    "device10": (10, None, True, False, "switching 1 s / 0.2 s"),
}


def _spec(device):
    width, period, fixed, whole, law = _TABLE[device]
    return DeviceSpec(device, width, period, PAYLOAD_CONSTANT if fixed else (), ("delivered_count",) if whole else (), law)


DEVICES = tuple(sorted(_TABLE))
SPECS = {device: _spec(device) for device in DEVICES}

# Declared groupings (protocol section 4). A "family" is the set of devices whose windows share ONE set of learned parameters.
FREQ = ("device01", "device02", "device03", "device04", "device10")
PER = ("device05", "device06", "device07", "device08")
GROUPINGS = {
    "G-A": {"FREQ": FREQ, "PER": PER, "device09": ("device09",)},
    "G-B": {"FREQ1": ("device01", "device04"), "FREQ02": ("device02", "device03"), "device10": ("device10",), "PER": PER, "device09": ("device09",)},
    "G-C": {"ALL": DEVICES},
    "G-D": {"PER9": PER + ("device09",), "FREQ": FREQ},
}


def phase_grids(device):
    """The declared RAW_AUG grid offsets in ns: TRAIN uses i * P / 12, VAL additionally the native grid and the half steps (i + 0.5) * P / 12 (CORE-P1 section 3.2). None for a device without a period."""
    period = SPECS[device].period_ms
    if period is None:
        return None
    step = period * 1e6 / 12
    return dict(train=[int(round(i * step)) for i in range(12)], val=[0] + [int(round((i + 0.5) * step)) for i in range(12)])
