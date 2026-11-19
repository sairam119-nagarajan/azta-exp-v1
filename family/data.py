"""Window rows of the Phase 1 runs, one device at a time, through the partition door of `family.assignment`.

TRAIN rows of a device with a nominal period are re-windowed on the 12 declared shifted grids (the run's legitimate schedule phase); VAL rows on the native grid plus 12 half-step grids never seen
in training; CAL and DEVEVAL rows on the native, non-overlapping grid only. Every row keeps its source run and grid offset: an augmented row is never an independent observation. Only ready
windows (all six measures present) are returned as rows; nothing is imputed.
"""
from collections import namedtuple

from family import devices as dev
from hybrid import events as ev, windows as hw

NS = 1_000_000_000
Row = namedtuple("Row", "run device index offset_ns vector")


def shifted(run, offset_ns):
    """The same recorded events windowed on a grid shifted by `offset_ns` (what the live observer produces for a run whose schedule phase differs)."""
    return run._replace(usable_first_ns=run.usable_first_ns + offset_ns)


def offsets_for(device, role):
    grids = dev.phase_grids(device)
    if grids is None:
        return [0]
    return grids["train"] if role == "TRAIN" else grids["val"] if role == "VAL" else [0]


EDGE_DELTAS_MS = (-20, -10, -5, -2, -1, 0, 1, 2, 5, 10, 20)        # Phase 2 (protocol P2-REL section 4): declared before any fit


def message_phase_ns(run, device, period_ns):
    """The schedule phase psi of a strictly periodic device in one run: the messages sit at psi + k * P (plus the run's delivery variation); robust (median of the wrapped residuals)."""
    times = [o for o, _ in run.events.get(device, [])]
    if not times:
        raise ValueError(f"{device}: no deliveries in {run.run}")
    o0 = times[0]
    residuals = sorted(((o - o0 + period_ns // 2) % period_ns) - period_ns // 2 for o in times)
    return (o0 + residuals[len(residuals) // 2]) % period_ns


def edge_offsets(run, device):
    """Phase 2 EDGE augmentation (EA): grid offsets that put a window edge `delta` ms after a nominal message instant, for every declared delta, so the TRAIN rows contain the legitimate
    boundary effect (a message on either side of an edge: count one more or one less, with the matching gap and age values) that a live observer meets when its grid phase is close to the
    schedule phase. Only for a device whose window is a whole number of periods (its count is otherwise exactly constant in training); [] for every other device."""
    spec = dev.SPECS[device]
    if spec.period_ms is None or "delivered_count" not in spec.permitted_zero:
        return []
    period = spec.period_ms * 1_000_000
    psi = message_phase_ns(run, device, period)
    return [int((psi + delta * 1_000_000 - run.usable_first_ns) % period) for delta in EDGE_DELTAS_MS]


def native_windows(run_name, device, assignment):
    """All native windows (ready or not) of one run for one device at its contract width, in order."""
    run = ev.load_run(run_name, assignment)
    return hw.rewindow(None, device, run, dev.SPECS[device].width_s * NS)


def rows(role, device, assignment, *, runs=None, edge=False):
    """The ready rows of `device` in every run of `role` (or only `runs`), augmented as declared for TRAIN/VAL; `edge` adds the Phase 2 edge offsets to TRAIN rows only."""
    width = dev.SPECS[device].width_s * NS
    out = []
    for name in (runs if runs is not None else ev.runs_of_role(role, assignment)):
        run = ev.load_run(name, assignment)
        offsets = offsets_for(device, role) + (edge_offsets(run, device) if edge and role == "TRAIN" else [])
        for offset in offsets:
            out.extend(Row(w.run, device, w.index, offset, w.vector) for w in hw.rewindow(None, device, shifted(run, offset), width) if w.ready)
    return out
