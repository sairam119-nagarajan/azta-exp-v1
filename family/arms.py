"""The arm list of protocol P1-FAM section 6, declared before any fit: 31 arms, 186 fits. Nothing outside this table is trained under the protocol."""
from family import devices as dev
from family.normalize import FC_N, FC_R

AGE = dev.AGE


def _ind(contract_tag, contract):
    return {f"IND-{contract_tag}-{d}": dict(members=(d,), contract=contract, masked=(), role="device-specific counterpart (identical pipeline)") for d in dev.DEVICES}


def _arms():
    arms = {}
    arms.update(_ind("B", FC_N))
    arms.update(_ind("C", FC_R))
    shared = [
        ("B-FREQ", dev.FREQ, FC_N, (), "G-A shared"), ("B-PER", dev.PER, FC_N, (), "G-A shared"),
        ("C-FREQ", dev.FREQ, FC_R, (), "G-A shared"), ("C-PER", dev.PER, FC_R, (), "G-A shared"),
        ("B-F1S", ("device01", "device04"), FC_N, (), "G-B finer"), ("B-F02", ("device02", "device03"), FC_N, (), "G-B finer"),
        ("B-ALL", dev.DEVICES, FC_N, (), "G-C negative control"), ("B-PER9", dev.PER + ("device09",), FC_N, (), "G-D event-driven test"),
        ("B-FREQ-x03", tuple(d for d in dev.FREQ if d != "device03"), FC_N, (), "LODO: device03 never seen"),
        ("B-PER-x07", tuple(d for d in dev.PER if d != "device07"), FC_N, (), "LODO: device07 never seen"),
        ("B-PER-MASK", dev.PER, FC_N, (AGE,), "ablation: age masked"),
    ]
    for name, members, contract, masked, role in shared:
        arms[name] = dict(members=tuple(members), contract=contract, masked=masked, role=role)
    return arms


ARMS = _arms()
EXPECTED_ARMS, EXPECTED_FITS = 31, 186

# Deployed-candidate wiring for the primary grouping G-A (the arm whose networks a device uses in each contract): resolved by `rehearsal_tools/p1_decide.py` after R-NI.
PRIMARY_SHARED = {"B": {d: "B-FREQ" for d in dev.FREQ} | {d: "B-PER" for d in dev.PER}, "C": {d: "C-FREQ" for d in dev.FREQ} | {d: "C-PER" for d in dev.PER}}


def individual(contract_tag, device):
    return f"IND-{contract_tag}-{device}"


# ------------------------------------------------------------------------------------------------------------------------------ Phase 2 (protocol P2-REL section 5)
# Only the periodic devices whose window is a whole number of periods (06, 07, 08) get new TRAIN rows (edge augmentation, EA); every other Phase 2 candidate reuses a trained Phase 1 network
# (with or without input masking, IM, which changes scoring, not training). 7 arms, 42 fits; nothing else is trained under protocol P2-REL.
EA_DEVICES = ("device06", "device07", "device08")


def _p2_arms():
    arms = {"EA-C-PER": dict(members=dev.PER, contract=FC_R, masked=(), edge=True, role="shared periodic family, edge-augmented (hypothesis C-PER of Phase 1)")}
    for tag, contract in (("B", FC_N), ("C", FC_R)):
        for d in EA_DEVICES:
            arms[f"EA-IND-{tag}-{d}"] = dict(members=(d,), contract=contract, masked=(), edge=True, role="device-specific counterpart, edge-augmented")
    return arms


P2_ARMS = _p2_arms()
P2_EXPECTED_ARMS, P2_EXPECTED_FITS = 7, 42

P1_MODELS, P2_MODELS = "results/engineering/gate6c/p1/models/p1-train-01", "results/engineering/gate6c/p2/models/p2-train-01"


def _p2_candidates():
    """Every Phase 2 candidate (protocol section 5): {name: dict(network, models_dir_rel, members, contract, masked, input_mask, form, group)}. `+IM` = input masking at scoring."""
    out = {}

    def add(name, network, models, members, contract, form, group, im):
        out[name] = dict(network=network, models_dir_rel=models, members=tuple(members), contract=contract, masked=(), input_mask=im, form=form, group=group)

    for im in (False, True):
        s = "+IM" if im else ""
        add(f"B-FREQ{s}", "B-FREQ", P1_MODELS, dev.FREQ, FC_N, "shared", "FREQ", im)
        for d in dev.FREQ:
            add(f"IND-B-{d}{s}", f"IND-B-{d}", P1_MODELS, (d,), FC_N, "individual", "FREQ", im)
        add(f"C-PER{s}", "C-PER", P1_MODELS, dev.PER, FC_R, "shared", "PER", im)
        add(f"EA-C-PER{s}", "EA-C-PER", P2_MODELS, dev.PER, FC_R, "shared", "PER", im)
        for d in dev.PER:
            add(f"IND-C-{d}{s}", f"IND-C-{d}", P1_MODELS, (d,), FC_R, "individual", "PER", im)
        for d in EA_DEVICES:
            add(f"EA-IND-C-{d}{s}", f"EA-IND-C-{d}", P2_MODELS, (d,), FC_R, "individual", "PER", im)
        add(f"IND-B-device09{s}", "IND-B-device09", P1_MODELS, ("device09",), FC_N, "individual", "EVENT", im)
    for d in EA_DEVICES:
        add(f"EA-IND-B-{d}+IM", f"EA-IND-B-{d}", P2_MODELS, (d,), FC_N, "ablation", "PER", True)
    # leave-one-device-out networks of Phase 1, reported only (protocol section 8)
    add("B-FREQ-x03", "B-FREQ-x03", P1_MODELS, tuple(d for d in dev.FREQ if d != "device03"), FC_N, "lodo", "FREQ", False)
    add("B-PER-x07", "B-PER-x07", P1_MODELS, tuple(d for d in dev.PER if d != "device07"), FC_N, "lodo", "PER", False)
    return out


P2_CANDIDATES = _p2_candidates()
P2_HELD_OUT = {"B-FREQ-x03": ("device03",), "B-PER-x07": ("device07",)}


def p2_pair(device, form, corrected):
    """The declared Phase 2 candidate of `device` in `form` ("shared" / "individual"), corrected (IM, and EA for 06 to 08) or unmodified; None where the form does not exist (device09 shared)."""
    s = "+IM" if corrected else ""
    if device in dev.FREQ:
        return f"B-FREQ{s}" if form == "shared" else f"IND-B-{device}{s}"
    if device in dev.PER:
        ea = corrected and device in EA_DEVICES
        if form == "shared":
            return f"EA-C-PER{s}" if corrected else "C-PER"
        return f"EA-IND-C-{device}{s}" if ea else f"IND-C-{device}{s}"
    return None if form == "shared" else f"IND-B-device09{s}"
