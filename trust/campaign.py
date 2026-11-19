"""Partition protection from a committed collection manifest: which run and session IDs must never be scored in a given stage.

Reads only the append-only, hash-chained manifest JSONL (a committed configuration file) through the existing validators, WITHOUT an
artifact root, so no observation evidence is opened. Both manifest versions are understood: version 1 (historical B_train, B_val, B_cal,
D_shadow, D_test) and version 2 (CAL_V2, D_shadow, D_test). The calibration partition of each version (B_cal, CAL_V2) is ALWAYS reserved,
whatever the caller asks for: calibration windows are never Shadow evidence. During development the held-out final-test partition (D_test)
must also be reserved so that no tuning can touch it; invalidated runs are reserved always. Stage unlocking is not implemented here: it
needs an explicit controller decision and a freeze record.
"""
from pathlib import Path

from observation import manifest as manifest_v1
from observation import manifest_v2

ALWAYS_RESERVED_PARTITIONS = ("B_cal", "CAL_V2")


def _load(manifest_path):
    entries = manifest_v1.read_entries(Path(manifest_path))
    version = entries[0].get("schema_version") if entries and isinstance(entries[0], dict) else None
    if version == 1:
        return manifest_v1.validate(entries), tuple(manifest_v1.PARTITIONS), ("B_cal",)
    if version == 2:
        return manifest_v2.validate(entries), tuple(manifest_v2.PARTITIONS), (manifest_v2.CALIBRATION_PARTITION,)
    raise ValueError(f"unknown manifest schema version {version!r}")


def effective_partitions(manifest_path, partitions):
    """The partitions that are actually reserved for this manifest: the requested ones plus its calibration partition."""
    _, vocabulary, always = _load(manifest_path)
    unknown = set(partitions) - set(vocabulary)
    if unknown:
        raise ValueError(f"unknown partitions {sorted(unknown)} for this manifest version")
    return tuple(sorted(set(partitions) | set(always)))


def reserved_tokens_from_manifest(manifest_path, *, partitions):
    """Run IDs and observer session IDs of every planned run in `partitions`, in the manifest's calibration partition, and every invalidated run."""
    state, vocabulary, always = _load(manifest_path)
    wanted = set(partitions) | set(always)
    unknown = wanted - set(vocabulary)
    if unknown:
        raise ValueError(f"unknown partitions {sorted(unknown)} for this manifest version")
    tokens = set()
    for run, planned in state["planned"].items():
        if planned["intended_partition"] in wanted or run in state["invalidated"]:
            tokens.add(run)
            if run in state["collected"]:
                tokens.add(state["collected"][run]["observer_session_id"])
    return frozenset(tokens)
