"""Run provenance for windows of an UNFINISHED session: the class the pinned evidence producer does not have.

`trust.producer.build_bundle` (pinned by the CAL_V2 freeze, never edited) knows three source kinds, all of which describe a FINISHED, digest-pinned
windows artifact. A live window has none, and passing it off as a `MANIFEST_ARTIFACT` would claim a verification that has not happened. So this
module defines its own, separately versioned `LIVE_SESSION_PROVISIONAL` provenance and hands it to the unchanged `build_bundle`, which only READS
nine attributes of its run object (a tripwire test keeps that list pinned). Every protection of the producer therefore still applies to a live
window with no duplication: partition allow-list, reserved run and session ids, the plan's eligible range, the registry and configuration binding of
the profile route, mixed-provenance refusal, identity only from audits, the structural contract of the bundle.

The `windows_artifact_sha256` of a live window is the SHA-256 of the exact bytes of `windows.jsonl` up to and including that window's line (a real digest
of the artifact AS IT STOOD), never of the finished file. Its meaning is stated in every bundle (`annotations.live_provenance`).
"""
from dataclasses import dataclass, replace
import hashlib
from typing import ClassVar

from observation.schema import SHA256
from shadow_live.errors import LiveRefused

SOURCE_KIND = "LIVE_SESSION_PROVISIONAL"
PARTITIONS = ("D_shadow", "FUNCTIONAL")
EMPTY_PREFIX_SHA256 = hashlib.sha256(b"").hexdigest()
# Exactly the attributes `trust.producer.build_bundle` reads from the run object it is given (kept equal to the source by a test).
PRODUCER_RUN_ATTRIBUTES = frozenset({"partition", "collection_run_id", "observer_session_id", "eligible_window_indices", "source_kind", "workload_version",
                                     "plan_sha256", "manifest_sha256", "windows_artifact_sha256"})


def _require(condition, message):
    if not condition:
        raise LiveRefused("PROVENANCE_INVALID", message)


@dataclass(frozen=True)
class LiveRunProvenance:
    collection_run_id: str
    observer_session_id: str
    partition: str
    eligible_window_indices: tuple
    workload_version: str
    plan_sha256: str
    manifest_sha256: object
    windows_artifact_sha256: str
    source_kind: ClassVar[str] = SOURCE_KIND

    def __post_init__(self):
        _require(self.partition in PARTITIONS, f"a live window can only carry the partition role {PARTITIONS}, not {self.partition!r}")
        _require(isinstance(self.eligible_window_indices, tuple) and len(self.eligible_window_indices) == 2
                 and all(type(v) is int and v >= 0 for v in self.eligible_window_indices)
                 and self.eligible_window_indices[0] <= self.eligible_window_indices[1], "eligible_window_indices must be the plan's (first, last) pair")
        _require(isinstance(self.workload_version, str) and self.workload_version, "workload_version must be stated (from the plan generator)")
        for name in ("plan_sha256", "windows_artifact_sha256"):
            value = getattr(self, name)
            _require(isinstance(value, str) and SHA256.fullmatch(value), f"{name}: SHA-256 required")
        if self.partition == "D_shadow":
            _require(isinstance(self.manifest_sha256, str) and SHA256.fullmatch(self.manifest_sha256), "a D_shadow live window is bound to the committed manifest")
        else:
            _require(self.manifest_sha256 is None, "a functional live window has no collection manifest")


def base_provenance(plan, session_id):
    """The run as the declaration states it, before any byte of the window file has been consumed (the empty prefix)."""
    return LiveRunProvenance(plan.run_id, session_id, plan.partition, tuple(plan.eligible), plan.workload_version, plan.plan_sha256, plan.manifest_sha256,
                             EMPTY_PREFIX_SHA256)


def for_window(base, prefix_sha256):
    return replace(base, windows_artifact_sha256=prefix_sha256)
