"""Live-session declaration: the explicit, auditable authorization to follow ONE unfinished observer session of ONE planned run.

There is no default and no ambient permission. A declaration names the run, the partition role (`D_shadow` provisional evidence, or a non-scientific
`FUNCTIONAL` rehearsal), the committed plan and manifest it is bound to (by digest), the observer rules, the baseline broker-policy digest every audit
must show, the interval in which the authorization is valid, and the timing tolerances of the adapter. `clock_tolerance_ns` is the largest lead of a window's
nominal end over the host clock that is HELD (decided only after its nominal end has passed on this clock) rather than refused as a future window; it is a claim
about the observer-to-host mapping error and must be backed by a passing clock preflight (`rehearsal_tools/clock_probe.py evaluate`, enforced by the rehearsal
driver), never enlarged to make a run pass. Resolving it opens NO evidence: it reads only
committed configuration through the same validators as the replay reader (`shadow_feed.reader.load_plan_and_state`), so the two cannot disagree
about what a usable plan and manifest are.

What it refuses (each is tested): D_test, CAL_V2 and every B_* partition (they are consumed, locked or training evidence and never Shadow evidence);
a run that is not planned, is voided or invalidated, or is ALREADY COLLECTED (a finished session is replayed by the manifest-verified reader, never
followed as live); a plan or manifest that differs from the authorized digests; an unapproved scientific plan; and an evidence root at or around
`results/raw` unless the declaration carries an explicit raw-evidence authorization reference. The session id is NOT part of the declaration: the
observer generates it when it starts, so it is supplied at attach time and verified against the declared run, pins and observer rules.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from experiments import collection_plan as plans
from experiments import collection_plan_v2 as plans_v2
from observation.registry import DeviceRegistry
from observation.schema import IDENTIFIER, SHA256, canonical
from shadow_feed import reader
from shadow_feed.errors import ScientificReadRefused
from shadow_live.errors import LiveRefused
from trust import campaign as partition_protection
from trust.timeline import parse_utc_ns

ADAPTER_VERSION = "gate5f-live-3"
DECLARATION_SCHEMA = "azta.gate5f.live_session_declaration"
CLASSES = ("D_shadow", "FUNCTIONAL")
PURPOSE_OF = {"D_shadow": "COLLECTION", "FUNCTIONAL": "FUNCTIONAL_TEST"}
EVIDENCE_CLASS = "LIVE_PROVISIONAL"
_KEYS = {"schema", "schema_version", "declaration_id", "authorization_ref", "partition", "run_id", "plan", "manifest", "reserve_manifests",
         "evidence_root", "raw_evidence_access", "observer", "baseline_policy_sha256", "validity", "tolerances", "audit_interval_s"}


def _fail(code, message):
    raise LiveRefused(code, message)


def _require(condition, code, message):
    if not condition:
        _fail(code, message)


def _sha(blob):
    return hashlib.sha256(blob).hexdigest()


def _reject_constant(name):
    raise ValueError(f"non-finite JSON constant {name}")


def _keys(data, expected, label):
    _require(isinstance(data, dict) and set(data) == set(expected), "DECLARATION_INVALID", f"{label}: unexpected or missing fields")


def _file_ref(item, label):
    _keys(item, {"path", "sha256"}, label)
    _require(isinstance(item["path"], str) and item["path"] and isinstance(item["sha256"], str) and SHA256.fullmatch(item["sha256"]),
             "DECLARATION_INVALID", f"{label}: a relative path and a SHA-256 are required")
    return item["path"], item["sha256"]


@dataclass(frozen=True)
class LiveDeclaration:
    declaration_id: str
    authorization_ref: str
    partition: str
    run_id: str
    plan_path: str
    plan_sha256: str
    manifest_path: object
    manifest_sha256: object
    reserve_manifests: tuple
    evidence_root: str
    raw_access_reference: object
    allow_legacy_observer: bool
    baseline_policy_sha256: str
    valid_from_ns: int
    valid_until_ns: int
    clock_tolerance_ns: int
    stall_timeout_ns: int
    audit_interval_s: int
    data: dict


def parse_declaration(data):
    """Strict structure and types; no file is touched."""
    _keys(data, _KEYS, "declaration")
    _require(data["schema"] == DECLARATION_SCHEMA and data["schema_version"] == 1, "DECLARATION_INVALID", "schema or schema_version")
    for key in ("declaration_id", "authorization_ref", "run_id"):
        _require(isinstance(data[key], str) and IDENTIFIER.fullmatch(data[key]), "DECLARATION_INVALID", f"{key}: identifier required")
    partition = data["partition"]
    if partition in reader.LOCKED_PARTITIONS:
        _fail("PARTITION_LOCKED", f"{partition}: {reader.LOCKED_PARTITIONS[partition]}")
    _require(partition in CLASSES, "PARTITION_UNKNOWN", f"a live session can only be declared for {CLASSES}, not {partition!r}")
    plan_path, plan_sha = _file_ref(data["plan"], "plan")
    _require(plan_path.startswith("configs/collection_plans/"), "DECLARATION_INVALID", "the plan must be a repository collection plan")
    if partition == "D_shadow":
        _require(data["manifest"] is not None and data["reserve_manifests"] == [], "DECLARATION_INVALID",
                 "a D_shadow live session is bound to its manifest and needs no separate reserve manifests")
        manifest_path, manifest_sha = _file_ref(data["manifest"], "manifest")
        reserve = ()
    else:
        _require(data["manifest"] is None and isinstance(data["reserve_manifests"], list) and data["reserve_manifests"], "DECLARATION_INVALID",
                 "a functional live session has no collection manifest and must name at least one reserve manifest")
        manifest_path = manifest_sha = None
        reserve = tuple(_file_ref(item, "reserve_manifests") for item in data["reserve_manifests"])
    for path, _ in ((manifest_path, None), *reserve):
        _require(path is None or path.startswith("configs/collection_manifests/"), "DECLARATION_INVALID", "manifests must be repository configurations")
    root = data["evidence_root"]
    _require(isinstance(root, str) and root.startswith("results/") and "\\" not in root and ".." not in root.split("/"), "DECLARATION_INVALID",
             "evidence_root must be a relative path under results/")
    _keys(data["raw_evidence_access"], {"authorized", "reference"}, "raw_evidence_access")
    authorized, reference = data["raw_evidence_access"]["authorized"], data["raw_evidence_access"]["reference"]
    _require(type(authorized) is bool and ((authorized and isinstance(reference, str) and IDENTIFIER.fullmatch(reference))
                                           or (not authorized and reference is None)), "DECLARATION_INVALID",
             "raw_evidence_access: authorized needs a reference identifier, unauthorized needs null")
    _keys(data["observer"], {"allow_legacy_observer"}, "observer")
    _require(type(data["observer"]["allow_legacy_observer"]) is bool, "DECLARATION_INVALID", "observer.allow_legacy_observer must be a boolean")
    _require(isinstance(data["baseline_policy_sha256"], str) and SHA256.fullmatch(data["baseline_policy_sha256"]), "DECLARATION_INVALID",
             "baseline_policy_sha256: SHA-256 required")
    _keys(data["validity"], {"valid_from_utc", "valid_until_utc"}, "validity")
    try:
        start, end = parse_utc_ns(data["validity"]["valid_from_utc"]), parse_utc_ns(data["validity"]["valid_until_utc"])
    except ValueError as exc:
        _fail("DECLARATION_INVALID", f"validity: {exc}")
    _require(0 < start < end, "DECLARATION_INVALID", "validity: valid_from_utc must precede valid_until_utc")
    _keys(data["tolerances"], {"clock_tolerance_ns", "stall_timeout_ns"}, "tolerances")
    clock, stall = data["tolerances"]["clock_tolerance_ns"], data["tolerances"]["stall_timeout_ns"]
    _require(type(clock) is int and clock > 0 and type(stall) is int and stall > 0, "DECLARATION_INVALID",
             "tolerances: explicit positive integers (nanoseconds); the adapter owns no default")
    interval = data["audit_interval_s"]
    _require(type(interval) is int and interval >= 0, "DECLARATION_INVALID", "audit_interval_s: the declared cadence in seconds (0 = pre/post only)")
    return LiveDeclaration(data["declaration_id"], data["authorization_ref"], partition, data["run_id"], plan_path, plan_sha, manifest_path, manifest_sha,
                           reserve, root, reference if authorized else None, data["observer"]["allow_legacy_observer"], data["baseline_policy_sha256"],
                           start, end, clock, stall, interval, json.loads(canonical(data)))


@dataclass(frozen=True)
class LivePlan:
    """A resolved declaration: everything about the run that comes from committed configuration, nothing from the observer."""
    declaration: LiveDeclaration
    declaration_file_sha256: str
    repo: Path
    plan: dict
    plan_sha256: str
    manifest_sha256: object
    reserved_tokens: frozenset
    evidence_root: Path
    purpose: str
    planned_entry_sha256: object
    run_config: dict
    devices: dict
    window_ns: int
    planned_window_count: int
    eligible: tuple
    workload_version: str
    registry_sha256: str
    observation_config_sha256: str
    schema_fingerprint: str

    @property
    def run_id(self):
        return self.declaration.run_id

    @property
    def partition(self):
        return self.declaration.partition

    def require_valid_at(self, now_ns):
        d = self.declaration
        _require(d.valid_from_ns <= now_ns <= d.valid_until_ns, "AUTHORIZATION_NOT_VALID_NOW",
                 "the live authorization is outside its declared validity interval (an expired authorization is never reused)")

    def describe(self):
        d = self.declaration
        return dict(adapter_version=ADAPTER_VERSION, evidence_class=EVIDENCE_CLASS, declaration_id=d.declaration_id, declaration_file_sha256=self.declaration_file_sha256,
                    authorization_ref=d.authorization_ref, partition_role=d.partition, run_id=d.run_id, purpose=self.purpose,
                    plan=dict(path=d.plan_path, canonical_sha256=self.plan_sha256), manifest=dict(path=d.manifest_path, sha256=self.manifest_sha256),
                    reserve_manifests=[dict(path=p, sha256=s) for p, s in d.reserve_manifests], evidence_root=d.evidence_root,
                    raw_evidence_access_reference=d.raw_access_reference, allow_legacy_observer=d.allow_legacy_observer,
                    baseline_policy_sha256=d.baseline_policy_sha256, validity=dict(valid_from_ns=d.valid_from_ns, valid_until_ns=d.valid_until_ns),
                    tolerances=dict(clock_tolerance_ns=d.clock_tolerance_ns, stall_timeout_ns=d.stall_timeout_ns), audit_interval_s=d.audit_interval_s,
                    workload_version=self.workload_version, planned_window_count=self.planned_window_count, eligible_window_indices=list(self.eligible),
                    window_ns=self.window_ns, devices=sorted(self.devices), planned_entry_sha256=self.planned_entry_sha256,
                    reserved_token_count=len(self.reserved_tokens))


def _wrapped(call, *args, **kwargs):
    """The shared replay-reader validators raise ScientificReadRefused; a declaration reports the same stable code as a LiveRefused."""
    try:
        return call(*args, **kwargs)
    except ScientificReadRefused as exc:
        raise LiveRefused(exc.code, str(exc).split(": ", 1)[-1]) from None


def _evidence_root(repo, declaration):
    root = _wrapped(reader.safe_path, repo, declaration.evidence_root)
    raw = (repo / reader.RAW_REL).resolve()
    resolved = root.resolve()
    touches_raw = resolved == raw or raw in resolved.parents       # any other root under results/ cannot contain the raw root
    _require(declaration.raw_access_reference is not None or not touches_raw, "RAW_EVIDENCE_NOT_AUTHORIZED",
             "the evidence root is or contains the raw evidence root: following a live session there needs an explicit raw-evidence authorization "
             "reference in the declaration (a separately authorized stage; no declaration grants it by default)")
    return root


def _routes(run_config):
    return {device: dict(profile=spec["profile"], username=spec["username"], client_id=spec["client_id"], telemetry_topic=spec["telemetry_topic"])
            for device, spec in run_config["devices"].items()}


def resolve_declaration(repo, declaration, *, declaration_file_sha256):
    """Everything that can be established WITHOUT opening one evidence byte."""
    _require(isinstance(declaration, LiveDeclaration), "DECLARATION_INVALID", "a parsed declaration is required")
    repo = Path(repo).resolve()
    run = declaration.run_id
    if declaration.partition == "D_shadow":
        loaded = _wrapped(reader.load_plan_and_state, repo, plan_rel=declaration.plan_path, manifest_rel=declaration.manifest_path,
                          expected_manifest_sha256=declaration.manifest_sha256)
        plan, state = loaded.plan, loaded.state
        _require(plans.digest(plan) == declaration.plan_sha256, "PLAN_DIGEST_MISMATCH", "the declaration names a different plan")
        cells = {c["run_id"]: c for c in plan["cells"]}
        _require(run in cells and run in state["planned"], "RUN_NOT_PLANNED", f"{run} is not a planned run of the declared plan and manifest")
        for partition, why in reader.LOCKED_PARTITIONS.items():
            _require(cells[run]["intended_partition"] != partition and state["planned"][run]["intended_partition"] != partition,
                     "PARTITION_LOCKED", f"{run} belongs to {partition}: {why}")
        _require(cells[run]["intended_partition"] == "D_shadow" == state["planned"][run]["intended_partition"], "PARTITION_LOCKED",
                 f"{run} does not belong to the declared D_shadow partition")
        _require(run not in state["collected"], "RUN_ALREADY_COLLECTED",
                 f"{run} is already collected: a finished session is replayed by the manifest-verified reader, never followed as live")
        _require(run not in state["voided"] and run not in state["invalidated"], "RUN_NOT_ACTIVE", f"{run} is voided or invalidated")
        reserved = reader.reserved_tokens(state) | loaded.historical_tokens
        manifest_sha, planned_entry = loaded.manifest_sha256, state["planned"][run]["entry_sha256"]
    else:
        plan_blob = _wrapped(reader.safe_path, repo, declaration.plan_path).read_bytes()
        try:
            plan = json.loads(plan_blob, parse_constant=_reject_constant)
            registry = DeviceRegistry.load(_wrapped(reader.safe_path, repo, reader.REGISTRY_REL))
            v1_plan = json.loads(_wrapped(reader.safe_path, repo, reader.V1_PLAN_REL).read_bytes())
            plans_v2.validate_plan_v2(plan, registry, v1_plan=v1_plan)
        except (ValueError, KeyError, TypeError, OSError) as exc:
            _fail("PLAN_INVALID", f"the functional plan does not validate against the registry ({type(exc).__name__}: {str(exc)[:200]})")
        _require(plans.digest(plan) == declaration.plan_sha256, "PLAN_DIGEST_MISMATCH", "the declaration names a different plan")
        _require(plan["kind"] == "FUNCTIONAL_TEST", "PLAN_KIND_MISMATCH", "a functional live session needs a FUNCTIONAL_TEST plan")
        _wrapped(reader.check_plan_pins_and_geometry, plan)
        _require(run in plan["runs"], "RUN_NOT_PLANNED", f"{run} is not a run of the declared plan")
        reserved = set()
        for path, expected in declaration.reserve_manifests:
            blob = _wrapped(reader.safe_path, repo, path).read_bytes()
            _require(_sha(blob) == expected, "MANIFEST_DIGEST_MISMATCH", f"{path}: the declaration names a different reserve manifest")
            try:
                reserved |= partition_protection.reserved_tokens_from_manifest(repo / path, partitions=["D_test"])
            except (ValueError, KeyError, TypeError, OSError) as exc:
                _fail("MANIFEST_INVALID", f"{path}: reserve manifest cannot be validated ({type(exc).__name__})")
        reserved = frozenset(reserved)
        manifest_sha = planned_entry = None
    _require(run not in reserved, "RUN_RESERVED", f"{run} is reserved evidence (held-out, calibration or invalidated) and can never be fed")
    config = plan["runs"][run]
    return LivePlan(
        declaration=declaration, declaration_file_sha256=declaration_file_sha256, repo=repo, plan=plan, plan_sha256=plans.digest(plan),
        manifest_sha256=manifest_sha, reserved_tokens=frozenset(reserved), evidence_root=_evidence_root(repo, declaration),
        purpose=PURPOSE_OF[declaration.partition], planned_entry_sha256=planned_entry, run_config=config, devices=_routes(config),
        window_ns=plan["window_duration_ms"] * 1_000_000, planned_window_count=config["planned_window_count"],
        eligible=tuple(config["eligible_window_indices"]), workload_version=plan["generator_version"], registry_sha256=plan["registry_sha256"],
        observation_config_sha256=plan["observation_config_sha256"], schema_fingerprint=plan["schema_fingerprint"])


def load_declaration(repo, path, *, authorized_sha256):
    """Read a declaration file, require its SHA-256 to equal the digest the controller authorized, parse and resolve it (no evidence is opened)."""
    _require(isinstance(authorized_sha256, str) and SHA256.fullmatch(authorized_sha256), "AUTHORIZATION_INVALID",
             "the authorized declaration SHA-256 is required; there is no default and no ambient permission")
    blob = Path(path).read_bytes()
    digest = _sha(blob)
    _require(digest == authorized_sha256, "DECLARATION_DIGEST_MISMATCH", "the declaration file differs from the digest that was authorized")
    try:
        data = json.loads(blob.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError) as exc:
        _fail("DECLARATION_INVALID", f"the declaration is not valid JSON ({str(exc)[:120]})")
    return resolve_declaration(repo, parse_declaration(data), declaration_file_sha256=digest)
