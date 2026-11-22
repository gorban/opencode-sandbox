"""Pure workflow@1 compilation, live RunAuthorityStore, dir_fd materialization, and lane leases."""

from __future__ import annotations

import hashlib
import math
import os
import re
import secrets
import stat
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal

from oc_workflow_schema import (
    PLAN_DIGEST_DOMAIN,
    SPEC_DIGEST_DOMAIN,
    WorkflowSpec,
    canonical_json_bytes,
    domain_sha256,
    parse_and_validate_workflow_toml,
)

MAX_SKILL_BYTES = 65_536
SKILL_FILENAME = "SKILL.md"
_SAFE_DIR_COMPONENT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")

_STATE_SHAPE_EFFECTS: dict[str, frozenset[str]] = {
    "ship_lane": frozenset({"spawn_lane", "acquire_lane_lease"}),
    "scout_lane": frozenset({"spawn_lane", "acquire_lane_lease"}),
    "parallel_lanes": frozenset({"spawn_lane", "acquire_lane_lease"}),
    "deterministic": frozenset({"launch_sandbox"}),
    "human_gate_async": frozenset({"pause_lane_gate"}),
    "human_gate_blocking": frozenset({"blocking_gate"}),
}

OBSERVE_ONLY_ALLOWED_EFFECTS = frozenset(
    {
        "read_metrics",
        "update_health_projection",
        "post_advisory_inbox",
    }
)

LaneAccess = Literal["exclusive_owner", "nonexclusive_observer"]
CallerRole = Literal["operator", "orchestrator"]
AdmissionMode = Literal["operator_leased", "tier_a_leased", "observe_only_auto"]


class WorkflowPlanError(ValueError):
    """Base error for workflow compilation, admission, materialization, or lane authority."""


class AdmissionDeniedError(WorkflowPlanError):
    """Raised when workflow admission fails security or lease checks."""


class AuthorityError(WorkflowPlanError):
    """Raised when a run authority record is missing, revoked, expired, or out of scope."""


class MaterializationError(WorkflowPlanError):
    """Raised when skill or lockfile materialization fails integrity or path checks."""


class LaneOwnershipConflictError(WorkflowPlanError):
    """Raised when an exclusive lane lease is already held by another run."""


class MixedLaneRoleError(WorkflowPlanError):
    """Raised when a run attempts to hold both exclusive and nonexclusive roles."""


class LaneAuthorityError(WorkflowPlanError):
    """Raised when a run lacks authority to nudge, act on, or observe a target incarnation."""


def is_remote_target(sandbox_addr: str) -> bool:
    """Return True for non-local sandbox addresses (anything outside 'local/...')."""
    return not sandbox_addr.startswith("local/")


@dataclass(frozen=True)
class ClockSnapshot:
    """Explicit injected monotonic and wall clocks (no hidden time.time())."""

    monotonic_s: float
    wall_s: float

    def __post_init__(self) -> None:
        if type(self.monotonic_s) is bool or type(self.wall_s) is bool:
            raise WorkflowPlanError("ClockSnapshot fields must be finite numbers, not bool")
        if not (math.isfinite(self.monotonic_s) and math.isfinite(self.wall_s)):
            raise WorkflowPlanError("ClockSnapshot fields must be finite")


@dataclass(frozen=True)
class TargetIncarnation:
    """Host-assigned target sandbox address and live incarnation identifier."""

    sandbox_addr: str
    incarnation_id: str


@dataclass(frozen=True)
class ModelCatalogEntry:
    """Host model catalog entry for offline tariff and capability validation."""

    route: str
    model: str
    capability: Literal["decisions", "blind_check"]
    max_call_cost_microusd: int


class ModelCatalog:
    """Read-only host model catalog lookup."""

    def __init__(self, entries: tuple[ModelCatalogEntry, ...] = ()) -> None:
        self._by_route_model: dict[tuple[str, str], ModelCatalogEntry] = {}
        self._by_profile: dict[str, ModelCatalogEntry] = {}
        for entry in entries:
            if entry.max_call_cost_microusd < 0:
                raise WorkflowPlanError("catalog tariff must be non-negative")
            self._by_route_model[(entry.route, entry.model)] = entry
            if entry.capability == "blind_check":
                self._by_profile[entry.model] = entry

    def lookup_decisions(self, route: str, model: str) -> ModelCatalogEntry:
        entry = self._by_route_model.get((route, model))
        if entry is None or entry.capability != "decisions":
            raise WorkflowPlanError(f"unknown decisions catalog entry ({route!r}, {model!r})")
        return entry

    def lookup_blind_profile(self, model_profile: str) -> ModelCatalogEntry:
        entry = self._by_profile.get(model_profile)
        if entry is None:
            raise WorkflowPlanError(f"unknown blind_check profile {model_profile!r}")
        return entry


@dataclass(frozen=True)
class CompiledWorkflowPlan:
    """Immutable compiled plan produced side-effect-free by compile_workflow_plan()."""

    spec: WorkflowSpec
    reachable_effects: frozenset[str]
    skill_namespace: str
    skill_slug: str
    skill_bytes: bytes
    skill_sha256: str
    blind_route: str | None
    decisions_call_cost_microusd: int
    blind_call_cost_microusd: int
    workflow_plan_digest: str

    @property
    def spec_digest(self) -> str:
        return self.spec.spec_digest

    @property
    def candidate_rubric_digest(self) -> str | None:
        return self.spec.candidate_rubric_digest

    def to_lock_dict(self) -> dict[str, object]:
        return {
            "blind_call_cost_microusd": self.blind_call_cost_microusd,
            "blind_route": self.blind_route,
            "candidate_rubric_digest": self.candidate_rubric_digest,
            "decisions_call_cost_microusd": self.decisions_call_cost_microusd,
            "reachable_effects": sorted(self.reachable_effects),
            "skill_namespace": self.skill_namespace,
            "skill_sha256": self.skill_sha256,
            "skill_slug": self.skill_slug,
            "spec": self.spec.to_canonical_dict(),
            "spec_digest": self.spec_digest,
            "workflow_plan_digest": self.workflow_plan_digest,
        }


def compute_reachable_effects(spec: WorkflowSpec) -> frozenset[str]:
    """Compute the complete reachable effect closure across all workflow constructs."""
    effects: set[str] = set()
    if spec.autonomy != "observe_only":
        effects.update(("acquire_lane_lease", "nudge_sandbox"))
    if spec.system1 is not None:
        effects.add("call_decisions_model")
    if spec.blind_check is not None:
        effects.add("call_blind_check_model")
    for st in spec.states:
        effects.update(st.effects)
        effects.update(_STATE_SHAPE_EFFECTS.get(st.shape, ()))
        if st.factory_id is not None:
            effects.add("invoke_factory")
    for group in (spec.transitions, spec.timers, spec.signal_handlers):
        for item in group:
            effects.update(item.effects)
    return frozenset(effects) if effects else frozenset({"read_metrics"})


def recompute_plan_digests(plan: CompiledWorkflowPlan) -> tuple[str, str, str]:
    """Recompute (spec_digest, skill_sha256, workflow_plan_digest) from live plan fields & bytes."""
    spec_digest = domain_sha256(SPEC_DIGEST_DOMAIN, plan.spec.to_canonical_dict())
    skill_sha256 = hashlib.sha256(plan.skill_bytes).hexdigest()
    reachable = compute_reachable_effects(plan.spec)
    plan_body = {
        "blind_call_cost_microusd": plan.blind_call_cost_microusd,
        "blind_route": plan.blind_route,
        "decisions_call_cost_microusd": plan.decisions_call_cost_microusd,
        "reachable_effects": sorted(reachable),
        "skill_namespace": plan.spec.skill_namespace,
        "skill_sha256": skill_sha256,
        "skill_slug": plan.spec.skill_slug,
        "spec_digest": spec_digest,
    }
    plan_digest = domain_sha256(PLAN_DIGEST_DOMAIN, plan_body)
    return spec_digest, skill_sha256, plan_digest


def _verify_plan_binding(plan: CompiledWorkflowPlan) -> tuple[str, str, str]:
    """Verify plan wrapper fields agree with spec and recomputed digests."""
    spec_d, skill_d, plan_d = recompute_plan_digests(plan)
    if (spec_d, skill_d, plan_d) != (plan.spec_digest, plan.skill_sha256, plan.workflow_plan_digest):
        raise AdmissionDeniedError("PLAN_INTEGRITY_MISMATCH")
    if plan.reachable_effects != compute_reachable_effects(plan.spec):
        raise AdmissionDeniedError("PLAN_REACHABLE_EFFECTS_MISMATCH")
    if (plan.skill_namespace, plan.skill_slug) != (plan.spec.skill_namespace, plan.spec.skill_slug):
        raise AdmissionDeniedError("PLAN_SKILL_IDENTITY_MISMATCH")
    return spec_d, skill_d, plan_d


# --- Descriptor-anchored trusted traversal, O_NOFOLLOW, O_NONBLOCK, and dir_fd helpers ---


def _is_root_owned_os_alias(path: Path, st: os.stat_result, checker: Callable[[Path], bool] | None) -> bool:
    if checker is not None and checker(path):
        return True
    return st.st_uid == 0


def _check_ancestor_ownership_and_mode(path: Path, st: os.stat_result, expected_uid: int) -> None:
    if st.st_uid not in (0, expected_uid):
        raise MaterializationError(f"ancestor owned by untrusted uid {st.st_uid}: {path}")
    mode = stat.S_IMODE(st.st_mode)
    is_root_sticky = st.st_uid == 0 and bool(st.st_mode & stat.S_ISVTX)
    if (mode & 0o022) != 0 and not is_root_sticky:
        raise MaterializationError(f"ancestor directory is group/world-writable ({oct(mode)}): {path}")


def _resolve_verified_alias_target(
    cur_fd: int,
    part: str,
    cur_path: Path,
    *,
    expected_uid: int,
    root_alias_checker: Callable[[Path], bool] | None,
    max_hops: int = 8,
) -> int:
    """Resolve an approved root-owned symlink alias hop-by-hop, verifying every intermediate target."""
    link_raw = os.readlink(part, dir_fd=cur_fd)
    target_path = Path(link_raw) if Path(link_raw).is_absolute() else (cur_path.parent / link_raw)
    if ".." in target_path.parts:
        raise MaterializationError(f"symlink alias contains '..' traversal: {cur_path} -> {link_raw}")
    return _open_ancestor_chain_fd(
        target_path,
        expected_uid=expected_uid,
        root_alias_checker=root_alias_checker,
        remaining_hops=max_hops - 1,
    )


def _step_ancestor_fd(
    cur_fd: int,
    part: str,
    cur_path: Path,
    *,
    expected_uid: int,
    root_alias_checker: Callable[[Path], bool] | None,
    remaining_hops: int,
) -> int:
    st = os.lstat(part, dir_fd=cur_fd)
    if stat.S_ISLNK(st.st_mode):
        if remaining_hops <= 0:
            raise MaterializationError(f"symlink alias hop limit exceeded: {cur_path}")
        if not _is_root_owned_os_alias(cur_path, st, root_alias_checker):
            raise MaterializationError(f"user-owned symlink ancestor rejected: {cur_path}")
        return _resolve_verified_alias_target(
            cur_fd,
            part,
            cur_path,
            expected_uid=expected_uid,
            root_alias_checker=root_alias_checker,
            max_hops=remaining_hops,
        )
    if not stat.S_ISDIR(st.st_mode):
        raise MaterializationError(f"ancestor is not a directory: {cur_path}")
    _check_ancestor_ownership_and_mode(cur_path, st, expected_uid)
    next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=cur_fd)
    try:
        _check_ancestor_ownership_and_mode(cur_path, os.fstat(next_fd), expected_uid)
    except Exception:
        os.close(next_fd)
        raise
    return next_fd


def _open_ancestor_chain_fd(
    path: Path,
    *,
    expected_uid: int,
    root_alias_checker: Callable[[Path], bool] | None,
    remaining_hops: int = 8,
) -> int:
    if not path.is_absolute() or ".." in path.parts:
        raise MaterializationError(f"unsafe ancestor path rejected: {path}")
    parts = path.parts
    cur_fd = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY)
    cur_path = Path(parts[0])
    try:
        for part in parts[1:]:
            cur_path = cur_path / part
            next_fd = _step_ancestor_fd(
                cur_fd,
                part,
                cur_path,
                expected_uid=expected_uid,
                root_alias_checker=root_alias_checker,
                remaining_hops=remaining_hops,
            )
            os.close(cur_fd)
            cur_fd = next_fd
        return cur_fd
    except Exception:
        os.close(cur_fd)
        raise


def _check_fd_not_in_forbidden_roots(root_fd: int, root: Path, forbidden_sandbox_roots: tuple[Path, ...]) -> None:
    if not forbidden_sandbox_roots:
        return
    try:
        resolved_root = Path(os.readlink(f"/proc/self/fd/{root_fd}")).resolve(strict=False)
    except OSError:
        resolved_root = root.resolve(strict=False)
    root_st = os.fstat(root_fd)
    for forbidden in forbidden_sandbox_roots:
        resolved_forbidden = forbidden.resolve(strict=False)
        if resolved_root == resolved_forbidden or resolved_forbidden in resolved_root.parents:
            raise MaterializationError(f"path resolves inside forbidden sandbox root: {root}")
        try:
            forb_st = os.stat(resolved_forbidden)
            if (root_st.st_dev, root_st.st_ino) == (forb_st.st_dev, forb_st.st_ino):
                raise MaterializationError(f"directory inode matches forbidden sandbox root: {root}")
        except OSError:
            pass


def _open_trusted_root_fd(
    root: Path,
    *,
    expected_uid: int,
    forbidden_sandbox_roots: tuple[Path, ...] = (),
    root_alias_checker: Callable[[Path], bool] | None = None,
) -> int:
    """Anchor traversal from '/' in dir_fds and return the verified 0o700 root_fd directly."""
    if not root.is_absolute() or ".." in root.parts:
        raise MaterializationError(f"trusted directory must be absolute without '..': {root}")
    parts = root.parts
    if len(parts) < 2:
        raise MaterializationError(f"filesystem root cannot be used as trusted root: {root}")

    parent_fd = _open_ancestor_chain_fd(
        root.parent,
        expected_uid=expected_uid,
        root_alias_checker=root_alias_checker,
    )
    try:
        root_fd = os.open(parts[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except OSError as exc:
        raise MaterializationError(f"failed to open trusted root {root}: {exc}") from exc
    finally:
        os.close(parent_fd)

    try:
        root_st = os.fstat(root_fd)
        if root_st.st_uid != expected_uid:
            raise MaterializationError(f"root owned by unexpected uid {root_st.st_uid}: {root}")
        if stat.S_IMODE(root_st.st_mode) != 0o700:
            raise MaterializationError(
                f"root must have exact mode 0o700, got {oct(stat.S_IMODE(root_st.st_mode))}: {root}"
            )
        _check_fd_not_in_forbidden_roots(root_fd, root, forbidden_sandbox_roots)
        return root_fd
    except Exception:
        os.close(root_fd)
        raise


def _open_verified_dir_fd(parent_fd: int, name: str, *, expected_uid: int) -> int:
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        st = os.fstat(fd)
        if st.st_uid != expected_uid:
            raise MaterializationError(f"directory {name!r} has wrong uid {st.st_uid}")
        if stat.S_IMODE(st.st_mode) != 0o700:
            raise MaterializationError(
                f"directory {name!r} must have exact mode 0o700, got {oct(stat.S_IMODE(st.st_mode))}"
            )
        return fd
    except Exception:
        os.close(fd)
        raise


def _ensure_subdir_fd(parent_fd: int, name: str, *, expected_uid: int) -> int:
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    return _open_verified_dir_fd(parent_fd, name, expected_uid=expected_uid)


def _read_skill_bytes_strict(
    skill_root: Path,
    skill_namespace: str,
    skill_slug: str,
    *,
    expected_uid: int,
    forbidden_sandbox_roots: tuple[Path, ...] = (),
    root_alias_checker: Callable[[Path], bool] | None = None,
) -> bytes:
    """Read <skill_root>/<ns>/<slug>/SKILL.md anchored strictly on verified root_fd."""
    root_fd = _open_trusted_root_fd(
        skill_root,
        expected_uid=expected_uid,
        forbidden_sandbox_roots=forbidden_sandbox_roots,
        root_alias_checker=root_alias_checker,
    )
    ns_fd = slug_fd = file_fd = -1
    try:
        ns_fd = _open_verified_dir_fd(root_fd, skill_namespace, expected_uid=expected_uid)
        slug_fd = _open_verified_dir_fd(ns_fd, skill_slug, expected_uid=expected_uid)
        file_fd = os.open(
            SKILL_FILENAME,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=slug_fd,
        )
        st = os.fstat(file_fd)
        if not stat.S_ISREG(st.st_mode):
            raise MaterializationError("skill source is not a regular file")
        if st.st_uid != expected_uid:
            raise MaterializationError(f"skill source has unexpected uid {st.st_uid}")
        if stat.S_IMODE(st.st_mode) != 0o600:
            raise MaterializationError(
                f"skill source must have exact mode 0o600, got {oct(stat.S_IMODE(st.st_mode))}"
            )
        if st.st_nlink != 1:
            raise MaterializationError(f"skill source must have st_nlink == 1, got {st.st_nlink}")
        if st.st_size > MAX_SKILL_BYTES:
            raise MaterializationError(f"skill source exceeds {MAX_SKILL_BYTES} bytes")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(file_fd, 8192)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_SKILL_BYTES:
                raise MaterializationError(f"skill source exceeded {MAX_SKILL_BYTES} bytes during read")
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError as exc:
        raise MaterializationError(f"failed to read trusted skill source: {exc}") from exc
    finally:
        for fd in (file_fd, slug_fd, ns_fd, root_fd):
            if fd >= 0:
                os.close(fd)


def _atomic_write_readonly(dir_fd: int, filename: str, data: bytes) -> None:
    tmp_name = f".{filename}.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(tmp_name, flags, 0o600, dir_fd=dir_fd)
    try:
        view = memoryview(data)
        written = 0
        while written < len(view):
            written += os.write(fd, view[written:])
        os.fsync(fd)
        os.fchmod(fd, 0o400)
    except Exception:
        os.close(fd)
        try:
            os.unlink(tmp_name, dir_fd=dir_fd)
        except OSError:
            pass
        raise
    os.close(fd)
    try:
        os.replace(tmp_name, filename, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        os.fsync(dir_fd)
    except Exception:
        try:
            os.unlink(tmp_name, dir_fd=dir_fd)
        except OSError:
            pass
        raise


def compile_workflow_plan(
    raw_toml: str,
    *,
    is_builtin: bool,
    skill_root: Path,
    model_catalog: ModelCatalog,
    allowlisted_factories: frozenset[str] = frozenset(),
    forbidden_sandbox_roots: tuple[Path, ...] = (),
    expected_uid: int | None = None,
    root_alias_checker: Callable[[Path], bool] | None = None,
) -> CompiledWorkflowPlan:
    """Strictly side-effect-free compilation pinning skill bytes and computing plan digest."""
    uid = os.getuid() if expected_uid is None else expected_uid
    spec = parse_and_validate_workflow_toml(
        raw_toml,
        is_builtin=is_builtin,
        allowlisted_factories=allowlisted_factories,
    )
    reachable = compute_reachable_effects(spec)

    decisions_cost = 0
    if spec.system1 is not None:
        d_entry = model_catalog.lookup_decisions(spec.system1.route, spec.system1.model)
        decisions_cost = d_entry.max_call_cost_microusd
        if spec.limits.max_decisions_spend_microusd < decisions_cost:
            raise WorkflowPlanError("max_decisions_spend_usd is below single-call catalog tariff")

    blind_route: str | None = None
    blind_cost = 0
    if spec.blind_check is not None:
        b_entry = model_catalog.lookup_blind_profile(spec.blind_check.model_profile)
        blind_route = b_entry.route
        blind_cost = b_entry.max_call_cost_microusd
        if spec.limits.max_blind_check_spend_microusd < blind_cost:
            raise WorkflowPlanError("max_blind_check_spend_usd is below single-call catalog tariff")

    skill_bytes = _read_skill_bytes_strict(
        skill_root,
        spec.skill_namespace,
        spec.skill_slug,
        expected_uid=uid,
        forbidden_sandbox_roots=forbidden_sandbox_roots,
        root_alias_checker=root_alias_checker,
    )
    skill_sha256 = hashlib.sha256(skill_bytes).hexdigest()

    plan_body = {
        "blind_call_cost_microusd": blind_cost,
        "blind_route": blind_route,
        "decisions_call_cost_microusd": decisions_cost,
        "reachable_effects": sorted(reachable),
        "skill_namespace": spec.skill_namespace,
        "skill_sha256": skill_sha256,
        "skill_slug": spec.skill_slug,
        "spec_digest": spec.spec_digest,
    }
    plan_digest = domain_sha256(PLAN_DIGEST_DOMAIN, plan_body)
    return CompiledWorkflowPlan(
        spec=spec,
        reachable_effects=reachable,
        skill_namespace=spec.skill_namespace,
        skill_slug=spec.skill_slug,
        skill_bytes=skill_bytes,
        skill_sha256=skill_sha256,
        blind_route=blind_route,
        decisions_call_cost_microusd=decisions_cost,
        blind_call_cost_microusd=blind_cost,
        workflow_plan_digest=plan_digest,
    )


# --- Live RunAuthorityStore (with fixture-owned budgets & incarnation tracking) ---


@dataclass(frozen=True)
class EffectiveTargetScope:
    """Narrowed target scope bound into RunAuthorityRecord, enforcing remote eligibility."""

    selector: str
    allowed_targets: frozenset[str]
    all_running_allowed: bool
    allow_remote_workers: bool

    def is_non_vacuous(self) -> bool:
        return self.all_running_allowed or len(self.allowed_targets) > 0

    def allows(self, sandbox_addr: str) -> bool:
        if not self.allow_remote_workers and is_remote_target(sandbox_addr):
            return False
        if self.all_running_allowed:
            return True
        return sandbox_addr in self.allowed_targets


@dataclass(frozen=True)
class WorkflowRunLease:
    """Tier-A approved lease input presented to evaluate_admission()."""

    run_id: str
    grant_generation: int
    principal_id: str
    owner_role: CallerRole
    workflow_id: str
    workflow_plan_digest: str
    expires_at_wall_s: float
    revoked: bool = False

    def __post_init__(self) -> None:
        if type(self.expires_at_wall_s) is bool or not math.isfinite(self.expires_at_wall_s):
            raise AdmissionDeniedError("WorkflowRunLease.expires_at_wall_s must be a finite number")


@dataclass(frozen=True)
class AdmissionReceipt:
    """Non-self-authorizing reference to a live RunAuthorityRecord."""

    run_id: str
    grant_generation: int
    workflow_plan_digest: str
    workflow_id: str


@dataclass
class _RunAccountingState:
    """Fixture-owned per-(run_id, grant_generation) budget state derived from admitted limits."""

    max_decisions_calls_per_hour: int
    max_decisions_spend_microusd: int
    max_blind_spend_microusd: int
    min_nudge_interval_s: int
    max_nudges_per_target_per_hour: int
    max_total_nudges_per_run: int
    decisions_call_times: deque[float]
    decisions_spend_microusd_used: int = 0
    blind_spend_microusd_used: int = 0
    nudge_target_times: dict[TargetIncarnation, deque[float]] | None = None
    total_nudges: int = 0
    seen_dedupe_keys: set[str] | None = None

    def __post_init__(self) -> None:
        if self.nudge_target_times is None:
            self.nudge_target_times = {}
        if self.seen_dedupe_keys is None:
            self.seen_dedupe_keys = set()


@dataclass
class RunAuthorityRecord:
    """Authoritative live in-memory run authority record."""

    run_id: str
    grant_generation: int
    principal_id: str
    owner_role: CallerRole
    workflow_id: str
    workflow_plan_digest: str
    approved_plan: CompiledWorkflowPlan
    admission_mode: AdmissionMode
    lane_access: LaneAccess
    effective_target_scope: EffectiveTargetScope
    expires_at_wall_s: float
    revoked: bool = False
    materialized: bool = False


class RunAuthorityStore:
    """Fixture-owned single source of live run authority, incarnation state, and run budgets."""

    def __init__(self) -> None:
        self._records: dict[str, RunAuthorityRecord] = {}
        self._accounting: dict[tuple[str, int], _RunAccountingState] = {}
        self._revoked_incarnations: set[TargetIncarnation] = set()
        self._active_incarnations: dict[str, str] = {}
        self._next_gen = 1

    def register_active_incarnation(self, target: TargetIncarnation) -> None:
        if target in self._revoked_incarnations:
            raise AuthorityError("TARGET_INCARNATION_REVOKED")
        prev = self._active_incarnations.get(target.sandbox_addr)
        if prev is not None and prev != target.incarnation_id:
            self._revoked_incarnations.add(TargetIncarnation(target.sandbox_addr, prev))
        self._active_incarnations[target.sandbox_addr] = target.incarnation_id

    def revoke_target_incarnation(self, target: TargetIncarnation) -> None:
        self._revoked_incarnations.add(target)
        if self._active_incarnations.get(target.sandbox_addr) == target.incarnation_id:
            del self._active_incarnations[target.sandbox_addr]

    def is_incarnation_active(self, target: TargetIncarnation) -> bool:
        """Require exact match against independently registered fixture inventory."""
        if target in self._revoked_incarnations:
            return False
        return self._active_incarnations.get(target.sandbox_addr) == target.incarnation_id

    def _init_accounting(self, record: RunAuthorityRecord) -> None:
        lim = record.approved_plan.spec.limits
        self._accounting[(record.run_id, record.grant_generation)] = _RunAccountingState(
            max_decisions_calls_per_hour=lim.max_decisions_calls_per_hour,
            max_decisions_spend_microusd=lim.max_decisions_spend_microusd,
            max_blind_spend_microusd=lim.max_blind_check_spend_microusd,
            min_nudge_interval_s=lim.min_nudge_interval_s,
            max_nudges_per_target_per_hour=lim.max_nudges_per_target_per_hour,
            max_total_nudges_per_run=lim.max_total_nudges_per_run,
            decisions_call_times=deque(),
        )

    def _get_accounting(self, run_id: str, grant_generation: int) -> _RunAccountingState:
        acct = self._accounting.get((run_id, grant_generation))
        if acct is None:
            raise AuthorityError("missing run accounting state")
        return acct

    def mint_record(
        self,
        *,
        run_id: str,
        grant_generation: int,
        principal_id: str,
        owner_role: CallerRole,
        plan: CompiledWorkflowPlan,
        admission_mode: AdmissionMode,
        lane_access: LaneAccess,
        effective_target_scope: EffectiveTargetScope,
        expires_at_wall_s: float,
    ) -> AdmissionReceipt:
        if not run_id or run_id in self._records:
            raise AdmissionDeniedError(f"run_id {run_id!r} invalid or already minted")
        if grant_generation < 1:
            raise AdmissionDeniedError("grant_generation must be >= 1")
        if not math.isfinite(expires_at_wall_s):
            raise AdmissionDeniedError("expires_at_wall_s must be finite")
        _, _, plan_d = _verify_plan_binding(plan)
        record = RunAuthorityRecord(
            run_id=run_id,
            grant_generation=grant_generation,
            principal_id=principal_id,
            owner_role=owner_role,
            workflow_id=plan.spec.id,
            workflow_plan_digest=plan_d,
            approved_plan=plan,
            admission_mode=admission_mode,
            lane_access=lane_access,
            effective_target_scope=effective_target_scope,
            expires_at_wall_s=expires_at_wall_s,
        )
        self._records[run_id] = record
        self._init_accounting(record)
        return AdmissionReceipt(
            run_id=run_id,
            grant_generation=grant_generation,
            workflow_plan_digest=plan_d,
            workflow_id=plan.spec.id,
        )

    def mint_fresh_run(
        self,
        *,
        principal_id: str,
        owner_role: CallerRole,
        plan: CompiledWorkflowPlan,
        admission_mode: AdmissionMode,
        lane_access: LaneAccess,
        effective_target_scope: EffectiveTargetScope,
        expires_at_wall_s: float,
    ) -> AdmissionReceipt:
        run_id = f"wfrun_{secrets.token_hex(8)}"
        gen = self._next_gen
        self._next_gen += 1
        return self.mint_record(
            run_id=run_id,
            grant_generation=gen,
            principal_id=principal_id,
            owner_role=owner_role,
            plan=plan,
            admission_mode=admission_mode,
            lane_access=lane_access,
            effective_target_scope=effective_target_scope,
            expires_at_wall_s=expires_at_wall_s,
        )

    def revoke_run(self, run_id: str) -> None:
        record = self._records.get(run_id)
        if record is not None:
            record.revoked = True

    def mark_materialized(self, run_id: str, grant_generation: int) -> None:
        record = self._records.get(run_id)
        if record is None or record.grant_generation != grant_generation:
            raise AuthorityError("cannot mark unknown or mismatched run materialized")
        if record.materialized:
            raise AuthorityError("RECEIPT_ALREADY_MATERIALIZED")
        record.materialized = True

    def verify_active(
        self,
        receipt: AdmissionReceipt,
        *,
        clock: ClockSnapshot,
        expected_plan_digest: str | None = None,
        target: TargetIncarnation | None = None,
    ) -> RunAuthorityRecord:
        record = self._records.get(receipt.run_id)
        if record is None:
            raise AuthorityError(f"unknown run_id {receipt.run_id!r}")
        if record.grant_generation != receipt.grant_generation:
            raise AuthorityError("GRANT_GENERATION_MISMATCH")
        if record.revoked:
            raise AuthorityError("RUN_REVOKED")
        if clock.wall_s >= record.expires_at_wall_s:
            raise AuthorityError("RUN_EXPIRED")
        if record.workflow_plan_digest != receipt.workflow_plan_digest or record.workflow_id != receipt.workflow_id:
            raise AuthorityError("RECEIPT_DIGEST_MISMATCH")
        if expected_plan_digest is not None and record.workflow_plan_digest != expected_plan_digest:
            raise AuthorityError("PLAN_DIGEST_MISMATCH")
        if target is not None:
            if not self.is_incarnation_active(target):
                raise AuthorityError("TARGET_INCARNATION_REVOKED")
            if not record.effective_target_scope.allows(target.sandbox_addr):
                raise AuthorityError(f"target {target.sandbox_addr!r} outside effective_target_scope")
        return record

    def verify_record_access(
        self,
        *,
        run_id: str,
        principal_id: str,
        caller_role: CallerRole,
        caller_subtree: frozenset[str],
        target: TargetIncarnation,
        clock: ClockSnapshot,
    ) -> RunAuthorityRecord:
        """Verify live run & exact incarnation authorization for calibration queries and replay."""
        record = self._records.get(run_id)
        if record is None:
            raise AuthorityError(f"unknown run_id {run_id!r}")
        if record.revoked:
            raise AuthorityError("RUN_REVOKED")
        if clock.wall_s >= record.expires_at_wall_s:
            raise AuthorityError("RUN_EXPIRED")
        if not self.is_incarnation_active(target):
            raise AuthorityError("TARGET_INCARNATION_REVOKED")
        if not record.effective_target_scope.allows(target.sandbox_addr):
            raise AuthorityError(f"target {target.sandbox_addr!r} outside run target scope")
        if caller_role == "orchestrator":
            if record.owner_role != "orchestrator" or record.principal_id != principal_id:
                raise AuthorityError("orchestrator cannot access another principal's or operator run")
            if target.sandbox_addr not in caller_subtree:
                raise AuthorityError(f"target {target.sandbox_addr!r} outside caller subtree")
        return record

    # --- Authoritative fixture-owned budget operations keyed by (run_id, grant_generation) ---

    def reserve_decisions_budget(
        self,
        receipt: AdmissionReceipt,
        *,
        calls: int,
        cost_microusd: int,
        clock: ClockSnapshot,
    ) -> bool:
        record = self.verify_active(receipt, clock=clock)
        acct = self._get_accounting(record.run_id, record.grant_generation)
        cutoff = clock.monotonic_s - 3600.0
        while acct.decisions_call_times and acct.decisions_call_times[0] <= cutoff:
            acct.decisions_call_times.popleft()
        if len(acct.decisions_call_times) + calls > acct.max_decisions_calls_per_hour:
            return False
        if acct.decisions_spend_microusd_used + cost_microusd > acct.max_decisions_spend_microusd:
            return False
        for _ in range(calls):
            acct.decisions_call_times.append(clock.monotonic_s)
        acct.decisions_spend_microusd_used += cost_microusd
        return True

    def can_afford_blind(self, receipt: AdmissionReceipt, *, cost_microusd: int, clock: ClockSnapshot) -> bool:
        record = self.verify_active(receipt, clock=clock)
        acct = self._get_accounting(record.run_id, record.grant_generation)
        return acct.blind_spend_microusd_used + cost_microusd <= acct.max_blind_spend_microusd

    def reserve_blind_budget(
        self,
        receipt: AdmissionReceipt,
        *,
        cost_microusd: int,
        clock: ClockSnapshot,
    ) -> bool:
        record = self.verify_active(receipt, clock=clock)
        acct = self._get_accounting(record.run_id, record.grant_generation)
        if acct.blind_spend_microusd_used + cost_microusd > acct.max_blind_spend_microusd:
            return False
        acct.blind_spend_microusd_used += cost_microusd
        return True

    def allow_and_record_nudge(
        self,
        receipt: AdmissionReceipt,
        target: TargetIncarnation,
        *,
        dedupe_key: str,
        clock: ClockSnapshot,
    ) -> bool:
        record = self.verify_active(receipt, clock=clock, target=target)
        acct = self._get_accounting(record.run_id, record.grant_generation)
        seen = acct.seen_dedupe_keys
        target_map = acct.nudge_target_times
        if seen is None or target_map is None or dedupe_key in seen:
            return False
        if acct.total_nudges >= acct.max_total_nudges_per_run:
            return False
        times = target_map.setdefault(target, deque())
        cutoff = clock.monotonic_s - 3600.0
        while times and times[0] <= cutoff:
            times.popleft()
        if len(times) >= acct.max_nudges_per_target_per_hour:
            return False
        if times and (clock.monotonic_s - times[-1]) < acct.min_nudge_interval_s:
            return False
        times.append(clock.monotonic_s)
        acct.total_nudges += 1
        seen.add(dedupe_key)
        return True

    def run_usage(self, receipt: AdmissionReceipt) -> dict[str, int]:
        acct = self._get_accounting(receipt.run_id, receipt.grant_generation)
        return {
            "blind_spend_microusd_used": acct.blind_spend_microusd_used,
            "decisions_spend_microusd_used": acct.decisions_spend_microusd_used,
            "total_nudges": acct.total_nudges,
        }


def _compute_effective_target_scope(
    plan: CompiledWorkflowPlan,
    *,
    caller_role: CallerRole,
    caller_subtree: frozenset[str],
    project_members: frozenset[str],
) -> EffectiveTargetScope:
    selector = plan.spec.scope.target_selector
    allow_remote = plan.spec.scope.allow_remote_workers
    if selector == "all_running_sandboxes":
        if caller_role != "operator":
            raise AdmissionDeniedError("all_running_sandboxes requires operator role")
        return EffectiveTargetScope(
            selector=selector,
            allowed_targets=frozenset(),
            all_running_allowed=True,
            allow_remote_workers=allow_remote,
        )
    if selector == "bound_targets":
        bound = frozenset(plan.spec.scope.bound_targets)
        if not bound:
            raise AdmissionDeniedError("bound_targets cannot be empty")
        if not allow_remote and any(is_remote_target(addr) for addr in bound):
            raise AdmissionDeniedError("bound_targets includes remote worker while allow_remote_workers is false")
        if caller_role == "orchestrator" and not bound.issubset(caller_subtree):
            raise AdmissionDeniedError("bound_targets exceed caller_subtree")
        return EffectiveTargetScope(
            selector=selector,
            allowed_targets=bound,
            all_running_allowed=False,
            allow_remote_workers=allow_remote,
        )
    # project_scope: NEVER wildcard! Strictly resolved from fixture-owned project_members
    # (intersected with caller_subtree for orchestrator) and filtered by remote eligibility.
    candidates = project_members if caller_role == "operator" else (project_members & caller_subtree)
    eligible = frozenset(addr for addr in candidates if allow_remote or not is_remote_target(addr))
    if not eligible:
        raise AdmissionDeniedError("project_scope resolved to empty eligible target set")
    return EffectiveTargetScope(
        selector=selector,
        allowed_targets=eligible,
        all_running_allowed=False,
        allow_remote_workers=allow_remote,
    )


def _verify_tier_a_lease(
    plan: CompiledWorkflowPlan,
    lease: WorkflowRunLease,
    *,
    principal_id: str,
    caller_role: CallerRole,
    clock: ClockSnapshot,
) -> None:
    if lease.revoked:
        raise AdmissionDeniedError("TIER_A_LEASE_REVOKED")
    if clock.wall_s >= lease.expires_at_wall_s:
        raise AdmissionDeniedError("TIER_A_LEASE_EXPIRED")
    if lease.workflow_plan_digest != plan.workflow_plan_digest:
        raise AdmissionDeniedError("TIER_A_LEASE_DIGEST_MISMATCH")
    if lease.workflow_id != plan.spec.id:
        raise AdmissionDeniedError("TIER_A_LEASE_WORKFLOW_MISMATCH")
    if lease.owner_role != caller_role or lease.principal_id != principal_id:
        raise AdmissionDeniedError("TIER_A_LEASE_PRINCIPAL_MISMATCH")


def _validate_positive_ttl(ttl: float, name: str) -> None:
    if type(ttl) is bool or not isinstance(ttl, (int, float)) or not math.isfinite(ttl) or ttl <= 0:
        raise AdmissionDeniedError(f"{name} must be a positive finite number")


def _can_auto_admit_observe_only(
    plan: CompiledWorkflowPlan,
    effective_scope: EffectiveTargetScope,
    *,
    active_orchestrator_runs: int,
    max_active_orchestrator_runs: int,
) -> bool:
    lim = plan.spec.limits
    zero_caps = (
        lim.max_decisions_spend_microusd == 0
        and lim.max_blind_check_spend_microusd == 0
        and lim.max_decisions_calls_per_hour == 0
        and lim.max_nudges_per_target_per_hour == 0
        and lim.max_total_nudges_per_run == 0
    )
    return (
        plan.spec.autonomy == "observe_only"
        and zero_caps
        and plan.spec.excerpt_disclosure.mode == "none"
        and effective_scope.is_non_vacuous()
        and active_orchestrator_runs < max_active_orchestrator_runs
        and compute_reachable_effects(plan.spec).issubset(OBSERVE_ONLY_ALLOWED_EFFECTS)
    )


def evaluate_admission(
    plan: CompiledWorkflowPlan,
    authority_store: RunAuthorityStore,
    *,
    principal_id: str,
    caller_role: CallerRole,
    caller_subtree: frozenset[str],
    active_orchestrator_runs: int,
    max_active_orchestrator_runs: int,
    clock: ClockSnapshot,
    project_members: frozenset[str] = frozenset(),
    operator_lease_ttl_s: float = 3600.0,
    auto_observer_ttl_s: float = 3600.0,
    tier_a_lease: WorkflowRunLease | None = None,
) -> AdmissionReceipt:
    """Admit a compiled plan and mint its live RunAuthorityRecord."""
    _verify_plan_binding(plan)
    _validate_positive_ttl(operator_lease_ttl_s, "operator_lease_ttl_s")
    _validate_positive_ttl(auto_observer_ttl_s, "auto_observer_ttl_s")
    lane_access: LaneAccess = (
        "nonexclusive_observer"
        if plan.spec.autonomy == "observe_only"
        else "exclusive_owner"
    )
    effective_scope = _compute_effective_target_scope(
        plan,
        caller_role=caller_role,
        caller_subtree=caller_subtree,
        project_members=project_members,
    )

    if tier_a_lease is not None:
        _verify_tier_a_lease(plan, tier_a_lease, principal_id=principal_id, caller_role=caller_role, clock=clock)
        return authority_store.mint_record(
            run_id=tier_a_lease.run_id,
            grant_generation=tier_a_lease.grant_generation,
            principal_id=principal_id,
            owner_role=caller_role,
            plan=plan,
            admission_mode="tier_a_leased",
            lane_access=lane_access,
            effective_target_scope=effective_scope,
            expires_at_wall_s=tier_a_lease.expires_at_wall_s,
        )

    if caller_role == "operator":
        return authority_store.mint_fresh_run(
            principal_id=principal_id,
            owner_role="operator",
            plan=plan,
            admission_mode="operator_leased",
            lane_access=lane_access,
            effective_target_scope=effective_scope,
            expires_at_wall_s=clock.wall_s + operator_lease_ttl_s,
        )

    if not _can_auto_admit_observe_only(
        plan,
        effective_scope,
        active_orchestrator_runs=active_orchestrator_runs,
        max_active_orchestrator_runs=max_active_orchestrator_runs,
    ):
        raise AdmissionDeniedError("TIER_A_APPROVAL_REQUIRED")
    return authority_store.mint_fresh_run(
        principal_id=principal_id,
        owner_role="orchestrator",
        plan=plan,
        admission_mode="observe_only_auto",
        lane_access="nonexclusive_observer",
        effective_target_scope=effective_scope,
        expires_at_wall_s=clock.wall_s + auto_observer_ttl_s,
    )


@dataclass(frozen=True)
class MaterializedArtifacts:
    """Paths and digest produced by approved materialize_workflow_plan()."""

    skill_path: Path
    lockfile_path: Path
    digest: str


def materialize_workflow_plan(
    plan: CompiledWorkflowPlan,
    receipt: AdmissionReceipt,
    *,
    authority_store: RunAuthorityStore,
    clock: ClockSnapshot,
    staging_root: Path,
    forbidden_sandbox_roots: tuple[Path, ...] = (),
    expected_uid: int | None = None,
    root_alias_checker: Callable[[Path], bool] | None = None,
) -> MaterializedArtifacts:
    """Recompute complete plan binding and materialize anchored on verified root_fd into digest-scoped path."""
    uid = os.getuid() if expected_uid is None else expected_uid
    record = authority_store.verify_active(
        receipt, clock=clock, expected_plan_digest=plan.workflow_plan_digest
    )
    if record.materialized:
        raise MaterializationError("RECEIPT_ALREADY_MATERIALIZED")

    try:
        spec_d, skill_d, plan_d = _verify_plan_binding(plan)
    except AdmissionDeniedError as exc:
        raise MaterializationError("PLAN_INTEGRITY_MISMATCH") from exc
    approved = record.approved_plan
    if (
        plan_d != record.workflow_plan_digest
        or spec_d != approved.spec_digest
        or skill_d != approved.skill_sha256
        or plan.skill_bytes != approved.skill_bytes
    ):
        raise MaterializationError("PLAN_INTEGRITY_MISMATCH")

    # Digest-specific skill directory derived strictly from verified spec & validated as one component!
    skill_dir_name = f"wf-{approved.spec.skill_namespace}-{approved.spec.skill_slug}-{plan_d[:16]}"
    if not _SAFE_DIR_COMPONENT_RE.match(skill_dir_name):
        raise MaterializationError(f"invalid skill directory component: {skill_dir_name!r}")
    lock_filename = f"{plan_d}.lock.json"
    lock_bytes = canonical_json_bytes(approved.to_lock_dict())

    # Open trusted staging_root ONCE via descriptor-anchored traversal and never reopen by pathname!
    root_fd = _open_trusted_root_fd(
        staging_root,
        expected_uid=uid,
        forbidden_sandbox_roots=forbidden_sandbox_roots,
        root_alias_checker=root_alias_checker,
    )
    skills_fd = wf_skill_fd = plans_fd = -1
    try:
        skills_fd = _ensure_subdir_fd(root_fd, "skills", expected_uid=uid)
        wf_skill_fd = _ensure_subdir_fd(skills_fd, skill_dir_name, expected_uid=uid)
        plans_fd = _ensure_subdir_fd(root_fd, "plans", expected_uid=uid)
        _atomic_write_readonly(wf_skill_fd, SKILL_FILENAME, approved.skill_bytes)
        _atomic_write_readonly(plans_fd, lock_filename, lock_bytes)
    finally:
        for fd in (plans_fd, wf_skill_fd, skills_fd, root_fd):
            if fd >= 0:
                os.close(fd)

    authority_store.mark_materialized(record.run_id, record.grant_generation)
    return MaterializedArtifacts(
        skill_path=staging_root / "skills" / skill_dir_name / SKILL_FILENAME,
        lockfile_path=staging_root / "plans" / lock_filename,
        digest=plan_d,
    )


# --- Exclusive workflow_lane_leases vs. nonexclusive workflow_observer_subscriptions ---


class LaneLeaseRegistry:
    """Enforces exclusive lane ownership for active runs, nonexclusive observer subs, and pause/action checks."""

    def __init__(self) -> None:
        self._exclusive: dict[TargetIncarnation, str] = {}
        self._observers: dict[TargetIncarnation, set[str]] = {}
        self._run_roles: dict[str, LaneAccess] = {}
        self._paused_runs: set[str] = set()

    def attach(
        self,
        target: TargetIncarnation,
        *,
        receipt: AdmissionReceipt,
        authority_store: RunAuthorityStore,
        clock: ClockSnapshot,
    ) -> None:
        record = authority_store.verify_active(receipt, clock=clock, target=target)
        run_id = record.run_id
        if run_id in self._run_roles and self._run_roles[run_id] != record.lane_access:
            raise MixedLaneRoleError(f"run {run_id!r} cannot hold mixed lane roles")
        self._run_roles[run_id] = record.lane_access

        if record.lane_access == "nonexclusive_observer":
            if self._exclusive.get(target) == run_id:
                raise MixedLaneRoleError(f"run {run_id!r} already holds exclusive lease")
            self._observers.setdefault(target, set()).add(run_id)
            return

        if run_id in self._observers.get(target, ()):
            raise MixedLaneRoleError(f"run {run_id!r} already attached as observer")
        existing = self._exclusive.get(target)
        if existing is not None and existing != run_id:
            raise LaneOwnershipConflictError(f"{target} already owned by {existing!r}")
        self._exclusive[target] = run_id

    def exclusive_owner(self, target: TargetIncarnation) -> str | None:
        return self._exclusive.get(target)

    def observers(self, target: TargetIncarnation) -> frozenset[str]:
        return frozenset(self._observers.get(target, ()))

    def pause(self, run_id: str) -> None:
        self._paused_runs.add(run_id)

    def resume(self, run_id: str) -> None:
        self._paused_runs.discard(run_id)

    def is_paused(self, run_id: str) -> bool:
        return run_id in self._paused_runs

    def assert_can_nudge(
        self,
        receipt: AdmissionReceipt,
        target: TargetIncarnation,
        *,
        authority_store: RunAuthorityStore,
        clock: ClockSnapshot,
    ) -> None:
        record = authority_store.verify_active(receipt, clock=clock, target=target)
        if self.is_paused(record.run_id):
            raise LaneAuthorityError("RUN_PAUSED")
        if self._exclusive.get(target) != record.run_id:
            raise LaneAuthorityError(f"run {record.run_id!r} does not hold exclusive lease on {target}")

    def assert_can_observe(
        self,
        receipt: AdmissionReceipt,
        target: TargetIncarnation,
        *,
        authority_store: RunAuthorityStore,
        clock: ClockSnapshot,
    ) -> None:
        record = authority_store.verify_active(receipt, clock=clock, target=target)
        if self._exclusive.get(target) != record.run_id and record.run_id not in self._observers.get(target, ()):
            raise LaneAuthorityError(f"run {record.run_id!r} is not attached to {target}")

    def assert_can_act(
        self,
        receipt: AdmissionReceipt,
        target: TargetIncarnation,
        *,
        action: str,
        authority_store: RunAuthorityStore,
        clock: ClockSnapshot,
    ) -> None:
        """Enforce pause, live incarnation binding, and action-specific autonomy permissions."""
        record = authority_store.verify_active(receipt, clock=clock, target=target)
        if self.is_paused(record.run_id):
            raise LaneAuthorityError("RUN_PAUSED")
        autonomy = record.approved_plan.spec.autonomy
        if action == "health_nudge_lane":
            if autonomy not in ("nudge_bounded", "orchestrator_signal"):
                raise LaneAuthorityError(f"autonomy {autonomy!r} cannot execute health_nudge_lane")
            if self._exclusive.get(target) != record.run_id:
                raise LaneAuthorityError("exclusive lane lease required for health_nudge_lane")
            return
        if action == "health_wake_orchestrator":
            if autonomy != "orchestrator_signal":
                raise LaneAuthorityError(f"autonomy {autonomy!r} cannot execute health_wake_orchestrator")
            if self._exclusive.get(target) != record.run_id:
                raise LaneAuthorityError("exclusive lane lease required for health_wake_orchestrator")
            return
        if action == "health_escalate_human":
            self.assert_can_observe(receipt, target, authority_store=authority_store, clock=clock)
            return
        raise LaneAuthorityError(f"unsupported action {action!r}")

    def release(self, run_id: str) -> None:
        self._paused_runs.discard(run_id)
        self._run_roles.pop(run_id, None)
        for target in [t for t, owner in self._exclusive.items() if owner == run_id]:
            del self._exclusive[target]
        for target in tuple(self._observers):
            subs = self._observers[target]
            subs.discard(run_id)
            if not subs:
                del self._observers[target]

    def revoke_run(self, run_id: str, authority_store: RunAuthorityStore) -> None:
        authority_store.revoke_run(run_id)
        self.release(run_id)

    def revoke_target_incarnation(
        self,
        target: TargetIncarnation,
        authority_store: RunAuthorityStore | None = None,
    ) -> None:
        self._exclusive.pop(target, None)
        self._observers.pop(target, None)
        if authority_store is not None:
            authority_store.revoke_target_incarnation(target)
