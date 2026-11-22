"""PRD M Coordination Hub: WaitForGraph, ArtifactSpool, OutboxDispatcher, CoordHub.

Pure Python standard library + shared PRD M contract and PRD L trust-boundary
helpers. Implements default-deny capability routing, two-phase fenced admission
with private artifact staging, fenced outbox delivery, failure-safe revocation,
and controller BrokerLease watchdog integration.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import threading
import time
from typing import Any, Protocol, runtime_checkable

_SPIKE_M_DIR = Path(__file__).resolve().parent
_SPIKE_L_DIR = _SPIKE_M_DIR.parent / "l"
_REPO_ROOT = _SPIKE_M_DIR.parents[3]
for _import_dir in (_SPIKE_M_DIR, _SPIKE_L_DIR, _REPO_ROOT):
    if str(_import_dir) not in sys.path:
        sys.path.insert(0, str(_import_dir))

from oc_address import (  # noqa: E402
    AddressError,
    parse_local_target,
    validate_msg_kind,
    validate_thread_id,
)
from oc_broker_common import BrokerLease, _UMASK_LOCK  # noqa: E402
from oc_controller import Controller, Denied, Principal  # noqa: E402
from oc_coord_contract import (  # noqa: E402
    DEFAULT_EDGE_MAX_ROUNDS,
    EDGE_MAX_QUEUED_BYTES,
    EDGE_MAX_QUEUED_MSGS,
    MAX_ARTIFACT_BYTES,
    MAX_ARTIFACTS_PER_EDGE,
    MAX_ARTIFACTS_PER_MSG,
    MAX_FRAMED_BODY_BYTES,
    MAX_STREAM_EVENT_BYTES,
    MAX_TURN_STREAM_EVENTS,
    STREAM_EVENT_TYPES,
    ArtifactRef,
    CoordAuthError,
    CoordBackpressureError,
    CoordPolicyError,
    CoordRole,
    CoordValidationError,
    DeadlockCycleError,
    DispatchOutcome,
    Envelope,
    IncarnationMismatchError,
    PrincipalCtx,
    RevocationStatus,
    RevokedError,
    RoutingEdge,
    SandboxRecord,
    StreamEvent,
    SubtreeBudget,
    ThreadRecord,
    TrustClass,
    TurnDispatch,
    WorkerTransport,
    canonicalize_body_text,
    frame_untrusted_peer_message,
    is_control_priority,
    mint_crypto_id,
    sha256_canonical_body,
    validate_opaque_token,
    validate_reason_text,
    validate_sandbox_rel_path,
    validate_stream_text,
    validate_task_brief,
)
from oc_schema import (  # noqa: E402
    PolicyError,
    assert_trusted_dir,
    check_not_host_production_dir,
    check_not_in_sandbox,
)

_ERR_DEGRADED = "hub_store_degraded"
_ERR_HUB_CLOSED = "hub_closed"
_ERR_STATE_LOCKED = "hub_state_dir_locked"
_ERR_CLOSE_INCOMPLETE = "hub_close_incomplete_workers_running"
_ERR_ARTIFACT_RECONCILE = "artifact_reconciliation_failed"
_ERR_LEASE_SETTLE = "close_lease_settlement_failed"
_ERR_CTRL_UNAVAILABLE = "controller_authority_unavailable"
_ERR_MISSING_STREAM_ABORT = "transport_missing_stream_abort"
_REASON_RECOVERY_RETIRED = "recovery_incarnation_retired"
_REASON_EDGE_LEASE_REVOKED = "edge_lease_revoked"
_REASON_CTRL_LEASE_REVOKED = "controller_lease_revoked"
_REASON_HANDOFF_PERSIST_FAILED = "handoff_persist_failed"
_ATTR_LEASE_REQ_ID = "_controller_request_id"
_ERR_EDGE_REVOKED = "edge_revoked"
_ERR_NO_ACTIVE_EDGE = "no_active_edge"
_ERR_REVOKED_UNCONFIRMED = "revoked_locally_persistence_unconfirmed"
_ERR_SANDBOX_NOT_FOUND = "sandbox_not_found"
_ERR_SANDBOX_REVOKED = "sandbox_revoked"
_ERR_ADMIN_ONLY = "operator_or_orchestrator_required"
_STATUS_ACTIVE = "active"
_STATUS_UNAVAILABLE = "unavailable"
_STATUS_REVOKED = "revoked"
_STATUS_RUNNING = "running"
_STATUS_PENDING = "pending"
_STATUS_DISPATCH_STARTED = "dispatch_started"


class _AuthorityUnavailableError(CoordPolicyError):
    """Controller authority lookup failed transiently (distinct from confirmed revocation)."""
_STAGING_DIR_NAME = ".staging"
_SPOOL_DIR_NAME = "inbox-spool"
_DEGRADED_MARKER_NAME = ".coord_degraded"
_SESSION_ACTIVE_MARKER_NAME = ".coord_session_active"
_STATE_LOCK_NAME = ".coord_hub.lock"
_EPHEMERAL_LEASE_PREFIX = "ephemeral-lease:"
_ORCH_ACTOR_PREFIX = "orchestrator:"
_PATCH_SUFFIX = ".patch"


def _sandbox_addr_from_actor(actor: str) -> str | None:
    if not isinstance(actor, str) or not actor:
        return None
    candidate = actor[len(_ORCH_ACTOR_PREFIX) :] if actor.startswith(_ORCH_ACTOR_PREFIX) else actor
    try:
        return parse_local_target(candidate).canonical
    except AddressError:
        return None
_THREAD_MAIN = "main"
_KIND_PROMPT = "prompt"
_MEDIA_PATCH = "text/x-patch"
_LABEL_INCARNATION = "incarnation_id"
_LABEL_CTRL_REQ_ID = "controller_request_id"
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_OUTCOME_OK = "ok"

_DEFAULT_MAX_EDGE_ARTIFACT_BYTES = 16 * 1024 * 1024
_DEFAULT_MAX_GLOBAL_ARTIFACT_BYTES = 64 * 1024 * 1024
_DEFAULT_MAX_GLOBAL_ARTIFACT_COUNT = 256
_MAX_EDGE_ROUNDS_CAP = 1024
_MAX_RATE_LIMIT_RPM = 6000


@runtime_checkable
class RegistryStore(Protocol):
    """Persistence and transactional admission contract implemented by CoordRegistry."""

    def register_sandbox(self, record: SandboxRecord) -> SandboxRecord: ...

    def get_sandbox(self, sandbox_addr: str) -> SandboxRecord | None: ...

    def list_sandboxes(self) -> list[SandboxRecord]: ...

    def update_sandbox_status(
        self, sandbox_addr: str, status: str, *, incarnation_id: str | None = None
    ) -> None: ...

    def ensure_thread(
        self, sandbox_addr: str, incarnation_id: str, thread_id: str, *, title: str = ""
    ) -> ThreadRecord: ...

    def grant_edge(self, edge: RoutingEdge) -> RoutingEdge: ...

    def get_edge(self, edge_id: str) -> RoutingEdge | None: ...

    def find_active_edge(
        self, src_actor: str, dst_addr: str, thread_id: str, msg_kind: str
    ) -> RoutingEdge | None: ...

    def list_edges(
        self,
        *,
        dst_addr: str | None = None,
        src_actor: str | None = None,
        active_only: bool = True,
    ) -> list[RoutingEdge]: ...

    def reset_edge_turns(self, edge_id: str) -> None: ...

    def revoke_grant_and_cancel_outbox(
        self,
        *,
        target_addr: str | None = None,
        edge_id: str | None = None,
        lease_request_id: str | None = None,
        reason: str = _STATUS_REVOKED,
    ) -> list[str]: ...

    def is_grant_tombstoned(self, edge_id: str, grant_generation: int) -> bool: ...

    def admit_and_enqueue_send(
        self,
        *,
        edge_id: str,
        expected_grant_generation: int,
        expected_src_incarnation: str | None,
        expected_dst_incarnation: str,
        envelope: Envelope,
        count_turn: bool,
        max_queued_msgs: int,
        max_queued_bytes: int,
        check_in_reply_to: tuple[str, str, str] | None = None,
    ) -> tuple[int, Envelope]: ...

    def list_outbox(
        self, *, statuses: tuple[str, ...] = (_STATUS_PENDING,)
    ) -> list[dict[str, Any]]: ...

    def get_envelope(self, msg_id: str) -> Envelope | None: ...

    def mark_outbox_dispatch_started(
        self,
        msg_id: str,
        *,
        edge_id: str,
        grant_generation: int,
        dst_incarnation: str,
    ) -> bool: ...

    def return_outbox_to_pending(self, msg_id: str, *, detail: str = "") -> bool: ...

    def mark_outbox_handed_off(self, msg_id: str, *, stream_id: str) -> None: ...

    def mark_outbox_uncertain(self, msg_id: str, *, detail: str) -> None: ...

    def mark_outbox_completed(self, msg_id: str) -> None: ...

    def cancel_outbox_row(self, msg_id: str, *, reason: str) -> None: ...

    def save_sandbox_budget(
        self, sandbox_addr: str, incarnation_id: str, budget: SubtreeBudget
    ) -> None: ...

    def get_sandbox_budget(
        self, sandbox_addr: str, incarnation_id: str
    ) -> SubtreeBudget | None: ...

    def list_committed_artifact_manifests(self) -> list[dict[str, Any]]: ...

    def record_stream_event(
        self,
        event: StreamEvent,
        *,
        tui_enter_token: str | None = None,
        dispatch_msg_id: str | None = None,
    ) -> dict[str, Any]: ...

    def list_events_since(
        self, sandbox_addrs: Iterable[str], since_seq: int, *, limit: int = 200
    ) -> list[dict[str, Any]]: ...

    def get_projection(self) -> dict[str, Any]: ...

    def append_audit(
        self,
        actor: str,
        action: str,
        target: str,
        outcome: str,
        detail: Mapping[str, Any] | None = None,
    ) -> int: ...


class WaitForGraph:
    """Thread-safe directed wait-for graph rejecting cycles before blocking."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._next_token = 1
        self._waits: dict[str, dict[int, frozenset[str]]] = {}

    def _neighbors_locked(self, node: str) -> set[str]:
        entries = self._waits.get(node)
        if not entries:
            return set()
        out: set[str] = set()
        for targets in entries.values():
            out.update(targets)
        return out

    def _path_exists_locked(self, start: str, goal: str) -> bool:
        visited: set[str] = set()
        stack: list[str] = [start]
        while stack:
            cur = stack.pop()
            if cur == goal:
                return True
            if cur in visited:
                continue
            visited.add(cur)
            for nxt in self._neighbors_locked(cur):
                if nxt not in visited:
                    stack.append(nxt)
        return False

    def enter(self, waiter_actor: str, targets: Iterable[str]) -> int:
        target_set = frozenset(targets)
        with self._lock:
            if waiter_actor in target_set:
                raise DeadlockCycleError(f"Self-wait deadlock cycle rejected for {waiter_actor!r}")
            for target in target_set:
                if self._path_exists_locked(target, waiter_actor):
                    raise DeadlockCycleError(
                        f"Wait-for cycle detected: {waiter_actor!r} -> {target!r}"
                    )
            token = self._next_token
            self._next_token += 1
            self._waits.setdefault(waiter_actor, {})[token] = target_set
            return token

    def exit(self, waiter_actor: str, token: int) -> None:
        with self._lock:
            entries = self._waits.get(waiter_actor)
            if entries is None:
                return
            entries.pop(token, None)
            if not entries:
                self._waits.pop(waiter_actor, None)


def _assert_raw_no_user_symlink_ancestors(raw: Path) -> None:
    """Reject any non-root symlink along raw path before resolving physical ancestors."""
    cur = raw
    while True:
        try:
            st = os.lstat(cur)
            if stat.S_ISLNK(st.st_mode) and st.st_uid != 0:
                raise CoordPolicyError(f"Symlink ancestor rejected: {cur}")
        except FileNotFoundError:
            pass
        if cur.parent == cur:
            break
        cur = cur.parent


def _assert_existing_ancestors_safe(phys: Path) -> None:
    """Verify every existing resolved ancestor is a safe, non-symlink, non-writable dir."""
    uid = os.geteuid()
    cur = phys
    while not cur.exists() and cur.parent != cur:
        cur = cur.parent
    while True:
        st = os.lstat(cur)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise CoordPolicyError(f"Non-directory or symlink ancestor rejected: {cur}")
        if st.st_uid not in (uid, 0):
            raise CoordPolicyError(f"Untrusted ancestor owner rejected: {cur}")
        if (st.st_mode & 0o022) and not (st.st_uid == 0 and (st.st_mode & stat.S_ISVTX)):
            raise CoordPolicyError(f"Writable ancestor directory rejected: {cur}")
        if cur.parent == cur:
            break
        cur = cur.parent


def _fsync_dir(path: Path) -> None:
    """Fsync a trusted directory fd (no symlinks) to make directory entry updates durable."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _O_NOFOLLOW
    dir_fd = os.open(path, flags)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _write_marker_durable(path: Path, parent_dir: Path, payload: bytes) -> None:
    """Atomically write a 0o600 non-symlink marker file and fsync both file and parent dir."""
    flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC | _O_NOFOLLOW
    with _UMASK_LOCK:
        old_umask = os.umask(0o077)
        try:
            fd = os.open(path, flags, 0o600)
        finally:
            os.umask(old_umask)
    try:
        view = memoryview(payload)
        written = 0
        while written < len(payload):
            written += os.write(fd, view[written:])
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_dir(parent_dir)


def _read_marker_text_nofollow(path: Path) -> str | None:
    """Read a regular non-symlink marker file text (up to 256 bytes), or None if absent."""
    try:
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise CoordPolicyError(f"Symlink marker rejected: {path}") from exc
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise CoordPolicyError(f"Non-regular marker rejected: {path}")
        return os.read(fd, 256).decode("utf-8", errors="replace").strip()
    finally:
        os.close(fd)


def _acquire_state_dir_lock(state_dir: Path) -> int:
    """Acquire an exclusive non-blocking flock on $STATE/.coord_hub.lock."""
    lock_path = state_dir / _STATE_LOCK_NAME
    flags = os.O_CREAT | os.O_RDWR | _O_NOFOLLOW
    with _UMASK_LOCK:
        old_umask = os.umask(0o077)
        try:
            fd = os.open(lock_path, flags, 0o600)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise CoordPolicyError(f"Symlink state lock rejected: {lock_path}") from exc
            raise CoordPolicyError(f"Unable to open state lock: {lock_path}") from exc
        finally:
            os.umask(old_umask)
    try:
        st = os.fstat(fd)
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_nlink != 1
            or st.st_uid != os.geteuid()
            or (st.st_mode & 0o077)
        ):
            raise CoordPolicyError(f"Untrusted state lock metadata: {lock_path}")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BlockingIOError as exc:
        os.close(fd)
        raise CoordPolicyError(_ERR_STATE_LOCKED) from exc
    except OSError as exc:
        os.close(fd)
        if exc.errno in (errno.EACCES, errno.EAGAIN):
            raise CoordPolicyError(_ERR_STATE_LOCKED) from exc
        raise CoordPolicyError(f"State lock failed: {lock_path}") from exc
    except Exception:
        os.close(fd)
        raise


def _release_state_dir_lock(fd: int) -> None:
    if fd < 0:
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass
    try:
        os.close(fd)
    except OSError:
        pass


def _unlink_marker_durable(path: Path, parent_dir: Path) -> None:
    """Unlink a non-symlink marker file if present and fsync the parent directory."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise CoordPolicyError(f"Refusing to remove non-regular marker: {path}")
    os.unlink(path)
    _fsync_dir(parent_dir)


def _ensure_trusted_dir(path: Path, *, sandbox_root: Path | None) -> Path:
    """Validate trust boundaries and ensure a 0o700 non-symlink directory exists."""
    raw = Path(path)
    if raw.is_symlink():
        raise CoordPolicyError(f"Symlink directory rejected: {raw}")
    _assert_raw_no_user_symlink_ancestors(raw)
    try:
        phys = check_not_in_sandbox(raw, sandbox_root)
        check_not_host_production_dir(phys)
        _assert_existing_ancestors_safe(phys)
        if not phys.exists():
            with _UMASK_LOCK:
                old_umask = os.umask(0o077)
                try:
                    phys.mkdir(parents=True, exist_ok=True, mode=0o700)
                finally:
                    os.umask(old_umask)
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _O_NOFOLLOW
        dir_fd = os.open(phys, flags)
        try:
            st = os.fstat(dir_fd)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid():
                raise CoordPolicyError(f"Untrusted directory owner or mode: {phys}")
            if stat.S_IMODE(st.st_mode) & 0o077:
                os.fchmod(dir_fd, 0o700)
        finally:
            os.close(dir_fd)
        return assert_trusted_dir(phys, sandbox_root=sandbox_root)
    except PolicyError as exc:
        raise CoordPolicyError(str(exc)) from exc


@dataclass(slots=True)
class StagingReservation:
    """In-flight private artifact staging reservation prior to transactional commit."""

    admission_id: str
    edge_id: str
    count: int
    total_bytes: int
    staging_dir: Path
    staged_digests: list[str] = field(default_factory=list)
    finalized: bool = False


class ArtifactSpool:
    """Host-owned private-staging artifact spool with capacity reservations and digest checks."""

    def __init__(
        self,
        state_dir: Path,
        *,
        sandbox_root: Path | None = None,
        max_edge_count: int = MAX_ARTIFACTS_PER_EDGE,
        max_edge_bytes: int = _DEFAULT_MAX_EDGE_ARTIFACT_BYTES,
        max_global_count: int = _DEFAULT_MAX_GLOBAL_ARTIFACT_COUNT,
        max_global_bytes: int = _DEFAULT_MAX_GLOBAL_ARTIFACT_BYTES,
    ) -> None:
        self._sandbox_root = sandbox_root
        self._state_dir = _ensure_trusted_dir(Path(state_dir), sandbox_root=sandbox_root)
        self._spool_root = _ensure_trusted_dir(
            self._state_dir / _SPOOL_DIR_NAME, sandbox_root=sandbox_root
        )
        self._staging_root = _ensure_trusted_dir(
            self._spool_root / _STAGING_DIR_NAME, sandbox_root=sandbox_root
        )
        self._max_edge_count = max_edge_count
        self._max_edge_bytes = max_edge_bytes
        self._max_global_count = max_global_count
        self._max_global_bytes = max_global_bytes

        self._lock = threading.Lock()
        self._reserved_count = 0
        self._reserved_bytes = 0
        self._published_count = 0
        self._published_bytes = 0
        self._edge_reserved_count: dict[str, int] = {}
        self._edge_reserved_bytes: dict[str, int] = {}
        self._edge_published_count: dict[str, int] = {}
        self._edge_published_bytes: dict[str, int] = {}
        self.reconcile_abandoned_staging()
        self._scan_existing_published()

    @staticmethod
    def _count_inc_dir_patches(inc_dir: Path) -> tuple[int, int]:
        count = 0
        total_bytes = 0
        for item in inc_dir.iterdir():
            try:
                st = os.lstat(item)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode) and item.name.endswith(_PATCH_SUFFIX):
                count += 1
                total_bytes += st.st_size
        return count, total_bytes

    def _scan_existing_published(self) -> None:
        """Recover published count/byte quotas from existing host-spool directories on restart."""
        count = 0
        total_bytes = 0
        try:
            entries = list(self._spool_root.iterdir())
        except OSError:
            return
        for inc_dir in entries:
            if inc_dir.name == _STAGING_DIR_NAME or inc_dir.is_symlink() or not inc_dir.is_dir():
                continue
            c, b = self._count_inc_dir_patches(inc_dir)
            count += c
            total_bytes += b
        with self._lock:
            self._published_count = count
            self._published_bytes = total_bytes

    @property
    def spool_root(self) -> Path:
        return self._spool_root

    @property
    def staging_root(self) -> Path:
        return self._staging_root

    def usage_snapshot(self) -> dict[str, int]:
        with self._lock:
            return {
                "reserved_count": self._reserved_count,
                "reserved_bytes": self._reserved_bytes,
                "published_count": self._published_count,
                "published_bytes": self._published_bytes,
            }

    @staticmethod
    def _validate_blobs(blobs: Sequence[bytes]) -> int:
        if len(blobs) > MAX_ARTIFACTS_PER_MSG:
            raise CoordValidationError(f"Too many artifacts in message (max {MAX_ARTIFACTS_PER_MSG})")
        total_bytes = 0
        for blob in blobs:
            if not isinstance(blob, (bytes, bytearray)):
                raise CoordValidationError("Artifact blob must be bytes")
            raw = bytes(blob)
            if not raw or len(raw) > MAX_ARTIFACT_BYTES:
                raise CoordValidationError(f"Artifact blob size must be 1..{MAX_ARTIFACT_BYTES} bytes")
            if b"\x00" in raw:
                raise CoordValidationError("NUL byte forbidden in artifact blob")
            try:
                raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise CoordValidationError("Artifact blob must be valid UTF-8") from exc
            total_bytes += len(raw)
        return total_bytes

    def reserve(self, edge_id: str, blobs: Sequence[bytes]) -> StagingReservation:
        total_bytes = self._validate_blobs(blobs)
        count = len(blobs)
        with self._lock:
            edge_cnt = self._edge_reserved_count.get(edge_id, 0) + self._edge_published_count.get(
                edge_id, 0
            )
            edge_byt = self._edge_reserved_bytes.get(edge_id, 0) + self._edge_published_bytes.get(
                edge_id, 0
            )
            if edge_cnt + count > self._max_edge_count or edge_byt + total_bytes > self._max_edge_bytes:
                raise CoordBackpressureError("Per-edge artifact staging budget exceeded")
            if (
                self._reserved_count + self._published_count + count > self._max_global_count
                or self._reserved_bytes + self._published_bytes + total_bytes
                > self._max_global_bytes
            ):
                raise CoordBackpressureError("Global artifact staging budget exceeded")
            self._reserved_count += count
            self._reserved_bytes += total_bytes
            self._edge_reserved_count[edge_id] = self._edge_reserved_count.get(edge_id, 0) + count
            self._edge_reserved_bytes[edge_id] = (
                self._edge_reserved_bytes.get(edge_id, 0) + total_bytes
            )

        admission_id = mint_crypto_id("adm")
        staging_dir = self._staging_root / admission_id
        return StagingReservation(
            admission_id=admission_id,
            edge_id=edge_id,
            count=count,
            total_bytes=total_bytes,
            staging_dir=staging_dir,
        )

    def stage_blobs(
        self,
        reservation: StagingReservation,
        blobs: Sequence[bytes],
        *,
        media_type: str = _MEDIA_PATCH,
    ) -> tuple[ArtifactRef, ...]:
        _ensure_trusted_dir(reservation.staging_dir, sandbox_root=self._sandbox_root)
        refs: list[ArtifactRef] = []
        seen_digests: set[str] = set()
        for blob in blobs:
            raw = bytes(blob)
            digest = hashlib.sha256(raw).hexdigest()
            ref = ArtifactRef(blob_sha256=digest, size_bytes=len(raw), media_type=media_type)
            if digest not in seen_digests:
                self._write_staged_file(reservation.staging_dir / f"{digest}{_PATCH_SUFFIX}", raw)
                reservation.staged_digests.append(digest)
                seen_digests.add(digest)
            refs.append(ref)
        return tuple(refs)

    @staticmethod
    def _write_staged_file(path: Path, data: bytes) -> None:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW
        with _UMASK_LOCK:
            old_umask = os.umask(0o077)
            try:
                fd = os.open(path, flags, 0o600)
            finally:
                os.umask(old_umask)
        try:
            view = memoryview(data)
            written = 0
            while written < len(data):
                written += os.write(fd, view[written:])
            os.fsync(fd)
        finally:
            os.close(fd)

    def publish(self, reservation: StagingReservation, dst_incarnation: str) -> None:
        clean_inc = validate_opaque_token(dst_incarnation, "dst_incarnation")
        dst_dir = _ensure_trusted_dir(
            self._spool_root / clean_inc, sandbox_root=self._sandbox_root
        )
        for digest in reservation.staged_digests:
            src_path = reservation.staging_dir / f"{digest}{_PATCH_SUFFIX}"
            dst_path = dst_dir / f"{digest}{_PATCH_SUFFIX}"
            os.chmod(src_path, 0o400)
            os.replace(src_path, dst_path)
        _fsync_dir(dst_dir)
        self._remove_dir_quietly(reservation.staging_dir)

        with self._lock:
            if reservation.finalized:
                return
            reservation.finalized = True
            self._release_reserved_locked(reservation)
            self._published_count += reservation.count
            self._published_bytes += reservation.total_bytes
            self._edge_published_count[reservation.edge_id] = (
                self._edge_published_count.get(reservation.edge_id, 0) + reservation.count
            )
            self._edge_published_bytes[reservation.edge_id] = (
                self._edge_published_bytes.get(reservation.edge_id, 0) + reservation.total_bytes
            )

    def abort_reservation(self, reservation: StagingReservation) -> None:
        self._cleanup_staging_dir(reservation.staging_dir)
        with self._lock:
            if reservation.finalized:
                return
            reservation.finalized = True
            self._release_reserved_locked(reservation)

    def _release_reserved_locked(self, reservation: StagingReservation) -> None:
        self._reserved_count = max(0, self._reserved_count - reservation.count)
        self._reserved_bytes = max(0, self._reserved_bytes - reservation.total_bytes)
        edge_id = reservation.edge_id
        rem_cnt = max(0, self._edge_reserved_count.get(edge_id, 0) - reservation.count)
        rem_byt = max(0, self._edge_reserved_bytes.get(edge_id, 0) - reservation.total_bytes)
        if rem_cnt == 0:
            self._edge_reserved_count.pop(edge_id, None)
        else:
            self._edge_reserved_count[edge_id] = rem_cnt
        if rem_byt == 0:
            self._edge_reserved_bytes.pop(edge_id, None)
        else:
            self._edge_reserved_bytes[edge_id] = rem_byt

    @staticmethod
    def _remove_dir_quietly(path: Path) -> None:
        try:
            path.rmdir()
        except FileNotFoundError:
            pass

    @staticmethod
    def _cleanup_staging_dir(staging_dir: Path) -> int:
        reclaimed = 0
        if not staging_dir.exists() or staging_dir.is_symlink():
            return 0
        try:
            for entry in os.scandir(staging_dir):
                os.unlink(entry.path)
                reclaimed += 1
            staging_dir.rmdir()
        except FileNotFoundError:
            pass
        return reclaimed

    def reconcile_abandoned_staging(self) -> int:
        """Reclaim leftover .staging/* admission directories after a crash."""
        reclaimed = 0
        if not self._staging_root.exists():
            return 0
        for entry in os.scandir(self._staging_root):
            entry_path = Path(entry.path)
            if entry.is_dir(follow_symlinks=False):
                reclaimed += self._cleanup_staging_dir(entry_path) + 1
            else:
                os.unlink(entry_path)
                reclaimed += 1
        with self._lock:
            self._reserved_count = 0
            self._reserved_bytes = 0
            self._edge_reserved_count.clear()
            self._edge_reserved_bytes.clear()
        return reclaimed

    def has_verified_blob(self, incarnation_id: str, ref: ArtifactRef) -> bool:
        """Return True iff the published spool file exists, passes metadata checks, and matches SHA-256."""
        try:
            self.read_artifact(incarnation_id, ref)
            return True
        except (CoordPolicyError, CoordValidationError):
            return False

    def restore_edge_charges(
        self, edge_counts: Mapping[str, int], edge_bytes: Mapping[str, int]
    ) -> None:
        """Restore per-edge published artifact counts and byte charges from reconciled manifests."""
        with self._lock:
            self._edge_published_count = {
                edge_id: cnt for edge_id, cnt in edge_counts.items() if cnt > 0
            }
            self._edge_published_bytes = {
                edge_id: byt for edge_id, byt in edge_bytes.items() if byt > 0
            }

    def read_artifact(self, incarnation_id: str, ref: ArtifactRef) -> bytes:
        clean_inc = validate_opaque_token(incarnation_id, _LABEL_INCARNATION)
        if not isinstance(ref, ArtifactRef):
            raise CoordValidationError("ref must be an ArtifactRef")
        inc_dir = self._spool_root / clean_inc
        filename = f"{ref.blob_sha256}{_PATCH_SUFFIX}"
        dir_fd = self._open_verified_dir_nofollow(inc_dir)
        try:
            fd = self._open_file_nofollow(dir_fd, filename)
        finally:
            os.close(dir_fd)
        try:
            return self._read_and_verify_fd(fd, ref)
        finally:
            os.close(fd)

    @staticmethod
    def _open_verified_dir_nofollow(path: Path) -> int:
        try:
            dir_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise CoordPolicyError(f"Symlink rejected in artifact spool: {path}") from exc
            raise CoordPolicyError(f"Artifact directory inaccessible: {path}") from exc
        try:
            st = os.fstat(dir_fd)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or (st.st_mode & 0o077):
                raise CoordPolicyError(f"Untrusted artifact directory metadata: {path}")
        except BaseException:
            os.close(dir_fd)
            raise
        return dir_fd

    @staticmethod
    def _open_file_nofollow(dir_fd: int, filename: str) -> int:
        try:
            return os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise CoordPolicyError(f"Symlink artifact rejected: {filename}") from exc
            raise CoordPolicyError(f"Artifact file inaccessible: {filename}") from exc

    @staticmethod
    def _read_and_verify_fd(fd: int, ref: ArtifactRef) -> bytes:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise CoordPolicyError("Non-regular artifact file rejected")
        if st.st_nlink != 1:
            raise CoordPolicyError("Hardlinked artifact file rejected")
        if st.st_uid != os.geteuid():
            raise CoordPolicyError("Artifact file owner mismatch")
        if st.st_mode & 0o077:
            raise CoordPolicyError("Artifact file permissions too open")
        if st.st_size != ref.size_bytes:
            raise CoordPolicyError("Artifact file size mismatch")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ARTIFACT_BYTES or total > ref.size_bytes:
                raise CoordPolicyError("Artifact exceeded declared byte size")
            chunks.append(chunk)
        data = b"".join(chunks)
        if len(data) != ref.size_bytes:
            raise CoordPolicyError("Artifact truncated during read")
        if hashlib.sha256(data).hexdigest() != ref.blob_sha256:
            raise CoordPolicyError("Artifact SHA-256 integrity mismatch")
        return data


@dataclass(eq=False, slots=True)
class _WaiterState:
    caller_actor: str
    targets: frozenset[str]
    revoked: bool = False


@dataclass(eq=False, slots=True)
class _StreamAuth:
    msg_id: str
    edge_id: str
    grant_generation: int
    dst_addr: str
    dst_incarnation: str
    req_ids: frozenset[str]


@dataclass(eq=False, slots=True)
class _InflightAuth:
    msg_id: str
    edge_id: str
    grant_generation: int
    dst_addr: str
    dst_incarnation: str
    req_ids: frozenset[str]
    outage_observed: bool = False
    revoked_observed: bool = False


@dataclass(eq=False, slots=True)
class _RequestMonitorState:
    stop_ev: threading.Event
    thread: threading.Thread | None = None
    ready_ev: threading.Event = field(default_factory=threading.Event)
    started: bool = False
    start_error: Exception | None = None


class OutboxDispatcher:
    """Background outbox pump with tracked concurrent stream consumer threads."""

    def __init__(self, hub: CoordHub, *, poll_interval_s: float = 0.02) -> None:
        self._hub = hub
        self._poll_interval_s = poll_interval_s
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._stream_threads: set[threading.Thread] = set()

    def start(self) -> None:
        with self._lock:
            if self._hub._is_closed():
                raise CoordPolicyError(_ERR_HUB_CLOSED)
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._run_loop, daemon=True)
            self._thread.start()

    def wake(self) -> None:
        self._wake_event.set()

    def spawn_stream(self, fn: Callable[[], None]) -> None:
        def _runner() -> None:
            try:
                fn()
            finally:
                with self._lock:
                    self._stream_threads.discard(threading.current_thread())

        worker = threading.Thread(target=_runner, daemon=True)
        with self._lock:
            self._stream_threads.add(worker)
        worker.start()

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            self._wake_event.clear()
            try:
                self._hub.dispatch_once(async_stream=True)
            except Exception:
                pass
            self._wake_event.wait(timeout=self._poll_interval_s)

    def stop_pump(self, deadline: float) -> bool:
        self._stop_event.set()
        self._wake_event.set()
        with self._lock:
            pump = self._thread
        if pump is not None:
            pump.join(timeout=max(0.0, deadline - time.monotonic()))
        pump_alive = pump is not None and pump.is_alive()
        with self._lock:
            if not pump_alive and self._thread is pump:
                self._thread = None
        return not pump_alive

    def join_streams(self, deadline: float) -> bool:
        while True:
            with self._lock:
                alive_streams = [w for w in self._stream_threads if w.is_alive()]
            if not alive_streams:
                return True
            if deadline - time.monotonic() <= 0:
                return False
            for worker in alive_streams:
                worker.join(timeout=max(0.0, deadline - time.monotonic()))

    def stop(self, *, timeout_s: float = 2.0) -> bool:
        deadline = time.monotonic() + timeout_s
        pump_ok = self.stop_pump(deadline)
        streams_ok = self.join_streams(deadline)
        return pump_ok and streams_ok


class CoordHub:
    """Host-owned PRD M coordination hub enforcing capabilities, fencing, and revocation."""

    def __init__(
        self,
        registry: RegistryStore,
        transport: WorkerTransport,
        state_dir: Path,
        *,
        controller: Controller | None = None,
        controller_actor: Principal | None = None,
        root_budget: SubtreeBudget | None = None,
        sandbox_root: Path | None = None,
        watchdog_interval_s: float = 0.02,
    ) -> None:
        self._registry = registry
        self._transport = transport
        self._controller = controller
        self._controller_actor = controller_actor
        self._root_budget = root_budget or SubtreeBudget()
        self._watchdog_interval_s = watchdog_interval_s

        self._state_dir = _ensure_trusted_dir(Path(state_dir), sandbox_root=sandbox_root)
        self._state_lock_fd = _acquire_state_dir_lock(self._state_dir)
        try:
            self.spool = ArtifactSpool(self._state_dir, sandbox_root=sandbox_root)
            self._degraded_marker = self._state_dir / _DEGRADED_MARKER_NAME
            self._session_active_marker = self._state_dir / _SESSION_ACTIVE_MARKER_NAME
            self.wait_graph = WaitForGraph()
            self.dispatcher = OutboxDispatcher(self, poll_interval_s=watchdog_interval_s)

            self._meta_lock = threading.Lock()
            self._register_lock = threading.Lock()
            self._close_lock = threading.Lock()
            self._fg_cond = threading.Condition(self._meta_lock)
            self._fg_ops = 0
            self._session_id = mint_crypto_id("sess")
            self._closed = False
            self._shutdown_settled = False
            self._accept_watchdog_spawns = True
            self._recovery_generation = 0
            self._wait_cond = threading.Condition()
            self._wait_gen = 0
            self._waiters: set[_WaiterState] = set()
            self._degraded = self._init_recovery_seal()
            self._grant_fences: dict[str, threading.RLock] = {}
            self._fenced_generations: set[tuple[str, int]] = set()
            self._fenced_targets: set[tuple[str, str]] = set()
            self._fenced_addrs: set[str] = set()
            self._known_incarnations: dict[str, set[str]] = {}
            self._budgets: dict[tuple[str, str], SubtreeBudget] = {}
            self._leases: dict[str, BrokerLease] = {}
            self._lease_callbacks: dict[str, Callable[[], None]] = {}
            self._pending_close_retirements: dict[str, BrokerLease] = {}
            self._pending_recovery_leases: list[BrokerLease] = []
            self._settlement_thread: threading.Thread | None = None
            self._settlement_error: Exception | None = None
            self._watchdog_threads: set[threading.Thread] = set()
            self._request_monitors: dict[str, _RequestMonitorState] = {}
            self._retired_monitors: set[_RequestMonitorState] = set()
            self._unavailable_requests: set[str] = set()
            self._inflight_handoffs: dict[str, _InflightAuth] = {}
            self._stream_authorities: dict[str, _StreamAuth] = {}
            self._stream_abort_reasons: dict[str, str] = {}
            self._rate_windows: dict[str, deque[float]] = {}
            self._reconcile_artifacts_on_startup()
        except Exception:
            _release_state_dir_lock(self._state_lock_fd)
            self._state_lock_fd = -1
            raise

    @staticmethod
    def _marker_present_or_error(path: Path) -> bool:
        try:
            os.lstat(path)
            return True
        except FileNotFoundError:
            return False
        except OSError:
            return True

    def _init_recovery_seal(self) -> bool:
        if self._marker_present_or_error(self._degraded_marker) or self._marker_present_or_error(
            self._session_active_marker
        ):
            return True
        try:
            _write_marker_durable(
                self._session_active_marker,
                self._state_dir,
                f"{self._session_id}\n".encode("utf-8"),
            )
        except OSError:
            return True
        return False

    def _mark_degraded(self, detail: str) -> None:
        with self._meta_lock:
            self._degraded = True
        self._notify_waiters()
        try:
            _write_marker_durable(
                self._degraded_marker,
                self._state_dir,
                f"{time.time():.6f}:{detail}\n".encode("utf-8", errors="replace"),
            )
        except OSError:
            pass

    @staticmethod
    def _parse_manifest_refs(raw_refs: Any) -> list[ArtifactRef] | None:
        if not isinstance(raw_refs, list) or not raw_refs:
            return None
        parsed: list[ArtifactRef] = []
        for item in raw_refs:
            if not isinstance(item, Mapping):
                return None
            try:
                parsed.append(
                    ArtifactRef(
                        blob_sha256=item["blob_sha256"],
                        size_bytes=item["size_bytes"],
                        media_type=item.get("media_type", _MEDIA_PATCH),
                    )
                )
            except (KeyError, TypeError, ValueError, CoordValidationError):
                return None
        return parsed

    def _reconcile_artifacts_on_startup(self, *, raise_on_error: bool = False) -> None:
        list_manifests = getattr(self._registry, "list_committed_artifact_manifests", None)
        if not callable(list_manifests):
            return
        try:
            manifests = list_manifests()
        except Exception as exc:
            self._mark_degraded(_ERR_ARTIFACT_RECONCILE)
            if raise_on_error:
                raise CoordPolicyError(_ERR_ARTIFACT_RECONCILE) from exc
            return
        edge_counts: dict[str, int] = {}
        edge_bytes: dict[str, int] = {}
        for item in manifests:
            self._reconcile_single_manifest(
                item, edge_counts, edge_bytes, raise_on_error=raise_on_error
            )
        self.spool.restore_edge_charges(edge_counts, edge_bytes)

    def _reconcile_missing_blob_row(
        self, msg_id: str, edge_id: str, status: Any, *, raise_on_error: bool
    ) -> None:
        if not msg_id or status not in (_STATUS_PENDING, _STATUS_DISPATCH_STARTED):
            return
        try:
            if status == _STATUS_PENDING:
                self._registry.cancel_outbox_row(
                    msg_id, reason="artifact_unreconciled_after_crash"
                )
                self._registry.append_audit(
                    "hub",
                    "reconcile_artifact_cancelled",
                    msg_id,
                    "cancelled",
                    {"edge_id": edge_id},
                )
            else:
                self._registry.mark_outbox_uncertain(
                    msg_id, detail="artifact_missing_after_dispatch_started"
                )
                self._registry.append_audit(
                    "hub",
                    "reconcile_artifact_uncertain",
                    msg_id,
                    "uncertain",
                    {"edge_id": edge_id},
                )
        except Exception as exc:
            self._mark_degraded("artifact_reconciliation_update_failed")
            if raise_on_error:
                raise CoordPolicyError(_ERR_ARTIFACT_RECONCILE) from exc

    def _reconcile_single_manifest(
        self,
        item: Mapping[str, Any],
        edge_counts: dict[str, int],
        edge_bytes: dict[str, int],
        *,
        raise_on_error: bool = False,
    ) -> None:
        msg_id = str(item.get("msg_id", ""))
        edge_id = str(item.get("edge_id", ""))
        dst_inc = str(item.get("dst_incarnation", ""))
        status = item.get("outbox_status")
        refs = self._parse_manifest_refs(item.get("artifact_refs"))
        blobs_ok = refs is not None and all(
            self.spool.has_verified_blob(dst_inc, ref) for ref in refs
        )
        if not blobs_ok:
            self._reconcile_missing_blob_row(
                msg_id, edge_id, status, raise_on_error=raise_on_error
            )
            return
        if refs is not None and edge_id:
            edge_counts[edge_id] = edge_counts.get(edge_id, 0) + len(refs)
            edge_bytes[edge_id] = edge_bytes.get(edge_id, 0) + sum(r.size_bytes for r in refs)

    def _enter_fg_op(self) -> None:
        with self._meta_lock:
            if self._closed:
                raise CoordPolicyError(_ERR_HUB_CLOSED)
            self._fg_ops += 1

    def _exit_fg_op(self) -> None:
        with self._meta_lock:
            self._fg_ops = max(0, self._fg_ops - 1)
            if self._fg_ops == 0:
                self._fg_cond.notify_all()

    def _wait_fg_ops(self, deadline: float) -> bool:
        with self._fg_cond:
            while self._fg_ops > 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._fg_cond.wait(timeout=remaining)
            return True

    def _fence_all_for_recovery_locked(
        self,
        all_edges: Sequence[RoutingEdge],
        sandboxes: Sequence[SandboxRecord],
    ) -> tuple[list[tuple[str, str]], list[str]]:
        detached_incs: set[tuple[str, str]] = set()
        with self._meta_lock:
            for edge in all_edges:
                self._fenced_generations.add((edge.edge_id, edge.grant_generation))
            for sb in sandboxes:
                self._fenced_targets.add((sb.sandbox_addr, sb.incarnation_id))
                detached_incs.add((sb.sandbox_addr, sb.incarnation_id))
            for sb_addr, inc_set in self._known_incarnations.items():
                for inc_id in inc_set:
                    self._fenced_targets.add((sb_addr, inc_id))
                    detached_incs.add((sb_addr, inc_id))
            detached_sids: list[str] = []
            for sid, auth in self._stream_authorities.items():
                self._stream_abort_reasons.setdefault(sid, _REASON_RECOVERY_RETIRED)
                self._fenced_targets.add((auth.dst_addr, auth.dst_incarnation))
                detached_incs.add((auth.dst_addr, auth.dst_incarnation))
                detached_sids.append(sid)
            leases = tuple(self._leases.items())
            callbacks = dict(self._lease_callbacks)
            for _addr, lease in leases:
                if lease not in self._pending_recovery_leases:
                    self._pending_recovery_leases.append(lease)
            self._leases.clear()
            self._lease_callbacks.clear()
            self._retire_all_monitors_locked()
        with self._wait_cond:
            for w in self._waiters:
                w.revoked = True
            self._wait_gen += 1
            self._wait_cond.notify_all()
        self._detach_lease_callbacks(leases, callbacks)
        return sorted(detached_incs), detached_sids

    def _mark_orphaned_dispatch_started_uncertain(self) -> None:
        rows = self._registry.list_outbox(statuses=(_STATUS_DISPATCH_STARTED,))
        for row in rows:
            msg_id = str(row.get("msg_id", ""))
            if msg_id:
                self._registry.mark_outbox_uncertain(
                    msg_id, detail="recovery_dispatch_started_uncertain"
                )

    def _drain_pending_recovery_leases(self) -> None:
        with self._meta_lock:
            leases = tuple(self._pending_recovery_leases)
        remaining: list[BrokerLease] = []
        for lease in leases:
            try:
                lease.revoke()
            except Exception:
                remaining.append(lease)
        with self._meta_lock:
            self._pending_recovery_leases = remaining

    def _teardown_recovery_detached(
        self,
        detached_incarnations: Sequence[tuple[str, str]],
        detached_sids: Sequence[str],
    ) -> None:
        for sb_addr, inc_id in detached_incarnations:
            try:
                self._transport.abort_incarnation(
                    sb_addr, inc_id, reason=_REASON_RECOVERY_RETIRED
                )
            except Exception:
                pass
        for sid in detached_sids:
            if self._try_abort_stream(sid, reason=_REASON_RECOVERY_RETIRED):
                self._clear_unpersisted_stream_if_aborted(sid)
        self._drain_pending_recovery_leases()
        self._notify_waiters()

    def _reconcile_grants_and_incarnations_for_recovery(self) -> tuple[int, int]:
        """Fence grants/streams, issue local cancellation immediately, then persist retirements."""
        all_edges = self._registry.list_edges(active_only=False)
        active_edges = [e for e in all_edges if e.active]
        with self._meta_lock:
            extra_eids = {inf.edge_id for inf in self._inflight_handoffs.values()} | {
                auth.edge_id for auth in self._stream_authorities.values()
            }
        edge_ids = sorted({e.edge_id for e in all_edges} | extra_eids)
        fences = [self._get_grant_fence(eid) for eid in edge_ids]
        for fence in fences:
            fence.acquire()
        try:
            sandboxes = self._registry.list_sandboxes()
            detached_incs, detached_sids = self._fence_all_for_recovery_locked(
                all_edges, sandboxes
            )
        finally:
            for fence in reversed(fences):
                fence.release()
        # Local cancellation runs BEFORE durable DB writes so slow/failing writes never retain active leases/streams.
        self._teardown_recovery_detached(detached_incs, detached_sids)

        invalidated_grants = 0
        for edge in active_edges:
            revoked = self._registry.revoke_grant_and_cancel_outbox(
                edge_id=edge.edge_id, reason="recovery_grant_generation_invalidated"
            )
            invalidated_grants += len(revoked)
        self._mark_orphaned_dispatch_started_uncertain()
        retired_incarnations = 0
        for sb in sandboxes:
            if sb.status == _STATUS_REVOKED:
                continue
            self._registry.update_sandbox_status(
                sb.sandbox_addr, _STATUS_REVOKED, incarnation_id=sb.incarnation_id
            )
            retired_incarnations += 1
        return invalidated_grants, retired_incarnations

    def confirm_recovery(
        self, caller: PrincipalCtx, *, reason: str = "operator_verified_recovery"
    ) -> None:
        """Operator-only recovery: retire all pre-recovery grants/incarnations, audit, then reopen."""
        if caller.role is not CoordRole.OPERATOR:
            raise CoordAuthError("operator_required:confirm_recovery")
        clean_reason = validate_reason_text(reason, "reason")
        self._enter_fg_op()
        try:
            with self._register_lock:
                if self._is_closed():
                    raise CoordPolicyError(_ERR_HUB_CLOSED)
                if not self.is_degraded:
                    return
                with self._meta_lock:
                    self._recovery_generation += 1
                # Keep _degraded=True through artifact reconciliation, invalidation, and audit.
                self._reconcile_artifacts_on_startup(raise_on_error=True)
                invalidated_grants, retired_incarnations = (
                    self._reconcile_grants_and_incarnations_for_recovery()
                )
                if self._is_closed():
                    raise CoordPolicyError(_ERR_HUB_CLOSED)
                self._registry.append_audit(
                    caller.canonical_sender,
                    "confirm_recovery",
                    "hub",
                    _OUTCOME_OK,
                    {
                        "reason": clean_reason,
                        "invalidated_grants": invalidated_grants,
                        "retired_incarnations": retired_incarnations,
                    },
                )
                # Write session seal BEFORE unlinking .coord_degraded so failure never drops protection.
                _write_marker_durable(
                    self._session_active_marker,
                    self._state_dir,
                    f"{self._session_id}\n".encode("utf-8"),
                )
                _unlink_marker_durable(self._degraded_marker, self._state_dir)
                with self._meta_lock:
                    self._degraded = False
        finally:
            self._exit_fg_op()

    @property
    def is_degraded(self) -> bool:
        with self._meta_lock:
            return self._degraded

    def _is_closed(self) -> bool:
        with self._meta_lock:
            return self._closed

    def start_dispatcher(self) -> None:
        self.dispatcher.start()

    @staticmethod
    def _detach_lease_callbacks(
        leases: Sequence[tuple[str, BrokerLease]],
        callbacks: Mapping[str, Callable[[], None]],
    ) -> None:
        for addr, lease in leases:
            cb = callbacks.get(addr)
            if cb is not None:
                lease.remove_revoke_callback(cb)

    def _retire_single_pending_lease(
        self, watchdog_caller: PrincipalCtx, addr: str, lease: BrokerLease
    ) -> None:
        sb = self._registry.get_sandbox(addr)
        if sb is not None:
            self._revoke_unlocked(
                watchdog_caller,
                target=addr,
                reason="hub_close_lease_retired",
            )
        try:
            lease.revoke()
        except Exception:
            pass
        with self._meta_lock:
            self._pending_close_retirements.pop(addr, None)

    def _retire_pending_leases_locked(self) -> None:
        self._drain_pending_recovery_leases()
        watchdog_caller = PrincipalCtx(role=CoordRole.OPERATOR, actor_id="lease-watchdog")
        first_err: Exception | None = None
        with self._meta_lock:
            pending = tuple(self._pending_close_retirements.items())
        for addr, lease in pending:
            try:
                self._retire_single_pending_lease(watchdog_caller, addr, lease)
            except Exception as exc:
                self._mark_degraded(_ERR_LEASE_SETTLE)
                with self._meta_lock:
                    self._fenced_addrs.add(addr)
                if first_err is None:
                    first_err = exc
        if first_err is not None:
            raise first_err

    def _acquire_lock_by_deadline(self, lock: threading.Lock, deadline: float) -> bool:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return lock.acquire(blocking=False)
        return lock.acquire(timeout=remaining)

    def _run_close_settlement(self) -> None:
        err: Exception | None = None
        try:
            with self._register_lock:
                self._retire_pending_leases_locked()
                with self._meta_lock:
                    self._leases.clear()
                    self._lease_callbacks.clear()
                    degraded = self._degraded
                if not degraded:
                    try:
                        owner = _read_marker_text_nofollow(self._session_active_marker)
                        if owner == self._session_id:
                            _unlink_marker_durable(self._session_active_marker, self._state_dir)
                    except (OSError, CoordPolicyError):
                        with self._meta_lock:
                            self._degraded = True
                with self._meta_lock:
                    lock_fd = self._state_lock_fd
                    self._state_lock_fd = -1
                _release_state_dir_lock(lock_fd)
                with self._meta_lock:
                    self._shutdown_settled = True
        except Exception as exc:
            err = exc
        finally:
            with self._meta_lock:
                self._settlement_error = err
                if self._settlement_thread is threading.current_thread():
                    self._settlement_thread = None

    def _finalize_settled_close(self, deadline: float) -> None:
        with self._meta_lock:
            if self._shutdown_settled:
                return
            worker = self._settlement_thread
            if worker is None:
                self._settlement_error = None
                worker = threading.Thread(target=self._run_close_settlement, daemon=True)
                self._settlement_thread = worker
                should_start = True
            else:
                should_start = False
        if should_start:
            try:
                worker.start()
            except Exception:
                with self._meta_lock:
                    if self._settlement_thread is worker:
                        self._settlement_thread = None
                raise
        worker.join(timeout=max(0.0, deadline - time.monotonic()))
        if worker.is_alive():
            raise CoordPolicyError(_ERR_CLOSE_INCOMPLETE)
        with self._meta_lock:
            err = self._settlement_error
            self._settlement_error = None
            settled = self._shutdown_settled
        if err is not None:
            raise err
        if not settled:
            raise CoordPolicyError(_ERR_CLOSE_INCOMPLETE)

    def _drain_producers_and_streams(self, deadline: float) -> None:
        pump_ok = self.dispatcher.stop_pump(deadline)
        fg_ok = self._wait_fg_ops(deadline)
        if not pump_ok or not fg_ok:
            raise CoordPolicyError(_ERR_CLOSE_INCOMPLETE)
        streams_ok = self.dispatcher.join_streams(deadline)
        if not streams_ok:
            raise CoordPolicyError(_ERR_CLOSE_INCOMPLETE)

    def close(self, *, timeout_s: float = 2.0) -> None:
        deadline = time.monotonic() + timeout_s
        if not self._acquire_lock_by_deadline(self._close_lock, deadline):
            raise CoordPolicyError(_ERR_CLOSE_INCOMPLETE)
        try:
            with self._meta_lock:
                if self._shutdown_settled:
                    return
                self._closed = True
                active_settlement = self._settlement_thread
            self._notify_waiters()
            if active_settlement is not None:
                self._finalize_settled_close(deadline)
                return
            self._drain_producers_and_streams(deadline)
            if not self._acquire_lock_by_deadline(self._register_lock, deadline):
                raise CoordPolicyError(_ERR_CLOSE_INCOMPLETE)
            try:
                with self._meta_lock:
                    self._accept_watchdog_spawns = False
                    for addr, lease in self._leases.items():
                        self._pending_close_retirements.setdefault(addr, lease)
                    leases = tuple(self._leases.items())
                    callbacks = dict(self._lease_callbacks)
            finally:
                self._register_lock.release()
            mon_ok = self._stop_all_controller_monitors(deadline)
            self._detach_lease_callbacks(leases, callbacks)
            wd_ok = self._join_watchdog_threads(timeout_s=max(0.0, deadline - time.monotonic()))
            if not mon_ok or not wd_ok:
                raise CoordPolicyError(_ERR_CLOSE_INCOMPLETE)
            self._finalize_settled_close(deadline)
        finally:
            self._close_lock.release()

    def _join_watchdog_threads(self, *, timeout_s: float = 2.0) -> bool:
        deadline = time.monotonic() + timeout_s
        current = threading.current_thread()
        with self._meta_lock:
            threads = [t for t in self._watchdog_threads if t is not current]
        for worker in threads:
            worker.join(timeout=max(0.0, deadline - time.monotonic()))
        return not any(t.is_alive() for t in threads)

    def _get_grant_fence(self, edge_id: str) -> threading.RLock:
        with self._meta_lock:
            fence = self._grant_fences.get(edge_id)
            if fence is None:
                fence = threading.RLock()
                self._grant_fences[edge_id] = fence
            return fence

    def _require_operational(
        self,
        *,
        allow_operator_diagnostic: bool = False,
        caller: PrincipalCtx | None = None,
    ) -> None:
        with self._meta_lock:
            if self._closed:
                raise CoordPolicyError(_ERR_HUB_CLOSED)
            degraded = self._degraded
        if degraded and not (
            allow_operator_diagnostic and caller is not None and caller.role is CoordRole.OPERATOR
        ):
            raise CoordPolicyError(_ERR_DEGRADED)

    def _require_not_degraded(self) -> None:
        self._require_operational()

    @staticmethod
    def _require_admin_role(caller: PrincipalCtx, action: str) -> None:
        if caller.role not in (CoordRole.OPERATOR, CoordRole.ORCHESTRATOR):
            raise CoordAuthError(f"{_ERR_ADMIN_ONLY}:{action}")

    @staticmethod
    def _is_lease_locally_revoked(lease: BrokerLease) -> bool:
        """Read BrokerLease local revocation flag without mutating it on controller lookup error."""
        lock = getattr(lease, "_lock", None)
        if lock is not None:
            with lock:
                return bool(getattr(lease, "_revoked", False))
        return bool(getattr(lease, "_revoked", False))

    def _probe_controller_request(
        self,
        request_id: str,
        *,
        controller: Controller | None = None,
        actor: Principal | None = None,
    ) -> str:
        """Return 'active', 'revoked' (authoritative deny), or 'unavailable' (lookup error)."""
        if request_id.startswith(_EPHEMERAL_LEASE_PREFIX):
            return _STATUS_REVOKED
        ctrl = controller if controller is not None else self._controller
        act = actor if actor is not None else self._controller_actor
        if ctrl is None or act is None:
            return _STATUS_UNAVAILABLE
        try:
            st = ctrl.status(act, request_id)
        except Denied:
            return _STATUS_REVOKED
        except Exception:
            return _STATUS_UNAVAILABLE
        active = st.eligible and not st.revoked
        if active and (controller is None or controller is self._controller):
            with self._meta_lock:
                self._unavailable_requests.discard(request_id)
        return _STATUS_ACTIVE if active else _STATUS_REVOKED

    def _check_controller_request_active(
        self,
        request_id: str,
        *,
        controller: Controller | None = None,
        actor: Principal | None = None,
    ) -> bool:
        return (
            self._probe_controller_request(request_id, controller=controller, actor=actor)
            == _STATUS_ACTIVE
        )

    @staticmethod
    def _require_authority_status_active(status: str, revoked_msg: str) -> None:
        if status == _STATUS_ACTIVE:
            return
        if status == _STATUS_UNAVAILABLE:
            raise _AuthorityUnavailableError(_ERR_CTRL_UNAVAILABLE)
        raise RevokedError(revoked_msg)

    def _check_in_memory_lease_status(
        self, lease: BrokerLease, controller_request_id: str | None
    ) -> str:
        if self._is_lease_locally_revoked(lease):
            return _STATUS_REVOKED
        lease_req = getattr(lease, _ATTR_LEASE_REQ_ID, None)
        if controller_request_id is None:
            if lease_req is None:
                return _STATUS_ACTIVE
            return self._probe_controller_request(lease_req)
        if lease_req is None and controller_request_id == self._ephemeral_authority_id(lease):
            return _STATUS_ACTIVE
        primary = self._probe_controller_request(controller_request_id)
        if primary != _STATUS_ACTIVE:
            return primary
        if lease_req is not None and lease_req != controller_request_id:
            return self._probe_controller_request(lease_req)
        return _STATUS_ACTIVE

    def _check_lease_status(
        self, sandbox_addr: str, *, controller_request_id: str | None = None
    ) -> str:
        with self._meta_lock:
            lease = self._leases.get(sandbox_addr)
        if lease is not None:
            return self._check_in_memory_lease_status(lease, controller_request_id)
        req_id = controller_request_id
        if req_id is None:
            sb = self._registry.get_sandbox(sandbox_addr)
            req_id = sb.controller_request_id if sb is not None else None
        if req_id is not None:
            return self._probe_controller_request(req_id)
        return _STATUS_ACTIVE

    def _check_lease_active(
        self, sandbox_addr: str, *, controller_request_id: str | None = None
    ) -> bool:
        return (
            self._check_lease_status(sandbox_addr, controller_request_id=controller_request_id)
            == _STATUS_ACTIVE
        )

    def _try_abort_stream(self, stream_id: str, *, reason: str) -> bool:
        """Attempt nonterminal per-stream abort without ever revoking the incarnation."""
        abort_stream = getattr(self._transport, "abort_stream", None)
        if not callable(abort_stream):
            return False
        try:
            return bool(abort_stream(stream_id, reason=reason))
        except Exception:
            return False

    def _handle_request_unavailable(self, request_id: str) -> None:
        """Fence and locally abort only turns/streams authorized by unavailable request_id."""
        with self._meta_lock:
            self._unavailable_requests.add(request_id)
            for inf in self._inflight_handoffs.values():
                if request_id in inf.req_ids:
                    inf.outage_observed = True
            affected = [
                sid
                for sid, auth in self._stream_authorities.items()
                if request_id in auth.req_ids
            ]
            for sid in affected:
                self._stream_abort_reasons.setdefault(sid, _ERR_CTRL_UNAVAILABLE)
        if not affected:
            return
        for sid in affected:
            self._try_abort_stream(sid, reason=_ERR_CTRL_UNAVAILABLE)
        self._notify_waiters()

    def _clear_unpersisted_stream_if_aborted(self, stream_id: str) -> None:
        """Release an unpersisted stream handle once transport cancellation succeeds."""
        with self._meta_lock:
            if self._stream_abort_reasons.get(stream_id) == _REASON_HANDOFF_PERSIST_FAILED:
                self._stream_authorities.pop(stream_id, None)
                self._stream_abort_reasons.pop(stream_id, None)

    def _retry_fenced_stream_aborts(self, request_id: str) -> None:
        with self._meta_lock:
            pairs = [
                (sid, self._stream_abort_reasons[sid])
                for sid, auth in self._stream_authorities.items()
                if request_id in auth.req_ids and sid in self._stream_abort_reasons
            ]
        for sid, reason in pairs:
            if self._try_abort_stream(sid, reason=reason):
                self._clear_unpersisted_stream_if_aborted(sid)

    def _has_streams_for_request(self, request_id: str) -> bool:
        with self._meta_lock:
            return any(
                request_id in auth.req_ids for auth in self._stream_authorities.values()
            ) or any(
                request_id in inf.req_ids for inf in self._inflight_handoffs.values()
            )

    def _revoke_edges_for_lease_request_locked(
        self, watchdog_caller: PrincipalCtx, request_id: str
    ) -> list[str]:
        matching = [
            e
            for e in self._registry.list_edges(active_only=True)
            if e.lease_request_id == request_id
        ]
        if not matching:
            return []
        edge_ids = sorted(e.edge_id for e in matching)
        edge_id_set = set(edge_ids)
        fences = [self._get_grant_fence(eid) for eid in edge_ids]
        for fence in fences:
            fence.acquire()
        try:
            with self._meta_lock:
                for edge in matching:
                    self._fenced_generations.add((edge.edge_id, edge.grant_generation))
                edge_sids = [
                    sid
                    for sid, auth in self._stream_authorities.items()
                    if auth.edge_id in edge_id_set or request_id in auth.req_ids
                ]
                for sid in edge_sids:
                    self._stream_abort_reasons.setdefault(sid, _REASON_EDGE_LEASE_REVOKED)
            for edge in matching:
                self._registry.revoke_grant_and_cancel_outbox(
                    edge_id=edge.edge_id, reason=_REASON_EDGE_LEASE_REVOKED
                )
                self._registry.append_audit(
                    watchdog_caller.canonical_sender,
                    "revoke_edge_lease",
                    edge.edge_id,
                    _OUTCOME_OK,
                    {"lease_request_id": request_id, "dst_addr": edge.dst_addr},
                )
            return edge_sids
        finally:
            for fence in reversed(fences):
                fence.release()

    def _handle_request_revoked(self, request_id: str) -> None:
        """Apply confirmed revocation strictly to sandboxes, edges, and streams bound to request_id."""
        with self._meta_lock:
            self._unavailable_requests.discard(request_id)
            for inf in self._inflight_handoffs.values():
                if request_id in inf.req_ids:
                    inf.revoked_observed = True
        watchdog_caller = PrincipalCtx(role=CoordRole.OPERATOR, actor_id="controller-monitor")
        edge_sids: list[str] = []
        try:
            with self._register_lock:
                if self._shutdown_settled:
                    return
                for sb in self._registry.list_sandboxes():
                    if sb.status != _STATUS_REVOKED and sb.controller_request_id == request_id:
                        self._revoke_unlocked(
                            watchdog_caller,
                            target=sb.sandbox_addr,
                            reason=_REASON_CTRL_LEASE_REVOKED,
                        )
                edge_sids = self._revoke_edges_for_lease_request_locked(
                    watchdog_caller, request_id
                )
        except Exception:
            self._mark_degraded("controller_monitor_revoke_failed")
        with self._meta_lock:
            extra_sids = [
                sid
                for sid, auth in self._stream_authorities.items()
                if request_id in auth.req_ids
            ]
            for sid in extra_sids:
                self._stream_abort_reasons.setdefault(sid, _REASON_CTRL_LEASE_REVOKED)
        for sid in edge_sids:
            self._try_abort_stream(sid, reason=_REASON_EDGE_LEASE_REVOKED)
        for sid in extra_sids:
            if sid not in edge_sids:
                self._try_abort_stream(sid, reason=_REASON_CTRL_LEASE_REVOKED)
        self._notify_waiters()

    def _ensure_controller_monitor(self, request_id: str) -> None:
        """Reserve and start one tracked hub controller-grant monitor per unique request_id."""
        if request_id.startswith(_EPHEMERAL_LEASE_PREFIX):
            return
        if self._controller is None or self._controller_actor is None:
            raise _AuthorityUnavailableError(_ERR_CTRL_UNAVAILABLE)
        with self._meta_lock:
            if not self._accept_watchdog_spawns or self._shutdown_settled:
                return
            existing = self._request_monitors.get(request_id)
            if existing is None:
                stop_ev = threading.Event()
                state = _RequestMonitorState(stop_ev=stop_ev)
                worker = threading.Thread(
                    target=self._run_controller_monitor,
                    args=(state, request_id),
                    daemon=True,
                )
                state.thread = worker
                self._request_monitors[request_id] = state
        if existing is not None:
            existing.ready_ev.wait()
            if existing.start_error is not None:
                raise existing.start_error
            return
        try:
            worker.start()
        except Exception as exc:
            with self._meta_lock:
                state.start_error = exc
                if self._request_monitors.get(request_id) is state:
                    self._request_monitors.pop(request_id, None)
                self._retired_monitors.discard(state)
                state.ready_ev.set()
            raise
        with self._meta_lock:
            state.started = True
            if not self._accept_watchdog_spawns or self._shutdown_settled:
                state.stop_ev.set()
            state.ready_ev.set()

    def _poll_controller_monitor_tick(
        self, request_id: str, revoked_applied: bool
    ) -> tuple[bool, bool]:
        if revoked_applied:
            self._retry_fenced_stream_aborts(request_id)
            return not self._has_streams_for_request(request_id), True
        probe = self._probe_controller_request(request_id)
        if probe == _STATUS_ACTIVE:
            with self._meta_lock:
                self._unavailable_requests.discard(request_id)
            self._retry_fenced_stream_aborts(request_id)
            return False, False
        if probe == _STATUS_UNAVAILABLE:
            self._handle_request_unavailable(request_id)
            return False, False
        if probe == _STATUS_REVOKED:
            self._handle_request_revoked(request_id)
            return not self._has_streams_for_request(request_id), True
        return False, False

    def _run_controller_monitor(
        self,
        state: _RequestMonitorState,
        request_id: str,
    ) -> None:
        revoked_applied = False
        try:
            while not state.stop_ev.wait(self._watchdog_interval_s):
                done, revoked_applied = self._poll_controller_monitor_tick(
                    request_id, revoked_applied
                )
                if done:
                    return
        finally:
            with self._meta_lock:
                if self._request_monitors.get(request_id) is state:
                    self._request_monitors.pop(request_id, None)
                self._retired_monitors.discard(state)

    def _retire_all_monitors_locked(self) -> None:
        for state in self._request_monitors.values():
            state.stop_ev.set()
            self._retired_monitors.add(state)
        self._request_monitors.clear()

    def _stop_all_controller_monitors(self, deadline: float) -> bool:
        current = threading.current_thread()
        with self._meta_lock:
            states = tuple(self._request_monitors.values()) + tuple(self._retired_monitors)
            for st in states:
                st.stop_ev.set()
        for st in states:
            if st.thread is current:
                continue
            remaining = max(0.0, deadline - time.monotonic())
            if not st.ready_ev.wait(timeout=remaining):
                return False
            if st.started and st.thread is not None:
                st.thread.join(timeout=max(0.0, deadline - time.monotonic()))
        with self._meta_lock:
            remaining_states = tuple(self._request_monitors.values()) + tuple(
                self._retired_monitors
            )
            return not any(
                st.thread is not current
                and (
                    not st.ready_ev.is_set()
                    or (st.thread is not None and st.thread.is_alive())
                )
                for st in remaining_states
            )

    @staticmethod
    def _ephemeral_authority_id(lease: BrokerLease) -> str:
        raw_id = f"{_EPHEMERAL_LEASE_PREFIX}{lease.job_id}"
        try:
            return validate_opaque_token(raw_id, _LABEL_CTRL_REQ_ID)
        except CoordValidationError:
            digest = hashlib.sha256(str(lease.job_id).encode("utf-8", errors="replace")).hexdigest()[:32]
            return f"{_EPHEMERAL_LEASE_PREFIX}{digest}"

    def _verify_caller_live(self, caller: PrincipalCtx) -> None:
        if caller.sandbox_addr is None:
            return
        addr = caller.sandbox_addr
        with self._meta_lock:
            if addr in self._fenced_addrs:
                raise RevokedError(_ERR_SANDBOX_REVOKED)
        sb = self._registry.get_sandbox(addr)
        if sb is None or sb.status == _STATUS_REVOKED:
            raise RevokedError(_ERR_SANDBOX_REVOKED)
        if caller.incarnation_id != sb.incarnation_id:
            raise IncarnationMismatchError("Caller sandbox incarnation mismatch")
        with self._meta_lock:
            if (addr, sb.incarnation_id) in self._fenced_targets:
                raise RevokedError(_ERR_SANDBOX_REVOKED)
        self._require_authority_status_active(
            self._check_lease_status(addr, controller_request_id=sb.controller_request_id),
            _ERR_SANDBOX_REVOKED,
        )

    def _subtree_addrs(self, root_addr: str) -> set[str]:
        all_sbs = self._registry.list_sandboxes()
        by_parent: dict[str | None, list[str]] = {}
        for sb in all_sbs:
            by_parent.setdefault(sb.parent_addr, []).append(sb.sandbox_addr)
        visited: set[str] = {root_addr}
        queue: deque[str] = deque([root_addr])
        while queue:
            cur = queue.popleft()
            for child in by_parent.get(cur, ()):
                if child not in visited:
                    visited.add(child)
                    queue.append(child)
        return visited

    def _is_in_subtree(self, ancestor_addr: str, target_addr: str) -> bool:
        return target_addr in self._subtree_addrs(ancestor_addr)

    def _detach_prior_lease(self, sandbox_addr: str) -> None:
        with self._meta_lock:
            old_lease = self._leases.pop(sandbox_addr, None)
            old_cb = self._lease_callbacks.pop(sandbox_addr, None)
        if old_lease is not None:
            if old_cb is not None:
                old_lease.remove_revoke_callback(old_cb)
            try:
                old_lease.revoke()
            except Exception:
                pass

    def _on_lease_revoked(
        self,
        sandbox_addr: str,
        expected_incarnation_id: str,
        expected_lease: BrokerLease,
    ) -> None:
        """Dispatch incarnation-bound revocation on a tracked daemon thread without re-entering fences."""

        def _run() -> None:
            watchdog_caller = PrincipalCtx(role=CoordRole.OPERATOR, actor_id="lease-watchdog")
            try:
                with self._register_lock:
                    with self._meta_lock:
                        if self._shutdown_settled:
                            return
                        current_lease = self._leases.get(sandbox_addr)
                    if current_lease is not expected_lease:
                        return
                    sb = self._registry.get_sandbox(sandbox_addr)
                    if sb is None or sb.incarnation_id != expected_incarnation_id:
                        return
                    self._revoke_unlocked(
                        watchdog_caller,
                        target=sandbox_addr,
                        reason=_REASON_CTRL_LEASE_REVOKED,
                    )
            except Exception:
                self._mark_degraded("lease_watchdog_revoke_failed")
            finally:
                with self._meta_lock:
                    self._watchdog_threads.discard(threading.current_thread())

        worker = threading.Thread(target=_run, daemon=True)
        with self._meta_lock:
            if not self._accept_watchdog_spawns or self._shutdown_settled:
                return
            self._watchdog_threads.add(worker)
        worker.start()

    def _resolve_parent_budget(
        self, parent_addr: str | None, active_sandboxes: list[SandboxRecord]
    ) -> tuple[int, SubtreeBudget]:
        if parent_addr is None:
            return 0, self._root_budget
        parent = self._registry.get_sandbox(parent_addr)
        if (
            parent is None
            or parent.status == _STATUS_REVOKED
            or self._is_target_fenced(parent_addr, parent.incarnation_id)
        ):
            raise CoordPolicyError(f"Parent sandbox unavailable: {parent_addr!r}")
        budget_key = (parent_addr, parent.incarnation_id)
        with self._meta_lock:
            parent_budget = self._budgets.get(budget_key)
        if parent_budget is None:
            get_budget = getattr(self._registry, "get_sandbox_budget", None)
            if callable(get_budget):
                parent_budget = get_budget(parent_addr, parent.incarnation_id)
            if parent_budget is None:
                raise CoordPolicyError("parent_budget_not_established")
            with self._meta_lock:
                self._budgets[budget_key] = parent_budget
        if parent_budget.max_depth_remaining <= 0:
            raise CoordPolicyError("Subtree max_depth_remaining exhausted")
        children = [sb for sb in active_sandboxes if sb.parent_addr == parent_addr]
        if len(children) >= parent_budget.max_children:
            raise CoordPolicyError("Parent max_children budget exceeded")
        return parent.depth + 1, parent_budget

    def _validate_sandbox_budget(
        self,
        *,
        parent_addr: str | None,
        sandbox_type: str,
        child_budget: SubtreeBudget | None,
    ) -> tuple[int, SubtreeBudget]:
        active_sandboxes = [
            sb for sb in self._registry.list_sandboxes() if sb.status != _STATUS_REVOKED
        ]
        if len(active_sandboxes) >= self._root_budget.max_total_sandboxes:
            raise CoordPolicyError("Global max_total_sandboxes cap exceeded")

        depth, parent_budget = self._resolve_parent_budget(parent_addr, active_sandboxes)
        if len(active_sandboxes) >= parent_budget.max_total_sandboxes:
            raise CoordPolicyError("Subtree max_total_sandboxes cap exceeded")
        if sandbox_type not in parent_budget.allowed_sandbox_types:
            raise CoordPolicyError(f"sandbox_type {sandbox_type!r} denied by SubtreeBudget")
        if "local" not in parent_budget.allowed_workers:
            raise CoordPolicyError("local worker denied by SubtreeBudget")

        if child_budget is not None:
            if not parent_budget.attenuates(child_budget):
                raise CoordPolicyError("child_budget fails monotonic SubtreeBudget attenuation")
            return depth, child_budget

        next_depth = max(0, parent_budget.max_depth_remaining - 1)
        effective_budget = SubtreeBudget(
            max_depth_remaining=next_depth,
            max_children=parent_budget.max_children,
            max_total_sandboxes=parent_budget.max_total_sandboxes,
            allowed_workers=parent_budget.allowed_workers,
            allowed_sandbox_types=parent_budget.allowed_sandbox_types,
            allowed_models=parent_budget.allowed_models,
            allowed_variants=parent_budget.allowed_variants,
            allowed_broker_routes=parent_budget.allowed_broker_routes,
            max_security_profile=parent_budget.max_security_profile,
        )
        return depth, effective_budget

    def _enforce_register_caller_scope(
        self,
        caller: PrincipalCtx,
        addr: str,
        clean_parent: str | None,
        existing: SandboxRecord | None,
        clean_inc: str,
    ) -> None:
        if (
            existing is not None
            and existing.status == _STATUS_REVOKED
            and existing.incarnation_id == clean_inc
        ) or self._is_target_fenced(addr, clean_inc):
            raise RevokedError("cannot_reregister_revoked_incarnation")
        if caller.role is CoordRole.ORCHESTRATOR:
            if existing is not None:
                raise CoordPolicyError("orchestrator_cannot_overwrite_sandbox")
            if caller.sandbox_addr is not None and clean_parent != caller.sandbox_addr:
                raise CoordAuthError("sub_orchestrator_must_bind_own_parent_addr")

    def _rotate_existing_sandbox(
        self, addr: str, existing: SandboxRecord, new_incarnation: str
    ) -> None:
        self._detach_prior_lease(addr)
        if existing.incarnation_id == new_incarnation:
            return
        with self._meta_lock:
            self._fenced_targets.add((addr, existing.incarnation_id))
        orch_actor = f"{_ORCH_ACTOR_PREFIX}{addr}"
        with self._wait_cond:
            for w in self._waiters:
                if addr in w.targets or w.caller_actor in (addr, orch_actor):
                    w.revoked = True
            self._wait_gen += 1
            self._wait_cond.notify_all()
        try:
            self._transport.abort_incarnation(
                addr, existing.incarnation_id, reason="incarnation_rotated"
            )
        except Exception:
            pass
        invalidate = getattr(self._registry, "invalidate_prior_incarnation", None)
        if callable(invalidate):
            invalidate(addr, new_incarnation, reason="incarnation_rotated")

    def _inspect_lease_controller(
        self, caller: PrincipalCtx, lease: BrokerLease
    ) -> tuple[str | None, Controller | None, Principal | None]:
        if self._is_lease_locally_revoked(lease):
            raise RevokedError("lease_already_revoked")
        lease_controller = getattr(lease, "_controller", None)
        if (
            self._controller is not None
            and lease_controller is not None
            and lease_controller is not self._controller
        ):
            raise CoordPolicyError("lease_controller_mismatch")
        eff_controller = self._controller
        if eff_controller is None and lease_controller is not None:
            if caller.role is not CoordRole.OPERATOR:
                raise CoordAuthError("operator_required_to_bind_controller")
            eff_controller = lease_controller
        lease_actor = getattr(lease, "_controller_actor", None)
        eff_actor = self._controller_actor
        if eff_actor is None and lease_actor is not None:
            if caller.role is not CoordRole.OPERATOR:
                raise CoordAuthError("operator_required_to_bind_controller")
            eff_actor = lease_actor
        raw_lease_req = getattr(lease, _ATTR_LEASE_REQ_ID, None)
        lease_req = (
            validate_opaque_token(raw_lease_req, _LABEL_CTRL_REQ_ID)
            if raw_lease_req is not None
            else None
        )
        return lease_req, eff_controller, eff_actor

    def _resolve_register_authority(
        self,
        caller: PrincipalCtx,
        lease: BrokerLease | None,
        controller_request_id: str | None,
    ) -> tuple[str | None, Controller | None, Principal | None]:
        clean_req = (
            validate_opaque_token(controller_request_id, _LABEL_CTRL_REQ_ID)
            if controller_request_id is not None
            else None
        )
        if clean_req is not None and clean_req.startswith(_EPHEMERAL_LEASE_PREFIX):
            raise CoordValidationError("ephemeral_lease_prefix_reserved")
        if lease is None:
            if clean_req is not None:
                self._require_authority_status_active(
                    self._probe_controller_request(clean_req), "controller_request_not_active"
                )
            return clean_req, self._controller, self._controller_actor
        lease_req, eff_controller, eff_actor = self._inspect_lease_controller(caller, lease)
        if clean_req is not None and lease_req is not None and clean_req != lease_req:
            raise CoordPolicyError("lease_controller_request_id_mismatch")
        effective_req = clean_req if clean_req is not None else lease_req
        if effective_req is None:
            return self._ephemeral_authority_id(lease), eff_controller, eff_actor
        # Durable authority requires the lease itself to carry the same controller & request ID.
        if (
            getattr(lease, "_controller", None) is not eff_controller
            or getattr(lease, _ATTR_LEASE_REQ_ID, None) != effective_req
            or getattr(lease, "_controller_actor", None) is None
        ):
            raise CoordPolicyError("lease_controller_binding_incomplete")
        self._require_authority_status_active(
            self._probe_controller_request(
                effective_req, controller=eff_controller, actor=eff_actor
            ),
            "controller_request_not_active",
        )
        return effective_req, eff_controller, eff_actor

    def register_sandbox(
        self,
        caller: PrincipalCtx,
        *,
        name: str,
        incarnation_id: str,
        project_id: str,
        project_name: str,
        branch: str,
        sandbox_type: str = "default",
        task_brief: str,
        parent_addr: str | None = None,
        child_budget: SubtreeBudget | None = None,
        lease: BrokerLease | None = None,
        controller_request_id: str | None = None,
    ) -> SandboxRecord:
        self._enter_fg_op()
        try:
            return self._register_sandbox_tracked(
                caller,
                name=name,
                incarnation_id=incarnation_id,
                project_id=project_id,
                project_name=project_name,
                branch=branch,
                sandbox_type=sandbox_type,
                task_brief=task_brief,
                parent_addr=parent_addr,
                child_budget=child_budget,
                lease=lease,
                controller_request_id=controller_request_id,
            )
        finally:
            self._exit_fg_op()

    def _bind_and_start_register_monitor(
        self,
        effective_req_id: str | None,
        eff_controller: Controller | None,
        eff_actor: Principal | None,
    ) -> None:
        prev_ctrl, prev_actor = self._controller, self._controller_actor
        if self._controller is None and eff_controller is not None:
            self._controller = eff_controller
        if self._controller_actor is None and eff_actor is not None:
            self._controller_actor = eff_actor
        if effective_req_id is None or effective_req_id.startswith(_EPHEMERAL_LEASE_PREFIX):
            return
        try:
            self._ensure_controller_monitor(effective_req_id)
        except Exception:
            self._controller = prev_ctrl
            self._controller_actor = prev_actor
            raise

    def _register_sandbox_tracked(
        self,
        caller: PrincipalCtx,
        *,
        name: str,
        incarnation_id: str,
        project_id: str,
        project_name: str,
        branch: str,
        sandbox_type: str = "default",
        task_brief: str,
        parent_addr: str | None = None,
        child_budget: SubtreeBudget | None = None,
        lease: BrokerLease | None = None,
        controller_request_id: str | None = None,
    ) -> SandboxRecord:
        with self._meta_lock:
            start_rec_gen = self._recovery_generation
        self._require_not_degraded()
        self._require_admin_role(caller, "register_sandbox")
        addr = parse_local_target(name)
        clean_inc = validate_opaque_token(incarnation_id, _LABEL_INCARNATION)
        clean_brief = validate_task_brief(task_brief)
        clean_parent = parse_local_target(parent_addr).canonical if parent_addr is not None else None

        with self._register_lock:
            self._require_not_degraded()
            with self._meta_lock:
                if self._recovery_generation != start_rec_gen:
                    raise CoordPolicyError(_ERR_DEGRADED)
            self._verify_caller_live(caller)
            existing = self._registry.get_sandbox(addr.canonical)
            self._enforce_register_caller_scope(
                caller, addr.canonical, clean_parent, existing, clean_inc
            )
            depth, effective_budget = self._validate_sandbox_budget(
                parent_addr=clean_parent,
                sandbox_type=sandbox_type,
                child_budget=child_budget,
            )
            effective_req_id, eff_controller, eff_actor = self._resolve_register_authority(
                caller, lease, controller_request_id
            )
            self._bind_and_start_register_monitor(effective_req_id, eff_controller, eff_actor)
            if existing is not None:
                self._rotate_existing_sandbox(addr.canonical, existing, clean_inc)
            now = time.time()
            record = SandboxRecord(
                sandbox_addr=addr.canonical,
                worker_ref=addr.worker_ref,
                instance_name=addr.name,
                incarnation_id=clean_inc,
                job_id=lease.job_id if lease is not None else mint_crypto_id("job"),
                project_id=project_id,
                project_name=project_name,
                branch=branch,
                sandbox_type=sandbox_type,
                task_brief=clean_brief,
                status=_STATUS_RUNNING,
                controller_request_id=effective_req_id,
                parent_addr=clean_parent,
                depth=depth,
                created_at=now,
                updated_at=now,
            )
            persisted = self._registry.register_sandbox(record)
            save_budget = getattr(self._registry, "save_sandbox_budget", None)
            if callable(save_budget):
                save_budget(addr.canonical, clean_inc, effective_budget)
            self._registry.ensure_thread(addr.canonical, clean_inc, _THREAD_MAIN, title=clean_brief[:64])
            self._record_registered_meta(addr.canonical, clean_inc, effective_budget, lease)
            if lease is not None:
                self._attach_lease_watchdog(addr.canonical, clean_inc, lease)

        self._registry.append_audit(
            caller.canonical_sender,
            "register_sandbox",
            addr.canonical,
            _OUTCOME_OK,
            {_LABEL_INCARNATION: clean_inc, "depth": depth},
        )
        return persisted

    def _record_registered_meta(
        self,
        addr: str,
        incarnation_id: str,
        budget: SubtreeBudget,
        lease: BrokerLease | None,
    ) -> None:
        with self._meta_lock:
            self._fenced_addrs.discard(addr)
            self._known_incarnations.setdefault(addr, set()).add(incarnation_id)
            self._budgets[(addr, incarnation_id)] = budget
            if lease is not None:
                self._leases[addr] = lease

    def _attach_lease_watchdog(
        self, sandbox_addr: str, incarnation_id: str, lease: BrokerLease
    ) -> None:
        def _cb() -> None:
            self._on_lease_revoked(sandbox_addr, incarnation_id, lease)

        with self._meta_lock:
            if self._leases.get(sandbox_addr) is not lease:
                return
            self._lease_callbacks[sandbox_addr] = _cb
        lease.add_revoke_callback(_cb)

    def _enforce_grant_edge_scope(
        self,
        caller: PrincipalCtx,
        src_actor: str,
        dst_addr: str,
        clean_src_inc: str | None,
    ) -> str | None:
        if caller.role is not CoordRole.ORCHESTRATOR:
            return clean_src_inc
        if src_actor.startswith("operator:"):
            raise CoordAuthError("orchestrator_cannot_grant_operator_edge")
        if caller.sandbox_addr is None:
            return clean_src_inc
        subtree = self._subtree_addrs(caller.sandbox_addr)
        if dst_addr not in subtree or dst_addr == caller.sandbox_addr:
            raise CoordAuthError("orchestrator_edge_target_outside_subtree")
        if src_actor == caller.canonical_sender:
            return caller.incarnation_id
        src_sb_addr = _sandbox_addr_from_actor(src_actor)
        if src_sb_addr is None or src_sb_addr not in subtree or src_sb_addr == caller.sandbox_addr:
            raise CoordAuthError("orchestrator_edge_source_outside_subtree")
        src_sb = self._require_dst_sandbox_live(src_sb_addr, None)
        if clean_src_inc is not None and clean_src_inc != src_sb.incarnation_id:
            raise IncarnationMismatchError("Source child incarnation mismatch")
        return src_sb.incarnation_id

    @staticmethod
    def _validate_edge_bounds(
        threads: frozenset[str],
        kinds: frozenset[str],
        max_rounds: int,
        rate_limit_rpm: int,
        grant_generation: int,
    ) -> None:
        if not threads or not kinds:
            raise CoordValidationError("allowed_threads and allowed_msg_kinds must be non-empty")
        if type(max_rounds) is not int or not (1 <= max_rounds <= _MAX_EDGE_ROUNDS_CAP):
            raise CoordValidationError("max_rounds out of bounds")
        if type(rate_limit_rpm) is not int or not (1 <= rate_limit_rpm <= _MAX_RATE_LIMIT_RPM):
            raise CoordValidationError("rate_limit_rpm out of bounds")
        if type(grant_generation) is not int or grant_generation < 1:
            raise CoordValidationError("grant_generation must be >= 1")

    def grant_edge(
        self,
        caller: PrincipalCtx,
        *,
        src_actor: str,
        dst_addr: str,
        allowed_threads: Iterable[str] = (_THREAD_MAIN,),
        allowed_msg_kinds: Iterable[str] = (_KIND_PROMPT,),
        max_rounds: int = DEFAULT_EDGE_MAX_ROUNDS,
        rate_limit_rpm: int = 60,
        src_incarnation: str | None = None,
        lease_request_id: str | None = None,
        grant_generation: int = 1,
    ) -> RoutingEdge:
        self._enter_fg_op()
        try:
            return self._grant_edge_tracked(
                caller,
                src_actor=src_actor,
                dst_addr=dst_addr,
                allowed_threads=allowed_threads,
                allowed_msg_kinds=allowed_msg_kinds,
                max_rounds=max_rounds,
                rate_limit_rpm=rate_limit_rpm,
                src_incarnation=src_incarnation,
                lease_request_id=lease_request_id,
                grant_generation=grant_generation,
            )
        finally:
            self._exit_fg_op()

    def _grant_edge_tracked(
        self,
        caller: PrincipalCtx,
        *,
        src_actor: str,
        dst_addr: str,
        allowed_threads: Iterable[str] = (_THREAD_MAIN,),
        allowed_msg_kinds: Iterable[str] = (_KIND_PROMPT,),
        max_rounds: int = DEFAULT_EDGE_MAX_ROUNDS,
        rate_limit_rpm: int = 60,
        src_incarnation: str | None = None,
        lease_request_id: str | None = None,
        grant_generation: int = 1,
    ) -> RoutingEdge:
        with self._meta_lock:
            start_rec_gen = self._recovery_generation
        self._require_not_degraded()
        self._require_admin_role(caller, "grant_edge")
        dst = parse_local_target(dst_addr)
        threads = frozenset(validate_thread_id(t) for t in allowed_threads)
        kinds = frozenset(validate_msg_kind(k) for k in allowed_msg_kinds)
        self._validate_edge_bounds(threads, kinds, max_rounds, rate_limit_rpm, grant_generation)
        clean_src_inc = (
            validate_opaque_token(src_incarnation, "src_incarnation")
            if src_incarnation is not None
            else None
        )
        clean_lease_req = (
            validate_opaque_token(lease_request_id, "lease_request_id")
            if lease_request_id is not None
            else None
        )
        if clean_lease_req is not None and clean_lease_req.startswith(_EPHEMERAL_LEASE_PREFIX):
            raise CoordValidationError("ephemeral_lease_prefix_reserved")

        with self._register_lock:
            self._require_not_degraded()
            with self._meta_lock:
                if self._recovery_generation != start_rec_gen:
                    raise CoordPolicyError(_ERR_DEGRADED)
            self._verify_caller_live(caller)
            clean_src_inc = self._enforce_grant_edge_scope(
                caller, src_actor, dst.canonical, clean_src_inc
            )
            if clean_src_inc is not None:
                self._check_source_sandbox_live(src_actor, clean_src_inc)
            self._require_dst_sandbox_live(dst.canonical, clean_lease_req)
            if clean_lease_req is not None:
                self._ensure_controller_monitor(clean_lease_req)
            edge = RoutingEdge(
                edge_id=mint_crypto_id("edge"),
                src_actor=src_actor,
                src_incarnation=clean_src_inc,
                dst_addr=dst.canonical,
                allowed_threads=threads,
                allowed_msg_kinds=kinds,
                max_rounds=max_rounds,
                turns_used=0,
                rate_limit_rpm=rate_limit_rpm,
                active=True,
                lease_request_id=clean_lease_req,
                grant_generation=grant_generation,
                created_at=time.time(),
            )
            persisted = self._registry.grant_edge(edge)
        self._registry.append_audit(
            caller.canonical_sender,
            "grant_edge",
            dst.canonical,
            _OUTCOME_OK,
            {"edge_id": persisted.edge_id, "src_actor": src_actor},
        )
        return persisted

    def _require_dst_sandbox_live(
        self, dst_addr: str, lease_request_id: str | None
    ) -> SandboxRecord:
        sandbox = self._registry.get_sandbox(dst_addr)
        if sandbox is None:
            raise CoordPolicyError(_ERR_SANDBOX_NOT_FOUND)
        if sandbox.status == _STATUS_REVOKED or self._is_target_fenced(dst_addr, sandbox.incarnation_id):
            raise RevokedError(_ERR_SANDBOX_REVOKED)
        self._require_authority_status_active(
            self._check_lease_status(dst_addr, controller_request_id=sandbox.controller_request_id),
            _ERR_SANDBOX_REVOKED,
        )
        if lease_request_id is not None and lease_request_id != sandbox.controller_request_id:
            self._require_authority_status_active(
                self._check_lease_status(dst_addr, controller_request_id=lease_request_id),
                _ERR_SANDBOX_REVOKED,
            )
        return sandbox

    def _check_rate_limit(self, edge_id: str, rate_limit_rpm: int) -> None:
        now = time.monotonic()
        cutoff = now - 60.0
        with self._meta_lock:
            window = self._rate_windows.setdefault(edge_id, deque())
            while window and window[0] < cutoff:
                window.popleft()
            if len(window) >= rate_limit_rpm:
                raise CoordBackpressureError("Per-edge rate_limit_rpm exceeded")

    def _record_rate_hit(self, edge_id: str) -> None:
        with self._meta_lock:
            self._rate_windows.setdefault(edge_id, deque()).append(time.monotonic())

    def _is_target_fenced(self, addr: str, incarnation_id: str | None = None) -> bool:
        with self._meta_lock:
            if addr in self._fenced_addrs:
                return True
            if incarnation_id is not None and (addr, incarnation_id) in self._fenced_targets:
                return True
        return False

    def _check_source_sandbox_live(
        self, src_actor: str, expected_src_incarnation: str | None = None
    ) -> None:
        sb_addr = _sandbox_addr_from_actor(src_actor)
        if sb_addr is None:
            if expected_src_incarnation is not None:
                raise IncarnationMismatchError("src_sandbox_not_found")
            return
        if self._is_target_fenced(sb_addr):
            raise RevokedError(_ERR_EDGE_REVOKED)
        src_sb = self._registry.get_sandbox(sb_addr)
        if src_sb is None:
            if expected_src_incarnation is not None:
                raise IncarnationMismatchError("src_sandbox_not_found")
            return
        if src_sb.status == _STATUS_REVOKED or self._is_target_fenced(sb_addr, src_sb.incarnation_id):
            raise RevokedError(_ERR_EDGE_REVOKED)
        if expected_src_incarnation is not None and src_sb.incarnation_id != expected_src_incarnation:
            raise IncarnationMismatchError("src_incarnation_mismatch")
        self._require_authority_status_active(
            self._check_lease_status(sb_addr, controller_request_id=src_sb.controller_request_id),
            _ERR_EDGE_REVOKED,
        )

    def _check_grant_pins_live_under_fence(
        self,
        edge_id: str,
        expected_gen: int,
        dst_addr: str,
        *,
        expected_dst_incarnation: str | None = None,
        expected_src_incarnation: str | None = None,
    ) -> tuple[RoutingEdge, SandboxRecord]:
        edge = self._registry.get_edge(edge_id)
        if edge is None or not edge.active or edge.grant_generation != expected_gen:
            raise RevokedError(_ERR_EDGE_REVOKED)
        with self._meta_lock:
            gen_fenced = (edge_id, expected_gen) in self._fenced_generations
        if gen_fenced or self._registry.is_grant_tombstoned(edge_id, expected_gen):
            raise RevokedError(_ERR_EDGE_REVOKED)
        eff_src_inc = expected_src_incarnation if expected_src_incarnation is not None else edge.src_incarnation
        self._check_source_sandbox_live(edge.src_actor, eff_src_inc)
        sandbox = self._require_dst_sandbox_live(dst_addr, edge.lease_request_id)
        if expected_dst_incarnation is not None and sandbox.incarnation_id != expected_dst_incarnation:
            raise IncarnationMismatchError("Target sandbox incarnation rotated")
        return edge, sandbox

    def _verify_grant_live_under_fence(
        self,
        edge_id: str,
        expected_gen: int,
        dst_addr: str,
        *,
        expected_dst_incarnation: str | None = None,
        expected_src_incarnation: str | None = None,
    ) -> tuple[RoutingEdge, SandboxRecord]:
        self._require_not_degraded()
        return self._check_grant_pins_live_under_fence(
            edge_id,
            expected_gen,
            dst_addr,
            expected_dst_incarnation=expected_dst_incarnation,
            expected_src_incarnation=expected_src_incarnation,
        )

    def _validate_caller_incarnation_and_lease(
        self, caller: PrincipalCtx, edge: RoutingEdge
    ) -> None:
        self._verify_caller_live(caller)
        if edge.src_incarnation is not None and caller.incarnation_id != edge.src_incarnation:
            raise IncarnationMismatchError("Caller incarnation mismatch")

    @staticmethod
    def _validate_artifact_inputs(
        artifact_blobs: Sequence[bytes], artifact_refs: Sequence[ArtifactRef]
    ) -> tuple[ArtifactRef, ...]:
        if artifact_refs:
            raise CoordPolicyError("unverified_artifact_refs_rejected")
        if len(artifact_blobs) > MAX_ARTIFACTS_PER_MSG:
            raise CoordValidationError(f"Too many total artifacts (max {MAX_ARTIFACTS_PER_MSG})")
        return ()

    def _build_and_enqueue_envelope(
        self,
        caller: PrincipalCtx,
        edge: RoutingEdge,
        *,
        target_addr: str,
        thread_id: str,
        msg_kind: str,
        clean_body: str,
        dst_incarnation: str,
        in_reply_to: str | None,
        all_refs: tuple[ArtifactRef, ...],
    ) -> tuple[int, Envelope]:
        sender_id = caller.canonical_sender
        wire_body = clean_body
        if caller.trust_class is TrustClass.UNTRUSTED_PEER_DATA:
            wire_body, _nonce = frame_untrusted_peer_message(
                clean_body, verified_sender=sender_id, msg_kind=msg_kind
            )
        envelope = Envelope(
            msg_id=mint_crypto_id("msg"),
            seq=0,
            src_role=caller.role,
            src_actor=sender_id,
            src_incarnation=caller.incarnation_id,
            dst_addr=target_addr,
            dst_thread_id=thread_id,
            dst_incarnation=dst_incarnation,
            trust_class=caller.trust_class,
            msg_kind=msg_kind,
            body_text=wire_body,
            body_sha256=sha256_canonical_body(wire_body, max_bytes=MAX_FRAMED_BODY_BYTES),
            edge_id=edge.edge_id,
            edge_turn_seq=0,
            in_reply_to=in_reply_to,
            artifact_refs=all_refs,
            created_at=time.time(),
        )
        reply_check = (in_reply_to, sender_id, thread_id) if in_reply_to is not None else None
        return self._registry.admit_and_enqueue_send(
            edge_id=edge.edge_id,
            expected_grant_generation=edge.grant_generation,
            expected_src_incarnation=caller.incarnation_id,
            expected_dst_incarnation=dst_incarnation,
            envelope=envelope,
            count_turn=not is_control_priority(caller.trust_class, msg_kind),
            max_queued_msgs=EDGE_MAX_QUEUED_MSGS,
            max_queued_bytes=EDGE_MAX_QUEUED_BYTES,
            check_in_reply_to=reply_check,
        )

    def _prepare_send_phase1(
        self,
        caller: PrincipalCtx,
        edge: RoutingEdge,
        target_addr: str,
        *,
        control_prio: bool,
        artifact_blobs: Sequence[bytes],
    ) -> tuple[str, int, StagingReservation | None]:
        live_edge, dst_sb = self._verify_grant_live_under_fence(
            edge.edge_id, edge.grant_generation, target_addr
        )
        self._validate_caller_incarnation_and_lease(caller, live_edge)
        if not control_prio:
            self._check_rate_limit(live_edge.edge_id, live_edge.rate_limit_rpm)
        reservation = self.spool.reserve(live_edge.edge_id, artifact_blobs) if artifact_blobs else None
        return dst_sb.incarnation_id, live_edge.grant_generation, reservation

    def send(
        self,
        caller: PrincipalCtx,
        *,
        target: str,
        thread_id: str = _THREAD_MAIN,
        msg_kind: str = _KIND_PROMPT,
        body_text: str,
        in_reply_to: str | None = None,
        artifact_blobs: Sequence[bytes] = (),
        artifact_refs: Sequence[ArtifactRef] = (),
    ) -> dict[str, Any]:
        self._enter_fg_op()
        try:
            return self._send_tracked(
                caller,
                target=target,
                thread_id=thread_id,
                msg_kind=msg_kind,
                body_text=body_text,
                in_reply_to=in_reply_to,
                artifact_blobs=artifact_blobs,
                artifact_refs=artifact_refs,
            )
        finally:
            self._exit_fg_op()

    def _send_tracked(
        self,
        caller: PrincipalCtx,
        *,
        target: str,
        thread_id: str = _THREAD_MAIN,
        msg_kind: str = _KIND_PROMPT,
        body_text: str,
        in_reply_to: str | None = None,
        artifact_blobs: Sequence[bytes] = (),
        artifact_refs: Sequence[ArtifactRef] = (),
    ) -> dict[str, Any]:
        with self._meta_lock:
            start_rec_gen = self._recovery_generation
        self._require_not_degraded()
        self._verify_caller_live(caller)
        addr = parse_local_target(target)
        clean_thread = validate_thread_id(thread_id)
        clean_kind = validate_msg_kind(msg_kind)
        clean_body = canonicalize_body_text(body_text)
        validated_refs = self._validate_artifact_inputs(artifact_blobs, artifact_refs)
        sender_id = caller.canonical_sender
        control_prio = is_control_priority(caller.trust_class, clean_kind)

        edge = self._registry.find_active_edge(sender_id, addr.canonical, clean_thread, clean_kind)
        if edge is None:
            self._registry.append_audit(
                sender_id, "send", addr.canonical, "denied", {"reason": _ERR_NO_ACTIVE_EDGE}
            )
            raise CoordAuthError(_ERR_NO_ACTIVE_EDGE)

        fence = self._get_grant_fence(edge.edge_id)
        reservation: StagingReservation | None = None
        try:
            with fence:
                dst_incarnation, expected_gen, reservation = self._prepare_send_phase1(
                    caller,
                    edge,
                    addr.canonical,
                    control_prio=control_prio,
                    artifact_blobs=artifact_blobs,
                )

            staged_refs: tuple[ArtifactRef, ...] = (
                self.spool.stage_blobs(reservation, artifact_blobs)
                if reservation is not None
                else ()
            )
            all_refs = validated_refs + staged_refs

            with fence:
                with self._meta_lock:
                    if self._recovery_generation != start_rec_gen:
                        raise CoordPolicyError(_ERR_DEGRADED)
                live_edge, _dst_sb = self._verify_grant_live_under_fence(
                    edge.edge_id,
                    expected_gen,
                    addr.canonical,
                    expected_dst_incarnation=dst_incarnation,
                )
                self._validate_caller_incarnation_and_lease(caller, live_edge)
                if not control_prio:
                    self._check_rate_limit(live_edge.edge_id, live_edge.rate_limit_rpm)
                seq, persisted = self._build_and_enqueue_envelope(
                    caller,
                    live_edge,
                    target_addr=addr.canonical,
                    thread_id=clean_thread,
                    msg_kind=clean_kind,
                    clean_body=clean_body,
                    dst_incarnation=dst_incarnation,
                    in_reply_to=in_reply_to,
                    all_refs=all_refs,
                )
                if reservation is not None:
                    self._publish_or_rollback_outbox(reservation, dst_incarnation, persisted.msg_id)
                if not control_prio:
                    self._record_rate_hit(live_edge.edge_id)
        finally:
            if reservation is not None and not reservation.finalized:
                self.spool.abort_reservation(reservation)

        self._notify_waiters()
        self.dispatcher.wake()
        return {
            "msg_id": persisted.msg_id,
            "seq": seq,
            "edge_id": persisted.edge_id,
            "edge_turn_seq": persisted.edge_turn_seq,
        }

    def _publish_or_rollback_outbox(
        self, reservation: StagingReservation, dst_incarnation: str, msg_id: str
    ) -> None:
        try:
            self.spool.publish(reservation, dst_incarnation)
        except Exception:
            try:
                self._registry.cancel_outbox_row(msg_id, reason="artifact_publish_failed")
            except Exception:
                self._mark_degraded("artifact_publish_rollback_failed")
            raise

    def _classify_row_liveness_under_fence(
        self,
        edge_id: str,
        grant_gen: int,
        dst_addr: str,
        dst_incarnation: str,
        *,
        src_incarnation: str | None = None,
    ) -> str:
        """Return 'live', 'fenced' (confirmed stale pin), or 'unavailable' (transient/shutdown)."""
        try:
            self._check_grant_pins_live_under_fence(
                edge_id,
                grant_gen,
                dst_addr,
                expected_dst_incarnation=dst_incarnation,
                expected_src_incarnation=src_incarnation,
            )
            return "live"
        except (RevokedError, IncarnationMismatchError):
            return "fenced"
        except CoordPolicyError as exc:
            if str(exc) == _ERR_SANDBOX_NOT_FOUND:
                return "fenced"
            return _STATUS_UNAVAILABLE
        except Exception:
            return _STATUS_UNAVAILABLE

    def _resolve_row_dst_addr(
        self, row: dict[str, Any], env: Envelope | None, edge: RoutingEdge | None
    ) -> str | None:
        raw_dst = row.get("dst_addr")
        if isinstance(raw_dst, str) and raw_dst:
            return raw_dst
        if env is not None:
            return env.dst_addr
        if edge is not None:
            return edge.dst_addr
        return None

    def _build_turn_dispatch(
        self, env: Envelope, edge: RoutingEdge | None, grant_gen: int
    ) -> TurnDispatch:
        return TurnDispatch(
            msg_id=env.msg_id,
            sandbox_addr=env.dst_addr,
            incarnation_id=env.dst_incarnation,
            thread_id=env.dst_thread_id,
            trust_class=env.trust_class,
            msg_kind=env.msg_kind,
            wire_text=env.body_text,
            body_sha256=env.body_sha256,
            artifact_refs=env.artifact_refs,
            edge_id=env.edge_id,
            lease_request_id=edge.lease_request_id if edge is not None else None,
            grant_generation=grant_gen,
        )

    def _collect_turn_req_ids(
        self, dst_addr: str, edge: RoutingEdge | None
    ) -> frozenset[str]:
        req_ids: set[str] = set()
        dst_sb = self._registry.get_sandbox(dst_addr)
        if dst_sb is not None and dst_sb.controller_request_id is not None:
            req_ids.add(dst_sb.controller_request_id)
        if edge is not None:
            if edge.lease_request_id is not None:
                req_ids.add(edge.lease_request_id)
            src_addr = _sandbox_addr_from_actor(edge.src_actor)
            if src_addr is not None:
                src_sb = self._registry.get_sandbox(src_addr)
                if src_sb is not None and src_sb.controller_request_id is not None:
                    req_ids.add(src_sb.controller_request_id)
        return frozenset(r for r in req_ids if not r.startswith(_EPHEMERAL_LEASE_PREFIX))

    def _prepare_turn_monitors(self, req_ids: frozenset[str]) -> None:
        if not req_ids:
            return
        if not callable(getattr(self._transport, "abort_stream", None)):
            raise CoordPolicyError(_ERR_MISSING_STREAM_ABORT)
        for req_id in sorted(req_ids):
            self._ensure_controller_monitor(req_id)

    def _dispatch_single_row(self, row: dict[str, Any], *, async_stream: bool) -> bool:
        msg_id = str(row["msg_id"])
        edge_id = str(row["edge_id"])
        grant_gen = int(row["grant_generation"])
        dst_inc = str(row["dst_incarnation"])
        raw_src_inc = row.get("src_incarnation")
        src_inc = str(raw_src_inc) if isinstance(raw_src_inc, str) and raw_src_inc else None

        fence = self._get_grant_fence(edge_id)
        stream_task: Callable[[], None] | None = None
        immediate_abort: tuple[str, str] | None = None
        with fence:
            if self._is_closed() or self.is_degraded:
                return False
            env = self._registry.get_envelope(msg_id)
            edge = self._registry.get_edge(edge_id)
            dst_addr = self._resolve_row_dst_addr(row, env, edge)
            if dst_addr is None or env is None:
                self._registry.cancel_outbox_row(msg_id, reason="envelope_missing")
                return False
            liveness = self._classify_row_liveness_under_fence(
                edge_id, grant_gen, dst_addr, dst_inc, src_incarnation=src_inc
            )
            if liveness == "fenced":
                self._registry.cancel_outbox_row(msg_id, reason="grant_or_incarnation_fenced")
                return False
            if liveness != "live":
                return False
            req_ids = self._collect_turn_req_ids(dst_addr, edge)
            try:
                self._prepare_turn_monitors(req_ids)
            except _AuthorityUnavailableError:
                return False
            with self._meta_lock:
                if req_ids & self._unavailable_requests:
                    return False
            if not self._registry.mark_outbox_dispatch_started(
                msg_id, edge_id=edge_id, grant_generation=grant_gen, dst_incarnation=dst_inc
            ):
                return False
            inflight = _InflightAuth(
                msg_id=env.msg_id,
                edge_id=edge_id,
                grant_generation=grant_gen,
                dst_addr=env.dst_addr,
                dst_incarnation=env.dst_incarnation,
                req_ids=req_ids,
            )
            with self._meta_lock:
                if req_ids & self._unavailable_requests:
                    outage_before_handoff = True
                else:
                    outage_before_handoff = False
                    self._inflight_handoffs[env.msg_id] = inflight
            if outage_before_handoff:
                self._registry.return_outbox_to_pending(env.msg_id, detail=_ERR_CTRL_UNAVAILABLE)
                return False
            turn = self._build_turn_dispatch(env, edge, grant_gen)
            try:
                result = self._transport.dispatch_turn(turn)
            except Exception as exc:
                with self._meta_lock:
                    self._inflight_handoffs.pop(env.msg_id, None)
                self._registry.mark_outbox_uncertain(env.msg_id, detail=f"dispatch_exception:{exc}")
                return True
            stream_task, immediate_abort = self._handle_dispatch_result_locked(
                env, result, edge_id, grant_gen, inflight
            )

        self._apply_immediate_stream_abort(env, immediate_abort)
        self._run_stream_task(stream_task, async_stream=async_stream)
        return True

    def _apply_immediate_stream_abort(
        self, env: Envelope, immediate_abort: tuple[str, str] | None
    ) -> None:
        if immediate_abort is None:
            return
        sid, reason = immediate_abort
        if self._try_abort_stream(sid, reason=reason):
            self._clear_unpersisted_stream_if_aborted(sid)
            return
        if reason == _REASON_HANDOFF_PERSIST_FAILED and not callable(
            getattr(self._transport, "abort_stream", None)
        ):
            try:
                if self._transport.abort_incarnation(
                    env.dst_addr, env.dst_incarnation, reason=reason
                ):
                    self._clear_unpersisted_stream_if_aborted(sid)
            except Exception:
                pass

    def _run_stream_task(
        self, stream_task: Callable[[], None] | None, *, async_stream: bool
    ) -> None:
        if stream_task is None:
            return
        if async_stream:
            self.dispatcher.spawn_stream(stream_task)
        else:
            stream_task()

    def _check_immediate_stream_abort_locked(
        self, inflight: _InflightAuth, stream_id: str
    ) -> str | None:
        if (
            inflight.revoked_observed
            or (inflight.edge_id, inflight.grant_generation) in self._fenced_generations
            or (inflight.dst_addr, inflight.dst_incarnation) in self._fenced_targets
            or inflight.dst_addr in self._fenced_addrs
        ):
            self._stream_abort_reasons.setdefault(stream_id, _STATUS_REVOKED)
            return self._stream_abort_reasons[stream_id]
        if inflight.outage_observed or (inflight.req_ids & self._unavailable_requests):
            self._stream_abort_reasons.setdefault(stream_id, _ERR_CTRL_UNAVAILABLE)
            return self._stream_abort_reasons[stream_id]
        return None

    def _handle_dispatch_result_locked(
        self,
        env: Envelope,
        result: Any,
        edge_id: str,
        grant_gen: int,
        inflight: _InflightAuth,
    ) -> tuple[Callable[[], None] | None, tuple[str, str] | None]:
        if result.outcome is DispatchOutcome.ZERO_BYTES_SENT:
            with self._meta_lock:
                self._inflight_handoffs.pop(env.msg_id, None)
            liveness = self._classify_row_liveness_under_fence(
                edge_id,
                grant_gen,
                env.dst_addr,
                env.dst_incarnation,
                src_incarnation=env.src_incarnation,
            )
            if liveness != "fenced":
                self._registry.return_outbox_to_pending(env.msg_id, detail=result.detail)
            else:
                cancel_reason = result.detail or _STATUS_REVOKED
                try:
                    self._registry.cancel_outbox_row(env.msg_id, reason=cancel_reason)
                except Exception:
                    pass
            return None, None

        if result.outcome is DispatchOutcome.UNCERTAIN:
            with self._meta_lock:
                self._inflight_handoffs.pop(env.msg_id, None)
            self._registry.mark_outbox_uncertain(
                env.msg_id, detail=result.detail or "uncertain_handoff"
            )
            return None, None

        stream_id = result.stream_id
        if not isinstance(stream_id, str) or not stream_id:
            with self._meta_lock:
                self._inflight_handoffs.pop(env.msg_id, None)
            self._registry.mark_outbox_uncertain(env.msg_id, detail="missing_stream_id")
            return None, None

        with self._meta_lock:
            self._inflight_handoffs.pop(env.msg_id, None)
            self._stream_authorities[stream_id] = _StreamAuth(
                msg_id=env.msg_id,
                edge_id=edge_id,
                grant_generation=grant_gen,
                dst_addr=env.dst_addr,
                dst_incarnation=env.dst_incarnation,
                req_ids=inflight.req_ids,
            )
            abort_reason = self._check_immediate_stream_abort_locked(inflight, stream_id)

        try:
            self._registry.mark_outbox_handed_off(env.msg_id, stream_id=stream_id)
        except Exception as exc:
            with self._meta_lock:
                self._stream_abort_reasons[stream_id] = _REASON_HANDOFF_PERSIST_FAILED
            try:
                self._registry.mark_outbox_uncertain(
                    env.msg_id, detail=f"{_REASON_HANDOFF_PERSIST_FAILED}:{exc}"
                )
            except Exception:
                self._mark_degraded(_REASON_HANDOFF_PERSIST_FAILED)
            return None, (stream_id, _REASON_HANDOFF_PERSIST_FAILED)

        def _consume() -> None:
            self._consume_stream(env, stream_id)

        immediate = (stream_id, abort_reason) if abort_reason is not None else None
        return _consume, immediate

    @staticmethod
    def _validate_untrusted_event(
        raw_ev: Any,
        *,
        expected_sandbox: str,
        expected_incarnation: str,
        expected_thread: str,
        allow_revoked_event: bool = True,
    ) -> StreamEvent | None:
        if not isinstance(raw_ev, StreamEvent) or raw_ev.event_type not in STREAM_EVENT_TYPES:
            return None
        if raw_ev.event_type == _STATUS_REVOKED and not allow_revoked_event:
            return None
        if (
            raw_ev.sandbox_addr != expected_sandbox
            or raw_ev.incarnation_id != expected_incarnation
            or raw_ev.thread_id != expected_thread
        ):
            return None
        try:
            validate_thread_id(raw_ev.thread_id)
            validate_stream_text(raw_ev.text)
            if raw_ev.file_path is not None:
                validate_sandbox_rel_path(raw_ev.file_path)
            encoded_detail = json.dumps(raw_ev.detail, separators=(",", ":")).encode("utf-8")
        except (CoordValidationError, TypeError, ValueError):
            return None
        if len(encoded_detail) > MAX_STREAM_EVENT_BYTES:
            return None
        return raw_ev

    def _finalize_stream_outbox(
        self, msg_id: str, *, saw_completed: bool, abort_reason: str | None
    ) -> None:
        try:
            if saw_completed and abort_reason is None:
                self._registry.mark_outbox_completed(msg_id)
                return
            mark_aborted = getattr(self._registry, "mark_outbox_aborted", None)
            if callable(mark_aborted):
                mark_aborted(msg_id, reason=abort_reason or "stream_incomplete")
        except Exception:
            pass

    def _get_stream_abort_reason(self, stream_id: str) -> str | None:
        with self._meta_lock:
            return self._stream_abort_reasons.get(stream_id)

    def _process_single_stream_event(
        self, env: Envelope, stream_id: str, raw_ev: Any
    ) -> tuple[bool, str | None]:
        fence = self._get_grant_fence(env.edge_id)
        with fence:
            abort_reason = self._get_stream_abort_reason(stream_id)
            if abort_reason is not None:
                return False, abort_reason
            target_fenced = self._is_target_fenced(env.dst_addr, env.dst_incarnation)
            if target_fenced and (
                not isinstance(raw_ev, StreamEvent) or raw_ev.event_type != _STATUS_REVOKED
            ):
                return False, _STATUS_REVOKED
            valid_ev = self._validate_untrusted_event(
                raw_ev,
                expected_sandbox=env.dst_addr,
                expected_incarnation=env.dst_incarnation,
                expected_thread=env.dst_thread_id,
                allow_revoked_event=target_fenced,
            )
            if valid_ev is None:
                self._registry.append_audit(
                    env.dst_addr,
                    "stream_event_rejected",
                    env.msg_id,
                    "dropped",
                    {"stream_id": stream_id},
                )
                return False, None
            self._registry.record_stream_event(valid_ev, dispatch_msg_id=env.msg_id)
        self._notify_waiters()
        if valid_ev.event_type == "turn_completed":
            return True, None
        if valid_ev.event_type in ("turn_error", _STATUS_REVOKED):
            return False, valid_ev.event_type
        return False, None

    def _record_stream_cap_event(self, env: Envelope, stream_id: str) -> str:
        fence = self._get_grant_fence(env.edge_id)
        with fence:
            abort_reason = self._get_stream_abort_reason(stream_id)
            if abort_reason is not None:
                return abort_reason
            if self._is_target_fenced(env.dst_addr, env.dst_incarnation):
                return _STATUS_REVOKED
            cap_reason = "stream_event_cap_exceeded"
            cap_ev = StreamEvent(
                event_type="turn_error",
                sandbox_addr=env.dst_addr,
                incarnation_id=env.dst_incarnation,
                thread_id=env.dst_thread_id,
                message_id=env.msg_id,
                text=cap_reason,
                created_at=time.time(),
            )
            self._registry.record_stream_event(cap_ev, dispatch_msg_id=env.msg_id)
        self._notify_waiters()
        return cap_reason

    def _consume_stream(self, env: Envelope, stream_id: str) -> None:
        total_seen = 0
        saw_completed = False
        abort_reason: str | None = None
        try:
            for raw_ev in self._transport.stream_events(stream_id):
                pre_abort = self._get_stream_abort_reason(stream_id)
                if pre_abort is not None:
                    abort_reason = pre_abort
                    break
                if total_seen >= MAX_TURN_STREAM_EVENTS:
                    abort_reason = self._record_stream_cap_event(env, stream_id)
                    break
                total_seen += 1
                done, err_reason = self._process_single_stream_event(env, stream_id, raw_ev)
                if done:
                    saw_completed = True
                if err_reason is not None:
                    abort_reason = err_reason
                    break
        except Exception as exc:
            abort_reason = "stream_exception"
            self._registry.append_audit(
                env.dst_addr,
                "stream_error",
                env.msg_id,
                "error",
                {"detail": str(exc)},
            )
        finally:
            with self._meta_lock:
                self._stream_authorities.pop(stream_id, None)
                fenced_reason = self._stream_abort_reasons.pop(stream_id, None)
                if abort_reason is None and fenced_reason is not None:
                    abort_reason = fenced_reason
            self._finalize_stream_outbox(
                env.msg_id, saw_completed=saw_completed, abort_reason=abort_reason
            )
            self._notify_waiters()

    def dispatch_once(self, *, async_stream: bool = False) -> int:
        is_pump = threading.current_thread() is self.dispatcher._thread
        if not is_pump:
            try:
                self._enter_fg_op()
            except CoordPolicyError:
                return 0
        try:
            if self._is_closed() or self.is_degraded:
                return 0
            rows = self._registry.list_outbox(statuses=(_STATUS_PENDING,))
            if not rows:
                return 0
            prioritized = sorted(
                rows,
                key=lambda r: (-int(r.get("priority", 0)), int(r.get("seq", 0))),
            )
            processed = 0
            for row in prioritized:
                if self._dispatch_single_row(row, async_stream=async_stream):
                    processed += 1
            return processed
        finally:
            if not is_pump:
                self._exit_fg_op()

    def _notify_waiters(self) -> None:
        with self._wait_cond:
            self._wait_gen += 1
            self._wait_cond.notify_all()

    def _edge_is_live_for_read(self, edge: RoutingEdge, target_addr: str) -> bool:
        with self._meta_lock:
            gen_fenced = (edge.edge_id, edge.grant_generation) in self._fenced_generations
        if gen_fenced or self._registry.is_grant_tombstoned(edge.edge_id, edge.grant_generation):
            return False
        try:
            self._require_dst_sandbox_live(target_addr, edge.lease_request_id)
        except RevokedError:
            return False
        return True

    def _authorize_target_read(
        self, caller: PrincipalCtx, target_addr: str
    ) -> frozenset[str] | None:
        self._require_operational(allow_operator_diagnostic=True, caller=caller)
        self._verify_caller_live(caller)
        if caller.role is CoordRole.OPERATOR:
            return None
        if caller.role is CoordRole.ORCHESTRATOR:
            if caller.sandbox_addr is None or self._is_in_subtree(caller.sandbox_addr, target_addr):
                return None
            raise CoordAuthError("orchestrator_target_outside_subtree")
        if caller.sandbox_addr == target_addr:
            return None
        edges = self._registry.list_edges(
            src_actor=caller.canonical_sender, dst_addr=target_addr, active_only=True
        )
        candidates = [
            e
            for e in edges
            if e.src_incarnation is None or e.src_incarnation == caller.incarnation_id
        ]
        if not candidates:
            raise CoordAuthError(_ERR_NO_ACTIVE_EDGE)
        allowed: set[str] = set()
        for edge in candidates:
            if self._edge_is_live_for_read(edge, target_addr):
                allowed.update(edge.allowed_threads)
        if not allowed:
            raise RevokedError(_ERR_EDGE_REVOKED)
        return frozenset(allowed)

    def status(self, caller: PrincipalCtx, *, target: str | None = None) -> dict[str, Any]:
        self._require_operational(allow_operator_diagnostic=True, caller=caller)
        self._verify_caller_live(caller)
        if target is not None:
            addr = parse_local_target(target)
            self._authorize_target_read(caller, addr.canonical)
            sandbox = self._registry.get_sandbox(addr.canonical)
            if sandbox is None:
                raise CoordPolicyError(_ERR_SANDBOX_NOT_FOUND)
            transport_st = self._transport.status(sandbox.sandbox_addr, sandbox.incarnation_id)
            edges = self._registry.list_edges(dst_addr=addr.canonical, active_only=True)
            return {
                "sandbox": asdict(sandbox),
                "worker_status": asdict(transport_st),
                "active_edges": len(edges),
                "degraded": self.is_degraded,
            }

        self._require_admin_role(caller, "status_all")
        sandboxes = self._registry.list_sandboxes()
        if caller.role is CoordRole.ORCHESTRATOR and caller.sandbox_addr is not None:
            allowed_addrs = self._subtree_addrs(caller.sandbox_addr)
            sandboxes = [sb for sb in sandboxes if sb.sandbox_addr in allowed_addrs]
        return {
            "sandboxes": [asdict(sb) for sb in sandboxes],
            "count": len(sandboxes),
            "degraded": self.is_degraded,
        }

    def _build_wait_scope(
        self,
        caller: PrincipalCtx,
        target_addrs: tuple[str, ...],
        allowed_threads_map: dict[str, frozenset[str]],
    ) -> tuple[dict[str, frozenset[str]] | None, dict[str, str] | None, frozenset[str]]:
        if caller.role in (CoordRole.OPERATOR, CoordRole.ORCHESTRATOR):
            return None, None, frozenset()
        req_incs: dict[str, str] = {}
        for addr in target_addrs:
            sb = self._registry.get_sandbox(addr)
            if sb is not None:
                req_incs[addr] = sb.incarnation_id
        threads_filter = allowed_threads_map if allowed_threads_map else None
        excluded = (
            frozenset({TrustClass.OPERATOR_DIRECTIVE.value})
            if any(addr != caller.sandbox_addr for addr in target_addrs)
            else frozenset()
        )
        return threads_filter, req_incs, excluded

    def _list_scoped_wait_events(
        self,
        target_addrs: Sequence[str],
        since_seq: int,
        allowed_threads: dict[str, frozenset[str]] | None,
        req_incs: dict[str, str] | None,
        exclude_trust: frozenset[str],
    ) -> list[dict[str, Any]]:
        if allowed_threads is None and req_incs is None and not exclude_trust:
            return self._registry.list_events_since(target_addrs, since_seq)
        return self._registry.list_events_since(
            target_addrs,
            since_seq,
            allowed_threads_by_sandbox=allowed_threads,
            required_incarnations=req_incs,
            exclude_trust_classes=exclude_trust,
        )

    def wait(
        self,
        caller: PrincipalCtx,
        *,
        targets: Sequence[str],
        since_seq: int = 0,
        timeout_s: float = 5.0,
    ) -> dict[str, Any]:
        if not targets:
            raise CoordValidationError("targets must be non-empty")
        self._enter_fg_op()
        try:
            return self._wait_tracked(
                caller, targets=targets, since_seq=since_seq, timeout_s=timeout_s
            )
        finally:
            self._exit_fg_op()

    def _wait_tracked(
        self,
        caller: PrincipalCtx,
        *,
        targets: Sequence[str],
        since_seq: int = 0,
        timeout_s: float = 5.0,
    ) -> dict[str, Any]:
        target_addrs = tuple(dict.fromkeys(parse_local_target(t).canonical for t in targets))
        allowed_threads_map: dict[str, frozenset[str]] = {}
        for addr in target_addrs:
            allowed = self._authorize_target_read(caller, addr)
            if allowed is not None:
                allowed_threads_map[addr] = allowed

        token = self.wait_graph.enter(caller.canonical_sender, target_addrs)
        waiter = _WaiterState(
            caller_actor=caller.canonical_sender, targets=frozenset(target_addrs)
        )
        try:
            threads_filter, req_incs, exclude_trust = self._build_wait_scope(
                caller, target_addrs, allowed_threads_map
            )
            deadline = time.monotonic() + timeout_s
            with self._wait_cond:
                self._waiters.add(waiter)
            try:
                return self._wait_loop(
                    waiter,
                    caller,
                    target_addrs,
                    since_seq,
                    deadline,
                    threads_filter,
                    req_incs,
                    exclude_trust,
                )
            finally:
                with self._wait_cond:
                    self._waiters.discard(waiter)
        finally:
            self.wait_graph.exit(caller.canonical_sender, token)

    def _assert_single_target_not_revoked(self, addr: str) -> None:
        with self._meta_lock:
            fenced = addr in self._fenced_addrs
        if fenced:
            raise RevokedError(_ERR_EDGE_REVOKED)
        sb = self._registry.get_sandbox(addr)
        if sb is None or sb.status == _STATUS_REVOKED:
            raise RevokedError(_ERR_EDGE_REVOKED)
        with self._meta_lock:
            target_fenced = (addr, sb.incarnation_id) in self._fenced_targets
        if target_fenced:
            raise RevokedError(_ERR_EDGE_REVOKED)
        self._require_authority_status_active(
            self._check_lease_status(addr, controller_request_id=sb.controller_request_id),
            _ERR_SANDBOX_REVOKED,
        )

    def _assert_targets_not_revoked(
        self, caller_actor: str, target_addrs: Sequence[str]
    ) -> None:
        caller_sb = _sandbox_addr_from_actor(caller_actor)
        with self._meta_lock:
            caller_fenced = caller_actor in self._fenced_addrs or (
                caller_sb is not None and caller_sb in self._fenced_addrs
            )
        if caller_fenced:
            raise RevokedError(_ERR_EDGE_REVOKED)
        for addr in target_addrs:
            self._assert_single_target_not_revoked(addr)

    def _reauthorize_wait_targets(
        self, caller: PrincipalCtx, target_addrs: Sequence[str]
    ) -> dict[str, frozenset[str]]:
        allowed_map: dict[str, frozenset[str]] = {}
        for addr in target_addrs:
            try:
                allowed = self._authorize_target_read(caller, addr)
            except CoordAuthError as exc:
                raise RevokedError(_ERR_EDGE_REVOKED) from exc
            if allowed is not None:
                allowed_map[addr] = allowed
        return allowed_map

    def _wait_loop(
        self,
        waiter: _WaiterState,
        caller: PrincipalCtx,
        target_addrs: Sequence[str],
        since_seq: int,
        deadline: float,
        threads_filter: dict[str, frozenset[str]] | None,
        req_incs: dict[str, str] | None,
        exclude_trust: frozenset[str],
    ) -> dict[str, Any]:
        while True:
            with self._wait_cond:
                if waiter.revoked:
                    raise RevokedError(_ERR_EDGE_REVOKED)
                seen_gen = self._wait_gen
            self._require_operational(allow_operator_diagnostic=True, caller=caller)
            self._assert_targets_not_revoked(caller.canonical_sender, target_addrs)
            live_threads = self._reauthorize_wait_targets(caller, target_addrs)
            eff_threads = live_threads if threads_filter is not None else None
            events = self._list_scoped_wait_events(
                target_addrs, since_seq, eff_threads, req_incs, exclude_trust
            )
            if events:
                return {"events": events, "last_seq": events[-1]["seq"], "timed_out": False}
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {"events": [], "last_seq": since_seq, "timed_out": True}
            with self._wait_cond:
                if waiter.revoked:
                    raise RevokedError(_ERR_EDGE_REVOKED)
                if self._wait_gen != seen_gen:
                    continue
                self._wait_cond.wait(timeout=remaining)

    def _fence_target_in_memory(
        self,
        target_addr: str,
        incarnation_id: str | None,
        edges: Sequence[RoutingEdge],
    ) -> tuple[list[tuple[str, str]], list[str], list[_WaiterState], BrokerLease | None]:
        edge_ids = sorted(e.edge_id for e in edges)
        fences = [self._get_grant_fence(eid) for eid in edge_ids]
        orch_actor = f"{_ORCH_ACTOR_PREFIX}{target_addr}"
        for fence in fences:
            fence.acquire()
        try:
            detached_incarnations, outbound_sids, lease = self._detach_meta_for_target(
                target_addr, incarnation_id, edges
            )
            with self._wait_cond:
                detached_waiters = [
                    w
                    for w in self._waiters
                    if target_addr in w.targets or w.caller_actor in (target_addr, orch_actor)
                ]
                for w in detached_waiters:
                    w.revoked = True
                self._wait_gen += 1
            return detached_incarnations, outbound_sids, detached_waiters, lease
        finally:
            for fence in reversed(fences):
                fence.release()

    def _detach_meta_for_target(
        self,
        target_addr: str,
        incarnation_id: str | None,
        edges: Sequence[RoutingEdge],
    ) -> tuple[list[tuple[str, str]], list[str], BrokerLease | None]:
        edge_id_set = {edge.edge_id for edge in edges}
        with self._meta_lock:
            self._fenced_addrs.add(target_addr)
            inc_set: set[str] = set(self._known_incarnations.get(target_addr, ()))
            if incarnation_id is not None:
                inc_set.add(incarnation_id)
            outbound_sids: list[str] = []
            for sid, auth in self._stream_authorities.items():
                if auth.dst_addr == target_addr:
                    inc_set.add(auth.dst_incarnation)
                elif auth.edge_id in edge_id_set:
                    self._stream_abort_reasons.setdefault(sid, _STATUS_REVOKED)
                    outbound_sids.append(sid)
            for inc_id in inc_set:
                self._fenced_targets.add((target_addr, inc_id))
            for edge in edges:
                self._fenced_generations.add((edge.edge_id, edge.grant_generation))
            lease = self._leases.pop(target_addr, None)
            cb = self._lease_callbacks.pop(target_addr, None)
        if lease is not None and cb is not None:
            lease.remove_revoke_callback(cb)
        return [(target_addr, inc_id) for inc_id in sorted(inc_set)], outbound_sids, lease

    def _teardown_detached(
        self,
        detached_incarnations: list[tuple[str, str]],
        outbound_sids: list[str],
        detached_waiters: list[_WaiterState],
        lease: BrokerLease | None,
        reason: str,
    ) -> bool:
        aborted = False
        for sb_addr, inc_id in detached_incarnations:
            try:
                if self._transport.abort_incarnation(sb_addr, inc_id, reason=reason):
                    aborted = True
            except Exception:
                pass
        for sid in outbound_sids:
            if self._try_abort_stream(sid, reason=reason):
                aborted = True
        if detached_waiters:
            try:
                self._notify_waiters()
            except Exception:
                pass
        if lease is not None:
            try:
                lease.revoke()
            except Exception:
                pass
        return aborted

    def _lookup_revoke_metadata(
        self, addr: str
    ) -> tuple[SandboxRecord | None, list[RoutingEdge], bool]:
        try:
            sandbox = self._registry.get_sandbox(addr)
            dst_edges = self._registry.list_edges(dst_addr=addr, active_only=False)
            src_edges = self._registry.list_edges(src_actor=addr, active_only=False)
            orch_edges = self._registry.list_edges(
                src_actor=f"{_ORCH_ACTOR_PREFIX}{addr}", active_only=False
            )
            edges = list({e.edge_id: e for e in (*dst_edges, *src_edges, *orch_edges)}.values())
            return sandbox, edges, False
        except Exception:
            return None, [], True

    def revoke(
        self,
        caller: PrincipalCtx,
        *,
        target: str,
        reason: str = "operator_revoked",
    ) -> RevocationStatus:
        self._enter_fg_op()
        try:
            with self._register_lock:
                if self._is_closed():
                    raise CoordPolicyError(_ERR_HUB_CLOSED)
                return self._revoke_unlocked(caller, target=target, reason=reason)
        finally:
            self._exit_fg_op()

    def _revoke_unlocked(
        self,
        caller: PrincipalCtx,
        *,
        target: str,
        reason: str = "operator_revoked",
    ) -> RevocationStatus:
        start_ts = time.monotonic()
        self._require_admin_role(caller, "revoke")
        self._verify_caller_live(caller)
        clean_reason = validate_reason_text(reason, "reason")
        addr = parse_local_target(target).canonical
        if (
            caller.role is CoordRole.ORCHESTRATOR
            and caller.sandbox_addr is not None
            and not self._is_in_subtree(caller.sandbox_addr, addr)
        ):
            raise CoordAuthError("orchestrator_cannot_revoke_outside_subtree")

        sandbox, edges, lookup_failed = self._lookup_revoke_metadata(addr)
        if not lookup_failed and sandbox is None:
            raise CoordPolicyError(_ERR_SANDBOX_NOT_FOUND)
        incarnation_id = sandbox.incarnation_id if sandbox is not None else None

        # Step 1: Fence target & grant generations in memory and detach streams + waiters.
        detached_incarnations, outbound_sids, detached_waiters, lease = self._fence_target_in_memory(
            addr, incarnation_id, edges
        )

        # Step 2: OUTSIDE DB, nonblocking, fault-isolated teardown of streams, waiters, lease.
        aborted = self._teardown_detached(
            detached_incarnations, outbound_sids, detached_waiters, lease, clean_reason
        )

        if lookup_failed:
            self._mark_degraded("revoke_metadata_lookup_failed")
            raise CoordPolicyError(_ERR_REVOKED_UNCONFIRMED)

        # Step 3: Persist tombstone & cancel pending outbox; degrade store on failure.
        try:
            revoked_edge_ids = self._registry.revoke_grant_and_cancel_outbox(
                target_addr=addr, reason=clean_reason
            )
            self._registry.update_sandbox_status(
                addr, _STATUS_REVOKED, incarnation_id=incarnation_id
            )
            self._registry.append_audit(
                caller.canonical_sender,
                "revoke",
                addr,
                _OUTCOME_OK,
                {"reason": clean_reason, "revoked_edges": len(revoked_edge_ids)},
            )
        except Exception as exc:
            self._mark_degraded("revoke_persistence_failed")
            raise CoordPolicyError(_ERR_REVOKED_UNCONFIRMED) from exc

        elapsed_ms = (time.monotonic() - start_ts) * 1000.0
        return RevocationStatus(
            target_addr=addr,
            incarnation_id=incarnation_id or "",
            revoked_edges=len(revoked_edge_ids),
            aborted_streams=aborted,
            elapsed_ms=elapsed_ms,
        )

    def projection(self, caller: PrincipalCtx) -> dict[str, Any]:
        self._require_operational(allow_operator_diagnostic=True, caller=caller)
        self._require_admin_role(caller, "projection")
        self._verify_caller_live(caller)
        full = self._registry.get_projection()
        if caller.role is CoordRole.OPERATOR or caller.sandbox_addr is None:
            return full
        allowed = self._subtree_addrs(caller.sandbox_addr)
        filtered_projects: list[dict[str, Any]] = []
        for proj in full.get("projects", []):
            sbs = [sb for sb in proj.get("sandboxes", []) if sb.get("sandbox_addr") in allowed]
            if sbs:
                filtered_projects.append({**proj, "sandboxes": sbs})
        return {"projects": filtered_projects}

    def read_artifact(
        self, caller: PrincipalCtx, *, sandbox_addr: str, ref: ArtifactRef
    ) -> bytes:
        self._require_not_degraded()
        self._verify_caller_live(caller)
        addr = parse_local_target(sandbox_addr).canonical
        if caller.role is not CoordRole.OPERATOR and caller.sandbox_addr != addr:
            raise CoordAuthError("artifact_read_restricted_to_recipient_or_operator")
        with self._meta_lock:
            if addr in self._fenced_addrs:
                raise RevokedError(_ERR_SANDBOX_REVOKED)
        sandbox = self._registry.get_sandbox(addr)
        if sandbox is None:
            raise CoordPolicyError(_ERR_SANDBOX_NOT_FOUND)
        if sandbox.status == _STATUS_REVOKED:
            raise RevokedError(_ERR_SANDBOX_REVOKED)
        if caller.role is not CoordRole.OPERATOR and caller.incarnation_id != sandbox.incarnation_id:
            raise IncarnationMismatchError("Caller incarnation mismatch")
        with self._meta_lock:
            if (addr, sandbox.incarnation_id) in self._fenced_targets:
                raise RevokedError(_ERR_SANDBOX_REVOKED)
        self._require_authority_status_active(
            self._check_lease_status(addr, controller_request_id=sandbox.controller_request_id),
            _ERR_SANDBOX_REVOKED,
        )
        has_committed = getattr(self._registry, "has_committed_artifact", None)
        if callable(has_committed) and not has_committed(addr, sandbox.incarnation_id, ref.blob_sha256):
            raise CoordAuthError("artifact_not_committed_to_sandbox_incarnation")
        return self.spool.read_artifact(sandbox.incarnation_id, ref)
