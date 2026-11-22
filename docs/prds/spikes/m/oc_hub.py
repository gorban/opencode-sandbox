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
from oc_controller import Controller, Principal  # noqa: E402
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
_ERR_EDGE_REVOKED = "edge_revoked"
_ERR_NO_ACTIVE_EDGE = "no_active_edge"
_ERR_REVOKED_UNCONFIRMED = "revoked_locally_persistence_unconfirmed"
_ERR_SANDBOX_NOT_FOUND = "sandbox_not_found"
_ERR_SANDBOX_REVOKED = "sandbox_revoked"
_ERR_ADMIN_ONLY = "operator_or_orchestrator_required"
_STATUS_REVOKED = "revoked"
_STATUS_RUNNING = "running"
_STATUS_PENDING = "pending"
_STAGING_DIR_NAME = ".staging"
_SPOOL_DIR_NAME = "inbox-spool"
_DEGRADED_MARKER_NAME = ".coord_degraded"
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

    def record_stream_event(
        self, event: StreamEvent, *, tui_enter_token: str | None = None
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
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
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
            old_umask = os.umask(0o177)
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

    def stop(self, *, timeout_s: float = 2.0) -> None:
        self._stop_event.set()
        self._wake_event.set()
        deadline = time.monotonic() + timeout_s
        with self._lock:
            pump = self._thread
            self._thread = None
            streams = list(self._stream_threads)
        if pump is not None:
            pump.join(timeout=max(0.0, deadline - time.monotonic()))
        for worker in streams:
            worker.join(timeout=max(0.0, deadline - time.monotonic()))


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

        self.spool = ArtifactSpool(state_dir, sandbox_root=sandbox_root)
        self._state_dir = self.spool._state_dir
        self._degraded_marker = self._state_dir / _DEGRADED_MARKER_NAME
        self.wait_graph = WaitForGraph()
        self.dispatcher = OutboxDispatcher(self, poll_interval_s=watchdog_interval_s)

        self._meta_lock = threading.Lock()
        self._register_lock = threading.Lock()
        self._degraded = self._load_degraded_marker()
        self._grant_fences: dict[str, threading.RLock] = {}
        self._fenced_generations: set[tuple[str, int]] = set()
        self._fenced_targets: set[tuple[str, str]] = set()
        self._fenced_addrs: set[str] = set()
        self._known_incarnations: dict[str, set[str]] = {}
        self._budgets: dict[str, SubtreeBudget] = {}
        self._leases: dict[str, BrokerLease] = {}
        self._lease_callbacks: dict[str, Callable[[], None]] = {}
        self._rate_windows: dict[str, deque[float]] = {}
        self._active_streams: dict[tuple[str, str], set[str]] = {}

        self._wait_cond = threading.Condition()
        self._waiters: set[_WaiterState] = set()

    def _load_degraded_marker(self) -> bool:
        try:
            os.lstat(self._degraded_marker)
            return True
        except FileNotFoundError:
            return False
        except OSError:
            return True

    def _mark_degraded(self, detail: str) -> None:
        with self._meta_lock:
            self._degraded = True
        flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        try:
            with _UMASK_LOCK:
                old_umask = os.umask(0o177)
                try:
                    fd = os.open(self._degraded_marker, flags, 0o600)
                finally:
                    os.umask(old_umask)
            try:
                os.write(fd, f"{time.time():.6f}:{detail}\n".encode("utf-8", errors="replace"))
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            pass

    @property
    def is_degraded(self) -> bool:
        with self._meta_lock:
            return self._degraded

    def start_dispatcher(self) -> None:
        self.dispatcher.start()

    def close(self) -> None:
        self.dispatcher.stop()
        with self._meta_lock:
            leases = list(self._leases.items())
            callbacks = dict(self._lease_callbacks)
            self._leases.clear()
            self._lease_callbacks.clear()
        for addr, lease in leases:
            cb = callbacks.get(addr)
            if cb is not None:
                lease.remove_revoke_callback(cb)
            lease.stop_watchdog()

    def _get_grant_fence(self, edge_id: str) -> threading.RLock:
        with self._meta_lock:
            fence = self._grant_fences.get(edge_id)
            if fence is None:
                fence = threading.RLock()
                self._grant_fences[edge_id] = fence
            return fence

    def _require_not_degraded(self) -> None:
        with self._meta_lock:
            if self._degraded:
                raise CoordPolicyError(_ERR_DEGRADED)

    @staticmethod
    def _require_admin_role(caller: PrincipalCtx, action: str) -> None:
        if caller.role not in (CoordRole.OPERATOR, CoordRole.ORCHESTRATOR):
            raise CoordAuthError(f"{_ERR_ADMIN_ONLY}:{action}")

    def _check_controller_request_active(self, request_id: str) -> bool:
        if self._controller is None or self._controller_actor is None:
            return False
        try:
            st = self._controller.status(self._controller_actor, request_id)
        except Exception:
            return False
        return bool(st.eligible and not st.revoked)

    def _check_lease_active(
        self, sandbox_addr: str, *, controller_request_id: str | None = None
    ) -> bool:
        with self._meta_lock:
            lease = self._leases.get(sandbox_addr)
        if lease is not None:
            if not lease.is_active():
                return False
            if controller_request_id is not None:
                lease_req = getattr(lease, "_controller_request_id", None)
                if lease_req != controller_request_id:
                    return self._check_controller_request_active(controller_request_id)
            return True
        req_id = controller_request_id
        if req_id is None:
            sb = self._registry.get_sandbox(sandbox_addr)
            if sb is not None:
                req_id = sb.controller_request_id
        if req_id is not None:
            return self._check_controller_request_active(req_id)
        return True

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
        if not self._check_lease_active(addr, controller_request_id=sb.controller_request_id):
            raise RevokedError(_ERR_SANDBOX_REVOKED)

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
                old_lease.stop_watchdog()
            except Exception:
                pass

    def _on_lease_revoked(self, sandbox_addr: str) -> None:
        """Dispatch revocation on a daemon thread so BrokerLease never re-enters grant fences."""

        def _run() -> None:
            watchdog_caller = PrincipalCtx(role=CoordRole.OPERATOR, actor_id="lease-watchdog")
            try:
                self.revoke(watchdog_caller, target=sandbox_addr, reason="controller_lease_revoked")
            except Exception:
                pass

        threading.Thread(target=_run, daemon=True).start()

    def _resolve_parent_budget(
        self, parent_addr: str | None, active_sandboxes: list[SandboxRecord]
    ) -> tuple[int, SubtreeBudget]:
        if parent_addr is None:
            return 0, self._root_budget
        parent = self._registry.get_sandbox(parent_addr)
        if parent is None or parent.status == _STATUS_REVOKED:
            raise CoordPolicyError(f"Parent sandbox unavailable: {parent_addr!r}")
        with self._meta_lock:
            parent_budget = self._budgets.get(parent_addr)
        if parent_budget is None:
            rem_depth = max(0, self._root_budget.max_depth_remaining - parent.depth)
            parent_budget = SubtreeBudget(
                max_depth_remaining=rem_depth,
                max_children=self._root_budget.max_children,
                max_total_sandboxes=self._root_budget.max_total_sandboxes,
                allowed_workers=self._root_budget.allowed_workers,
                allowed_sandbox_types=self._root_budget.allowed_sandbox_types,
                allowed_models=self._root_budget.allowed_models,
                allowed_variants=self._root_budget.allowed_variants,
                allowed_broker_routes=self._root_budget.allowed_broker_routes,
                max_security_profile=self._root_budget.max_security_profile,
            )
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

    def _check_register_lease(self, lease: BrokerLease | None) -> None:
        if lease is None:
            return
        if not lease.is_active():
            raise RevokedError("lease_already_revoked")
        lease_actor = getattr(lease, "_controller_actor", None)
        if self._controller_actor is None and lease_actor is not None:
            self._controller_actor = lease_actor

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
        self._require_not_degraded()
        self._require_admin_role(caller, "register_sandbox")
        self._verify_caller_live(caller)
        addr = parse_local_target(name)
        clean_inc = validate_opaque_token(incarnation_id, _LABEL_INCARNATION)
        clean_brief = validate_task_brief(task_brief)
        clean_parent = parse_local_target(parent_addr).canonical if parent_addr is not None else None
        self._check_register_lease(lease)

        with self._register_lock:
            existing = self._registry.get_sandbox(addr.canonical)
            self._enforce_register_caller_scope(
                caller, addr.canonical, clean_parent, existing, clean_inc
            )
            depth, effective_budget = self._validate_sandbox_budget(
                parent_addr=clean_parent,
                sandbox_type=sandbox_type,
                child_budget=child_budget,
            )
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
                controller_request_id=controller_request_id,
                parent_addr=clean_parent,
                depth=depth,
                created_at=now,
                updated_at=now,
            )
            persisted = self._registry.register_sandbox(record)
            self._registry.ensure_thread(addr.canonical, clean_inc, _THREAD_MAIN, title=clean_brief[:64])
            self._record_registered_meta(addr.canonical, clean_inc, effective_budget, lease)

        if lease is not None:
            self._attach_lease_watchdog(addr.canonical, lease)

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
            self._budgets[addr] = budget
            if lease is not None:
                self._leases[addr] = lease

    def _attach_lease_watchdog(self, sandbox_addr: str, lease: BrokerLease) -> None:
        def _cb() -> None:
            self._on_lease_revoked(sandbox_addr)

        with self._meta_lock:
            self._lease_callbacks[sandbox_addr] = _cb
        lease.add_revoke_callback(_cb)
        lease.start_watchdog(poll_interval=self._watchdog_interval_s)

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
        self._require_not_degraded()
        self._require_admin_role(caller, "grant_edge")
        self._verify_caller_live(caller)
        dst = parse_local_target(dst_addr)
        threads = frozenset(validate_thread_id(t) for t in allowed_threads)
        kinds = frozenset(validate_msg_kind(k) for k in allowed_msg_kinds)
        self._validate_edge_bounds(threads, kinds, max_rounds, rate_limit_rpm, grant_generation)
        clean_src_inc = (
            validate_opaque_token(src_incarnation, "src_incarnation")
            if src_incarnation is not None
            else None
        )
        clean_src_inc = self._enforce_grant_edge_scope(
            caller, src_actor, dst.canonical, clean_src_inc
        )
        self._require_dst_sandbox_live(dst.canonical, lease_request_id)

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
            lease_request_id=lease_request_id,
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
        if not self._check_lease_active(dst_addr, controller_request_id=sandbox.controller_request_id):
            raise RevokedError(_ERR_SANDBOX_REVOKED)
        if (
            lease_request_id is not None
            and lease_request_id != sandbox.controller_request_id
            and not self._check_lease_active(dst_addr, controller_request_id=lease_request_id)
        ):
            raise RevokedError(_ERR_SANDBOX_REVOKED)
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
        if not self._check_lease_active(sb_addr, controller_request_id=src_sb.controller_request_id):
            raise RevokedError(_ERR_EDGE_REVOKED)

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

    def _row_is_live_under_fence(
        self,
        edge_id: str,
        grant_gen: int,
        dst_addr: str,
        dst_incarnation: str,
        *,
        src_incarnation: str | None = None,
    ) -> bool:
        try:
            self._verify_grant_live_under_fence(
                edge_id,
                grant_gen,
                dst_addr,
                expected_dst_incarnation=dst_incarnation,
                expected_src_incarnation=src_incarnation,
            )
            return True
        except Exception:
            return False

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

    def _dispatch_single_row(self, row: dict[str, Any], *, async_stream: bool) -> bool:
        msg_id = str(row["msg_id"])
        edge_id = str(row["edge_id"])
        grant_gen = int(row["grant_generation"])
        dst_inc = str(row["dst_incarnation"])
        raw_src_inc = row.get("src_incarnation")
        src_inc = str(raw_src_inc) if isinstance(raw_src_inc, str) and raw_src_inc else None

        fence = self._get_grant_fence(edge_id)
        stream_task: Callable[[], None] | None = None
        with fence:
            env = self._registry.get_envelope(msg_id)
            edge = self._registry.get_edge(edge_id)
            dst_addr = self._resolve_row_dst_addr(row, env, edge)
            if dst_addr is None or env is None:
                self._registry.cancel_outbox_row(msg_id, reason="envelope_missing")
                return False
            if not self._row_is_live_under_fence(
                edge_id, grant_gen, dst_addr, dst_inc, src_incarnation=src_inc
            ):
                self._registry.cancel_outbox_row(msg_id, reason="grant_or_incarnation_fenced")
                return False
            if not self._registry.mark_outbox_dispatch_started(
                msg_id, edge_id=edge_id, grant_generation=grant_gen, dst_incarnation=dst_inc
            ):
                return False
            turn = self._build_turn_dispatch(env, edge, grant_gen)
            try:
                result = self._transport.dispatch_turn(turn)
            except Exception as exc:
                self._registry.mark_outbox_uncertain(env.msg_id, detail=f"dispatch_exception:{exc}")
                return True
            stream_task = self._handle_dispatch_result_locked(env, result, edge_id, grant_gen)

        self._run_stream_task(stream_task, async_stream=async_stream)
        return True

    def _run_stream_task(
        self, stream_task: Callable[[], None] | None, *, async_stream: bool
    ) -> None:
        if stream_task is None:
            return
        if async_stream:
            self.dispatcher.spawn_stream(stream_task)
        else:
            stream_task()

    def _handle_dispatch_result_locked(
        self,
        env: Envelope,
        result: Any,
        edge_id: str,
        grant_gen: int,
    ) -> Callable[[], None] | None:
        if result.outcome is DispatchOutcome.ZERO_BYTES_SENT:
            if self._row_is_live_under_fence(
                edge_id,
                grant_gen,
                env.dst_addr,
                env.dst_incarnation,
                src_incarnation=env.src_incarnation,
            ):
                self._registry.return_outbox_to_pending(env.msg_id, detail=result.detail)
            else:
                cancel_reason = result.detail or _STATUS_REVOKED
                try:
                    self._registry.cancel_outbox_row(env.msg_id, reason=cancel_reason)
                except Exception:
                    pass
            return None

        if result.outcome is DispatchOutcome.UNCERTAIN:
            self._registry.mark_outbox_uncertain(
                env.msg_id, detail=result.detail or "uncertain_handoff"
            )
            return None

        stream_id = result.stream_id
        if not isinstance(stream_id, str) or not stream_id:
            self._registry.mark_outbox_uncertain(env.msg_id, detail="missing_stream_id")
            return None

        self._registry.mark_outbox_handed_off(env.msg_id, stream_id=stream_id)
        inc_key = (env.dst_addr, env.dst_incarnation)
        with self._meta_lock:
            self._active_streams.setdefault(inc_key, set()).add(stream_id)

        def _consume() -> None:
            self._consume_stream(env, stream_id)

        return _consume

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
        except (AddressError, CoordValidationError, TypeError, ValueError, UnicodeEncodeError):
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

    def _process_single_stream_event(
        self, env: Envelope, stream_id: str, raw_ev: Any
    ) -> tuple[bool, str | None]:
        target_fenced = self._is_target_fenced(env.dst_addr, env.dst_incarnation)
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
        self._registry.record_stream_event(valid_ev)
        self._notify_waiters()
        if valid_ev.event_type == "turn_completed":
            return True, None
        if valid_ev.event_type in ("turn_error", _STATUS_REVOKED):
            return False, valid_ev.event_type
        return False, None

    def _consume_stream(self, env: Envelope, stream_id: str) -> None:
        inc_key = (env.dst_addr, env.dst_incarnation)
        total_seen = 0
        saw_completed = False
        abort_reason: str | None = None
        try:
            for raw_ev in self._transport.stream_events(stream_id):
                if total_seen >= MAX_TURN_STREAM_EVENTS:
                    abort_reason = "stream_event_cap_exceeded"
                    cap_ev = StreamEvent(
                        event_type="turn_error",
                        sandbox_addr=env.dst_addr,
                        incarnation_id=env.dst_incarnation,
                        thread_id=env.dst_thread_id,
                        message_id=env.msg_id,
                        text=abort_reason,
                        created_at=time.time(),
                    )
                    self._registry.record_stream_event(cap_ev)
                    self._notify_waiters()
                    break
                total_seen += 1
                done, err_reason = self._process_single_stream_event(env, stream_id, raw_ev)
                if done:
                    saw_completed = True
                if err_reason is not None:
                    abort_reason = err_reason
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
                active_set = self._active_streams.get(inc_key)
                if active_set is not None:
                    active_set.discard(stream_id)
            self._finalize_stream_outbox(
                env.msg_id, saw_completed=saw_completed, abort_reason=abort_reason
            )
            self._notify_waiters()

    def dispatch_once(self, *, async_stream: bool = False) -> int:
        if self.is_degraded:
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

    def _notify_waiters(self) -> None:
        with self._wait_cond:
            self._wait_cond.notify_all()

    def _authorize_target_read(
        self, caller: PrincipalCtx, target_addr: str
    ) -> frozenset[str] | None:
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
        matching = [
            e
            for e in edges
            if (e.src_incarnation is None or e.src_incarnation == caller.incarnation_id)
            and not self._registry.is_grant_tombstoned(e.edge_id, e.grant_generation)
        ]
        if not matching:
            raise CoordAuthError(_ERR_NO_ACTIVE_EDGE)
        allowed: set[str] = set()
        for edge in matching:
            allowed.update(edge.allowed_threads)
        return frozenset(allowed)

    def status(self, caller: PrincipalCtx, *, target: str | None = None) -> dict[str, Any]:
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
                    return self._wait_loop_locked(
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

    def _wait_loop_locked(
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
            if waiter.revoked:
                raise RevokedError(_ERR_EDGE_REVOKED)
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
            self._wait_cond.wait(timeout=remaining)

    def _fence_target_in_memory(
        self,
        target_addr: str,
        incarnation_id: str | None,
        edges: Sequence[RoutingEdge],
    ) -> tuple[list[tuple[str, str]], list[_WaiterState], BrokerLease | None]:
        edge_ids = sorted(e.edge_id for e in edges)
        fences = [self._get_grant_fence(eid) for eid in edge_ids]
        orch_actor = f"{_ORCH_ACTOR_PREFIX}{target_addr}"
        for fence in fences:
            fence.acquire()
        try:
            detached_incarnations, lease = self._detach_meta_for_target(
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
            return detached_incarnations, detached_waiters, lease
        finally:
            for fence in reversed(fences):
                fence.release()

    def _detach_meta_for_target(
        self,
        target_addr: str,
        incarnation_id: str | None,
        edges: Sequence[RoutingEdge],
    ) -> tuple[list[tuple[str, str]], BrokerLease | None]:
        with self._meta_lock:
            self._fenced_addrs.add(target_addr)
            inc_set: set[str] = set(self._known_incarnations.get(target_addr, ()))
            if incarnation_id is not None:
                inc_set.add(incarnation_id)
            for sb_addr, inc_id in list(self._active_streams.keys()):
                if sb_addr == target_addr:
                    inc_set.add(inc_id)
                    self._active_streams.pop((sb_addr, inc_id), None)
            for inc_id in inc_set:
                self._fenced_targets.add((target_addr, inc_id))
            for edge in edges:
                self._fenced_generations.add((edge.edge_id, edge.grant_generation))
            lease = self._leases.pop(target_addr, None)
            cb = self._lease_callbacks.pop(target_addr, None)
        if lease is not None and cb is not None:
            lease.remove_revoke_callback(cb)
        return [(target_addr, inc_id) for inc_id in sorted(inc_set)], lease

    def _teardown_detached(
        self,
        detached_incarnations: list[tuple[str, str]],
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
        if detached_waiters:
            try:
                self._notify_waiters()
            except Exception:
                pass
        if lease is not None:
            try:
                if getattr(lease, "_watch_thread", None) is not threading.current_thread():
                    lease.stop_watchdog()
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
        detached_incarnations, detached_waiters, lease = self._fence_target_in_memory(
            addr, incarnation_id, edges
        )

        # Step 2: OUTSIDE DB, nonblocking, fault-isolated teardown of streams, waiters, lease.
        aborted = self._teardown_detached(
            detached_incarnations, detached_waiters, lease, clean_reason
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
        if not self._check_lease_active(addr, controller_request_id=sandbox.controller_request_id):
            raise RevokedError(_ERR_SANDBOX_REVOKED)
        has_committed = getattr(self._registry, "has_committed_artifact", None)
        if callable(has_committed) and not has_committed(addr, sandbox.incarnation_id, ref.blob_sha256):
            raise CoordAuthError("artifact_not_committed_to_sandbox_incarnation")
        return self.spool.read_artifact(sandbox.incarnation_id, ref)
