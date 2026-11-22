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
from oc_controller import Controller  # noqa: E402
from oc_coord_contract import (  # noqa: E402
    DEFAULT_EDGE_MAX_ROUNDS,
    EDGE_MAX_QUEUED_BYTES,
    EDGE_MAX_QUEUED_MSGS,
    MAX_ARTIFACT_BYTES,
    MAX_ARTIFACTS_PER_EDGE,
    MAX_ARTIFACTS_PER_MSG,
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
    validate_sandbox_rel_path,
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
_PATCH_SUFFIX = ".patch"
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


def _ensure_trusted_dir(path: Path, *, sandbox_root: Path | None) -> Path:
    """Validate trust boundaries and ensure a 0o700 non-symlink directory exists."""
    raw = Path(path)
    if raw.is_symlink():
        raise CoordPolicyError(f"Symlink directory rejected: {raw}")
    try:
        phys = check_not_in_sandbox(raw, sandbox_root)
        check_not_host_production_dir(phys)
        if phys.is_symlink():
            raise CoordPolicyError(f"Symlink directory rejected: {phys}")
        if not phys.exists():
            with _UMASK_LOCK:
                old_umask = os.umask(0o077)
                try:
                    phys.mkdir(parents=True, exist_ok=True, mode=0o700)
                finally:
                    os.umask(old_umask)
            os.chmod(phys, 0o700)
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
        root_budget: SubtreeBudget | None = None,
        sandbox_root: Path | None = None,
        watchdog_interval_s: float = 0.02,
    ) -> None:
        self._registry = registry
        self._transport = transport
        self._controller = controller
        self._root_budget = root_budget or SubtreeBudget()
        self._watchdog_interval_s = watchdog_interval_s

        self.spool = ArtifactSpool(state_dir, sandbox_root=sandbox_root)
        self.wait_graph = WaitForGraph()
        self.dispatcher = OutboxDispatcher(self, poll_interval_s=watchdog_interval_s)

        self._meta_lock = threading.Lock()
        self._register_lock = threading.Lock()
        self._degraded = False
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

    def _check_lease_active(self, sandbox_addr: str) -> bool:
        with self._meta_lock:
            lease = self._leases.get(sandbox_addr)
        if lease is None:
            return True
        return lease.is_active()

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
        addr = parse_local_target(name)
        clean_inc = validate_opaque_token(incarnation_id, _LABEL_INCARNATION)
        clean_brief = validate_task_brief(task_brief)
        clean_parent = parse_local_target(parent_addr).canonical if parent_addr is not None else None

        if lease is not None and not lease.is_active():
            raise RevokedError("lease_already_revoked")

        with self._register_lock:
            depth, effective_budget = self._validate_sandbox_budget(
                parent_addr=clean_parent,
                sandbox_type=sandbox_type,
                child_budget=child_budget,
            )
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

            with self._meta_lock:
                self._fenced_addrs.discard(addr.canonical)
                self._known_incarnations.setdefault(addr.canonical, set()).add(clean_inc)
                self._budgets[addr.canonical] = effective_budget
                if lease is not None:
                    self._leases[addr.canonical] = lease

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

    def _attach_lease_watchdog(self, sandbox_addr: str, lease: BrokerLease) -> None:
        def _cb() -> None:
            self._on_lease_revoked(sandbox_addr)

        with self._meta_lock:
            self._lease_callbacks[sandbox_addr] = _cb
        lease.add_revoke_callback(_cb)
        lease.start_watchdog(poll_interval=self._watchdog_interval_s)

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
        dst = parse_local_target(dst_addr)
        threads = frozenset(validate_thread_id(t) for t in allowed_threads)
        kinds = frozenset(validate_msg_kind(k) for k in allowed_msg_kinds)
        if not threads or not kinds:
            raise CoordValidationError("allowed_threads and allowed_msg_kinds must be non-empty")
        if type(max_rounds) is not int or not (1 <= max_rounds <= _MAX_EDGE_ROUNDS_CAP):
            raise CoordValidationError("max_rounds out of bounds")
        if type(rate_limit_rpm) is not int or not (1 <= rate_limit_rpm <= _MAX_RATE_LIMIT_RPM):
            raise CoordValidationError("rate_limit_rpm out of bounds")
        if type(grant_generation) is not int or grant_generation < 1:
            raise CoordValidationError("grant_generation must be >= 1")
        clean_src_inc = (
            validate_opaque_token(src_incarnation, "src_incarnation")
            if src_incarnation is not None
            else None
        )
        sandbox = self._registry.get_sandbox(dst.canonical)
        if sandbox is None:
            raise CoordPolicyError(_ERR_SANDBOX_NOT_FOUND)
        if sandbox.status == _STATUS_REVOKED:
            raise RevokedError(_ERR_SANDBOX_REVOKED)

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

    def _check_source_sandbox_live(self, src_actor: str) -> None:
        with self._meta_lock:
            if src_actor in self._fenced_addrs:
                raise RevokedError(_ERR_EDGE_REVOKED)
        if not self._check_lease_active(src_actor):
            raise RevokedError(_ERR_EDGE_REVOKED)
        src_sb = self._registry.get_sandbox(src_actor)
        if src_sb is not None and src_sb.status == _STATUS_REVOKED:
            raise RevokedError(_ERR_EDGE_REVOKED)

    def _verify_grant_live_under_fence(
        self,
        edge_id: str,
        expected_gen: int,
        dst_addr: str,
        *,
        expected_dst_incarnation: str | None = None,
    ) -> tuple[RoutingEdge, SandboxRecord]:
        self._require_not_degraded()
        edge = self._registry.get_edge(edge_id)
        if edge is None or not edge.active or edge.grant_generation != expected_gen:
            raise RevokedError(_ERR_EDGE_REVOKED)
        with self._meta_lock:
            fenced = (edge_id, expected_gen) in self._fenced_generations or dst_addr in self._fenced_addrs
        if fenced or self._registry.is_grant_tombstoned(edge_id, expected_gen):
            raise RevokedError(_ERR_EDGE_REVOKED)
        self._check_source_sandbox_live(edge.src_actor)
        sandbox = self._registry.get_sandbox(dst_addr)
        if sandbox is None:
            raise CoordPolicyError(_ERR_SANDBOX_NOT_FOUND)
        if sandbox.status == _STATUS_REVOKED:
            raise RevokedError(_ERR_SANDBOX_REVOKED)
        with self._meta_lock:
            if (dst_addr, sandbox.incarnation_id) in self._fenced_targets:
                raise RevokedError(_ERR_SANDBOX_REVOKED)
        if not self._check_lease_active(dst_addr):
            raise RevokedError(_ERR_SANDBOX_REVOKED)
        if expected_dst_incarnation is not None and sandbox.incarnation_id != expected_dst_incarnation:
            raise IncarnationMismatchError("Target sandbox incarnation rotated")
        return edge, sandbox

    def _validate_caller_incarnation_and_lease(
        self, caller: PrincipalCtx, edge: RoutingEdge
    ) -> None:
        if caller.sandbox_addr is not None and not self._check_lease_active(caller.sandbox_addr):
            raise RevokedError("caller_lease_revoked")
        if edge.src_incarnation is not None and caller.incarnation_id != edge.src_incarnation:
            raise IncarnationMismatchError("Caller incarnation mismatch")

    @staticmethod
    def _validate_artifact_inputs(
        artifact_blobs: Sequence[bytes], artifact_refs: Sequence[ArtifactRef]
    ) -> tuple[ArtifactRef, ...]:
        refs_tuple = tuple(artifact_refs)
        for ref in refs_tuple:
            if not isinstance(ref, ArtifactRef):
                raise CoordValidationError("artifact_refs entries must be ArtifactRef instances")
        if len(refs_tuple) + len(artifact_blobs) > MAX_ARTIFACTS_PER_MSG:
            raise CoordValidationError(f"Too many total artifacts (max {MAX_ARTIFACTS_PER_MSG})")
        return refs_tuple

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
            body_sha256=sha256_canonical_body(wire_body),
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
                live_edge, dst_sb = self._verify_grant_live_under_fence(
                    edge.edge_id, edge.grant_generation, addr.canonical
                )
                self._validate_caller_incarnation_and_lease(caller, live_edge)
                if not control_prio:
                    self._check_rate_limit(live_edge.edge_id, live_edge.rate_limit_rpm)
                dst_incarnation = dst_sb.incarnation_id
                expected_gen = live_edge.grant_generation
                if artifact_blobs:
                    reservation = self.spool.reserve(live_edge.edge_id, artifact_blobs)

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
                    self.spool.publish(reservation, dst_incarnation)
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

    def _row_is_live_under_fence(
        self, edge_id: str, grant_gen: int, dst_addr: str, dst_incarnation: str
    ) -> bool:
        try:
            self._verify_grant_live_under_fence(
                edge_id,
                grant_gen,
                dst_addr,
                expected_dst_incarnation=dst_incarnation,
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

    def _dispatch_single_row(self, row: dict[str, Any], *, async_stream: bool) -> bool:
        msg_id = str(row["msg_id"])
        edge_id = str(row["edge_id"])
        grant_gen = int(row["grant_generation"])
        dst_inc = str(row["dst_incarnation"])

        fence = self._get_grant_fence(edge_id)
        stream_task: Callable[[], None] | None = None
        with fence:
            env = self._registry.get_envelope(msg_id)
            edge = self._registry.get_edge(edge_id)
            dst_addr = self._resolve_row_dst_addr(row, env, edge)
            if dst_addr is None or env is None:
                self._registry.cancel_outbox_row(msg_id, reason="envelope_missing")
                return False
            if not self._row_is_live_under_fence(edge_id, grant_gen, dst_addr, dst_inc):
                self._registry.cancel_outbox_row(msg_id, reason="grant_or_incarnation_fenced")
                return False
            started = self._registry.mark_outbox_dispatch_started(
                msg_id,
                edge_id=edge_id,
                grant_generation=grant_gen,
                dst_incarnation=dst_inc,
            )
            if not started:
                return False

            turn = TurnDispatch(
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
            try:
                result = self._transport.dispatch_turn(turn)
            except Exception as exc:
                self._registry.mark_outbox_uncertain(env.msg_id, detail=f"dispatch_exception:{exc}")
                return True
            stream_task = self._handle_dispatch_result_locked(env, result, edge_id, grant_gen)

        if stream_task is not None:
            if async_stream:
                self.dispatcher.spawn_stream(stream_task)
            else:
                stream_task()
        return True

    def _handle_dispatch_result_locked(
        self,
        env: Envelope,
        result: Any,
        edge_id: str,
        grant_gen: int,
    ) -> Callable[[], None] | None:
        if result.outcome is DispatchOutcome.ZERO_BYTES_SENT:
            if self._row_is_live_under_fence(
                edge_id, grant_gen, env.dst_addr, env.dst_incarnation
            ):
                self._registry.return_outbox_to_pending(env.msg_id, detail=result.detail)
            else:
                returned = self._registry.return_outbox_to_pending(
                    env.msg_id, detail=result.detail or _STATUS_REVOKED
                )
                if returned:
                    self._registry.cancel_outbox_row(
                        env.msg_id, reason=result.detail or _STATUS_REVOKED
                    )
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
        raw_ev: Any, *, expected_sandbox: str, expected_incarnation: str
    ) -> StreamEvent | None:
        if not isinstance(raw_ev, StreamEvent):
            return None
        if raw_ev.event_type not in STREAM_EVENT_TYPES:
            return None
        if raw_ev.sandbox_addr != expected_sandbox or raw_ev.incarnation_id != expected_incarnation:
            return None
        try:
            validate_thread_id(raw_ev.thread_id)
        except AddressError:
            return None
        if len(raw_ev.text.encode("utf-8")) > MAX_STREAM_EVENT_BYTES:
            return None
        if raw_ev.file_path is not None:
            try:
                validate_sandbox_rel_path(raw_ev.file_path)
            except (AddressError, CoordValidationError):
                return None
        try:
            encoded_detail = json.dumps(raw_ev.detail, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError):
            return None
        if len(encoded_detail) > MAX_STREAM_EVENT_BYTES:
            return None
        return raw_ev

    def _consume_stream(self, env: Envelope, stream_id: str) -> None:
        inc_key = (env.dst_addr, env.dst_incarnation)
        total_seen = 0
        try:
            for raw_ev in self._transport.stream_events(stream_id):
                if total_seen >= MAX_TURN_STREAM_EVENTS:
                    cap_ev = StreamEvent(
                        event_type="turn_error",
                        sandbox_addr=env.dst_addr,
                        incarnation_id=env.dst_incarnation,
                        thread_id=env.dst_thread_id,
                        message_id=env.msg_id,
                        text="stream_event_cap_exceeded",
                        created_at=time.time(),
                    )
                    self._registry.record_stream_event(cap_ev)
                    self._notify_waiters()
                    break
                total_seen += 1
                valid_ev = self._validate_untrusted_event(
                    raw_ev,
                    expected_sandbox=env.dst_addr,
                    expected_incarnation=env.dst_incarnation,
                )
                if valid_ev is None:
                    self._registry.append_audit(
                        env.dst_addr,
                        "stream_event_rejected",
                        env.msg_id,
                        "dropped",
                        {"stream_id": stream_id},
                    )
                    continue
                self._registry.record_stream_event(valid_ev)
                self._notify_waiters()
        except Exception as exc:
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
            try:
                self._registry.mark_outbox_completed(env.msg_id)
            except Exception:
                pass
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

    def _authorize_target_read(self, caller: PrincipalCtx, target_addr: str) -> None:
        if caller.role in (CoordRole.OPERATOR, CoordRole.ORCHESTRATOR):
            return
        if caller.sandbox_addr == target_addr:
            return
        edges = self._registry.list_edges(
            src_actor=caller.canonical_sender, dst_addr=target_addr, active_only=True
        )
        if not edges:
            raise CoordAuthError(_ERR_NO_ACTIVE_EDGE)

    def status(self, caller: PrincipalCtx, *, target: str | None = None) -> dict[str, Any]:
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
        return {
            "sandboxes": [asdict(sb) for sb in sandboxes],
            "count": len(sandboxes),
            "degraded": self.is_degraded,
        }

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
        target_addrs = tuple(parse_local_target(t).canonical for t in targets)
        for addr in target_addrs:
            self._authorize_target_read(caller, addr)

        token = self.wait_graph.enter(caller.canonical_sender, target_addrs)
        waiter = _WaiterState(
            caller_actor=caller.canonical_sender, targets=frozenset(target_addrs)
        )
        try:
            self._assert_targets_not_revoked(caller.canonical_sender, target_addrs)
            initial = self._registry.list_events_since(target_addrs, since_seq)
            if initial:
                return {"events": initial, "last_seq": initial[-1]["seq"], "timed_out": False}

            deadline = time.monotonic() + timeout_s
            with self._wait_cond:
                self._waiters.add(waiter)
                try:
                    return self._wait_loop_locked(waiter, target_addrs, since_seq, deadline)
                finally:
                    self._waiters.discard(waiter)
        finally:
            self.wait_graph.exit(caller.canonical_sender, token)

    def _assert_targets_not_revoked(
        self, caller_actor: str, target_addrs: Sequence[str]
    ) -> None:
        with self._meta_lock:
            if caller_actor in self._fenced_addrs:
                raise RevokedError(_ERR_EDGE_REVOKED)
        for addr in target_addrs:
            with self._meta_lock:
                if addr in self._fenced_addrs:
                    raise RevokedError(_ERR_EDGE_REVOKED)
            sb = self._registry.get_sandbox(addr)
            if sb is None or sb.status == _STATUS_REVOKED:
                raise RevokedError(_ERR_EDGE_REVOKED)
            with self._meta_lock:
                if (addr, sb.incarnation_id) in self._fenced_targets:
                    raise RevokedError(_ERR_EDGE_REVOKED)

    def _wait_loop_locked(
        self,
        waiter: _WaiterState,
        target_addrs: Sequence[str],
        since_seq: int,
        deadline: float,
    ) -> dict[str, Any]:
        while True:
            if waiter.revoked:
                raise RevokedError(_ERR_EDGE_REVOKED)
            events = self._registry.list_events_since(target_addrs, since_seq)
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
                    if target_addr in w.targets or w.caller_actor == target_addr
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
            edges = list({e.edge_id: e for e in (*dst_edges, *src_edges)}.values())
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
        addr = parse_local_target(target).canonical

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
            detached_incarnations, detached_waiters, lease, reason
        )

        if lookup_failed:
            with self._meta_lock:
                self._degraded = True
            raise CoordPolicyError(_ERR_REVOKED_UNCONFIRMED)

        # Step 3: Persist tombstone & cancel pending outbox; degrade store on failure.
        try:
            revoked_edge_ids = self._registry.revoke_grant_and_cancel_outbox(
                target_addr=addr, reason=reason
            )
            self._registry.update_sandbox_status(
                addr, _STATUS_REVOKED, incarnation_id=incarnation_id
            )
            self._registry.append_audit(
                caller.canonical_sender,
                "revoke",
                addr,
                _OUTCOME_OK,
                {"reason": reason, "revoked_edges": len(revoked_edge_ids)},
            )
        except Exception as exc:
            with self._meta_lock:
                self._degraded = True
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
        return self._registry.get_projection()

    def read_artifact(
        self, caller: PrincipalCtx, *, sandbox_addr: str, ref: ArtifactRef
    ) -> bytes:
        self._require_not_degraded()
        addr = parse_local_target(sandbox_addr).canonical
        self._authorize_target_read(caller, addr)
        with self._meta_lock:
            if addr in self._fenced_addrs:
                raise RevokedError(_ERR_SANDBOX_REVOKED)
        sandbox = self._registry.get_sandbox(addr)
        if sandbox is None:
            raise CoordPolicyError(_ERR_SANDBOX_NOT_FOUND)
        if sandbox.status == _STATUS_REVOKED:
            raise RevokedError(_ERR_SANDBOX_REVOKED)
        with self._meta_lock:
            if (addr, sandbox.incarnation_id) in self._fenced_targets:
                raise RevokedError(_ERR_SANDBOX_REVOKED)
        if not self._check_lease_active(addr):
            raise RevokedError(_ERR_SANDBOX_REVOKED)
        return self.spool.read_artifact(sandbox.incarnation_id, ref)
