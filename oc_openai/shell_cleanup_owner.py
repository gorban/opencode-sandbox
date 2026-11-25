"""Cleanup-only detached Podman pod/volume/worktree/slot owner for OpenAI shell live e2e.

This module intentionally has zero imports of OAuth, profile, exposure ledger, HTTP,
or upstream provider code. It is structurally incapable of making any provider request.

Lifecycle guarantees:
- Spawned in its own session (`start_new_session=True`) over a private AF_UNIX control
  socketpair and lifeline pipe so teardown survives `SIGKILL` of the foreground driver.
- Persists an fsynced (file + dir) on-disk ownership journal before and after every
  pod, volume, worktree, and container-slot creation step.
- Acquires `oc-sandbox`'s real exclusive `lifecycle` lock (`oc-setup-lock.py`) for BOTH
  creation and teardown.
- Checks exact pod membership (`podman pod inspect <pod_id>`) before `podman pod rm -f`
  so an untracked/foreign container inside the pod can never be deleted with the pod.
- If driver loss occurs between `begin_slot_create` and `finish_slot_create` (in-flight
  create / lost ack), revokes the slot's grant state to terminal, marks uncertainty,
  retains grant/slot/journal evidence, and refuses blind name-based deletion.
"""

from contextlib import suppress
from dataclasses import dataclass
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import select
import signal
import socket
import stat
import subprocess
import sys


PROOF_OWNER_LABEL = "io.oc-sandbox.shell-proof"
_HOST_BRIDGE = "/usr/bin/host-spawn"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_RUN_ID_RE = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_INST_RE = re.compile(r"e2e-[0-9a-f]{8}\Z", re.ASCII)
_LEVEL_RE = re.compile(r"s0:c\d+,c\d+\Z", re.ASCII)
_MAX_CMD_BYTES = 64 * 1024
_STATUS_LEASE_ACQUIRING = "lease_acquiring"
_STATUS_CREATING = "creating"
_STATUS_CREATED = "created"
_STATUS_LEASE_RELEASED = "lease_released"
_OP_PREPARE_SLOT = "prepare_slot"
_OP_BEGIN_SLOT = "begin_slot_create"
_OP_FINISH_SLOT = "finish_slot_create"
_OP_LEASE_RELEASED = "mark_lease_released"
_KEY_CONTAINER_NAME = "container_name"
_KEY_UNCERTAIN = "ownership_uncertain"
_KEY_LEASE_RELEASED = "lease_released"


class CleanupOwnerError(RuntimeError):
    """Fail-closed lifecycle or cleanup error from the detached shell proof owner."""


def _is_devbox() -> bool:
    return Path("/run/.containerenv").exists() and Path(_HOST_BRIDGE).exists()


def _podman_command(args: list[str]) -> tuple[list[str], dict[str, str]]:
    uid = os.getuid()
    runtime_dir = f"/run/user/{uid}"
    home_dir = os.environ.get("HOME", "")
    if _is_devbox():
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": home_dir,
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/host{runtime_dir}/bus",
        }
        cmd = [
            _HOST_BRIDGE,
            "--env=",
            "/usr/bin/env",
            "-i",
            "PATH=/usr/bin:/bin",
            f"HOME={home_dir}",
            f"XDG_RUNTIME_DIR={runtime_dir}",
            f"DBUS_SESSION_BUS_ADDRESS=unix:path={runtime_dir}/bus",
            "/usr/bin/podman",
            "--remote=false",
            "--default-mounts-file=/dev/null",
            *args,
        ]
        return cmd, env
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": home_dir,
        "XDG_RUNTIME_DIR": runtime_dir,
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime_dir}/bus",
    }
    cmd = ["/usr/bin/podman", "--remote=false", "--default-mounts-file=/dev/null", *args]
    return cmd, env


def _run_podman(args: list[str], *, timeout: float = 30.0) -> subprocess.CompletedProcess[bytes]:
    cmd, env = _podman_command(args)
    try:
        return subprocess.run(
            cmd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, b"", b"podman command timed out")
    except OSError as exc:
        return subprocess.CompletedProcess(cmd, 127, b"", str(exc).encode("ascii", errors="replace"))


def _fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_fsync_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    fd_owned = True
    try:
        os.fchmod(fd, 0o600)
        stream = os.fdopen(fd, "wb")
        fd_owned = False
        with stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        _fsync_dir(path.parent)
    except BaseException:
        if fd_owned:
            with suppress(OSError):
                os.close(fd)
        with suppress(OSError):
            tmp.unlink(missing_ok=True)
        raise


def _open_owned_dir_pin(path_str: str) -> tuple[int, int, int] | None:
    if not path_str:
        return None
    try:
        fd = os.open(path_str, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            os.close(fd)
            return None
        return fd, info.st_dev, info.st_ino
    except OSError:
        os.close(fd)
        return None


def _clear_dir_fd(dir_fd: int) -> None:
    for name in os.listdir(dir_fd):
        info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            sub_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
            try:
                _clear_dir_fd(sub_fd)
            finally:
                os.close(sub_fd)
            os.rmdir(name, dir_fd=dir_fd)
        else:
            os.unlink(name, dir_fd=dir_fd)


def _open_pinned_leaf_dir(parent_fd: int, leaf: str, want_dev: int, want_ino: int) -> tuple[int | None, str]:
    try:
        leaf_fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    except FileNotFoundError:
        return None, "absent"
    except OSError as exc:
        if exc.errno in (errno.ENOTDIR, errno.ELOOP):
            return None, "replaced"
        return None, "error"
    info = os.fstat(leaf_fd)
    if (info.st_dev, info.st_ino) != (want_dev, want_ino) or info.st_uid != os.geteuid():
        os.close(leaf_fd)
        return None, "replaced"
    return leaf_fd, "ok"


def _remove_pinned_dir(root_path: Path, want_dev: int, want_ino: int) -> str:
    """Remove only the exact (st_dev, st_ino) directory via dir_fd; never touch replacements."""
    try:
        parent_fd = os.open(root_path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "error"
    leaf = root_path.name
    try:
        leaf_fd, status = _open_pinned_leaf_dir(parent_fd, leaf, want_dev, want_ino)
        if leaf_fd is None:
            return status
        try:
            _clear_dir_fd(leaf_fd)
        except OSError:
            return "error"
        finally:
            os.close(leaf_fd)
        try:
            cur = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return "absent"
        except OSError:
            return "error"
        if (cur.st_dev, cur.st_ino) != (want_dev, want_ino) or not stat.S_ISDIR(cur.st_mode):
            return "replaced"
        try:
            os.rmdir(leaf, dir_fd=parent_fd)
        except FileNotFoundError:
            return "absent"
        except OSError:
            return "error"
        try:
            after = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return "removed"
        except OSError:
            return "error"
        return "error" if (after.st_dev, after.st_ino) == (want_dev, want_ino) else "replaced"
    finally:
        os.close(parent_fd)


def _revoke_grant_dir(grant_dir: str, *, slot_root: str = "") -> None:
    if grant_dir:
        target_dir: Path | None = Path(grant_dir)
    elif slot_root:
        target_dir = Path(slot_root) / "grant"
    else:
        target_dir = None
    if target_dir is None or not target_dir.is_dir():
        return
    state_path = target_dir / "state"
    lock_path = target_dir / "lock"
    with suppress(OSError):
        if lock_path.is_file():
            lock_fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                _atomic_fsync_write(state_path, b"revoked\n")
            finally:
                with suppress(OSError):
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
        else:
            _atomic_fsync_write(state_path, b"revoked\n")


def _read_lock_helper_source(lock_helper: Path) -> str:
    """Capture verified oc-setup-lock.py source into RAM so cleanup survives snapshot deletion."""
    try:
        fd = os.open(lock_helper, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise CleanupOwnerError("lock helper unavailable") from None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
            raise CleanupOwnerError("untrusted lock helper file")
        raw = stream.read(65_537)
    if len(raw) > 65_536:
        raise CleanupOwnerError("lock helper exceeds size cap")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise CleanupOwnerError("lock helper is not valid UTF-8") from None


class _LifecycleLock:
    """Acquire `oc-sandbox`'s real exclusive lifecycle lock via verified `oc-setup-lock.py` source."""

    def __init__(self, lock_helper: Path | str, state_dir: Path, instance: str):
        self._helper_source = (
            lock_helper if isinstance(lock_helper, str) else _read_lock_helper_source(lock_helper)
        )
        self._state_dir = state_dir
        self._instance = instance
        self._proc: subprocess.Popen[bytes] | None = None

    def __enter__(self) -> "_LifecycleLock":
        self._state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        proc = subprocess.Popen(
            [
                sys.executable,
                "-IB",
                "-c",
                self._helper_source,
                str(self._state_dir),
                "lifecycle",
                "exclusive",
                self._instance,
                str(os.getpid()),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._proc = proc
        assert proc.stdout is not None
        ready, _, _ = select.select([proc.stdout], [], [], 15.0)
        if not ready:
            self._close_proc()
            raise CleanupOwnerError("timed out acquiring oc-sandbox lifecycle lock")
        line = proc.stdout.readline(64)
        if line.strip() != b"LOCKED":
            self._close_proc()
            raise CleanupOwnerError("could not acquire oc-sandbox lifecycle lock")
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self._close_proc()

    def _close_proc(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None:
            return
        if proc.stdin is not None:
            with suppress(OSError):
                proc.stdin.close()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            with suppress(OSError):
                proc.kill()
            with suppress(OSError, subprocess.TimeoutExpired):
                proc.wait(timeout=2)
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                with suppress(OSError):
                    stream.close()


@dataclass(frozen=True)
class JournalSpec:
    """Immutable identity and pinning spec for one owned disposable proof pod."""

    run_id: str
    instance: str
    pod_name: str
    volume_name: str
    sandbox_dir: Path
    cwd: str
    level: str
    agent_image_id: str
    journal_path: Path | None = None


class _OwnershipJournal:
    """Track verified owned resources durably and perform exact ID/membership-gated teardown."""

    def __init__(self, spec: JournalSpec, *, podman_runner=_run_podman):
        self.run_id = spec.run_id
        self.instance = spec.instance
        self.pod_name = spec.pod_name
        self.volume_name = spec.volume_name
        self.sandbox_dir = spec.sandbox_dir
        self.cwd = spec.cwd
        self.level = spec.level
        self.agent_image_id = spec.agent_image_id
        self.journal_path = spec.journal_path
        self._pm = podman_runner
        self._lock_helper: Path | None = None
        self._lock_helper_source: str | None = None
        self._state_dir: Path | None = None
        self.pod_id: str | None = None
        self.volume_owned = False
        self.worktree_owned = False
        self.worktree_dev_ino: tuple[int, int] | None = None
        self.slots: dict[str, dict[str, object]] = {}
        self._pinned_slot_fds: dict[str, int] = {}
        self.owned_cids: set[str] = set()
        self.ownership_uncertain = False
        self.cleanup_errors: list[str] = []

    def _close_pinned_slot_fd(self, slot_key: str) -> None:
        fd = self._pinned_slot_fds.pop(slot_key, None)
        if fd is not None:
            with suppress(OSError):
                os.close(fd)

    def _close_all_pinned_slot_fds(self) -> None:
        for slot_key in list(self._pinned_slot_fds):
            self._close_pinned_slot_fd(slot_key)

    def __del__(self) -> None:
        self._close_all_pinned_slot_fds()

    def _persist(self) -> None:
        if self.journal_path is None:
            return
        payload = {
            "run_id": self.run_id,
            "instance": self.instance,
            "pod_name": self.pod_name,
            "pod_id": self.pod_id,
            "volume_name": self.volume_name,
            "volume_owned": self.volume_owned,
            "worktree_owned": self.worktree_owned,
            "worktree_dev_ino": list(self.worktree_dev_ino) if self.worktree_dev_ino else None,
            "slots": self.slots,
            "owned_cids": sorted(self.owned_cids),
            _KEY_UNCERTAIN: self.ownership_uncertain,
            "cleanup_errors": list(self.cleanup_errors),
        }
        raw = (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")
        _atomic_fsync_write(self.journal_path, raw)

    def _pod_exists(self, name: str) -> bool:
        res = self._pm(["pod", "exists", name], timeout=10.0)
        if res.returncode == 0:
            return True
        if res.returncode == 1:
            return False
        raise CleanupOwnerError(f"pod existence check failed ({res.returncode})")

    def _volume_exists(self, name: str) -> bool:
        res = self._pm(["volume", "exists", name], timeout=10.0)
        if res.returncode == 0:
            return True
        if res.returncode == 1:
            return False
        raise CleanupOwnerError(f"volume existence check failed ({res.returncode})")

    def create_under_lock(self, lock_helper: Path, state_dir: Path) -> dict[str, object]:
        self._lock_helper = lock_helper
        self._lock_helper_source = _read_lock_helper_source(lock_helper)
        self._state_dir = state_dir
        self._persist()
        with _LifecycleLock(self._lock_helper_source, state_dir, self.instance):
            if self._pod_exists(self.pod_name):
                raise CleanupOwnerError(f"refusing reuse of pre-existing pod {self.pod_name}")
            if self._volume_exists(self.volume_name):
                raise CleanupOwnerError(f"refusing reuse of pre-existing volume {self.volume_name}")
            self._create_owned_pod()
            self._create_owned_volume()
            self._create_owned_worktree()
        return {
            "pod_id": self.pod_id,
            "pod_name": self.pod_name,
            "volume_name": self.volume_name,
            "cwd": self.cwd,
            "instance": self.instance,
            "run_id": self.run_id,
        }

    def _create_owned_pod(self) -> None:
        res = self._pm(
            [
                "pod", "create",
                "--name", self.pod_name,
                "--label", "oc.sandbox=1",
                "--label", f"oc.instance={self.instance}",
                "--label", "oc.ports=",
                "--label", f"{PROOF_OWNER_LABEL}={self.run_id}",
                "--network", "pasta:--host-lo-to-ns-lo",
                "--sysctl", "net.ipv4.ip_unprivileged_port_start=0",
            ],
            timeout=20.0,
        )
        if res.returncode != 0:
            self.ownership_uncertain = True
            self._persist()
            raise CleanupOwnerError(f"pod creation failed or uncertain ({res.returncode})")
        pod_id = res.stdout.decode("ascii", errors="replace").strip()
        if not _HEX64.fullmatch(pod_id):
            self.ownership_uncertain = True
            self._persist()
            raise CleanupOwnerError("pod creation returned malformed pod ID")
        self.pod_id = pod_id
        self._persist()

    def _create_owned_volume(self) -> None:
        res = self._pm(
            [
                "volume", "create",
                "--label", "oc.sandbox=1",
                "--label", f"oc.instance={self.instance}",
                "--label", f"{PROOF_OWNER_LABEL}={self.run_id}",
                self.volume_name,
            ],
            timeout=15.0,
        )
        if res.returncode != 0:
            self.ownership_uncertain = True
            self._persist()
            raise CleanupOwnerError(f"volume creation failed or uncertain ({res.returncode})")
        self.volume_owned = True
        self._persist()

    def _create_owned_worktree(self) -> None:
        script = (
            "import os, sys\n"
            "rel = sys.argv[1]\n"
            "os.chdir('/sandbox')\n"
            "os.makedirs('wt', mode=0o755, exist_ok=True)\n"
            "fd = os.open('wt', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)\n"
            "try:\n"
            "    os.mkdir(rel, 0o700, dir_fd=fd)\n"
            "    st = os.stat(rel, dir_fd=fd, follow_symlinks=False)\n"
            "    print(f'{st.st_dev}:{st.st_ino}')\n"
            "finally:\n"
            "    os.close(fd)\n"
        )
        leaf = self.cwd.split("/", 1)[1]
        res = self._pm(
            [
                "run", "--rm", "--pull=never", "--network=none", "--http-proxy=false",
                "--cap-drop=ALL", "--security-opt=no-new-privileges",
                "--security-opt", f"label=level:{self.level}",
                "--pids-limit=64", "--memory=128m",
                "-v", f"{self.sandbox_dir}:/sandbox",
                "--entrypoint", "python3",
                self.agent_image_id, "-I", "-c", script, leaf,
            ],
            timeout=20.0,
        )
        if res.returncode != 0:
            self.ownership_uncertain = True
            self._persist()
            raise CleanupOwnerError(f"worktree directory creation failed ({res.returncode})")
        raw_id = res.stdout.decode("ascii", errors="replace").strip()
        dev_s, sep, ino_s = raw_id.partition(":")
        if not sep or not dev_s.isdigit() or not ino_s.isdigit():
            self.ownership_uncertain = True
            self._persist()
            raise CleanupOwnerError("worktree creation did not return valid (dev, ino)")
        self.worktree_dev_ino = (int(dev_s), int(ino_s))
        self.worktree_owned = True
        self._persist()

    def _slot_root_identity(self, slot_key: str, slot_root: str) -> tuple[int | None, int | None]:
        prev = self.slots.get(slot_key)
        if prev is not None and prev.get("slot_root") == slot_root:
            prev_dev, prev_ino = prev.get("slot_root_dev"), prev.get("slot_root_ino")
            if type(prev_dev) is int and type(prev_ino) is int:
                return prev_dev, prev_ino
        self._close_pinned_slot_fd(slot_key)
        pinned = _open_owned_dir_pin(slot_root)
        if pinned is None:
            return None, None
        fd, dev, ino = pinned
        self._pinned_slot_fds[slot_key] = fd
        return dev, ino

    def prepare_slot(self, slot_key: str, *, container_name: str, slot_root: str = "") -> None:
        """Persist intended slot BEFORE open_slot() acquires any profile lease in worker_leases."""
        root_dev, root_ino = self._slot_root_identity(slot_key, slot_root)
        self.slots[slot_key] = {
            "status": _STATUS_LEASE_ACQUIRING,
            _KEY_CONTAINER_NAME: container_name,
            "cid": None,
            "grant_dir": "",
            "slot_root": slot_root,
            "slot_root_dev": root_dev,
            "slot_root_ino": root_ino,
            _KEY_LEASE_RELEASED: False,
        }
        self._persist()

    def begin_slot_create(self, slot_key: str, *, container_name: str, grant_dir: str = "", slot_root: str = "") -> None:
        """Persist in-flight container creation BEFORE invoking podman create."""
        root_dev, root_ino = self._slot_root_identity(slot_key, slot_root)
        self.slots[slot_key] = {
            "status": _STATUS_CREATING,
            _KEY_CONTAINER_NAME: container_name,
            "cid": None,
            "grant_dir": grant_dir,
            "slot_root": slot_root,
            "slot_root_dev": root_dev,
            "slot_root_ino": root_ino,
            _KEY_LEASE_RELEASED: False,
        }
        self._persist()

    def finish_slot_create(self, slot_key: str, cid: str) -> None:
        """Record verified 64-hex container ID once podman create succeeds."""
        if not _HEX64.fullmatch(cid):
            raise CleanupOwnerError("invalid container ID")
        entry = self.slots.setdefault(
            slot_key,
            {
                "status": _STATUS_CREATING,
                _KEY_CONTAINER_NAME: "",
                "cid": None,
                "grant_dir": "",
                "slot_root": "",
                _KEY_LEASE_RELEASED: False,
            },
        )
        entry["status"] = _STATUS_CREATED
        entry["cid"] = cid
        self.owned_cids.add(cid)
        self._persist()

    def mark_lease_released(self, slot_key: str) -> None:
        """Record exact profile lease release ONLY after foreground slot_cm.__exit__ completes."""
        entry = self.slots.get(slot_key)
        if entry is not None:
            entry["status"] = _STATUS_LEASE_RELEASED
            entry[_KEY_LEASE_RELEASED] = True
            self._persist()

    def _inspect_pod_details(self, pod_id: str) -> dict[str, object] | None:
        res = self._pm(["pod", "inspect", pod_id], timeout=10.0)
        if res.returncode != 0:
            return None
        try:
            parsed = json.loads(res.stdout.decode("utf-8"))
        except ValueError:
            return None
        entry = parsed[0] if isinstance(parsed, list) and parsed else parsed
        if not isinstance(entry, dict) or entry.get("Id") != pod_id:
            return None
        return entry

    def _inspect_volume_labels(self, name: str) -> dict[str, str] | None:
        res = self._pm(["volume", "inspect", name], timeout=10.0)
        if res.returncode != 0:
            return None
        try:
            parsed = json.loads(res.stdout.decode("utf-8"))
        except ValueError:
            return None
        entry = parsed[0] if isinstance(parsed, list) and parsed else parsed
        if not isinstance(entry, dict):
            return None
        labels = entry.get("Labels")
        return labels if isinstance(labels, dict) else {}

    def teardown(self) -> dict[str, object]:
        try:
            self._reconcile_slots()
            lock_target: Path | str | None = self._lock_helper_source or self._lock_helper
            if lock_target is not None and self._state_dir is not None:
                try:
                    with _LifecycleLock(lock_target, self._state_dir, self.instance):
                        self._teardown_pod_volume_worktree()
                except CleanupOwnerError:
                    self.ownership_uncertain = True
                    self.cleanup_errors.append("teardown_lifecycle_lock_failed")
            else:
                self._teardown_pod_volume_worktree()
            self._persist()
            return {
                "cleanup_verified": (not self.cleanup_errors) and (not self.ownership_uncertain),
                _KEY_UNCERTAIN: self.ownership_uncertain,
                "errors": list(self.cleanup_errors),
            }
        finally:
            self._close_all_pinned_slot_fds()

    def _confirm_absent(self, kind: str, target: str, error_code: str) -> bool:
        """Return True ONLY when podman `<kind> exists <target>` exits with explicit absence code 1."""
        res = self._pm([kind, "exists", target], timeout=10.0)
        if res.returncode == 1:
            return True
        self.ownership_uncertain = True
        self.cleanup_errors.append(error_code)
        return False

    def _teardown_pod_volume_worktree(self) -> None:
        if not self._teardown_pod():
            return
        self._teardown_volume()
        self._teardown_worktree()

    def _retire_unreleased_slot(self, slot_key: str, entry: dict[str, object]) -> None:
        status = entry.get("status")
        grant_dir = str(entry.get("grant_dir") or "")
        slot_root = str(entry.get("slot_root") or "")
        _revoke_grant_dir(grant_dir, slot_root=slot_root)
        if status == _STATUS_CREATED:
            cid = entry.get("cid")
            if not isinstance(cid, str) or not _HEX64.fullmatch(cid):
                self.cleanup_errors.append(f"invalid_container_id:{slot_key}")
            else:
                res = self._pm(["rm", "-f", cid], timeout=15.0)
                absent = self._confirm_absent("container", cid, f"container_remove_failed:{cid[:12]}")
                if res.returncode != 0 and absent:
                    # Container is confirmed absent (rc == 1); no extra remove error needed.
                    pass
        elif status == _STATUS_CREATING:
            self.cleanup_errors.append(f"slot_create_uncertain:{slot_key}")
        # Never delete slot_root or grant_dir while the profile lease in worker_leases is unreleased:
        # trusted lease recovery requires the original grant directory inodes to verify terminal state.
        self.ownership_uncertain = True
        self.cleanup_errors.append(f"lease_unreleased:{slot_key}")

    def _remove_released_slot_root(self, slot_key: str, entry: dict[str, object]) -> None:
        slot_root = str(entry.get("slot_root") or "")
        if not slot_root:
            self._close_pinned_slot_fd(slot_key)
            return
        want_dev = entry.get("slot_root_dev")
        want_ino = entry.get("slot_root_ino")
        if type(want_dev) is not int or type(want_ino) is not int:
            self._close_pinned_slot_fd(slot_key)
            self.ownership_uncertain = True
            self.cleanup_errors.append(f"slot_root_identity_unknown:{slot_key}")
            return
        try:
            outcome = _remove_pinned_dir(Path(slot_root), want_dev, want_ino)
        finally:
            self._close_pinned_slot_fd(slot_key)
        if outcome == "replaced":
            self.ownership_uncertain = True
            self.cleanup_errors.append(f"slot_root_identity_mismatch:{slot_key}")
        elif outcome == "error":
            self.cleanup_errors.append(f"slot_root_remove_failed:{slot_key}")

    def _reconcile_slots(self) -> None:
        for slot_key in reversed(list(self.slots)):
            entry = self.slots[slot_key]
            if entry.get(_KEY_LEASE_RELEASED) is True:
                self._remove_released_slot_root(slot_key, entry)
                continue
            self._retire_unreleased_slot(slot_key, entry)

    def _pod_has_untracked_members(self, details: dict[str, object]) -> bool:
        infra_id = details.get("InfraContainerID")
        containers = details.get("Containers")
        if not isinstance(infra_id, str) or not _HEX64.fullmatch(infra_id) or not isinstance(containers, list) or not containers:
            return True
        saw_infra = False
        for member in containers:
            if not isinstance(member, dict):
                return True
            mid = member.get("Id")
            if not isinstance(mid, str) or not _HEX64.fullmatch(mid):
                return True
            if mid == infra_id:
                saw_infra = True
                continue
            if mid not in self.owned_cids:
                return True
        return not saw_infra

    def _teardown_pod(self) -> bool:
        if self.pod_id is None:
            return True
        details = self._inspect_pod_details(self.pod_id)
        if details is None:
            return self._confirm_absent("pod", self.pod_id, "pod_inspect_failed")
        inspected_id = details.get("Id")
        if not isinstance(inspected_id, str) or inspected_id != self.pod_id:
            self.ownership_uncertain = True
            self.cleanup_errors.append("pod_id_mismatch")
            return False
        labels = details.get("Labels") if isinstance(details.get("Labels"), dict) else {}
        if labels.get(PROOF_OWNER_LABEL) != self.run_id:
            self.ownership_uncertain = True
            self.cleanup_errors.append("pod_owner_label_mismatch")
            return False
        if self._pod_has_untracked_members(details):
            self.ownership_uncertain = True
            self.cleanup_errors.append("pod_has_untracked_members")
            return False
        res = self._pm(["pod", "rm", "-f", self.pod_id], timeout=20.0)
        if res.returncode != 0 or not self._confirm_absent("pod", self.pod_id, "pod_remove_failed"):
            if "pod_remove_failed" not in self.cleanup_errors:
                self.cleanup_errors.append("pod_remove_failed")
            return False
        return True

    def _teardown_volume(self) -> None:
        if not self.volume_owned:
            return
        labels = self._inspect_volume_labels(self.volume_name)
        if labels is None:
            self._confirm_absent("volume", self.volume_name, "volume_inspect_failed")
            return
        if labels.get(PROOF_OWNER_LABEL) != self.run_id:
            self.ownership_uncertain = True
            self.cleanup_errors.append("volume_owner_label_mismatch")
            return
        res = self._pm(["volume", "rm", self.volume_name], timeout=15.0)
        if res.returncode != 0 or not self._confirm_absent("volume", self.volume_name, "volume_remove_failed"):
            if "volume_remove_failed" not in self.cleanup_errors:
                self.cleanup_errors.append("volume_remove_failed")

    def _teardown_worktree(self) -> None:
        if not self.worktree_owned or self.worktree_dev_ino is None:
            return
        want_dev, want_ino = self.worktree_dev_ino
        script = (
            "import os, stat, sys\n"
            "leaf, dev_s, ino_s = sys.argv[1], sys.argv[2], sys.argv[3]\n"
            "want = (int(dev_s), int(ino_s))\n"
            "def _clear_dir_fd(dir_fd):\n"
            "    for entry in os.listdir(dir_fd):\n"
            "        st = os.stat(entry, dir_fd=dir_fd, follow_symlinks=False)\n"
            "        if stat.S_ISDIR(st.st_mode):\n"
            "            child_fd = os.open(entry, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)\n"
            "            try:\n"
            "                _clear_dir_fd(child_fd)\n"
            "            finally:\n"
            "                os.close(child_fd)\n"
            "            os.rmdir(entry, dir_fd=dir_fd)\n"
            "        else:\n"
            "            os.unlink(entry, dir_fd=dir_fd)\n"
            "wt_fd = os.open('/sandbox/wt', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)\n"
            "try:\n"
            "    leaf_fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=wt_fd)\n"
            "    try:\n"
            "        fst = os.fstat(leaf_fd)\n"
            "        if not stat.S_ISDIR(fst.st_mode) or (fst.st_dev, fst.st_ino) != want:\n"
            "            raise SystemExit(2)\n"
            "        _clear_dir_fd(leaf_fd)\n"
            "    finally:\n"
            "        os.close(leaf_fd)\n"
            "    st2 = os.stat(leaf, dir_fd=wt_fd, follow_symlinks=False)\n"
            "    if not stat.S_ISDIR(st2.st_mode) or (st2.st_dev, st2.st_ino) != want:\n"
            "        raise SystemExit(2)\n"
            "    os.rmdir(leaf, dir_fd=wt_fd)\n"
            "finally:\n"
            "    os.close(wt_fd)\n"
        )
        leaf = self.cwd.split("/", 1)[1]
        res = self._pm(
            [
                "run", "--rm", "--pull=never", "--network=none", "--http-proxy=false",
                "--cap-drop=ALL", "--security-opt=no-new-privileges",
                "--security-opt", f"label=level:{self.level}",
                "--pids-limit=64", "--memory=128m",
                "-v", f"{self.sandbox_dir}:/sandbox",
                "--entrypoint", "python3",
                self.agent_image_id, "-I", "-c", script, leaf, str(want_dev), str(want_ino),
            ],
            timeout=20.0,
        )
        if res.returncode != 0:
            self.cleanup_errors.append("worktree_remove_failed")


def _send_line(sock: socket.socket, payload: dict[str, object]) -> None:
    data = (json.dumps(payload, ensure_ascii=True) + "\n").encode("ascii")
    sock.sendall(data)


def _lifeline_closed(lifeline_fd: int) -> bool:
    try:
        return not os.read(lifeline_fd, 64)
    except OSError:
        return True


def _recv_line(sock: socket.socket, lifeline_fd: int) -> dict[str, object] | None:
    buf = bytearray()
    while True:
        ready, _, _ = select.select([sock, lifeline_fd], [], [], 0.25)
        if lifeline_fd in ready and _lifeline_closed(lifeline_fd):
            return None
        if sock not in ready:
            continue
        chunk = sock.recv(4096)
        if not chunk:
            return None
        buf.extend(chunk)
        if len(buf) > _MAX_CMD_BYTES:
            raise CleanupOwnerError("control frame exceeds limit")
        if b"\n" in buf:
            line, _, _ = bytes(buf).partition(b"\n")
            return json.loads(line.decode("ascii"))


def _handle_slot_op(op: str, msg: dict[str, object], journal: _OwnershipJournal | None) -> None:
    if journal is None:
        raise CleanupOwnerError("not created")
    slot_key = str(msg["slot_key"])
    if op == _OP_PREPARE_SLOT:
        journal.prepare_slot(
            slot_key,
            container_name=str(msg.get(_KEY_CONTAINER_NAME) or ""),
            slot_root=str(msg.get("slot_root") or ""),
        )
    elif op == _OP_BEGIN_SLOT:
        journal.begin_slot_create(
            slot_key,
            container_name=str(msg.get(_KEY_CONTAINER_NAME) or ""),
            grant_dir=str(msg.get("grant_dir") or ""),
            slot_root=str(msg.get("slot_root") or ""),
        )
    elif op == _OP_FINISH_SLOT:
        journal.finish_slot_create(slot_key, str(msg["cid"]))
    elif op == _OP_LEASE_RELEASED:
        journal.mark_lease_released(slot_key)


def _dispatch_owner_op(
    sock: socket.socket,
    msg: dict[str, object],
    state: dict[str, _OwnershipJournal | None],
) -> bool:
    op = str(msg.get("op") or "")
    journal = state["journal"]
    if op == "create":
        if journal is not None:
            raise CleanupOwnerError("already created")
        new_journal = _build_journal_from_msg(msg)
        # Install BEFORE first side effect so partial create or lost reply still tears down!
        state["journal"] = new_journal
        info = new_journal.create_under_lock(Path(str(msg["lock_helper"])), Path(str(msg["state_dir"])))
        _send_line(sock, {"ok": True, "result": info})
        return False
    if op in (_OP_PREPARE_SLOT, _OP_BEGIN_SLOT, _OP_FINISH_SLOT, _OP_LEASE_RELEASED):
        _handle_slot_op(op, msg, journal)
        _send_line(sock, {"ok": True})
        return False
    if op == "teardown":
        result = (
            journal.teardown()
            if journal is not None
            else {"cleanup_verified": True, _KEY_UNCERTAIN: False, "errors": []}
        )
        _send_line(sock, {"ok": True, "result": result})
        return True
    _send_line(sock, {"ok": False, "error": "unknown_op"})
    return False


def _owner_loop(control_fd: int, lifeline_fd: int) -> int:
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    sock = socket.socket(fileno=control_fd)
    state: dict[str, _OwnershipJournal | None] = {"journal": None}
    torn_down = False
    try:
        while True:
            msg = _recv_line(sock, lifeline_fd)
            if msg is None:
                break
            try:
                done = _dispatch_owner_op(sock, msg, state)
            except Exception as exc:
                with suppress(OSError):
                    _send_line(sock, {"ok": False, "error": str(exc)})
                continue
            if done:
                torn_down = True
                break
    finally:
        journal = state["journal"]
        if journal is not None and not torn_down:
            with suppress(Exception):
                journal.teardown()
        with suppress(OSError):
            sock.close()
        with suppress(OSError):
            os.close(lifeline_fd)
    return 0


def _build_journal_from_msg(msg: dict[str, object]) -> _OwnershipJournal:
    run_id = str(msg["run_id"])
    instance = str(msg["instance"])
    level = str(msg["level"])
    agent_image_id = str(msg["agent_image_id"])
    if not _RUN_ID_RE.fullmatch(run_id) or not _INST_RE.fullmatch(instance):
        raise CleanupOwnerError("invalid run_id or disposable instance name")
    if not _LEVEL_RE.fullmatch(level) or not _HEX64.fullmatch(agent_image_id):
        raise CleanupOwnerError("invalid SELinux level or pinned agent image ID")
    raw_journal = msg.get("journal_path")
    return _OwnershipJournal(
        JournalSpec(
            run_id=run_id,
            instance=instance,
            pod_name=f"oc-{instance}",
            volume_name=f"oc-{instance}-openai-home",
            sandbox_dir=Path(str(msg["sandbox_dir"])),
            cwd=f"wt/{instance}",
            level=level,
            agent_image_id=agent_image_id,
            journal_path=Path(str(raw_journal)) if raw_journal else None,
        )
    )


class DetachedShellCleanupOwner:
    """Client handle to the SIGKILL-surviving detached cleanup-only owner process."""

    def __init__(self, *, helper_module: Path | None = None):
        self._module = helper_module or Path(__file__).resolve()
        self._proc: subprocess.Popen[bytes] | None = None
        self._sock: socket.socket | None = None
        self._life_w: int | None = None

    def start(self) -> None:
        parent_sock, child_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        life_r, life_w = os.pipe()
        os.set_inheritable(child_sock.fileno(), True)
        os.set_inheritable(life_r, True)
        try:
            proc = subprocess.Popen(
                [
                    sys.executable,
                    "-IB",
                    str(self._module),
                    "--owner",
                    str(child_sock.fileno()),
                    str(life_r),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                pass_fds=(child_sock.fileno(), life_r),
                start_new_session=True,
                close_fds=True,
            )
        except BaseException:
            parent_sock.close()
            child_sock.close()
            os.close(life_r)
            os.close(life_w)
            raise
        child_sock.close()
        os.close(life_r)
        self._proc = proc
        self._sock = parent_sock
        self._life_w = life_w

    def _rpc(self, payload: dict[str, object], *, timeout: float = 45.0) -> dict[str, object]:
        if self._sock is None:
            raise CleanupOwnerError("cleanup owner not started")
        self._sock.settimeout(timeout)
        _send_line(self._sock, payload)
        buf = bytearray()
        while b"\n" not in buf:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise CleanupOwnerError("cleanup owner disconnected unexpectedly")
            buf.extend(chunk)
            if len(buf) > _MAX_CMD_BYTES:
                raise CleanupOwnerError("cleanup owner reply exceeds limit")
        line, _, _ = bytes(buf).partition(b"\n")
        reply = json.loads(line.decode("ascii"))
        if not reply.get("ok"):
            raise CleanupOwnerError(str(reply.get("error", "cleanup owner failed")))
        return reply

    def create(
        self,
        *,
        spec: JournalSpec,
        lock_helper: Path,
        state_dir: Path,
    ) -> dict[str, object]:
        reply = self._rpc({
            "op": "create",
            "run_id": spec.run_id,
            "instance": spec.instance,
            "sandbox_dir": str(spec.sandbox_dir),
            "level": spec.level,
            "agent_image_id": spec.agent_image_id,
            "journal_path": str(spec.journal_path) if spec.journal_path else "",
            "lock_helper": str(lock_helper),
            "state_dir": str(state_dir),
        })
        return dict(reply["result"])

    def prepare_slot(self, slot_key: str, *, container_name: str, slot_root: str = "") -> None:
        self._rpc({
            "op": _OP_PREPARE_SLOT,
            "slot_key": slot_key,
            _KEY_CONTAINER_NAME: container_name,
            "slot_root": slot_root,
        })

    def begin_slot_create(self, slot_key: str, *, container_name: str, grant_dir: str = "", slot_root: str = "") -> None:
        self._rpc({
            "op": _OP_BEGIN_SLOT,
            "slot_key": slot_key,
            _KEY_CONTAINER_NAME: container_name,
            "grant_dir": grant_dir,
            "slot_root": slot_root,
        })

    def finish_slot_create(self, slot_key: str, cid: str) -> None:
        self._rpc({"op": _OP_FINISH_SLOT, "slot_key": slot_key, "cid": cid})

    def mark_lease_released(self, slot_key: str) -> None:
        self._rpc({"op": _OP_LEASE_RELEASED, "slot_key": slot_key})

    def teardown(self) -> dict[str, object]:
        try:
            reply = self._rpc({"op": "teardown"}, timeout=60.0)
            return dict(reply["result"])
        finally:
            self.close()

    def close(self) -> None:
        if self._sock is not None:
            with suppress(OSError):
                self._sock.close()
            self._sock = None
        if self._life_w is not None:
            with suppress(OSError):
                os.close(self._life_w)
            self._life_w = None
        if self._proc is not None:
            with suppress(OSError, subprocess.TimeoutExpired):
                self._proc.wait(timeout=10)
            self._proc = None


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--owner":
        raise SystemExit(_owner_loop(int(sys.argv[2]), int(sys.argv[3])))
    raise SystemExit(2)
