"""Private, owner-bound placement handoff for managed interactive launches."""

from contextlib import contextmanager, ExitStack, nullcontext
import fcntl
import os
from pathlib import Path
import re
import select
import signal
import stat
import termios
import threading
import time
from types import SimpleNamespace

from oc_providers.catalog import (
    LaunchRefusedError,
    plan_interactive_launch,
    preflight_admission_route,
    revalidate_interactive_launch,
    snapshot_launch_selections,
)
from oc_providers.config import load_provider_config_with_digest

from .cli import StreamTerminal
from .connection_state import decode_json
from .managed.runtime import IMAGE_ID, host_operation_budget
from . import session_broker as broker

MAX_FRAME = 64 * 1024
ADMISSION_SECONDS = 285
SETUP_SECONDS = 3600
CREATION_SECONDS = 115
CLEANUP_SECONDS = 25
_INTENT_KEYS = frozenset({
    "instance", "cwd", "provider_filter", "cli_ui_mode", "workspace_mode", "caller_cwd",
    "lifecycle_dir", "sandbox", "worktree_repo", "worktree_branch",
})
_WORKTREE_BRANCH = re.compile(r"[A-Za-z0-9._/@+-]+")
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class AdmissionChannel:
    """Receive two delimited frames, then require a live, silent owner until exit."""

    def __init__(self, reader: int, writer: int, parent: int):
        self.reader = reader
        self.writer = writer
        self.parent = parent
        self.cancelled = threading.Event()
        self._finished = threading.Event()
        self._watcher = None

    def _owner_missing(self) -> bool:
        return os.getppid() != self.parent

    def checkpoint(self):
        if self.cancelled.is_set() or self._owner_missing() or select.select([self.reader], [], [], 0)[0]:
            self.cancelled.set()
            raise LaunchRefusedError("launch_owner_lost", "Managed launch cancelled or owner channel closed.")

    def read_frame(self, deadline: float):
        buffered = bytearray()
        while not self.cancelled.is_set() and (remaining := deadline - time.monotonic()) > 0:
            if self._owner_missing():
                self.cancelled.set()
                break
            if not select.select([self.reader], [], [], min(remaining, 0.1))[0]:
                continue
            chunk = os.read(self.reader, min(4096, MAX_FRAME + 1 - len(buffered)))
            if not chunk:
                self.cancelled.set()
                break
            buffered.extend(chunk)
            if len(buffered) > MAX_FRAME:
                raise ValueError("Oversized managed launch frame")
            if b"\n" in buffered:
                if buffered.count(b"\n") != 1 or not buffered.endswith(b"\n"):
                    raise ValueError("Unexpected data after managed launch frame")
                self.checkpoint()
                return decode_json(buffered[:-1])
        raise LaunchRefusedError("launch_interrupted", "Managed launch cancelled or preparation timed out.")

    def acknowledge(self, message: bytes, *, final: bool = False):
        self.checkpoint()
        if not select.select([], [self.writer], [], 0)[1]:
            raise ValueError("Managed launch acknowledgment channel unavailable")
        if os.write(self.writer, message) != len(message):
            raise ValueError("Managed launch acknowledgment was incomplete")
        if final:
            os.close(self.writer)

    def watch_owner(self):
        self._finished.clear()

        def watch():
            while not self._finished.is_set():
                if self._owner_missing() or select.select([self.reader], [], [], 0.1)[0]:
                    self.cancelled.set()
                    break

        self._watcher = threading.Thread(target=watch, name="oc-launch-owner", daemon=True)
        self._watcher.start()

    def finish(self):
        self._finished.set()
        if self._watcher is not None:
            self._watcher.join()
            self._watcher = None


class AdmissionTerminal(StreamTerminal):
    """Use the same foreground prompts and allow the owner to interrupt idle reads."""

    def __init__(self, terminal: StreamTerminal, channel: AdmissionChannel, deadline: float):
        super().__init__(terminal.reader, terminal.writer, terminal.errors)
        self.channel = channel
        self.deadline = deadline

    def _read_bounded_line(self, fd: int, max_len: int) -> bytes | None:
        answer = bytearray()
        while len(answer) < max_len:
            self.channel.checkpoint()
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise LaunchRefusedError("launch_admission_timeout", "Managed launch admission timed out.")
            ready, _, _ = select.select([self.channel.reader, fd], [], [], min(remaining, 0.1))
            self.channel.checkpoint()
            if fd not in ready:
                continue
            char = os.read(fd, 1)
            if not char:
                return None
            answer.extend(char)
            if char == b"\n":
                return bytes(answer)
        termios.tcflush(fd, termios.TCIFLUSH)
        return None


def _validate_intent(raw):
    if type(raw) is not dict or set(raw) != _INTENT_KEYS or any(type(v) is not str for v in raw.values()):
        raise ValueError("Invalid managed launch intent")
    broker._validate_session_instance(raw["instance"])
    if (
        not broker._valid_relpath(raw["cwd"])
        or not broker._valid_sandbox_path(raw["sandbox"])
        or raw["workspace_mode"] not in ("explicit", "automatic")
    ):
        raise ValueError("Malformed managed launch workspace selector")
    if raw["workspace_mode"] == "automatic":
        default = "construct" if raw["instance"] == "default" else f"wt/{raw['instance']}"
        if raw["cwd"] != default:
            raise ValueError("Malformed initial automatic workspace")
    for name in ("caller_cwd", "lifecycle_dir"):
        value = raw[name]
        if not value.startswith("/") or os.path.normpath(value) != value or any(c in value for c in "\x00\n\r"):
            raise ValueError("Malformed managed launch path")
    if any(raw[name] for name in ("worktree_repo", "worktree_branch")) and (
        not broker._valid_relpath(raw["worktree_repo"]) or not _WORKTREE_BRANCH.fullmatch(raw["worktree_branch"])
    ):
        raise ValueError("Malformed worktree request")
    return broker._validate_spec_options(raw)


@contextmanager
def _owned_state_dir(state: Path, *, sandbox: Path):
    if state == sandbox or state.is_relative_to(sandbox) or sandbox.is_relative_to(state):
        raise ValueError("Lifecycle state overlaps the sandbox")
    for part in (*reversed(state.parents), state):
        info = part.lstat()
        sticky_ancestor = part != state and info.st_uid in (0, 65534) and info.st_mode & stat.S_ISVTX
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid not in (os.geteuid(), 0) and not sticky_ancestor
            or info.st_mode & 0o022 and not sticky_ancestor
        ):
            raise ValueError("Untrusted lifecycle state path")
    fd = os.open(state, _DIR_FLAGS)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o022 or not os.path.samestat(info, state.lstat()):
            raise ValueError("Untrusted lifecycle state directory")
        yield fd
    finally:
        os.close(fd)


def _owned_file(directory: int, name: str):
    fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    try:
        _verify_owned_file(fd, directory, name)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _verify_owned_file(fd: int, directory: int, name: str):
    info = os.fstat(fd)
    named = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
        or not os.path.samestat(info, named)
    ):
        raise ValueError("Untrusted managed launch state file")
    return info


def _read_worktree(intent: dict, sandbox: Path) -> tuple[str, str, str] | None:
    with ExitStack() as files:
        try:
            state = files.enter_context(_owned_state_dir(Path(intent["lifecycle_dir"]), sandbox=sandbox))
            directory = os.open("worktrees", _DIR_FLAGS, dir_fd=state)
            files.callback(os.close, directory)
            info = os.fstat(directory)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError("Untrusted worktree record directory")
            fd = _owned_file(directory, intent["instance"])
            files.callback(os.close, fd)
        except FileNotFoundError:
            return None
        initial = os.fstat(fd)
        raw = os.read(fd, 4097)
        final = _verify_owned_file(fd, directory, intent["instance"])
        if len(raw) > 4096 or len(raw) != initial.st_size or initial.st_mtime_ns != final.st_mtime_ns:
            raise ValueError("Managed launch worktree record changed")
    cwd, repo, branch, end = raw.decode("ascii").split("\n")
    if end or not broker._valid_relpath(cwd) or not broker._valid_relpath(repo) or not _WORKTREE_BRANCH.fullmatch(branch):
        raise ValueError("Malformed managed launch worktree record")
    return cwd, repo, branch


def _expected_workspace(intent: dict, sandbox: Path):
    cwd = intent["cwd"]
    repo = intent["worktree_repo"]
    branch = intent["worktree_branch"]
    if intent["workspace_mode"] == "automatic":
        saved = _read_worktree(intent, sandbox)
        if saved is not None:
            cwd, saved_repo, saved_branch = saved
            repo, branch = (repo, branch) if repo else (saved_repo, saved_branch)
    return cwd, (cwd, repo, branch) if repo else None


def _verify_workspace(spec: dict, intent: dict, sandbox: Path, expected):
    cwd, expected_record = expected
    automatic = intent["workspace_mode"] == "automatic"
    record = _read_worktree(intent, sandbox) if automatic or expected_record is not None else None
    if automatic and expected_record is None and record is not None:
        # Bash discovers repositories inside a throwaway sandbox container.
        # Accept its recorded selection only when it matches the original selector.
        resolved, repo, branch = record
        if (
            intent["instance"] == "default" or branch != intent["instance"]
            or repo == "wt" or repo.startswith("wt/")
            or resolved != f"wt/{repo}/{branch}"
            or not Path(intent["caller_cwd"]).is_relative_to(sandbox / repo)
        ):
            raise ValueError("Managed launch worktree differs from the approved selector")
        cwd, expected_record = resolved, record
    if (
        any(spec[key] != intent[key] for key in ("instance", "provider_filter", "cli_ui_mode", "sandbox"))
        or spec["cwd"] != cwd
        or Path(spec["sandbox"]).resolve() != sandbox
    ):
        raise ValueError("Managed launch placement differs from the approved request")
    if (
        (expected_record is not None or intent["workspace_mode"] == "automatic")
        and record != expected_record
    ):
        raise ValueError("Managed launch worktree record changed")
    with ExitStack() as opened:
        directory = os.open(sandbox, _DIR_FLAGS)
        opened.callback(os.close, directory)
        for part in cwd.split("/"):
            directory = os.open(part, _DIR_FLAGS, dir_fd=directory)
            opened.callback(os.close, directory)
        if not os.path.samestat(os.fstat(directory), (sandbox / cwd).lstat()):
            raise ValueError("Managed launch workspace changed")
        selected = os.fstat(directory)
        return cwd, record, selected.st_dev, selected.st_ino


def _parent_holds_guard(pid: int, parent: int, expected: os.stat_result) -> bool:
    proc = Path(f"/proc/{pid}")
    try:
        if proc.stat().st_uid != os.geteuid():
            return False
        status = (proc / "stat").read_text(encoding="ascii").rsplit(")", 1)[1].split()
        if int(status[1]) != parent:
            return False
        for entry in (proc / "fd").iterdir():
            try:
                if not os.path.samestat(entry.stat(), expected):
                    continue
                for line in (proc / "fdinfo" / entry.name).read_text(encoding="ascii").splitlines():
                    fields = line.split()
                    if fields[:1] == ["lock:"] and fields[2:6] == ["FLOCK", "ADVISORY", "READ", str(pid)]:
                        return True
            except FileNotFoundError:
                continue
    except (OSError, IndexError, ValueError):
        return False
    return False


@contextmanager
def _lifecycle_guard(intent, sandbox, parent, pid, checkpoint):
    with _owned_state_dir(Path(intent["lifecycle_dir"]), sandbox=sandbox) as state:
        fd = _owned_file(state, "lifecycle.lock")
        try:
            while True:
                checkpoint()
                try:
                    fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    time.sleep(0.05)
            info = _verify_owned_file(fd, state, "lifecycle.lock")
            if not _parent_holds_guard(pid, parent, info) or os.getppid() != parent:
                raise ValueError("Launcher did not retain the shared lifecycle guard")
            checkpoint()
            yield
        finally:
            os.close(fd)


def _validate_placement(raw):
    if type(raw) is not dict or set(raw) != {"spec", "pod_id", "lifecycle_pid"}:
        raise ValueError("Invalid managed launch placement")
    pod_id = raw["pod_id"]
    pid = raw["lifecycle_pid"]
    if type(pid) is str and re.fullmatch(r"[1-9][0-9]{0,9}", pid):
        pid = int(pid)
    if type(pod_id) is not str or not IMAGE_ID.fullmatch(pod_id) or type(pid) is not int or not 1 < pid < 2**31:
        raise ValueError("Malformed managed launch placement")
    return broker._validate_spec(raw["spec"]), pod_id, pid


def _report_prepared_workspace(cwd, checkpoint):
    # A fresh open description avoids toggling blocking mode on the shell's terminal.
    fd = os.open("/dev/tty", os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        pending = memoryview(f"Prepared workspace: /sandbox/{cwd}\n".encode("ascii"))
        while pending:
            checkpoint()
            if not select.select([], [fd], [], 0.1)[1]:
                continue
            try:
                pending = pending[os.write(fd, pending):]
            except BlockingIOError:
                continue
    finally:
        os.close(fd)


@contextmanager
def _deferred_guard_errors(terminal):
    errors = []
    try:
        yield SimpleNamespace(error=errors.append)
    finally:
        for message in errors:
            terminal.error(message)


def run_admission_session(channel: AdmissionChannel, terminal: StreamTerminal) -> int:
    def cancel(_signal, _frame):
        channel.cancelled.set()

    signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    original_signals = [signal.signal(signum, cancel) for signum in signals]
    try:
        return _run_admission_session(channel, terminal)
    except (ValueError, OSError):
        terminal.error("Managed launch could not verify its approved placement or owner. Start a fresh launch.")
        return 1
    except Exception as error:
        return broker._report_session_error(terminal, error)
    finally:
        channel.finish()
        for signum, handler in zip(signals, original_signals):
            signal.signal(signum, handler)


def _run_admission_session(channel, terminal):
    deadline = time.monotonic() + ADMISSION_SECONDS
    intent = _validate_intent(channel.read_frame(deadline))
    channel.watch_owner()
    sandbox = Path(intent["sandbox"]).resolve()
    expected = _expected_workspace(intent, sandbox)
    admission_terminal = AdmissionTerminal(terminal, channel, deadline)
    with host_operation_budget(deadline, channel.cancelled):
        qualification_error = broker._qualify_session(admission_terminal)
    if qualification_error:
        return qualification_error

    channel.checkpoint()
    config, digest = load_provider_config_with_digest()
    adapters, lock_dir = broker._resolve_adapters_and_lock_dir(None, None, None)
    selection = snapshot_launch_selections(intent["provider_filter"], adapters)
    workspace = (
        f"/sandbox/{intent['cwd']}" if intent["workspace_mode"] == "explicit"
        else f"automatic selection for {ascii(intent['caller_cwd'])}"
    )
    plan = plan_interactive_launch(
        instance_name=intent["instance"], cwd=intent["cwd"], provider_filter=intent["provider_filter"],
        cli_ui_mode=intent["cli_ui_mode"], config=config, adapters=adapters, terminal=admission_terminal,
        workspace_description=workspace,
        preflight=lambda adapter, spec: preflight_admission_route(
            adapter, spec, deadline=deadline, cancelled=channel.cancelled,
        ),
    )
    def verify_config_and_selection():
        if load_provider_config_with_digest() != (config, digest) or snapshot_launch_selections(
            intent["provider_filter"], adapters
        ) != selection:
            raise LaunchRefusedError("launch_config_drift", "Provider configuration or selection changed. Start a fresh launch.")

    verify_config_and_selection()
    if time.monotonic() >= deadline:
        raise LaunchRefusedError("launch_admission_timeout", "Managed launch admission timed out.")
    channel.finish()
    channel.acknowledge(b"ADMITTED\n")
    spec, pod_id, pid = _validate_placement(channel.read_frame(time.monotonic() + SETUP_SECONDS))
    channel.watch_owner()
    with _deferred_guard_errors(terminal) as guarded_terminal, ExitStack() as creation:
        deadline = time.monotonic() + CREATION_SECONDS
        workspace = None

        def checkpoint():
            channel.checkpoint()
            if time.monotonic() >= deadline:
                raise LaunchRefusedError("launch_creation_timeout", "Managed launch timed out during guarded creation.")
            if workspace is not None and _verify_workspace(spec, intent, sandbox, expected) != workspace:
                raise ValueError("Managed launch workspace changed")

        creation.enter_context(_lifecycle_guard(intent, sandbox, channel.parent, pid, checkpoint))
        creation.enter_context(host_operation_budget(deadline, channel.cancelled))
        workspace = _verify_workspace(spec, intent, sandbox, expected)
        _report_prepared_workspace(spec["cwd"], checkpoint)
        verify_config_and_selection()
        revalidate_interactive_launch(
            plan, adapters, deadline=deadline, cancelled=channel.cancelled, checkpoint=checkpoint,
        )
        checkpoint()
        verify_config_and_selection()

        guard_held = True

        def created():
            nonlocal guard_held
            verify_config_and_selection()
            checkpoint()
            channel.acknowledge(b"CREATED\n", final=True)
            creation.close()
            guard_held = False

        def cleanup_budget():
            return (
                host_operation_budget(time.monotonic() + CLEANUP_SECONDS)
                if guard_held else nullcontext()
            )

        return broker._run_admitted_session(
            spec, plan, adapters, lock_dir, guarded_terminal, None,
            stop_event=channel.cancelled,
            prepared_pod=pod_id, checkpoint=checkpoint, before_lease=verify_config_and_selection,
            created=created, cleanup_budget=cleanup_budget,
        )
