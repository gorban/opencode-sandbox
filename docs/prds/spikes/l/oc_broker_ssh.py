"""Host-mediated fixed-argv SSH command broker for PRD L1 (Path A).

Pure Python standard library only. Never exposes SSH keys or SSH_AUTH_SOCK to
the sandbox container. Executes strictly validated read-only presets with
DNS-pinned HostName/HostKeyAlias,
-F /dev/null non-overridable OpenSSH hardening options, shlex.quote() remote
token protection, owner-only known_hosts verification, streaming bounded memory
output/timeout enforcement, lease-revoke process-group kill, and canary scrubbing.
Custom APPLY_ONCE commands are available only to injected offline fixture runners.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import shutil
import signal
import subprocess
import threading
import time
from typing import Any

from oc_broker_common import (
    BrokerAuthError,
    BrokerError,
    BrokerLease,
    BrokerPolicyError,
    OverlapCanaryScanner,
    resolve_and_validate_ip,
    validate_allowed_cidrs,
)
from oc_schema import (
    PolicyError,
    SchemaError,
    assert_trusted_dir,
    check_not_in_sandbox,
    read_regular_no_follow,
)

DEFAULT_SSH_TIMEOUT = 15.0
DEFAULT_CONNECT_TIMEOUT = 10
DEFAULT_MAX_OUTPUT_BYTES = 262_144
MAX_KNOWN_HOSTS_BYTES = 262_144
MAX_IDENTITY_FILE_BYTES = 16_384
MAX_JOURNALCTL_LINES = 500
MAX_CUSTOM_ARGV_TOKENS = 64
MAX_TOKEN_LEN = 256
STREAM_READ_CHUNK = 8192

SSH_USER_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$", re.ASCII)
DNS_HOST_RE = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
    re.ASCII,
)
UNIT_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,127}$", re.ASCII)
DF_PATH_RE = re.compile(r"^/[a-zA-Z0-9._/@+-]{0,255}$", re.ASCII)
PODMAN_FILTER_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$", re.ASCII)


@dataclass(frozen=True, slots=True)
class SshTarget:
    """Validated remote SSH host target, pinned known_hosts, and optional public/key IdentityFile."""

    user: str
    host: str
    known_hosts_path: Path
    port: int = 22
    allowed_cidrs: tuple[str, ...] = ()
    identity_file: Path | None = None
    allowed_presets: frozenset[str] = frozenset()
    lease: BrokerLease | None = None

    @classmethod
    def from_route(
        cls, route: Mapping[str, Any], *, known_hosts_path: Path, lease: BrokerLease
    ) -> SshTarget:
        """Lower host-only compiled policy for this exact job lease."""
        if (route["kind"], route["credential_delivery"], route["access_mode"]) != (
            "ssh", "host-brokered", "ro"
        ):
            raise BrokerPolicyError("Expected a host-brokered read-only SSH route")
        upstream = route["upstream"]
        return cls(
            user=upstream["user"], host=upstream["host"], port=upstream["port"],
            known_hosts_path=known_hosts_path, allowed_cidrs=tuple(route["allowed_cidrs"]),
            allowed_presets=frozenset(route["allowed_presets"]), lease=lease,
        )


@dataclass(frozen=True, slots=True)
class SshRawOutput:
    """Raw subprocess result returned by an injectable runner."""

    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True, slots=True)
class SshExecResult:
    """Scrubbed, bounded SSH command execution result."""

    returncode: int
    stdout: bytes
    stderr: bytes
    truncated: bool = False


SshRunner = Callable[..., SshRawOutput]


def _check_no_ctrl_or_surrogate(value: str, label: str) -> None:
    for ch in value:
        code = ord(ch)
        if code < 0x20 or code == 0x7F or 0xD800 <= code <= 0xDFFF:
            raise BrokerPolicyError(f"Illegal control or surrogate character in {label}")


def _kill_proc_group(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        try:
            proc.kill()
        except OSError:
            pass


@dataclass
class _StreamState:
    scanner: OverlapCanaryScanner
    buf: bytearray
    truncated: bool = False


def _drain_stream_chunk(
    fd: int,
    state: _StreamState,
    max_output_bytes: int,
) -> tuple[bool, bool]:
    """Read one chunk, scan for canary, append up to cap; return (eof, overflowed)."""
    chunk = os.read(fd, STREAM_READ_CHUNK)
    if not chunk:
        tail = state.scanner.finish()
        if tail:
            _append_capped(state, tail, max_output_bytes)
        return True, state.truncated
    emitted = state.scanner.feed(chunk)
    if emitted:
        _append_capped(state, emitted, max_output_bytes)
    return False, state.truncated


def _append_capped(state: _StreamState, data: bytes, max_output_bytes: int) -> None:
    room = max_output_bytes - len(state.buf)
    if len(data) > room:
        if room > 0:
            state.buf.extend(data[:room])
        state.truncated = True
    else:
        state.buf.extend(data)


def _resolve_ssh_binary() -> str:
    for cand in ("/usr/bin/ssh", "/bin/ssh"):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    found = shutil.which("ssh", path="/usr/bin:/bin")
    if not found or not os.path.isabs(found):
        raise BrokerPolicyError("Unable to locate absolute trusted ssh binary under /usr/bin:/bin")
    return found


def _build_ssh_env() -> dict[str, str]:
    env: dict[str, str] = {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "SSH_ASKPASS_REQUIRE": "never",
    }
    home = os.environ.get("HOME")
    if home:
        env["HOME"] = home
    auth_sock = os.environ.get("SSH_AUTH_SOCK")
    if auth_sock:
        env["SSH_AUTH_SOCK"] = auth_sock
    return env


def _finalize_stream_states(states: tuple[_StreamState, ...], max_output_bytes: int) -> None:
    for state in states:
        tail = state.scanner.finish()
        if tail:
            _append_capped(state, tail, max_output_bytes)


def _run_streaming_subprocess(
    argv: list[str],
    *,
    timeout: float,
    max_output_bytes: int,
    canary_secrets: tuple[str, ...],
    lease: BrokerLease | None = None,
) -> SshExecResult:
    """Execute argv with shell=False, DEVNULL stdin, minimal env, bounded RAM, canary scan & revoke kill."""
    proc = subprocess.Popen(
        argv,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_build_ssh_env(),
        start_new_session=True,
    )
    revoked_ev = threading.Event()

    def _on_revoke() -> None:
        revoked_ev.set()
        _kill_proc_group(proc)

    if lease is not None:
        lease.add_revoke_callback(_on_revoke)

    sel = selectors.DefaultSelector()
    out_state = _StreamState(OverlapCanaryScanner(canary_secrets), bytearray())
    err_state = _StreamState(OverlapCanaryScanner(canary_secrets), bytearray())
    if proc.stdout is not None:
        sel.register(proc.stdout, selectors.EVENT_READ, data=out_state)
    if proc.stderr is not None:
        sel.register(proc.stderr, selectors.EVENT_READ, data=err_state)

    deadline = time.monotonic() + timeout
    try:
        _pump_subprocess_pipes(proc, sel, deadline, max_output_bytes, revoked_ev)
        if revoked_ev.is_set() or (lease is not None and not lease.is_active()):
            raise BrokerAuthError("lease_revoked_or_expired")
        _finalize_stream_states((out_state, err_state), max_output_bytes)
        rem = max(0.05, deadline - time.monotonic())
        try:
            rc = proc.wait(timeout=rem)
        except subprocess.TimeoutExpired as exc:
            _kill_proc_group(proc)
            proc.wait(timeout=1.0)
            raise BrokerError("SSH command timed out") from exc
        return SshExecResult(
            returncode=rc,
            stdout=bytes(out_state.buf),
            stderr=bytes(err_state.buf),
            truncated=out_state.truncated or err_state.truncated,
        )
    except Exception:
        _kill_proc_group(proc)
        try:
            proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass
        raise
    finally:
        sel.close()
        if proc.stdout is not None:
            proc.stdout.close()
        if proc.stderr is not None:
            proc.stderr.close()
        if lease is not None:
            lease.remove_revoke_callback(_on_revoke)


def _pump_subprocess_pipes(
    proc: subprocess.Popen[bytes],
    sel: selectors.DefaultSelector,
    deadline: float,
    max_output_bytes: int,
    revoked_ev: threading.Event,
) -> None:
    while sel.get_map():
        if revoked_ev.is_set():
            _kill_proc_group(proc)
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _kill_proc_group(proc)
            raise BrokerError("SSH command timed out")
        events = sel.select(timeout=min(0.1, remaining))
        for key, _ in events:
            eof, overflowed = _drain_stream_chunk(key.fd, key.data, max_output_bytes)
            if overflowed:
                _kill_proc_group(proc)
                sel.unregister(key.fileobj)
                return
            if eof:
                sel.unregister(key.fileobj)


def _validate_ssh_host_syntax(host: str) -> str:
    if type(host) is not str or not host or len(host) > 253 or host.startswith("-"):
        raise BrokerPolicyError(f"Invalid SSH host: {host!r}")
    _check_no_ctrl_or_surrogate(host, "SSH host")
    if any(ch in host for ch in (" ", "\t")):
        raise BrokerPolicyError(f"Illegal whitespace in SSH host: {host!r}")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if DNS_HOST_RE.fullmatch(host) is None:
        raise BrokerPolicyError(f"Invalid SSH DNS hostname: {host!r}")
    return host


def _validate_trusted_ssh_file(
    raw_path: Path,
    *,
    label: str,
    max_bytes: int,
    sandbox_root: Path | None = None,
) -> Path:
    """Verify an SSH host file is regular, non-symlink, non-hardlink, 0600, in a trusted dir."""
    path = Path(raw_path)
    try:
        physical = check_not_in_sandbox(path, sandbox_root=sandbox_root)
        assert_trusted_dir(physical.parent, sandbox_root=sandbox_root)
        content = read_regular_no_follow(
            path,
            max_bytes=max_bytes,
            require_owner_only=True,
            sandbox_root=sandbox_root,
        )
    except (PolicyError, SchemaError, OSError) as exc:
        raise BrokerPolicyError(f"Invalid {label} file {path}: {exc}") from exc
    if not content.strip():
        raise BrokerPolicyError(f"{label} file must not be empty: {path}")
    phys_str = str(physical)
    _check_no_ctrl_or_surrogate(phys_str, f"{label} path")
    if any(ch in phys_str for ch in (" ", "\t", "%", '"', "'")):
        raise BrokerPolicyError(f"{label} physical path contains forbidden OpenSSH chars")
    return physical


def validate_known_hosts_path(
    known_hosts_path: Path, *, sandbox_root: Path | None = None
) -> Path:
    """Verify known_hosts is a regular, non-symlink, non-hardlink, 0600 file in a trusted dir."""
    return _validate_trusted_ssh_file(
        known_hosts_path,
        label="known_hosts",
        max_bytes=MAX_KNOWN_HOSTS_BYTES,
        sandbox_root=sandbox_root,
    )


def validate_identity_file_path(
    identity_file: Path, *, sandbox_root: Path | None = None
) -> Path:
    """Verify optional IdentityFile (.pub or key) is regular, non-symlink, 0600, in a trusted dir."""
    return _validate_trusted_ssh_file(
        identity_file,
        label="identity_file",
        max_bytes=MAX_IDENTITY_FILE_BYTES,
        sandbox_root=sandbox_root,
    )


def validate_ssh_target(
    target: SshTarget,
    *,
    resolver: Callable[..., list[Any]] | None = None,
    allow_test_loopback: bool = False,
    sandbox_root: Path | None = None,
) -> tuple[str, Path, tuple[str, ...], Path | None]:
    """Validate target and return (resolved_ip, physical_known_hosts, normalized_cidrs, physical_identity)."""
    if not isinstance(target, SshTarget):
        raise BrokerPolicyError("target must be an SshTarget")
    if type(target.user) is not str or SSH_USER_RE.fullmatch(target.user) is None:
        raise BrokerPolicyError(f"Invalid SSH username: {target.user!r}")
    if type(target.port) is not int or not (1 <= target.port <= 65535):
        raise BrokerPolicyError(f"Invalid SSH port: {target.port!r}")
    host = _validate_ssh_host_syntax(target.host)
    norm_cidrs = validate_allowed_cidrs(target.allowed_cidrs, context="ssh.allowed_cidrs")
    resolved_ip = resolve_and_validate_ip(
        host,
        norm_cidrs,
        port=target.port,
        resolver=resolver,
        allow_test_loopback=allow_test_loopback,
    )
    physical_kh = validate_known_hosts_path(
        target.known_hosts_path, sandbox_root=sandbox_root
    )
    physical_id = (
        validate_identity_file_path(target.identity_file, sandbox_root=sandbox_root)
        if target.identity_file is not None
        else None
    )
    return resolved_ip, physical_kh, norm_cidrs, physical_id


def _reject_extra_params(params: Mapping[str, Any], allowed: frozenset[str], preset: str) -> None:
    extra = sorted(set(params.keys()) - allowed)
    if extra:
        raise BrokerPolicyError(f"Unknown parameter(s) for preset {preset!r}: {', '.join(extra)}")


def _validate_unit_name(unit: object) -> str:
    if (
        type(unit) is not str
        or unit.startswith("-")
        or ".." in unit
        or UNIT_NAME_RE.fullmatch(unit) is None
    ):
        raise BrokerPolicyError(f"Invalid systemd unit name: {unit!r}")
    return unit


def _preset_journalctl(params: Mapping[str, Any]) -> list[str]:
    _reject_extra_params(params, frozenset({"unit", "lines"}), "journalctl")
    unit = _validate_unit_name(params.get("unit"))
    lines = params.get("lines", 100)
    if type(lines) is not int or not (1 <= lines <= MAX_JOURNALCTL_LINES):
        raise BrokerPolicyError(f"journalctl lines must be int 1..{MAX_JOURNALCTL_LINES}")
    return ["journalctl", "--no-pager", "-n", str(lines), "-u", unit]


def _preset_systemctl_status(params: Mapping[str, Any]) -> list[str]:
    _reject_extra_params(params, frozenset({"unit"}), "systemctl_status")
    unit = _validate_unit_name(params.get("unit"))
    return ["systemctl", "status", "--no-pager", "--", unit]


def _preset_df(params: Mapping[str, Any]) -> list[str]:
    _reject_extra_params(params, frozenset({"path"}), "df")
    path = params.get("path")
    if path is None:
        return ["df", "-h"]
    if (
        type(path) is not str
        or path.startswith("-")
        or ".." in path.split("/")
        or DF_PATH_RE.fullmatch(path) is None
    ):
        raise BrokerPolicyError(f"Invalid df path: {path!r}")
    return ["df", "-h", "--", path]


def _preset_podman_ps(params: Mapping[str, Any]) -> list[str]:
    _reject_extra_params(params, frozenset({"filter_name"}), "podman_ps")
    filter_name = params.get("filter_name")
    if filter_name is None:
        return ["podman", "ps", "--format", "json"]
    if (
        type(filter_name) is not str
        or filter_name.startswith("-")
        or ".." in filter_name
        or PODMAN_FILTER_RE.fullmatch(filter_name) is None
    ):
        raise BrokerPolicyError(f"Invalid podman_ps filter_name: {filter_name!r}")
    return ["podman", "ps", "--format", "json", "--filter", f"name={filter_name}"]


_PRESET_BUILDERS: dict[str, Callable[[Mapping[str, Any]], list[str]]] = {
    "journalctl": _preset_journalctl,
    "systemctl_status": _preset_systemctl_status,
    "df": _preset_df,
    "podman_ps": _preset_podman_ps,
}


def build_preset_remote_tokens(preset: str, params: Mapping[str, Any] | None = None) -> list[str]:
    """Validate preset name & parameters and return exact remote argv tokens."""
    if type(preset) is not str or preset not in _PRESET_BUILDERS:
        raise BrokerPolicyError(f"Unsupported SSH read-only preset: {preset!r}")
    param_map = {} if params is None else params
    if not isinstance(param_map, Mapping):
        raise BrokerPolicyError("Preset params must be a mapping")
    return _PRESET_BUILDERS[preset](param_map)


def validate_custom_remote_argv(remote_argv: Sequence[str]) -> tuple[str, ...]:
    """Validate a custom non-preset remote argv sequence."""
    if isinstance(remote_argv, (str, bytes)) or not isinstance(remote_argv, Sequence):
        raise BrokerPolicyError("remote_argv must be a non-empty sequence of strings")
    if not (1 <= len(remote_argv) <= MAX_CUSTOM_ARGV_TOKENS):
        raise BrokerPolicyError(f"remote_argv length must be 1..{MAX_CUSTOM_ARGV_TOKENS}")
    out: list[str] = []
    for idx, tok in enumerate(remote_argv):
        if type(tok) is not str or not tok or len(tok) > MAX_TOKEN_LEN:
            raise BrokerPolicyError(f"Invalid remote_argv token at index {idx}")
        _check_no_ctrl_or_surrogate(tok, f"remote_argv[{idx}]")
        if idx == 0 and (tok.startswith("-") or "=" in tok):
            raise BrokerPolicyError("remote_argv executable must not start with '-' or contain '='")
        out.append(tok)
    return tuple(out)


def format_remote_command(tokens: Sequence[str]) -> str:
    """Safely shlex.quote every remote token to defeat OpenSSH remote shell joining."""
    validated = validate_custom_remote_argv(tokens)
    return " ".join(shlex.quote(tok) for tok in validated)


def build_ssh_argv(
    target: SshTarget,
    resolved_ip: str,
    physical_known_hosts: Path,
    remote_tokens: Sequence[str],
    *,
    physical_identity_file: Path | None = None,
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
) -> list[str]:
    """Build hardened local ssh argv pinned to resolved_ip with -F /dev/null."""
    if type(connect_timeout) is not int or not (1 <= connect_timeout <= 60):
        raise BrokerPolicyError("connect_timeout must be int 1..60")
    remote_cmd = format_remote_command(remote_tokens)
    ssh_bin = _resolve_ssh_binary()
    argv = [
        ssh_bin,
        "-F",
        "/dev/null",
        "-n",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        f"UserKnownHostsFile={physical_known_hosts}",
    ]
    if physical_identity_file is not None:
        argv.extend(
            [
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                f"IdentityFile={physical_identity_file}",
            ]
        )
    argv.extend(
        [
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            "-o",
            "ControlPersist=no",
            "-o",
            "ProxyCommand=none",
            "-o",
            "ProxyJump=none",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            "Tunnel=no",
            "-o",
            f"HostName={resolved_ip}",
            "-o",
            f"HostKeyAlias={target.host}",
            "-o",
            f"ConnectTimeout={connect_timeout}",
            "-p",
            str(target.port),
            "--",
            f"{target.user}@{target.host}",
            remote_cmd,
        ]
    )
    return argv


def compute_ssh_command_digest(
    user: str,
    host: str,
    port: int,
    remote_argv: Sequence[str],
    *,
    known_hosts_path: Path | str,
    allowed_cidrs: Sequence[str] = (),
    identity_file: Path | str | None = None,
) -> str:
    """Compute canonical SHA-256 hex digest pinning full target and argv."""
    canonical = json.dumps(
        {
            "allowed_cidrs": list(allowed_cidrs),
            "argv": list(remote_argv),
            "host": host,
            "identity_file": str(identity_file) if identity_file is not None else None,
            "known_hosts_path": str(known_hosts_path),
            "port": port,
            "user": user,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class _FixtureCommand:
    request_id: str
    target_id: str
    subject_channel: str
    digest: str
    argv: tuple[str, ...]


@dataclass(eq=False, slots=True)
class _FixtureInvocation:
    command: _FixtureCommand
    run: Callable[[tuple[str, ...]], SshExecResult]
    started: bool = False
    result: SshExecResult | None = None


class SshApprovalAdapter:
    """Dispatch a reserved synthetic command under the fixture controller's lock."""

    def __init__(self, initial_revisions: dict[str, str] | None = None):
        self._lock = threading.Lock()
        self._revisions: dict[str, str | None] = dict(initial_revisions or {})
        self._invocations: dict[str, _FixtureInvocation] = {}
        self._journal: dict[tuple[str, int], Any] = {}

    def target_revision(self, target: str) -> str | None:
        with self._lock:
            return self._revisions.get(target)

    def set_target_revision(self, target: str, revision: str | None) -> None:
        with self._lock:
            self._revisions[target] = revision

    def reserve(self, invocation: _FixtureInvocation) -> None:
        key = invocation.command.request_id
        with self._lock:
            if key in self._invocations:
                raise BrokerAuthError("SSH invocation already reserved")
            self._invocations[key] = invocation

    def release(self, invocation: _FixtureInvocation) -> None:
        key = invocation.command.request_id
        with self._lock:
            if self._invocations.get(key) is invocation:
                del self._invocations[key]

    def _claim(self, attempt: Any, payload: Any) -> _FixtureInvocation | None:
        from oc_controller import Intent, Operation

        if (attempt.number != 1 or payload.request_id != attempt.request_id
                or payload.intent is not Intent.APPLY_ONCE
                or payload.operation is not Operation.APPLY or payload.scope != "fixture:apply"):
            return None
        with self._lock:
            invocation = self._invocations.get(attempt.request_id)
            if invocation is None or invocation.started:
                return None
            command = invocation.command
            live_rev = self._revisions.get(payload.pin.target)
            if (command.subject_channel != payload.subject.channel
                    or command.target_id != payload.pin.target or live_rev is None
                    or not hmac.compare_digest(live_rev, payload.pin.revision)
                    or not hmac.compare_digest(command.digest, payload.pin.revision)):
                return None
            invocation.started = True
            return invocation

    def dispatch(self, attempt: Any, payload: Any) -> Any:
        from oc_controller import Outcome

        invocation = self._claim(attempt, payload)
        if invocation is None:
            outcome = Outcome.DEFINITE_FAILURE
        else:
            outcome = Outcome.UNKNOWN
            try:
                invocation.result = invocation.run(invocation.command.argv)
                if invocation.result.returncode == 0:
                    outcome = Outcome.SUCCEEDED
            except Exception:
                # Once entered, a failed runner cannot prove the effect did not happen.
                pass
        with self._lock:
            self._journal[(attempt.request_id, attempt.number)] = outcome
        return outcome

    def reconcile(self, attempt: Any, payload: Any) -> Any:
        from oc_controller import Outcome

        _ = payload
        with self._lock:
            return self._journal.get((attempt.request_id, attempt.number), Outcome.UNKNOWN)


def _scan_and_cap_output(
    raw: SshRawOutput,
    canary_secrets: Iterable[str],
    max_output_bytes: int,
) -> SshExecResult:
    secret_list = tuple(canary_secrets)
    stdout = OverlapCanaryScanner(secret_list).scan_bytes(raw.stdout)
    stderr = OverlapCanaryScanner(secret_list).scan_bytes(raw.stderr)
    truncated = len(stdout) > max_output_bytes or len(stderr) > max_output_bytes
    return SshExecResult(
        returncode=raw.returncode,
        stdout=stdout[:max_output_bytes],
        stderr=stderr[:max_output_bytes],
        truncated=truncated,
    )


class HostSshBroker:
    """Host-side SSH broker enforcing read-only presets and oc_controller APPLY_ONCE gating."""

    def __init__(
        self,
        *,
        runner: SshRunner | None = None,
        timeout: float = DEFAULT_SSH_TIMEOUT,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
        canary_secrets: Iterable[str] = (),
        resolver: Callable[..., list[Any]] | None = None,
        allow_test_loopback: bool = False,
        sandbox_root: Path | None = None,
    ):
        if timeout <= 0:
            raise BrokerPolicyError("timeout must be > 0")
        if type(max_output_bytes) is not int or max_output_bytes < 1:
            raise BrokerPolicyError("max_output_bytes must be >= 1")
        self._runner = runner
        self._timeout = timeout
        self._max_output_bytes = max_output_bytes
        self._canary_secrets = tuple(canary_secrets)
        self._resolver = resolver
        self._allow_test_loopback = allow_test_loopback
        self._sandbox_root = sandbox_root

    def _require_fixture_runner(self) -> SshRunner:
        if self._runner is None:
            raise BrokerPolicyError("Custom SSH commands require a synthetic fixture runner")
        return self._runner

    def _run_validated(
        self,
        target: SshTarget,
        remote_tokens: Sequence[str],
        *,
        lease: BrokerLease,
    ) -> SshExecResult:
        if not lease.is_active():
            raise BrokerAuthError("lease_revoked_or_expired")
        resolved_ip, physical_kh, _, physical_id = validate_ssh_target(
            target,
            resolver=self._resolver,
            allow_test_loopback=self._allow_test_loopback,
            sandbox_root=self._sandbox_root,
        )
        argv = build_ssh_argv(
            target,
            resolved_ip,
            physical_kh,
            remote_tokens,
            physical_identity_file=physical_id,
        )
        if not lease.is_active():
            raise BrokerAuthError("lease_revoked_or_expired")
        if self._runner is None:
            return _run_streaming_subprocess(
                argv,
                timeout=self._timeout,
                max_output_bytes=self._max_output_bytes,
                canary_secrets=self._canary_secrets,
                lease=lease,
            )
        raw = self._runner(argv, timeout=self._timeout, shell=False)
        return _scan_and_cap_output(raw, self._canary_secrets, self._max_output_bytes)

    def run_preset(
        self,
        target: SshTarget,
        preset: str,
        params: Mapping[str, Any] | None = None,
        *,
        lease: BrokerLease,
    ) -> SshExecResult:
        """Execute a fixed-argv preset authorized by the lease's compiled route."""
        if lease is None or target.lease is not lease:
            raise BrokerAuthError("SSH route belongs to another job lease")
        if type(preset) is not str or preset not in target.allowed_presets:
            raise BrokerPolicyError("SSH preset is unavailable on this route")
        remote_tokens = build_preset_remote_tokens(preset, params)
        return self._run_validated(target, remote_tokens, lease=lease)

    def propose_custom_command(
        self,
        target: SshTarget,
        remote_argv: Sequence[str],
        *,
        controller: Any,
        job_actor: Any,
        alias: str,
        reference: str,
        target_id: str,
    ) -> tuple[Any, str]:
        """Pin canonical (user, host, port, known_hosts, identity_file, cidrs, argv) digest and propose APPLY_ONCE."""
        from oc_controller import Intent, Proposal

        self._require_fixture_runner()
        _, physical_kh, norm_cidrs, physical_id = validate_ssh_target(
            target,
            resolver=self._resolver,
            allow_test_loopback=self._allow_test_loopback,
            sandbox_root=self._sandbox_root,
        )
        validated_argv = validate_custom_remote_argv(remote_argv)
        cmd_digest = compute_ssh_command_digest(
            target.user,
            target.host,
            target.port,
            validated_argv,
            known_hosts_path=physical_kh,
            allowed_cidrs=norm_cidrs,
            identity_file=physical_id,
        )
        controller._set_target_revision(target_id, cmd_digest)
        status = controller.propose(job_actor, Proposal(Intent.APPLY_ONCE, alias, reference))
        return status, cmd_digest

    def run_approved_command(
        self,
        target: SshTarget,
        remote_argv: Sequence[str],
        *,
        controller: Any,
        adapter: SshApprovalAdapter,
        job_actor: Any,
        request_id: str,
        lease: BrokerLease | None = None,
    ) -> SshExecResult:
        """Send the exact approved command to the controller's synthetic adapter."""
        from oc_controller import Conflict, Denied, InvalidRequest, State

        runner = self._require_fixture_runner()
        if controller._adapter is not adapter:
            raise BrokerAuthError("SSH adapter does not belong to this controller")
        if lease is not None and not lease.is_active():
            raise BrokerAuthError("lease_revoked_or_expired")
        resolved_ip, physical_kh, norm_cidrs, physical_id = validate_ssh_target(
            target,
            resolver=self._resolver,
            allow_test_loopback=self._allow_test_loopback,
            sandbox_root=self._sandbox_root,
        )
        tokens = validate_custom_remote_argv(remote_argv)
        digest = compute_ssh_command_digest(
            target.user, target.host, target.port, tokens,
            known_hosts_path=physical_kh, allowed_cidrs=norm_cidrs, identity_file=physical_id,
        )
        argv = tuple(build_ssh_argv(target, resolved_ip, physical_kh, tokens, physical_identity_file=physical_id))

        def run(frozen_argv: tuple[str, ...]) -> SshExecResult:
            raw = runner(list(frozen_argv), timeout=self._timeout, shell=False)
            return _scan_and_cap_output(raw, self._canary_secrets, self._max_output_bytes)

        try:
            status = controller.status(job_actor, request_id)
            if not status.eligible or status.revoked or status.consumed:
                raise BrokerAuthError("SSH command is not eligible for execution")
            if lease is not None and not lease.is_active():
                raise BrokerAuthError("lease_revoked_or_expired")
            invocation = _FixtureInvocation(
                _FixtureCommand(request_id, status.target, job_actor.identifier, digest, argv), run
            )
            adapter.reserve(invocation)
            try:
                invoked = controller.invoke(job_actor, request_id)
                if invoked.state is not State.SUCCEEDED or invocation.result is None:
                    raise BrokerAuthError(f"SSH fixture did not succeed: {invoked.state}/{invoked.reason}")
                return invocation.result
            finally:
                adapter.release(invocation)
        except (Conflict, Denied, InvalidRequest) as exc:
            raise BrokerAuthError("Controller refused SSH APPLY_ONCE invocation") from exc
