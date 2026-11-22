"""Host-mediated fixed-argv SSH command broker for PRD L1 (Path A).

Pure Python standard library only. Never exposes SSH keys or SSH_AUTH_SOCK to
the sandbox container. Executes strictly validated read-only presets or
oc_controller APPLY_ONCE-approved commands with non-overridable OpenSSH
hardening options, shlex.quote() remote token protection, owner-only
known_hosts verification, bounded output/timeout, and canary scrubbing.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shlex
import subprocess
from typing import Any

from oc_broker_common import (
    BrokerAuthError,
    BrokerLease,
    BrokerPolicyError,
    OverlapCanaryScanner,
    resolve_and_validate_ip,
)
from oc_schema import PolicyError, SchemaError, check_not_in_sandbox, read_regular_no_follow

DEFAULT_SSH_TIMEOUT = 15.0
DEFAULT_CONNECT_TIMEOUT = 10
DEFAULT_MAX_OUTPUT_BYTES = 262_144
MAX_KNOWN_HOSTS_BYTES = 262_144
MAX_JOURNALCTL_LINES = 500
MAX_CUSTOM_ARGV_TOKENS = 64
MAX_TOKEN_LEN = 256

SSH_USER_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$", re.ASCII)
DNS_HOST_RE = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
    re.ASCII,
)
UNIT_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,127}$", re.ASCII)
DF_PATH_RE = re.compile(r"^/[a-zA-Z0-9._/@+-]{0,255}$", re.ASCII)
PODMAN_FILTER_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$", re.ASCII)
FORBIDDEN_CONTROL_CHARS = ("\x00", "\r", "\n")


@dataclass(frozen=True, slots=True)
class SshTarget:
    """Validated remote SSH host target and pinned known_hosts path."""

    user: str
    host: str
    known_hosts_path: Path
    port: int = 22
    allowed_cidrs: tuple[str, ...] = ()


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


def _default_ssh_runner(
    argv: list[str], *, timeout: float, shell: bool = False
) -> SshRawOutput:
    if shell:
        raise BrokerPolicyError("SSH broker forbids shell=True execution")
    proc = subprocess.run(
        argv,
        shell=False,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    return SshRawOutput(
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )


def _validate_ssh_host_syntax(host: str) -> str:
    if type(host) is not str or not host or len(host) > 253 or host.startswith("-"):
        raise BrokerPolicyError(f"Invalid SSH host: {host!r}")
    if any(ch in host for ch in (*FORBIDDEN_CONTROL_CHARS, " ", "\t")):
        raise BrokerPolicyError(f"Illegal character in SSH host: {host!r}")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if DNS_HOST_RE.fullmatch(host) is None:
        raise BrokerPolicyError(f"Invalid SSH DNS hostname: {host!r}")
    return host


def validate_known_hosts_path(
    known_hosts_path: Path, *, sandbox_root: Path | None = None
) -> Path:
    """Verify known_hosts is a regular, non-symlink, non-hardlink, 0600 file outside $SB."""
    path = Path(known_hosts_path)
    try:
        physical = check_not_in_sandbox(path, sandbox_root=sandbox_root)
        content = read_regular_no_follow(
            path,
            max_bytes=MAX_KNOWN_HOSTS_BYTES,
            require_owner_only=True,
            sandbox_root=sandbox_root,
        )
    except (PolicyError, SchemaError, OSError) as exc:
        raise BrokerPolicyError(f"Invalid known_hosts file {path}: {exc}") from exc
    if not content.strip():
        raise BrokerPolicyError(f"known_hosts file must not be empty: {path}")
    phys_str = str(physical)
    if any(ch in phys_str for ch in (*FORBIDDEN_CONTROL_CHARS, " ", "\t")):
        raise BrokerPolicyError("known_hosts physical path contains illegal whitespace/control chars")
    return physical


def validate_ssh_target(
    target: SshTarget,
    *,
    resolver: Callable[..., list[Any]] | None = None,
    allow_test_loopback: bool = False,
    sandbox_root: Path | None = None,
) -> tuple[str, Path]:
    """Validate user, host, port, IP policy, and known_hosts; return (resolved_ip, physical_kh)."""
    if not isinstance(target, SshTarget):
        raise BrokerPolicyError("target must be an SshTarget")
    if type(target.user) is not str or SSH_USER_RE.fullmatch(target.user) is None:
        raise BrokerPolicyError(f"Invalid SSH username: {target.user!r}")
    if type(target.port) is not int or not (1 <= target.port <= 65535):
        raise BrokerPolicyError(f"Invalid SSH port: {target.port!r}")
    host = _validate_ssh_host_syntax(target.host)
    resolved_ip = resolve_and_validate_ip(
        host,
        target.allowed_cidrs,
        port=target.port,
        resolver=resolver,
        allow_test_loopback=allow_test_loopback,
    )
    physical_kh = validate_known_hosts_path(
        target.known_hosts_path, sandbox_root=sandbox_root
    )
    return resolved_ip, physical_kh


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
        if any(ch in tok for ch in FORBIDDEN_CONTROL_CHARS):
            raise BrokerPolicyError(f"Control character forbidden in remote_argv token {idx}")
        if idx == 0 and tok.startswith("-"):
            raise BrokerPolicyError("remote_argv executable must not start with '-'")
        out.append(tok)
    return tuple(out)


def format_remote_command(tokens: Sequence[str]) -> str:
    """Safely shlex.quote every remote token to defeat OpenSSH remote shell joining."""
    validated = validate_custom_remote_argv(tokens)
    return " ".join(shlex.quote(tok) for tok in validated)


def build_ssh_argv(
    target: SshTarget,
    physical_known_hosts: Path,
    remote_tokens: Sequence[str],
    *,
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
) -> list[str]:
    """Build hardened local ssh argv with non-overridable security options."""
    if type(connect_timeout) is not int or not (1 <= connect_timeout <= 60):
        raise BrokerPolicyError("connect_timeout must be int 1..60")
    remote_cmd = format_remote_command(remote_tokens)
    return [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={physical_known_hosts}",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        f"ConnectTimeout={connect_timeout}",
        "-p",
        str(target.port),
        "--",
        f"{target.user}@{target.host}",
        remote_cmd,
    ]


def compute_ssh_command_digest(
    user: str, host: str, port: int, remote_argv: Sequence[str]
) -> str:
    """Compute canonical SHA-256 hex digest pinning (user, host, port, argv)."""
    canonical = json.dumps(
        {"argv": list(remote_argv), "host": host, "port": port, "user": user},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class SshApprovalAdapter:
    """oc_controller.FixtureAdapter binding APPLY_ONCE target revisions to SSH command digests."""

    def __init__(self, initial_revisions: dict[str, str] | None = None):
        self._revisions: dict[str, str | None] = dict(initial_revisions or {})
        self._expected_digest: dict[str, str] = {}
        self._journal: dict[tuple[str, int], Any] = {}

    def target_revision(self, target: str) -> str | None:
        return self._revisions.get(target)

    def set_target_revision(self, target: str, revision: str | None) -> None:
        self._revisions[target] = revision

    def expect_digest(self, request_id: str, digest: str) -> None:
        self._expected_digest[request_id] = digest

    def dispatch(self, attempt: Any, payload: Any) -> Any:
        from oc_controller import Outcome

        expected = self._expected_digest.get(attempt.request_id)
        live_rev = self._revisions.get(payload.pin.target)
        if expected is None or live_rev != payload.pin.revision or expected != payload.pin.revision:
            self._journal[(attempt.request_id, attempt.number)] = Outcome.DEFINITE_FAILURE
            return Outcome.DEFINITE_FAILURE
        self._journal[(attempt.request_id, attempt.number)] = Outcome.SUCCEEDED
        return Outcome.SUCCEEDED

    def reconcile(self, attempt: Any, payload: Any) -> Any:
        from oc_controller import Outcome

        _ = payload
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
        self._runner = runner or _default_ssh_runner
        self._timeout = timeout
        self._max_output_bytes = max_output_bytes
        self._canary_secrets = tuple(canary_secrets)
        self._resolver = resolver
        self._allow_test_loopback = allow_test_loopback
        self._sandbox_root = sandbox_root

    def _run_validated(
        self,
        target: SshTarget,
        remote_tokens: Sequence[str],
        *,
        lease: BrokerLease | None = None,
    ) -> SshExecResult:
        if lease is not None and not lease.is_active():
            raise BrokerAuthError("lease_revoked_or_expired")
        _, physical_kh = validate_ssh_target(
            target,
            resolver=self._resolver,
            allow_test_loopback=self._allow_test_loopback,
            sandbox_root=self._sandbox_root,
        )
        argv = build_ssh_argv(target, physical_kh, remote_tokens)
        raw = self._runner(argv, timeout=self._timeout, shell=False)
        return _scan_and_cap_output(raw, self._canary_secrets, self._max_output_bytes)

    def run_preset(
        self,
        target: SshTarget,
        preset: str,
        params: Mapping[str, Any] | None = None,
        *,
        lease: BrokerLease | None = None,
    ) -> SshExecResult:
        """Execute an allowlisted fixed-argv read-only preset."""
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
        """Pin canonical (user, host, port, argv) digest and submit APPLY_ONCE proposal."""
        from oc_controller import Intent, Proposal

        validate_ssh_target(
            target,
            resolver=self._resolver,
            allow_test_loopback=self._allow_test_loopback,
            sandbox_root=self._sandbox_root,
        )
        validated_argv = validate_custom_remote_argv(remote_argv)
        cmd_digest = compute_ssh_command_digest(
            target.user, target.host, target.port, validated_argv
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
        """Execute a non-preset SSH command strictly after oc_controller APPLY_ONCE approval."""
        from oc_controller import Conflict, Denied, InvalidRequest, State

        if lease is not None and not lease.is_active():
            raise BrokerAuthError("lease_revoked_or_expired")
        validated_argv = validate_custom_remote_argv(remote_argv)
        cmd_digest = compute_ssh_command_digest(
            target.user, target.host, target.port, validated_argv
        )
        try:
            pre_status = controller.status(job_actor, request_id)
        except (Denied, InvalidRequest) as exc:
            raise BrokerAuthError(f"Controller rejected SSH command status: {exc}") from exc
        if not pre_status.eligible or pre_status.revoked or pre_status.consumed:
            raise BrokerAuthError(
                f"SSH command not eligible for execution: {pre_status.state}/{pre_status.reason}"
            )
        adapter.expect_digest(request_id, cmd_digest)
        try:
            invoked = controller.invoke(job_actor, request_id)
        except (Conflict, Denied, InvalidRequest) as exc:
            raise BrokerAuthError(f"Controller refused SSH APPLY_ONCE invoke: {exc}") from exc
        if invoked.state is not State.SUCCEEDED:
            raise BrokerAuthError(
                f"SSH APPLY_ONCE invoke did not succeed: {invoked.state}/{invoked.reason}"
            )
        return self._run_validated(target, validated_argv, lease=lease)
