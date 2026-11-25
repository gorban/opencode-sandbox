"""Verified foreground owner for the opt-in OpenAI interactive shell live e2e (`full` & `mini`).

Retains 100% of attended /dev/tty approval, two-phase discovery-to-turn arming cutover,
and upstream dispatch authority in a single verified foreground process running from a
read-only verified snapshot. Delegates disposable pod/volume/worktree/slot durability
and SIGKILL-surviving teardown to the zero-OAuth DetachedShellCleanupOwner.
"""

from contextlib import suppress
from dataclasses import dataclass
import fcntl
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import pty
import re
import secrets
import select
import stat
import struct
import subprocess
import sys
import tempfile
import termios
import time

from oc_openai.cli import StreamTerminal
from oc_openai.exposure import ExposureLedger
from oc_openai.live import make_backend
from oc_openai.managed.runtime import HOST_SPAWN, account_home, check_devbox, check_host
from oc_openai.proof_gate import (
    EXPECTED_REPLY,
    PROOF_PROMPT,
    ProofApproval,
    ProofGate,
    ProofGateError,
    compute_exposure_history_digest,
    compute_providers_config_digest,
)
from oc_openai.session_adapter import OpenAISessionAdapter
from oc_openai.session_broker import ProofSessionOptions, run_interactive_session
from oc_openai.shell_cleanup_owner import (
    DetachedShellCleanupOwner,
    JournalSpec,
    _is_devbox,
    _run_podman,
)
from oc_providers.catalog import ResolvedLaunchPlan, _preflight_default_catalog
from oc_providers.config import load_provider_config_with_digest


_HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_LEVEL_RE = re.compile(r"s0:c\d+,c\d+\Z", re.ASCII)
_ANSI_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\)|[@-Z\\-_])")
_SCREEN_CAP = 256 * 1024
_IMAGE_ROLE_LABEL = "io.github.gorban.opencode-sandbox.image"
_DEFAULT_PATH = "/usr/bin:/bin"
_DEFAULT_TERM = "xterm-256color"
_DBUS_ENV_KEY = "DBUS_SESSION_BUS_ADDRESS"
_ERR_APPROVAL_DRIFT = "proof_gate_approval_drift"


class ShellDriverError(RuntimeError):
    """Fail-closed live shell driver preflight, approval, or verification error."""


@dataclass(frozen=True)
class ShellLiveConfig:
    """Validated operator inputs for one live OpenAI interactive shell e2e run."""

    ui_mode: str
    model: str
    instance_label: str
    source_sha256: str
    snapshot_root: Path
    agent_image_id: str
    relay_image_id: str


@dataclass(frozen=True)
class ShellLiveResult:
    """Strictly content-free verification result for one OpenAI shell live e2e run."""

    ok: bool
    run_id: str
    ui_mode: str
    instance_label: str
    model: str
    admitted_writes: int
    exact_ok_delivered: bool
    export_verified: bool
    cleanup_verified: bool
    receipt_history_unchanged: bool
    agent_rc: int
    evidence_path: str


@dataclass
class _PtyState:
    armed: bool = False
    prompt_sent: bool = False
    prompt_offset: int = 0


def strip_ansi(text: str) -> str:
    """Remove ANSI/VT escape sequences for bounded TUI screen matching."""
    return _ANSI_RE.sub("", text)


def _read_private_regular(path: Path, *, max_bytes: int = 128 * 1024) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise ShellDriverError(f"trusted host file unavailable: {path}") from None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid not in (0, os.geteuid())
            or info.st_mode & 0o022
            or info.st_nlink != 1
        ):
            raise ShellDriverError(f"unsafe trusted host file metadata: {path}")
        data = stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ShellDriverError(f"trusted host file exceeds size cap: {path}")
    return data


def read_sb_level(state_dir: Path) -> str:
    """Read and validate the host-trusted SELinux MCS level from $STATE/sb-level."""
    raw = _read_private_regular(state_dir / "sb-level", max_bytes=128).decode("ascii", errors="replace").strip()
    if not _LEVEL_RE.fullmatch(raw):
        raise ShellDriverError("invalid SELinux MCS level in sb-level")
    return raw


def load_built_image_ids(built_images_path: Path) -> frozenset[str]:
    """Read host-trusted 64-hex image IDs recorded in ~/.local/share/oc-sandbox/built-images."""
    raw = _read_private_regular(built_images_path, max_bytes=256 * 1024).decode("ascii", errors="replace")
    ids = {line.strip() for line in raw.splitlines() if _HEX64.fullmatch(line.strip())}
    return frozenset(ids)


def verify_reviewed_role_image(
    *,
    role: str,
    image_id: str,
    built_images_path: Path,
    podman_runner=_run_podman,
) -> str:
    """Verify an explicit 64-hex image ID exists locally, is owned in built-images, and matches role."""
    if role not in ("agent", "relay"):
        raise ShellDriverError("unsupported image role")
    if not _HEX64.fullmatch(image_id):
        raise ShellDriverError(f"invalid reviewed image ID for role {role}")
    owned_ids = load_built_image_ids(built_images_path)
    if image_id not in owned_ids:
        raise ShellDriverError(f"image {image_id[:12]} ({role}) is not recorded in {built_images_path}")
    res = podman_runner(["image", "inspect", image_id], timeout=15.0)
    if res.returncode != 0:
        raise ShellDriverError(f"reviewed {role} image {image_id[:12]} is not present locally")
    try:
        parsed = json.loads(res.stdout.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ShellDriverError(f"malformed image inspect output for {role}") from None
    entry = parsed[0] if isinstance(parsed, list) and parsed else parsed
    if not isinstance(entry, dict) or entry.get("Id") != image_id:
        raise ShellDriverError(f"image inspect ID mismatch for {role}")
    labels = entry.get("Labels")
    if not isinstance(labels, dict):
        config = entry.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else {}
    if not isinstance(labels, dict) or labels.get(_IMAGE_ROLE_LABEL) != role:
        raise ShellDriverError(f"image {image_id[:12]} does not carry required role label '{role}'")
    return image_id


def compute_locked_exposure_digest(exposure_dir: Path) -> str:
    """Compute the full 12-file exposure digest while holding ExposureLedger._locked()."""
    ledger = ExposureLedger(exposure_dir)
    with ledger._locked():
        return compute_exposure_history_digest(exposure_dir)


def prompt_attended_approval(summary: dict[str, object]) -> None:
    """Present exact approval details directly on /dev/tty and require typed confirmation."""
    if not StreamTerminal(sys.stdin, sys.stdout, sys.stderr).attended():
        raise ShellDriverError("attended foreground TTY is required for live OpenAI shell approval")
    run_id = str(summary["run_id"])
    expected_phrase = f"APPROVE {run_id[:8]}"
    lines = [
        "",
        "=== Live OpenAI Interactive Shell E2E Approval ===",
        f"  run_id                : {run_id}",
        f"  instance_label        : {summary['instance_label']}",
        f"  scoped_provider_id    : {summary['scoped_provider_id']}",
        f"  approved_model        : {summary['approved_model']}",
        f"  ui_mode               : {summary['ui_mode']}",
        f"  route_policy          : {summary['route_policy']}",
        f"  client_id             : {summary['client_id']}",
        f"  selection_epoch       : {summary['selection_epoch']}",
        f"  reg_generation        : {summary['registration_generation']}",
        f"  providers_cfg_sha256  : {summary['providers_config_digest']}",
        f"  exposure_12file_sha256: {summary['history_digest_all_12_files']}",
        f"  agent_image_id        : {summary['agent_image_id']}",
        f"  relay_image_id        : {summary['relay_image_id']}",
        f"  source_sha256         : {summary['source_sha256']}",
        "  scope                 : 1-send latched zero-tool turn ('Reply with exactly: ok')",
        f"Type exact confirmation phrase '{expected_phrase}' to authorize (anything else aborts):",
        "> ",
    ]
    rfd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
    rfd_owned = True
    wfd = -1
    wfd_owned = False
    try:
        wfd = os.dup(rfd)
        wfd_owned = True
        tty_in = os.fdopen(rfd, "r", encoding="utf-8", buffering=1)
        rfd_owned = False
        tty_out = os.fdopen(wfd, "w", encoding="utf-8", buffering=1)
        wfd_owned = False
        with tty_in, tty_out:
            tty_out.write("\n".join(lines))
            tty_out.flush()
            response = tty_in.readline()
    finally:
        if wfd_owned:
            with suppress(OSError):
                os.close(wfd)
        if rfd_owned:
            with suppress(OSError):
                os.close(rfd)
    if not response or response.strip() != expected_phrase:
        raise ShellDriverError("operator declined live OpenAI shell approval")


def _collect_parts(parts: object, texts: list[str]) -> int:
    if not isinstance(parts, list):
        return 0
    tool_parts = 0
    for part in parts:
        if not isinstance(part, dict):
            continue
        ptype = part.get("type")
        if ptype == "text" and isinstance(part.get("text"), str):
            texts.append(part["text"])
        elif ptype in ("tool", "tool-invocation", "tool_call", "function_call"):
            tool_parts += 1
    return tool_parts


def _verify_export_messages(export_data: dict[str, object]) -> None:
    messages = export_data.get("messages")
    if not isinstance(messages, list) or len(messages) != 2:
        raise ShellDriverError("session export must contain exactly one user message and one assistant message")
    user_msg, asst_msg = messages
    if not isinstance(user_msg, dict) or not isinstance(asst_msg, dict):
        raise ShellDriverError("session export message entries must be JSON objects")
    user_info = user_msg.get("info") if isinstance(user_msg.get("info"), dict) else user_msg
    asst_info = asst_msg.get("info") if isinstance(asst_msg.get("info"), dict) else asst_msg
    if user_info.get("role") != "user" or asst_info.get("role") != "assistant":
        raise ShellDriverError("session export roles must be exact [user, assistant]")
    user_texts: list[str] = []
    asst_texts: list[str] = []
    tool_parts = _collect_parts(user_msg.get("parts"), user_texts)
    tool_parts += _collect_parts(asst_msg.get("parts"), asst_texts)
    if tool_parts != 0:
        raise ShellDriverError("session export recorded unexpected tool calls")
    if "".join(user_texts) != PROOF_PROMPT:
        raise ShellDriverError("session export user prompt did not match exact proof prompt")
    if "".join(asst_texts) != EXPECTED_REPLY:
        raise ShellDriverError("session export assistant reply did not match exact untrimmed 'ok'")


def inspect_session_export(
    *,
    volume_name: str,
    level: str,
    cwd: str,
    agent_image_id: str,
    podman_runner=_run_podman,
) -> bool:
    """Verify via pinned-ID --network=none --tmpfs /sandbox container that exported session is exact 'ok' with 0 tools."""
    inspect_script = (
        "import json, os, shutil, subprocess, sys\n"
        "cwd = sys.argv[1]\n"
        "os.makedirs(os.path.join('/sandbox', cwd), exist_ok=True)\n"
        "dst = '/tmp/home/.local/share/opencode'\n"
        "os.makedirs(dst, exist_ok=True)\n"
        "src = '/src-home/.local/share/opencode'\n"
        "for name in ('opencode.db', 'opencode.db-wal', 'opencode.db-shm'):\n"
        "    p = os.path.join(src, name)\n"
        "    if os.path.exists(p):\n"
        "        shutil.copy2(p, os.path.join(dst, name))\n"
        "env = dict(os.environ, HOME='/tmp/home', XDG_DATA_HOME='/tmp/home/.local/share')\n"
        "workdir = os.path.join('/sandbox', cwd)\n"
        "listed = subprocess.run(['opencode', '--standalone', 'session', 'list', '--format', 'json'],\n"
        "                        cwd=workdir, env=env, capture_output=True, text=True, check=True)\n"
        "sessions = json.loads(listed.stdout)\n"
        "if not isinstance(sessions, list) or len(sessions) != 1:\n"
        "    raise SystemExit(f'expected 1 session, got {len(sessions) if isinstance(sessions, list) else None}')\n"
        "sid = sessions[0]['id']\n"
        "exported = subprocess.run(['opencode', '--standalone', 'session', 'export', sid],\n"
        "                          cwd=workdir, env=env, capture_output=True, text=True, check=True)\n"
        "sys.stdout.write(exported.stdout)\n"
    )
    res = podman_runner(
        [
            "run", "--rm", "--pull=never", "--network=none", "--http-proxy=false",
            "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--security-opt", f"label=level:{level}",
            "--pids-limit=128", "--memory=512m",
            "--tmpfs", "/sandbox:rw,nosuid,nodev,noexec,size=4m,mode=0700",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m,mode=0700",
            "-v", f"{volume_name}:/src-home:ro",
            "--entrypoint", "python3",
            agent_image_id, "-I", "-c", inspect_script, cwd,
        ],
        timeout=30.0,
    )
    if res.returncode != 0:
        raise ShellDriverError(f"session export inspection failed ({res.returncode})")
    try:
        export_data = json.loads(res.stdout.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ShellDriverError("session export returned invalid JSON") from None
    _verify_export_messages(export_data)
    return True


def _agent_start_command(agent_id: str) -> tuple[list[str], dict[str, str]]:
    uid = os.getuid()
    runtime_dir = f"/run/user/{uid}"
    home_dir = str(account_home())
    if _is_devbox():
        host_env = {
            "PATH": _DEFAULT_PATH,
            "HOME": home_dir,
            "TERM": _DEFAULT_TERM,
            "XDG_RUNTIME_DIR": runtime_dir,
            _DBUS_ENV_KEY: f"unix:path={runtime_dir}/bus",
        }
        spawn_env = {
            "PATH": _DEFAULT_PATH,
            "HOME": home_dir,
            "TERM": _DEFAULT_TERM,
            _DBUS_ENV_KEY: f"unix:path=/run/host{runtime_dir}/bus",
        }
        cmd = [
            HOST_SPAWN, "--env=", "/usr/bin/env", "-i",
            *(f"{k}={v}" for k, v in host_env.items()),
            "/usr/bin/podman", "--remote=false", "--default-mounts-file=/dev/null",
            "start", "-ai", agent_id,
        ]
        return cmd, spawn_env
    env = {
        "PATH": _DEFAULT_PATH,
        "HOME": home_dir,
        "TERM": _DEFAULT_TERM,
        "XDG_RUNTIME_DIR": runtime_dir,
        _DBUS_ENV_KEY: f"unix:path={runtime_dir}/bus",
    }
    cmd = ["/usr/bin/podman", "--remote=false", "--default-mounts-file=/dev/null", "start", "-ai", agent_id]
    return cmd, env


def _drain_pty_chunk(master_fd: int, screen_buf: bytearray) -> bool:
    ready, _, _ = select.select([master_fd], [], [], 0.15)
    if not ready:
        return True
    try:
        chunk = os.read(master_fd, 4096)
    except OSError:
        return False
    if not chunk:
        return False
    if len(screen_buf) + len(chunk) <= _SCREEN_CAP:
        screen_buf.extend(chunk)
    else:
        keep = _SCREEN_CAP - len(chunk)
        del screen_buf[:-keep if keep > 0 else len(screen_buf)]
        screen_buf.extend(chunk[-_SCREEN_CAP:])
    return True


_ANY_SCOPED_RE = re.compile(r"(?<![A-Za-z0-9_-])openai--[a-z0-9][a-z0-9-]*(?![A-Za-z0-9_-])")
_ANY_DISPLAY_LABEL_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:ChatGPT\s+Subscription|OpenAI)\s*\(([a-z0-9][a-z0-9-]*)\)(?![A-Za-z0-9_-])"
)


def _line_has_conflicting_provider(line: str, approval: ProofApproval) -> bool:
    for found in _ANY_SCOPED_RE.findall(line):
        if found != approval.scoped_provider_id:
            return True
    for found_label in _ANY_DISPLAY_LABEL_RE.findall(line):
        if found_label != approval.instance_label:
            return True
    return False


def _provider_matches_line(text: str, approval: ProofApproval, scoped_re: re.Pattern[str], label_re: re.Pattern[str]) -> bool:
    if _line_has_conflicting_provider(text, approval):
        return False
    return scoped_re.search(text) is not None or label_re.search(text) is not None


def _line_matches_route(
    line: str,
    approval: ProofApproval,
    exact_route_re: re.Pattern[str],
    model_re: re.Pattern[str],
    scoped_re: re.Pattern[str],
    label_re: re.Pattern[str],
) -> bool:
    if _line_has_conflicting_provider(line, approval):
        return False
    if exact_route_re.search(line) is not None:
        return True
    return _provider_matches_line(line, approval, scoped_re, label_re) and model_re.search(line) is not None


def _pair_matches_route(
    a: str,
    b: str,
    approval: ProofApproval,
    model_re: re.Pattern[str],
    scoped_re: re.Pattern[str],
    label_re: re.Pattern[str],
) -> bool:
    if _line_has_conflicting_provider(a, approval) or _line_has_conflicting_provider(b, approval):
        return False
    pair_a = _provider_matches_line(a, approval, scoped_re, label_re) and model_re.search(b) is not None
    pair_b = model_re.search(a) is not None and _provider_matches_line(b, approval, scoped_re, label_re)
    return pair_a or pair_b


def extract_observed_route_row(clean: str, approval: ProofApproval) -> str | None:
    """Return an unambiguous observed route row matching exact approved provider and model, or None."""
    esc_model = re.escape(approval.approved_model)
    esc_scoped = re.escape(approval.scoped_provider_id)
    esc_label = re.escape(approval.instance_label)
    exact_route_re = re.compile(rf"(?<![A-Za-z0-9._/-]){esc_scoped}/{esc_model}(?![A-Za-z0-9._/-])")
    model_re = re.compile(rf"(?<![A-Za-z0-9._/-]){esc_model}(?![A-Za-z0-9._/-])")
    scoped_re = re.compile(rf"(?<![A-Za-z0-9_-]){esc_scoped}(?![A-Za-z0-9_-])")
    label_re = re.compile(rf"(?<![A-Za-z0-9_-])(?:ChatGPT\s+Subscription|OpenAI)\s*\({esc_label}\)(?![A-Za-z0-9_-])")

    lines = [ln for ln in (" ".join(raw.split()) for raw in clean.splitlines()) if ln]
    for line in lines:
        if _line_matches_route(line, approval, exact_route_re, model_re, scoped_re, label_re):
            return line[:200]
    for a, b in zip(lines, lines[1:]):
        if _pair_matches_route(a, b, approval, model_re, scoped_re, label_re):
            return f"{a} | {b}"[:200]
    return None


def _step_pty_driver(
    master_fd: int,
    clean: str,
    elapsed: float,
    proof_gate: ProofGate,
    arm_turn_route,
    state: _PtyState,
) -> bool:
    if not state.armed:
        if proof_gate.admitted_writes != 0:
            raise ShellDriverError("unexpected upstream write during CLOSED_DISCOVERY")
        observed_row = extract_observed_route_row(clean, proof_gate.approval)
        if observed_row is not None and elapsed >= 1.5:
            screen_digest = sha256(clean.encode("utf-8")).hexdigest()
            arm_turn_route(observed_row, screen_digest)
            state.armed = True
        elif elapsed > 25.0:
            raise ShellDriverError("timed out waiting for OpenCode TUI readiness row")
        return False
    if not state.prompt_sent:
        state.prompt_offset = len(clean)
        os.write(master_fd, (PROOF_PROMPT + "\r").encode("ascii"))
        state.prompt_sent = True
        return False
    tail = clean[state.prompt_offset:]
    if proof_gate.exact_ok_delivered and EXPECTED_REPLY in tail:
        time.sleep(0.6)
        with suppress(OSError):
            os.write(master_fd, b"\x03")
        return True
    if elapsed > 90.0:
        raise ShellDriverError("timed out waiting for exact 'ok' delivery in OpenCode TUI")
    return False


def _drive_agent_pty(agent_id: str, stop_event, proof_gate: ProofGate, arm_turn_route) -> int:
    master_fd, slave_fd = pty.openpty()
    fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, struct.pack("HHHH", 32, 120, 0, 0))
    cmd, env = _agent_start_command(agent_id)
    proc = subprocess.Popen(cmd, stdin=slave_fd, stdout=slave_fd, stderr=slave_fd, env=env, close_fds=True)
    os.close(slave_fd)
    screen_buf = bytearray()
    state = _PtyState()
    started = time.monotonic()
    try:
        while proc.poll() is None and not stop_event.is_set():
            if not _drain_pty_chunk(master_fd, screen_buf):
                break
            clean = strip_ansi(screen_buf.decode("utf-8", errors="replace"))
            if _step_pty_driver(master_fd, clean, time.monotonic() - started, proof_gate, arm_turn_route, state):
                break
        try:
            return proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            with suppress(OSError):
                proc.terminate()
            _run_podman(["stop", "-t", "2", agent_id], timeout=10.0)
            return proc.wait(timeout=5)
    finally:
        with suppress(OSError):
            os.close(master_fd)


def _select_admitted_item(plan, scoped_provider_id: str, model: str):
    matches = [item for item in plan.admitted if item.spec.scoped_id == scoped_provider_id]
    if len(matches) != 1:
        raise ShellDriverError(f"configured OpenAI instance '{scoped_provider_id}' is not admitted for launch")
    item = matches[0]
    if model not in item.models:
        raise ShellDriverError(f"model '{model}' is not in verified catalog for '{scoped_provider_id}'")
    return item


def _read_private_json_no_lock(path: Path) -> dict[str, object]:
    """Read an atomically replaced private JSON store file without acquiring flock."""
    try:
        dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise ProofGateError(_ERR_APPROVAL_DRIFT) from None
    try:
        dinfo = os.fstat(dir_fd)
        if dinfo.st_uid != os.geteuid() or dinfo.st_mode & 0o077:
            raise ProofGateError(_ERR_APPROVAL_DRIFT)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
        with os.fdopen(fd, "rb") as stream:
            finfo = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(finfo.st_mode)
                or finfo.st_uid != os.geteuid()
                or finfo.st_mode & 0o077
                or finfo.st_nlink != 1
            ):
                raise ProofGateError(_ERR_APPROVAL_DRIFT)
            raw = stream.read(262_145)
    except ProofGateError:
        raise
    except OSError:
        raise ProofGateError(_ERR_APPROVAL_DRIFT) from None
    finally:
        os.close(dir_fd)
    if len(raw) > 262_144:
        raise ProofGateError(_ERR_APPROVAL_DRIFT)
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except ValueError:
        raise ProofGateError(_ERR_APPROVAL_DRIFT) from None
    if not isinstance(parsed, dict):
        raise ProofGateError(_ERR_APPROVAL_DRIFT)
    return parsed


def _verify_live_binding_intact(
    approval: ProofApproval,
    *,
    backend,
    config_dir: Path,
    target_binding,
) -> None:
    """Lock-free drift recheck safe inside arm() and inside before_write() under held fences."""
    del target_binding
    current_cfg_digest = compute_providers_config_digest(config_dir)
    if not hmac.compare_digest(current_cfg_digest, approval.providers_config_digest):
        raise ProofGateError(_ERR_APPROVAL_DRIFT)
    profiles_root = Path(backend.profiles._root)
    prof_state = _read_private_json_no_lock(profiles_root / "profiles" / "state.json")
    registrations = prof_state.get("registrations")
    if not isinstance(registrations, dict) or approval.instance_label not in registrations:
        raise ProofGateError(_ERR_APPROVAL_DRIFT)
    entry = registrations[approval.instance_label]
    if not isinstance(entry, dict):
        raise ProofGateError(_ERR_APPROVAL_DRIFT)
    entry_dir = str(profiles_root / "registrations" / str(entry.get("key") or ""))
    if (
        entry.get("retiring") is not False
        or entry_dir != approval.profile_directory
        or str(entry.get("client_id") or "") != approval.client_id
        or str(prof_state.get("epoch") or "") != approval.selection_epoch
    ):
        raise ProofGateError(_ERR_APPROVAL_DRIFT)
    reg_state = _read_private_json_no_lock(Path(approval.profile_directory) / "state.json")
    if (
        reg_state.get("generation") != approval.credential_generation
        or str(reg_state.get("client") or "") != approval.client_id
        or not reg_state.get("tokens")
        or reg_state.get("worker_retiring") is True
    ):
        raise ProofGateError(_ERR_APPROVAL_DRIFT)


def build_driver_session_spec(
    jspec: JournalSpec,
    *,
    relay_image_id: str,
    ui_mode: str,
    agent_mem: str = "4g",
) -> dict[str, str]:
    """Build the session spec matching `oc-sandbox` / `oc-sandbox --mini` fd-3 JSON schema."""
    return {
        "instance": jspec.instance,
        "pod": jspec.pod_name,
        "agent": f"oc-{jspec.instance}-agent",
        "relay": f"oc-{jspec.instance}-openai-relay",
        "relay_image": relay_image_id,
        "agent_image": jspec.agent_image_id,
        "agent_mem": agent_mem,
        "level": jspec.level,
        "sandbox": str(jspec.sandbox_dir),
        "cwd": jspec.cwd,
        "home_vol": jspec.volume_name,
        "chromium": f"oc-{jspec.instance}-chromium",
        "postgres": "",
        "pg_secret": "",
        "dind": "",
        "dind_run": "",
        "provider_filter": "",
        "cli_ui_mode": "mini" if ui_mode == "mini" else "default",
    }


def _build_preflight_plan(provider_config, preflight_adapter, scoped_id: str, config: ShellLiveConfig):
    plan_candidates, excluded = _preflight_default_catalog(provider_config, {"openai": preflight_adapter})
    acknowledged_digests: dict[str, str] = {}
    hold_notes: list[str] = []
    for item in plan_candidates:
        if item.exposure_hold is not None:
            acknowledged_digests[item.exposure_hold.scope_id] = item.exposure_hold.digest
            hold_notes.append(
                f"{item.spec.qualified_name}: {item.exposure_hold.file_count} files, "
                f"{item.exposure_hold.unsettled_count} unsettled, {item.exposure_hold.digest[:12]}"
            )
    plan = ResolvedLaunchPlan(
        admitted=tuple(plan_candidates),
        excluded=tuple(excluded),
        acknowledged_digests=acknowledged_digests,
        initial_provider_id=scoped_id,
        initial_model=config.model,
        ui_mode=config.ui_mode,
        ui_source="cli",
    )
    admitted = _select_admitted_item(plan, scoped_id, config.model)
    return plan, admitted, hold_notes


def run_openai_shell_live(config: ShellLiveConfig) -> ShellLiveResult:
    """Execute one attended live OpenAI interactive shell e2e run inside the verified foreground owner."""
    check_devbox()
    check_host()
    if config.agent_image_id == config.relay_image_id:
        raise ShellDriverError("agent and relay image IDs must be distinct")
    home = account_home()
    state_dir = home / ".local/share/oc-sandbox"
    config_dir = home / ".config/oc-sandbox"
    sandbox_dir = home / "opencode-sandbox"
    built_images_path = state_dir / "built-images"
    level = read_sb_level(state_dir)

    agent_image_id = verify_reviewed_role_image(
        role="agent", image_id=config.agent_image_id, built_images_path=built_images_path,
    )
    relay_image_id = verify_reviewed_role_image(
        role="relay", image_id=config.relay_image_id, built_images_path=built_images_path,
    )

    provider_config, providers_cfg_digest = load_provider_config_with_digest(config_dir=config_dir)
    if provider_config is None or providers_cfg_digest is None:
        raise ShellDriverError("providers.toml is required for configuration-first live OpenAI shell e2e")
    backend = make_backend()
    exposure_dir = backend._state
    history_digest_before = compute_locked_exposure_digest(exposure_dir)

    terminal = StreamTerminal(sys.stdin, sys.stdout, sys.stderr)
    preflight_adapter = OpenAISessionAdapter(backend)
    scoped_id = f"openai--{config.instance_label}"
    instance_name = f"e2e-{secrets.token_hex(4)}"
    run_id = secrets.token_hex(16)
    cwd = f"wt/{instance_name}"

    plan, admitted, hold_notes = _build_preflight_plan(provider_config, preflight_adapter, scoped_id, config)
    target = admitted.handle
    approval = ProofApproval(
        run_id=run_id,
        instance_label=config.instance_label,
        scoped_provider_id=scoped_id,
        approved_model=config.model,
        ui_mode=config.ui_mode,
        cwd=cwd,
        selection_epoch=target.profile.epoch,
        credential_generation=target.binding.generation,
        history_digest_all_12_files=history_digest_before,
        profile_directory=str(target.profile.directory),
        client_id=str(target.profile.client_id or ""),
        auth_mode=admitted.spec.auth_mode,
        route_policy=admitted.route_policy,
        providers_config_digest=providers_cfg_digest,
    )

    prompt_attended_approval({
        "run_id": run_id,
        "instance_label": config.instance_label,
        "scoped_provider_id": scoped_id,
        "approved_model": config.model,
        "ui_mode": config.ui_mode,
        "route_policy": admitted.route_policy + (f" | prior holds: {'; '.join(hold_notes)}" if hold_notes else ""),
        "client_id": approval.client_id,
        "selection_epoch": approval.selection_epoch,
        "registration_generation": approval.credential_generation,
        "providers_config_digest": providers_cfg_digest,
        "history_digest_all_12_files": history_digest_before,
        "agent_image_id": agent_image_id,
        "relay_image_id": relay_image_id,
        "source_sha256": config.source_sha256,
    })

    evidence_dir = Path(tempfile.mkdtemp(prefix="oc-shell-evidence-"))
    os.chmod(evidence_dir, 0o700)
    session_stop: dict[str, object] = {"event": None}

    def _check_foreground() -> None:
        ev = session_stop["event"]
        if (ev is not None and ev.is_set()) or not terminal.attended():
            raise ProofGateError("proof_gate_foreground_lost")

    proof_gate = ProofGate(
        approval,
        evidence_dir=evidence_dir,
        exposure_dir=exposure_dir,
        check_owner_alive=_check_foreground,
        check_binding_intact=lambda appr: _verify_live_binding_intact(
            appr, backend=backend, config_dir=config_dir, target_binding=target.binding,
        ),
    )
    owner = DetachedShellCleanupOwner(helper_module=config.snapshot_root / "oc_openai/shell_cleanup_owner.py")
    owner.start()
    export_verified = False
    cleanup_result = {"cleanup_verified": False}
    agent_rc = 1
    try:
        jspec = JournalSpec(
            run_id=run_id,
            instance=instance_name,
            pod_name=f"oc-{instance_name}",
            volume_name=f"oc-{instance_name}-openai-home",
            sandbox_dir=sandbox_dir,
            cwd=cwd,
            level=level,
            agent_image_id=agent_image_id,
            journal_path=evidence_dir / f"owner-{run_id}.json",
        )
        created = owner.create(
            spec=jspec,
            lock_helper=config.snapshot_root / "oc-setup-lock.py",
            state_dir=state_dir,
        )
        spec = build_driver_session_spec(jspec, relay_image_id=relay_image_id, ui_mode=config.ui_mode)
        proof_adapter = OpenAISessionAdapter(backend, proof_gate=proof_gate)
        def _run_agent(aid, ev, arm_fn):
            session_stop["event"] = ev
            return _drive_agent_pty(aid, ev, proof_gate, arm_fn)

        proof_options = ProofSessionOptions(
            proof_gate=proof_gate,
            preconfirmed_plan=plan,
            agent_runner=_run_agent,
            on_slot_prepare=owner.prepare_slot,
            on_slot_begin=owner.begin_slot_create,
            on_slot_finish=owner.finish_slot_create,
            on_slot_lease_released=owner.mark_lease_released,
        )
        agent_rc = run_interactive_session(
            spec,
            terminal,
            adapters={"openai": proof_adapter},
            lock_dir=exposure_dir,
            proof_options=proof_options,
        )
        settled_verified = proof_gate.exact_ok_delivered and proof_gate.verify_settled_evidence()
        if settled_verified:
            export_verified = inspect_session_export(
                volume_name=str(created["volume_name"]),
                level=level,
                cwd=cwd,
                agent_image_id=agent_image_id,
            )
    finally:
        cleanup_result = owner.teardown()

    history_digest_after = compute_locked_exposure_digest(exposure_dir)
    receipts_unchanged = hmac.compare_digest(history_digest_before, history_digest_after)
    cleanup_verified = bool(cleanup_result.get("cleanup_verified"))
    settled_on_disk = proof_gate.exact_ok_delivered and proof_gate.verify_settled_evidence()
    overall_ok = (
        agent_rc == 0
        and proof_gate.admitted_writes == 1
        and settled_on_disk
        and export_verified
        and cleanup_verified
        and receipts_unchanged
    )
    return ShellLiveResult(
        ok=overall_ok,
        run_id=run_id,
        ui_mode=config.ui_mode,
        instance_label=config.instance_label,
        model=config.model,
        admitted_writes=proof_gate.admitted_writes,
        exact_ok_delivered=settled_on_disk,
        export_verified=export_verified,
        cleanup_verified=cleanup_verified,
        receipt_history_unchanged=receipts_unchanged,
        agent_rc=agent_rc,
        evidence_path=str(proof_gate.evidence_path or evidence_dir),
    )
