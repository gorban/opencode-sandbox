#!/usr/bin/env python3
"""Trusted read-only snapshot bootstrap for the opt-in OpenAI interactive shell live e2e.

Copies the complete reviewed first-party manifest (including conftest.py, test_openai_shell_e2e.py,
openai_shell_driver.py, run_openai_shell_live.py, oc-sandbox, oc-openai-session.py, oc-setup-lock.py,
oc_providers/**, and oc_openai/**) via O_NOFOLLOW into an owner-only staging directory, locks files
to 0o400/0o500 (read-only snapshot), verifies the exact SHA-256 manifest digest and its own running
bytes, runs pytest from inside that read-only snapshot forwarding SIGINT, and cleans up in finally.
"""

import argparse
from contextlib import suppress
from hashlib import sha256
import hmac
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile


_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z", re.ASCII)
_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?\Z", re.ASCII)
_MAX_FILE_BYTES = 2 * 1024 * 1024

_SELF_RELPATH = "tests/e2e/live/run_openai_shell_live.py"
_ROOT_MANIFEST_FILES: tuple[str, ...] = (
    "oc-sandbox",
    "oc-openai-session.py",
    "oc-setup-lock.py",
    "tests/e2e/live/conftest.py",
    _SELF_RELPATH,
    "tests/e2e/live/openai_shell_driver.py",
    "tests/e2e/live/test_openai_shell_e2e.py",
)
_EXECUTABLE_RELPATHS = frozenset({
    "oc-sandbox",
    "oc-openai-session.py",
    "oc-setup-lock.py",
    _SELF_RELPATH,
})
_MANIFEST_PACKAGES: tuple[str, ...] = ("oc_openai", "oc_providers")


class SnapshotError(RuntimeError):
    """Fail-closed source provenance or read-only snapshot error."""


def _read_trusted_file(path: Path) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise SnapshotError(f"untrusted source file: {path}") from None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid not in (0, os.geteuid())
            or info.st_nlink != 1
            or info.st_mode & 0o022
        ):
            raise SnapshotError(f"unsafe source file metadata: {path}")
        data = stream.read(_MAX_FILE_BYTES + 1)
    if len(data) > _MAX_FILE_BYTES:
        raise SnapshotError(f"source file exceeds size cap: {path}")
    return data


def _collect_package_py(root: Path, relative: Path, out: list[Path]) -> None:
    directory = root / relative
    try:
        info = directory.lstat()
    except OSError:
        raise SnapshotError(f"missing source package directory: {relative}") from None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
        raise SnapshotError(f"unsafe source package directory: {relative}")
    for entry in sorted(directory.iterdir()):
        rel = entry.relative_to(root)
        if not entry.is_symlink() and entry.is_dir():
            if entry.name == "__pycache__":
                continue
            _collect_package_py(root, rel, out)
        elif entry.suffix == ".py":
            out.append(rel)
        else:
            raise SnapshotError(f"unexpected file in source package: {rel}")


def collect_manifest_relpaths(root: Path) -> list[Path]:
    """Return sorted relative paths of every first-party file in the reviewed snapshot manifest."""
    files = [Path(rel) for rel in _ROOT_MANIFEST_FILES]
    for pkg in _MANIFEST_PACKAGES:
        _collect_package_py(root, Path(pkg), files)
    return sorted(files)


def capture_manifest(root: Path) -> tuple[str, dict[Path, bytes]]:
    """Read and hash every file in the reviewed manifest without importing or executing it."""
    hasher = sha256()
    captured: dict[Path, bytes] = {}
    for rel in collect_manifest_relpaths(root):
        data = _read_trusted_file(root / rel)
        hasher.update(rel.as_posix().encode("ascii") + b"\0" + sha256(data).digest())
        captured[rel] = data
    return hasher.hexdigest(), captured


def _validate_staging_parent(parent: Path) -> Path:
    """Validate snapshot staging parent ancestry is outside sandbox and protected from non-owners."""
    try:
        resolved = parent.resolve(strict=True)
    except OSError:
        raise SnapshotError(f"snapshot staging parent unavailable: {parent}") from None
    import pwd
    sandbox = (Path(pwd.getpwuid(os.getuid()).pw_dir) / "opencode-sandbox").resolve()
    if resolved.is_relative_to(sandbox):
        raise SnapshotError("snapshot staging parent must not be inside agent-writable sandbox")
    uid = os.geteuid()
    cur = parent
    while True:
        try:
            info = cur.lstat()
        except OSError:
            raise SnapshotError(f"snapshot staging ancestor unavailable: {cur}") from None
        sticky_tmp = cur == Path("/tmp") and info.st_uid in (0, 65534) and bool(info.st_mode & stat.S_ISVTX)
        if not stat.S_ISDIR(info.st_mode) or (
            not sticky_tmp and (info.st_uid not in (0, uid) or bool(info.st_mode & 0o022))
        ):
            raise SnapshotError(f"unsafe snapshot staging directory ancestor: {cur}")
        if cur == cur.parent:
            break
        cur = cur.parent
    return resolved


def _verify_snapshot_dir(directory: Path, label: str) -> None:
    try:
        info = directory.lstat()
    except OSError:
        raise SnapshotError(f"snapshot directory unavailable: {label}") from None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o277:
        raise SnapshotError(
            "live execution requires an owner-only read-only verified snapshot "
            f"(unsafe directory: {label}; run via run_openai_shell_live.py)"
        )


def _verify_snapshot_file_meta(fpath: Path, rel_file: Path) -> None:
    info = fpath.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o277:
        raise SnapshotError(f"snapshot file is not owner-only read-only: {rel_file}")


def _scan_snapshot_tree(snapshot_root: Path) -> set[Path]:
    observed: set[Path] = set()
    for root, dirs, files in os.walk(snapshot_root, topdown=True, followlinks=False):
        root_path = Path(root)
        rel_dir = root_path.relative_to(snapshot_root)
        _verify_snapshot_dir(root_path, "." if rel_dir == Path(".") else rel_dir.as_posix())
        for dname in dirs:
            _verify_snapshot_dir(root_path / dname, (rel_dir / dname).as_posix())
        for fname in files:
            fpath = root_path / fname
            rel_file = fpath.relative_to(snapshot_root)
            _verify_snapshot_file_meta(fpath, rel_file)
            observed.add(rel_file)
    return observed


def verify_read_only_snapshot(snapshot_root: Path, expected_sha256: str) -> str:
    """Verify complete snapshot tree is owner-only read-only with zero unmeasured files and matches expected_sha256."""
    if not _SHA256_RE.fullmatch(expected_sha256):
        raise SnapshotError("invalid expected source SHA-256 pin")
    _verify_snapshot_dir(snapshot_root, ".")
    expected_files = collect_manifest_relpaths(snapshot_root)
    observed_files = _scan_snapshot_tree(snapshot_root)
    extra = sorted(p.as_posix() for p in (observed_files - set(expected_files)))
    if extra:
        raise SnapshotError(f"unexpected unmeasured file in snapshot: {extra[0]}")
    hasher = sha256()
    for rel in expected_files:
        data = _read_trusted_file(snapshot_root / rel)
        hasher.update(rel.as_posix().encode("ascii") + b"\0" + sha256(data).digest())
    actual = hasher.hexdigest()
    if not hmac.compare_digest(actual, expected_sha256):
        raise SnapshotError("snapshot manifest SHA-256 mismatch")
    return actual


def build_read_only_snapshot(source_root: Path, expected_sha256: str, *, base_dir: Path | None = None) -> Path:
    """Copy verified manifest files into a private owner-only read-only (0o400/0o500) snapshot."""
    if not _SHA256_RE.fullmatch(expected_sha256):
        raise SnapshotError("invalid --source-sha256 pin")
    digest, captured = capture_manifest(source_root)
    if not hmac.compare_digest(digest, expected_sha256):
        raise SnapshotError(f"source manifest digest {digest} does not match pin {expected_sha256}")
    self_rel = Path(_SELF_RELPATH)
    self_bytes = _read_trusted_file(Path(__file__).resolve())
    if not hmac.compare_digest(sha256(self_bytes).digest(), sha256(captured[self_rel]).digest()):
        raise SnapshotError("running bootstrap bytes differ from verified snapshot copy")

    parent_path = _validate_staging_parent(Path("/tmp") if base_dir is None else Path(base_dir))
    stage = Path(tempfile.mkdtemp(prefix="oc-shell-snap-", dir=str(parent_path)))
    try:
        os.chmod(stage, 0o700)
        created_dirs: set[Path] = {stage}
        for rel, data in captured.items():
            dest = stage / rel
            cur = stage
            for part in rel.parent.parts:
                cur = cur / part
                if cur not in created_dirs:
                    cur.mkdir(mode=0o700, exist_ok=True)
                    os.chmod(cur, 0o700)
                    created_dirs.add(cur)
            mode = 0o500 if rel.as_posix() in _EXECUTABLE_RELPATHS else 0o400
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
            os.chmod(dest, mode)
        for directory in sorted(created_dirs, key=lambda p: len(p.parts), reverse=True):
            os.chmod(directory, 0o500)
        verify_read_only_snapshot(stage, expected_sha256)
    except BaseException:
        cleanup_snapshot(stage)
        raise
    return stage


def cleanup_snapshot(snapshot_root: Path) -> None:
    """Restore owner write bits bottom-up and remove the temporary read-only snapshot."""
    if not snapshot_root.exists():
        return
    for root, dirs, files in os.walk(snapshot_root, topdown=True, followlinks=False):
        root_path = Path(root)
        with suppress(OSError):
            os.chmod(root_path, 0o700)
        for name in dirs:
            with suppress(OSError):
                os.chmod(root_path / name, 0o700)
        for name in files:
            with suppress(OSError):
                os.chmod(root_path / name, 0o600)
    with suppress(OSError):
        shutil.rmtree(snapshot_root)


def _clean_pytest_env(snapshot_root: Path) -> dict[str, str]:
    env: dict[str, str] = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", ""),
        "TERM": os.environ.get("TERM", "xterm-256color"),
        "PYTHONPATH": str(snapshot_root),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    }
    for key in ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "USER", "LANG"):
        val = os.environ.get(key)
        if val:
            env[key] = val
    return env


def _build_pytest_args(args: argparse.Namespace, snapshot_root: Path) -> list[str]:
    test_file = snapshot_root / "tests/e2e/live/test_openai_shell_e2e.py"
    return [
        sys.executable,
        "-IB",
        "-m",
        "pytest",
        "-s",
        "-p",
        "no:cacheprovider",
        "-c",
        "/dev/null",
        "-o",
        "addopts=",
        "-o",
        f"pythonpath={snapshot_root}",
        "--confcutdir",
        str(snapshot_root / "tests/e2e/live"),
        "--rootdir",
        str(snapshot_root),
        str(test_file),
        "--run-openai-shell-live",
        "--openai-shell-mode",
        args.mode,
        "--openai-shell-model",
        args.model,
        "--openai-shell-instance",
        args.instance,
        "--openai-shell-source-sha256",
        args.source_sha256,
        "--openai-shell-agent-image-id",
        args.agent_image_id,
        "--openai-shell-relay-image-id",
        args.relay_image_id,
    ]


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run live OpenAI interactive shell e2e from a verified read-only snapshot.")
    parser.add_argument("--print-source-sha256", action="store_true",
                        help="Print the current repository snapshot manifest SHA-256 and exit without running pytest.")
    parser.add_argument("--source-sha256", default=None, help="Exact 64-hex reviewed manifest SHA-256.")
    parser.add_argument("--mode", choices=("full", "mini"), default=None, help="UI mode (full or mini).")
    parser.add_argument("--model", default=None, help="Reviewed upstream model slug.")
    parser.add_argument("--instance", default=None, help="Configured OpenAI instance label.")
    parser.add_argument("--agent-image-id", default=None, help="Required reviewed 64-hex oc-agent image ID.")
    parser.add_argument("--relay-image-id", default=None, help="Required reviewed 64-hex oc-openai-relay image ID.")
    return parser.parse_args(argv)


def _validate_run_args(args: argparse.Namespace) -> None:
    if not args.source_sha256 or not _SHA256_RE.fullmatch(args.source_sha256):
        raise SnapshotError("--source-sha256 must be a 64-lowercase-hex SHA-256 digest")
    if args.mode not in ("full", "mini"):
        raise SnapshotError("--mode must be 'full' or 'mini'")
    if not args.model or not _MODEL_RE.fullmatch(args.model):
        raise SnapshotError("--model must be a valid model slug")
    if not args.instance or not _LABEL_RE.fullmatch(args.instance):
        raise SnapshotError("--instance must be a valid instance label")
    for flag, val in (("--agent-image-id", args.agent_image_id), ("--relay-image-id", args.relay_image_id)):
        if not val or not _SHA256_RE.fullmatch(val):
            raise SnapshotError(f"{flag} must be a 64-lowercase-hex reviewed image ID")
    if args.agent_image_id == args.relay_image_id:
        raise SnapshotError("--agent-image-id and --relay-image-id must be distinct role-bound image IDs")


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repo_root = Path(__file__).resolve().parents[3]
    if args.print_source_sha256:
        digest, _ = capture_manifest(repo_root)
        print(digest)
        return 0
    _validate_run_args(args)
    snapshot_root = build_read_only_snapshot(repo_root, args.source_sha256)
    proc: subprocess.Popen[bytes] | None = None
    prev_int = signal.getsignal(signal.SIGINT)
    try:
        cmd = _build_pytest_args(args, snapshot_root)
        proc = subprocess.Popen(cmd, cwd=str(snapshot_root), env=_clean_pytest_env(snapshot_root))

        def _forward_sigint(_sig, _frame) -> None:
            if proc is not None and proc.poll() is None:
                with suppress(OSError):
                    proc.send_signal(signal.SIGINT)

        signal.signal(signal.SIGINT, _forward_sigint)
        return proc.wait()
    finally:
        signal.signal(signal.SIGINT, prev_int)
        if proc is not None and proc.poll() is None:
            with suppress(OSError):
                proc.terminate()
            with suppress(OSError, subprocess.TimeoutExpired):
                proc.wait(timeout=5)
        cleanup_snapshot(snapshot_root)


if __name__ == "__main__":
    raise SystemExit(main())
