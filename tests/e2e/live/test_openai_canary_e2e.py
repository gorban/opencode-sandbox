"""Opt-in live zero-tool OpenCode + OpenAI subscription canary e2e test."""

from hashlib import sha256
import hmac
import os
from pathlib import Path
import pwd
import re
import signal
import stat
import subprocess
import tempfile


LIVE_FLAG = "--run-openai-canary-live"
SOURCE_PIN_FLAG = "--openai-canary-source-sha256"
_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z", re.ASCII)
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_SOURCE_BYTES = 1_048_576


def _check_trusted_source(source: Path, sandbox: Path, uid: int) -> None:
    if source.is_relative_to(sandbox):
        raise ValueError("canary source is inside the agent-writable sandbox")
    private = False
    for directory in reversed(source.parents):
        info = directory.lstat()
        sticky_tmp = directory == Path("/tmp") and info.st_uid in (0, 65534) and info.st_mode & stat.S_ISVTX
        if not stat.S_ISDIR(info.st_mode) or (
            not sticky_tmp and (info.st_uid not in (0, uid) or (info.st_mode & 0o022 and not private))
        ):
            raise ValueError("canary source directory is unprotected")
        private |= info.st_uid == uid and not info.st_mode & 0o077
    info = source.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, uid)
            or info.st_mode & 0o022 or info.st_nlink != 1):
        raise ValueError("canary source file is unprotected")


def _trusted_driver(root: Path, home: Path) -> Path:
    uid = os.geteuid()
    sandbox = (home / "opencode-sandbox").resolve()
    driver = root / "tests/e2e/live/openai_canary_driver.py"
    for source in (driver, root / "oc-openai.py"):
        _check_trusted_source(source, sandbox, uid)
    return driver


def _collect_package_files(root: Path, relative: Path, files: list[Path]) -> None:
    directory = root / relative
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
        raise ValueError("untrusted canary package directory")
    for entry in sorted(directory.iterdir()):
        rel = entry.relative_to(root)
        if entry.is_dir() and not entry.is_symlink():
            if entry.name == "__pycache__":
                continue
            _collect_package_files(root, rel, files)
        elif entry.suffix == ".py":
            files.append(rel)
        else:
            raise ValueError("unexpected file in canary package")


def _capture_sources(root: Path, driver: Path) -> tuple[str, dict[Path, bytes]]:
    """Capture candidate first-party sources without importing or executing them."""
    files: list[Path] = [driver.relative_to(root), Path("oc-openai.py")]
    _collect_package_files(root, Path("oc_openai"), files)
    providers = root / "oc_providers"
    if providers.exists() or providers.is_symlink():
        _collect_package_files(root, Path("oc_providers"), files)
    digest = sha256()
    captured: dict[Path, bytes] = {}
    for rel in sorted(files):
        fd = os.open(root / rel, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid())
                    or info.st_nlink != 1 or info.st_mode & 0o022):
                raise ValueError("untrusted canary source file")
            contents = stream.read(_MAX_SOURCE_BYTES + 1)
        if len(contents) > _MAX_SOURCE_BYTES:
            raise ValueError("canary source file exceeds size cap")
        digest.update(rel.as_posix().encode("ascii") + b"\0" + sha256(contents).digest())
        captured[rel] = contents
    return digest.hexdigest(), captured


def _signal_child(proc: subprocess.Popen) -> None:
    try:
        proc.send_signal(signal.SIGINT)
    except OSError:
        pass


def _wait_for_driver(command: list[str], *, root: Path, env: dict[str, str]) -> int:
    interrupted = False
    active: list[subprocess.Popen] = []

    def record_interrupt(_signum, _frame):
        nonlocal interrupted
        interrupted = True
        if active:
            _signal_child(active[0])

    previous = signal.signal(signal.SIGINT, record_interrupt)
    try:
        with subprocess.Popen(command, cwd=root, env=env) as proc:
            active.append(proc)
            if interrupted:
                _signal_child(proc)
            status = proc.wait()
    finally:
        active.clear()
        signal.signal(signal.SIGINT, previous)
    if interrupted:
        raise KeyboardInterrupt
    return status


def _run_checked_driver(root: Path, *, model: str | None, source_sha256: str | None = None) -> int | None:
    try:
        home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
        driver = _trusted_driver(root, home)
    except (KeyError, OSError, ValueError):
        return None
    env = {"HOME": str(home), "PATH": "/usr/bin:/bin"}
    extra_args: list[str] = [LIVE_FLAG]
    if model is not None:
        extra_args.extend(["--model", model])
    if source_sha256 is None:
        command = ["/usr/bin/python3", "-IB", str(driver), *extra_args]
        return _wait_for_driver(command, root=root, env=env)
    try:
        digest, files = _capture_sources(root, driver)
        if not hmac.compare_digest(digest, source_sha256):
            return None
    except (OSError, ValueError):
        return None
    with tempfile.TemporaryDirectory(prefix="oc-reviewed-canary-") as scratch:
        snapshot = Path(scratch)
        for rel, data in files.items():
            destination = snapshot / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            destination.chmod(0o400)
        for directory in sorted((entry for entry in snapshot.rglob("*") if entry.is_dir()), reverse=True):
            directory.chmod(0o500)
        snap_driver = snapshot / driver.relative_to(root)
        command = ["/usr/bin/python3", "-IB", str(snap_driver), *extra_args, "--source-sha256", source_sha256]
        return _wait_for_driver(command, root=snapshot, env=env)


def _validated_source_pin(request, args) -> str | None:
    source_sha256 = request.config.getoption(SOURCE_PIN_FLAG, default=None)
    if source_sha256 is None:
        return None
    direct_count = sum(arg == SOURCE_PIN_FLAG or arg.startswith(f"{SOURCE_PIN_FLAG}=") for arg in args)
    if (type(source_sha256) is not str or not _SHA256_RE.fullmatch(source_sha256)
            or direct_count != 1 or source_sha256 not in " ".join(args)):
        raise ValueError("invalid source pin")
    return source_sha256


def test_live_openai_opencode_canary(request):
    """Run one zero-tool OpenCode 2.3.0 turn against the active OpenAI subscription."""
    import pytest

    args = request.config.invocation_params.args
    if LIVE_FLAG not in args or not request.config.getoption(LIVE_FLAG, default=False):
        pytest.skip("explicit --run-openai-canary-live opt-in required")

    model = request.config.getoption("--openai-canary-model", default=None)
    if model is not None and (type(model) is not str or not _MODEL_RE.fullmatch(model)):
        pytest.fail("Invalid --openai-canary-model value.", pytrace=False)

    try:
        source_sha256 = _validated_source_pin(request, args)
    except ValueError:
        pytest.fail("Invalid --openai-canary-source-sha256 value.", pytrace=False)

    root = Path(__file__).resolve(strict=True).parents[3]
    status = _run_checked_driver(root, model=model, source_sha256=source_sha256)
    if status is None:
        pytest.fail("Canary workstation source verification failed.", pytrace=False)
    if status == 130:
        raise KeyboardInterrupt
    assert status == 0, "Live OpenCode + OpenAI subscription canary did not pass."
