"""Opt-in local OpenAI proof through a separately isolated Python process."""

from hashlib import sha256
import os
from pathlib import Path
import pwd
import re
import signal
import stat
import subprocess
import tempfile

RECOVERY = "--recover-proof-live"


def _trusted_driver(root, home):
    uid = os.geteuid()
    sandbox = (home / "opencode-sandbox").resolve()
    driver = root / "tests/e2e/live/openai_driver.py"
    for source in (driver, root / "oc-openai.py"):
        if source.is_relative_to(sandbox):
            raise ValueError("proof source is inside the agent-writable sandbox")
        private = False
        for directory in reversed(source.parents):
            info = directory.lstat()
            sticky_tmp = directory == Path("/tmp") and info.st_uid in (0, 65534) and info.st_mode & stat.S_ISVTX
            if not stat.S_ISDIR(info.st_mode) or (
                not sticky_tmp and (info.st_uid not in (0, uid) or (info.st_mode & 0o022 and not private))
            ):
                raise ValueError("proof source directory is unprotected")
            private |= info.st_uid == uid and not info.st_mode & 0o077
        info = source.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, uid)
                or info.st_mode & 0o022 or info.st_nlink != 1):
            raise ValueError("proof source file is unprotected")
    return driver


def _wait_for_proof(command, *, root, env):
    interrupted = False

    def record_interrupt(signum, frame):
        nonlocal interrupted
        interrupted = True

    # The child inherits the foreground process group and handles the same
    # terminal SIGINT. The parent must wait for retirement and reap the child.
    previous = signal.signal(signal.SIGINT, record_interrupt)
    try:
        with subprocess.Popen(command, cwd=root, env=env) as proof:
            if interrupted:
                proof.send_signal(signal.SIGINT)
            status = proof.wait()
    finally:
        signal.signal(signal.SIGINT, previous)
    if interrupted:
        raise KeyboardInterrupt
    return status


def _capture_sources(root, driver):
    """Capture candidate data without importing or executing it."""
    files = [driver, root / "oc-openai.py"]
    for directory in (root / "oc_openai", root / "oc_openai/managed"):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
            raise ValueError("untrusted proof package directory")
        files.extend(directory.glob("*.py"))
    digest = sha256()
    captured = {}
    for source in sorted(files):
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid())
                    or info.st_nlink != 1 or info.st_mode & 0o022):
                raise ValueError("untrusted proof source file")
            contents = stream.read(1_048_577)
        if len(contents) > 1_048_576:
            raise ValueError("unexpected proof source size")
        name = source.relative_to(root)
        digest.update(name.as_posix().encode("ascii") + b"\0" + sha256(contents).digest())
        captured[name] = contents
    return digest.hexdigest(), captured


def _run_driver(root, home, *, recovery=None, recovery_source=None):
    driver = _trusted_driver(root, home)
    command = ["/usr/bin/python3", "-IB", str(driver)]
    if recovery is not None:
        command.append(recovery)
    env = {"HOME": str(home), "PATH": "/usr/bin:/bin"}
    if recovery_source is None:
        return _wait_for_proof(command, root=root, env=env)
    digest, files = _capture_sources(root, driver)
    if digest != recovery_source:
        raise ValueError("recovery proof does not match reviewed source")
    with tempfile.TemporaryDirectory(prefix="oc-reviewed-openai-") as scratch:
        snapshot = Path(scratch)
        for name, data in files.items():
            destination = snapshot / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            destination.chmod(0o400)
        for directory in sorted((entry for entry in snapshot.rglob("*") if entry.is_dir()), reverse=True):
            directory.chmod(0o500)
        command[-1] = str(snapshot / driver.relative_to(root))
        return _wait_for_proof(
            [*command, RECOVERY, recovery_source], root=snapshot, env=env,
        )


def _run_checked_driver(case, recovery, source):
    try:
        home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
        return _run_driver(case.parents[3], home, recovery=recovery, recovery_source=source)
    except (KeyError, OSError, ValueError):
        return None


def test_attended_openai_route(request):
    import pytest

    args = request.config.invocation_params.args
    if ("--run-openai-live" not in args
            or not request.config.getoption("--run-openai-live", default=False)):
        pytest.skip("explicit --run-openai-live opt-in required")
    known = ("--recover-openai-live", "--recover-stream-live")
    recovery = [flag for flag in known if request.config.getoption(flag, default=False)]
    if len(recovery) > 1 or any(args.count(flag) != int(flag in recovery) for flag in known):
        pytest.fail("Select at most one explicit recovery option.", pytrace=False)
    source = request.config.getoption("--recover-proof-live", default=None)
    if source is not None and (recovery or type(source) is not str or not re.fullmatch(
        r"[0-9a-f]{64}", source,
    ) or sum(arg.startswith("--recover-proof-live=") or arg == "--recover-proof-live" for arg in args) != 1
            or f"--recover-proof-live={source}" not in args):
        pytest.fail("Select one exact reviewed SHA-256 with --recover-proof-live=SHA256.", pytrace=False)
    case = Path(__file__).resolve(strict=True)
    if [Path(arg).resolve() for arg in request.config.args] != [case]:
        pytest.fail("Select this one test file for an attended live run.", pytrace=False)
    result = _run_checked_driver(case, next(iter(recovery), None), source)
    if result is None:
        pytest.fail("The reviewed workstation proof source is unavailable.", pytrace=False)
    if result == 130:
        raise KeyboardInterrupt
    if result != 0:
        pytest.fail("The attended OpenAI proof did not pass. See the terminal result above.", pytrace=False)
