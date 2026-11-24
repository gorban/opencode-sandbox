"""Opt-in live zero-tool OpenCode + OpenAI subscription canary e2e test."""

import os
from pathlib import Path
import pwd
import re
import signal
import stat
import subprocess


_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z", re.ASCII)


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


def _run_checked_driver(root: Path, *, model: str | None) -> int | None:
    try:
        home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
        driver = _trusted_driver(root, home)
    except (KeyError, OSError, ValueError):
        return None
    command = ["/usr/bin/python3", "-IB", str(driver)]
    if model is not None:
        command.extend(["--model", model])
    env = {"HOME": str(home), "PATH": "/usr/bin:/bin"}
    return _wait_for_driver(command, root=root, env=env)


def test_live_openai_opencode_canary(request):
    """Run one zero-tool OpenCode 2.3.0 turn against the active OpenAI subscription."""
    import pytest

    args = request.config.invocation_params.args
    if ("--run-openai-canary-live" not in args
            or not request.config.getoption("--run-openai-canary-live", default=False)):
        pytest.skip("explicit --run-openai-canary-live opt-in required")

    model = request.config.getoption("--openai-canary-model", default=None)
    if model is not None and (type(model) is not str or not _MODEL_RE.fullmatch(model)):
        pytest.fail("Invalid --openai-canary-model value.", pytrace=False)

    root = Path(__file__).resolve(strict=True).parents[3]
    status = _run_checked_driver(root, model=model)
    if status is None:
        pytest.fail("The reviewed workstation canary source is unavailable.", pytrace=False)
    if status == 130:
        raise KeyboardInterrupt
    assert status == 0, "Live OpenCode + OpenAI subscription canary did not pass."
