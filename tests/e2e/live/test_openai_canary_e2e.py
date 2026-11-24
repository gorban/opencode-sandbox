"""Opt-in live zero-tool OpenCode + OpenAI subscription canary e2e test."""

import os
from pathlib import Path
import pwd
import re
import subprocess


_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z", re.ASCII)


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
    driver = root / "tests/e2e/live/openai_canary_driver.py"
    home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
    command = ["/usr/bin/python3", "-IB", str(driver)]
    if model is not None:
        command.extend(["--model", model])
    env = {"HOME": str(home), "PATH": "/usr/bin:/bin"}
    result = subprocess.run(command, cwd=root, env=env, check=False)
    if result.returncode == 130:
        raise KeyboardInterrupt
    assert result.returncode == 0, "Live OpenCode + OpenAI subscription canary did not pass."
