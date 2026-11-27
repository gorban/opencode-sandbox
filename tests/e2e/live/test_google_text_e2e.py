"""Opt-in live checks sharing one approval for the selected Google subscription tests."""

from pathlib import Path
import subprocess

import pytest

from conftest import claim_google_case


def run_google_case(request, route):
    if not claim_google_case(request):
        pytest.skip("Google subscription test was not enabled and approved")
    target = Path(__file__).resolve()
    root = target.parents[3]
    driver = target.with_name("google_text_driver.py")
    status = subprocess.run(
        ["/usr/bin/python3", "-IBS", str(driver), route], cwd=root,
        env={"HOME": str(Path.home()), "PATH": "/usr/bin:/bin"}, check=False,
        input=f"pytest approved {route}\n".encode("ascii"),
    ).returncode
    if status == 130:
        raise KeyboardInterrupt
    if status != 0:
        pytest.fail("The live Gemini text proof did not pass. See the workstation diagnostic.", pytrace=False)


def test_google_cached_login_text(request):
    run_google_case(request, "native")


def test_google_opencode_text(request):
    run_google_case(request, "opencode")


def test_google_public_shell(request):
    if not claim_google_case(request):
        pytest.skip("The public Google shell test was not enabled and approved")
    source = Path(__file__).resolve()
    root = source.parents[3]
    driver = source.with_name("google_public_shell_driver.py")
    status = subprocess.run(
        ["/usr/bin/python3", "-IBS", str(driver)], cwd=root,
        env={"HOME": str(Path.home()), "PATH": "/usr/bin:/bin"}, check=False,
        input=b"pytest approved public shell\n",
    ).returncode
    if status == 130:
        raise KeyboardInterrupt
    if status != 0:
        pytest.fail("The public Google shell proof did not pass. Inspect the terminal result.", pytrace=False)
