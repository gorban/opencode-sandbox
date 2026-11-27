#!/usr/bin/env python3
"""Check the copied public Google enrollment launcher using synthetic metadata."""

import argparse
import errno
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import socket
import tempfile
import time
from urllib.parse import parse_qs, urlencode, urlsplit

from test_google_enrollment import LOAD_REPLY, SUBJECT
from test_google_oauth_exchange import CODE, grant


SOURCE = Path(__file__).resolve().parent.parent
PACKAGE_FILES = ("oc_google", "oc_orchestrator", "oc_providers")
AUTH_URL = rb"https://accounts\.google\.com/o/oauth2/v2/auth\?[^\r\n ]+"
VENDOR_FILES = ("agy_acp_server.par", "localharness_external")
STEPS = ("TOKEN", "USERINFO", "LOAD_CODE_ASSIST", "TOKEN", "USERINFO", "LOAD_CODE_ASSIST", "FETCH_AVAILABLE_MODELS")


def catalog():
    model = "gemini-2.5-flash"
    row = {"displayName": "Synthetic Gemini Flash", "model": "MODEL_GOOGLE_GEMINI_2_5_FLASH",
           "modelProvider": "MODEL_PROVIDER_GOOGLE", "apiProvider": "API_PROVIDER_GOOGLE_GEMINI",
           "maxTokens": 1048576, "maxOutputTokens": 8192}
    groups = [{"displayName": "Fixture", "modelIds": [model]}]
    sorts = [{"displayName": "Synthetic Gemini", "groups": groups}]
    return json.dumps({"models": {model: row}, "defaultAgentModelId": model, "agentModelSorts": sorts}).encode()


def copy_fixture(root, vendor):
    home = root / "home"
    target = root / "source"
    target.mkdir(mode=0o700)
    artifact = home / ".local/share/oc-sandbox/google/standalone-1.5.2"
    artifact.mkdir(mode=0o700, parents=True)
    for name in VENDOR_FILES:
        shutil.copyfile(vendor / name, artifact / name)
    config = home / ".config/oc-sandbox"
    config.mkdir(mode=0o700, parents=True)
    (config / "providers.toml").write_text(
        '[providers.google.fixture]\nenabled = true\nauth_mode = "subscription"\n', encoding="ascii",
    )
    for name in ("oc-sandbox", "oc-google.py"):
        shutil.copy2(SOURCE / name, target / name)
    for package in PACKAGE_FILES:
        shutil.copytree(SOURCE / package, target / package, ignore=shutil.ignore_patterns("__pycache__"))
    config_source = target / "oc_providers/config.py"
    contents = config_source.read_text(encoding="utf-8")
    start = contents.index("def _account_home() -> Path:")
    end = contents.index("\n\ndef default_config_dir()", start)
    contents = contents[:start] + f"def _account_home() -> Path:\n    return Path({str(home)!r})" + contents[end:]
    env_check = 'env_home = os.environ.get("HOME")'
    assert contents.count(env_check) == 1
    config_source.write_text(contents.replace(env_check, f"env_home = {str(home)!r}"), encoding="utf-8")

    token = json.loads(grant())
    del token["refresh_token"]
    replies = (grant(), SUBJECT, LOAD_REPLY, json.dumps(token).encode(), SUBJECT, LOAD_REPLY, catalog())
    destination = target / "oc_google/metadata_destination.py"
    contents = destination.read_text(encoding="utf-8")
    assert contents.count("\ndef exchange(") == 1
    head, _, _ = contents.partition("\ndef exchange(")
    log = root / "synthetic-routes"
    destination.write_text(head + f"""
_steps = {STEPS!r}
_replies = {replies!r}
_observed = []

def exchange(route, *, authorization, body=b"", deadline, deliver):
    index = len(_observed)
    if index >= len(_steps) or route.name != _steps[index]:
        raise MetadataDestinationError("Synthetic route mismatch")
    _remaining(deadline)

    def report():
        _observed.append(route.name)
        with open({str(log)!r}, "a", encoding="ascii") as sink:
            sink.write(route.name + "\\n")

    deliver(report)
    return _replies[index]
""", encoding="utf-8")
    return home, target / "oc-sandbox", log


def forward_fixture_offer(raw):
    offered = urlsplit(raw.decode("ascii"))
    fields = parse_qs(offered.query, strict_parsing=True)
    destination = urlsplit(fields["redirect_uri"][0])
    if destination.scheme != "http" or destination.hostname != "127.0.0.1" or destination.path != "/":
        raise AssertionError("Synthetic browser saw an unexpected loopback callback")
    port = destination.port
    query = urlencode({"state": fields["state"][0], "code": CODE})
    with socket.create_connection(("127.0.0.1", port), timeout=5) as callback:
        callback.sendall(f"GET /?{query} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode("ascii"))
        if b"200 OK" not in callback.recv(512):
            raise AssertionError("Synthetic browser callback was refused")


def launch(home, launcher):
    pid, master = pty.fork()
    if pid == 0:
        os.chdir(launcher.parent)
        os.execve(launcher, [str(launcher), "google", "connect", "fixture"],
                  {"HOME": str(home), "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})

    output = bytearray()
    consent = False
    offered = False
    deadline = time.monotonic() + 220
    try:
        while time.monotonic() < deadline:
            if not select.select([master], [], [], .1)[0]:
                continue
            try:
                chunk = os.read(master, 16384)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > 16384:
                raise AssertionError("Synthetic enrollment exceeded terminal output bound")
            if not consent and b"Continue? [y/N] " in output:
                os.write(master, b"y\n")
                consent = True
            if not offered and (match := re.search(AUTH_URL + rb"(?=\r?\n)", output)):
                forward_fixture_offer(match.group())
                offered = True
        else:
            raise AssertionError("Synthetic public enrollment exceeded its terminal deadline")
    finally:
        os.close(master)
        _, status = os.waitpid(pid, 0)
    if os.waitstatus_to_exitcode(status) or not consent or not offered or (
        b"Verified Google registration fixture for workstation metadata." not in output
    ):
        error = next((line for line in bytes(output).splitlines() if line.startswith(b"oc-sandbox google: ")), b"")
        raise AssertionError(f"Synthetic public enrollment did not complete {error.decode('ascii', 'replace')}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vendor", required=True, type=Path, help="Directory containing the two pinned standalone artifacts")
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="oc-g-connect-fixture-", dir=f"/run/user/{os.getuid()}"))
    try:
        home, launcher, log = copy_fixture(root, args.vendor)
        launch(home, launcher)
        if tuple(log.read_text(encoding="ascii").splitlines()) != STEPS:
            raise AssertionError("The copied launcher did not perform the exact fake operation sequence")
        state = home / ".local/state/oc-sandbox/google/registrations/fixture"
        receipt = json.loads((state / "registration.json").read_text(encoding="ascii"))
        if receipt["phase"] != "cold-retirement-observed":
            raise AssertionError("No settled cold observation was recorded")
        for phase in ("enrollment", "cold"):
            launched = json.loads((state / f"{phase}-native-launch.json").read_text(encoding="ascii"))
            attested = json.loads((state / f"{phase}-native-attested.json").read_text(encoding="ascii"))
            retired = json.loads((state / f"{phase}-native-retired.json").read_text(encoding="ascii"))
            scratch = Path(launched["root"])
            if (launched["unit"] != attested["unit"] or retired != attested or scratch.exists()
                    or scratch.with_name("." + scratch.name + "-retire").exists()):
                raise AssertionError("The recorded exact runtime did not retire")
    except BaseException:
        print(f"Retained private synthetic fixture for inspection under {root}", flush=True)
        raise
    else:
        shutil.rmtree(root)
        print("Copied public launcher enrolled and cold-reopened with seven exact fake operations and two retired runtimes.")


if __name__ == "__main__":
    main()
