#!/usr/bin/env python3
"""Check sealed named Google enrollment using synthetic metadata."""

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
import runpy
import sys
import subprocess
import time
from urllib.parse import parse_qs, urlencode, urlsplit

SOURCE = Path(__file__).resolve().parent.parent
AUTH_URL = rb"https://accounts\.google\.com/o/oauth2/v2/auth\?[^\r\n ]+"
VENDOR_FILES = ("agy_acp_server.par", "localharness_external")
STEPS = ("TOKEN", "USERINFO", "LOAD_CODE_ASSIST", "TOKEN", "USERINFO", "LOAD_CODE_ASSIST", "FETCH_AVAILABLE_MODELS")
BROWSER_SCOPE = " ".join((
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/aicode",
    "email",
    "openid",
))


def catalog(*models):
    models = models or ("gemini-2.5-flash",)
    row = {"displayName": "Synthetic Gemini Flash", "model": "MODEL_GOOGLE_GEMINI_2_5_FLASH",
           "modelProvider": "MODEL_PROVIDER_GOOGLE", "apiProvider": "API_PROVIDER_GOOGLE_GEMINI",
           "maxTokens": 1048576, "maxOutputTokens": 8192}
    groups = [{"displayName": "Fixture", "modelIds": models}]
    sorts = [{"displayName": "Synthetic Gemini", "groups": groups}]
    entries = {
        "gemini-2.5-flash": row,
        "gemini-2.5-pro": row | {"displayName": "Synthetic Gemini Pro", "model": "MODEL_GOOGLE_GEMINI_2_5_PRO"},
    }
    return json.dumps({"models": {model: entries[model] for model in models},
                       "defaultAgentModelId": models[0], "agentModelSorts": sorts}).encode()


def copy_fixture(root, vendor, guard, *, label, subject, models):
    from test_google_enrollment import LOAD_REPLY
    from test_google_oauth_exchange import grant
    home = root / "home"
    target = root / "source"
    target.mkdir(mode=0o700)
    artifact = home / ".local/share/oc-sandbox/google/standalone-1.5.2"
    artifact.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name in VENDOR_FILES:
        shutil.copyfile(vendor / name, artifact / name)
    config = home / ".config/oc-sandbox"
    config.mkdir(mode=0o700, parents=True)
    (config / "providers.toml").write_text(
        f'[providers.google.{label}]\nenabled = true\nauth_mode = "subscription"\n', encoding="ascii",
    )
    for name in guard["RUNTIME"]:
        if name == guard["CONFIG"]:
            continue
        path = target / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(SOURCE / name, path)
    driver = target / guard["DRIVER"]
    shutil.copyfile(SOURCE / "tests" / guard["DRIVER"], driver)

    token = json.loads(grant())
    del token["refresh_token"]
    replies = (grant(), subject, LOAD_REPLY, json.dumps(token).encode(), subject, LOAD_REPLY, catalog(*models))
    destination = target / "oc_google/metadata_destination.py"
    contents = destination.read_text(encoding="utf-8")
    assert contents.count("\ndef _request(") == contents.count("\ndef exchange(") == 1
    head, _, _ = contents.partition("\ndef _request(")
    log = root / "synthetic-routes"
    destination.write_text(head + f"""
SYNTHETIC_FIXTURE_EXCHANGE = True
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
    return home, driver, log


def forward_fixture_offer(raw):
    from test_google_oauth_exchange import CODE
    offered = urlsplit(raw.decode("ascii"))
    fields = parse_qs(offered.query, strict_parsing=True)
    destination = urlsplit(fields["redirect_uri"][0])
    if destination.scheme != "http" or destination.hostname != "127.0.0.1" or destination.path != "/":
        raise AssertionError("Synthetic browser saw an unexpected loopback callback")
    port = destination.port
    query = urlencode({
        "state": fields["state"][0],
        "code": CODE,
        "iss": "https://accounts.google.com",
        "scope": BROWSER_SCOPE,
        "authuser": "1",
        "prompt": "consent",
    })
    with socket.create_connection(("127.0.0.1", port), timeout=5) as callback:
        callback.sendall(f"GET /?{query} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode("ascii"))
        if b"200 OK" not in callback.recv(512):
            raise AssertionError("Synthetic browser callback was refused")


def launch(home, launcher, label, descriptor):
    pid, master = pty.fork()
    if pid == 0:
        os.chdir(launcher.parent)
        os.execve("/usr/bin/python3", ["/usr/bin/python3", "-IBS", str(launcher), "--fixture", label, str(descriptor)],
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
            raise AssertionError("Synthetic offline enrollment exceeded its terminal deadline")
    finally:
        os.close(master)
        _, status = os.waitpid(pid, 0)
    if os.waitstatus_to_exitcode(status) or not consent or not offered or (
        f"Verified Google registration {label} for workstation metadata.".encode("ascii") not in output
    ):
        error = next((line for line in bytes(output).splitlines() if line.startswith(b"oc-sandbox google: ")), b"")
        raise AssertionError(f"Synthetic offline enrollment did not complete {error.decode('ascii', 'replace')}")


def observe_bound_catalog(root, source):
    """Record only test projections in the private copied launcher."""
    candidate_log = root / "bound-catalog"
    connect = source / "oc_google/connect.py"
    contents = connect.read_text(encoding="utf-8")
    anchor = "    _connect_metadata_for(label)\n"
    if contents.count(anchor) != 1:
        raise AssertionError("The public enrollment wrapper has no bound metadata return to observe")
    connect.write_text(contents.replace(anchor, f"""    from dataclasses import asdict
    import json
    catalog = _connect_metadata_for(label)
    payload = json.dumps(None if catalog is None else asdict(catalog))
    with open({str(candidate_log)!r}, "x", encoding="ascii") as receipt:
        receipt.write(payload)
"""), encoding="utf-8")

    acp_log = root / "acp-operations"
    acp_source = source / "oc_google/native_enrollment_acp.py"
    contents = acp_source.read_text(encoding="utf-8")
    anchor = "    def _send(self, request, method, params):\n"
    if contents.count(anchor) != 1:
        raise AssertionError("The pinned ACP dispatch point changed")
    acp_source.write_text(contents.replace(anchor, f"""    def _send(self, request, method, params):
        if method not in ("initialize", "session/new", "authenticate"):
            raise AssertionError("Unexpected ACP method in the metadata fixture")
        self._send_metadata_fixture(request, method, params)
        with open({str(acp_log)!r}, "a", encoding="ascii") as receipt:
            receipt.write(json.dumps([
                method, params.get("mcpServers"), params.get("_meta", {{}}).get(
                    "antigravity", {{}}
                ).get("enabledTools"),
            ]) + chr(10))

    def _send_metadata_fixture(self, request, method, params):
"""), encoding="utf-8")
    return candidate_log, acp_log


def verify_retired_registration(home, log, label):
    if tuple(log.read_text(encoding="ascii").splitlines()) != STEPS:
        raise AssertionError("The copied launcher did not perform the exact fake operation sequence")
    google = home / ".local/state/oc-sandbox/google"
    state = google / "registrations" / label
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
    if (google / "generation-fixtures").exists():
        raise AssertionError("The metadata enrollment touched the generation journal")
    return receipt["enrollment"]


def verify_bound_catalog(home, log, label, candidate_log, acp_log, expected_models):
    registration = verify_retired_registration(home, log, label)
    if registration["label"] != label:
        raise AssertionError("The durable journal belongs to a different label")
    candidate = json.loads(candidate_log.read_text(encoding="ascii"))
    expected = None
    if expected_models:
        expected = {"provider": f"google/{label}", "registration_id": registration["registration_id"],
                    "generation": registration["generation"], "build_digest": registration["build_digest"],
                    "models": expected_models}
    if candidate != expected:
        raise AssertionError("The bound metadata candidate differs from its actual registration or catalog")
    operations = [json.loads(line) for line in acp_log.read_text(encoding="ascii").splitlines()]
    if operations != [["initialize", None, None], ["session/new", [], None],
                      ["authenticate", None, None], ["initialize", None, None], ["session/new", [], []]]:
        raise AssertionError("The exact ACP sends extended beyond zero-prompt enrollment and cold metadata")
    return registration["registration_id"], registration["generation"]


def run_bound_catalog_cases(guard, vendor, seal):
    flash = "gemini-2.5-flash"
    decoy = "gemini-2.5-pro"
    cases = (
        ("fixture-alpha", b'{"id":"1040000001"}', (decoy, flash), [flash]),
        ("fixture-beta", b'{"id":"1040000002"}', (flash, decoy), [flash]),
        ("fixture-no-flash", b'{"id":"1040000003"}', (decoy,), None),
    )
    registrations, generations = set(), set()
    for label, subject, models, expected in cases:
        guard["require"](guard["guest"]() == seal)
        guard["check_home_before"](seal)
        guard["private_inventory"](seal["uid"])
        with guard["case_paths"](seal, label) as (case, home, _):
            home, launcher, log = copy_fixture(case, vendor, guard, label=label, subject=subject, models=models)
            candidate_log, acp_log = observe_bound_catalog(case, launcher.parent)
            source = launcher.parent
            for item in source.rglob("*"):
                item.chmod(0o500 if item.is_dir() else 0o400)
            source.chmod(0o500)
            descriptor = guard["prepare_descriptor"](case, label, seal)
            try:
                launch(home, launcher, label, descriptor)
            finally:
                os.close(descriptor)
            registration, generation = verify_bound_catalog(home, log, label, candidate_log, acp_log, expected)
        guard["private_inventory"](seal["uid"])
        if registration in registrations or generation in generations:
            raise AssertionError("Synthetic registrations shared a journal identity or generation")
        registrations.add(registration)
        generations.add(generation)
        for item in source.rglob("*"):
            if item.is_dir():
                item.chmod(0o700)
        source.chmod(0o700)
        shutil.rmtree(case)


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--bound-catalog", required=True, action="store_true")
    parser.parse_args()
    os.umask(0o077)
    private_source = Path("/home/.oc-gemini-cold-proof/source")
    entry = private_source / "tests/google-connect-fixture.py"
    loader = private_source / "tests/google_connect_driver.py"
    try:
        if not (sys.flags.isolated and sys.flags.dont_write_bytecode and sys.flags.no_site
                and Path(__file__).absolute() == entry and entry.resolve(strict=True) == entry):
            raise RuntimeError("Unsafe offline fixture entry")
        for path in (loader, *loader.parents):
            info = path.lstat()
            if path.resolve(strict=True) != path or info.st_uid != 0 or info.st_mode & 0o022:
                raise RuntimeError("Unsafe offline fixture source")
        guard = runpy.run_path(str(loader))
        guard["isolated"]()
        seal = guard["guest"]()
        guard["check_home_before"](seal)
        vendor = guard["vendor_pair"]()
        guard["private_inventory"](seal["uid"])
        sys.path.extend((str(private_source), str(private_source / "tests")))
        run_bound_catalog_cases(guard, vendor, seal)
        guard["private_inventory"](seal["uid"])
    except (OSError, ValueError, TypeError, KeyError, AssertionError, RuntimeError, subprocess.SubprocessError):
        print("Sealed offline Google fixture did not complete.", file=sys.stderr)
        return 1
    print("Verified three named offline catalogs, two Flash candidates, zero prompts and six retired runtimes.")
    print("Scoped native inventory empty.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
