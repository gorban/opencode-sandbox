#!/usr/bin/env python3
"""Offline portal repair checks with synthetic files and no external inputs."""

import argparse
import hashlib
import importlib.util
from ipaddress import IPv4Address
import json
from pathlib import Path
import shlex
import shutil
import ssl
import sys
import tempfile
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
VARIANTS = ("E", "X")
BROWSER_DIRS = ("home", "config", "data", "cache", "state", "profile")
ORIGINAL_LAUNCHER = "before\n"


def load_repair(root):
    destination = root / "docs/prds/spikes/e1/repair-host-chrome-portal.py"
    destination.parent.mkdir(parents=True)
    shutil.copyfile(HERE / destination.name, destination)
    spec = importlib.util.spec_from_file_location("e1_repair", destination)
    repair = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(repair)
    return repair


def make_fixture(root):
    chrome = root / ".scratch/e1-chrome-fixture"
    chrome.mkdir(parents=True, mode=0o700)
    for name in (*BROWSER_DIRS, "ca"):
        (chrome / name).mkdir(mode=0o700)

    launcher = chrome / "launch-chrome.sh"
    launcher.write_text(ORIGINAL_LAUNCHER, encoding="utf-8")
    launcher.chmod(0o700)
    (chrome / "profile/sentinel").write_text("unchanged", encoding="utf-8")
    data = {
        "chrome_home": str(chrome / "home"),
        "chrome_user_data_dir": str(chrome / "profile"),
        "chrome_launcher": str(launcher),
        "proxy": "127.0.0.1:4430",
        "ca_files": {},
        "ca_sha256": {},
    }
    exports = {}
    for variant in VARIANTS:
        # The helper checks the PEM framing and digest without installing trust.
        payload = f"synthetic portal fixture {variant}".encode("ascii")
        pem = ssl.DER_cert_to_PEM_cert(payload)
        ca = chrome / "ca" / f"{variant}.pem"
        ca.write_text(pem, encoding="ascii")
        ca.chmod(0o600)
        data["ca_files"][variant] = str(ca)
        data["ca_sha256"][variant] = hashlib.sha256(payload).hexdigest()

        portal_file = root / "doc" / f"id{variant}" / ca.name
        portal_file.parent.mkdir(parents=True)
        portal_file.write_text(pem, encoding="ascii")
        exports[variant] = portal_file

    manifest = chrome / "manifest.json"
    manifest.write_text(json.dumps(data), encoding="utf-8")
    manifest.chmod(0o600)
    return chrome, manifest, launcher, exports, data


def check_repair(repair, chrome, manifest, launcher, exports):
    target, content = repair.build(manifest, exports)
    assert target == launcher
    argv = shlex.split(content.splitlines()[2][5:])
    mounts = [argument for argument in argv if argument.startswith("--filesystem=")]
    expected = [f"--filesystem={chrome / name}" for name in BROWSER_DIRS]
    expected.extend(f"--filesystem={path}:ro" for path in (chrome / "ca", *exports.values()))
    assert mounts == expected
    assert "--session-bus" in argv and "--sandbox" in argv
    assert not any("ignore-certificate-errors" in arg or arg in ("--no-sandbox", "--socket=session-bus")
                   for arg in argv)

    assert launcher.read_text(encoding="utf-8") == ORIGINAL_LAUNCHER
    with launcher.open(encoding="utf-8") as original:
        repair.replace_launcher(target, content)
        assert original.read() == ORIGINAL_LAUNCHER
    assert launcher.read_text(encoding="utf-8") == content
    assert launcher.stat().st_mode & 0o777 == 0o700
    assert (chrome / "profile/sentinel").read_text(encoding="utf-8") == "unchanged"
    print("exact mounts, private profile and atomic launcher replacement: PASS")


def assert_rejected(repair, manifest, exports, label, expected):
    try:
        repair.build(manifest, exports)
    except ValueError as error:
        assert expected in str(error), error
        print(f"{label}: rejected")
    else:
        raise AssertionError(f"{label} accepted")


def check_invalid_exports(repair, root, manifest, exports):
    mismatched = root / "doc/bad/E.pem"
    mismatched.parent.mkdir()
    mismatched.write_bytes(b"not the synthetic CA")
    wrong_name = exports["E"].with_name("other.pem")
    shutil.copyfile(exports["E"], wrong_name)
    link = root / "doc/link/E.pem"
    link.parent.mkdir()
    link.symlink_to(exports["E"])
    for label, candidate, expected in (
        ("different bytes", mismatched, "does not match the private CA bytes"),
        ("wrong filename", wrong_name, "must be a single matching PEM"),
        ("symlink", link, "unsafe file"),
    ):
        assert_rejected(repair, manifest, {**exports, "E": candidate}, label, expected)


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    sys.dont_write_bytecode = True
    with tempfile.TemporaryDirectory(prefix="oc-e1-portal-") as directory:
        root = Path(directory).resolve()
        repair = load_repair(root)
        chrome, manifest, launcher, exports, data = make_fixture(root)
        validate_export = repair.validate_export

        def validate_in_fixture(path, variant, expected, _portal_root):
            validate_export(path, variant, expected, root / "doc")

        with patch.object(repair, "validate_export", side_effect=validate_in_fixture):
            check_repair(repair, chrome, manifest, launcher, exports)
            check_invalid_exports(repair, root, manifest, exports)
            # RFC 5737 TEST-NET-1 keeps the rejection check off public endpoints.
            test_address = IPv4Address(bytes((192, 0, 2, 1)))
            data["proxy"] = f"{test_address}:443"
            manifest.write_text(json.dumps(data), encoding="utf-8")
            assert_rejected(repair, manifest, exports, "non-loopback proxy", "proxy must be loopback")


if __name__ == "__main__":
    main()
