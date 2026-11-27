#!/usr/bin/env python3
"""Enter the Google workstation commands through the trusted launcher."""

import argparse
import os
from pathlib import Path
import stat
import sys


SOURCE_ROOT = Path(__file__).absolute().parent
PACKAGES = {
    "oc_google": (
        "__init__.py", "account_binding.py", "auth_offer.py", "cold_catalog.py", "connect.py",
        "control.py", "enrollment.py", "enrollment_session.py", "metadata_destination.py",
        "metadata_ingress.py", "metadata_workflow.py", "native_artifacts.py", "native_browser.py",
        "native_enrollment_acp.py", "native_namespace.py", "native_peer.py", "native_proxy.py",
        "native_service.py", "native_transport.py", "oauth_exchange.py", "registration.py",
        "route.py", "shell.py", "native_text.py", "token_diagnostic.py",
    ),
    "oc_orchestrator": ("__init__.py", "capture.py", "owner.py", "protocol.py", "relay.py", "runtime.py"),
    "oc_providers": ("__init__.py", "config.py", "contracts.py"),
}


def verify_node(path, *, directory=False):
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (not kind(info.st_mode) or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022
            or (not directory and info.st_nlink != 1)):
        raise ValueError("unsafe Google session source")


def verify_package(path, files):
    verify_node(path, directory=True)
    for name in files:
        verify_node(path / name)
    module_names = {name.partition(".")[0] for name in files}
    for entry in path.iterdir():
        if entry.name.partition(".")[0] in module_names and entry.name not in files:
            raise ValueError("unverified Google session import")


def verify_sources():
    if not sys.flags.isolated or not sys.flags.dont_write_bytecode or not sys.flags.no_site:
        raise ValueError("isolated Python is required")
    verify_node(SOURCE_ROOT, directory=True)
    verify_node(SOURCE_ROOT / "oc-google.py")
    for name, files in PACKAGES.items():
        verify_package(SOURCE_ROOT / name, files)
    # Imports should read the verified source rather than a prior checkout's bytecode.
    sys.pycache_prefix = "/dev/null"
    sys.path.append(str(SOURCE_ROOT))


def run_connect(label):
    from oc_google.connect import ConnectError, CustodyUnconfirmed, connect_for, needs_custody_inspection
    from oc_google.native_service import NativeRetirementUnconfirmed
    from oc_google.registration import RegistrationLabelOccupied

    try:
        return connect_for(label)
    except (OSError, ValueError, RuntimeError, KeyboardInterrupt) as error:
        interrupted = isinstance(error, KeyboardInterrupt)
        cleanup_only = isinstance(error, (CustodyUnconfirmed, NativeRetirementUnconfirmed))
        if cleanup_only:
            message = "Google enrollment cleanup requires inspection."
        elif isinstance(error, RegistrationLabelOccupied):
            message = "This label already has a Google registration or an unfinished attempt. Use a fresh label."
        elif isinstance(error, ConnectError):
            message = str(error)
        elif interrupted:
            message = "Google sign-in cancelled."
        else:
            message = "Workstation enrollment did not complete."
        print(f"oc-sandbox google: {message}", file=sys.stderr)
        if not cleanup_only and needs_custody_inspection(error):
            print("oc-sandbox google: Google enrollment cleanup requires inspection.", file=sys.stderr)
        return 130 if interrupted else 1


def main():
    try:
        verify_sources()
    except (OSError, ValueError):
        print("oc-sandbox google: trusted workstation command unavailable.", file=sys.stderr)
        return 1
    parser = argparse.ArgumentParser(prog="oc-sandbox google", allow_abbrev=False)
    verbs = parser.add_subparsers(dest="verb", required=True)
    verbs.add_parser("connect", help="Enroll Google workstation metadata using a sign-in link").add_argument("label")
    verbs.add_parser("shell", help="Open a restricted, one-turn Gemini OpenCode shell").add_argument("label")
    verbs.add_parser("arm", help="Authorize one fixed Gemini turn").add_argument("run_id")
    args = parser.parse_args()
    if args.verb == "connect":
        return run_connect(args.label)
    if args.verb == "arm":
        from oc_google.control import ControlError, arm
        try:
            return arm(args.run_id)
        except (OSError, ValueError, RuntimeError, ControlError):
            print("oc-sandbox google: The shell arm did not complete.", file=sys.stderr)
            return 1
    from oc_google.native_text import target_from_config
    from oc_google.shell import run_shell
    try:
        return run_shell(target_from_config(args.label))
    except (OSError, ValueError, RuntimeError):
        print("oc-sandbox google: The restricted shell did not complete.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
