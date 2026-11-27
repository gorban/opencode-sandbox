#!/usr/bin/env python3
"""Enter the Google workstation commands through the trusted launcher."""

import argparse
import os
from pathlib import Path
import re
import stat
import sys


SOURCE_ROOT = Path(__file__).absolute().parent
CONFIG_DIR = None
PACKAGES = {
    "oc_google": (
        "__init__.py", "account_binding.py", "auth_offer.py", "cold_catalog.py", "connect.py",
        "control.py", "enrollment.py", "enrollment_session.py", "metadata_destination.py",
        "metadata_ingress.py", "metadata_workflow.py", "native_artifacts.py", "native_browser.py",
        "native_enrollment_acp.py", "native_namespace.py", "native_peer.py", "native_proxy.py",
        "native_service.py", "native_transport.py", "oauth_exchange.py", "registration.py",
        "route.py", "shell.py",
    ),
    "oc_orchestrator": ("__init__.py", "capture.py", "owner.py", "protocol.py", "relay.py", "runtime.py"),
    "oc_providers": ("__init__.py", "config.py", "contracts.py"),
}
RUN_ID = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)


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


class GoogleUnavailable(RuntimeError):
    """The requested Google launch is unavailable without touching provider state."""


def qualified_route(spec):
    raise GoogleUnavailable("This Google subscription route has yet to qualify for native inference.")


def shell_for(label):
    from oc_providers.config import load_provider_config
    from oc_providers.contracts import is_valid_instance_label

    if not is_valid_instance_label(label):
        raise GoogleUnavailable("Invalid Google registration label.")
    config = load_provider_config(config_dir=CONFIG_DIR)
    spec = config.get("google", label) if config is not None else None
    if spec is None or not spec.enabled or spec.auth_mode != "subscription":
        raise GoogleUnavailable("Enable a Google subscription registration in providers.toml first.")
    target = qualified_route(spec)
    from oc_google.shell import run_shell

    return run_shell(target)


def arm_turn(run_id):
    if RUN_ID.fullmatch(run_id) is None:
        raise GoogleUnavailable("Invalid Google session ID.")
    from oc_google.control import arm

    return arm(run_id)


def run_connect(label):
    from oc_google.connect import ConnectError, CustodyUnconfirmed, connect_for, needs_custody_inspection
    from oc_google.native_service import NativeRetirementUnconfirmed

    try:
        return connect_for(label)
    except (OSError, ValueError, RuntimeError, KeyboardInterrupt) as error:
        interrupted = isinstance(error, KeyboardInterrupt)
        cleanup_only = isinstance(error, (CustodyUnconfirmed, NativeRetirementUnconfirmed))
        if cleanup_only:
            message = "Google enrollment cleanup requires inspection."
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
    verbs.add_parser("shell", help="Open the restricted Google text shell").add_argument("label")
    verbs.add_parser("arm", help="Authorize one turn in the specified shell").add_argument("run_id")
    args = parser.parse_args()

    if args.verb == "connect":
        return run_connect(args.label)

    from oc_google.control import ControlError
    from oc_orchestrator.owner import OwnerLost
    from oc_orchestrator.runtime import Failure
    from oc_providers.config import ProviderConfigError

    try:
        if args.verb == "shell":
            return shell_for(args.label)
        return arm_turn(args.run_id)
    except KeyboardInterrupt:
        return 130
    except (ControlError, Failure, GoogleUnavailable, OwnerLost, ProviderConfigError) as error:
        print(f"oc-sandbox google: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, RuntimeError):
        print("oc-sandbox google: local session did not complete.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
