#!/usr/bin/env python3
"""Enter the restricted orchestrator before normal sandbox setup."""

import argparse
import os
import signal
import stat
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve()


def check_sources():
    package = SOURCE.parent / "oc_orchestrator"
    for path in (SOURCE.parent, package, SOURCE, *(package / name for name in (
            "__init__.py", "capture.py", "owner.py", "protocol.py", "relay.py", "runtime.py"))):
        info = path.lstat()
        kind = stat.S_ISDIR if path in (SOURCE.parent, package) else stat.S_ISREG
        if not kind(info.st_mode) or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
            raise ValueError("unsafe offline launcher source")


try:
    check_sources()
except (OSError, ValueError):
    raise SystemExit("orchestrate: unavailable trusted launcher sources") from None

sys.path.insert(0, str(SOURCE.parent))

from oc_orchestrator.owner import OwnerLost, accept_launch, supervise
from oc_orchestrator.runtime import Failure, run_proof


def interrupt(_number, _frame):
    raise KeyboardInterrupt


def main():
    if sys.argv[1:] == ["_owner"]:
        return run_owner()
    parser = argparse.ArgumentParser(prog="oc-sandbox orchestrate", allow_abbrev=False)
    parser.add_argument("--synthetic-check", action="store_true", help="run a disposable offline OpenCode check")
    args = parser.parse_args(sys.argv[2:])
    if not args.synthetic_check:
        print("orchestrate: live_route_unqualified", file=sys.stderr)
        return 2
    if sys.argv[1:2] != ["distrobox"]:
        print("orchestrate: the offline check currently requires the qualified devbox placement", file=sys.stderr)
        return 1
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGHUP, interrupt)
    try:
        code = supervise(SOURCE)
    except KeyboardInterrupt:
        print("orchestrate: interrupted", file=sys.stderr)
        return 130
    except (OSError, ValueError):
        print("orchestrate: local proof failed", file=sys.stderr)
        return 1
    if code == 0:
        print("ok")
    return code


def run_owner():
    try:
        run_proof(accept_launch())
    except (Failure, OwnerLost) as error:
        print(f"orchestrate: {error}", file=sys.stderr)
        return 1
    except (KeyError, OSError, RecursionError, TypeError, ValueError):
        print("orchestrate: local proof failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
