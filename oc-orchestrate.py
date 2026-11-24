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
            "__init__.py", "capture.py", "owner.py", "protocol.py", "relay.py", "runtime.py",
            "claude.py", "claude_fixture.py", "claude_launch.py", "claude_protocol.py"))):
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
from oc_orchestrator.claude import run_proof as run_claude_proof


def interrupt(_number, _frame):
    raise KeyboardInterrupt


def main():
    if sys.argv[1:] == ["_owner"]:
        return run_owner()
    if len(sys.argv) == 4 and sys.argv[1:3] == ["_owner", "claude"]:
        return run_owner(claude_binary=sys.argv[3])
    parser = argparse.ArgumentParser(prog="oc-sandbox orchestrate", allow_abbrev=False)
    parser.add_argument("--synthetic-check", action="store_true", help="run a disposable offline OpenCode check")
    parser.add_argument("--provider", choices=("claude",), help="select a provider")
    parser.add_argument("--opencode", type=Path, help="use the pinned standalone OpenCode binary for the Claude fixture")
    args = parser.parse_args(sys.argv[2:])
    if not args.synthetic_check:
        print("orchestrate: live_route_unqualified", file=sys.stderr)
        return 2
    if args.provider == "claude" and (args.opencode is None or not args.opencode.is_absolute()):
        parser.error("the Claude fixture requires an absolute --opencode path")
    if args.provider is None and args.opencode is not None:
        parser.error("--opencode is available for the Claude fixture")
    if args.provider is None and sys.argv[1:2] != ["distrobox"]:
        print("orchestrate: the offline check currently requires the qualified devbox placement", file=sys.stderr)
        return 1
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGHUP, interrupt)
    try:
        if args.provider == "claude":
            code, reply = supervise(SOURCE, "claude", str(args.opencode), output=True)
            if code == 0:
                sys.stdout.buffer.write(reply)
            return code
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


def run_owner(*, claude_binary=None):
    try:
        lifeline = accept_launch()
        if claude_binary is None:
            run_proof(lifeline)
        else:
            reply = run_claude_proof(lifeline, claude_binary)
            lifeline.check()
            os.write(1, (reply + "\n").encode())
    except (Failure, OwnerLost) as error:
        print(f"orchestrate: {error}", file=sys.stderr)
        return 1
    except (KeyError, OSError, RecursionError, TypeError, ValueError):
        print("orchestrate: local proof failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
