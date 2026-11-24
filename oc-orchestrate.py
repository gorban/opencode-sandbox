#!/usr/bin/env python3
"""Enter the restricted orchestrator before normal sandbox setup."""

import argparse
import signal
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from oc_orchestrator.runtime import Failure, run_proof


def interrupt(_number, _frame):
    raise KeyboardInterrupt


def main():
    parser = argparse.ArgumentParser(prog="oc-sandbox orchestrate", allow_abbrev=False)
    parser.add_argument("--synthetic-check", action="store_true", help="run a disposable offline OpenCode check")
    args = parser.parse_args(sys.argv[2:])
    if not args.synthetic_check:
        print("orchestrate: live_route_unqualified", file=sys.stderr)
        return 2
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGHUP, interrupt)
    try:
        run_proof(sys.argv[1])
    except Failure as error:
        print(f"orchestrate: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("orchestrate: interrupted", file=sys.stderr)
        return 130
    except (OSError, ValueError):
        print("orchestrate: local proof failed", file=sys.stderr)
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
