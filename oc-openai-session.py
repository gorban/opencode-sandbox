#!/usr/bin/env python3
"""Private workstation supervisor bootstrap for managed multi-provider `oc-sandbox` sessions.

Reads launch parameters from file descriptor 3 (never argv/cmdline) so stdin/stdout/stderr
stay attached to the operator's controlling foreground terminal.
"""

import importlib.util
import os
from pathlib import Path
import stat
import sys

MAX_SPEC_BYTES = 64 * 1024


def _trusted_node(path: Path, *, directory: bool = False) -> None:
    info = path.lstat()
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected_type(info.st_mode)
        or info.st_uid not in (0, os.geteuid())
        or info.st_mode & 0o022
        or (not directory and info.st_nlink != 1)
    ):
        raise ValueError("unsafe package path")


def _verify_package(directory: Path) -> None:
    _trusted_node(directory, directory=True)
    for entry in directory.iterdir():
        info = entry.lstat()
        if stat.S_ISDIR(info.st_mode):
            if entry.name == "__pycache__":
                raise ValueError("unverified cache directory in package")
            _verify_package(entry)
        else:
            if entry.suffix != ".py":
                raise ValueError("unverified non-source file in package")
            _trusted_node(entry)


def _load_package(name: str):
    package_dir = Path(__file__).parent / name
    _verify_package(package_dir)
    spec = importlib.util.spec_from_file_location(
        name,
        package_dir / "__init__.py",
        submodule_search_locations=[str(package_dir)],
    )
    if spec is None or spec.loader is None:
        raise ValueError(f"{name} package unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    if not sys.flags.isolated or not sys.flags.dont_write_bytecode or len(sys.argv) != 1:
        print("oc-sandbox: isolated workstation supervisor invocation required.", file=sys.stderr)
        return 2
    try:
        info = os.fstat(3)
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISFIFO(info.st_mode)):
            raise ValueError("invalid launch specification descriptor")
        with os.fdopen(3, "rb") as pipe:
            raw = pipe.read(MAX_SPEC_BYTES + 1)
        if not raw or len(raw) > MAX_SPEC_BYTES:
            raise ValueError("invalid launch specification size")
        _load_package("oc_providers")
        _load_package("oc_openai")
        from oc_openai.cli import StreamTerminal
        from oc_openai.connection_state import decode_json
        from oc_openai.session_broker import run_interactive_session
        launch_spec = decode_json(raw)
    except (ImportError, OSError, ValueError):
        print("oc-sandbox: trusted workstation supervisor unavailable.", file=sys.stderr)
        return 1
    return run_interactive_session(launch_spec, StreamTerminal(sys.stdin, sys.stdout, sys.stderr))


if __name__ == "__main__":
    raise SystemExit(main())
