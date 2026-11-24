#!/usr/bin/env python3
"""Bootstrap the OpenAI workstation command from the verified checkout."""

import importlib.util
import os
from pathlib import Path
import stat
import sys


def trusted_node(path: Path, *, directory: bool = False) -> None:
    info = path.lstat()
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected_type(info.st_mode)
        or info.st_uid not in (0, os.geteuid())
        or info.st_mode & 0o022
        or (not directory and info.st_nlink != 1)
    ):
        raise ValueError("unsafe OpenAI package path")


def verify_package(directory: Path) -> None:
    trusted_node(directory, directory=True)
    for entry in directory.iterdir():
        if entry.is_dir():
            verify_package(entry)
        else:
            trusted_node(entry)


def load_cli():
    if not sys.flags.isolated or not sys.flags.dont_write_bytecode:
        raise ValueError("isolated Python is required")
    package_dir = Path(__file__).parent / "oc_openai"
    verify_package(package_dir)
    package = importlib.util.spec_from_file_location(
        "oc_openai",
        package_dir / "__init__.py",
        submodule_search_locations=[str(package_dir)],
    )
    if package is None or package.loader is None:
        raise ValueError("OpenAI command package is unavailable")
    module = importlib.util.module_from_spec(package)
    sys.modules[package.name] = module
    package.loader.exec_module(module)
    from oc_openai import cli

    return cli


def main() -> int:
    try:
        cli = load_cli()
    except (ImportError, OSError, ValueError):
        print("oc-sandbox openai: trusted workstation command unavailable.", file=sys.stderr)
        return 1
    return cli.run(sys.argv[1:], terminal=cli.StreamTerminal(sys.stdin, sys.stdout, sys.stderr))


if __name__ == "__main__":
    raise SystemExit(main())
