#!/usr/bin/env python3
"""Bootstrap the OpenAI workstation command from the verified checkout."""

import hashlib
import hmac
import importlib.util
import os
from pathlib import Path
import re
import stat
import sys


_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_SOURCE_BYTES = 1_048_576


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


def _read_trusted_source(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid not in (0, os.geteuid())
            or info.st_nlink != 1
            or info.st_mode & 0o022
        ):
            raise ValueError("unsafe OpenAI source file")
        data = stream.read(_MAX_SOURCE_BYTES + 1)
    if len(data) > _MAX_SOURCE_BYTES:
        raise ValueError("OpenAI source file exceeds size cap")
    return data


def _collect_package_files(base: Path, directory: Path, out: list[Path]) -> None:
    trusted_node(directory, directory=True)
    for entry in sorted(directory.iterdir()):
        if entry.is_dir():
            _collect_package_files(base, entry, out)
        else:
            trusted_node(entry)
            out.append(entry.relative_to(base))


def canary_source_digest(root: Path | None = None) -> str:
    """Compute a deterministic SHA-256 over the bootstrap, launcher, and all first-party packages."""
    base = Path(__file__).resolve().parent if root is None else Path(root)
    files = [Path("oc-sandbox"), Path("oc-openai.py")]
    for pkg in ("oc_openai", "oc_providers"):
        _collect_package_files(base, base / pkg, files)
    hasher = hashlib.sha256()
    for rel in sorted(files):
        data = _read_trusted_source(base / rel)
        hasher.update(rel.as_posix().encode("ascii") + b"\0" + hashlib.sha256(data).digest())
    return hasher.hexdigest()


def _extract_reviewed_source(argv: list[str]) -> str | None:
    if not argv or argv[0] != "canary":
        return None
    found = None
    recover = False
    synth = False
    idx = 1
    while idx < len(argv):
        arg = argv[idx]
        if arg == "--reviewed-source":
            if found is not None or idx + 1 >= len(argv) or not _SHA256_RE.fullmatch(argv[idx + 1]):
                raise ValueError("invalid --reviewed-source")
            found = argv[idx + 1]
            idx += 2
            continue
        recover = recover or (arg == "--recover-unsettled")
        synth = synth or (arg == "--synthetic-check")
        idx += 1
    if recover and (found is None or synth):
        raise ValueError("invalid --recover-unsettled arguments")
    return found


def _load_package(name: str):
    package_dir = Path(__file__).parent / name
    verify_package(package_dir)
    package = importlib.util.spec_from_file_location(
        name,
        package_dir / "__init__.py",
        submodule_search_locations=[str(package_dir)],
    )
    if package is None or package.loader is None:
        raise ValueError(f"{name} package is unavailable")
    module = importlib.util.module_from_spec(package)
    sys.modules[package.name] = module
    package.loader.exec_module(module)
    return module


def load_cli():
    if not sys.flags.isolated or not sys.flags.dont_write_bytecode:
        raise ValueError("isolated Python is required")
    providers_dir = Path(__file__).parent / "oc_providers"
    if providers_dir.exists() or providers_dir.is_symlink():
        _load_package("oc_providers")
    _load_package("oc_openai")
    from oc_openai import cli

    return cli


def main() -> int:
    argv = sys.argv[1:]
    try:
        reviewed = _extract_reviewed_source(argv)
        if reviewed is not None:
            computed = canary_source_digest(Path(__file__).resolve().parent)
            if not hmac.compare_digest(computed, reviewed):
                print("ChatGPT canary source digest does not match --reviewed-source.", file=sys.stderr)
                return 1
        cli = load_cli()
    except (ImportError, OSError, ValueError):
        print("oc-sandbox openai: trusted workstation command unavailable.", file=sys.stderr)
        return 1
    return cli.run(argv, terminal=cli.StreamTerminal(sys.stdin, sys.stdout, sys.stderr))


if __name__ == "__main__":
    raise SystemExit(main())
