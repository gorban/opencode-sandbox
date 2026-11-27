#!/usr/bin/env python3
"""Private workstation supervisor bootstrap for managed multi-provider `oc-sandbox` sessions.

Reads launch parameters from file descriptor 3 (never argv/cmdline) so stdin/stdout/stderr
stay attached to the operator's controlling foreground terminal.
"""

import importlib.util
import fcntl
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
        if entry.is_dir():
            _verify_package(entry)
        else:
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


def _verify_launcher_command(process: Path) -> None:
    source = Path(__file__).resolve().with_name("oc-sandbox")
    _trusted_node(source)
    if process.stat().st_uid != os.geteuid() or not os.path.samefile(process / "exe", "/usr/bin/bash"):
        raise ValueError("invalid launcher parent")
    with (process / "cmdline").open("rb") as command:
        args = command.read(4096).split(b"\0")
    # The script may be launched through a symlink or relative to the caller.
    script = next((arg for arg in args[1:] if arg and not arg.startswith(b"-")), b"")
    preceding = args[1:args.index(script, 1)] if script else ()
    if any(arg == b"-c" or (arg.startswith(b"-") and not arg.startswith(b"--") and b"c" in arg)
           for arg in preceding):
        raise ValueError("invalid launcher command")
    if not script or ((process / "cwd") / os.fsdecode(script)).resolve(strict=True) != source:
        raise ValueError("invalid launcher source")


def _launcher_pipe_endpoints(process: Path):
    for remote in (process / "fd").iterdir():
        try:
            info = remote.stat()
            if not stat.S_ISFIFO(info.st_mode):
                continue
            with (process / "fdinfo" / remote.name).open(encoding="ascii") as metadata:
                flags = next((line.split()[1] for line in metadata if line.startswith("flags:")), None)
            if flags is not None:
                yield info.st_dev, info.st_ino, int(flags, 8) & os.O_ACCMODE
        except FileNotFoundError:
            continue


def _admission_parent() -> int:
    parent = os.getppid()
    process = Path(f"/proc/{parent}")
    _verify_launcher_command(process)
    in_pipe, out_pipe = os.fstat(3), os.fstat(4)
    if (
        any(not stat.S_ISFIFO(info.st_mode) for info in (in_pipe, out_pipe))
        or os.path.samestat(in_pipe, out_pipe)
        or fcntl.fcntl(3, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
        or fcntl.fcntl(4, fcntl.F_GETFL) & os.O_ACCMODE != os.O_WRONLY
    ):
        raise ValueError("invalid managed launch channel")
    required = {(in_pipe.st_dev, in_pipe.st_ino, os.O_WRONLY), (out_pipe.st_dev, out_pipe.st_ino, os.O_RDONLY)}
    if required - set(_launcher_pipe_endpoints(process)) or os.getppid() != parent:
        raise ValueError("managed launch channels are not owned by the launcher")
    os.set_inheritable(3, False)
    os.set_inheritable(4, False)
    return parent


def main() -> int:
    if not sys.flags.isolated or not sys.flags.dont_write_bytecode or sys.argv[1:] not in ([], ["--admission"]):
        print("oc-sandbox: isolated workstation supervisor invocation required.", file=sys.stderr)
        return 2
    try:
        parent = _admission_parent() if sys.argv[1:] else None
        if parent is None:
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
        terminal = StreamTerminal(sys.stdin, sys.stdout, sys.stderr)
        if parent is None:
            from oc_openai.connection_state import decode_json
            from oc_openai.session_broker import run_interactive_session
            launch_spec = decode_json(raw)
        else:
            from oc_openai.session_admission import AdmissionChannel, run_admission_session
    except (ImportError, OSError, ValueError):
        print("oc-sandbox: trusted workstation supervisor unavailable.", file=sys.stderr)
        return 1
    if parent is not None:
        return run_admission_session(AdmissionChannel(3, 4, parent), terminal)
    return run_interactive_session(launch_spec, terminal)


if __name__ == "__main__":
    raise SystemExit(main())
