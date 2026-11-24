"""Run the fixed proof in the verified workstation interpreter."""

from hashlib import sha256
import os
from pathlib import Path
import re
import signal
import stat
import sys


DRIVER = Path("tests/e2e/live/openai_driver.py")
RECOVERY = "--recover-proof-live"


def snapshot_digest(root):
    # Only these project modules are reachable through the workstation bootstrap.
    files = [DRIVER, Path("oc-openai.py")]
    for relative in (Path("oc_openai"), Path("oc_openai/managed")):
        directory = root / relative
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
                or info.st_mode & 0o222):
            raise ValueError("untrusted proof package directory")
        for entry in directory.iterdir():
            if entry.suffix == ".py":
                files.append(entry.relative_to(root))
            elif entry != root / "oc_openai/managed":
                raise ValueError("unexpected file in proof snapshot")
    digest = sha256()
    for name in sorted(files):
        fd = os.open(root / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid())
                    or info.st_nlink != 1 or info.st_mode & 0o222):
                raise ValueError("untrusted proof source file")
            contents = stream.read(1_048_577)
        if len(contents) > 1_048_576:
            raise ValueError("unexpected proof source size")
        digest.update(name.as_posix().encode("ascii") + b"\0" + sha256(contents).digest())
    return digest.hexdigest()


def main():
    args = sys.argv[1:]
    is_recovery = len(args) == 2 and args[0] == RECOVERY and re.fullmatch(r"[0-9a-f]{64}", args[1])
    if (not sys.flags.isolated or not sys.flags.dont_write_bytecode
            or (not is_recovery and args not in ([], ["--recover-openai-live"], ["--recover-stream-live"]))):
        return 2
    root = Path(__file__).parents[3]
    bootstrap = root / "oc-openai.py"
    try:
        if is_recovery and snapshot_digest(root) != args[1]:
            raise ValueError("recovery proof does not match reviewed source")
        # Execute the source the parent checked. -B alone still reads bytecode caches.
        namespace = {"__file__": str(bootstrap), "__name__": "openai_bootstrap"}
        exec(compile(bootstrap.read_bytes(), str(bootstrap), "exec"), namespace)
        cli = namespace["load_cli"]()
        from oc_openai.acceptance import run_attended
        from oc_openai.exposure import RecoveryMode
    except (ImportError, KeyError, OSError, SyntaxError, ValueError):
        print("OpenAI proof: trusted workstation source unavailable.", file=sys.stderr)
        return 1

    def interrupt_once(signum, frame):
        # Let the first interruption unwind through worker retirement and cleanup.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, interrupt_once)
    recovery = {
        ("--recover-openai-live",): RecoveryMode.FIRST,
        ("--recover-stream-live",): RecoveryMode.STREAM,
    }.get(tuple(args))
    return run_attended(
        cli.StreamTerminal(sys.stdin, sys.stdout, sys.stderr), recovery=recovery,
        recovery_source=args[1] if is_recovery else None,
    )


if __name__ == "__main__":
    raise SystemExit(main())
