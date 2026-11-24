"""Run the zero-tool OpenCode + OpenAI live canary in the verified workstation interpreter."""

from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys


DRIVER = Path("tests/e2e/live/openai_canary_driver.py")
LIVE_FLAG = "--run-openai-canary-live"
_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z", re.ASCII)
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_SOURCE_BYTES = 1_048_576


def _parse_args(argv: list[str]) -> tuple[str | None, str | None]:
    if not argv or argv[0] != LIVE_FLAG:
        raise ValueError("explicit --run-openai-canary-live flag required")
    model: str | None = None
    source_sha256: str | None = None
    idx = 1
    while idx < len(argv):
        flag = argv[idx]
        if idx + 1 >= len(argv):
            raise ValueError("missing flag value")
        value = argv[idx + 1]
        if flag == "--model" and model is None and _MODEL_RE.fullmatch(value):
            model = value
        elif flag == "--source-sha256" and source_sha256 is None and _SHA256_RE.fullmatch(value):
            source_sha256 = value
        else:
            raise ValueError("unsupported driver arguments")
        idx += 2
    return model, source_sha256


def _check_dir_node(directory: Path, *, mode_mask: int) -> None:
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
            or info.st_mode & mode_mask):
        raise ValueError("untrusted canary source directory")


def _collect_package_files(root: Path, relative: Path, *, mode_mask: int, files: list[Path]) -> None:
    directory = root / relative
    _check_dir_node(directory, mode_mask=mode_mask)
    for entry in sorted(directory.iterdir()):
        rel = entry.relative_to(root)
        if entry.is_dir() and not entry.is_symlink():
            if entry.name == "__pycache__":
                if mode_mask & 0o200:
                    raise ValueError("unexpected bytecode cache in verified canary package")
                continue
            _collect_package_files(root, rel, mode_mask=mode_mask, files=files)
        elif entry.suffix == ".py":
            files.append(rel)
        else:
            raise ValueError("unexpected file in canary package")


def _read_trusted_file(path: Path, *, mode_mask: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid())
                or info.st_nlink != 1 or info.st_mode & mode_mask):
            raise ValueError("untrusted canary source file")
        data = stream.read(_MAX_SOURCE_BYTES + 1)
    if len(data) > _MAX_SOURCE_BYTES:
        raise ValueError("canary source file exceeds size cap")
    return data


def snapshot_digest(root: Path, *, require_readonly: bool = False) -> tuple[str, bytes]:
    """Verify and hash all first-party canary sources before executing any bootstrap code."""
    mode_mask = 0o222 if require_readonly else 0o022
    if require_readonly:
        _check_dir_node(root, mode_mask=mode_mask)
        cur = root
        for part in DRIVER.parent.parts:
            cur = cur / part
            _check_dir_node(cur, mode_mask=mode_mask)
    files: list[Path] = [DRIVER, Path("oc-openai.py")]
    _collect_package_files(root, Path("oc_openai"), mode_mask=mode_mask, files=files)
    providers = root / "oc_providers"
    if providers.exists() or providers.is_symlink():
        _collect_package_files(root, Path("oc_providers"), mode_mask=mode_mask, files=files)
    digest = sha256()
    bootstrap_raw: bytes | None = None
    for rel in sorted(files):
        raw = _read_trusted_file(root / rel, mode_mask=mode_mask)
        if rel == Path("oc-openai.py"):
            bootstrap_raw = raw
        digest.update(rel.as_posix().encode("ascii") + b"\0" + sha256(raw).digest())
    if bootstrap_raw is None:
        raise ValueError("missing canary bootstrap")
    return digest.hexdigest(), bootstrap_raw


def main() -> int:
    if not sys.flags.isolated or not sys.flags.dont_write_bytecode:
        return 2
    try:
        model, expected_sha256 = _parse_args(sys.argv[1:])
    except ValueError:
        return 2
    root = Path(__file__).resolve().parents[3]
    bootstrap = root / "oc-openai.py"
    try:
        actual_digest, raw = snapshot_digest(root, require_readonly=(expected_sha256 is not None))
        if expected_sha256 is not None and not hmac.compare_digest(actual_digest, expected_sha256):
            raise ValueError("canary source digest does not match expected pin")
        namespace = {"__file__": str(bootstrap), "__name__": "openai_bootstrap"}
        exec(compile(raw, str(bootstrap), "exec"), namespace)
        namespace["load_cli"]()
        from oc_openai.canary import run_live_canary_e2e
    except (ImportError, KeyError, OSError, SyntaxError, ValueError):
        print("OpenAI canary e2e: trusted workstation source verification failed.", file=sys.stderr)
        return 1

    def interrupt_once(_signum, _frame):
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, interrupt_once)
    try:
        result = run_live_canary_e2e(requested_model=model)
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    summary = {
        "ok": result.ok,
        "label": result.label,
        "model": result.model,
        "source_digest": actual_digest,
        "upstream_calls": result.upstream_calls,
        "ledger_outcome": result.ledger_outcome,
        "delivered_bytes": result.delivered_bytes,
        "media_fallback": result.media_fallback,
        "input_tokens": result.input_tokens,
        "output_tokens": result.output_tokens,
        "opencode_rc": result.opencode_rc,
        "stdout_verified": result.stdout_verified,
        "cleanup_verified": result.cleanup_verified,
        "details": result.details,
    }
    print(json.dumps(summary, sort_keys=True), flush=True)
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
