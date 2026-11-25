"""Bundled offline ACP test peer. All response material is synthetic."""

from contextlib import contextmanager
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import sys
import time


SESSION = "synthetic-private-session"
PROFILE = "synthetic-profile.json"
VERIFIER = "synthetic-verifier.json"
ENROLLMENT_LOCK = "synthetic-enrollment.lock"


def is_identifier(value):
    return type(value) is str and re.fullmatch(r"[a-f0-9]{32}", value) is not None


def _unique(fields):
    result = dict(fields)
    if len(result) != len(fields):
        raise ValueError("duplicate JSON key")
    return result


def _invalid_constant(_value):
    raise ValueError("nonstandard JSON constant")


def decode_json(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_invalid_constant)


@contextmanager
def open_private(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ValueError("unsafe synthetic profile file")
        yield stream


def credential_digest(generation, credential, expires_at):
    payload = json.dumps([generation, credential, expires_at], separators=(",", ":")).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _load_private_record(path, keys):
    with open_private(path) as stream:
        raw = stream.read(1025)
    if len(raw) > 1024:
        raise ValueError("oversized synthetic record")
    fields = decode_json(raw)
    if type(fields) is not dict or fields.keys() != keys:
        raise ValueError("invalid synthetic record fields")
    return fields


def _check_binding(profile_root, generation, profile):
    if not is_identifier(generation) or profile["generation"] != generation or not is_identifier(profile["credential"]):
        raise ValueError("invalid profile binding")
    expires_at = profile["expires_at"]
    if expires_at is not None and (type(expires_at) is not int or expires_at < 0):
        raise ValueError("invalid profile expiration")
    expected = _load_private_record(profile_root / VERIFIER, {"generation", "digest"})
    digest = expected["digest"]
    if (expected["generation"] != generation or type(digest) is not str
            or not re.fullmatch(r"[a-f0-9]{64}", digest)):
        raise ValueError("invalid synthetic verifier binding")
    if not hmac.compare_digest(digest, credential_digest(generation, profile["credential"], expires_at)):
        raise ValueError("synthetic credential differs from enrollment")
    return expires_at


def profile_error(profile_root, generation):
    try:
        with open_private(profile_root / ENROLLMENT_LOCK) as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
            try:
                profile = _load_private_record(profile_root / PROFILE, {"generation", "credential", "expires_at"})
            except FileNotFoundError:
                return {"code": -32000, "message": "authentication required"}
            expires_at = _check_binding(profile_root, generation, profile)
    except (OSError, ValueError, RecursionError):
        return {"code": -32002, "message": "synthetic profile integrity error"}
    if expires_at is not None and expires_at <= time.time():
        return {"code": -32001, "message": "synthetic credential expired"}
    return None


def send(request_id, **body):
    print(json.dumps({"jsonrpc": "2.0", "id": request_id, **body}), flush=True)


def expect(request_id, method, params):
    expected = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
    if json.loads(sys.stdin.buffer.readline(4097)) != expected:
        raise SystemExit(2)


def send_session(scene):
    if scene == "duplicate":
        print('{"jsonrpc":"2.0","id":2,"result":{"sessionId":"first","sessionId":"second"}}', flush=True)
    elif scene == "malformed":
        print("{synthetic-private-error}", flush=True)
    elif scene == "oversized":
        send(2, result={"sessionId": "x" * (256 * 1024)})
    elif scene == "split":
        print('{"jsonrpc":"2.0",', end="", flush=True)
        time.sleep(.01)
        print('"id":2,"result":{"sessionId":"synthetic-private-session"}}', flush=True)
    elif scene == "dirty-workspace":
        Path("peer-created").touch(exist_ok=False)
        send(2, result={"sessionId": SESSION})
    elif scene in {"ready", "empty-session", "trailing", "bad-exit"}:
        send(2, result={"sessionId": " " if scene == "empty-session" else SESSION})
    else:
        raise SystemExit(2)


def main(scene, profile_root, generation):
    profile_root = Path(profile_root)
    if (os.environ != {"HOME": "/nonexistent", "LANG": "C.UTF-8"} or Path.cwd().parent != profile_root
            or any(Path.cwd().iterdir())):
        return 2
    expect(1, "initialize", {"protocolVersion": 1, "clientCapabilities": {}})
    if scene == "timeout":
        time.sleep(30)
        return 2
    if scene == "unsolicited":
        send(91, method="terminal/create", params={"command": "synthetic-never-run"})
        return 2
    send(3 if scene == "wrong-id" else 1, result={"protocolVersion": True if scene == "wrong-version" else 1})
    expect(2, "session/new", {"cwd": os.getcwd(), "mcpServers": []})
    error = profile_error(profile_root, generation)
    if error is not None:
        send(2, error=error)
    elif scene == "truncated":
        print('{"jsonrpc":"2.0","id":2,', end="", flush=True)
        return 0
    else:
        send_session(scene)
    if sys.stdin.buffer.read(1):
        return 2
    if scene == "trailing":
        send(92, method="session/update", params={"sessionUpdate": "tool_call"})
    return 2 if scene == "bad-exit" else 0


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:]))
