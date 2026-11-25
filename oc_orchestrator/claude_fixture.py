#!/usr/bin/python3 -IB
"""Synthetic native process and OpenCode executable-path shim for local qualification."""

import errno
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
from threading import Thread

if __package__:
    from .claude_protocol import LIMIT, ROUTE_FILE, SOCKET, control_reply, decode, encode, turn
else:
    sys.path.insert(0, str(Path(__file__).parent))
    from claude_protocol import LIMIT, ROUTE_FILE, SOCKET, control_reply, decode, encode, turn


CREDENTIAL = Path("/private/native-profile")
JOB_DATA = Path("/workspace/job.txt")
ALTERNATE_AUTH = {
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY",
}


def feed(client):
    try:
        while block := os.read(0, 8192):
            client.sendall(block)
        client.shutdown(socket.SHUT_WR)
    except OSError:
        return


def extra_descriptors():
    entries = list(Path("/proc/self/fd").iterdir())
    for entry in entries:
        number = int(entry.name)
        if number < 3:
            continue
        try:
            os.fstat(number)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise
        else:
            yield number


def verify_frontend_boundary():
    for target in (CREDENTIAL, Path("/proc/1/root/private/native-profile")):
        try:
            with target.open("rb"):
                raise RuntimeError("native login sentinel was readable by the frontend")
        except (FileNotFoundError, PermissionError):
            pass
    if ALTERNATE_AUTH.intersection(os.environ) or list(extra_descriptors()) or JOB_DATA.read_text() != "synthetic job data":
        raise RuntimeError("frontend fixture placement did not verify")


def frontend_route():
    return json.loads(Path(ROUTE_FILE).read_bytes())


def shim():
    verify_frontend_boundary()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(12)
        client.connect(SOCKET)
        client.sendall(encode({"route": frontend_route(), "argv": sys.argv[1:]}))
        Thread(target=feed, args=(client,), daemon=True).start()
        while block := client.recv(8192):
            sys.stdout.buffer.write(block)
            sys.stdout.buffer.flush()


def native(session, digest):
    assert hashlib.sha256(CREDENTIAL.read_bytes()).hexdigest() == digest
    assert not Path(SOCKET).exists()
    assert not Path(ROUTE_FILE).exists()
    assert not JOB_DATA.exists()
    assert not ALTERNATE_AUTH.intersection(os.environ)
    for raw in iter(lambda: sys.stdin.buffer.readline(LIMIT + 1), b""):
        message = decode(raw)
        replies = [control_reply(message)] if message["type"] == "control_request" else turn(session)
        for reply in replies:
            sys.stdout.buffer.write(encode(reply))
        sys.stdout.buffer.flush()


if __name__ == "__main__":
    if Path(sys.argv[0]).name == "claude-shim":
        shim()
    else:
        native(*sys.argv[1:])
