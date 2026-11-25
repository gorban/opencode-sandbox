#!/usr/bin/python3 -IB
"""Synthetic native process and OpenCode executable-path shim for local qualification."""

import errno
import hashlib
import os
from pathlib import Path
import socket
import sys
from threading import Thread
import uuid

if __package__:
    from .claude_protocol import LIMIT, REPLY, decode, encode
else:
    sys.path.insert(0, str(Path(__file__).parent))
    from claude_protocol import LIMIT, REPLY, decode, encode


SOCKET = "/broker/native.sock"
CREDENTIAL = Path("/private/native-profile")
MODEL = "claude-fixture"


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


def shim():
    assert not CREDENTIAL.exists()
    assert not Path("/proc/1/root/private/native-profile").exists()
    assert not list(extra_descriptors())
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(12)
        client.connect(SOCKET)
        client.sendall(encode({"argv": sys.argv[1:]}))
        Thread(target=feed, args=(client,), daemon=True).start()
        while block := client.recv(8192):
            sys.stdout.buffer.write(block)
            sys.stdout.buffer.flush()


def control(message):
    subtype = message["request"]["subtype"]
    body = {}
    if subtype == "initialize":
        body = {
            "claude_code_version": "2.1.330", "models": [{"value": "haiku", "resolvedModel": MODEL,
                "displayName": "Fixture Haiku", "description": "Synthetic", "supportsEffort": False}],
            "account": {"tokenSource": "claude.ai", "subscriptionType": "pro", "apiProvider": "firstParty"},
            "commands": [], "agents": [], "output_style": "default", "available_output_styles": ["default"],
        }
    elif subtype == "get_context_usage":
        body = {"rawMaxTokens": 1048576}
    return {"type": "control_response", "response": {"subtype": "success", "request_id": message["request_id"],
                                                      "response": body}}


def turn(session):
    usage = {"input_tokens": 1, "output_tokens": 1, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}
    message = {"id": "msg_fixture", "type": "message", "role": "assistant", "model": MODEL, "content": [],
               "stop_reason": None, "stop_sequence": None, "usage": usage}
    identity = {"session_id": session, "parent_tool_use_id": None}
    events = [
        {"type": "message_start", "message": message},
        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": REPLY}},
        {"type": "content_block_stop", "index": 0},
        {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None}, "usage": usage},
        {"type": "message_stop"},
    ]
    for event in events:
        yield {"type": "stream_event", "event": event, "uuid": str(uuid.uuid4()), **identity}
    yield {"type": "assistant", "message": {**message, "content": [{"type": "text", "text": REPLY}]},
           "uuid": str(uuid.uuid4()), **identity}
    yield {"type": "result", "subtype": "success", "is_error": False, "num_turns": 1, "result": REPLY,
           "session_id": session, "uuid": str(uuid.uuid4()), "usage": usage, "modelUsage": {}, "total_cost_usd": 0,
           "duration_ms": 1, "duration_api_ms": 1, "permission_denials": [], "stop_reason": "end_turn"}


def native(session, digest):
    assert hashlib.sha256(CREDENTIAL.read_bytes()).hexdigest() == digest
    assert not Path(SOCKET).exists()
    for raw in iter(lambda: sys.stdin.buffer.readline(LIMIT + 1), b""):
        message = decode(raw)
        replies = [control(message)] if message["type"] == "control_request" else turn(session)
        for reply in replies:
            sys.stdout.buffer.write(encode(reply))
        sys.stdout.buffer.flush()


if __name__ == "__main__":
    if Path(sys.argv[0]).name == "claude-shim":
        shim()
    else:
        native(*sys.argv[1:])
