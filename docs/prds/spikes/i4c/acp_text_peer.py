"""Bundled synthetic ACP text peer. Every output and credential is a local fixture."""

import hashlib
import json
import os
from pathlib import Path
import sys
import time

from acp_fixture import SESSION, decode_json, is_identifier, profile_error
from oc_orchestrator.protocol import PROMPT


INIT_ID = 1
SESSION_ID = 2
PROMPT_ID = 3
MAX_FRAMES = 16
EARLY_SCENES = frozenset({"early", "mixed"})
SCENES = EARLY_SCENES | {
    "ready", "split", "permission", "wrong-stop", "wrong-id", "wrong-session",
    "trailing", "bad-exit", "timeout", "init-timeout", "malformed", "duplicate",
    "cr", "bom", "bad-utf8", "constant", "bool-id", "extra-result", "extra-envelope",
    "truncated", "oversized", "coalesced-init", "over-frames", "bad-receipt", "extra-receipt",
    "wrong-version", "empty-line", "coalesced-session",
}


def wire(frame):
    return json.dumps(frame, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"


def frame_body(line):
    if not line or b"\r" in line or line.startswith(b"\xef\xbb\xbf"):
        raise ValueError("invalid NDJSON frame")
    return decode_json(line)


def request(request_id, method, params):
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}


def prompt_request(session_id):
    return request(PROMPT_ID, "session/prompt",
                   {"sessionId": session_id, "prompt": [{"type": "text", "text": PROMPT}]})


def response(request_id, **body):
    return {"jsonrpc": "2.0", "id": request_id, **body}


def update(text, session_id=SESSION):
    return {
        "jsonrpc": "2.0", "method": "session/update",
        "params": {"sessionId": session_id, "update": {
            "sessionUpdate": "agent_message_chunk",
            "content": {"type": "text", "text": text},
        }},
    }


def hash_chunk(digest, text):
    raw = text.encode("utf-8")
    digest.update(len(raw).to_bytes(4, "big"))
    digest.update(raw)


def read_request(expected):
    line = sys.stdin.buffer.readline(4096)
    if not line:
        return None
    if not line.endswith(b"\n"):
        return False
    try:
        actual = frame_body(line[:-1])
    except (ValueError, RecursionError):
        return False
    return type(actual) is dict and type(actual.get("id")) is int and actual == expected


def stdout(raw):
    if os.write(1, raw) != len(raw):
        raise SystemExit(2)


def send_reply(scene):
    hello = wire(response(INIT_ID, result={"protocolVersion": True if scene == "wrong-version" else 1}))
    if scene == "coalesced-init":
        stdout(hello + wire(update("ok")))
    else:
        stdout(hello)


def send_session(scene):
    frame = wire(response(SESSION_ID, result={"sessionId": SESSION}))
    invalid = {
        "malformed": b"{synthetic-private-error}\n",
        "empty-line": b"\n",
        "coalesced-session": frame + wire(update("ok")),
        "duplicate": b'{"jsonrpc":"2.0","id":2,"result":{"sessionId":"x","sessionId":"y"}}\n',
        "cr": frame[:-1] + b"\r\n",
        "bom": b"\xef\xbb\xbf" + frame,
        "bad-utf8": b"\xff\n",
        "constant": b'{"jsonrpc":"2.0","id":2,"result":{"sessionId":NaN}}\n',
        "bool-id": wire(response(True, result={"sessionId": SESSION})),
        "extra-result": wire(response(SESSION_ID, result={"sessionId": SESSION, "extra": 0})),
        "extra-envelope": wire(response(SESSION_ID, result={"sessionId": SESSION}, extra=0)),
        "truncated": frame[:-1],
        "oversized": wire(response(SESSION_ID, result={"sessionId": "x" * 1100})),
    }
    stdout(invalid.get(scene, frame))
    return scene != "truncated"


class TurnEvidence:
    def __init__(self, fd, attempt):
        self.fd = fd
        self.attempt = attempt
        self.digest = hashlib.sha256()
        self.chunks = 0

    def emit(self, text, *, split=False):
        raw = wire(update(text))
        if split:
            stdout(raw[:31])
            time.sleep(.01)
            stdout(raw[31:])
        else:
            stdout(raw)
        self.chunks += 1
        hash_chunk(self.digest, text)

    def write(self, prompt_count, scene):
        record = wire({
            "attempt": self.attempt,
            "session_id": SESSION,
            "prompt_request_id": PROMPT_ID,
            "prompt_count": prompt_count,
            "post_prompt_chunk_count": self.chunks,
            "post_prompt_chunks_sha256": self.digest.hexdigest() if scene != "bad-receipt" else "0" * 64,
        })
        if scene == "extra-receipt":
            record += b"\n"
        try:
            if os.write(self.fd, record) != len(record):
                raise SystemExit(2)
        finally:
            os.close(self.fd)


def emit_turn_text(scene, evidence):
    if scene == "mixed":
        evidence.emit("k")
    elif scene == "split":
        evidence.emit("o", split=True)
        evidence.emit("k")
    elif scene != "early":
        evidence.emit("ok")
    if scene == "over-frames":
        # Two startup replies and the counted "ok" already occupy three slots.
        # The terminal reply will exceed the cap after we have published the receipt.
        for _ in range(MAX_FRAMES - 3):
            evidence.emit("")


def turn(scene, evidence):
    accepted = read_request(prompt_request(SESSION))
    if accepted is not True:
        evidence.write(0, scene)
        return 0 if accepted is None else 2

    emit_turn_text(scene, evidence)
    evidence.write(1, scene)

    if scene == "timeout":
        time.sleep(30)
        return 2
    if scene == "wrong-session":
        # This notification is foreign to the retained session and does not extend its receipt.
        stdout(wire(update("x", "unknown-session")))
    if scene == "permission":
        stdout(wire(request(41, "session/request_permission", {"sessionId": SESSION})))
    stdout(wire(response(4 if scene == "wrong-id" else PROMPT_ID,
                         result={"stopReason": "max_tokens" if scene == "wrong-stop" else "end_turn"})))
    if sys.stdin.buffer.read(1):
        return 2
    if scene == "trailing":
        stdout(b"trailing")
    return 2 if scene == "bad-exit" else 0


def queue_early(scene, sync_r, sync_w):
    try:
        # The parent only sends this byte after parsing session/new.
        if os.read(sync_r, 1) != b"\x01":
            return False
        stdout(wire(update("ok" if scene == "early" else "o")))
        # This travels on a private test pipe and never appears on ACP stdio.
        return os.write(sync_w, b"\x01") == 1
    finally:
        os.close(sync_r)
        os.close(sync_w)


def main(scene, profile_root, generation, attempt, evidence_w, sync_r, sync_w):
    profile_root = Path(profile_root)
    if (scene not in SCENES or not is_identifier(attempt)
            or os.environ != {"HOME": "/nonexistent", "LANG": "C.UTF-8"}
            or Path.cwd() != profile_root / attempt or any(Path.cwd().iterdir())):
        return 2
    if not read_request(request(INIT_ID, "initialize", {"protocolVersion": 1, "clientCapabilities": {}})):
        return 2
    if scene == "init-timeout":
        time.sleep(30)
        return 2
    send_reply(scene)
    if not read_request(request(SESSION_ID, "session/new", {"cwd": str(Path.cwd()), "mcpServers": []})):
        return 2
    evidence = TurnEvidence(int(evidence_w), attempt)
    error = profile_error(profile_root, generation)
    if error is not None:
        evidence.write(0, scene)
        stdout(wire(response(SESSION_ID, error=error)))
        return 2 if sys.stdin.buffer.read(1) else 0
    if not send_session(scene):
        return 0
    if scene in EARLY_SCENES and not queue_early(scene, int(sync_r), int(sync_w)):
        return 2
    return turn(scene, evidence)
