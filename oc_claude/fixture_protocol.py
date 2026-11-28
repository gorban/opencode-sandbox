"""The closed synthetic Claude text exchange."""

import json
import math
import re


FRAME_LIMIT = 8192
STDOUT_LIMIT = 32768
STDERR_LIMIT = 8192
PROMPT_LIMIT = 512
ANSWER_LIMIT = 4096
PACKET_LIMIT = 4096
MAX_DELTAS = 16

MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", re.ASCII)
IDENTIFIER = re.compile(r"[a-f0-9]{32}", re.ASCII)
ACCOUNT = re.compile(r"[a-f0-9]{64}", re.ASCII)
STATUS_KEYS = {"type", "logged_in", "auth", "provider", "profile", "account", "expires_at", "model"}


class FixtureError(RuntimeError):
    """Report a fixed diagnostic without returning native bytes or metadata."""

    def __init__(self, reason, *, possible_send=False):
        super().__init__(reason)
        self.reason = reason
        self.possible_send = possible_send


def require(condition):
    if not condition:
        raise FixtureError("integrity_error")


def _pairs(entries):
    values = dict(entries)
    require(len(values) == len(entries))
    return values


def _reject_constant(_value):
    raise FixtureError("integrity_error")


def _validate_tree(value, depth=1):
    require(depth <= 8)
    if type(value) is str:
        value.encode("utf-8")
    elif type(value) is float:
        require(math.isfinite(value))
    elif type(value) is list:
        for item in value:
            _validate_tree(item, depth + 1)
    elif type(value) is dict:
        for key, item in value.items():
            key.encode("utf-8")
            _validate_tree(item, depth + 1)


def decode(frame):
    require(type(frame) is bytes and 0 < len(frame) <= FRAME_LIMIT and frame.endswith(b"\n"))
    try:
        value = json.loads(frame.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_reject_constant)
        require(type(value) is dict)
        _validate_tree(value)
    except (ValueError, RecursionError):
        raise FixtureError("integrity_error") from None
    return value


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"


def _exact(value, expected):
    # JSON encoding distinguishes bool, int, and float with the same numeric value.
    require(json.dumps(value, sort_keys=True) == json.dumps(expected, sort_keys=True))


def valid_id(value, pattern=IDENTIFIER):
    return type(value) is str and pattern.fullmatch(value) is not None


def _text_size(text):
    require(type(text) is str and bool(text) and "\0" not in text)
    try:
        return len(text.encode("utf-8"))
    except UnicodeError:
        raise FixtureError("integrity_error") from None


def validate_prompt(text):
    require(_text_size(text) <= PROMPT_LIMIT and bool(text.strip()))


def status_expiry(frame, pin):
    message = decode(frame)
    require(message.keys() == STATUS_KEYS and type(message["logged_in"]) is bool)
    require(message["type"] == "status" and message["profile"] == pin.profile_id)
    if not message["logged_in"]:
        _exact(message, {
            "type": "status", "logged_in": False, "auth": "none", "provider": "none",
            "profile": pin.profile_id, "account": None, "expires_at": None, "model": None,
        })
        return None
    expires = message["expires_at"]
    require(type(expires) is int and expires == pin.expires_at)
    _exact(message, {
        "type": "status", "logged_in": True, "auth": "claude.ai", "provider": "firstParty",
        "profile": pin.profile_id, "account": pin.account_tag, "expires_at": expires, "model": pin.model,
    })
    return expires


def verify_ready(frame, pin, session):
    _exact(decode(frame), {
        "type": "ready", "session": session, "profile": pin.profile_id, "account": pin.account_tag,
        "auth": "claude.ai", "provider": "firstParty", "model": pin.model, "tools": [], "mcp": [], "hooks": [],
    })


def user_frame(session, challenge, text, pipe_buf):
    packet = encode({"type": "user", "session": session, "challenge": challenge, "role": "user", "text": text})
    require(type(pipe_buf) is int and len(packet) <= min(pipe_buf, PACKET_LIMIT))
    return packet


def read_answer(read, session, challenge, model):
    parts = []
    size = 0
    route = {"session": session, "challenge": challenge, "model": model}
    for _ in range(MAX_DELTAS + 1):
        message = decode(read())
        if message.get("type") == "result":
            _exact(message, {"type": "result", **route, "stop": "end_turn", "tool_calls": 0})
            require(size > 0)
            return "".join(parts)
        text = message.get("text")
        size += _text_size(text)
        require(size <= ANSWER_LIMIT and len(parts) < MAX_DELTAS)
        _exact(message, {"type": "delta", **route, "role": "assistant", "text": text})
        parts.append(text)
    raise FixtureError("integrity_error")
