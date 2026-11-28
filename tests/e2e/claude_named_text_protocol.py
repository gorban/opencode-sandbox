"""Wire translation for the offline, single-turn named Claude fixture."""

from collections.abc import Iterable
from dataclasses import dataclass
from hashlib import sha256
import json
import re

from oc_openai.connection_state import decode_json
from oc_openai.session_protocol import (
    ReasoningVault, encode_chunk, parse_worker_request, sse_frame, sse_response_headers,
)


_PROMPT_BYTES = 512
_ANSWER_BYTES = 4096
_FRAME_BYTES = 8192
_WIRE_BYTES = 32 * 1024
_MAX_DELTAS = 16
_OPAQUE = re.compile(r"[0-9a-f]{32}")
_STOCK_SESSION = re.compile(r"ses_[A-Za-z0-9]{1,124}")
_REQUEST_KEYS = {
    "model", "input", "instructions", "max_output_tokens", "include", "prompt_cache_key", "store", "stream",
}


class TextWireError(ValueError):
    def __init__(self):
        super().__init__("Unexpected named Claude text fixture message")


def _require(condition):
    if not condition:
        raise TextWireError()


def _text_size(value):
    _require(type(value) is str and bool(value) and "\0" not in value)
    try:
        return len(value.encode("utf-8"))
    except UnicodeError:
        raise TextWireError() from None


def _identifier(value):
    return type(value) is str and _OPAQUE.fullmatch(value) is not None


def lower_stock_request(raw, *, token, port, model, instructions_digest, stock_output_limit):
    """Strip measured stock-only fields and return the only user text."""
    _require(type(raw) is bytes and 0 < len(raw) <= _WIRE_BYTES)
    _, separator, payload = raw.partition(b"\r\n\r\n")
    _require(bool(separator))
    try:
        body = decode_json(payload.decode("utf-8"))
    except (ValueError, RecursionError):
        raise TextWireError() from None
    _require(type(body) is dict and body.keys() == _REQUEST_KEYS and body["store"] is False)
    _require(body["include"] == ["reasoning.encrypted_content"])
    _require(type(body["max_output_tokens"]) is int and body["max_output_tokens"] == stock_output_limit)
    cache_key = body["prompt_cache_key"]
    _require(type(cache_key) is str and _STOCK_SESSION.fullmatch(cache_key) is not None)
    instructions = body["instructions"]
    _text_size(instructions)
    _require(sha256(instructions.encode("utf-8")).hexdigest() == instructions_digest)

    items = body["input"]
    _require(type(items) is list and len(items) == 1 and type(items[0]) is dict)
    message = items[0]
    _require(message.keys() == {"type", "role", "content"}
             and message["type"] == "message" and message["role"] == "user")
    parts = message["content"]
    _require(type(parts) is list and len(parts) == 1 and type(parts[0]) is dict)
    part = parts[0]
    _require(part.keys() == {"type", "text"} and part["type"] == "input_text")
    text = part["text"]
    _require(_text_size(text) <= _PROMPT_BYTES and bool(text.strip()))
    # Check generic HTTP framing and authorization after screening the exact text envelope.
    parsed = parse_worker_request(
        raw, expected_token=token, allowed_models=frozenset({model}),
        vault=ReasoningVault(), expected_port=port,
    )
    _require(parsed.route == "responses" and not parsed.allowed_tools)
    # Stock instructions, reasoning retention and cache hints never enter the child packet.
    return text


def _native_frame(raw):
    _require(type(raw) is bytes and 0 < len(raw) <= _FRAME_BYTES and raw.endswith(b"\n"))
    _require(b"\n" not in raw[:-1] and b"\r" not in raw)
    try:
        message = decode_json(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        raise TextWireError() from None
    _require(type(message) is dict)
    return message


def verify_ready(raw, *, session, profile, account, model):
    _require(_identifier(session))
    _require(_native_frame(raw) == {
        "type": "ready", "session": session, "profile": profile, "account": account,
        "auth": "claude.ai", "provider": "firstParty", "model": model,
        "tools": [], "mcp": [], "hooks": [],
    })


def native_packet(text, *, session, challenge, pipe_buf):
    _require(_identifier(session) and _identifier(challenge))
    _require(_text_size(text) <= _PROMPT_BYTES and bool(text.strip()))
    packet = json.dumps(
        {"type": "user", "session": session, "challenge": challenge, "role": "user", "text": text},
        ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    _require(type(pipe_buf) is int and 0 < len(packet) <= min(pipe_buf, 4096))
    return packet


@dataclass(frozen=True)
class NativeText:
    text: str
    input_tokens: int
    output_tokens: int
    terminal_digest: str


def _terminal_usage(message, route, *, max_input, max_output):
    input_tokens, output_tokens = message.get("input_tokens"), message.get("output_tokens")
    _require(type(message.get("tool_calls")) is int and message["tool_calls"] == 0)
    _require(type(input_tokens) is int and 1 <= input_tokens <= max_input)
    _require(type(output_tokens) is int and 1 <= output_tokens <= max_output)
    _require(message == {
        "type": "result", **route, "stop": "end_turn", "tool_calls": 0,
        "input_tokens": input_tokens, "output_tokens": output_tokens,
    })
    return input_tokens, output_tokens


def read_native_turn(frames: Iterable[bytes], *, session, challenge, model, max_input, max_output):
    """Check the fake child's full stdout transcript through EOF."""
    _require(_identifier(session) and _identifier(challenge))
    route = {"session": session, "challenge": challenge, "model": model}
    parts = []
    size = 0
    terminal = None
    for raw in frames:
        _require(terminal is None)
        message = _native_frame(raw)
        if message.get("type") == "result":
            _require(bool(parts))
            input_tokens, output_tokens = _terminal_usage(message, route, max_input=max_input, max_output=max_output)
            terminal = NativeText("".join(parts), input_tokens, output_tokens, sha256(raw).hexdigest())
            continue
        text = message.get("text")
        size += _text_size(text)
        _require(size <= _ANSWER_BYTES and len(parts) < _MAX_DELTAS)
        _require(message == {"type": "delta", **route, "role": "assistant", "text": text})
        parts.append(text)
    _require(terminal is not None)
    return terminal


def render_stock_reply(reply: NativeText, *, response_id, model):
    """Encode a bounded fake reply after the caller has verified retirement and settlement."""
    _require(_identifier(response_id) and _text_size(reply.text) <= _ANSWER_BYTES)
    response_id, message_id = f"resp_{response_id}", f"msg_{response_id}"
    response = {"id": response_id, "object": "response", "model": model}
    item = {"id": message_id, "type": "message", "role": "assistant"}
    position = {"item_id": message_id, "output_index": 0, "content_index": 0}
    part = {"type": "output_text", "text": reply.text, "annotations": []}
    message = {**item, "status": "completed", "content": [part]}
    usage = {
        "input_tokens": reply.input_tokens, "output_tokens": reply.output_tokens,
        "total_tokens": reply.input_tokens + reply.output_tokens,
    }
    frames = (
        ("response.created", {"response": {**response, "status": "in_progress", "output": []}}),
        ("response.output_item.added", {"output_index": 0,
                                        "item": {**item, "status": "in_progress", "content": []}}),
        ("response.content_part.added", {**position, "part": {**part, "text": ""}}),
        ("response.output_text.delta", {**position, "delta": reply.text}),
        ("response.output_text.done", {**position, "text": reply.text}),
        ("response.content_part.done", {**position, "part": part}),
        ("response.output_item.done", {"output_index": 0, "item": message}),
        ("response.completed", {"response": {
            **response, "status": "completed", "output": [message], "usage": usage,
        }}),
    )
    return sse_response_headers() + b"".join(
        encode_chunk(sse_frame(kind, {"type": kind, **data})) for kind, data in frames
    ) + b"0\r\n\r\n"
