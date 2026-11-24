"""Strict Responses protocol, SCM_RIGHTS handoff, and buffered SSE filtering for the canary."""

from array import array
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import os
import re
import socket
import time


PROMPT = "Reply with exactly: ok"
EXPECTED_REPLY = "ok"
PORT = 8401
IDLE_SECONDS = 15
TOTAL_SECONDS = 60
REQUEST_LIMIT = 64 * 1024
HEADER_LIMIT = 16 * 1024
PROJECTED_LIMIT = 256 * 1024
MAX_EVENTS = 1024
MAX_MODELS_REQUESTS = 4
PROOF_SIZE = 32
SYSTEM_DATE = re.compile(r"^Today's date: [A-Z][a-z]{2} [A-Z][a-z]{2} \d{2} \d{4}$", re.MULTILINE | re.ASCII)
SYSTEM_DIGEST = "9dbfd7bee7bd57cc1776a0867584dd69d65157bed267c6cec826ebec27878c3d"
_RESPONSE_ID_RE = re.compile(r"resp_[A-Za-z0-9_-]{1,123}\Z", re.ASCII)
_CACHE_KEY_RE = re.compile(r"ses_[A-Za-z0-9]{26}\Z", re.ASCII)
_HEADER_VAL_RE = re.compile(rb"[ -~]+\Z")
_LENGTH_RE = re.compile(rb"[1-9]\d{0,4}\Z")
_ALLOWED_HEADERS = frozenset({
    b"accept", b"accept-encoding", b"authorization", b"connection", b"content-length",
    b"content-type", b"host", b"user-agent", b"b3", b"traceparent", b"x-opencode-client",
    b"x-opencode-project", b"x-opencode-session", b"x-opencode-session-id", b"x-session-affinity",
    b"x-session-id",
})
_REQUIRED_REQ_KEYS = frozenset({"model", "input", "stream", "instructions"})
_ALLOWED_REQ_KEYS = _REQUIRED_REQ_KEYS | frozenset({
    "store", "max_output_tokens", "prompt_cache_key", "include", "tools", "tool_choice",
})
_EMPTY_REASONING_KEYS = frozenset({"id", "type", "status", "summary"})
_MESSAGE_ITEM_KEYS = frozenset({"id", "type", "role", "status", "content", "phase"})
_EV_CREATED = "response.created"
_EV_IN_PROGRESS = "response.in_progress"
_EV_METADATA = "response.metadata"
_EV_ITEM_ADDED = "response.output_item.added"
_EV_ITEM_DONE = "response.output_item.done"
_EV_PART_ADDED = "response.content_part.added"
_EV_PART_DONE = "response.content_part.done"
_EV_TEXT_DELTA = "response.output_text.delta"
_EV_TEXT_DONE = "response.output_text.done"
_EV_COMPLETED = "response.completed"
_TERMINAL_FAILURES = frozenset({"response.failed", "response.incomplete", "error"})
_MODERATION_ROOT_KEYS = frozenset({"presentation", "prompt", "response", "schema_version"})
_MODERATION_SLOT_KEYS = frozenset({"outputs", "results", "is_blocked"})
_MODERATION_ENTRY_KEYS = frozenset({"is_blocked", "category", "classifier", "label", "score"})
_MAX_SCAN_DEPTH = 32
_MAX_SCAN_NODES = 4096
REFUSAL_RESPONSE = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


class _SafetyRejected(RuntimeError):
    """Internal marker when safety or metadata inspection requires delivery suppression."""


def _check_moderation_or_metadata(low: str, value) -> None:
    if low == "openai_chatgpt_moderation_metadata":
        _validate_moderation_root(value)
        return
    if "moderation" in low:
        raise _SafetyRejected("metadata_moderation")
    if low == "metadata" and value not in (None, {}):
        _validate_metadata_dict(value)


def _check_safety_entry(key, value) -> None:
    if type(key) is not str:
        return
    low = key.lower()
    if "guardian" in low:
        raise _SafetyRejected("metadata_guardian")
    if (low == "safety_buffering" and value is not False) or (low == "type" and value == "safety_buffering"):
        raise _SafetyRejected("safety_buffering")
    if (low in ("is_blocked", "blocked", "flagged", "requires_review", "needs_review", "review_required")
            and value is not False
            or (low == "openai_verification_recommendation" and value != [])
            or (low == "refusal" and value not in (None, "", False))
            or (low in ("incomplete_details", "error") and value is not None)):
        raise _SafetyRejected("safety_signal")
    _check_moderation_or_metadata(low, value)


def _scan_dict_children(current: dict, depth: int, stack: list) -> None:
    for key, value in current.items():
        _check_safety_entry(key, value)
        if type(value) in (dict, list):
            stack.append((value, depth + 1))


def _scan_list_children(current: list, depth: int, stack: list) -> None:
    for item in current:
        if type(item) in (dict, list):
            stack.append((item, depth + 1))


def _scan_global_safety(obj) -> None:
    stack = [(obj, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if depth > _MAX_SCAN_DEPTH or nodes > _MAX_SCAN_NODES:
            raise _SafetyRejected("safety_scan_limit")
        if type(current) is dict:
            _scan_dict_children(current, depth, stack)
        elif type(current) is list:
            _scan_list_children(current, depth, stack)


def _validate_moderation_entry(entry) -> None:
    if (type(entry) is not dict or not set(entry) <= _MODERATION_ENTRY_KEYS
            or entry.get("is_blocked") is not False):
        raise _SafetyRejected("metadata_moderation")
    for text_key in ("category", "classifier", "label"):
        val = entry.get(text_key)
        if val is not None and (type(val) is not str or len(val) > 256):
            raise _SafetyRejected("metadata_moderation")
    score = entry.get("score")
    if score is not None and (type(score) not in (int, float) or not math.isfinite(score)):
        raise _SafetyRejected("metadata_moderation")


def _validate_moderation_entries(entries) -> None:
    if type(entries) is not list or len(entries) > 32:
        raise _SafetyRejected("metadata_moderation")
    for entry in entries:
        _validate_moderation_entry(entry)


def _validate_moderation_slot(slot) -> None:
    if slot is None or slot == {}:
        return
    if type(slot) is not dict or not set(slot) <= _MODERATION_SLOT_KEYS:
        raise _SafetyRejected("metadata_moderation")
    if "is_blocked" in slot and slot["is_blocked"] is not False:
        raise _SafetyRejected("metadata_moderation")
    for list_key in ("outputs", "results"):
        if slot.get(list_key) is not None:
            _validate_moderation_entries(slot[list_key])


def _validate_moderation_root(moderation) -> None:
    if type(moderation) is not dict or not set(moderation) <= _MODERATION_ROOT_KEYS:
        raise _SafetyRejected("metadata_moderation")
    if moderation.get("presentation") not in (None, "inline"):
        raise _SafetyRejected("metadata_moderation")
    schema_version = moderation.get("schema_version")
    if schema_version is not None and (type(schema_version) is not int or schema_version != 1):
        raise _SafetyRejected("metadata_moderation")
    _validate_moderation_slot(moderation.get("prompt"))
    if moderation.get("response") not in (None, {}):
        raise _SafetyRejected("metadata_moderation")


def _validate_metadata_dict(metadata) -> None:
    if type(metadata) is not dict:
        raise _SafetyRejected("metadata_envelope")
    if not set(metadata) <= {"openai_verification_recommendation", "openai_chatgpt_moderation_metadata"}:
        raise _SafetyRejected("metadata_fields")
    if metadata.get("openai_verification_recommendation", []) != []:
        raise _SafetyRejected("metadata_review")
    _validate_moderation_root(metadata.get("openai_chatgpt_moderation_metadata", {}))


def _validate_metadata_event(event: dict, active_upstream_id: str | None) -> None:
    if (event.keys() != {"type", "response_id", "sequence_number", "metadata"}
            or active_upstream_id is None or event["response_id"] != active_upstream_id
            or type(event["sequence_number"]) is not int
            or not 0 <= event["sequence_number"] <= 2**31):
        raise _SafetyRejected("metadata_envelope")
    _validate_metadata_dict(event["metadata"])


class Refused(ValueError):
    """Local canary request failed strict allowlist validation."""


class CanaryUnsettledError(RuntimeError):
    """Upstream stream did not reach authenticated terminal completion with usage."""


@dataclass(frozen=True)
class LocalRequest:
    kind: str
    body: bytes | None = None


@dataclass(frozen=True)
class StreamOutcome:
    input_tokens: int
    output_tokens: int
    allow_delivery: bool
    reason: str


def _unique(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise Refused("duplicate_json_key")
    return obj


def _bad_constant(_value):
    raise Refused("non_finite_json")


def _recv_chunk(connection: socket.socket, length: int, deadline: float) -> bytes:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise Refused("request_timeout")
    connection.settimeout(min(IDLE_SECONDS, remaining))
    chunk = connection.recv(length)
    if not chunk:
        raise Refused("request_eof")
    return chunk


def _recv_exact(connection: socket.socket, length: int, deadline: float) -> bytes:
    buf = bytearray()
    while len(buf) < length:
        buf.extend(_recv_chunk(connection, length - len(buf), deadline))
    return bytes(buf)


def receive_client(control: socket.socket, port: int = PORT) -> socket.socket:
    """Receive and validate one accepted loopback TCP connection FD over SCM_RIGHTS."""
    fds = array("i")
    marker, messages, flags, _ = control.recvmsg(
        1, socket.CMSG_SPACE(fds.itemsize * 2), socket.MSG_CMSG_CLOEXEC,
    )
    try:
        for level, kind, data in messages:
            if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                fds.frombytes(data[:len(data) - len(data) % fds.itemsize])
        if marker != b"F" or flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC) or len(messages) != 1 or len(fds) != 1:
            raise Refused("invalid_scm_rights")
        client = socket.socket(fileno=fds[0])
        fds.pop()
    finally:
        for fd in fds:
            os.close(fd)
    try:
        if (client.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_INET
                or client.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or client.getsockopt(socket.SOL_SOCKET, socket.SO_PROTOCOL) != socket.IPPROTO_TCP
                or client.getsockname() != ("127.0.0.1", port)
                or client.getpeername()[0] != "127.0.0.1"):
            raise Refused("invalid_client_socket")
        return client
    except BaseException:
        client.close()
        raise


def _parse_headers(lines: list[bytes], *, port: int, expected_token: str) -> dict[bytes, bytes]:
    fields: dict[bytes, bytes] = {}
    for line in lines:
        name, sep, value = line.partition(b":")
        name, value = name.lower(), value.strip(b" ")
        if not sep or name not in _ALLOWED_HEADERS or name in fields or not _HEADER_VAL_RE.fullmatch(value):
            raise Refused("invalid_header")
        fields[name] = value
    expected_host = f"127.0.0.1:{port}".encode("ascii")
    expected_auth = f"Bearer {expected_token}".encode("ascii")
    auth = fields.get(b"authorization", b"")
    if fields.get(b"host") != expected_host or not hmac.compare_digest(auth, expected_auth):
        raise Refused("unauthorized_request")
    return fields


def parse_local_request(
    connection: socket.socket, deadline: float, *, port: int, expected_token: str,
) -> LocalRequest:
    """Parse and authenticate one bounded local canary HTTP/1.1 request."""
    delimiter = b"\r\n\r\n"
    head = bytearray()
    while delimiter not in head:
        if len(head) >= HEADER_LIMIT:
            raise Refused("header_limit")
        head.extend(_recv_chunk(connection, min(4096, HEADER_LIMIT - len(head)), deadline))
    raw_headers, _, remainder = bytes(head).partition(delimiter)
    target, *lines = raw_headers.split(b"\r\n")
    fields = _parse_headers(lines, port=port, expected_token=expected_token)
    if target == b"GET /v1/models HTTP/1.1":
        if fields.get(b"content-length", b"0") != b"0" or remainder:
            raise Refused("models_body_forbidden")
        return LocalRequest("models", None)
    if target != b"POST /v1/responses HTTP/1.1":
        raise Refused("unsupported_target")
    ctype = fields.get(b"content-type", b"").lower()
    if ctype not in {b"application/json", b"application/json; charset=utf-8"}:
        raise Refused("unsupported_content_type")
    length_raw = fields.get(b"content-length", b"")
    if not _LENGTH_RE.fullmatch(length_raw):
        raise Refused("invalid_content_length")
    length = int(length_raw)
    if not len(remainder) <= length <= REQUEST_LIMIT:
        raise Refused("body_limit")
    body = remainder + _recv_exact(connection, length - len(remainder), deadline)
    return LocalRequest("responses", body)


def _valid_user_input(items) -> bool:
    if type(items) is not list or len(items) != 1 or type(items[0]) is not dict:
        return False
    msg = items[0]
    if msg.get("role") != "user" or msg.get("type", "message") != "message":
        return False
    if not set(msg) <= {"type", "role", "content"}:
        return False
    content = msg.get("content")
    if content == PROMPT:
        return True
    return (
        type(content) is list and len(content) == 1 and type(content[0]) is dict
        and content[0] == {"type": "input_text", "text": PROMPT}
    )


def _valid_instructions(instructions) -> bool:
    if type(instructions) is not str:
        return False
    normalized, count = SYSTEM_DATE.subn("Today's date: [date]", instructions)
    try:
        encoded = normalized.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return count == 1 and hashlib.sha256(encoded).hexdigest() == SYSTEM_DIGEST


def _validate_optional_fields(data: dict) -> None:
    if "max_output_tokens" in data:
        cap = data["max_output_tokens"]
        if type(cap) is not int or not 1 <= cap <= 2048:
            raise Refused("invalid_max_output_tokens")
    if "prompt_cache_key" in data:
        key = data["prompt_cache_key"]
        if type(key) is not str or not _CACHE_KEY_RE.fullmatch(key):
            raise Refused("invalid_cache_key")


def validate_responses_request(body: bytes, *, bound_model: str) -> dict:
    """Strictly validate the inbound OpenCode Responses request and return the canonical upstream body."""
    try:
        data = json.loads(body.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_bad_constant)
    except (ValueError, RecursionError):
        raise Refused("invalid_json") from None
    if type(data) is not dict or not _REQUIRED_REQ_KEYS <= set(data) <= _ALLOWED_REQ_KEYS:
        raise Refused("unexpected_keys")
    if (data["model"] != bound_model or data["stream"] is not True
            or data.get("store", False) is not False
            or data.get("tools", []) != []
            or data.get("tool_choice", "none") != "none"
            or data.get("include", []) not in ([], ["reasoning.encrypted_content"])):
        raise Refused("disallowed_options")
    _validate_optional_fields(data)
    if not _valid_user_input(data["input"]) or not _valid_instructions(data["instructions"]):
        raise Refused("unapproved_prompt_or_instructions")
    return canonical_upstream_body(bound_model)


def canonical_upstream_body(bound_model: str) -> dict:
    """Build the 4-key canonical upstream body (omitting max_output_tokens and include)."""
    return {
        "model": bound_model,
        "input": [{"type": "message", "role": "user", "content": PROMPT}],
        "store": False,
        "stream": True,
    }


def _is_empty_reasoning_item(item: dict) -> bool:
    if item.get("type") != "reasoning":
        return False
    if not set(item) <= _EMPTY_REASONING_KEYS:
        return False
    summary = item.get("summary")
    return summary is None or summary == []


def _is_clean_output_text_part(part) -> bool:
    return (
        type(part) is dict
        and part.get("type") == "output_text"
        and set(part) <= {"type", "text", "annotations", "logprobs"}
        and type(part.get("text", "")) is str
        and part.get("annotations") in (None, [])
        and part.get("logprobs") in (None, [])
    )


def _is_clean_assistant_message(item: dict) -> bool:
    if (item.get("type") != "message" or item.get("role") != "assistant"
            or not set(item) <= _MESSAGE_ITEM_KEYS):
        return False
    content = item.get("content", [])
    if type(content) is not list:
        return False
    return all(_is_clean_output_text_part(part) for part in content)


def _extract_exact_ok(response: dict, deltas: list[str]) -> bool:
    items = response.get("output")
    if type(items) is not list or any(type(item) is not dict for item in items):
        return False
    messages = []
    for item in items:
        if _is_empty_reasoning_item(item):
            continue
        if not _is_clean_assistant_message(item) or item.get("status") != "completed":
            return False
        messages.append(item)
    if len(messages) != 1:
        return False
    content = messages[0].get("content")
    if type(content) is not list or len(content) != 1 or content[0].get("text") != EXPECTED_REPLY:
        return False
    return not deltas or "".join(deltas) == EXPECTED_REPLY


def _extract_verified_usage(response: dict, *, created_id: str | None, bound_model: str) -> tuple[int, int]:
    if (type(response) is not dict or created_id is None
            or response.get("id") != created_id
            or response.get("model") != bound_model
            or response.get("status") != "completed"):
        raise CanaryUnsettledError("provider_identity")
    usage = response.get("usage")
    if type(usage) is not dict:
        raise CanaryUnsettledError("provider_usage")
    counts = tuple(usage.get(k) for k in ("input_tokens", "output_tokens", "total_tokens"))
    if any(type(c) is not int or c < 0 for c in counts) or counts[0] + counts[1] != counts[2]:
        raise CanaryUnsettledError("provider_usage")
    return counts[0], counts[1]


class _CanaryStreamState:
    def __init__(self, bound_model: str):
        self.bound_model = bound_model
        self.created_id: str | None = None
        self.suppressed = False
        self.suppress_reason = ""
        self.deltas: list[str] = []
        self.delta_bytes = 0
        self.completed: dict | None = None

    def _suppress(self, reason: str) -> None:
        if not self.suppressed:
            self.suppressed = True
            self.suppress_reason = reason

    def _check_response_output(self, response) -> None:
        if type(response) is not dict or "output" not in response:
            return
        items = response["output"]
        if type(items) is not list:
            self._suppress("invalid_output")
            return
        for item in items:
            if type(item) is not dict or not (_is_empty_reasoning_item(item) or _is_clean_assistant_message(item)):
                self._suppress("disallowed_item")
                return

    def _check_created(self, event: dict) -> None:
        response = event.get("response")
        rid = response.get("id") if type(response) is dict else None
        if (self.created_id is not None or type(rid) is not str
                or not _RESPONSE_ID_RE.fullmatch(rid)
                or response.get("model", self.bound_model) != self.bound_model):
            raise CanaryUnsettledError("provider_identity")
        self.created_id = rid
        self._check_response_output(response)

    def _check_item(self, event: dict) -> None:
        item = event.get("item")
        if type(item) is not dict:
            self._suppress("invalid_item")
            return
        if _is_empty_reasoning_item(item) or _is_clean_assistant_message(item):
            return
        self._suppress("disallowed_item")

    def _check_part(self, event: dict) -> None:
        if not _is_clean_output_text_part(event.get("part")):
            self._suppress("disallowed_part")

    def _check_text(self, kind: str, event: dict) -> None:
        if kind == _EV_TEXT_DELTA:
            delta = event.get("delta")
            if type(delta) is not str:
                self._suppress("invalid_delta")
                return
            try:
                encoded_len = len(delta.encode("utf-8"))
            except UnicodeEncodeError:
                self._suppress("invalid_delta")
                return
            self.delta_bytes += encoded_len
            if self.delta_bytes > PROJECTED_LIMIT:
                self._suppress("projected_limit")
                return
            self.deltas.append(delta)
            return
        if event.get("text") != EXPECTED_REPLY:
            self._suppress("non_exact_text")

    def _check_metadata(self, event: dict) -> None:
        try:
            _validate_metadata_event(event, self.created_id)
        except _SafetyRejected:
            self._suppress("moderation_or_ambiguous_metadata")

    def accept(self, event: dict) -> None:
        if type(event) is not dict or type(event.get("type")) is not str or self.completed is not None:
            raise CanaryUnsettledError("provider_stream")
        kind = event["type"]
        if kind in _TERMINAL_FAILURES:
            raise CanaryUnsettledError("provider_terminal")
        try:
            _scan_global_safety(event)
        except _SafetyRejected:
            self._suppress("safety_signal")
        if kind == _EV_CREATED:
            self._check_created(event)
            return
        if self.created_id is None:
            raise CanaryUnsettledError("provider_identity")
        if kind == _EV_COMPLETED:
            self.completed = event.get("response")
            return
        if kind == _EV_METADATA:
            self._check_metadata(event)
            return
        self._accept_body_event(kind, event)

    def _accept_body_event(self, kind: str, event: dict) -> None:
        if kind == _EV_IN_PROGRESS:
            self._check_response_output(event.get("response"))
            return
        if kind in (_EV_ITEM_ADDED, _EV_ITEM_DONE):
            self._check_item(event)
            return
        if kind in (_EV_PART_ADDED, _EV_PART_DONE):
            self._check_part(event)
            return
        if kind in (_EV_TEXT_DELTA, _EV_TEXT_DONE):
            self._check_text(kind, event)
            return
        self._suppress("unexpected_event")


def consume_upstream_stream(events, *, bound_model: str, check_alive) -> StreamOutcome:
    """Consume bounded upstream Responses SSE, decoupling usage settlement from ok delivery."""
    state = _CanaryStreamState(bound_model)
    for count, event in enumerate(events, 1):
        check_alive()
        if count > MAX_EVENTS:
            raise CanaryUnsettledError("provider_stream_limit")
        state.accept(event)
    check_alive()
    if state.completed is None:
        raise CanaryUnsettledError("provider_missing_completion")
    in_tok, out_tok = _extract_verified_usage(
        state.completed, created_id=state.created_id, bound_model=bound_model,
    )
    try:
        _scan_global_safety(state.completed)
    except _SafetyRejected:
        state._suppress("safety_signal")
    exact_ok = not state.suppressed and _extract_exact_ok(state.completed, state.deltas)
    reason = "ok" if exact_ok else (state.suppress_reason or "non_exact_output")
    return StreamOutcome(
        input_tokens=in_tok,
        output_tokens=out_tok,
        allow_delivery=exact_ok,
        reason=reason,
    )


def models_http_response(bound_model: str) -> bytes:
    """Serve only the single bound model from the local host catalog (0 upstream calls)."""
    payload = json.dumps(
        {"object": "list", "data": [{"id": bound_model, "object": "model"}]},
        ensure_ascii=True,
    ).encode("ascii")
    return (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n"
        + f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii")
        + payload
    )


def ok_sse_http_response(bound_model: str, input_tokens: int, output_tokens: int) -> bytes:
    """Build the minimal Responses SSE payload required by pinned OpenCode 2.3.0."""
    item_id = "msg_canary_1"
    resp_id = "resp_canary_1"
    frames = (
        {"type": _EV_CREATED, "response": {"id": resp_id, "model": bound_model, "status": "in_progress"}},
        {
            "type": _EV_ITEM_ADDED, "output_index": 0,
            "item": {"id": item_id, "type": "message", "role": "assistant", "status": "in_progress", "content": []},
        },
        {
            "type": _EV_PART_ADDED, "item_id": item_id, "output_index": 0, "content_index": 0,
            "part": {"type": "output_text", "text": ""},
        },
        {
            "type": _EV_TEXT_DELTA, "item_id": item_id, "output_index": 0, "content_index": 0,
            "delta": EXPECTED_REPLY,
        },
        {
            "type": _EV_TEXT_DONE, "item_id": item_id, "output_index": 0, "content_index": 0,
            "text": EXPECTED_REPLY,
        },
        {
            "type": _EV_PART_DONE, "item_id": item_id, "output_index": 0, "content_index": 0,
            "part": {"type": "output_text", "text": EXPECTED_REPLY},
        },
        {
            "type": _EV_ITEM_DONE, "output_index": 0,
            "item": {
                "id": item_id, "type": "message", "role": "assistant", "status": "completed",
                "content": [{"type": "output_text", "text": EXPECTED_REPLY}],
            },
        },
        {
            "type": _EV_COMPLETED,
            "response": {
                "id": resp_id, "model": bound_model, "status": "completed",
                "output": [{
                    "id": item_id, "type": "message", "role": "assistant", "status": "completed",
                    "content": [{"type": "output_text", "text": EXPECTED_REPLY}],
                }],
                "usage": {
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "total_tokens": input_tokens + output_tokens,
                },
            },
        },
    )
    body = b"".join(
        f"event: {frame['type']}\ndata: {json.dumps(frame, ensure_ascii=True)}\n\n".encode("ascii")
        for frame in frames
    ) + b"data: [DONE]\n\n"
    return (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        + body
    )


def _parse_stdout_event(raw: str) -> dict | None:
    try:
        event = json.loads(raw, object_pairs_hook=_unique, parse_constant=_bad_constant)
    except (ValueError, RecursionError):
        return None
    return event if type(event) is dict else None


def _valid_stdout_ids(event: dict, part: dict, seen_ids: list[str | None]) -> bool:
    sid = event.get("sessionID")
    mid = part.get("messageID")
    if type(sid) is not str or not sid or type(mid) is not str or not mid:
        return False
    if part.get("sessionID") is not None and part.get("sessionID") != sid:
        return False
    if seen_ids[0] is None:
        seen_ids[0] = sid
        seen_ids[1] = mid
        return True
    return seen_ids[0] == sid and seen_ids[1] == mid


def verify_opencode_json_stdout(stdout_bytes: bytes) -> bool:
    """Strict 3-event allowlist verifier: exact [step_start, text('ok'), step_finish('stop')]."""
    try:
        lines = [line for line in stdout_bytes.decode("utf-8").splitlines() if line.strip()]
    except UnicodeDecodeError:
        return False
    if len(lines) != 3:
        return False
    events = [_parse_stdout_event(line) for line in lines]
    if any(event is None for event in events):
        return False
    seen_ids: list[str | None] = [None, None]
    expected_types = ("step_start", "text", "step_finish")
    for event, want in zip(events, expected_types):
        part = event.get("part")
        if event.get("type") != want or type(part) is not dict or not _valid_stdout_ids(event, part, seen_ids):
            return False
    return (
        events[0]["part"].get("type") == "step-start"
        and events[1]["part"].get("type") == "text"
        and events[1]["part"].get("text") == EXPECTED_REPLY
        and events[2]["part"].get("type") == "step-finish"
        and events[2]["part"].get("reason") == "stop"
    )
