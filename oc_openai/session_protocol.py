"""Interactive OpenAI Responses sanitizer, vault, and fail-closed SSE projector."""

from collections import OrderedDict
from dataclasses import dataclass
import hmac
import json
import re
import secrets

from .connection_state import decode_json

MAX_INTERACTIVE_HEADER = 16 * 1024
MAX_INTERACTIVE_BODY = 4 * 1024 * 1024
MAX_INTERACTIVE_EVENTS = 16_384
MAX_INPUT_ITEMS = 512
MAX_CONTENT_PARTS = 64
MAX_TOOLS = 128
MAX_VAULT_ENTRIES = 256
MAX_SCAN_DEPTH = 32
MAX_SCAN_NODES = 16_384

HANDLE_PREFIX = "oc_rs_"
_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_EVENT_LABEL = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){0,4}\Z")
_HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_JSON_CONTENT_TYPE = re.compile(rb"application/json(?:[ \t]*;[ \t]*charset=utf-8)?\Z")

_ALLOWED_HEADERS = frozenset({
    b"host", b"authorization", b"content-type", b"content-length", b"accept",
    b"accept-encoding", b"connection", b"user-agent", b"x-stainless-lang",
    b"x-stainless-package-version", b"x-stainless-os", b"x-stainless-arch",
    b"x-stainless-runtime", b"x-stainless-runtime-version", b"x-stainless-retry-count",
    b"x-stainless-timeout", b"b3", b"traceparent", b"x-opencode-client",
    b"x-opencode-project", b"x-opencode-session", b"x-opencode-session-id",
    b"x-session-affinity", b"x-session-id",
})
_FORBIDDEN_HEADER_PREFIXES = (b"sec-fetch-", b"sec-ch-")
_FORBIDDEN_HEADERS = frozenset({b"origin", b"referer", b"cookie", b"transfer-encoding"})

_ALLOWED_REQUEST_KEYS = frozenset({
    "model", "input", "instructions", "tools", "tool_choice", "parallel_tool_calls",
    "max_output_tokens", "reasoning", "text", "temperature", "top_p", "truncation",
    "include", "store", "stream", "prompt_cache_key",
})
_ALLOWED_TOOL_KEYS = frozenset({"type", "name", "parameters", "description", "strict"})
_ALLOWED_MESSAGE_KEYS = frozenset({"type", "id", "role", "status", "content", "phase"})
_ALLOWED_CALL_KEYS = frozenset({"type", "id", "call_id", "name", "arguments", "status"})
_ALLOWED_CALL_OUTPUT_KEYS = frozenset({"type", "id", "call_id", "output", "status"})
_ALLOWED_REASONING_KEYS = frozenset({"type", "id", "summary", "content", "encrypted_content", "status"})
_ALLOWED_TEXT_PART_TYPES = frozenset({"input_text", "output_text", "refusal"})
_ALLOWED_ROLES = frozenset({"user", "assistant", "developer", "system"})

_EVENT_CREATED = "response.created"
_EVENT_ITEM_ADDED = "response.output_item.added"
_EVENT_TEXT_DONE = "response.output_text.done"
_EVENT_COMPLETED = "response.completed"
_DELTA_SUFFIX = ".delta"

_ALLOWED_STREAM_EVENTS = frozenset({
    _EVENT_CREATED, "response.in_progress", "response.queued",
    _EVENT_ITEM_ADDED, "response.output_item.done",
    "response.content_part.added", "response.content_part.done",
    "response.output_text.delta", _EVENT_TEXT_DONE,
    "response.refusal.delta", "response.refusal.done",
    "response.function_call_arguments.delta", "response.function_call_arguments.done",
    "response.reasoning_summary_part.added", "response.reasoning_summary_part.done",
    "response.reasoning_summary_text.delta", "response.reasoning_summary_text.done",
    "response.reasoning_text.delta", "response.reasoning_text.done",
    _EVENT_COMPLETED,
})
_UNSUPPORTED_EVENT_PREFIXES = (
    "response.audio.", "response.code_interpreter_", "response.compaction.",
    "response.file_search_", "response.shell_", "response.web_search_",
    "response.image_generation_", "response.mcp_", "response.custom_tool_",
)
_MODERATION_ROOT_KEYS = frozenset({
    "presentation", "prompt", "response", "generation", "tool_call", "tool_response", "schema_version",
})
_MODERATION_SLOT_KEYS = frozenset({"outputs", "results", "is_blocked", "protection_type"})
_MODERATION_ENTRY_KEYS = frozenset({
    "is_blocked", "category", "classifier", "label", "score", "results", "category_flags", "category_scores",
})
_MODERATION_CLASSIFIER_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}\Z", re.ASCII)
MAX_BUFFERED_TOOL_BYTES = 2 * 1024 * 1024


class RequestRefused(ValueError):
    """Worker HTTP request failed closed validation."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


class StreamAborted(RuntimeError):
    """Upstream SSE stream failed closed safety or protocol validation."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ParsedRequest:
    route: str
    body: dict | None = None
    model: str | None = None
    allowed_tools: frozenset[str] = frozenset()


@dataclass(frozen=True)
class _VaultEntry:
    ciphertext: str
    upstream_item_id: str
    local_item_id: str
    model: str


class ReasoningVault:
    """Bounded host-RAM vault binding opaque local handles to authentic reasoning ciphertext."""

    def __init__(self, *, max_entries: int = MAX_VAULT_ENTRIES):
        self._max_entries = max_entries
        self._entries: OrderedDict[str, _VaultEntry] = OrderedDict()
        self._counter = 0

    def next_local_id(self) -> str:
        self._counter += 1
        return f"rs_local_{self._counter}"

    def make_handle(self) -> str:
        return HANDLE_PREFIX + secrets.token_urlsafe(24)

    def commit(self, local_item_id: str, upstream_item_id: str, handle: str,
               ciphertext: str, model: str) -> None:
        if (type(upstream_item_id) is not str or not _ID_RE.fullmatch(upstream_item_id)
                or type(local_item_id) is not str or not _ID_RE.fullmatch(local_item_id)
                or type(handle) is not str or not handle.startswith(HANDLE_PREFIX)
                or type(ciphertext) is not str or not ciphertext or not ciphertext.isascii()
                or any(ord(ch) < 33 or ord(ch) > 126 for ch in ciphertext)):
            raise StreamAborted("invalid_reasoning_ciphertext")
        self._entries[handle] = _VaultEntry(ciphertext, upstream_item_id, local_item_id, model)
        self._entries.move_to_end(handle)
        while len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)

    def store(self, upstream_item_id: str, ciphertext: str, model: str) -> tuple[str, str]:
        local_item_id = self.next_local_id()
        handle = self.make_handle()
        self.commit(local_item_id, upstream_item_id, handle, ciphertext, model)
        return local_item_id, handle

    def resolve(self, handle: str, local_item_id: str, model: str) -> tuple[str, str]:
        if type(handle) is not str or not handle.startswith(HANDLE_PREFIX):
            raise RequestRefused(400, "invalid_reasoning_handle", "Invalid reasoning replay handle.")
        entry = self._entries.get(handle)
        if entry is None or entry.local_item_id != local_item_id or entry.model != model:
            raise RequestRefused(400, "invalid_reasoning_handle", "Unknown or mismatched reasoning replay handle.")
        self._entries.move_to_end(handle)
        return entry.upstream_item_id, entry.ciphertext


def _require_req(condition: bool, status: int = 400, code: str = "invalid_request",
                 message: str = "Request rejected by workstation broker.") -> None:
    if not condition:
        raise RequestRefused(status, code, message)


def _valid_id(value) -> bool:
    return type(value) is str and bool(_ID_RE.fullmatch(value))


def _sanitize_content(content) -> str | list:
    if type(content) is str:
        return content
    _require_req(type(content) is list and len(content) <= MAX_CONTENT_PARTS)
    cleaned = []
    for part in content:
        _require_req(type(part) is dict)
        kind = part.get("type")
        _require_req(kind in _ALLOWED_TEXT_PART_TYPES)
        if kind == "refusal":
            _require_req(set(part) <= {"type", "refusal"} and type(part.get("refusal")) is str)
            cleaned.append({"type": "refusal", "refusal": part["refusal"]})
        else:
            _require_req(set(part) <= {"type", "text", "annotations", "logprobs"} and type(part.get("text")) is str)
            item = {"type": kind, "text": part["text"]}
            if "annotations" in part:
                _require_req(part["annotations"] == [])
                item["annotations"] = []
            cleaned.append(item)
    return cleaned


def _sanitize_message_item(raw: dict) -> dict:
    _require_req(set(raw) <= _ALLOWED_MESSAGE_KEYS)
    role = raw.get("role")
    _require_req(role in _ALLOWED_ROLES and "content" in raw)
    item = {"type": "message", "role": role, "content": _sanitize_content(raw["content"])}
    if "status" in raw:
        _require_req(raw["status"] in ("in_progress", "completed", "incomplete"))
        item["status"] = raw["status"]
    if "phase" in raw and raw["phase"] is not None:
        _require_req(raw["phase"] in ("commentary", "final_answer"))
        item["phase"] = raw["phase"]
    return item


def _sanitize_call_item(raw: dict) -> dict:
    _require_req(set(raw) <= _ALLOWED_CALL_KEYS)
    _require_req(_valid_id(raw.get("call_id")) and _valid_id(raw.get("name"))
                 and type(raw.get("arguments")) is str)
    item = {
        "type": "function_call",
        "call_id": raw["call_id"],
        "name": raw["name"],
        "arguments": raw["arguments"],
    }
    if "status" in raw and raw["status"] is not None:
        _require_req(raw["status"] in ("in_progress", "completed", "incomplete"))
        item["status"] = raw["status"]
    return item


def _sanitize_call_output_item(raw: dict) -> dict:
    _require_req(set(raw) <= _ALLOWED_CALL_OUTPUT_KEYS)
    _require_req(_valid_id(raw.get("call_id")) and "output" in raw)
    output = raw["output"]
    if type(output) is not str:
        output = _sanitize_content(output)
    return {"type": "function_call_output", "call_id": raw["call_id"], "output": output}


def _sanitize_reasoning_item(raw: dict, model: str, vault: ReasoningVault) -> dict:
    _require_req(set(raw) <= _ALLOWED_REASONING_KEYS)
    local_id = raw.get("id")
    _require_req(_valid_id(local_id))
    summary = raw.get("summary", [])
    _require_req(type(summary) is list and len(summary) <= MAX_CONTENT_PARTS)
    for part in summary:
        _require_req(type(part) is dict and set(part) <= {"type", "text"}
                     and part.get("type") == "summary_text" and type(part.get("text")) is str)
    encrypted = raw.get("encrypted_content")
    _require_req(encrypted is not None, 400, "invalid_reasoning_handle",
                 "Reasoning replay requires an authenticated host handle.")
    upstream_id, ciphertext = vault.resolve(encrypted, local_id, model)
    item = {"type": "reasoning", "id": upstream_id, "summary": summary, "encrypted_content": ciphertext}
    if "status" in raw and raw["status"] is not None:
        _require_req(raw["status"] in ("completed",))
        item["status"] = raw["status"]
    return item


def _sanitize_input(items, model: str, vault: ReasoningVault) -> list[dict]:
    _require_req(type(items) is list and 1 <= len(items) <= MAX_INPUT_ITEMS)
    cleaned = []
    for raw in items:
        _require_req(type(raw) is dict)
        kind = raw.get("type", "message")
        if kind == "message":
            cleaned.append(_sanitize_message_item(raw))
        elif kind == "function_call":
            cleaned.append(_sanitize_call_item(raw))
        elif kind == "function_call_output":
            cleaned.append(_sanitize_call_output_item(raw))
        elif kind == "reasoning":
            cleaned.append(_sanitize_reasoning_item(raw, model, vault))
        else:
            raise RequestRefused(400, "unsupported_input_item", "Unsupported input item type.")
    return cleaned


def _sanitize_tools(tools) -> list[dict]:
    _require_req(type(tools) is list and len(tools) <= MAX_TOOLS)
    cleaned = []
    names = set()
    for tool in tools:
        _require_req(type(tool) is dict and {"type", "name", "parameters"} <= tool.keys() <= _ALLOWED_TOOL_KEYS)
        _require_req(tool["type"] == "function" and _valid_id(tool["name"]) and tool["name"] not in names)
        _require_req(type(tool["parameters"]) is dict)
        names.add(tool["name"])
        entry = {"type": "function", "name": tool["name"], "parameters": tool["parameters"]}
        if "description" in tool and tool["description"] is not None:
            _require_req(type(tool["description"]) is str)
            entry["description"] = tool["description"]
        if "strict" in tool and tool["strict"] is not None:
            _require_req(type(tool["strict"]) is bool)
            entry["strict"] = tool["strict"]
        cleaned.append(entry)
    return cleaned


def _sanitize_tool_choice(choice):
    if choice in ("auto", "none", "required"):
        return choice
    _require_req(type(choice) is dict and set(choice) == {"type", "name"}
                 and choice.get("type") == "function" and _valid_id(choice.get("name")))
    return {"type": "function", "name": choice["name"]}


def _sanitize_reasoning(value) -> dict:
    _require_req(type(value) is dict and set(value) <= {"effort", "summary"})
    cleaned = {}
    if "effort" in value and value["effort"] is not None:
        _require_req(value["effort"] in ("none", "minimal", "low", "medium", "high", "xhigh"))
        cleaned["effort"] = value["effort"]
    if "summary" in value and value["summary"] is not None:
        _require_req(value["summary"] in ("auto", "concise", "detailed"))
        cleaned["summary"] = value["summary"]
    return cleaned


def _sanitize_text_format(fmt) -> dict:
    _require_req(type(fmt) is dict and fmt.get("type") in ("text", "json_object", "json_schema"))
    if fmt["type"] in ("text", "json_object"):
        _require_req(set(fmt) == {"type"})
        return {"type": fmt["type"]}
    _require_req({"type", "name", "schema"} <= set(fmt) <= {"type", "name", "schema", "description", "strict"})
    _require_req(_valid_id(fmt["name"]) and type(fmt["schema"]) is dict)
    entry = {"type": "json_schema", "name": fmt["name"], "schema": fmt["schema"]}
    if fmt.get("description") is not None:
        _require_req(type(fmt["description"]) is str)
        entry["description"] = fmt["description"]
    if fmt.get("strict") is not None:
        _require_req(type(fmt["strict"]) is bool)
        entry["strict"] = fmt["strict"]
    return entry


def _sanitize_text(value) -> dict:
    _require_req(type(value) is dict and set(value) <= {"format", "verbosity"})
    cleaned = {}
    if value.get("verbosity") is not None:
        _require_req(value["verbosity"] in ("low", "medium", "high"))
        cleaned["verbosity"] = value["verbosity"]
    if value.get("format") is not None:
        cleaned["format"] = _sanitize_text_format(value["format"])
    return cleaned


def _parse_headers(header_lines: list[bytes]) -> dict[bytes, bytes]:
    headers: dict[bytes, bytes] = {}
    for line in header_lines:
        name, sep, value = line.partition(b":")
        _require_req(bool(sep) and bool(_HEADER_NAME.fullmatch(name)))
        low = name.lower()
        if low in _FORBIDDEN_HEADERS or any(low.startswith(prefix) for prefix in _FORBIDDEN_HEADER_PREFIXES):
            raise RequestRefused(403, "forbidden_header", "Browser or hop-by-hop header rejected.")
        _require_req(low in _ALLOWED_HEADERS and low not in headers)
        stripped = value.strip(b" \t")
        _require_req(bool(re.fullmatch(rb"[ -~]*", stripped)))
        headers[low] = stripped
    return headers


def _validate_request_headers(headers: dict[bytes, bytes], body_len: int, expected_token: str) -> None:
    _require_req(headers.get(b"host") == b"127.0.0.1:8401", 403, "invalid_host", "Unexpected Host header.")
    auth = headers.get(b"authorization", b"")
    expected_auth = f"Bearer {expected_token}".encode("ascii")
    if not hmac.compare_digest(auth, expected_auth):
        raise RequestRefused(401, "unauthorized", "Missing or invalid worker token.")
    content_length = headers.get(b"content-length")
    if content_length is not None:
        _require_req(len(content_length) <= 8 and content_length.isdigit() and int(content_length) == body_len)
    else:
        _require_req(body_len == 0)


def _apply_optional_scalars(data: dict, sanitized: dict) -> None:
    if data.get("instructions") is not None:
        _require_req(type(data["instructions"]) is str)
        sanitized["instructions"] = data["instructions"]
    if data.get("parallel_tool_calls") is not None:
        _require_req(type(data["parallel_tool_calls"]) is bool)
        sanitized["parallel_tool_calls"] = data["parallel_tool_calls"]
    if data.get("max_output_tokens") is not None:
        # Validate caller input, then omit per SIWC direct-token route rules (prd_i4a.md).
        _require_req(type(data["max_output_tokens"]) is int and data["max_output_tokens"] > 0)
    if data.get("temperature") is not None:
        _require_req(type(data["temperature"]) in (int, float) and 0 <= data["temperature"] <= 2)
        sanitized["temperature"] = data["temperature"]
    if data.get("top_p") is not None:
        _require_req(type(data["top_p"]) in (int, float) and 0 < data["top_p"] <= 1)
        sanitized["top_p"] = data["top_p"]
    if data.get("truncation") is not None:
        _require_req(data["truncation"] in ("auto", "disabled"))
        sanitized["truncation"] = data["truncation"]
    if data.get("prompt_cache_key") is not None:
        _require_req(type(data["prompt_cache_key"]) is str and _ID_RE.fullmatch(data["prompt_cache_key"]))
        sanitized["prompt_cache_key"] = data["prompt_cache_key"]


def _apply_optional_structures(data: dict, sanitized: dict) -> None:
    if data.get("tools") is not None:
        sanitized["tools"] = _sanitize_tools(data["tools"])
    if data.get("tool_choice") is not None:
        sanitized["tool_choice"] = _sanitize_tool_choice(data["tool_choice"])
    if data.get("include") is not None:
        _require_req(data["include"] in ([], ["reasoning.encrypted_content"]))
        if data["include"]:
            sanitized["include"] = ["reasoning.encrypted_content"]
    if data.get("reasoning") is not None:
        reasoning = _sanitize_reasoning(data["reasoning"])
        if reasoning:
            sanitized["reasoning"] = reasoning
    if data.get("text") is not None:
        text_cfg = _sanitize_text(data["text"])
        if text_cfg:
            sanitized["text"] = text_cfg


def _resolve_allowed_tools(sanitized: dict) -> frozenset[str]:
    declared = frozenset(tool["name"] for tool in sanitized.get("tools", ()))
    choice = sanitized.get("tool_choice")
    if choice == "required":
        _require_req(bool(declared))
        return declared
    if type(choice) is dict:
        _require_req(choice["name"] in declared)
        return frozenset({choice["name"]})
    if choice == "none":
        return frozenset()
    return declared


def parse_worker_request(raw: bytes, *, expected_token: str, allowed_models: frozenset[str],
                         vault: ReasoningVault) -> ParsedRequest:
    """Validate HTTP/1.1 framing, auth, CSRF headers, and sanitize the Responses payload."""
    head, end, body = raw.partition(b"\r\n\r\n")
    _require_req(bool(end) and len(head) <= MAX_INTERACTIVE_HEADER and len(body) <= MAX_INTERACTIVE_BODY)
    request_line, *header_lines = head.split(b"\r\n")
    parts = request_line.split(b" ")
    _require_req(len(parts) == 3 and parts[2] == b"HTTP/1.1")
    method, target = parts[0], parts[1]

    headers = _parse_headers(header_lines)
    _validate_request_headers(headers, len(body), expected_token)

    if method == b"GET" and target == b"/v1/models":
        _require_req(len(body) == 0)
        return ParsedRequest(route="models")
    if method != b"POST" or target != b"/v1/responses":
        raise RequestRefused(404, "not_found", "Unsupported endpoint.")

    _require_req(len(body) > 0)
    ct = headers.get(b"content-type", b"").lower()
    _require_req(bool(_JSON_CONTENT_TYPE.fullmatch(ct)))

    try:
        data = decode_json(body)
    except (ValueError, RecursionError):
        raise RequestRefused(400, "invalid_json", "Invalid JSON body.") from None

    _require_req(type(data) is dict)
    _require_req({"model", "input", "stream"} <= data.keys() <= _ALLOWED_REQUEST_KEYS)
    _require_req(data.get("stream") is True, 400, "stream_required", "Streaming Responses required.")
    _require_req(data.get("store", False) is False, 400, "store_forbidden", "Server storage must be disabled.")

    model = data["model"]
    _require_req(type(model) is str and model in allowed_models, 400, "model_unavailable",
                 "Requested model is not in the verified ChatGPT catalog.")

    sanitized: dict = {
        "model": model,
        "store": False,
        "stream": True,
        "input": _sanitize_input(data["input"], model, vault),
    }
    _apply_optional_scalars(data, sanitized)
    _apply_optional_structures(data, sanitized)
    allowed_tools = _resolve_allowed_tools(sanitized)
    return ParsedRequest(route="responses", body=sanitized, model=model, allowed_tools=allowed_tools)


def _check_moderation_or_metadata(low: str, value) -> None:
    if low == "openai_chatgpt_moderation_metadata":
        _validate_moderation_root(value)
        return
    if low == "moderation" and value is None:
        return
    if "moderation" in low:
        raise StreamAborted("metadata_moderation")
    if low == "metadata" and value not in (None, {}):
        _validate_metadata_dict(value)


def _check_safety_entry(key, value) -> None:
    if type(key) is not str:
        return
    low = key.lower()
    if "guardian" in low:
        raise StreamAborted("metadata_guardian")
    if (low == "safety_buffering" and value is not False) or (low == "type" and value == "safety_buffering"):
        raise StreamAborted("safety_buffering")
    if (low in ("is_blocked", "blocked", "flagged", "requires_review", "needs_review", "review_required")
            and value is not False):
        raise StreamAborted("safety_signal")
    if low == "openai_verification_recommendation" and value != []:
        raise StreamAborted("metadata_review")
    if low in ("incomplete_details", "error") and value is not None:
        raise StreamAborted("safety_signal")
    _check_moderation_or_metadata(low, value)


def _scan_dict_children(current: dict, depth: int, stack: list) -> None:
    for key, value in current.items():
        _check_safety_entry(key, value)
        if type(value) in (dict, list):
            stack.append((value, depth + 1))


def _scan_global_safety(obj) -> None:
    """Recursively fail closed on any guardian, moderation, or safety_buffering signal."""
    stack = [(obj, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if depth > MAX_SCAN_DEPTH or nodes > MAX_SCAN_NODES:
            raise StreamAborted("safety_scan_limit")
        if type(current) is dict:
            _scan_dict_children(current, depth, stack)
        elif type(current) is list:
            for item in current:
                if type(item) in (dict, list):
                    stack.append((item, depth + 1))


def _validate_category_flags(flags) -> None:
    if type(flags) is not dict or len(flags) > 128:
        raise StreamAborted("metadata_moderation")
    for name, flagged in flags.items():
        if type(name) is not str or not 1 <= len(name) <= 64 or flagged is not False:
            raise StreamAborted("metadata_moderation")


def _validate_category_scores(scores) -> None:
    if type(scores) is not dict or len(scores) > 128:
        raise StreamAborted("metadata_moderation")
    for name, score in scores.items():
        if (type(name) is not str or not 1 <= len(name) <= 64
                or type(score) not in (int, float) or not 0 <= score <= 1):
            raise StreamAborted("metadata_moderation")


def _validate_moderation_entry_scalars(entry: dict) -> None:
    for text_key in ("category", "classifier", "label"):
        val = entry.get(text_key)
        if val is not None and (type(val) is not str or len(val) > 256):
            raise StreamAborted("metadata_moderation")
    score = entry.get("score")
    if score is not None and (type(score) not in (int, float) or not 0 <= score <= 1):
        raise StreamAborted("metadata_moderation")


def _validate_moderation_entry(entry, *, require_explicit_unblocked: bool = True, depth: int = 0) -> None:
    if depth > 2 or type(entry) is not dict or not set(entry) <= _MODERATION_ENTRY_KEYS:
        raise StreamAborted("metadata_moderation")
    unblocked = entry.get("is_blocked")
    if (require_explicit_unblocked and unblocked is not False) or (
            not require_explicit_unblocked and "is_blocked" in entry and unblocked is not False):
        raise StreamAborted("metadata_moderation")
    _validate_moderation_entry_scalars(entry)
    if entry.get("category_flags") is not None:
        _validate_category_flags(entry["category_flags"])
    if entry.get("category_scores") is not None:
        _validate_category_scores(entry["category_scores"])
    if entry.get("results") is not None:
        _validate_moderation_entries(entry["results"], require_explicit_unblocked=False, depth=depth + 1)


def _validate_moderation_entries(entries, *, require_explicit_unblocked: bool = True, depth: int = 0) -> None:
    if type(entries) is not list or len(entries) > 32:
        raise StreamAborted("metadata_moderation")
    for entry in entries:
        _validate_moderation_entry(entry, require_explicit_unblocked=require_explicit_unblocked, depth=depth)


def _validate_moderation_bucket(bucket) -> None:
    if bucket is None or bucket == {}:
        return
    if type(bucket) is not dict or not set(bucket) <= _MODERATION_SLOT_KEYS:
        raise StreamAborted("metadata_moderation")
    if "is_blocked" in bucket and bucket["is_blocked"] is not False:
        raise StreamAborted("metadata_moderation")
    ptype = bucket.get("protection_type")
    if ptype is not None and (type(ptype) is not str or not 1 <= len(ptype) <= 64):
        raise StreamAborted("metadata_moderation")
    for list_key in ("outputs", "results"):
        if bucket.get(list_key) is not None:
            _validate_moderation_entries(bucket[list_key])


def _validate_moderation_slot(slot) -> None:
    if slot is None or slot == {}:
        return
    if type(slot) is not dict or len(slot) > 16:
        raise StreamAborted("metadata_moderation")
    if set(slot) <= _MODERATION_SLOT_KEYS:
        _validate_moderation_bucket(slot)
        return
    for name, bucket in slot.items():
        if type(name) is not str or not _MODERATION_CLASSIFIER_RE.fullmatch(name):
            raise StreamAborted("metadata_moderation")
        _validate_moderation_bucket(bucket)


def _validate_moderation_root(moderation) -> None:
    if type(moderation) is not dict or not set(moderation) <= _MODERATION_ROOT_KEYS:
        raise StreamAborted("metadata_moderation")
    if moderation.get("presentation") not in (None, "inline"):
        raise StreamAborted("metadata_moderation")
    schema_version = moderation.get("schema_version")
    if schema_version is not None and (type(schema_version) is not int or schema_version != 1):
        raise StreamAborted("metadata_moderation")
    for slot_key in ("prompt", "generation", "tool_call", "tool_response"):
        _validate_moderation_slot(moderation.get(slot_key))
    if moderation.get("response") not in (None, {}):
        raise StreamAborted("metadata_moderation")


def _validate_metadata_dict(metadata) -> None:
    if type(metadata) is not dict:
        raise StreamAborted("metadata_envelope")
    if not set(metadata) <= {"openai_verification_recommendation", "openai_chatgpt_moderation_metadata"}:
        raise StreamAborted("metadata_fields")
    if metadata.get("openai_verification_recommendation", []) != []:
        raise StreamAborted("metadata_review")
    _validate_moderation_root(metadata.get("openai_chatgpt_moderation_metadata", {}))


def _validate_metadata_event(event: dict, active_upstream_id: str | None) -> None:
    if (event.keys() != {"type", "response_id", "sequence_number", "metadata"}
            or active_upstream_id is None or event["response_id"] != active_upstream_id
            or type(event["sequence_number"]) is not int
            or not 0 <= event["sequence_number"] <= 2**31
            or type(event["metadata"]) is not dict):
        raise StreamAborted("metadata_envelope")
    _validate_metadata_dict(event["metadata"])


def encode_chunk(payload: bytes) -> bytes:
    if not payload:
        return b""
    return f"{len(payload):x}\r\n".encode("ascii") + payload + b"\r\n"


def sse_frame(event_type: str, payload: dict) -> bytes:
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    return f"event: {event_type}\ndata: ".encode("ascii") + encoded + b"\n\n"


def _valid_index(value, limit: int = 64) -> int:
    if type(value) is not int or not 0 <= value < limit:
        raise StreamAborted("invalid_index")
    return value


def _valid_summary(summary) -> list[dict]:
    if summary is None:
        return []
    if type(summary) is not list or len(summary) > MAX_CONTENT_PARTS:
        raise StreamAborted("invalid_reasoning_item")
    out = []
    for part in summary:
        if type(part) is not dict or part.get("type") != "summary_text" or type(part.get("text")) is not str:
            raise StreamAborted("invalid_reasoning_item")
        out.append({"type": "summary_text", "text": part["text"]})
    return out


class SessionStreamProjector:
    """Project upstream Responses SSE safely with host-only IDs/vault and buffered tool calls."""

    def __init__(self, *, model: str, local_response_id: str, vault: ReasoningVault,
                 allowed_tools: frozenset[str] = frozenset()):
        self.model = model
        self.local_response_id = local_response_id
        self.vault = vault
        self._allowed_tools = frozenset(allowed_tools)
        self.upstream_response_id: str | None = None
        self.events_seen = 0
        self.metadata_checked = 0
        self.usage: tuple[int, int, int] | None = None
        self._item_ids: dict[str, str] = {}
        self._reasoning_ids: dict[str, str] = {}
        self._staged_vault: dict[str, tuple[str, str, str]] = {}
        self._buffered_frames: list[bytes] = []
        self._buffered_bytes = 0
        self._buffered_tool_added: dict[int, dict] = {}
        self._buffered_tool_done: dict[int, dict] = {}
        self._buffered_arg_deltas: dict[int, list[tuple[str | None, str | None, str | None, str]]] = {}
        self._buffered_arg_done: dict[int, tuple[str | None, str | None, str | None, str]] = {}
        self._completed_tool_calls: dict[int, dict] = {}
        self._non_tool_indices: set[int] = set()
        self._saw_refusal = False
        self._completed_seen = False

    def _buffer_frame(self, frame: bytes) -> None:
        self._buffered_bytes += len(frame)
        if self._buffered_bytes > MAX_BUFFERED_TOOL_BYTES:
            raise StreamAborted("buffered_tool_limit")
        self._buffered_frames.append(frame)

    def _local_item_id(self, upstream_id: str, prefix: str) -> str:
        if not _valid_id(upstream_id):
            raise StreamAborted("invalid_item_id")
        existing = self._item_ids.get(upstream_id)
        if existing is not None:
            return existing
        local = f"{prefix}_{len(self._item_ids) + 1}"
        self._item_ids[upstream_id] = local
        return local

    def _local_reasoning_id(self, upstream_id: str) -> str:
        if not _valid_id(upstream_id):
            raise StreamAborted("invalid_reasoning_item")
        existing = self._reasoning_ids.get(upstream_id)
        if existing is not None:
            return existing
        local = self.vault.next_local_id()
        self._reasoning_ids[upstream_id] = local
        self._item_ids[upstream_id] = local
        return local

    def _stage_reasoning_ciphertext(self, upstream_id: str, ciphertext: str) -> tuple[str, str]:
        if (type(ciphertext) is not str or not ciphertext or not ciphertext.isascii()
                or any(ord(ch) < 33 or ord(ch) > 126 for ch in ciphertext)):
            raise StreamAborted("invalid_reasoning_ciphertext")
        local_id = self._local_reasoning_id(upstream_id)
        staged = self._staged_vault.get(upstream_id)
        if staged is not None:
            prev_local, prev_handle, prev_cipher = staged
            if prev_cipher != ciphertext or prev_local != local_id:
                raise StreamAborted("reasoning_ciphertext_mismatch")
            return prev_local, prev_handle
        handle = self.vault.make_handle()
        self._staged_vault[upstream_id] = (local_id, handle, ciphertext)
        return local_id, handle

    def _project_content_part(self, part) -> dict:
        if type(part) is not dict:
            raise StreamAborted("invalid_content_part")
        ptype = part.get("type")
        if ptype == "output_text":
            text = part.get("text", "")
            if type(text) is not str:
                raise StreamAborted("invalid_content_part")
            return {"type": "output_text", "text": text, "annotations": []}
        if ptype == "refusal":
            refusal = part.get("refusal", "")
            if type(refusal) is not str:
                raise StreamAborted("invalid_content_part")
            self._saw_refusal = True
            return {"type": "refusal", "refusal": refusal}
        raise StreamAborted("unsupported_content_part")

    def _project_message_item(self, item: dict) -> dict:
        role = item.get("role", "assistant")
        status = item.get("status", "in_progress")
        content = item.get("content", [])
        if (role != "assistant" or status not in ("in_progress", "completed", "incomplete")
                or type(content) is not list or len(content) > MAX_CONTENT_PARTS):
            raise StreamAborted("invalid_item")
        out: dict = {
            "type": "message",
            "role": "assistant",
            "status": status,
            "content": [self._project_content_part(part) for part in content],
        }
        if item.get("id") is not None:
            out["id"] = self._local_item_id(item["id"], "msg_local")
        if item.get("phase") is not None:
            if item["phase"] not in ("commentary", "final_answer"):
                raise StreamAborted("invalid_item")
            out["phase"] = item["phase"]
        return out

    def _project_call_item(self, item: dict, *, terminal: bool = False) -> dict:
        raw_status = item.get("status")
        if terminal:
            if raw_status not in (None, "completed"):
                raise StreamAborted("invalid_function_call")
            status = "completed"
        else:
            status = "in_progress" if raw_status is None else raw_status
            if status not in ("in_progress", "completed", "incomplete"):
                raise StreamAborted("invalid_function_call")
        arguments = item.get("arguments", "")
        if (not _valid_id(item.get("call_id")) or not _valid_id(item.get("name"))
                or type(arguments) is not str):
            raise StreamAborted("invalid_function_call")
        if item["name"] not in self._allowed_tools:
            raise StreamAborted("unauthorized_tool_call")
        out = {
            "type": "function_call",
            "call_id": item["call_id"],
            "name": item["name"],
            "arguments": arguments,
            "status": status,
        }
        if item.get("id") is not None:
            out["id"] = self._local_item_id(item["id"], "fc_local")
        return out

    def _project_reasoning_item(self, item: dict, *, allow_vault: bool) -> dict:
        upstream_id = item.get("id")
        out = {
            "type": "reasoning",
            "id": self._local_reasoning_id(upstream_id),
            "summary": _valid_summary(item.get("summary", [])),
        }
        status = item.get("status")
        if status is not None:
            if status not in ("in_progress", "completed"):
                raise StreamAborted("invalid_reasoning_item")
            out["status"] = status
        ciphertext = item.get("encrypted_content")
        if allow_vault and ciphertext is not None:
            _, handle = self._stage_reasoning_ciphertext(upstream_id, ciphertext)
            out["encrypted_content"] = handle
        elif allow_vault and upstream_id in self._staged_vault:
            out["encrypted_content"] = self._staged_vault[upstream_id][1]
        return out

    def _project_item(self, item, *, allow_vault: bool, allow_tools: bool = True, terminal: bool = False) -> dict:
        if type(item) is not dict:
            raise StreamAborted("invalid_item")
        kind = item.get("type")
        if kind == "message":
            return self._project_message_item(item)
        if kind == "function_call":
            if not allow_tools:
                raise StreamAborted("premature_tool_call")
            return self._project_call_item(item, terminal=terminal)
        if kind == "reasoning":
            return self._project_reasoning_item(item, allow_vault=allow_vault)
        raise StreamAborted("unsupported_item_type")

    def _project_response_envelope(self, response: dict, *, allow_vault: bool,
                                   allow_tools: bool = False, terminal: bool = False) -> dict:
        if type(response) is not dict:
            raise StreamAborted("invalid_response_envelope")
        status = response.get("status", "in_progress")
        if status not in ("queued", "in_progress", "completed"):
            raise StreamAborted("invalid_response_envelope")
        raw_output = response.get("output", [])
        if type(raw_output) is not list or len(raw_output) > 64:
            raise StreamAborted("invalid_response_envelope")
        output = [
            self._project_item(item, allow_vault=allow_vault, allow_tools=allow_tools, terminal=terminal)
            for item in raw_output
        ]
        projected: dict = {
            "id": self.local_response_id,
            "object": "response",
            "model": self.model,
            "status": status,
            "output": output,
        }
        usage = response.get("usage")
        if type(usage) is dict:
            counts = tuple(usage.get(k) for k in ("input_tokens", "output_tokens", "total_tokens"))
            if all(type(c) is int and 0 <= c <= 2**31 for c in counts) and counts[0] + counts[1] == counts[2]:
                projected["usage"] = {
                    "input_tokens": counts[0],
                    "output_tokens": counts[1],
                    "total_tokens": counts[2],
                }
        return projected

    def _mapped_event_item_id(self, event: dict, *, require_reasoning: bool = False) -> str | None:
        item_id = event.get("item_id")
        if item_id is None:
            if require_reasoning:
                raise StreamAborted("missing_reasoning_item_id")
            return None
        if not _valid_id(item_id):
            raise StreamAborted("invalid_item_id")
        if require_reasoning:
            if item_id not in self._reasoning_ids:
                raise StreamAborted("unknown_reasoning_item_id")
            return self._reasoning_ids[item_id]
        return self._item_ids.get(item_id, self._local_item_id(item_id, "item_local"))

    def _attach_content_fields(self, event: dict, payload: dict) -> None:
        if "content_index" in event:
            payload["content_index"] = _valid_index(event["content_index"])
        mapped = self._mapped_event_item_id(event)
        if mapped is not None:
            payload["item_id"] = mapped

    def _project_text_event(self, kind: str, event: dict, payload: dict) -> tuple[bytes, bool]:
        if kind.startswith("response.refusal."):
            self._saw_refusal = True
        if kind.endswith(_DELTA_SUFFIX):
            field = "delta"
        elif kind == _EVENT_TEXT_DONE:
            field = "text"
        else:
            field = "refusal"
        if type(event.get(field)) is not str:
            raise StreamAborted("invalid_delta")
        payload[field] = event[field]
        self._attach_content_fields(event, payload)
        return sse_frame(kind, payload), False

    def _project_function_arg_event(self, kind: str, event: dict, payload: dict) -> tuple[bytes, bool]:
        if not self._allowed_tools:
            raise StreamAborted("unauthorized_tool_call")
        idx = _valid_index(event.get("output_index"))
        if idx in self._non_tool_indices:
            raise StreamAborted("tool_call_mismatch")
        payload["output_index"] = idx
        key = "delta" if kind.endswith(_DELTA_SUFFIX) else "arguments"
        value = event.get(key)
        if type(value) is not str:
            raise StreamAborted("invalid_function_call")
        payload[key] = value
        call_id = event.get("call_id")
        if call_id is not None:
            if not _valid_id(call_id):
                raise StreamAborted("invalid_function_call")
            payload["call_id"] = call_id
        name = event.get("name")
        if name is not None:
            if not _valid_id(name):
                raise StreamAborted("invalid_function_call")
            if name not in self._allowed_tools:
                raise StreamAborted("unauthorized_tool_call")
            payload["name"] = name
        mapped = self._mapped_event_item_id(event)
        if mapped is not None:
            payload["item_id"] = mapped
        if kind.endswith(_DELTA_SUFFIX):
            self._buffered_arg_deltas.setdefault(idx, []).append((call_id, mapped, name, value))
        else:
            if idx in self._buffered_arg_done:
                raise StreamAborted("tool_call_mismatch")
            self._buffered_arg_done[idx] = (call_id, mapped, name, value)
        # Buffer all tool-call argument frames until metadata + completed + EOF verify.
        return sse_frame(kind, payload), True

    def _project_reasoning_event(self, kind: str, event: dict, payload: dict) -> tuple[bytes, bool]:
        payload["item_id"] = self._mapped_event_item_id(event, require_reasoning=True)
        if "summary_index" in event:
            payload["summary_index"] = _valid_index(event["summary_index"])
        if kind in ("response.reasoning_summary_part.added", "response.reasoning_summary_part.done"):
            part = event.get("part")
            if type(part) is not dict or part.get("type") != "summary_text" or type(part.get("text")) is not str:
                raise StreamAborted("invalid_reasoning_item")
            payload["part"] = {"type": "summary_text", "text": part["text"]}
            return sse_frame(kind, payload), False
        field = "delta" if kind.endswith(_DELTA_SUFFIX) else "text"
        if type(event.get(field)) is not str:
            raise StreamAborted("invalid_reasoning_item")
        payload[field] = event[field]
        if "content_index" in event:
            payload["content_index"] = _valid_index(event["content_index"])
        return sse_frame(kind, payload), False

    def _project_stream_event(self, kind: str, event: dict) -> tuple[bytes, bool]:
        """Strictly project one non-envelope streaming event; returns (frame, should_buffer)."""
        if "response_id" in event and event["response_id"] != self.upstream_response_id:
            raise StreamAborted("response_id_mismatch")
        payload: dict = {"type": kind}
        if "output_index" in event:
            payload["output_index"] = _valid_index(event["output_index"])
        if kind in ("response.output_text.delta", "response.refusal.delta",
                    _EVENT_TEXT_DONE, "response.refusal.done"):
            return self._project_text_event(kind, event, payload)
        if kind in ("response.content_part.added", "response.content_part.done"):
            payload["part"] = self._project_content_part(event.get("part"))
            self._attach_content_fields(event, payload)
            return sse_frame(kind, payload), False
        if kind in ("response.function_call_arguments.delta", "response.function_call_arguments.done"):
            return self._project_function_arg_event(kind, event, payload)
        if kind.startswith(("response.reasoning_summary_", "response.reasoning_text.")):
            return self._project_reasoning_event(kind, event, payload)
        raise StreamAborted("unsupported_event")

    def _feed_created(self, event: dict) -> list[bytes]:
        response = event.get("response")
        if type(response) is not dict or not _valid_id(response.get("id")):
            raise StreamAborted("invalid_response_id")
        self.upstream_response_id = response["id"]
        projected_resp = self._project_response_envelope(response, allow_vault=False, allow_tools=False)
        return [sse_frame(_EVENT_CREATED, {"type": _EVENT_CREATED, "response": projected_resp})]

    def _feed_progress(self, kind: str, event: dict) -> list[bytes]:
        response = event.get("response")
        if type(response) is not dict or response.get("id") != self.upstream_response_id:
            raise StreamAborted("response_id_mismatch")
        projected_resp = self._project_response_envelope(response, allow_vault=False, allow_tools=False)
        return [sse_frame(kind, {"type": kind, "response": projected_resp})]

    def _feed_output_item(self, kind: str, event: dict, *, allow_vault: bool) -> list[bytes]:
        if "response_id" in event and event["response_id"] != self.upstream_response_id:
            raise StreamAborted("response_id_mismatch")
        raw_item = event.get("item")
        raw_idx = event.get("output_index")
        is_tool = type(raw_item) is dict and raw_item.get("type") == "function_call"
        if not is_tool and raw_idx is None:
            raw_idx = 0
        idx = _valid_index(raw_idx)
        item = self._project_item(raw_item, allow_vault=allow_vault, allow_tools=True)
        frame = sse_frame(kind, {"type": kind, "output_index": idx, "item": item})
        if item["type"] == "function_call":
            if idx in self._non_tool_indices:
                raise StreamAborted("tool_call_mismatch")
            bucket = self._buffered_tool_added if kind == _EVENT_ITEM_ADDED else self._buffered_tool_done
            if idx in bucket:
                raise StreamAborted("tool_call_mismatch")
            bucket[idx] = item
            self._buffer_frame(frame)
            return []
        if (idx in self._buffered_tool_added or idx in self._buffered_tool_done
                or idx in self._buffered_arg_deltas or idx in self._buffered_arg_done):
            raise StreamAborted("tool_call_mismatch")
        self._non_tool_indices.add(idx)
        return [frame]

    def _feed_completed(self, event: dict) -> list[bytes]:
        response = event.get("response")
        if (type(response) is not dict or response.get("id") != self.upstream_response_id
                or response.get("status") != "completed"):
            raise StreamAborted("invalid_completed")
        usage = response.get("usage")
        if type(usage) is dict:
            counts = tuple(usage.get(k) for k in ("input_tokens", "output_tokens", "total_tokens"))
            if all(type(c) is int and 0 <= c <= 2**31 for c in counts) and counts[0] + counts[1] == counts[2]:
                self.usage = counts
        projected_resp = self._project_response_envelope(response, allow_vault=True, allow_tools=True, terminal=True)
        self._completed_tool_calls = {
            idx: item for idx, item in enumerate(projected_resp["output"]) if item["type"] == "function_call"
        }
        self._buffer_frame(sse_frame(_EVENT_COMPLETED, {"type": _EVENT_COMPLETED, "response": projected_resp}))
        self._completed_seen = True
        return []

    def _validate_event_kind(self, event) -> str:
        self.events_seen += 1
        if self.events_seen > MAX_INTERACTIVE_EVENTS or self._completed_seen:
            raise StreamAborted("stream_bounds")
        if type(event) is not dict:
            raise StreamAborted("invalid_event")
        kind = event.get("type")
        if type(kind) is not str or len(kind) > 96 or not _EVENT_LABEL.fullmatch(kind):
            raise StreamAborted("invalid_event_label")
        _scan_global_safety(event)
        return kind

    def _feed_lifecycle(self, kind: str, event: dict) -> list[bytes] | None:
        if kind in ("response.in_progress", "response.queued"):
            return self._feed_progress(kind, event)
        if kind == _EVENT_ITEM_ADDED:
            return self._feed_output_item(kind, event, allow_vault=False)
        if kind == "response.output_item.done":
            return self._feed_output_item(kind, event, allow_vault=True)
        if kind == _EVENT_COMPLETED:
            return self._feed_completed(event)
        return None

    def feed(self, event: dict) -> list[bytes]:
        """Process one upstream event; return SSE frame bytes safe to emit immediately."""
        kind = self._validate_event_kind(event)
        if kind in ("ping", "keepalive"):
            return []
        if kind == "response.metadata":
            _validate_metadata_event(event, self.upstream_response_id)
            self.metadata_checked += 1
            return []
        if kind in ("response.failed", "response.incomplete", "error"):
            raise StreamAborted(f"provider_{kind.replace('.', '_')}")
        if kind.startswith(_UNSUPPORTED_EVENT_PREFIXES) or kind not in _ALLOWED_STREAM_EVENTS:
            raise StreamAborted("unsupported_event")
        if self.upstream_response_id is None:
            if kind != _EVENT_CREATED:
                raise StreamAborted("missing_response_created")
            return self._feed_created(event)
        if kind == _EVENT_CREATED:
            raise StreamAborted("duplicate_response_created")
        handled = self._feed_lifecycle(kind, event)
        if handled is not None:
            return handled

        frame, should_buffer = self._project_stream_event(kind, event)
        if should_buffer:
            self._buffer_frame(frame)
            return []
        return [frame]

    @staticmethod
    def _check_tool_identity(completed: dict, item: dict) -> None:
        if item["call_id"] != completed["call_id"] or item["name"] != completed["name"]:
            raise StreamAborted("tool_call_mismatch")
        if "id" in item and "id" in completed and item["id"] != completed["id"]:
            raise StreamAborted("tool_call_mismatch")

    def _verify_tool_items(self) -> None:
        for idx, added in self._buffered_tool_added.items():
            completed = self._completed_tool_calls.get(idx)
            if completed is None:
                raise StreamAborted("tool_call_mismatch")
            self._check_tool_identity(completed, added)
            if added["arguments"] and not completed["arguments"].startswith(added["arguments"]):
                raise StreamAborted("tool_call_mismatch")
        for idx, done in self._buffered_tool_done.items():
            completed = self._completed_tool_calls.get(idx)
            if completed is None:
                raise StreamAborted("tool_call_mismatch")
            self._check_tool_identity(completed, done)
            if done["arguments"] != completed["arguments"]:
                raise StreamAborted("tool_call_mismatch")

    @staticmethod
    def _check_arg_ids(completed: dict, call_id: str | None, item_id: str | None) -> None:
        if call_id is not None and call_id != completed["call_id"]:
            raise StreamAborted("tool_call_mismatch")
        if item_id is not None and completed.get("id") is not None and item_id != completed["id"]:
            raise StreamAborted("tool_call_mismatch")

    def _verify_arg_deltas(self) -> None:
        for idx, entries in self._buffered_arg_deltas.items():
            completed = self._completed_tool_calls.get(idx)
            if completed is None:
                raise StreamAborted("tool_call_mismatch")
            parts = []
            for call_id, item_id, name, delta in entries:
                self._check_arg_ids(completed, call_id, item_id)
                if name is not None and name != completed["name"]:
                    raise StreamAborted("tool_call_mismatch")
                parts.append(delta)
            if "".join(parts) != completed["arguments"]:
                raise StreamAborted("tool_call_mismatch")

    def _verify_arg_done(self) -> None:
        for idx, (call_id, item_id, name, args) in self._buffered_arg_done.items():
            completed = self._completed_tool_calls.get(idx)
            if completed is None:
                raise StreamAborted("tool_call_mismatch")
            self._check_arg_ids(completed, call_id, item_id)
            if (name is not None and name != completed["name"]) or args != completed["arguments"]:
                raise StreamAborted("tool_call_mismatch")

    def _verify_tool_args(self) -> None:
        self._verify_arg_deltas()
        self._verify_arg_done()

    def _collect_tool_ids(self, idx: int, completed: dict) -> set[str]:
        candidates = [
            item.get("id")
            for item in (completed, self._buffered_tool_added.get(idx), self._buffered_tool_done.get(idx))
            if item is not None
        ]
        candidates.extend(item_id for _c, item_id, _n, _d in self._buffered_arg_deltas.get(idx, ()))
        done_arg = self._buffered_arg_done.get(idx)
        if done_arg is not None:
            candidates.append(done_arg[1])
        return {val for val in candidates if val is not None}

    def _verify_tool_id_consistency(self) -> None:
        for idx, completed in self._completed_tool_calls.items():
            if len(self._collect_tool_ids(idx, completed)) > 1:
                raise StreamAborted("tool_call_mismatch")

    def _verify_buffered_tools(self) -> None:
        if self._saw_refusal and self._completed_tool_calls:
            raise StreamAborted("tool_call_with_refusal")
        if any(idx in self._non_tool_indices for idx in self._completed_tool_calls):
            raise StreamAborted("tool_call_mismatch")
        self._verify_tool_items()
        self._verify_tool_args()
        self._verify_tool_id_consistency()

    def finalize(self) -> list[bytes]:
        if not self._completed_seen:
            raise StreamAborted("missing_completed")
        self._verify_buffered_tools()
        for upstream_id, (local_id, handle, ciphertext) in self._staged_vault.items():
            self.vault.commit(local_id, upstream_id, handle, ciphertext, self.model)
        self._staged_vault.clear()
        frames = list(self._buffered_frames)
        self._buffered_frames.clear()
        self._buffered_bytes = 0
        return frames


def format_models_response(models: tuple[str, ...]) -> bytes:
    payload = {
        "object": "list",
        "data": [{"id": slug, "object": "model", "owned_by": "openai"} for slug in models],
    }
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Cache-Control: no-store\r\n"
        b"Connection: close\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        + body
    )


def format_error_response(status: int, code: str, message: str) -> bytes:
    reasons = {
        400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
        404: "Not Found", 429: "Too Many Requests", 502: "Bad Gateway", 503: "Service Unavailable",
    }
    reason = reasons.get(status, "Error")
    body = json.dumps(
        {"error": {"type": "broker_error", "code": code, "message": message}},
        separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")
    return (
        f"HTTP/1.1 {status} {reason}\r\n".encode("ascii")
        + b"Content-Type: application/json\r\n"
        + b"Cache-Control: no-store\r\n"
        + b"Connection: close\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        + body
    )


def sse_response_headers() -> bytes:
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/event-stream\r\n"
        b"Cache-Control: no-store\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: close\r\n\r\n"
    )
