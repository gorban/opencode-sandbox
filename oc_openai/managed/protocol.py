"""Fixed worker intent and bounded projection of upstream Responses events."""

from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
import json
import re

from ..responses import ConnectionError, encode_responses_body
from .relay_receipt import MAX_BODY, MAX_RESPONSE
from .runtime import PUBLIC_RESPONSES_VALUE

PROOF_PATH = "/workspace/proof.txt"
PROOF_BYTES = b"local OpenAI Responses proof\n"
INITIAL_TEXT = "Writing the proof."
FINAL_TEXT = "Wrote the proof."
TOOL_RESULT = "The approved proof file contains the expected bytes."
PROMPT = "Use the write tool to create the approved local proof file."
INSTRUCTIONS = (
    f"First say exactly {INITIAL_TEXT!r}, then call the write function once with path "
    f"{PROOF_PATH!r} and content {PROOF_BYTES.decode('ascii')!r}. Interpret the content escape "
    f"as a newline. After the function result say exactly {FINAL_TEXT!r} and make no tool call."
)
_MAX_EVENTS = 2048
_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_CALL_ID = re.compile(r"call_[A-Za-z0-9_-]{1,123}\Z")
_EVENT_LABEL = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){0,4}\Z")
_UNSUPPORTED_EVENTS = (
    "response.audio.", "response.code_interpreter_", "response.compaction.",
    "response.file_search_", "response.shell_", "response.web_search_", "response.image_generation_",
    "response.mcp_", "response.custom_tool_", "response.refusal.",
)
_HEADERS = set(b"host connection content-type content-length accept accept-encoding authorization "
               b"user-agent x-stainless-lang x-stainless-package-version x-stainless-os "
               b"x-stainless-arch x-stainless-runtime x-stainless-runtime-version "
               b"x-stainless-retry-count x-stainless-timeout b3 traceparent "
               b"x-opencode-client x-opencode-project x-opencode-session x-opencode-session-id "
               b"x-session-affinity x-session-id".split())


@dataclass(frozen=True)
class CompletedReply:
    native: dict
    continuation: dict | None = field(default=None, repr=False)


class Refused(ValueError):
    """A safe status for a closed worker exchange."""

    def __init__(self, message, *, fault=None):
        super().__init__(message)
        self.fault = fault


class Fault(str, Enum):
    EVENT = "upstream event validation"
    EVENT_SEQUENCE = "upstream event ordering or response identity"
    EVENT_COUNT = "upstream event count limit"
    EVENT_BYTES = "upstream worker JSON size limit"
    EVENT_LABEL = "malformed upstream event label"
    EVENT_UNKNOWN = "unknown upstream event"
    EVENT_UNSUPPORTED = "unsupported upstream event family"
    EVENT_ITEM = "upstream output-item shape"
    ANNOTATION = "unsupported upstream text annotation"
    METADATA_ENVELOPE = "upstream metadata envelope validation"
    METADATA_FIELDS = "unsupported upstream metadata fields"
    METADATA_REVIEW = "upstream metadata requires separate verification or review"
    METADATA_MODERATION = "unsupported upstream moderation metadata"
    SAFETY_BUFFERING = "upstream safety buffering"
    MESSAGE = "assistant message validation"
    TOOL = "approved write-call validation"
    REASONING = "stateless reasoning validation"
    REPLAY = "continuation request bounds"
    PROJECTION = "native response projection"
    DELIVERY = "native response delivery receipt"
    NATIVE = "native tool turn or terminal evidence"
    CONTINUATION = "native continuation admission"
    PLACEMENT = "worker placement or lifecycle"


@contextmanager
def checking(fault):
    try:
        yield
    except Refused as error:
        if error.fault is not None:
            raise
        raise Refused("Worker exchange refused", fault=fault) from None


def require(condition):
    if not condition:
        raise Refused("Worker exchange refused")


def _unique(pairs):
    values = dict(pairs)
    require(len(values) == len(pairs))
    return values


def _invalid_number(_):
    raise Refused("Invalid JSON number")


def decode(raw):
    try:
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=_invalid_number)
    except (ValueError, RecursionError):
        raise Refused("Invalid worker JSON") from None
    require(type(value) is dict)
    return value


def request(raw, model, output=None):
    """Accept a native trigger for the exact next phase. Return no request data."""
    head, end, body = raw.partition(b"\r\n\r\n")
    require(end and len(head) <= 16 * 1024 and 0 < len(body) <= MAX_BODY)
    line, *lines = head.split(b"\r\n")
    require(line == b"POST /v1/responses HTTP/1.1")
    headers = {}
    for line in lines:
        name, separator, value = line.partition(b":")
        name, value = name.lower(), value.strip(b" ")
        require(separator and name in _HEADERS and name not in headers and re.fullmatch(rb"[ -~]+", value))
        headers[name] = value
    require(headers.get(b"host") == b"127.0.0.1:8401")
    require(headers.get(b"authorization") == f"Bearer {PUBLIC_RESPONSES_VALUE}".encode("ascii"))
    require(headers.get(b"content-type", b"").lower() in (b"application/json", b"application/json; charset=utf-8"))
    require(headers.get(b"connection", b"close").lower() in (b"close", b"keep-alive"))
    require(headers.get(b"content-length") == str(len(body)).encode("ascii"))
    data = decode(body)
    required = {"model", "input", "stream", "tools"}
    tolerated = {"store", "instructions", "tool_choice", "parallel_tool_calls", "max_output_tokens",
                 "include", "prompt_cache_key"}
    require(required <= data.keys() <= required | tolerated)
    require(data["model"] == model and data["stream"] is True and data.get("store", False) is False)
    require(data.get("tool_choice", "auto") == "auto" and type(data.get("parallel_tool_calls", False)) is bool)
    require(data.get("include", []) in ([], ["reasoning.encrypted_content"]))
    if "max_output_tokens" in data:
        require(type(data["max_output_tokens"]) is int and 0 < data["max_output_tokens"] <= 2048)
    if "instructions" in data:
        require(type(data["instructions"]) is str)
    if "prompt_cache_key" in data:
        value = data["prompt_cache_key"]
        require(type(value) is str and re.fullmatch(r"ses_[A-Za-z0-9]{26}", value))
    _native_tools(data["tools"])
    _native_input(data["input"], output)


def _native_tools(tools):
    require(type(tools) is list and 0 < len(tools) <= 64)
    names = set()
    for tool in tools:
        require(type(tool) is dict and {"type", "name", "parameters"} <= tool.keys()
                <= {"type", "name", "parameters", "description", "strict"})
        name = tool["name"]
        require(tool["type"] == "function" and type(name) is str and _ID.fullmatch(name) and name not in names)
        require(type(tool["parameters"]) is dict)
        names.add(name)
        if name == "write":
            schema = tool["parameters"]
            properties = schema.get("properties")
            require(schema.get("type") == "object" and type(properties) is dict)
            require(set(properties) == {"path", "content"} and
                    all(type(item) is dict and item.get("type") == "string" for item in properties.values()))
    require("write" in names)


def _native_input(items, output):
    require(type(items) is list and 1 <= len(items) <= 64 and all(type(item) is dict for item in items))
    if output is not None:
        replay_count = len(output) + 1
        require(len(output) in (1, 2) and len(items) > replay_count)
        call, result = items[-2:]
        expected_call = output[-1]
        if len(output) == 2:
            message = items[-3]
            expected_message = output[0]
            require(message.get("type") == "message" and message.get("role") == "assistant")
            require(_content(message, "output_text") == INITIAL_TEXT)
            require(message.get("id", expected_message["id"]) == expected_message["id"])
        require(call.get("type") == "function_call" and call.get("call_id") == expected_call["call_id"]
                and call.get("id", expected_call["id"]) == expected_call["id"]
                and call.get("name") == "write" and type(call.get("arguments")) is str)
        require(decode(call["arguments"]) == _arguments())
        require(result.keys() == {"type", "call_id", "output"} and result["type"] == "function_call_output"
                and result["call_id"] == expected_call["call_id"])
        require(type(result["output"]) in (str, list))
        items = items[:-replay_count]
    require(items[-1].get("role") == "user" and _content(items[-1], "input_text") == PROMPT)
    require(all(item.get("type", "message") == "message" and item.get("role") == "developer"
                and type(item.get("content")) in (str, list) for item in items[:-1]))


def _content(item, content_type):
    content = item.get("content")
    if type(content) is str:
        return content
    require(type(content) is list and 0 < len(content) <= 16)
    require(all(type(part) is dict and part.get("type") == content_type and type(part.get("text")) is str
                for part in content))
    return "".join(part["text"] for part in content)


def _arguments():
    return {"path": PROOF_PATH, "content": PROOF_BYTES.decode("ascii")}


def body_for(model, output=None):
    parameters = {"type": "object", "properties": {key: {"type": "string"} for key in _arguments()},
                  "required": list(_arguments()), "additionalProperties": False}
    tool = {"type": "function", "name": "write", "description": "Write the approved proof file.",
            "parameters": parameters, "strict": True}
    input_items = [{"type": "additional_tools", "role": "developer", "tools": [tool]},
                   {"type": "message", "role": "user", "content": PROMPT}]
    if output is not None:
        call = next(item for item in output if item["type"] == "function_call")
        input_items.extend(output)
        input_items.append({"type": "function_call_output", "call_id": call["call_id"], "output": TOOL_RESULT})
    return {"model": model, "store": False, "stream": True, "instructions": INSTRUCTIONS, "input": input_items}


def _identifier(value):
    require(type(value) is str and _ID.fullmatch(value))
    return value


def _usage(raw):
    require(type(raw) is dict)
    keys = ("input_tokens", "output_tokens", "total_tokens")
    usage = {key: raw.get(key) for key in keys}
    require(all(type(value) is int and 0 <= value <= 2**31 for value in usage.values()))
    require(usage["total_tokens"] == usage["input_tokens"] + usage["output_tokens"])
    return usage


def _reasoning_item(item):
    require({"type", "id", "summary"} <= item.keys()
            <= {"type", "id", "summary", "encrypted_content", "status", "content"})
    require(item["type"] == "reasoning" and item["summary"] == [] and item.get("content") in (None, [])
            and item.get("status") in (None, "completed"))
    require(_identifier(item["id"]).startswith("rs_"))
    ciphertext = item.get("encrypted_content")
    return None if ciphertext is None else _encrypted(ciphertext)


def _encrypted(value):
    # Ciphertext is not interpreted. The stream's byte limit and the exact
    # connector encoding cap bound what we retain and replay.
    require(type(value) is str and bool(value) and value.isascii()
            and all("!" <= char <= "~" for char in value))
    return value


def _reasoning_position(index, identifier, seen):
    require(type(index) is int and 0 <= index < 8 and _identifier(identifier).startswith("rs_"))
    previous = seen.setdefault(index, identifier)
    require(previous == identifier)


def _reasoning_frame(kind, event, seen, completed):
    if kind in ("response.output_item.done", "response.output_item.added"):
        item = event["item"]
        index = event.get("output_index")
        if kind == "response.output_item.done":
            require(type(index) is int and 0 <= index < 8 and index not in completed)
            ciphertext = _reasoning_item(item) if item["type"] == "reasoning" else None
            completed[index] = (item["type"], _identifier(item.get("id")), ciphertext)
        if item["type"] != "reasoning":
            return
        _reasoning_position(index, item.get("id"), seen)
    elif kind.startswith("response.reasoning"):
        _reasoning_position(event.get("output_index"), event.get("item_id"), seen)


def _assistant_replay(message):
    require(message.keys() <= {"id", "type", "role", "status", "content", "phase"})
    require(message.get("phase") in (None, "commentary", "final_answer"))
    content = message.get("content")
    require(type(content) is list and all(
        part.keys() <= {"type", "text", "annotations", "logprobs"}
        and part.get("annotations", []) == [] and part.get("logprobs", []) == []
        for part in content
    ))
    return message.copy()


def _completed_message(message, expected, *, strict_annotations):
    content = message.get("content")
    if strict_annotations and type(content) is list:
        with checking(Fault.ANNOTATION):
            require(all(type(part) is dict and part.get("annotations", []) == [] for part in content))
    require(message.get("type") == "message" and message.get("role") == "assistant"
            and message.get("status") == "completed"
            and _content(message, "output_text").strip(" \t\r\n") == expected)
    return {"type": "message", "role": "assistant", "status": "completed", "id": _identifier(message.get("id")),
            "content": [{"type": "output_text", "text": expected, "annotations": []}]}


def _completed_call(call):
    fields = {"type", "name", "arguments", "id", "call_id"}
    require(fields <= call.keys() <= fields | {"status", "async", "caller", "namespace"}
            and call["type"] == "function_call" and call["name"] == "write"
            and call.get("status") in (None, "completed")
            and (call.get("async") is None or call["async"] is False)
            and call.get("caller") in (None, {"type": "direct"}) and call.get("namespace") is None
            and type(call["arguments"]) is str)
    require(len(call["arguments"]) <= 1024 and decode(call["arguments"]) == _arguments())
    call_id = _identifier(call["call_id"])
    require(_CALL_ID.fullmatch(call_id))
    return {"type": "function_call", "name": "write", "status": "completed",
            "id": _identifier(call["id"]), "call_id": call_id,
            "arguments": json.dumps(_arguments(), separators=(",", ":"))}


def _continuation_items(items, message, call, seen_reasoning, completed_reasoning):
    history = []
    seen_ids = set()
    terminal_positions = set()
    for index, item in enumerate(items):
        item_id = _identifier(item.get("id"))
        require(item_id not in seen_ids)
        seen_ids.add(item_id)
        completed = completed_reasoning.get(index)
        require(completed is None or completed[:2] == (item.get("type"), item_id))
        if item is message:
            with checking(Fault.MESSAGE):
                history.append(_assistant_replay(message))
        elif item is call:
            history.append(call.copy())
        else:
            with checking(Fault.REASONING):
                terminal_positions.add(index)
                require(seen_reasoning.get(index, item_id) == item_id)
                terminal_ciphertext = _reasoning_item(item)
                completed_ciphertext = completed[2] if completed is not None else None
                require(terminal_ciphertext is None or completed_ciphertext is None
                        or terminal_ciphertext == completed_ciphertext)
                ciphertext = terminal_ciphertext or completed_ciphertext
                require(ciphertext is not None)
                history.append({**item, "encrypted_content": ciphertext})
    require(seen_reasoning.keys() <= terminal_positions)
    require(all(index < len(items) for index in completed_reasoning))
    return history


def _terminal(response, model, initial, seen_reasoning, completed_reasoning, *, strict_annotations):
    require(type(response) is dict and response.get("model") == model and response.get("status") == "completed")
    expected = INITIAL_TEXT if initial else FINAL_TEXT
    items = response.get("output")
    require(type(items) is list and 0 < len(items) <= 8 and all(type(item) is dict for item in items))
    visible = [item for item in items if item.get("type") != "reasoning"]
    with checking(Fault.TOOL if initial else Fault.MESSAGE):
        require(len(visible) in ((1, 2) if initial else (1,)))
    message = None if initial and len(visible) == 1 else visible[0]
    with checking(Fault.MESSAGE):
        output = [] if message is None else [
            _completed_message(message, expected, strict_annotations=strict_annotations)
        ]
    continuation = None
    if initial:
        call = visible[-1]
        with checking(Fault.TOOL):
            output.append(_completed_call(call))
        with checking(Fault.REASONING):
            history = _continuation_items(items, message, call, seen_reasoning, completed_reasoning)
        continuation = body_for(model, history)
        # Check the entire future request using the exact connector encoding
        # before exposing even one executable frame to OpenCode.
        try:
            encode_responses_body(continuation)
        except ConnectionError:
            raise Refused("Worker continuation exceeds its request bounds", fault=Fault.REPLAY) from None
    native = {"object": "response", "id": _identifier(response.get("id")), "model": model, "status": "completed",
              "output": output, "usage": _usage(response.get("usage"))}
    return CompletedReply(native, continuation)


def _validate_metadata(event, response_id):
    with checking(Fault.METADATA_ENVELOPE):
        require(event.keys() == {"type", "response_id", "sequence_number", "metadata"}
                and event["response_id"] == response_id
                and type(event["sequence_number"]) is int and 0 <= event["sequence_number"] <= 2**31
                and type(event["metadata"]) is dict)
    metadata = event["metadata"]
    with checking(Fault.METADATA_REVIEW):
        require("guardian" not in metadata and metadata.get("openai_verification_recommendation", []) == [])
    with checking(Fault.METADATA_FIELDS):
        require(metadata.keys() <= {"openai_verification_recommendation", "openai_chatgpt_moderation_metadata"})
    with checking(Fault.METADATA_MODERATION):
        require(metadata.get("openai_chatgpt_moderation_metadata", {}) in ({}, {"presentation": "inline"}))


def validate(events, model, initial, cancelled, *, allow_progress=False, allow_metadata=False):
    """Buffer the proof through terminal validation before exposing executable items."""
    allowed = {"response.created", "response.in_progress", "response.output_item.added",
               "response.output_item.done", "response.content_part.added", "response.content_part.done",
               "response.output_text.delta", "response.output_text.done", "response.function_call_arguments.delta",
               "response.function_call_arguments.done", "response.completed",
               "response.reasoning_summary_part.added", "response.reasoning_summary_part.done",
               "response.reasoning_summary_text.delta", "response.reasoning_summary_text.done",
               "response.reasoning_text.delta", "response.reasoning_text.done"}
    terminal = None
    response_id = None
    seen_reasoning = {}
    completed_reasoning = {}
    total_bytes = 0
    for count, event in enumerate(events, 1):
        with checking(Fault.EVENT_SEQUENCE):
            require(not cancelled.is_set() and type(event) is dict and terminal is None)
        with checking(Fault.EVENT_COUNT):
            require(count <= _MAX_EVENTS)
        try:
            total_bytes += len(json.dumps(event, ensure_ascii=True, allow_nan=False))
        except (ValueError, TypeError, RecursionError):
            raise Refused("Invalid upstream event", fault=Fault.EVENT_BYTES) from None
        with checking(Fault.EVENT_BYTES):
            require(total_bytes <= MAX_RESPONSE)
        kind = event.get("type")
        with checking(Fault.EVENT_LABEL):
            require(type(kind) is str and len(kind) <= 96 and _EVENT_LABEL.fullmatch(kind))
        if allow_metadata:
            with checking(Fault.SAFETY_BUFFERING):
                require(event.get("safety_buffering", False) is False)
                metadata = event.get("metadata")
                require(type(metadata) is not dict or metadata.get("type") != "safety_buffering")
        if count == 1:
            with checking(Fault.EVENT_SEQUENCE):
                require(kind == "response.created" and type(event.get("response")) is dict)
                response_id = _identifier(event["response"].get("id"))
        elif allow_progress and kind == "response.queued":
            with checking(Fault.EVENT_SEQUENCE):
                queued = event.get("response")
                require(type(queued) is dict and queued.get("id") == response_id and queued.get("status") == "queued"
                        and queued.get("output", []) == [] and queued.get("error") is None
                        and queued.get("incomplete_details") is None)
        elif allow_progress and kind in ("ping", "keepalive"):
            with checking(Fault.EVENT_LABEL):
                require(event.keys() == {"type"})
        elif allow_metadata and kind == "response.metadata":
            _validate_metadata(event, response_id)
        elif kind == "response.completed":
            response = event.get("response")
            with checking(Fault.EVENT_SEQUENCE):
                require(type(response) is dict and response.get("id") == response_id)
            terminal = _terminal(
                response, model, initial, seen_reasoning, completed_reasoning, strict_annotations=allow_progress,
            )
        else:
            with checking(Fault.EVENT_SEQUENCE):
                require(kind != "response.created")
            if kind == "response.output_text.annotation.added":
                raise Refused("Unsupported text annotation", fault=Fault.ANNOTATION)
            if kind.startswith(_UNSUPPORTED_EVENTS) or kind in ("response.failed", "response.incomplete", "error"):
                raise Refused("Unsupported upstream event", fault=Fault.EVENT_UNSUPPORTED)
            with checking(Fault.EVENT_UNKNOWN):
                require(kind in allowed)
            if kind in ("response.output_item.added", "response.output_item.done"):
                with checking(Fault.EVENT_ITEM):
                    item = event.get("item")
                    index = event.get("output_index")
                    require(type(item) is dict and item.get("type") in ("message", "function_call", "reasoning"))
                    if allow_progress:
                        require(type(index) is int and 0 <= index < 8)
            if initial:
                with checking(Fault.REASONING):
                    require(event.get("response_id", response_id) == response_id)
                    _reasoning_frame(kind, event, seen_reasoning, completed_reasoning)
    with checking(Fault.EVENT_SEQUENCE):
        require(terminal is not None and not cancelled.is_set())
    return terminal


def project(terminal):
    """Construct native-compatible SSE using only the accepted fields."""
    def sse(kind, **values):
        return b"data: " + json.dumps({"type": kind, **values}, separators=(",", ":")).encode("ascii") + b"\n\n"

    yield sse("response.created", response={**terminal, "status": "in_progress", "output": [], "usage": None})
    for index, item in enumerate(terminal["output"]):
        if item["type"] == "message":
            yield sse("response.output_item.added", output_index=index,
                      item={**item, "status": "in_progress", "content": []})
            text = item["content"][0]["text"]
            for delta in (text[:len(text) // 2], text[len(text) // 2:]):
                yield sse("response.output_text.delta", output_index=index, item_id=item["id"], content_index=0,
                          delta=delta)
        else:
            yield sse("response.output_item.added", output_index=index,
                      item={**item, "status": "in_progress", "arguments": ""})
            yield sse("response.function_call_arguments.delta", output_index=index, item_id=item["id"],
                      delta=item["arguments"])
            yield sse("response.function_call_arguments.done", output_index=index, item_id=item["id"],
                      arguments=item["arguments"])
        yield sse("response.output_item.done", output_index=index, item=item)
    yield sse("response.completed", response=terminal)
