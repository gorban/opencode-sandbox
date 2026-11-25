"""The measured local Claude Agent SDK fixture traffic."""

import json
import re
import uuid

LIMIT = 128 * 1024
PROMPT = "Reply with exactly: ok"
REPLY = "ok"
STOCK_MODEL = "claude-agent/haiku"
NATIVE_MODEL = "claude-fixture"
ROUTE_FILE = "/frontend/route.json"
SOCKET = "/broker/native.sock"
PREFIX = [
    "--output-format", "stream-json", "--verbose", "--input-format", "stream-json",
    "--thinking=adaptive", "--thinking-display=summarized", "--allowedTools=mcp__opencode__*",
    "--tools=", "--setting-sources=", "--strict-mcp-config", "--permission-mode=dontAsk",
]
SETTINGS = ["--settings", '{"disableAllHooks":true}']


class ProtocolError(RuntimeError):
    """The SDK diverged from the admitted fixture protocol."""


def require(condition):
    if not condition:
        raise ProtocolError("unexpected Claude SDK fixture message")


def pairs(entries):
    values = dict(entries)
    require(len(values) == len(entries))
    return values


def decode(line):
    require(0 < len(line) <= LIMIT and line.endswith(b"\n"))
    try:
        message = json.loads(line.decode("utf-8"), object_pairs_hook=pairs, parse_constant=reject_constant)
    except (ValueError, RecursionError):
        raise ProtocolError("malformed JSON fixture message") from None
    require(type(message) is dict)
    return message


def reject_constant(_value):
    raise ProtocolError("invalid JSON constant")


def encode(message):
    return json.dumps(message, separators=(",", ":")).encode() + b"\n"


def select_native(args):
    require(type(args) is list and all(type(arg) is str for arg in args))
    selected_model = [arg for arg in args if arg.startswith("--model=")]
    fixed = [arg for arg in args if not arg.startswith("--model=")]
    require(fixed[:len(PREFIX)] == PREFIX and fixed[-2:] == SETTINGS)
    suffix = fixed[len(PREFIX):-2]
    if suffix == ["--no-session-persistence"] and not selected_model:
        return None
    require(selected_model == ["--model=haiku"] and len(suffix) == 2 and suffix[0] == "--include-partial-messages")
    require(suffix[1].startswith("--session-id="))
    return matching_id(suffix[1].removeprefix("--session-id="), UUID4)


UUID4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
REQUEST_ID = re.compile(r"[a-z0-9]{1,96}")
DISCOVERY_CONTROLS = (
    {"subtype": "initialize", "systemPrompt": [""], "skills": []},
    {"subtype": "set_model", "model": "haiku"},
    {"subtype": "get_context_usage", "detail": "summary"},
)
TURN_INITIALIZE = {
    "subtype": "initialize", "skills": [], "systemPromptSnapshot": False,
    "appendSystemPrompt": ("<runtime_info>You are running in OpenCode through the Claude Code harness. "
                           "Mention this only when asked.</runtime_info>"),
    "hooks": {"PostToolUse": [{"hookCallbackIds": ["hook_1"]}], "PreToolUse": [{"hookCallbackIds": ["hook_0"]}]},
}
USER = {"type": "user", "message": {"role": "user", "content": [{"type": "text", "text": PROMPT}]}}


def require_exact(observed, expected):
    # JSON comparison preserves scalar types, unlike Python equality for True, 1 and 1.0.
    require(json.dumps(observed, sort_keys=True) == json.dumps(expected, sort_keys=True))


def matching_id(value, pattern):
    require(type(value) is str and pattern.fullmatch(value) is not None)
    return value


def validate_sdk(message, session, position):
    if session is not None and position == 1:
        identifier = matching_id(message.get("uuid"), UUID4)
        require_exact(message, {**USER, "parent_tool_use_id": None, "uuid": identifier, "client_composed": True})
        return USER

    request = TURN_INITIALIZE if session is not None else DISCOVERY_CONTROLS[position]
    identifier = matching_id(message.get("request_id"), REQUEST_ID)
    require_exact(message, {"type": "control_request", "request_id": identifier, "request": request})
    fields = {"model": "haiku"} if request["subtype"] == "set_model" else {}
    # The fixture only needs these control fields. Hooks and prompt additions stop here.
    return {"type": "control_request", "request_id": identifier,
            "request": {"subtype": request["subtype"], **fields}}


def control_reply(message):
    subtype = message["request"]["subtype"]
    body = {}
    if subtype == "initialize":
        body = {
            "claude_code_version": "2.1.330", "models": [{"value": "haiku", "resolvedModel": NATIVE_MODEL,
                "displayName": "Fixture Haiku", "description": "Synthetic", "supportsEffort": False}],
            "account": {"tokenSource": "claude.ai", "subscriptionType": "pro", "apiProvider": "firstParty"},
            "commands": [], "agents": [], "output_style": "default", "available_output_styles": ["default"],
        }
    elif subtype == "get_context_usage":
        body = {"rawMaxTokens": 1048576}
    return {"type": "control_response", "response": {"subtype": "success", "request_id": message["request_id"],
                                                      "response": body}}


def turn(session, frame_ids=None):
    if frame_ids is None:
        frame_ids = [str(uuid.uuid4()) for _ in range(8)]
    ids = iter(frame_ids)
    usage = {"input_tokens": 1, "output_tokens": 1, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}
    message = {"id": "msg_fixture", "type": "message", "role": "assistant", "model": NATIVE_MODEL, "content": [],
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
        yield {"type": "stream_event", "event": event, "uuid": next(ids), **identity}
    yield {"type": "assistant", "message": {**message, "content": [{"type": "text", "text": REPLY}]},
           "uuid": next(ids), **identity}
    yield {"type": "result", "subtype": "success", "is_error": False, "num_turns": 1, "result": REPLY,
           "session_id": session, "uuid": next(ids), "usage": usage, "modelUsage": {}, "total_cost_usd": 0,
           "duration_ms": 1, "duration_api_ms": 1, "permission_denials": [], "stop_reason": "end_turn"}


def validate_control_output(message, request):
    expected = control_reply(request)
    require_exact(message, expected)
    return expected


def validate_turn_output(messages, session):
    """Require exact typed fixture frames, then return the allowlisted output."""
    require(len(messages) == 8)
    ids = [matching_id(frame.get("uuid"), UUID4) for frame in messages]
    require(len(set(ids)) == len(ids))
    expected = list(turn(session, ids))
    require_exact(messages, expected)
    return expected
