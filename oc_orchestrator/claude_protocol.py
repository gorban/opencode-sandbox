"""The measured local Claude Agent SDK fixture traffic."""

import json
import re

LIMIT = 128 * 1024
PROMPT = "Reply with exactly: ok"
REPLY = "Claude fixture response"
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
    message = json.loads(line, object_pairs_hook=pairs, parse_constant=reject_constant)
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
    session = re.fullmatch(r"--session-id=([a-f0-9-]{36})", suffix[1])
    require(session is not None)
    return session[1]


def validate_sdk(message, session, position):
    kind = message.get("type")
    request = message.get("request", {})
    if position == 0:
        require(kind == "control_request" and request.get("subtype") == "initialize")
        require(request.get("mcpServers", {}) == {} and request.get("sdkMcpServers", []) == [])
    elif session is None:
        expected = {1: "set_model", 2: "get_context_usage"}.get(position)
        require(kind == "control_request" and expected is not None and request.get("subtype") == expected)
        if position == 1:
            require(request.get("model") == "haiku")
    else:
        require(kind == "user" and position == 1)
        content = message.get("message", {}).get("content")
        require(type(content) is list and all(type(part) is dict and part.get("type") == "text" for part in content))
        require(sum(part.get("text") == PROMPT for part in content) == 1)
    if kind == "control_request":
        require(type(message.get("request_id")) is str and len(message["request_id"]) <= 96)
