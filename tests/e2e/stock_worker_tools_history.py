"""Exact request grammar for the pinned stock tool-loop capture."""

from dataclasses import dataclass
import hashlib
import json
import re

from oc_openai.connection_state import decode_json
from stock_worker_tools_protocol import MODEL, TITLE_PROMPT, TOOL_NAMES, FixtureMismatch, require

MAX_BATCH = 8
MAX_TURNS = 2
MAX_CONTINUATIONS = 3
MAX_FIELD_BYTES = 8192
MAX_INPUT = 32_768
MAX_OUTPUT = 4_096
MAX_WIRE = 2 * MAX_INPUT

# From the pinned binary's ordinary request in the empty fixture workspace.
_CHAT_INSTRUCTIONS = "ee1deb1f04992697a1a09fde5d559e9c714c1ea55ecaeba3d5081857bbde0bcd"
_TITLE_INSTRUCTIONS = "a8382db91f60f816e5a7c3057edc771476ae817e2bd53273577e4bf4ab3add02"
_TOOL_DEFINITIONS = {
    "glob": "f9f143749d1dd079b8ea60b647d56247c0f61a975cd6987d3c66539e270126c1",
    "grep": "f8f58a66e6cbbe26f5ec4ee606a96125d6534d533167740a771ce25df851edbd",
    "patch": "9cdcb8150e4303c48c89c72c2fbf5d3b10b2ec44206e420ce642b391a472e28c",
    "question": "3f2aa6e51aec8dca27c4865038ad31a64a808936602fd383f94ea797db0a18d0",
    "read": "c90fa26d84dd33ab6d73c0c7c1953dc497fbc4ac44849ef0d7131c206a06d407",
    "shell": "5a7ad9d89aead4613849e7064e1fcd780cdb1e1c6fe4642f260df2fe314b9da3",
    "skill": "41409855d2e83a52231b39276c664b32b7c30a2fafb5999af84d228b2e743a83",
    "subagent": "4e9b09e6e26b8d81cfe4e1fff8ea42e6f5f4e569a80e8b35c5676b8864259151",
    "webfetch": "14c1905b777083143466a0355a77a764724fa35f60a203b7f7c34c6ebe2ba00b",
    "websearch": "d92dfded7a1e0ce981bf0d9950236fa290630ee4e3b9fd2954ceed7bc0e21c45",
    "execute": "2b10c6e431a3d93d6eddf2060e92b2f25a71a3d9697a7bbb1e88d7cd21a8ca21",
}
_TOOL_FIELDS = {
    "patch": ("patchText", {"patchText": str}),
    "read": ("path", {"path": str, "offset": int, "limit": int}),
    "shell": ("command", {"command": str, "workdir": str, "timeout": int, "background": bool}),
}
_COMMON = {"model", "input", "instructions", "stream", "store", "prompt_cache_key", "include"}
_SESSION = re.compile(r"ses_[a-zA-Z0-9]{1,64}\Z")
_CALL = re.compile(r"[a-zA-Z0-9_-]{1,128}\Z")
_LOCAL_CALL = re.compile(r"fc_local_[1-9][0-9]*\Z")
_LOCAL_MESSAGE = re.compile(r"msg_local_[1-9][0-9]*\Z")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def bounded_text(value):
    if type(value) is not str:
        return False
    try:
        return len(value.encode("utf-8")) <= MAX_FIELD_BYTES
    except UnicodeError:
        return False


@dataclass(frozen=True)
class Call:
    call_id: str
    identity: str


@dataclass(frozen=True)
class Pair:
    call: Call
    identity: str


@dataclass(frozen=True)
class TurnInput:
    closed: tuple[str, ...]
    user: str
    pairs: tuple[Pair, ...]


def stock_call(item, *, projected=False):
    keys = {"type", "call_id", "id", "name", "arguments"}
    if projected:
        keys.add("status")
    require(item.keys() == keys and item["type"] == "function_call"
            and (not projected or item["status"] == "completed"), "Unmeasured stock tool call")
    call_id, local_id, name, raw = (item[key] for key in ("call_id", "id", "name", "arguments"))
    require(type(call_id) is str and _CALL.fullmatch(call_id)
            and type(local_id) is str and _LOCAL_CALL.fullmatch(local_id), "Invalid stock tool identity")
    require(type(name) is str and name in _TOOL_FIELDS and bounded_text(raw), "Unsupported stock tool")
    try:
        args = decode_json(raw)
    except (ValueError, RecursionError):
        raise FixtureMismatch("Invalid stock argument JSON") from None
    required, fields = _TOOL_FIELDS[name]
    require(type(args) is dict and required in args and args.keys() <= fields.keys()
            and all(type(value) is fields[key] for key, value in args.items()), "Invalid stock tool arguments")
    require(all(bounded_text(value) for value in args.values() if type(value) is str)
            and all(value >= 0 for key, value in args.items() if key in {"limit", "timeout"}),
            "Invalid stock argument bounds")
    return Call(call_id, digest([call_id, local_id, name, args]))


def stock_pair(call, result):
    identity = stock_call(call)
    require(result.keys() == {"type", "call_id", "output"} and result["type"] == "function_call_output"
            and result["call_id"] == identity.call_id and bounded_text(result["output"]),
            "Invalid stock result shape or identity")
    return Pair(identity, digest([identity.identity, result["output"]]))


def message_text(item, *, assistant=False):
    role, content_type = ("assistant", "output_text") if assistant else ("user", "input_text")
    keys = {"type", "role", "content"}
    if assistant:
        keys.update({"id", "status"})
    require(item.keys() == keys and item["type"] == "message" and item["role"] == role,
            "Unmeasured stock message")
    if assistant:
        require(type(item["id"]) is str and _LOCAL_MESSAGE.fullmatch(item["id"])
                and item["status"] == "completed", "Invalid stock assistant identity")
    content = item["content"]
    require(type(content) is list and len(content) == 1 and type(content[0]) is dict
            and content[0].keys() == {"type", "text"} and content[0]["type"] == content_type
            and bounded_text(content[0]["text"]), "Unmeasured stock message content")
    return content[0]["text"]


def stock_history(items):
    closed, pairs, seen = [], [], set()
    user = None
    pos = 0
    while pos < len(items):
        item = items[pos]
        if item.get("type") == "function_call":
            require(user is not None and pos + 1 < len(items), "Unmatched stock tool call")
            pair = stock_pair(item, items[pos + 1])
            require(pair.call.call_id not in seen and len(pairs) < MAX_BATCH * MAX_CONTINUATIONS,
                    "Repeated or oversized stock tool history")
            seen.add(pair.call.call_id)
            pairs.append(pair)
            pos += 2
            continue
        if item.get("role") == "assistant":
            require(user is not None and not closed, "Unmatched or excessive completed stock turn")
            message_text(item, assistant=True)
            closed.extend((user, *(pair.identity for pair in pairs), digest(item)))
            user, pairs = None, []
        else:
            require(user is None, "Unmatched stock user turn")
            text = message_text(item)
            require(text and text != TITLE_PROMPT, "Unexpected stock user text")
            user = digest(item)
        pos += 1
    require(user is not None, "Missing active stock user turn")
    return TurnInput(tuple(closed), user, tuple(pairs))


def classify(body):
    """Admit only the measured title and ordinary stock envelopes."""
    require(type(body) is dict and _COMMON <= body.keys()
            and body["model"] == MODEL and body["stream"] is True and body["store"] is False
            and body["include"] == ["reasoning.encrypted_content"]
            and type(body["prompt_cache_key"]) is str and _SESSION.fullmatch(body["prompt_cache_key"]),
            "Unmeasured stock envelope")
    instructions = body["instructions"]
    require(type(instructions) is str and len(instructions) <= MAX_INPUT, "Unmeasured stock instructions")
    try:
        instructions_hash = hashlib.sha256(instructions.encode("utf-8")).hexdigest()
    except UnicodeError:
        raise FixtureMismatch("Unmeasured stock instructions") from None
    items = body["input"]
    require(type(items) is list and 0 < len(items) <= 2 * MAX_BATCH * MAX_CONTINUATIONS * MAX_TURNS + 3
            and all(type(item) is dict for item in items), "Unmeasured stock input")
    if body.keys() == _COMMON and instructions_hash == _TITLE_INSTRUCTIONS:
        require(len(items) == 1 and message_text(items[0]) == TITLE_PROMPT, "Unmeasured stock title")
        return None

    require(body.keys() == _COMMON | {"tools", "max_output_tokens"}
            and instructions_hash == _CHAT_INSTRUCTIONS and type(body["max_output_tokens"]) is int
            and body["max_output_tokens"] == 16_384, "Unmeasured stock inference envelope")
    tools = body["tools"]
    require(type(tools) is list and len(tools) == len(_TOOL_DEFINITIONS)
            and all(type(tool) is dict and type(tool.get("name")) is str for tool in tools),
            "Unmeasured stock tool declarations")
    require({tool["name"]: digest(tool) for tool in tools} == _TOOL_DEFINITIONS,
            "Unmeasured stock tool declarations")
    return stock_history(items)


def upstream_body(parsed):
    """Admit only the three measured local function definitions into the synthetic send."""
    body = {**parsed.body, "max_output_tokens": MAX_OUTPUT,
            "tools": [tool for tool in parsed.body["tools"] if tool["name"] in TOOL_NAMES]}
    require(len(canonical(body)) <= MAX_INPUT, "Stock fixture input reservation exceeded")
    return body
