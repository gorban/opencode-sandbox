"""Synthetic Responses peer script shared by stock capture and public-launch proof."""

import json
from pathlib import PurePosixPath

MODEL = "gpt-6.2-sol"
LABEL = "harbor"
PROVIDER = "openai--harbor"
PROMPT = "Run the synthetic workspace tool proof."
REPLY = "The workspace tool proof is complete."
FILE_NAME = "proof.txt"
REFUSED_FILE = "refused-proof.txt"
FILE_TEXT = "worker-proof-workspace-marker\n"
SHELL_TEXT = "worker-proof-shell-marker"
TOOL_NAMES = ("patch", "read", "shell")
TITLE_PROMPT = f"Here is the first message of the conversation:\n\n<message>\n{PROMPT}\n</message>\n\nReply with only the title."
TITLE = "Synthetic workspace tool proof"


class FixtureMismatch(RuntimeError):
    """Stock traffic differed from the synthetic fixture contract."""


def require(condition, message):
    if not condition:
        raise FixtureMismatch(message)


def call_id(stage, tools=TOOL_NAMES):
    return f"call_worker_proof_{tools[stage]}"


def fixed_command():
    return f"printf '%s\\n' '{SHELL_TEXT}'; cat -- {FILE_NAME}"


def function_arguments(body, tool, workspace):
    definitions = [entry for entry in body.get("tools", ()) if entry.get("name") == tool]
    require(len(definitions) == 1, f"Missing or duplicate stock {tool} declaration")
    definition = definitions[0]
    require(definition.get("type") == "function", f"Stock {tool} was not a local function")
    schema = definition.get("parameters", {})
    properties = schema.get("properties", {})
    required = schema.get("required", [])
    path = str(PurePosixPath(workspace) / FILE_NAME)
    if tool == "patch":
        arguments = {"patchText": f"*** Begin Patch\n*** Add File: {FILE_NAME}\n+{FILE_TEXT}*** End Patch\n"}
    elif tool == "read":
        arguments = {"path": path}
    else:
        arguments = {"command": fixed_command(), "timeout": 5000, "workdir": workspace}
    require(set(required) <= arguments.keys() <= properties.keys(), f"Unexpected stock {tool} arguments")
    return arguments


def output_text(value):
    if type(value) is str:
        return value
    require(type(value) is list and bool(value), "Stock tool result was not text")
    require(all(type(part) is dict and part.get("type") in {"input_text", "output_text"}
                and type(part.get("text")) is str for part in value), "Non-text stock tool result")
    return "".join(part["text"] for part in value)


def expected_result(stage, workspace):
    return (
        f"Success. Updated the following files:\nA {FILE_NAME}",
        f"Read file {workspace}/{FILE_NAME}, lines 1-1\n1: {FILE_TEXT.rstrip()}",
        f"{SHELL_TEXT}\n{FILE_TEXT}",
    )[stage]


def check_result(stage, value, workspace):
    result = output_text(value)
    require(result == expected_result(stage, workspace), f"Stock {TOOL_NAMES[stage]} result differed")
    return result


def validate_export(exported, script):
    messages = exported["messages"]
    require([entry["type"] for entry in messages] == ["user", *["assistant"] * 4, "idle"],
            "Stock export does not show the exact active chat")
    user, *assistants, idle = messages
    require(user["text"] == PROMPT and not user["files"] and not user["agents"], "Unexpected stock prompt source")
    for assistant in assistants:
        require(assistant["model"]["id"] == MODEL and assistant["model"]["providerID"] == PROVIDER,
                "Stock export attributed a message to a different model or provider")
    for stage, assistant in enumerate(assistants[:-1]):
        (part,) = assistant["content"]
        require(part.get("type") == "tool" and part.get("id") == call_id(stage)
                and part.get("name") == TOOL_NAMES[stage] and part.get("executed") is False,
                "Stock export did not attribute the issued tool to worker execution")
        state = part["state"]
        (content,) = state["content"]
        require(state["status"] == "completed" and state["input"] == script.arguments[stage]
                and content == {"type": "text", "text": script.outputs[stage]},
                "Stock native tool state did not match the accepted continuation")
        if stage == 2:
            require(state["metadata"]["exit"] == 0, "Stock shell did not exit successfully")
    (final,) = assistants[-1]["content"]
    require(final["type"] == "text" and final["text"] == REPLY and idle["outcome"] == "succeeded"
            and exported["info"]["outcome"] == "succeeded", "Stock export did not complete the tool turn")


def validate_refused_export(exported):
    messages = exported["messages"]
    require(messages and messages[0]["type"] == "user" and messages[0]["text"] == PROMPT
            and messages[-1]["type"] == "idle" and messages[-1]["outcome"] == "failed"
            and exported["info"]["outcome"] == "failed", "The actual stock chat did not reach a failed idle outcome")
    require(not any(part.get("type") == "tool" for item in messages for part in item.get("content", ())),
            "Stock recorded native tool execution for an invalid upstream stream")


def response_events(stage, arguments=None, *, reply=REPLY, tools=TOOL_NAMES, call_identity=None):
    response = {"id": f"resp_worker_proof_{stage}", "object": "response", "created_at": 1,
                "model": MODEL, "status": "in_progress", "output": []}
    yield {"type": "response.created", "response": response}
    yield {"type": "response.metadata", "response_id": response["id"], "sequence_number": 1,
           "metadata": {"openai_chatgpt_moderation_metadata": {"prompt": {"outputs": [{"is_blocked": False}]}}}}
    if arguments is not None:
        item = {"id": f"fc_worker_proof_{stage}", "type": "function_call", "name": tools[stage],
                "call_id": call_identity or call_id(stage, tools), "arguments": json.dumps(arguments, separators=(",", ":")),
                "status": "completed"}
        yield {"type": "response.output_item.added", "output_index": 0,
               "item": {**item, "arguments": "", "status": "in_progress"}}
        identity = {"item_id": item["id"], "output_index": 0}
        yield {"type": "response.function_call_arguments.delta", **identity, "delta": item["arguments"]}
        yield {"type": "response.function_call_arguments.done", **identity, "arguments": item["arguments"]}
    else:
        part = {"type": "output_text", "text": "", "annotations": []}
        item = {"id": f"msg_worker_proof_{stage}", "type": "message", "role": "assistant", "status": "completed",
                "content": [{**part, "text": reply}]}
        identity = {"item_id": item["id"], "output_index": 0, "content_index": 0}
        yield {"type": "response.output_item.added", "output_index": 0,
               "item": {**item, "status": "in_progress", "content": []}}
        yield {"type": "response.content_part.added", **identity, "part": part}
        yield {"type": "response.output_text.delta", **identity, "delta": reply}
        yield {"type": "response.output_text.done", **identity, "text": reply}
        yield {"type": "response.content_part.done", **identity, "part": item["content"][0]}
    yield {"type": "response.output_item.done", "output_index": 0, "item": item}
    yield {"type": "response.completed", "response": {**response, "status": "completed", "output": [item],
           "usage": {"input_tokens": 2, "output_tokens": 3, "total_tokens": 5}}}


def refused_events(case, body, workspace):
    arguments = function_arguments(body, "patch", workspace)
    arguments["patchText"] = arguments["patchText"].replace(FILE_NAME, REFUSED_FILE, 1)
    events = list(response_events(0, arguments))
    if case == "hosted":
        # The preceding declaration, identity and complete arguments are all
        # valid. The hosted event must invalidate the buffered worker call.
        rejected = {"type": "response.web_search_call.completed", "response_id": events[0]["response"]["id"]}
        return (*events[:-1], rejected)
    require(case == "undeclared", "Unexpected upstream refusal case")
    for event in events:
        item = event.get("item")
        if item is not None:
            item["name"] = "synthetic_undeclared"
        for output in event.get("response", {}).get("output", ()):
            output["name"] = "synthetic_undeclared"
    return events


def encode_sse(events):
    return b"".join(b"data: " + json.dumps(event).encode("ascii") + b"\n\n" for event in events)


class ToolScript:
    """Require exact, ordered continuations from one active stock conversation."""

    def __init__(self, workspace):
        self.workspace = workspace
        self.arguments = []
        self.outputs = []
        self.requests = []
        self.title_requests = 0

    def respond(self, body):
        stage = len(self.requests)
        require(body.get("model") == MODEL and body.get("stream") is True and body.get("store") is False,
                "Wrong stock model, streaming mode or retention mode")
        tools = body.get("tools")
        items = body.get("input")
        require(type(items) is list and bool(items), "Missing stock input array")
        user = [item for item in items if item.get("role") == "user"]
        require(len(user) == 1, "Unexpected stock user prompt count")
        prompt = output_text(user[0].get("content"))
        if prompt == TITLE_PROMPT:
            require(len(items) == 1 and not tools and self.title_requests == 0, "Unexpected title side request")
            self.title_requests += 1
            return tuple(response_events("title", reply=TITLE))
        require(prompt == PROMPT and stage <= len(TOOL_NAMES), "Unexpected stock inference request")
        require(type(tools) is list and bool(tools)
                and all(type(tool) is dict and tool.get("type") == "function" for tool in tools),
                "Fixture observed a provider-native tool declaration")
        tool_items = [item for item in items if item.get("type") in {"function_call", "function_call_output"}]
        require(len(tool_items) == stage * 2, "Unexpected number of stock input tool history items")
        results = []
        for index in range(stage):
            call, output = tool_items[index * 2:index * 2 + 2]
            require(call.get("type") == "function_call" and call.get("call_id") == call_id(index)
                    and call.get("name") == TOOL_NAMES[index] and json.loads(call["arguments"]) == self.arguments[index],
                    "Stock input did not carry the issued tool identity and arguments")
            require(output.get("type") == "function_call_output" and output.get("call_id") == call_id(index),
                    "Stock input did not carry the matching tool result")
            results.append(check_result(index, output.get("output"), self.workspace))
        require(results[:len(self.outputs)] == self.outputs, "Earlier stock results changed during continuation")
        arguments = function_arguments(body, TOOL_NAMES[stage], self.workspace) if stage < len(TOOL_NAMES) else None
        if arguments is not None:
            self.arguments.append(arguments)
        self.outputs = results
        self.requests.append(body)
        return tuple(response_events(stage, arguments))

    def verify_done(self):
        require(len(self.requests) == 4 and len(self.outputs) == 3 and self.title_requests == 1,
                "Stock tool sequence or title request did not complete")
