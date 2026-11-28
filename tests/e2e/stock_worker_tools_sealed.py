"""Finite native-tool scenarios for the sealed guest's synthetic TLS peer."""

from dataclasses import dataclass
from fnmatch import fnmatchcase
import json
import os
from pathlib import Path
import re

from oc_openai.connection_state import decode_json
from stock_worker_tools_history import _TOOL_DEFINITIONS, bounded_text, canonical, digest
from stock_worker_tools_interaction import (
    Interaction, SKILL_BYTES, SKILL_ID, SKILL_RELATIVE, verify_tool as verify_interaction_tool,
)
from stock_worker_tools_protocol import MODEL, PROVIDER, require, response_events
from stock_worker_tools_search import SEARCH_TOOLS, SearchScript, verify_search_tool

SEARCH_CASES = ("sealed-search", "sealed-search-denials")
# A dismissed native question can leave a durable suspended stock session.
# Keep cancellation last so the other independent cases do not launch it again.
INTERACTION_CASES = ("sealed-question", "sealed-skill", "sealed-skill-boundary", "sealed-question-cancel")
SEALED_CASES = (*SEARCH_CASES, *INTERACTION_CASES)
WORKSPACE = Path("/sandbox/construct")
SEARCH_JOB = WORKSPACE / "search-proof"
CONTROLLER_HOME = Path("/home/oc-gemini-proof")
EVIDENCE_LEAF = ".oc-stock-tools-proof"
SEARCH_BOUNDARY = CONTROLLER_HOME / EVIDENCE_LEAF / "search-boundary"
SEARCH_SENTINEL = SEARCH_BOUNDARY / "protected.sample"
SEARCH_SENTINEL_BYTES = b"controller-stock-search-sentinel\n"
PROTECTED_GREP_QUERY = "stock-search-sentinel"
TITLE_SETTINGS = {"agent": {"title": {"disable": True}}}
CONTROLLER_SKILL_ID = "controller-stock-sentinel"
CONTROLLER_SKILL = CONTROLLER_HOME / ".config/opencode/skills" / CONTROLLER_SKILL_ID / "SKILL.md"
CONTROLLER_SKILL_MARKER = b"controller-only-stock-skill-marker"
CONTROLLER_SKILL_BYTES = (
    f"---\nname: {CONTROLLER_SKILL_ID}\ndescription: Synthetic controller boundary control.\n---\n\n".encode("ascii")
    + CONTROLLER_SKILL_MARKER + b"\n"
)
WORKER_SKILL = Path("/root") / SKILL_RELATIVE
QUESTION_DISMISSED = {"type": "aborted", "message": "The user dismissed this question"}
SENTINEL_LOOKUP_ERROR = {"type": "tool.execution", "message": f"Unable to load skill {CONTROLLER_SKILL_ID}"}


def interaction_config(case):
    permitted = [SKILL_ID] if case != "sealed-skill-boundary" else [SKILL_ID, CONTROLLER_SKILL_ID]
    return {**TITLE_SETTINGS, "permission": {"skill": {"*": "deny", **dict.fromkeys(permitted, "allow")}}}


def allowed_markers(value):
    payload = canonical(value)
    return all(marker not in payload for marker in (SEARCH_SENTINEL_BYTES.strip(), CONTROLLER_SKILL_MARKER))

_MAX_JOURNAL = 8192
_SESSION = re.compile(r"ses_[a-zA-Z0-9]{1,64}\Z")
_ENVELOPE = {"model", "input", "instructions", "tools", "stream", "store", "prompt_cache_key", "include"}

# OpenCode Full v2.3.0, measured with SHELL absent at process exec and Bash
# available on its PATH. The production broker sanitizer preserves this
# complete declaration. The separate loopback lane uses its existing sh pin.
MANAGED_SHELL_SHA256 = "d3c4513ca047dc316e37dbfc5143e86485ff77669c58befe27041e512dafb16b"
SHELL_SCHEMA_SHA256 = "363b3b4f6db39d64ab18f700273ab32086fd28b67c6053f30e082dd140ce0ba6"
SHELL_SCHEMA_KEYS = frozenset({"type", "name", "parameters"})



def setup_search(job):
    SearchScript(job).setup()


def search_lookup_error():
    return {"type": "tool.execution", "message": f"Search path does not exist: {SEARCH_BOUNDARY}"}


@dataclass(frozen=True)
class Scenario:
    case: str
    prompt: str
    reply: str
    tools: tuple
    arguments: tuple
    outputs: tuple

    @property
    def question(self):
        return self.tools == ("question",)

    @property
    def cancellation(self):
        return self.case == "sealed-question-cancel"

    @property
    def missing_skill(self):
        return self.case == "sealed-skill-boundary"

    def identity(self, run, index):
        return f"call_sealed_{self.tools[index]}_{run}"

    def steps(self, body, run, rows):
        """Verify the broker-sanitized request and every already delivered result."""
        require(type(body) is dict and body.keys() == _ENVELOPE and body["model"] == MODEL
                and body["stream"] is True and body["store"] is False
                and body["include"] == ["reasoning.encrypted_content"]
                and type(body["prompt_cache_key"]) is str and _SESSION.fullmatch(body["prompt_cache_key"])
                and type(body["instructions"]) is str and len(body["instructions"].encode("utf-8")) <= 32_768,
                "Unmeasured sealed stock request")
        tools = body["tools"]
        require(type(tools) is list and len(tools) == len(_TOOL_DEFINITIONS)
                and all(type(tool) is dict and type(tool.get("name")) is str for tool in tools)
                and {tool["name"] for tool in tools} == _TOOL_DEFINITIONS.keys(), "Unmeasured sealed stock declarations")
        for tool in tools:
            if tool["name"] in SEARCH_TOOLS:
                verify_search_tool(tool, canonical, bounded_text)
            elif tool["name"] == "shell":
                require(tool.keys() == SHELL_SCHEMA_KEYS | {"strict", "description"}
                        and digest({key: tool[key] for key in SHELL_SCHEMA_KEYS}) == SHELL_SCHEMA_SHA256
                        and digest(tool) == MANAGED_SHELL_SHA256, "Unmeasured sealed stock Bash declaration")
            else:
                if tool["name"] in {"question", "skill"}:
                    verify_interaction_tool(tool, canonical, bounded_text)
                require(digest(tool) == _TOOL_DEFINITIONS[tool["name"]], "Unmeasured sealed stock declaration")
        require(allowed_markers(body), "Unexpected protected synthetic marker")
        claims, submissions = verified_rows(rows)
        stage = len(claims)
        require(not any(row["op"] == "refused" for row in rows), "Repeated denied skill request")
        if self.question and stage > 0:
            require(not self.cancellation and any(row == self.operator(run, body["prompt_cache_key"]) for row in rows),
                    "Sealed question has no exact terminal answer")
        items = body["input"]
        require(stage == len(submissions) <= len(self.tools) and type(items) is list and len(items) == 1 + stage * 2
                and items[0] == {"type": "message", "role": "user", "content": [{"type": "input_text", "text": self.prompt}]},
                "Unmeasured sealed stock chat stage")
        session = body["prompt_cache_key"]
        require(not claims or all(row["session"] == session for row in claims), "Sealed stock session changed")
        for index in range(stage):
            call, result = items[1 + index * 2:3 + index * 2]
            identity = self.identity(run, index)
            require(type(call) is dict and call.keys() == {"type", "name", "call_id", "arguments"}
                    and call["type"] == "function_call" and call["name"] == self.tools[index]
                    and call["call_id"] == identity and bounded_text(call["arguments"])
                    and decode_json(call["arguments"]) == self.arguments[index], "Unmeasured sealed stock call")
            require(result == {"type": "function_call_output", "call_id": identity, "output": self.outputs[index]},
                    "Unmeasured sealed native result")
            if index + 1 < stage:
                require(digest(items[:3 + index * 2]) == claims[index + 1]["prefix"],
                        "Previously delivered sealed result changed")
        return stage

    def operator(self, run, session):
        require(self.question, "No operator input is expected for this case")
        return {"op": "operator", "session": session, "call": self.identity(run, 0),
                "key": "Escape" if self.cancellation else "Enter"}

    def response(self, run, stage):
        if stage == len(self.tools):
            return response_events(stage, reply=self.reply)
        return response_events(stage, self.arguments[stage], tools=self.tools, call_identity=self.identity(run, stage))

    def verify_export(self, exported, run, session):
        messages = exported["messages"]
        expected = ["user", "assistant"] if self.cancellation else [
            "user", *(["assistant"] * (len(self.tools) + 1)), "idle",
        ]
        require([entry["type"] for entry in messages] == expected and exported["info"]["id"] == session
                and messages[0]["text"] == self.prompt and not messages[0]["files"] and not messages[0]["agents"]
                and allowed_markers(exported), "Unexpected sealed stock export")
        if self.cancellation or self.missing_skill:
            return self.verify_interaction_failure(exported, run)
        for index, assistant in enumerate(messages[1:-1]):
            model = assistant["model"]
            require((model["id"], model["providerID"]) == (MODEL, PROVIDER), "Wrong sealed stock export route")
            (part,) = assistant["content"]
            if index == len(self.tools):
                require(part["type"] == "text" and part["text"] == self.reply, "Wrong sealed stock final text")
                continue
            state = part["state"]
            require(part["type"] == "tool" and part["name"] == self.tools[index]
                    and part["id"] == self.identity(run, index) and part["executed"] is False
                    and state["input"] == self.arguments[index], "Wrong sealed native call binding")
            if self.case == "sealed-search-denials":
                require(state["status"] == "error" and state["error"] == search_lookup_error(),
                        "Sealed native search lookup did not explicitly refuse")
            else:
                require(state["status"] == "completed" and state["content"] == [{"type": "text", "text": self.outputs[index]}],
                        "Wrong sealed native tool result")
                if self.case == "sealed-skill":
                    require(state["metadata"] == {"name": SKILL_ID, "directory": str(WORKER_SKILL.parent),
                                                   "truncated": False}
                            and state["metadata"]["truncated"] is False, "Wrong sealed skill metadata")
        require(exported["info"]["outcome"] == messages[-1]["outcome"] == "succeeded",
                "Unqualified sealed stock terminal result")

    def verify_interaction_failure(self, exported, run):
        assistant = exported["messages"][1]
        model = assistant["model"]
        (part,) = assistant["content"]
        state = part["state"]
        require((model["id"], model["providerID"]) == (MODEL, PROVIDER) and part["type"] == "tool"
                and part["name"] == self.tools[0] and part["id"] == self.identity(run, 0)
                and part["executed"] is False and state["input"] == self.arguments[0] and state["status"] == "error",
                "Wrong sealed native failure identity")
        if self.cancellation:
            require(state["error"] == QUESTION_DISMISSED and assistant["finish"] == "error"
                    and assistant["error"]["type"] == "aborted", "Stock question was not natively interrupted")
        else:
            _, _, provider, idle = exported["messages"]
            require(state["error"] == SENTINEL_LOOKUP_ERROR and not provider["content"]
                    and provider["error"]["type"] == "provider.auth"
                    and exported["info"]["outcome"] == idle["outcome"] == "failed",
                    "Controller skill lookup lacked the exact native denial")


def protected_search_arguments(arguments):
    glob, grep = arguments
    return (
        {**glob, "path": str(SEARCH_BOUNDARY), "pattern": SEARCH_SENTINEL.name},
        {**grep, "path": str(SEARCH_BOUNDARY), "pattern": PROTECTED_GREP_QUERY, "literal": True},
    )


def verify_search_control_match(filename, data):
    # Confirm the protected request would succeed against the known control
    # without putting the full withheld marker into either tool's arguments.
    glob, grep = protected_search_arguments(({}, {}))
    marker = data.rstrip(b"\n")
    query = grep["pattern"].encode("ascii")
    require(marker and fnmatchcase(filename, glob["pattern"]) and query in marker and query != marker
            and marker not in canonical([glob, grep]), "Protected queries do not match the known-present control")


def scenario(case, home):
    require(case in SEALED_CASES, "Unexpected sealed stock scenario")
    if case in INTERACTION_CASES:
        return interaction_scenario(case)
    job = Path(home) / "opencode-sandbox/construct/search-proof"
    script = SearchScript(SEARCH_JOB)
    script.freeze_inventory(job)
    if case == "sealed-search":
        return Scenario(case, "Find and inspect the synthetic job sample.", "The job search proof is complete.",
                        SEARCH_TOOLS, script.arguments, script.expected)
    denied = protected_search_arguments(script.arguments)
    error = json.dumps({"error": search_lookup_error(), "content": []}, separators=(",", ":"))
    return Scenario(case, "Check the isolated synthetic search control.", "The protected search control stayed outside.",
                    SEARCH_TOOLS, denied, (error, error))


def interaction_scenario(case):
    question = case.startswith("sealed-question")
    measured = Interaction("question" if question else "skill", "0" * 32, WORKSPACE)
    measured.source = WORKER_SKILL
    identity = {"id": CONTROLLER_SKILL_ID} if case == "sealed-skill-boundary" else measured.arguments
    output = measured.expected_result()
    if case == "sealed-skill-boundary":
        output = json.dumps({"error": SENTINEL_LOOKUP_ERROR, "content": []}, separators=(",", ":"))
    return Scenario(case, "Run the synthetic worker interaction proof.", "The worker interaction proof is complete.",
                    (measured.tool,), (identity,), (output,))


def journal_path(home, case):
    require(case in SEALED_CASES, "Unexpected sealed stock journal")
    return Path(home) / EVIDENCE_LEAF / f"{case}.jsonl"


def read_journal(stream, case):
    stream.seek(0)
    raw = stream.read(_MAX_JOURNAL + 1)
    require(0 < len(raw) <= _MAX_JOURNAL and raw.endswith(b"\n"), "Incomplete sealed stock journal")
    header, *rows = (decode_json(line) for line in raw.splitlines())
    require(type(header) is dict and header.keys() == {"case", "run"} and header["case"] == case
            and type(header["run"]) is str and re.fullmatch(r"[a-f0-9]{32}", header["run"]),
            "Sealed stock journal case changed")
    return header["run"], rows


def append_row(stream, path, row):
    identity = os.fstat(stream.fileno())
    require(os.path.samestat(identity, path.lstat()), "Sealed stock journal path changed")
    payload = canonical(row) + b"\n"
    require(identity.st_size + len(payload) <= _MAX_JOURNAL, "Sealed stock journal exceeded its bound")
    stream.seek(0, os.SEEK_END)
    require(stream.write(payload) == len(payload), "Short sealed stock journal write")
    os.fsync(stream.fileno())
    require(os.path.samestat(identity, path.lstat()), "Sealed stock journal path changed")


def verified_rows(rows):
    claims, submissions = [], []
    for row in rows:
        if row["op"] == "claim":
            require(len(claims) == len(submissions) and row["stage"] == len(claims), "Repeated sealed stock claim")
            claims.append(row)
        elif row["op"] == "operator":
            require(row.keys() == {"op", "session", "call", "key"} and len(claims) == len(submissions) == 1
                    and row["session"] == claims[0]["session"] and row["key"] in {"Escape", "Enter"}
                    and rows.index(row) == 2 and rows.count(row) == 1, "Unexpected sealed operator receipt")
        elif row["op"] == "refused":
            require(row.keys() == {"op", "session", "prefix"} and len(claims) == len(submissions) == 1
                    and row["session"] == claims[0]["session"] and rows.index(row) == 2 and rows.count(row) == 1,
                    "Unexpected sealed refusal receipt")
        else:
            require(row.keys() == {"op", "stage", "claim", "shutdown"} and row["op"] == "submitted"
                    and len(claims) == len(submissions) + 1 and row["stage"] == len(submissions)
                    and row["claim"] == digest(claims[-1]) and row["shutdown"] in {"mutual", "peer_eof"},
                    "Unmatched sealed stock peer submission")
            submissions.append(row)
    return claims, submissions


def usage_sequence_complete(rows, count, *, refused=False):
    expected = [("completed", 2, 3)] * count
    if refused:
        expected.append(("chatgpt_auth_rejected", None, None))
    require(len(rows) <= len(expected), "Unexpected extra sealed broker usage row")
    require(all(type(row) is dict and row.get("profile") == "harbor" and row.get("model") == MODEL
                and {"outcome", "input_tokens", "output_tokens"} <= row.keys()
                and type(row["input_tokens"]) is type(outcome[1])
                and type(row["output_tokens"]) is type(outcome[2])
                and (row["outcome"], row["input_tokens"], row["output_tokens"]) == outcome
                for row, outcome in zip(rows, expected)), "Broker usage did not match sealed fake-peer sends")
    return len(rows) == len(expected)


def verify_usage(rows, count, *, refused=False):
    require(usage_sequence_complete(rows, count, refused=refused), "Broker usage did not match sealed fake-peer sends")
