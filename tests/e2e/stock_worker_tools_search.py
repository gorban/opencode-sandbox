"""Fixed workspace discovery and content-search scenario for the stock loopback capture."""

import hashlib
from pathlib import Path
import stat

from stock_worker_tools_protocol import MODEL, PROVIDER, call_id, output_text, require, response_events

SEARCH_TOOLS = ("glob", "grep")
SEARCH_PROMPT = "Run the synthetic workspace search proof."
SEARCH_TITLE = "Synthetic workspace search proof"
SEARCH_REPLY = "The workspace search proof is complete."
_SEARCH_FILES = {
    "samples/discover.sample": b"header\nworker-search-fixture-marker\nfooter\n",
    "samples/control.txt": b"header\nworker-search-control\nfooter\n",
}
_MATCH_PATH = "samples/discover.sample"
_SEARCH_PATTERN = "**/*.sample"
_SEARCH_MARKER = "worker-search-fixture-marker"
SEARCH_MEASUREMENT_SHA256 = "59459dd54e589e62a34c90724c0c566b3b8c4fb984349d11df8a65a90412f97e"
SEARCH_SCHEMA_SHA256 = {
    "glob": "0618f54b418416c3002c2f0d2970f2fb981f79310a01651d3a61abefcef7cb73",
    "grep": "2c712c6442e7ab7a5a4ce87e3ebc6f8da30eb43998617b8745c7952dd4d8cc99",
}
# Canonical ASCII projections of the independently captured declarations.
_SCHEMAS = {
    'glob': (
        '{"name":"glob",'
        '"parameters":{"additionalProperties":false,'
        '"properties":{"hidden":{"description":"Include hidden files and directories (default: false).",'
        '"type":"boolean"},'
        '"limit":{"description":"Maximum number of matching files to return (default: 100)",'
        '"exclusiveMinimum":0,'
        '"type":"integer"},'
        '"path":{"description":"Directory to search. Defaults to the current working directory.",'
        '"type":"string"},'
        '"pattern":{"description":"Glob pattern to match files against",'
        '"type":"string"}},'
        '"required":["pattern"],'
        '"type":"object"},'
        '"type":"function"}'
    ),
    'grep': (
        '{"name":"grep",'
        '"parameters":{"additionalProperties":false,'
        '"properties":{"caseSensitive":{"description":"Use case-sensitive matching (default: true).",'
        '"type":"boolean"},'
        '"include":{"description":"Glob pattern to filter files (for example, \\"*.js\\" or \\"*.{ts,tsx}\\")",'
        '"type":"string"},'
        '"limit":{"description":"Maximum number of matching lines to return (default: 100)",'
        '"exclusiveMinimum":0,'
        '"type":"integer"},'
        '"literal":{"description":"Treat `pattern` as exact text instead of a regular expression (default: false).",'
        '"type":"boolean"},'
        '"path":{"description":"File or directory to search. Defaults to the current working directory.",'
        '"type":"string"},'
        '"pattern":{"description":"Regular expression or literal text to match in file contents.",'
        '"minLength":1,'
        '"type":"string"}},'
        '"required":["pattern"],'
        '"type":"object"},'
        '"type":"function"}'
    ),
}


def verify_search_tool(tool, canonical, bounded_text):
    name = tool["name"]
    fields = {"type", "name", "parameters"}
    require(fields | {"strict"} <= tool.keys() <= fields | {"strict", "description"}
            and tool["strict"] is False and bounded_text(tool.get("description", "")), "Unmeasured stock search declaration")
    projected = canonical({key: tool[key] for key in fields})
    require(projected == _SCHEMAS[name].encode("ascii")
            and hashlib.sha256(projected).hexdigest() == SEARCH_SCHEMA_SHA256[name],
            "Unmeasured stock search schema")


def inventory(workspace):
    entries = {}
    (directory,) = workspace.iterdir()
    info = directory.lstat()
    require(directory.name == "samples" and stat.S_ISDIR(info.st_mode), "Wrong stock search fixture directory")
    entries["samples"] = (info.st_mode, None)
    for item in directory.iterdir():
        info = item.lstat()
        name = item.relative_to(workspace).as_posix()
        require(stat.S_ISREG(info.st_mode) and name in _SEARCH_FILES and info.st_size <= 256,
                "Unexpected stock search fixture entry")
        entries[name] = (info.st_mode, item.read_bytes())
    return entries


class SearchScript:
    """Independent fixed search calls and exact output checks before a claim."""

    def __init__(self, workspace):
        self.workspace = Path(workspace)
        self.outputs = ()
        self.requests = []
        self.arguments = (
            {"pattern": _SEARCH_PATTERN, "path": str(workspace), "limit": 8},
            {"pattern": _SEARCH_MARKER, "path": str(workspace), "literal": True, "limit": 8},
        )

    def setup(self):
        require(not any(self.workspace.iterdir()), "Use an empty stock search workspace")
        for name, expected in _SEARCH_FILES.items():
            path = self.workspace / name
            path.parent.mkdir(mode=0o700, exist_ok=True)
            with path.open("xb") as out:
                out.write(expected)
        self.freeze_inventory(self.workspace)

    def freeze_inventory(self, read_workspace):
        self.initial_inventory = inventory(read_workspace)
        files = {name: entry[1] for name, entry in self.initial_inventory.items() if entry[1] is not None}
        require(files == _SEARCH_FILES, "Wrong stock search fixture bytes")
        matching_paths = tuple(name for name in files if Path(name).match(_SEARCH_PATTERN))
        hits = tuple((name, line, text) for name, content in files.items()
                     for line, text in enumerate(content.decode("ascii").splitlines(), 1)
                     if _SEARCH_MARKER in text)
        require(matching_paths == (_MATCH_PATH,) and len(hits) == 1 and hits[0][0] == _MATCH_PATH,
                "Stock search positive controls differ")
        match, line, content = hits[0]
        matched_path = self.workspace / match
        self.expected = (str(matched_path), f"Found 1 matches\n{matched_path}:\n  Line {line}: {content}\n")

    def verify_input(self, body):
        stage = len(self.requests)
        require(stage <= len(SEARCH_TOOLS), "Unexpected additional stock search request")
        items = body["input"]
        require(len(items) == 1 + stage * 2 and items[0].get("role") == "user"
                and output_text(items[0]["content"]) == SEARCH_PROMPT, "Wrong stock search turn")
        results = []
        for index in range(stage):
            call, result = items[1 + index * 2:3 + index * 2]
            require(call.get("type") == "function_call" and call["name"] == SEARCH_TOOLS[index]
                    and call["call_id"] == call_id(index, SEARCH_TOOLS)
                    and result["call_id"] == call["call_id"], "Wrong stock search call or result identity")
            text = output_text(result["output"])
            require(text == self.expected[index], "Wrong stock search result")
            results.append(text)
        require(tuple(results[:len(self.outputs)]) == self.outputs, "Earlier stock search results changed")
        return tuple(results)

    def respond(self, body, results):
        stage = len(self.requests)
        require(len(results) == stage, "Stock search sequence changed before dispatch")
        self.requests.append(body)
        self.outputs = results
        arguments = self.arguments[stage] if stage < len(SEARCH_TOOLS) else None
        return response_events(stage, arguments, reply=SEARCH_REPLY, tools=SEARCH_TOOLS)

    def verify_done(self, exported):
        require(inventory(self.workspace) == self.initial_inventory, "Stock search changed its workspace inventory")
        require(len(self.requests) == 3 and self.outputs == self.expected, "Stock search sequence did not complete")
        messages = exported["messages"]
        require([entry["type"] for entry in messages] == ["user", "assistant", "assistant", "assistant", "idle"]
                and exported["info"]["id"] == self.requests[0]["prompt_cache_key"],
                "Stock export does not show the exact search chat")
        user, glob, grep, answer, idle = messages
        require(user["text"] == SEARCH_PROMPT and not user["files"] and not user["agents"],
                "Unexpected stock search prompt source")
        for assistant in (glob, grep, answer):
            require(assistant["model"]["id"] == MODEL and assistant["model"]["providerID"] == PROVIDER,
                    "Stock search export used a different model or provider")
        for index, assistant in enumerate((glob, grep)):
            (part,) = assistant["content"]
            state = part["state"]
            require(part["type"] == "tool" and part["id"] == call_id(index, SEARCH_TOOLS)
                    and part["name"] == SEARCH_TOOLS[index] and part["executed"] is False
                    and state["status"] == "completed" and state["input"] == self.arguments[index]
                    and state["content"] == [{"type": "text", "text": self.expected[index]}],
                    "Stock export did not show the exact native search completion")
        (final,) = answer["content"]
        require(final["type"] == "text" and final["text"] == SEARCH_REPLY and idle["outcome"] == "succeeded"
                and exported["info"]["outcome"] == "succeeded", "Stock search export has no ordinary final reply")
