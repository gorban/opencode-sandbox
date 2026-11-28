"""Pinned stock terminal interaction with inert synthetic job data."""

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import stat

from stock_worker_tools_protocol import MODEL, PROVIDER, require, response_events

MEASUREMENT_SHA256 = "18b4f54bb42d256441b2681b894800ceedd8e3bdb8991f732b7cb60ca9da5709"
SCHEMA_SHA256 = {
    "question": "53a4878b7d8d0fbd22c2173f3fd28ee29267e30b0b33fbb7a83718f175c2debc",
    "skill": "cbd54fa647be584c66d3193a4dd22e779201c0e92345cf549ab5b354b19d7a7b",
}
# Canonical ASCII projections from the independent stock capture.
_SCHEMAS = {
    "question": (
        '{"name":"question","parameters":{"additionalProperties":false,"properties":{"questions":{"description":"'
        'Questions to ask","items":{"additionalProperties":false,"properties":{"header":{"description":"Very '
        'short label (max 30 '
        'chars)","type":"string"},"multiple":{"type":"boolean"},"options":{"description":"Available '
        'choices","items":{"additionalProperties":false,"properties":{"description":{"description":"Explanation '
        'of choice","type":"string"},"label":{"description":"Display text (1-5 words, concise)","type":"string"}}'
        ',"required":["label","description"],"type":"object"},"type":"array"},"question":{"description":"Complete'
        ' question","type":"string"}},"required":["question","header","options"],"type":"object"},"minItems":1,"t'
        'ype":"array"}},"required":["questions"],"type":"object"},"type":"function"}'
    ),
    "skill": (
        '{"name":"skill","parameters":{"additionalProperties":false,"properties":{"id":{"description":"The ID of '
        'an available skill or a skill explicitly referenced by the '
        'user","type":"string"}},"required":["id"],"type":"object"},"type":"function"}'
    ),
}

CASES = frozenset({"question", "question-cancel", "skill", "skill-unavailable", "skill-undeclared"})
PROMPT = "Run the synthetic terminal interaction proof."
TITLE = "Synthetic terminal interaction proof"
REPLY = "The terminal interaction proof is complete."
QUESTION = "Which fixture color should be recorded?"
QUESTION_OPTIONS = ("Blue sample", "Green sample")
_MEASURED_SKILL_CHAT = "b82ae38653d9c1e093437f1e0401f6fd494a36a1e4db84bdfa69d9e1a6406a7c"
_MEASURED_NO_SKILL_CHAT = "464cf8b608a255c9eecf989646d2cb04a50c8fc0d34f942fad6178ebebe36949"
_MEASURED_DATE = "Sat Nov 28 2026"
SKILL_ID = "fixture-neutral-note"
UNAVAILABLE_ID = "fixture-unavailable-note"
SKILL_RELATIVE = Path(".config/opencode/skills") / SKILL_ID / "SKILL.md"
SKILL_MARKER = "worker-skill-fixture-marker"
SKILL_BODY = f"# Fixture note\n\n{SKILL_MARKER}\n"
SKILL_BYTES = (f"---\nname: {SKILL_ID}\ndescription: A synthetic neutral fixture note.\n---\n\n"
               f"{SKILL_BODY}").encode("ascii")

_QUESTION_ARGUMENTS = {"questions": [{"question": QUESTION, "header": "Fixture color", "options": [
    {"label": QUESTION_OPTIONS[0], "description": "Use the blue fixture color."},
    {"label": QUESTION_OPTIONS[1], "description": "Use the green fixture color."},
]}]}


def verify_tool(tool, canonical, bounded_text):
    name = tool["name"]
    fields = {"type", "name", "parameters"}
    require(tool.keys() == fields | {"strict", "description"} and tool["strict"] is False
            and bounded_text(tool["description"]), "Unmeasured stock interaction declaration")
    projected = canonical({key: tool[key] for key in fields})
    require(projected == _SCHEMAS[name].encode("ascii")
            and hashlib.sha256(projected).hexdigest() == SCHEMA_SHA256[name],
            "Unmeasured stock interaction schema")


class Interaction:
    def __init__(self, case, generation, workspace):
        require(case in CASES and re.fullmatch("[a-f0-9]{32}", generation), "Invalid stock interaction scenario")
        self.case = case
        self.tool = case.split("-")[0]
        self.call_id = f"call_worker_proof_{self.tool}_{generation}"
        self.workspace = workspace
        if self.tool == "question":
            self.arguments = deepcopy(_QUESTION_ARGUMENTS)
        else:
            self.arguments = {"id": UNAVAILABLE_ID if case == "skill-unavailable" else SKILL_ID}
        self.day = datetime.now(timezone.utc).strftime("%a %b %d %Y")
        self.selected = False
        self.issued = False
        self.continued = False
        self.session = None
        self.result = None

    def configure(self, config):
        config["mcp"] = {}
        permitted = UNAVAILABLE_ID if self.case == "skill-unavailable" else SKILL_ID
        config["permission"] = {"skill": {"*": "deny", permitted: "allow"}}

    def verify_instructions(self, instructions):
        # Keep the measured envelope, substituting only the pinned fixture's UTC day.
        footer = f"Today's date: {self.day}"
        require(instructions.count(footer) == 1, "Unmeasured stock interaction date")
        normalized = instructions.replace(footer, f"Today's date: {_MEASURED_DATE}")
        expected = _MEASURED_SKILL_CHAT if self.case in {"skill", "skill-undeclared"} else _MEASURED_NO_SKILL_CHAT
        require(hashlib.sha256(normalized.encode("utf-8")).hexdigest() == expected,
                "Unmeasured stock interaction instructions")

    def setup(self, home):
        self.source = home / SKILL_RELATIVE
        if self.case in {"skill", "skill-undeclared"}:
            self.source.parent.mkdir(mode=0o700, parents=True)
            with self.source.open("xb") as skill:
                skill.write(SKILL_BYTES)
        self.verify_inventory()

    def verify_inventory(self):
        require(not any(self.workspace.iterdir()), "Unexpected stock interaction workspace content")
        root = self.source.parent.parent
        if self.case in {"skill", "skill-undeclared"}:
            require(stat.S_ISDIR(root.lstat().st_mode) and list(root.iterdir()) == [self.source.parent]
                    and stat.S_ISDIR(self.source.parent.lstat().st_mode)
                    and list(self.source.parent.iterdir()) == [self.source]
                    and stat.S_ISREG(self.source.lstat().st_mode)
                    and self.source.stat().st_size == len(SKILL_BYTES) and self.source.read_bytes() == SKILL_BYTES,
                    "Stock interaction skill source or inventory changed")
        else:
            require(not root.exists() and not root.is_symlink(), "Unexpected stock interaction skill source")

    def verify_call(self, name, args):
        require(name == self.tool and args == self.arguments
                and (self.tool != "question" or type(args["questions"]) is list),
                "Unexpected stock interaction tool or arguments")

    def verify_input(self, body, history):
        self.verify_inventory()
        require(not history.closed and body["input"][0]["content"] == [{"type": "input_text", "text": PROMPT}],
                "Wrong stock interaction turn")
        if not self.issued:
            require(not history.pairs, "Unissued stock interaction result")
            return None
        self.verify_binding(body, history)
        require(self.case in {"question", "skill"}, "This stock interaction cannot continue")
        require(self.tool != "question" or self.selected, "Stock question was unanswered")
        result = body["input"][2]["output"]
        expected = self.expected_result()
        require(result == expected, "Incorrect stock interaction result")
        return result

    def verify_binding(self, body, history):
        require(self.issued and not self.continued and not history.closed and body["prompt_cache_key"] == self.session
                and len(history.pairs) == 1 and history.pairs[0].call.call_id == self.call_id,
                "No matching stock interaction is awaiting continuation")

    def refusal(self):
        return {"type": "tool.execution", "message": f"Unable to load skill {UNAVAILABLE_ID}"}

    def verify_unavailable(self, body, history):
        self.verify_inventory()
        self.verify_binding(body, history)
        require(body["input"][2]["output"] == json.dumps({"error": self.refusal(), "content": []},
                                                          separators=(",", ":")),
                "Incorrect native skill denial")

    def respond(self, body, result):
        if self.issued:
            self.result = result
            self.continued = True
            return response_events(1, reply=REPLY)
        self.issued = True
        self.session = body["prompt_cache_key"]
        name = self.tool if self.case != "skill-undeclared" else "synthetic_undeclared_skill"
        return response_events(0, self.arguments, tools=(name,), call_identity=self.call_id)

    def expected_result(self):
        if self.tool == "question":
            return f'User has answered your questions: "{QUESTION}"="{QUESTION_OPTIONS[0]}". You can now continue with the user\'s answers in mind.'
        return (f'<skill_content name="{SKILL_ID}">\n# Skill: {SKILL_ID}\n\n{SKILL_BODY}\n'
                f'Base directory for this skill: {self.source.parent}\n'
                'Relative paths in this skill (e.g., scripts/, reference/) are relative to this base directory.\n'
                'Note: file list is sampled.\n\n<skill_files>\n</skill_files>\n</skill_content>')

    def verify_export_identity(self, exported):
        info = exported["info"]
        user = exported["messages"][0]
        require(info["id"] == self.session and user["type"] == "user" and user["text"] == PROMPT
                and not user["files"] and not user["agents"]
                and info["model"]["id"] == MODEL and info["model"]["providerID"] == PROVIDER,
                "Stock interaction export is for another chat, provider or model")
        assistants = [msg for msg in exported["messages"] if msg["type"] == "assistant"]
        require(all(msg["model"]["id"] == MODEL and msg["model"]["providerID"] == PROVIDER for msg in assistants),
                "Stock interaction export is for another provider or model")
        return assistants

    def verify_skill_metadata(self, metadata):
        # Export metadata is independent of the tool result projected upstream.
        require(type(metadata) is dict and metadata == {
            "name": SKILL_ID, "directory": str(self.source.parent), "truncated": False,
        } and metadata["truncated"] is False, "Stock skill export metadata differs")
        return {"name": SKILL_ID, "source": SKILL_RELATIVE.as_posix(), "truncated": False,
                "source_sha256": hashlib.sha256(SKILL_BYTES).hexdigest()}

    def verify_export_tool(self, part):
        require(part.get("type") == "tool" and part.get("id") == self.call_id and part.get("name") == self.tool
                and part.get("executed") is False and part.get("native") == {"itemId": "fc_local_1"}
                and part["state"]["input"] == self.arguments,
                "Unexpected stock interaction export tool binding")
        return part["state"]
