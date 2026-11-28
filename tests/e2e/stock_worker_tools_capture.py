"""Capture and validate an actual stock OpenCode write, read and shell turn offline."""

import argparse
from contextlib import contextmanager
from copy import deepcopy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
from threading import Lock, Thread
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from oc_openai.connection_state import decode_json
from oc_openai.session_adapter import OpenAISessionAdapter
from oc_openai.session_protocol import ReasoningVault, StreamAborted, encode_chunk, parse_worker_request
from oc_providers.catalog import ResolvedLaunchPlan, build_multi_provider_opencode_config
from oc_providers.contracts import InstancePreflight, ProviderInstanceSpec, ReadinessState
from stock_worker_tools_history import MAX_OUTPUT, MAX_WIRE, classify, upstream_body
from stock_worker_tools_protocol import (
    FILE_NAME, FILE_TEXT, LABEL, MODEL, PROMPT, PROVIDER, REPLY, REFUSED_FILE, TITLE, TOOL_NAMES,
    FixtureMismatch, ToolScript, refused_events, require, response_events, validate_export,
    validate_refused_export,
)
from stock_worker_tools_stream import project_stream, scripted_response, terminal_output
from stock_worker_tools_turns import HANDOFF_END, Authority, FixtureTurns

STOCK_SHA256 = "9e0cb0e096666f955c3f72d1b517fd2cb5cca65c2876e1012492d955fc974a7b"
MUSL_LOADER_SHA256 = "095b047c631447e4fa50401fa7ffce01f678587040d65ba18c574981dc630de5"
MUSL_PINS = {
    "libstdc++.so.6": "67a940194aec6c44c3eb47a98e44c53d248e4dac5f4eb57c0971c0d6286eafe5",
    "libgcc_s.so.1": "5ea51dd885b6fc691eccc569d0bda739204204f6161e97075b26dc9c050d1ca1",
}
PORT = 8401
FIXTURE_BEARER = "stock-tools-synthetic-only"
WORKSPACE = Path("/sandbox/construct")
AUTHORITY = Authority("synthetic-job", "harbor", "capture-generation", "/v1/responses", MODEL)
JOB_ENV = {
    "PATH": "/usr/bin:/bin",
    "TERM": "xterm-256color",
    "LANG": "C.UTF-8",
    "OPENCODE_CONFIG_PROJECT_DISABLE": "true",
    "OPENCODE_DISABLE_MODELS_FETCH": "true",
    "OPENCODE_DISABLE_FREE_MODELS": "true",
    "OPENCODE_DISABLE_AUTOUPDATE": "true",
    "OPENCODE_DISABLE_CLAUDE_CODE": "true",
}


def verify_digest(path, digest):
    with path.open("rb") as stream:
        require(hashlib.file_digest(stream, "sha256").hexdigest() == digest, f"Invalid pin for {path.name}")


@contextmanager
def measured_command(binary, libraries):
    binary = binary.resolve(strict=True)
    verify_digest(binary, STOCK_SHA256)
    loader = Path("/lib/ld-musl-x86_64.so.1")
    verify_digest(loader, MUSL_LOADER_SHA256)
    alias = loader.with_name("libc.musl-x86_64.so.1")
    require(alias.resolve(strict=True) == loader.resolve(strict=True), "Incorrect stock musl loader alias")
    with tempfile.TemporaryDirectory(prefix="oc-tools-musl-") as scratch:
        for name, digest in MUSL_PINS.items():
            target = Path(scratch) / name
            shutil.copyfile(libraries / name, target)
            verify_digest(target, digest)
            target.chmod(0o400)
        yield ("/usr/bin/env", f"LD_LIBRARY_PATH={scratch}", str(binary))


class Terminal:
    def __init__(self, root, env):
        self.command = ("/usr/bin/tmux", "-f", "/dev/null", "-S", str(root / "t"))
        self.env = env

    def run(self, *args, check=True):
        return subprocess.run((*self.command, *args), env=self.env, check=check, timeout=10,
                              capture_output=True, text=True).stdout

    def start(self, *command, width=104):
        launcher = shlex.join(command) + '; result=$?; printf "\\nFixture exit %s\\n" "$result"; sleep 120'
        self.run("new-session", "-d", "-s", "stock", "-x", str(width), "-y", "38", "/usr/bin/bash", "-c", launcher)

    def type_line(self, value):
        self.run("send-keys", "-t", "stock", "-l", value)
        self.run("send-keys", "-t", "stock", "Enter")

    def await_screen(self, predicate, description, server=None, timeout=45):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if server is not None and server.error is not None:
                raise server.error
            screen = self.run("capture-pane", "-p", "-S", "-", "-t", "stock")
            if predicate(screen):
                return screen
            if "Fixture exit" in screen:
                break
            time.sleep(.1)
        raise RuntimeError(f"Did not observe {description} in the stock terminal")


class FakeUpstream:
    def __init__(self, case):
        self.case = case
        self.script = ToolScript(str(WORKSPACE))
        self.writes = 0

    def start(self, body):
        self.writes += 1
        require(body["max_output_tokens"] == MAX_OUTPUT and {tool["name"] for tool in body["tools"]} == set(TOOL_NAMES),
                "Unexpected synthetic upstream output budget or tools")
        if self.case == "tools":
            events = self.script.respond(body)
        else:
            events = refused_events(self.case, body, str(WORKSPACE))
        return scripted_response(events)


class Observer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, case, ledger):
        super().__init__(("127.0.0.1", PORT), WireHandler)
        self.case = case
        self.abort = None
        self.upstream = FakeUpstream(case)
        self.turns = FixtureTurns(ledger, AUTHORITY)
        self.vault = ReasoningVault()
        self.requests = []
        self.local_titles = 0
        self.prefix_refusals = 0
        self.error = None
        self.lock = Lock()

    def dispatch(self, body, outbound):
        history = classify(body)
        require(history is not None, "Local title reached first-write boundary")
        return self.turns.dispatch(AUTHORITY, body["prompt_cache_key"], history,
                                   lambda _request: self.upstream.start(outbound))

    def check_prior_prefix(self, body, outbound):
        """Give each changed old prefix the exact genuine stock newest batch."""
        before = self.turns.records(), self.upstream.writes
        for change in ("output", "arguments", "call_id", "omission", "order"):
            altered = deepcopy(body)
            items = altered["input"]
            if change == "output":
                items[2]["output"] += " "
            elif change == "arguments":
                args = decode_json(items[1]["arguments"])
                args["patchText"] += " "
                items[1]["arguments"] = json.dumps(args)
            elif change == "call_id":
                items[1]["call_id"] = items[2]["call_id"] = "changed_earlier_call"
            elif change == "omission":
                del items[1:3]
            else:
                items[1:5] = items[3:5] + items[1:3]
            try:
                self.dispatch(altered, outbound)
            except FixtureMismatch as error:
                require(str(error) == "Earlier stock tool history differs", "Wrong earlier-prefix refusal")
            else:
                raise FixtureMismatch("Changed earlier stock history was accepted")
            require((self.turns.records(), self.upstream.writes) == before,
                    "Earlier-prefix refusal reached a claim or send")
            self.prefix_refusals += 1


class WireHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        self.request.settimeout(7)
        super().setup()

    def log_message(self, *_args):
        pass

    def _stream_headers(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Connection", "close")
        self.end_headers()

    def _send_frame(self, frame):
        self.wfile.write(frame)
        self.wfile.flush()

    def do_POST(self):
        request = None
        try:
            length = int(self.headers["Content-Length"])
            require(self.path == AUTHORITY.route and 0 < length <= MAX_WIRE, "Unexpected stock route")
            wire = self.rfile.read(length)
            raw = (self.requestline.encode("ascii") + b"\r\n" + self.headers.as_bytes().replace(b"\n", b"\r\n") + wire)
            parsed = parse_worker_request(raw, expected_token=FIXTURE_BEARER, allowed_models=frozenset({MODEL}),
                                          vault=self.server.vault, expected_port=PORT)
            body = decode_json(wire)
            history = classify(body)
            with self.server.lock:
                self.server.requests.append(body)
            if history is None:
                frames, _ = project_stream(scripted_response(response_events("title", reply=TITLE)),
                                           ReasoningVault(), (), "resp_local_title")
                self._stream_headers()
                for frame in frames:
                    self._send_frame(encode_chunk(frame))
                self._send_frame(HANDOFF_END)
                with self.server.lock:
                    self.server.local_titles += 1
                return

            if self.server.case != "tools" and self.server.abort is not None:
                self.send_error(401)
                return
            outbound = upstream_body(parsed)
            if self.server.case == "tools" and len(history.pairs) == 3:
                self.server.check_prior_prefix(body, outbound)
            request, upstream = self.server.dispatch(body, outbound)
            frames, usage = project_stream(upstream, self.server.vault, (tool["name"] for tool in outbound["tools"]),
                                           f"resp_local_{request.sequence}")
            calls, message = terminal_output(frames[-1])
            pending = self.server.turns.settle(AUTHORITY, request, calls=calls, completed_message=message, usage=usage)
            self._stream_headers()
            self.server.turns.deliver(AUTHORITY, request, pending, self._send_frame,
                                      (*map(encode_chunk, frames), HANDOFF_END))
        except StreamAborted as error:
            self.server.turns.fail(request)
            if self.server.case == "tools":
                self.server.error = error
            else:
                self.server.abort = error.code
            self.send_error(401)
        except Exception as error:
            self.server.turns.fail(request)
            self.server.error = error
            self.close_connection = True


def stock_config():
    preflight = InstancePreflight(ProviderInstanceSpec("openai", LABEL, True, "subscription"),
                                  ReadinessState.READY, (MODEL,))
    plan = ResolvedLaunchPlan((preflight,), (), {}, PROVIDER, MODEL, "full", "fixture")
    return build_multi_provider_opencode_config(plan=plan, adapters={"openai": OpenAISessionAdapter()},
                                               slot_ports={PROVIDER: PORT}, slot_tokens={PROVIDER: FIXTURE_BEARER})


def session_export(command, env):
    command = (*command, "--standalone", "session")
    listed = subprocess.run((*command, "list", "--format", "json"), env=env, cwd=WORKSPACE,
                            capture_output=True, check=True, timeout=15)
    sessions = json.loads(listed.stdout)
    if not sessions:
        return {"messages": []}
    (session,) = sessions
    exported = subprocess.run((*command, "export", session["id"]), env=env, cwd=WORKSPACE,
                              capture_output=True, check=True, timeout=15)
    return json.loads(exported.stdout)


def await_idle(export, *, observer=None, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if observer is not None and observer.error is not None:
            raise observer.error
        result = export()
        if result["messages"] and result["messages"][-1]["type"] == "idle" and result["info"].get("title") == TITLE:
            return result
        time.sleep(.1)
    raise RuntimeError("Stock session export did not reach an idle terminal state with its exact title")


def summarize(requests):
    return [{"input_types": [entry.get("type", entry.get("role")) for entry in request.get("input", ())],
             "tool_names": [entry["name"] for entry in request.get("tools", ())]}
            for request in requests]


def verify_scope():
    require({name for _, name in socket.if_nameindex()} == {"lo"}
            and len(Path("/proc/net/route").read_text().splitlines()) == 1,
            "Stock tools capture requires an isolated loopback-only namespace")
    require(WORKSPACE.is_dir() and not any(WORKSPACE.iterdir()), "Use an empty synthetic stock workspace")


def capture(command, evidence_path, case):
    with tempfile.TemporaryDirectory(prefix="oc-tools-") as scratch, Observer(case, Path(scratch) / "synthetic-exposure.sqlite") as observer:
        root = Path(scratch)
        home = root / "home"
        home.mkdir(mode=0o700)
        config = root / "opencode.json"
        config.write_text(json.dumps(stock_config()))
        env = {**JOB_ENV, "HOME": str(home), "OPENCODE_CONFIG": str(config)}
        term = Terminal(root, env)
        thread = Thread(target=observer.serve_forever)
        thread.start()
        try:
            term.start(*command, str(WORKSPACE))
            term.await_screen(lambda screen: "Ask anything" in screen, "ordinary stock input", observer)
            term.type_line(PROMPT)
            if case == "tools":
                term.await_screen(lambda screen: any(line.strip(" │┃▏●") == REPLY for line in screen.splitlines()),
                                  "exact final reply", observer)
            exported = await_idle(lambda: session_export(command, env), observer=observer)
            if case == "tools":
                script = observer.upstream.script
                records = observer.turns.records()
                require(len(script.requests) == len(records) == observer.upstream.writes == 4
                        and len(script.outputs) == 3 and observer.local_titles == 1
                        and observer.prefix_refusals == 5 and script.title_requests == 0,
                        "Wrong synthetic claim, send, tool or local title counts")
                require(records[0]["parent"] is None and all(record["parent"] for record in records[1:])
                        and all((record["actual_input"], record["actual_output"]) == (2, 3) for record in records),
                        "Synthetic exposure does not link and settle every write")
                require((WORKSPACE / FILE_NAME).read_bytes() == FILE_TEXT.encode(), "Independent workspace bytes differ")
                validate_export(exported, script)
            else:
                verify_abort = {"hosted": "unsupported_event", "undeclared": "unauthorized_tool_call"}[case]
                require(not (WORKSPACE / REFUSED_FILE).exists() and observer.abort == verify_abort,
                        "Refused stock tool crossed the execution boundary")
                validate_refused_export(exported)
                records = observer.turns.records()
                require(len(records) == observer.upstream.writes == observer.local_titles == 1
                        and records[0]["actual_input"] is None and records[0]["parent"] is None,
                        "A refused upstream tool acquired extra synthetic exposure")
            report = {"binary_sha256": STOCK_SHA256, "model": f"{PROVIDER}/{MODEL}", "tools": TOOL_NAMES,
                      "requests": summarize(observer.requests), "stock_export": exported, "abort": observer.abort,
                      "synthetic_claims": records, "synthetic_writes": observer.upstream.writes,
                      "local_titles": observer.local_titles, "earlier_prefix_refusals": observer.prefix_refusals}
            with os.fdopen(os.open(evidence_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600),
                           "w") as out:
                json.dump({"requests": observer.requests, "report": report}, out)
                out.write("\n")
            print(json.dumps({key: value for key, value in report.items() if key != "stock_export"}))
        except Exception as primary:
            try:
                with os.fdopen(os.open(evidence_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600),
                               "w") as out:
                    json.dump({"requests": observer.requests, "phase": "failed"}, out)
                    out.write("\n")
            except OSError as evidence_error:
                primary.add_note(f"Unable to save secondary evidence: {type(evidence_error).__name__}")
            print(json.dumps(summarize(observer.requests)), file=sys.stderr)
            raise
        finally:
            term.run("kill-server", check=False)
            observer.shutdown()
            thread.join()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--musl-libraries", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--case", choices=("tools", "hosted", "undeclared"), default="tools")
    args = parser.parse_args()
    verify_scope()
    with measured_command(args.binary, args.musl_libraries) as command:
        capture(command, args.evidence, args.case)


if __name__ == "__main__":
    main()
