"""Capture and validate an actual stock OpenCode write, read and shell turn offline."""

import argparse
from contextlib import contextmanager
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
from oc_openai.session_protocol import MAX_INTERACTIVE_BODY, ReasoningVault, SessionStreamProjector, StreamAborted, parse_worker_request
from oc_providers.catalog import ResolvedLaunchPlan, build_multi_provider_opencode_config
from oc_providers.contracts import InstancePreflight, ProviderInstanceSpec, ReadinessState
from stock_worker_tools_protocol import (FILE_NAME, FILE_TEXT, LABEL, MODEL, PROMPT, PROVIDER, REPLY,
                                         REFUSED_FILE, TITLE, TITLE_PROMPT, TOOL_NAMES, ToolScript, output_text, refused_events,
                                         require, response_events, validate_export, validate_refused_export)

STOCK_SHA256 = "9e0cb0e096666f955c3f72d1b517fd2cb5cca65c2876e1012492d955fc974a7b"
MUSL_LOADER_SHA256 = "095b047c631447e4fa50401fa7ffce01f678587040d65ba18c574981dc630de5"
MUSL_PINS = {
    "libstdc++.so.6": "67a940194aec6c44c3eb47a98e44c53d248e4dac5f4eb57c0971c0d6286eafe5",
    "libgcc_s.so.1": "5ea51dd885b6fc691eccc569d0bda739204204f6161e97075b26dc9c050d1ca1",
}
PORT = 8401
FIXTURE_BEARER = "stock-tools-synthetic-only"
WORKSPACE = Path("/sandbox/construct")
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


class Observer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, case):
        super().__init__(("127.0.0.1", PORT), WireHandler)
        self.case = case
        self.abort = None
        self.initial_refused = None
        self.script = ToolScript(str(WORKSPACE))
        self.vault = ReasoningVault()
        self.requests = []
        self.error = None
        self.lock = Lock()


class WireHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        self.request.settimeout(7)
        super().setup()

    def log_message(self, *_args):
        pass

    def do_POST(self):
        try:
            length = int(self.headers["Content-Length"])
            require(self.path == "/v1/responses" and 0 < length <= MAX_INTERACTIVE_BODY, "Unexpected stock route")
            require(self.headers.get("Authorization") == f"Bearer {FIXTURE_BEARER}", "Unexpected test bearer")
            wire = self.rfile.read(length)
            body = decode_json(wire)
            raw = (self.requestline.encode("ascii") + b"\r\n" + self.headers.as_bytes().replace(b"\n", b"\r\n") + wire)
            with self.server.lock:
                self.server.requests.append(body)
                parsed = parse_worker_request(raw, expected_token=FIXTURE_BEARER, allowed_models=frozenset({MODEL}),
                                              vault=self.server.vault, expected_port=PORT)
                content = parsed.body["input"][0]["content"]
                is_negative = self.server.case != "tools" and output_text(content) != TITLE_PROMPT
                if self.server.case == "tools":
                    events = self.server.script.respond(parsed.body)
                elif is_negative:
                    if self.server.initial_refused is not None:
                        require(self.server.initial_refused == parsed.body, "Stock retry changed the initial prompt")
                        self.send_error(401)
                        return
                    self.server.initial_refused = parsed.body
                    events = refused_events(self.server.case, parsed.body, str(WORKSPACE))
                else:
                    events = tuple(response_events("title", reply=TITLE))
                projector = SessionStreamProjector(model=MODEL, local_response_id=f"resp_local_{len(self.server.requests)}",
                                                   allowed_tools=parsed.allowed_tools, vault=self.server.vault)
                frames = []
                try:
                    for event in events:
                        frames.extend(projector.feed(event))
                    frames.extend(projector.finalize())
                except StreamAborted as error:
                    if not is_negative:
                        raise
                    self.server.abort = error.code
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Connection", "close")
            self.end_headers()
            for frame in frames:
                self.wfile.write(f"{len(frame):x}\r\n".encode("ascii") + frame + b"\r\n")
            if not is_negative:
                self.wfile.write(b"0\r\n\r\n")
        except Exception as error:
            if self.server.error is None:
                self.server.error = error
            self.send_error(400)


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
    with tempfile.TemporaryDirectory(prefix="oc-tools-") as scratch, Observer(case) as observer:
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
                observer.script.verify_done()
                require((WORKSPACE / FILE_NAME).read_bytes() == FILE_TEXT.encode(), "Independent workspace bytes differ")
                validate_export(exported, observer.script)
            else:
                verify_abort = {"hosted": "unsupported_event", "undeclared": "unauthorized_tool_call"}[case]
                require(not (WORKSPACE / REFUSED_FILE).exists() and observer.abort == verify_abort,
                        "Refused stock tool crossed the execution boundary")
                validate_refused_export(exported)
            report = {"binary_sha256": STOCK_SHA256, "model": f"{PROVIDER}/{MODEL}", "tools": TOOL_NAMES,
                      "requests": summarize(observer.requests), "stock_export": exported, "abort": observer.abort}
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
