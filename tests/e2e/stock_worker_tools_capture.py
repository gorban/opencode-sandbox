"""Capture and validate an actual stock OpenCode write, read and shell turn offline."""

import argparse
from contextlib import contextmanager
from copy import deepcopy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
from threading import Event, Lock, Thread
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from oc_openai.connection_state import decode_json
from oc_openai.session_adapter import OpenAISessionAdapter
from oc_openai.session_protocol import ReasoningVault, StreamAborted, encode_chunk, parse_worker_request
from oc_providers.catalog import ResolvedLaunchPlan, build_multi_provider_opencode_config
from oc_providers.contracts import InstancePreflight, ProviderInstanceSpec, ReadinessState
from stock_worker_tools_history import MAX_OUTPUT, MAX_WIRE, classify, stock_call, upstream_body
from stock_worker_tools_interaction import (
    CASES as INTERACTION_CASES, MEASUREMENT_SHA256 as INTERACTION_MEASUREMENT, PROMPT as INTERACTION_PROMPT,
    QUESTION, QUESTION_OPTIONS, REPLY as INTERACTION_REPLY, SCHEMA_SHA256 as INTERACTION_SCHEMAS,
    TITLE as INTERACTION_TITLE, Interaction,
)
from stock_worker_tools_protocol import (
    FILE_NAME, FILE_TEXT, LABEL, MODEL, PROMPT, PROVIDER, REPLY, REFUSED_FILE, TITLE, TOOL_NAMES,
    FixtureMismatch, ToolScript, refused_events, require, response_events, validate_export,
    validate_refused_export,
)
from stock_worker_tools_search import (
    SEARCH_MEASUREMENT_SHA256, SEARCH_PROMPT, SEARCH_REPLY, SEARCH_SCHEMA_SHA256, SEARCH_TITLE, SEARCH_TOOLS,
    SearchScript,
)
from stock_worker_tools_stream import project_stream, scripted_response, terminal_output
from stock_worker_tools_turns import HANDOFF_END, Authority, FixtureTurns, PinnedLedger

STOCK_SHA256 = "9e0cb0e096666f955c3f72d1b517fd2cb5cca65c2876e1012492d955fc974a7b"
MUSL_LOADER_SHA256 = "095b047c631447e4fa50401fa7ffce01f678587040d65ba18c574981dc630de5"
MUSL_PINS = {
    "libstdc++.so.6": "67a940194aec6c44c3eb47a98e44c53d248e4dac5f4eb57c0971c0d6286eafe5",
    "libgcc_s.so.1": "5ea51dd885b6fc691eccc569d0bda739204204f6161e97075b26dc9c050d1ca1",
}
SEARCH_RG_SHA256 = "f9fce9763d614143634eb1152c6653dc8b4c8baf1d47e468e8dd609e94ba2151"
SEARCH_PCRE_SHA256 = "496ce2b43e3910e8c232105fa04cf1b47df8860f9ec90e75dde05303c2fc69be"
PORT = 8401
OBSERVER_STOP_SECONDS = 10
TERMINAL_STOP_SECONDS = 10
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
def preserving_cleanup(action, description):
    try:
        yield
    except BaseException as primary:
        try:
            action()
        except BaseException as secondary:
            primary.add_note(f"Unable to finish {description}: {type(secondary).__name__}")
        raise
    else:
        action()


@contextmanager
def measured_command(binary, libraries, *, search=False):
    binary = binary.resolve(strict=True)
    verify_digest(binary, STOCK_SHA256)
    loader = Path("/lib/ld-musl-x86_64.so.1")
    verify_digest(loader, MUSL_LOADER_SHA256)
    alias = loader.with_name("libc.musl-x86_64.so.1")
    require(alias.resolve(strict=True) == loader.resolve(strict=True), "Incorrect stock musl loader alias")
    scratch = tempfile.TemporaryDirectory(prefix="oc-tools-musl-")
    with preserving_cleanup(scratch.cleanup, "stock library scratch cleanup"):
        pins = MUSL_PINS
        if search:
            verify_digest(Path("/usr/bin/rg"), SEARCH_RG_SHA256)
            pins = {**MUSL_PINS, "libpcre2-8.so.0": SEARCH_PCRE_SHA256}
        for name, digest in pins.items():
            target = Path(scratch.name) / name
            shutil.copyfile(libraries / name, target)
            verify_digest(target, digest)
            target.chmod(0o400)
        yield ("/usr/bin/env", f"LD_LIBRARY_PATH={scratch.name}", str(binary))


class Terminal:
    def __init__(self, root, env, *, allow_autostart=True):
        self.socket_path = root / "t"
        self.command = ("/usr/bin/tmux", "-f", "/dev/null", "-S", str(self.socket_path))
        self.client_command = self.command if allow_autostart else (*self.command, "-N")
        self.env = env

    def run(self, *args, check=True, timeout=10):
        return subprocess.run((*self.client_command, *args), env=self.env, check=check, timeout=timeout,
                              capture_output=True, text=True).stdout

    def launch_server(self):
        return subprocess.Popen((*self.command, "-D"), env=self.env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def await_server(self, server, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            require(server.poll() is None, "Foreground capture terminal exited during startup")
            try:
                info = self.socket_path.lstat()
            except FileNotFoundError:
                time.sleep(.05)
                continue
            require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid(), "Unexpected capture terminal socket")
            return
        raise TimeoutError("Foreground capture terminal did not become ready")

    def stop_server(self, server):
        require(server is not None, "Foreground capture terminal was never identified")
        if server.poll() is None:
            deadline = time.monotonic() + TERMINAL_STOP_SECONDS
            self.run("kill-server", timeout=max(0, deadline - time.monotonic()))
            server.wait(timeout=max(0, deadline - time.monotonic()))

    def start(self, *command, width=104):
        launcher = shlex.join(command) + '; result=$?; printf "\\nFixture exit %s\\n" "$result"; sleep 120'
        self.run("new-session", "-d", "-s", "stock", "-x", str(width), "-y", "38", "/usr/bin/bash", "-c", launcher)

    def type_line(self, value):
        self.run("send-keys", "-t", "stock", "-l", value)
        self.run("send-keys", "-t", "stock", "Enter")

    def await_screen(self, predicate, description, server=None, timeout=45, *, history=True):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if server is not None and server.error is not None:
                raise server.error
            scrollback = ("-S", "-") if history else ()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            screen = self.run("capture-pane", "-p", *scrollback, "-t", "stock", timeout=min(10, remaining))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if predicate(screen):
                return screen
            if "Fixture exit" in screen:
                break
            time.sleep(min(.1, remaining))
        raise RuntimeError(f"Did not observe {description} in the stock terminal")


class FakeUpstream:
    def __init__(self, case, interaction):
        self.case = case
        self.interaction = interaction
        self.script = SearchScript(WORKSPACE) if case == "search" else ToolScript(str(WORKSPACE))
        self.tools = (interaction.tool,) if interaction else (SEARCH_TOOLS if case == "search" else TOOL_NAMES)
        self.writes = 0

    def start(self, body, checked_input=None):
        require(body["max_output_tokens"] == MAX_OUTPUT and {tool["name"] for tool in body["tools"]} == set(self.tools),
                "Unexpected synthetic upstream output budget or tools")
        if self.interaction:
            events = self.interaction.respond(body, checked_input)
        elif self.case == "search":
            events = self.script.respond(body, checked_input)
        elif self.case == "tools":
            events = self.script.respond(body)
        else:
            events = refused_events(self.case, body, str(WORKSPACE))
        self.writes += 1
        return scripted_response(events)


class Observer(ThreadingHTTPServer):
    # Track handlers ourselves so closing the listener never waits without a deadline.
    block_on_close = False
    timeout = .1

    def __init__(self, case, ledger=None, *, bind_and_activate=True):
        self.case = case
        self.abort = None
        self.search = case == "search"
        generation = secrets.token_hex(16)
        self.interaction = Interaction(case, generation, WORKSPACE) if case in INTERACTION_CASES else None
        self.upstream = FakeUpstream(case, self.interaction)
        self.authority = Authority("synthetic-search-job", AUTHORITY.slot, secrets.token_hex(16),
                                   AUTHORITY.route, AUTHORITY.model) if self.search else AUTHORITY
        if self.interaction:
            self.authority = Authority("synthetic-interaction-job", AUTHORITY.slot, generation,
                                       AUTHORITY.route, AUTHORITY.model)
        self.turns = None if ledger is None else FixtureTurns(ledger, self.authority)
        self.vault = ReasoningVault()
        self.requests = []
        self.local_titles = 0
        self.prefix_refusals = 0
        self.error = None
        self.lock = Lock()
        self._stop_serving = Event()
        self._handlers = []
        super().__init__(("127.0.0.1", PORT), WireHandler, bind_and_activate=bind_and_activate)

    def serve_until_stopped(self):
        while not self._stop_serving.is_set():
            self.handle_request()

    def process_request(self, request, client_address):
        if self._stop_serving.is_set():
            self.shutdown_request(request)
            return
        handler = Thread(target=self.process_request_thread, args=(request, client_address), daemon=True)
        self._handlers = [thread for thread in self._handlers if thread.is_alive()]
        self._handlers.append(handler)
        handler.start()

    def stop(self, serving, deadline):
        self._stop_serving.set()
        if serving is not None and serving.is_alive():
            serving.join(max(0, deadline - time.monotonic()))
            if serving.is_alive():
                raise TimeoutError("Capture observer serving thread did not stop")
        # Only the serving thread adds handlers. The list is stable once it exits.
        for handler in self._handlers:
            if handler.is_alive():
                handler.join(max(0, deadline - time.monotonic()))
                if handler.is_alive():
                    raise TimeoutError("Capture observer request handlers did not stop")

    def dispatch(self, body, outbound):
        history = classify(body, search=self.search, interaction=self.interaction)
        require(history is not None, "Local title reached first-write boundary")
        if self.interaction:
            with self.lock:
                result = self.interaction.verify_input(body, history)
                return self.turns.dispatch(self.authority, body["prompt_cache_key"], history,
                                           lambda _request: self.upstream.start(outbound, result))
        if self.search:
            # Results and declaration authority are checked before the durable claim.
            results = self.upstream.script.verify_input(body)
            return self.turns.dispatch(self.authority, body["prompt_cache_key"], history,
                                       lambda _request: self.upstream.start(outbound, results))
        return self.turns.dispatch(self.authority, body["prompt_cache_key"], history,
                                   lambda _request: self.upstream.start(outbound))

    def verify_native_refusal(self, body, history):
        with self.lock:
            require(self.prefix_refusals == 0, "Repeated native skill rejection")
            self.interaction.verify_unavailable(body, history)
            self.turns.check_pending_call(self.authority, body["prompt_cache_key"], history.pairs[0].call)
            self.turns.retire()
            self.prefix_refusals += 1

    def check_interaction_refusals(self, body, outbound):
        original = self.turns.verified_records(), self.upstream.writes
        for label in ("schema", "arguments", "result", "foreign session", "foreign call"):
            altered = deepcopy(body)
            call, output = altered["input"][1:]
            if label == "schema":
                selected = next(tool for tool in altered["tools"] if tool["name"] == self.interaction.tool)
                selected["parameters"]["additionalProperties"] = True
            elif label == "arguments":
                call["arguments"] = "{}"
            elif label == "result":
                output["output"] += " "
            elif label == "foreign session":
                altered["prompt_cache_key"] += "a"
            else:
                output["call_id"] = call["call_id"] = "call_another_stock_interaction"
            try:
                self.dispatch(altered, outbound)
            except FixtureMismatch:
                pass
            else:
                raise FixtureMismatch(f"Accepted stock interaction {label} drift")
            require((self.turns.verified_records(), self.upstream.writes) == original,
                    "Stock interaction refusal reached a claim or send")
            self.prefix_refusals += 1

    def check_interaction_replay(self):
        before = self.turns.verified_records(), self.upstream.writes
        continued, = (body for body in self.requests if len(body["input"]) == 3)
        try:
            self.dispatch(continued, None)
        except FixtureMismatch as error:
            require(str(error) == "No matching stock interaction is awaiting continuation",
                    "Stock interaction replay failed for the wrong reason")
        else:
            raise FixtureMismatch("Accepted a previously delivered stock interaction result")
        require((self.turns.verified_records(), self.upstream.writes) == before,
                "Stock interaction replay reached a claim or send")

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
            history = classify(body, search=self.server.search, interaction=self.server.interaction)
            with self.server.lock:
                self.server.requests.append(body)
            if history is None:
                frames, _ = project_stream(scripted_response(response_events("title", reply=(INTERACTION_TITLE if self.server.interaction else SEARCH_TITLE if self.server.search else TITLE))),
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
            outbound = upstream_body(parsed, self.server.upstream.tools)
            if self.server.case == "tools" and len(history.pairs) == 3:
                self.server.check_prior_prefix(body, outbound)
            if self.server.case == "skill-unavailable" and history.pairs:
                self.server.verify_native_refusal(body, history)
                self.send_error(401)
                return
            if self.server.interaction and history.pairs:
                self.server.check_interaction_refusals(body, outbound)
            request, upstream = self.server.dispatch(body, outbound)
            frames, usage = project_stream(upstream, self.server.vault, (tool["name"] for tool in outbound["tools"]),
                                           f"resp_local_{request.sequence}")
            calls, message = terminal_output(frames[-1], search=self.server.search,
                                             interaction=self.server.interaction)
            pending = self.server.turns.settle(self.server.authority, request, calls=calls, completed_message=message, usage=usage)
            self._stream_headers()
            self.server.turns.deliver(self.server.authority, request, pending, self._send_frame,
                                      (*map(encode_chunk, frames), HANDOFF_END))
        except StreamAborted as error:
            self.server.turns.fail(request)
            if self.server.case in {"tools", "search"} | (INTERACTION_CASES - {"skill-undeclared"}):
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


def await_idle(export, *, observer=None, timeout=30, title=TITLE):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if observer is not None and observer.error is not None:
            raise observer.error
        result = export()
        if result["messages"] and result["messages"][-1]["type"] == "idle" and result["info"].get("title") == title:
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


@contextmanager
def private_evidence_root(path):
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    with preserving_cleanup(lambda: os.close(directory), "evidence directory close"):
        verify_private_directory(os.fstat(directory))
        yield directory


def verify_private_directory(info):
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not stat.S_IMODE(info.st_mode) & 0o077,
            "Capture evidence directory must be private and owned")


class ExposureScratch:
    def __init__(self, root, parent, directory):
        self.root = root
        self.parent = parent
        self.directory = directory
        self.identity = os.fstat(directory)
        self._descriptor_lock = Lock()
        self._revoked = False

    def verify_parent(self, parent=None):
        parent = self.parent if parent is None else parent
        observed = self.root.parent.lstat()
        verify_private_directory(observed)
        require(os.path.samestat(observed, os.fstat(parent)), "Capture evidence parent changed")

    def verify(self, parent=None):
        parent = self.parent if parent is None else parent
        self.verify_parent(parent)
        observed = os.stat(self.root.name, dir_fd=parent, follow_symlinks=False)
        verify_private_directory(observed)
        require(os.path.samestat(observed, self.identity), "Capture exposure directory changed")

    def require_active(self):
        with self._descriptor_lock:
            require(not self._revoked, "Capture exposure directory retired")

    def authorize_first_write(self, *, deadline, clock, verify_ledger):
        with self.borrow() as (directory, verify):
            verify()
            verify_ledger(directory)
        # The deadline and revocation must both be current after filesystem
        # verification, without holding this lock across I/O or the callback.
        with self._descriptor_lock:
            require(not self._revoked, "Capture exposure directory retired")
            require(clock() < deadline, "Stale or expired stock fixture authority")

    def revoke(self):
        with self._descriptor_lock:
            self._revoked = True

    @contextmanager
    def borrow(self):
        with self._descriptor_lock:
            require(not self._revoked, "Capture exposure directory retired")
            parent = os.dup(self.parent)
            try:
                directory = os.dup(self.directory)
            except BaseException:
                with preserving_cleanup(lambda: os.close(parent), "borrowed evidence parent close"):
                    raise
        with preserving_cleanup(lambda: os.close(parent), "borrowed evidence parent close"), \
                preserving_cleanup(lambda: os.close(directory), "borrowed exposure directory close"):
            self.verify(parent)
            yield directory, lambda: self.verify(parent)

    def still_named(self):
        try:
            self.verify()
        except (OSError, FixtureMismatch):
            return False
        return True

    def discard(self, ledger=None):
        self.verify()
        # A fresh file description sees entries published after the held
        # descriptor was opened, without sharing its enumeration position.
        scanner = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.directory)
        with preserving_cleanup(lambda: os.close(scanner), "exposure enumeration close"):
            require(os.path.samestat(self.identity, os.fstat(scanner)), "Capture exposure enumeration changed")
            with os.scandir(scanner) as entries:
                entry = next(entries, None)
                if entry is not None:
                    require(ledger is not None and entry.name == ledger.name and next(entries, None) is None
                            and ledger.owns(entry.stat(follow_symlinks=False)),
                            "Unexpected capture exposure artifacts")
                    identified = entry.stat(follow_symlinks=False)
        if entry is not None:
            named = os.stat(ledger.name, dir_fd=self.directory, follow_symlinks=False)
            require(ledger.owns(named) and os.path.samestat(identified, named),
                    "Capture exposure ledger changed before cleanup")
            os.unlink(ledger.name, dir_fd=self.directory)
        self.verify()
        os.rmdir(self.root.name, dir_fd=self.parent)


@contextmanager
def make_exposure_scratch(evidence_root):
    with private_evidence_root(evidence_root) as parent:
        created = Path(tempfile.mkdtemp(prefix=".oc-tools-exposure-", dir=f"/proc/self/fd/{parent}"))
        root = evidence_root.absolute() / created.name
        identity = created.lstat()
        directory = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        with preserving_cleanup(lambda: os.close(directory), "exposure directory close"):
            scratch = ExposureScratch(root, parent, directory)
            require(os.path.samestat(identity, scratch.identity), "Capture exposure directory changed")
            scratch.verify()
            try:
                os.fsync(parent)
            except BaseException:
                with preserving_cleanup(scratch.discard, "uninitialized exposure scratch cleanup"):
                    raise
            with preserving_cleanup(scratch.revoke, "exposure descriptor retirement"):
                yield scratch


def write_capture_evidence(directory, name, data):
    payload = json.dumps(data, allow_nan=False) + "\n"
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    identity = None
    try:
        with preserving_cleanup(lambda: os.close(fd), "evidence descriptor close"):
            identity = os.fstat(fd)
            out = os.fdopen(fd, "w", closefd=False)
            with preserving_cleanup(out.close, "evidence file close"):
                os.fchmod(fd, 0o600)
                out.write(payload)
                out.flush()
                os.fsync(fd)
        os.fsync(directory)
    except BaseException as primary:
        try:
            if identity is not None and os.path.samestat(identity, os.stat(name, dir_fd=directory, follow_symlinks=False)):
                os.unlink(name, dir_fd=directory)
        except BaseException as secondary:
            primary.add_note(f"Unable to remove partial evidence: {type(secondary).__name__}")
        raise


def save_failed_capture(scratch, evidence_name, observer, stopped, primary):
    status = "unavailable"
    if stopped and scratch.still_named():
        try:
            claims = observer.turns.verified_records()
        except FixtureMismatch:
            status = "corrupt"
        except OSError:
            pass
        except sqlite3.Error as error:
            corrupt = {sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB, sqlite3.SQLITE_TOOBIG,
                       sqlite3.SQLITE_SCHEMA, sqlite3.SQLITE_ERROR}
            code = getattr(error, "sqlite_errorcode", None)
            if code is not None and (code & 0xff) in corrupt:
                status = "corrupt"
        else:
            status = "verified"
    if stopped and not scratch.still_named():
        stopped = False
        status = "unavailable"
    evidence = {"status": status}
    if status == "verified":
        evidence["claims"] = claims
    else:
        primary.add_note(f"Synthetic exposure evidence {status}")
    report = {"phase": "failed", "exposure": evidence}
    if stopped:
        report["requests"] = summarize(observer.requests) if observer.interaction else observer.requests
    scratch.verify_parent()
    write_capture_evidence(scratch.parent, evidence_name, report)
    if stopped:
        print(json.dumps(summarize(observer.requests)), file=sys.stderr)


def question_screen(screen):
    lines = {line.strip(" ┃") for line in screen.splitlines()}
    return {QUESTION, "1. " + QUESTION_OPTIONS[0], "2. " + QUESTION_OPTIONS[1],
            "↑↓ select  enter submit  esc dismiss"} <= lines


def drive_question(term, observer, export):
    term.await_screen(question_screen, "the exact native question and its two choices", observer, history=False)
    script = observer.interaction
    snapshot = export()
    with observer.lock:
        call = stock_call({
            "type": "function_call", "call_id": script.call_id, "id": "fc_local_1",
            "name": script.tool, "arguments": json.dumps(script.arguments),
        }, interaction=script)
        observer.turns.check_pending_call(observer.authority, script.session, call)
        require(not script.verify_export_identity(snapshot) and question_screen(term.run("capture-pane", "-p", "-t", "stock"))
                and not script.selected and len(observer.turns.verified_records()) == observer.upstream.writes == 1,
                "Stock question was not pending with zero continuation exposure")
        key = "Escape" if script.case == "question-cancel" else "Enter"
        term.run("send-keys", "-t", "stock", key)
        script.selected = key == "Enter"
    if script.case == "question-cancel":
        term.await_screen(lambda screen: "interrupted" in screen and not question_screen(screen),
                          "native question interruption", observer, history=False)


def await_canceled_question(export, observer, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if observer.error is not None:
            raise observer.error
        result = export()
        if (result.get("info", {}).get("title") == INTERACTION_TITLE
                and any(message.get("error", {}).get("type") == "aborted" for message in result["messages"])):
            return result
        time.sleep(.1)
    raise FixtureMismatch("Dismissed question did not reach the native interrupted outcome")


def verify_interaction(observer, exported, records):
    script = observer.interaction
    script.verify_inventory()
    assistants = script.verify_export_identity(exported)
    success = script.case in {"question", "skill"}
    expected_writes = 2 if success else 1
    expected_requests = {"question": 3, "question-cancel": 2, "skill": 3, "skill-unavailable": 3}
    require(len(records) == observer.upstream.writes == expected_writes and observer.local_titles == 1
            and {r["prompt_cache_key"] for r in observer.requests} == {script.session}
            and len(observer.requests) == expected_requests.get(script.case, len(observer.requests)),
            "Wrong stock interaction claim, write, or title counts")
    require(records[0]["parent"] is None and json.loads(records[0]["suffix"]) == []
            and (not success or records[1]["parent"] and len(json.loads(records[1]["suffix"])) == 1),
            "Stock interaction claims do not bind the exact original and continuation")
    report = {"measurement_sha256": INTERACTION_MEASUREMENT, "schema_sha256": INTERACTION_SCHEMAS,
              "case": script.case, "result": "denied", "scope": "loopback-only",
              "inventory_unchanged": True, "terminal_server_exit_verified": True}
    last = exported["messages"][-1]
    if script.case == "skill-undeclared":
        require(len(observer.requests) in {2, 3} and observer.abort == "unauthorized_tool_call"
                and (records[0]["actual_input"], records[0]["actual_output"]) == (None, None)
                and all(not a["content"] for a in assistants)
                and last["type"] == "idle" and last["outcome"] == exported["info"]["outcome"] == "failed",
                "Undeclared skill reached native execution")
        return report
    require(all((r["actual_input"], r["actual_output"]) == (2, 3) for r in records),
            "Stock interaction claims did not settle exact usage")
    (part,) = assistants[0]["content"]
    state = script.verify_export_tool(part)
    if success:
        require(len(assistants) == 2 and state["status"] == "completed" and observer.prefix_refusals == 5,
                "Stock interaction had repeated results or missing refusal checks")
        (content,) = state["content"]
        (final,) = assistants[1]["content"]
        require(content == {"type": "text", "text": script.expected_result()} and script.result == content["text"]
                and final["type"] == "text" and final["text"] == INTERACTION_REPLY
                and last["type"] == "idle" and last["outcome"] == exported["info"]["outcome"] == "succeeded",
                "Stock interaction native result or terminal reply did not match")
        observer.check_interaction_replay()
        report["result"] = "completed"
        report["same_chat_replay_denied"] = True
        if script.case == "skill":
            report["skill_metadata"] = script.verify_skill_metadata(state.get("metadata"))
    elif script.case == "question-cancel":
        require(len(assistants) == 1 and last["finish"] == "error" and last["error"]["type"] == "aborted"
                and state["status"] == "error"
                and state["error"] == {"type": "aborted", "message": "The user dismissed this question"},
                "Stock question did not reach the exact native interruption")
        report["result"] = "interrupted"
    else:
        require(len(assistants) == 2 and not assistants[1]["content"] and observer.prefix_refusals == 1
                and state["status"] == "error" and state["error"] == script.refusal()
                and last["type"] == "idle" and last["outcome"] == exported["info"]["outcome"] == "failed",
                "Unavailable skill did not reach the exact native lookup denial")
    return report

def capture_report(observer, case, exported):
    if observer.interaction:
        records = observer.turns.verified_records()
        interaction = verify_interaction(observer, exported, records)
    elif case == "search":
        records = observer.turns.verified_records()
        require(len(records) == observer.upstream.writes == 3 and observer.local_titles == 1
                and len(observer.requests) == 4
                and {req["prompt_cache_key"] for req in observer.requests} == {exported["info"]["id"]},
                "Wrong stock search claim, send or local title counts")
        continuations = records[1:]
        require(records[0]["parent"] is None and json.loads(records[0]["suffix"]) == []
                and len({record["parent"] for record in continuations}) == 2
                and all(record["parent"] and len(json.loads(record["suffix"])) == 1
                        for record in continuations)
                and all((record["actual_input"], record["actual_output"]) == (2, 3) for record in records),
                "Stock search exposure does not link and settle every write")
        observer.upstream.script.verify_done(exported)
    elif case == "tools":
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
    report = {"binary_sha256": STOCK_SHA256, "model": f"{PROVIDER}/{MODEL}", "tools": observer.upstream.tools,
            "requests": summarize(observer.requests), "stock_export": exported, "abort": observer.abort,
            "synthetic_claims": records, "synthetic_writes": observer.upstream.writes,
            "local_titles": observer.local_titles, "earlier_prefix_refusals": observer.prefix_refusals}

    if observer.interaction:
        report["interaction"] = interaction
        del report["stock_export"]
    elif case == "search":
        report["search"] = {"measurement_sha256": SEARCH_MEASUREMENT_SHA256,
                            "schema_sha256": SEARCH_SCHEMA_SHA256,
                            "ripgrep_sha256": SEARCH_RG_SHA256, "pcre_sha256": SEARCH_PCRE_SHA256,
                            "job_inventory_unchanged": True}
    return report


def record_capture_failure(scratch, evidence_name, observer, stopped, primary, ledger, local):
    turns = observer.turns if observer is not None else None
    publication_uncertain = ledger.publication_uncertain or (turns is not None and turns.settlement_uncertain)
    retain = not (stopped and not publication_uncertain and scratch.still_named())
    if retain:
        scratch.revoke()
    try:
        save_failed_capture(scratch, evidence_name, observer, not retain and turns is not None, primary)
    except BaseException as evidence_error:
        primary.add_note(f"Unable to save secondary evidence: {type(evidence_error).__name__}")
    named = scratch.still_named()
    retain = retain or not named
    if retain:
        scratch.revoke()
        identities = ledger.recovery_identities() if stopped and ledger.publication_uncertain else ()
        save_recovery_receipt(scratch, ledger.name, *local, primary, named=named, identities=identities)
    return retain


def capture(command, evidence_path, case):
    with make_exposure_scratch(evidence_path.parent) as scratch:
        capture_in_scope(command, evidence_path.name, case, scratch)


def capture_in_scope(command, evidence_name, case, scratch):
    ledger = PinnedLedger("synthetic-exposure.sqlite", scratch)
    local_root = None
    local_identity = None
    retain = False
    observer_stopped = terminal_stopped = True
    observer = None
    thread = server = None

    def remove_exposure_scratch():
        if not retain:
            scratch.discard(ledger)

    def remove_local_scratch():
        if not retain and local_root is not None:
            require(os.path.samestat(local_identity, local_root.lstat()), "Capture terminal directory changed")
            shutil.rmtree(local_root)

    with preserving_cleanup(remove_exposure_scratch, "exposure scratch cleanup"), \
            preserving_cleanup(remove_local_scratch, "capture scratch cleanup"):
        def stop_observer():
            nonlocal observer_stopped
            with preserving_cleanup(observer.server_close, "observer close"):
                observer.stop(thread, time.monotonic() + OBSERVER_STOP_SECONDS)
            observer_stopped = True

        def stop_terminal():
            nonlocal terminal_stopped
            if not terminal_stopped:
                require(os.path.samestat(local_identity, local_root.lstat()), "Capture terminal directory changed")
                term.stop_server(server)
                terminal_stopped = True

        try:
            observer = Observer(case, bind_and_activate=False)
            with preserving_cleanup(stop_observer, "observer shutdown"):
                observer.turns = FixtureTurns(scratch.root / ledger.name, observer.authority, ledger=ledger)
                observer.server_bind()
                observer.server_activate()
                local_root = Path(tempfile.mkdtemp(prefix="oc-tools-"))
                local_identity = local_root.lstat()
                home = local_root / "home"
                home.mkdir(mode=0o700)
                config = local_root / "opencode.json"
                configuration = stock_config()
                if observer.interaction:
                    observer.interaction.configure(configuration)
                config.write_text(json.dumps(configuration))
                env = {**JOB_ENV, "HOME": str(home), "OPENCODE_CONFIG": str(config)}
                if observer.interaction:
                    env.update(TZ="UTC", OPENCODE_DISABLE_CLAUDE_CODE_SKILLS="true")
                term = Terminal(local_root, env, allow_autostart=False)
                with preserving_cleanup(stop_terminal, "terminal cleanup"):
                    thread = Thread(target=observer.serve_until_stopped, daemon=True)
                    observer_stopped = False
                    thread.start()
                    terminal_stopped = False
                    server = term.launch_server()
                    term.await_server(server)
                    if observer.interaction:
                        observer.interaction.setup(home)
                    elif case == "search":
                        observer.upstream.script.setup()
                    term.start(*command, str(WORKSPACE))
                    term.await_screen(lambda screen: "Ask anything" in screen, "ordinary stock input", observer)
                    prompt = INTERACTION_PROMPT if observer.interaction else SEARCH_PROMPT if case == "search" else PROMPT
                    title = INTERACTION_TITLE if observer.interaction else SEARCH_TITLE if case == "search" else TITLE

                    def export():
                        return session_export(command, env)

                    term.type_line(prompt)
                    if case in {"question", "question-cancel"}:
                        drive_question(term, observer, export)
                    if case in {"tools", "search", "question", "skill"}:
                        reply = INTERACTION_REPLY if observer.interaction else SEARCH_REPLY if case == "search" else REPLY
                        term.await_screen(lambda screen: any(line.strip(" │┃▏●") == reply for line in screen.splitlines()),
                                          "exact final reply", observer)
                    exported = (await_canceled_question(export, observer) if case == "question-cancel"
                                else await_idle(export, observer=observer, title=title))
            # Joined handlers can record a fault after the terminal export.
            if observer.error is not None:
                raise observer.error
            scratch.verify()
            report = capture_report(observer, case, exported)
            scratch.verify()
            write_capture_evidence(scratch.parent, evidence_name, {"requests": report["requests"] if observer.interaction else observer.requests, "report": report})
        except BaseException as primary:
            retain = record_capture_failure(scratch, evidence_name, observer, observer_stopped and terminal_stopped,
                                            primary, ledger, (local_root, local_identity))
            raise
    print(json.dumps({key: value for key, value in report.items() if key != "stock_export"}))


def terminal_socket_identity(local_root, local_identity):
    with private_evidence_root(local_root) as directory:
        if not os.path.samestat(os.fstat(directory), local_identity):
            return None
        info = os.stat("t", dir_fd=directory, follow_symlinks=False)
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
        return None
    return {"path": str(local_root / "t"), "device": info.st_dev, "inode": info.st_ino}


def save_recovery_receipt(scratch, ledger_name, local_root, local_identity, primary, *, named, identities):
    if named:
        primary.add_note(f"Private synthetic exposure journal retained in {scratch.root}")
    else:
        primary.add_note(
            f"Private exposure directory retained with run {scratch.root.name}, "
            f"device {scratch.identity.st_dev}, inode {scratch.identity.st_ino}. Its visible name changed."
        )
    terminal_socket = {"status": "unavailable"}
    try:
        terminal_socket = terminal_socket_identity(local_root, local_identity) or terminal_socket
    except BaseException:
        # Volatile socket inspection cannot prevent the durable receipt.
        pass
    try:
        verify_private_directory(os.fstat(scratch.directory))
        terminal_scratch = ({"path": str(local_root), "device": local_identity.st_dev, "inode": local_identity.st_ino}
                            if local_identity is not None else {"status": "unavailable"})
        receipt = {
            "run_id": scratch.root.name,
            "exposure_ledger": ledger_name,
            "terminal_scratch": terminal_scratch,
            "terminal_socket": terminal_socket,
        }
        if identities:
            receipt["owned_ledger_identities"] = identities
        write_capture_evidence(scratch.directory, "recovery.json", receipt)
    except BaseException as receipt_error:
        primary.add_note(f"Unable to save private recovery receipt: {type(receipt_error).__name__}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--musl-libraries", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--case", choices=("tools", "hosted", "undeclared", "search", *sorted(INTERACTION_CASES)), default="tools")
    args = parser.parse_args()
    verify_scope()
    with measured_command(args.binary, args.musl_libraries, search=args.case == "search") as command:
        capture(command, args.evidence, args.case)


if __name__ == "__main__":
    main()
