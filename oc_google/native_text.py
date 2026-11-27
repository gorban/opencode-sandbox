"""Approved fixed-text checks through Google's native workstation ACP client."""

from contextlib import ExitStack, contextmanager
from hashlib import file_digest
import json
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import tempfile
import threading
import time

_AGY_DIGEST = "7b004d26c3fdea25a7c9d456de4bfaccef4be1e4cc7fd6db628859c5c941fa2d"
_SYSTEM_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
_CA = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
_MAX_FRAME = 256 * 1024
_MODEL_ID = re.compile(r"gemini[A-Za-z0-9._-]{1,100}\Z", re.ASCII)
_STARTUP_UPDATES = {"available_commands_update", "current_mode_update", "config_option_update",
                    "session_info_update", "usage_update"}
_PASSIVE_TURN_UPDATES = _STARTUP_UPDATES | {"agent_thought_chunk", "plan"}
_TOOL_UPDATES = {"tool_call", "tool_call_update"}
_AGENT = "oc-sandbox-text"
_PROMPT = "Reply with exactly: ok. Do not use any tools."


class NativeCliTextError(RuntimeError):
    """A fixed workstation diagnostic that contains no native reply data."""


def _retire(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(3)
    for stream in (process.stdin, process.stdout):
        if stream is not None:
            stream.close()


def _pinned_agy(clean, home):
    from oc_providers.config import _open_trusted_dir

    directory = _open_trusted_dir(home / ".local/bin", sandbox=(home / "opencode-sandbox").resolve())
    if directory is None:
        raise NativeCliTextError("Install the pinned Antigravity CLI on the workstation first.")
    clean.callback(os.close, directory)
    fd = os.open("agy", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    clean.callback(os.close, fd)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid())
            or info.st_mode & 0o022 or not info.st_mode & 0o111 or info.st_nlink != 1):
        raise NativeCliTextError("The workstation Antigravity executable is not trusted.")
    with os.fdopen(os.dup(fd), "rb") as stream:
        if file_digest(stream, "sha256").hexdigest() != _AGY_DIGEST:
            raise NativeCliTextError("The workstation Antigravity executable differs from the tested build.")
    return fd


def _write_profile(home):
    app = home / ".gemini/antigravity-acp"
    app.mkdir(mode=0o700, parents=True)
    settings = {
        "auth": {"type": "oauth-personal"}, "toolPermission": "strict",
        "allowNonWorkspaceAccess": False, "enableTelemetry": False,
        "permissions": {"deny": [f"{tool}(*)" for tool in
                                 ("read_file", "write_file", "command", "read_url", "execute_url", "mcp")]},
    }
    (app / "settings.json").write_text(json.dumps(settings), encoding="ascii")
    agent = home / ".gemini/config/agents" / _AGENT
    agent.mkdir(mode=0o700, parents=True)
    (agent / "agent.md").write_text(
        f"---\nname: {_AGENT}\ndescription: Return the text requested by the operator.\n"
        "mainAgent: true\nsubagent: false\ntools: []\ninheritMcp: false\ninheritCustomizations: false\n"
        "excludeDefaultComponents: true\ncommandExecutionPolicy: off\n---\n"
        "Respond in plain text. Do not use any tools.\n", encoding="ascii",
    )


def _keyring_proxy(clean, runtime, proxy_socket):
    bus = runtime / "bus"
    proxy_exe = next((path for path in ("/usr/bin/xdg-dbus-proxy", "/run/host/usr/bin/xdg-dbus-proxy")
                      if os.path.isfile(path)), None)
    if proxy_exe is None or not bus.is_socket():
        raise NativeCliTextError("The workstation Secret Service proxy is unavailable.")
    proxy = subprocess.Popen(
        [proxy_exe, f"unix:path={bus}", str(proxy_socket), "--filter", "--talk=org.freedesktop.secrets"],
        env=_SYSTEM_ENV, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    clean.callback(_retire, proxy)
    end = time.monotonic() + 4
    while proxy.poll() is None and not proxy_socket.is_socket() and time.monotonic() < end:
        time.sleep(.025)
    if proxy.poll() is not None or not proxy_socket.is_socket():
        raise NativeCliTextError("The workstation Secret Service proxy could not start.")
    return proxy


def _start_native(clean, fd, home, workspace, proxy_socket):
    argv = [
        "/usr/bin/bwrap", "--unshare-all", "--share-net", "--die-with-parent", "--new-session", "--clearenv",
        "--ro-bind", "/usr/lib64", "/lib64", "--ro-bind", "/usr/lib64", "/usr/lib64",
        "--ro-bind", f"/proc/self/fd/{fd}", "/opt/agy", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
        "--bind", str(home), "/home/provider", "--ro-bind", str(workspace), "/workspace",
        "--ro-bind", str(proxy_socket), "/run/provider-bus", "--ro-bind", _CA, "/etc/ssl/oc-ca.pem",
        "--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf", "--setenv", "SSL_CERT_FILE", "/etc/ssl/oc-ca.pem",
        "--setenv", "HOME", "/home/provider", "--setenv", "GEMINI_HOME", "/home/provider/.gemini",
        "--setenv", "PATH", "/opt", "--setenv", "LANG", "C.UTF-8", "--setenv", "AGY_CLI_DISABLE_AUTO_UPDATE", "true",
        "--setenv", "DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/provider-bus", "--chdir", "/workspace",
        "/opt/agy", "acp", "--gemini-dir", "/home/provider/.gemini", "--app-data-dir", "antigravity-acp",
        "--agent", _AGENT, "--include-default-customizations=false", "--disable-telemetry", "--log-file", "/dev/null",
    ]
    child = subprocess.Popen(argv, env=_SYSTEM_ENV, pass_fds=(fd,), stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    clean.callback(_retire, child)
    return child


class _Acp:
    def __init__(self, child, cancelled=lambda: False):
        self.child = child
        self.input = child.stdin.fileno()
        self.output = child.stdout.fileno()
        self.buffer = bytearray()
        self.number = 0
        self.session = None
        self.cancelled = cancelled
        os.set_blocking(self.input, False)
        os.set_blocking(self.output, False)

    def _frame(self, end):
        from oc_google.native_enrollment_acp import _parse_frame

        while b"\n" not in self.buffer:
            remaining = end - time.monotonic()
            if self.cancelled():
                raise NativeCliTextError("The native ACP owner ended the turn.")
            if len(self.buffer) >= _MAX_FRAME or remaining <= 0:
                raise NativeCliTextError("The native ACP reply exceeded its deadline or size bound.")
            if not select.select([self.output], [], [], min(.1, remaining))[0]:
                continue
            chunk = os.read(self.output, min(65536, _MAX_FRAME - len(self.buffer)))
            if not chunk:
                raise NativeCliTextError("The native ACP server closed before replying.")
            self.buffer.extend(chunk)
        line, _, tail = self.buffer.partition(b"\n")
        self.buffer = tail
        return _parse_frame(bytes(line))

    def request(self, method, params, update, *, seconds=20):
        number = self.send(method, params)
        return self.receive(number, method, update, seconds=seconds)

    def send(self, method, params):
        if self.cancelled():
            raise NativeCliTextError("The native ACP owner ended the turn.")
        self.number += 1
        number = self.number
        packet = json.dumps({"jsonrpc": "2.0", "id": number, "method": method, "params": params}).encode() + b"\n"
        if os.write(self.input, packet) != len(packet):
            raise NativeCliTextError("The native ACP request write did not complete.")
        return number

    def receive(self, number, method, update, *, seconds):
        end = time.monotonic() + seconds
        for _ in range(192):
            frame = self._frame(end)
            if type(frame.get("id")) is int and frame["id"] == number and "method" not in frame:
                result = frame.get("result")
                if frame.keys() == {"jsonrpc", "id", "result"} and type(result) is dict:
                    return result
                error = frame.get("error")
                if method == "session/new" and type(error) is dict and error.get("code") == -32000:
                    raise NativeCliTextError("Native Antigravity could not open an authenticated session.")
                raise NativeCliTextError("Native Antigravity refused the ACP request.")
            if frame.keys() != {"jsonrpc", "method", "params"} or frame["method"] != "session/update":
                raise NativeCliTextError("The native ACP server requested an unexpected callback.")
            params = frame["params"]
            if type(params) is not dict or type(params.get("update")) is not dict:
                raise NativeCliTextError("The native ACP update was invalid.")
            if self.session is not None and params.get("sessionId") != self.session:
                raise NativeCliTextError("The native ACP update named a different session.")
            update(params["update"])
        raise NativeCliTextError("The native ACP update count exceeded its bound.")

    def verify_terminal_tail(self):
        """Stop the exact native peer and require EOF without queued output."""
        if self.child.poll() is None:
            self.child.terminate()
        try:
            self.child.wait(timeout=3)
        except subprocess.TimeoutExpired as error:
            raise NativeCliTextError("Native ACP retirement could not be verified.") from error
        if self.buffer or not select.select([self.output], [], [], .2)[0]:
            raise NativeCliTextError("Native ACP left an unverified terminal tail.")
        try:
            tail = os.read(self.output, _MAX_FRAME + 1)
        except BlockingIOError as error:
            raise NativeCliTextError("Native ACP terminal output stayed open.") from error
        if tail:
            raise NativeCliTextError("Native ACP sent data after the terminal event.")


def _startup_update(update):
    kind = update.get("sessionUpdate")
    if type(kind) is not str or kind not in _STARTUP_UPDATES:
        raise NativeCliTextError("The native ACP server sent an unexpected startup update.")


def _option(result, ident):
    options = result.get("configOptions")
    matches = [value for value in options if type(value) is dict and value.get("id") == ident] if type(options) is list else []
    if len(matches) != 1 or type(matches[0].get("options")) is not list:
        raise NativeCliTextError("The native ACP server did not advertise the required option.")
    return matches[0]


def _select(client, config, ident, choice):
    offered = {row.get("value") for row in config["options"]
               if type(row) is dict and type(row.get("value")) is str}
    if choice not in offered:
        raise NativeCliTextError("The selected option is unavailable on this Antigravity profile.")
    if config.get("currentValue") != choice:
        result = client.request("session/set_config_option",
                                {"sessionId": client.session, "configId": ident, "value": choice}, _startup_update)
        if _option(result, ident).get("currentValue") != choice:
            raise NativeCliTextError("The native ACP server did not confirm the requested option.")


def _open_session(client, requested, client_name="oc-sandbox"):
    init = client.request("initialize", {"protocolVersion": 1, "clientCapabilities": {},
                                         "clientInfo": {"name": client_name, "version": "0"}}, _startup_update)
    if type(init.get("protocolVersion")) is not int or init["protocolVersion"] != 1:
        raise NativeCliTextError("Native Antigravity did not negotiate ACP v1.")
    result = client.request("session/new", {"cwd": "/workspace", "mcpServers": []}, _startup_update)
    client.session = result.get("sessionId")
    if type(client.session) is not str or not 0 < len(client.session) <= 256:
        raise NativeCliTextError("The native ACP server did not return a bounded session.")
    _select(client, _option(result, "mode"), "mode", "default")
    config = _option(result, "model")
    choice = requested or config.get("currentValue")
    if type(choice) is not str or not _MODEL_ID.fullmatch(choice):
        raise NativeCliTextError("Select a Gemini model with --model.")
    _select(client, config, "model", choice)
    return choice


def _answer_collector():
    parts = []

    def update(event):
        kind = event.get("sessionUpdate")
        if type(kind) is str:
            if kind in _TOOL_UPDATES:
                raise NativeCliTextError("Native Antigravity reported a tool call. The reply was withheld.")
            if kind in _PASSIVE_TURN_UPDATES:
                return
        content = event.get("content")
        if (kind != "agent_message_chunk" or type(content) is not dict or content.get("type") != "text"
                or type(content.get("text")) is not str):
            raise NativeCliTextError("Native Antigravity returned an unsupported non-text update.")
        parts.append(content["text"])
        if sum(map(len, parts)) > 16:
            raise NativeCliTextError("Native Antigravity returned unexpected text.")

    def answer(result):
        if result.get("stopReason") != "end_turn" or "".join(parts) != "ok":
            raise NativeCliTextError("Native Antigravity did not finish with exact text `ok`.")
        return "ok"

    return update, answer


def _prompt_params(client):
    return {"sessionId": client.session, "prompt": [{"type": "text", "text": _PROMPT}]}


def _one_turn(client):
    update, answer = _answer_collector()
    answer(client.request("session/prompt", _prompt_params(client), update, seconds=45))
    client.verify_terminal_tail()


@contextmanager
def open_native(model, client_name, cancelled=lambda: False):
    from oc_providers.config import _account_home

    if model is not None and not _MODEL_ID.fullmatch(model):
        raise NativeCliTextError("Select a Gemini model with --model.")
    home = _account_home()
    runtime = Path("/run/user") / str(os.geteuid())
    info = runtime.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise NativeCliTextError("The workstation runtime directory is not private.")
    with ExitStack() as clean:
        fd = _pinned_agy(clean, home)
        root = Path(clean.enter_context(tempfile.TemporaryDirectory(prefix="oc-agy-text-", dir=runtime)))
        workspace, profile, sock = root / "workspace", root / "home", root / "bus"
        workspace.mkdir(mode=0o700)
        profile.mkdir(mode=0o700)
        _write_profile(profile)
        proxy = _keyring_proxy(clean, runtime, sock)
        client = _Acp(_start_native(clean, fd, profile, workspace, sock), cancelled)
        selected = _open_session(client, model, client_name)
        _retire(proxy)
        yield client, selected


class _OpenCodeSession:
    def __init__(self, stack, client):
        self._stack = stack
        self._client = client
        self._number = None
        self._retire_lock = threading.Lock()
        self.retirement_confirmed = False
        self.retirement_uncertain = False

    def send_prompt(self):
        if self._number is not None:
            raise NativeCliTextError("The test already used its single native ACP request.")
        self._number = self._client.send("session/prompt", _prompt_params(self._client))

    def complete(self):
        update, answer = _answer_collector()
        result = self._client.receive(self._number, "session/prompt", update, seconds=45)
        text = answer(result)
        self._client.verify_terminal_tail()
        self.retire()
        return text

    def retire(self):
        with self._retire_lock:
            if self.retirement_uncertain:
                raise NativeCliTextError("Native ACP retirement needs independent inspection.")
            if self.retirement_confirmed:
                return
            try:
                self._stack.close()
            except BaseException:
                self.retirement_uncertain = True
                raise
            self.retirement_confirmed = True


@contextmanager
def open_opencode_session(model, cancelled):
    with ExitStack() as stack:
        client, _ = stack.enter_context(open_native(model, "oc-sandbox", cancelled))
        session = _OpenCodeSession(stack.pop_all(), client)
        try:
            yield session
        finally:
            session.retire()


def target_from_config(label):
    """Select the one currently measured OpenCode transcript from trusted TOML."""
    from functools import partial
    from types import SimpleNamespace
    from oc_providers.config import load_provider_config

    config = load_provider_config()
    instance = config.get("google", label) if config is not None else None
    if instance is None or not instance.enabled or instance.auth_mode != "subscription":
        raise NativeCliTextError("The named Google subscription is not enabled in providers.toml.")
    if instance.default_model != "gemini-4-hydrogen":
        raise NativeCliTextError("The OpenCode transcript for this Google model is not qualified.")
    return SimpleNamespace(
        label=instance.label,
        model=instance.default_model,
        system_digest="5e9e60d4323abaec8d0a7d4dc4f0257da8ed1f647f7d48f4a39078e8cfd2d99c",
        system_baseline_label="elgoog",
        open_session=partial(open_opencode_session, instance.default_model),
    )
