"""Verify the local Claude Agent launch against independent synthetic namespaces."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, suppress
import hashlib
import json
import os
from pathlib import Path
import pwd
import select
import secrets
import shutil
import socket
import stat
import struct
import subprocess
from tempfile import TemporaryDirectory
from threading import Event, Lock, Thread
import time

from .capture import CaptureError, capture, kill_group
from .claude_protocol import LIMIT, REPLY, ProtocolError, decode, require, select_native, validate_sdk
from .runtime import Failure, verify_result


OPENCODE_SHA256 = "2e0e4656521ca56e5ba16a00d48429958b8105b3fa6466710a4350e68759381f"
SYSTEM_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
PYTHON = "/usr/bin/python3"
PACKAGE = Path(__file__).resolve().parent


def config():
    return {
        "model": "claude-agent/haiku", "update": "disable", "share": "disabled",
        "plugins": ["-opencode.tool.*"],
        "agents": {"fixture": {"mode": "primary",
                               "permissions": [{"action": "*", "resource": "*", "effect": "deny"}]}},
        "policies": [{"action": action, "resource": "*", "effect": "deny"}
                     for action in ("provider.use", "tool.use", "mcp.use", "skill.use", "plugin.use", "websearch.use")]
                    + [{"action": "provider.use", "resource": "claude-agent", "effect": "allow"}],
    }


def seed(root):
    program = root / "program"
    config_dir = program / "config" / "opencode"
    config_dir.mkdir(parents=True)
    (config_dir / "opencode.jsonc").write_text(json.dumps(config()))
    target = program / "opencode"
    binary = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".cache/oc-sandbox/fixtures/opencode-2.3.0"
    fd = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source, target.open("xb") as output:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise Failure("OpenCode fixture is not a regular file")
        copied = 0
        digest = hashlib.sha256()
        while chunk := source.read(1024 * 1024):
            copied += len(chunk)
            if copied > 512 * 1024 * 1024:
                raise Failure("OpenCode fixture exceeded its size bound")
            digest.update(chunk)
            output.write(chunk)
    if digest.hexdigest() != OPENCODE_SHA256:
        raise Failure("OpenCode fixture digest differs from the pinned release")
    target.chmod(0o500)
    for name in ("claude_protocol.py", "claude_fixture.py", "claude_launch.py"):
        shutil.copyfile(PACKAGE / name, program / name)
    shutil.copyfile(program / "claude_fixture.py", program / "claude-shim")
    (program / "claude-shim").chmod(0o500)


def namespace(root):
    return ["/usr/bin/bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--proc", "/proc",
            "--dev", "/dev", "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin",
            "--symlink", "usr/lib64", "/lib64", "--ro-bind", str(root / "program"), "/opt/proof",
            "--ro-bind", str(root / "workspace"), "/workspace", "--chdir", "/workspace"]


def open_code_command(root):
    return [*namespace(root), "--bind", str(root / "state"), "/state",
            "--ro-bind", str(root / "socket"), "/broker",
            "--setenv", "HOME", "/state", "--setenv", "XDG_CONFIG_HOME", "/opt/proof/config",
            "--setenv", "XDG_CACHE_HOME", "/state/cache", "--setenv", "XDG_DATA_HOME", "/state/data",
            "--setenv", "XDG_STATE_HOME", "/state/xdg-state", "--setenv", "TMPDIR", "/state/tmp",
            "--setenv", "OPENCODE_CLAUDE_PATH", "/opt/proof/claude-shim",
            "--setenv", "OPENCODE_DISABLE_MODELS_FETCH", "1", "--", PYTHON, "-IB", "/opt/proof/claude_launch.py"]


def native_command(root, session, digest):
    return [*namespace(root), "--ro-bind", str(root / "native-profile"), "/private/native-profile",
            "--", PYTHON, "-IB", "/opt/proof/claude_fixture.py", session or "", digest]


@contextmanager
def native_process(command):
    with subprocess.Popen(command, env=SYSTEM_ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, start_new_session=True) as process:
        try:
            yield process
        finally:
            if process.poll() is None:
                kill_group(process)
            process.wait(timeout=2)


class NativeFrames:
    def __init__(self, pipe):
        self.fd = pipe.fileno()
        self.buffer = b""

    def next_line(self):
        deadline = time.monotonic() + 3
        while b"\n" not in self.buffer:
            remaining = deadline - time.monotonic()
            require(remaining > 0 and select.select([self.fd], [], [], remaining)[0])
            chunk = os.read(self.fd, 8192)
            require(chunk and len(self.buffer) + len(chunk) <= LIMIT)
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b"\n", 1)
        return line + b"\n"


class Broker:
    def __init__(self, root, digest, lifeline):
        self.root, self.digest, self.lifeline = root, digest, lifeline
        self.turn = False
        self.lock = Lock()
        self.stop = Event()
        self.errors = []
        self.clients = set()
        self.children = set()

    @contextmanager
    def own(self, registry, item):
        with self.lock:
            require(not self.stop.is_set())
            registry.add(item)
        try:
            yield
        finally:
            with self.lock:
                registry.discard(item)

    def retire(self):
        self.stop.set()
        with self.lock:
            for client in self.clients:
                with suppress(OSError):
                    client.shutdown(socket.SHUT_RDWR)
            for child in self.children:
                if child.poll() is None:
                    kill_group(child)

    def serve(self, client):
        with client, self.own(self.clients, client):
            client.settimeout(8)
            _pid, uid, _gid = struct.unpack("3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(uid == os.getuid())
            with client.makefile("rb") as stream:
                session = select_native(decode(stream.readline(LIMIT + 1)).get("argv"))
                with (native_process(native_command(self.root, session, self.digest)) as process,
                      self.own(self.children, process)):
                    output = NativeFrames(process.stdout)
                    count = 2 if session is not None else 3
                    for position in range(count):
                        self.lifeline.check()
                        raw = stream.readline(LIMIT + 1)
                        message = decode(raw)
                        validate_sdk(message, session, position)
                        if message["type"] == "user":
                            with self.lock:
                                require(not self.turn)
                                self.turn = True
                        process.stdin.write(raw)
                        process.stdin.flush()
                        self.forward(client, output, message["type"] == "user")

    def forward(self, client, output, streaming):
        for _ in range(16 if streaming else 1):
            raw = output.next_line()
            message = decode(raw)
            self.lifeline.check()
            client.sendall(raw)
            if not streaming or message.get("type") == "result":
                return
        raise ProtocolError("Claude fixture response exceeded its frame bound")

    def poll(self, listener):
        with ThreadPoolExecutor(max_workers=3) as pool:
            jobs = []
            while not self.stop.is_set() and self.lifeline.active():
                try:
                    client, _address = listener.accept()
                except TimeoutError:
                    continue
                if len(jobs) == 4:
                    client.close()
                    self.errors.append(ProtocolError("too many Claude SDK process requests"))
                    break
                jobs.append(pool.submit(self.serve, client))
            for job in jobs:
                failure = job.exception()
                if failure is not None:
                    self.errors.append(failure)


def run_proof(lifeline):
    with TemporaryDirectory(prefix="oc-claude-proof-") as scratch:
        root = Path(scratch)
        for name in ("workspace", "state/tmp", "socket"):
            (root / name).mkdir(mode=0o700, parents=True)
        seed(root)
        marker = secrets.token_bytes(48)
        (root / "native-profile").write_bytes(marker)
        broker = Broker(root, hashlib.sha256(marker).hexdigest(), lifeline)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(root / "socket" / "native.sock"))
            listener.listen(3)
            listener.settimeout(.15)
            thread = Thread(target=broker.poll, args=(listener,))
            thread.start()
            try:
                result = capture(open_code_command(root), env=SYSTEM_ENV, timeout=25, limit=LIMIT, lifeline=lifeline,
                                 on_revoke=broker.retire)
            except (CaptureError, subprocess.TimeoutExpired):
                raise Failure("local Claude fixture did not complete within its bound") from None
            finally:
                broker.retire()
                thread.join(timeout=10)
                if thread.is_alive():
                    raise Failure("Claude fixture retirement could not be verified")
        lifeline.check()
        if result.returncode or broker.errors or not broker.turn:
            raise Failure("local Claude fixture could not verify the isolated OpenCode turn")
        return verify_result(result.stdout, expected=REPLY)
