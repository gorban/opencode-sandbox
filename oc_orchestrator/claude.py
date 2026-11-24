"""Verify the local Claude Agent launch against independent synthetic namespaces."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, suppress
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import stat
import struct
import subprocess
from tempfile import TemporaryDirectory
from threading import Event, Lock, Thread

from .capture import capture
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


def seed(root, binary):
    program = root / "program"
    config_dir = program / "config" / "opencode"
    config_dir.mkdir(parents=True)
    (config_dir / "opencode.jsonc").write_text(json.dumps(config()))
    target = program / "opencode"
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
            "--dev", "/dev", "--tmpfs", "/tmp", "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin",
            "--symlink", "usr/lib64", "/lib64", "--ro-bind", str(root / "program"), "/opt/proof",
            "--ro-bind", str(root / "workspace"), "/workspace", "--chdir", "/workspace"]


def open_code_command(root):
    return [*namespace(root), "--bind", str(root / "state"), "/state",
            "--ro-bind", str(root / "socket"), "/broker",
            "--setenv", "HOME", "/state", "--setenv", "XDG_CONFIG_HOME", "/opt/proof/config",
            "--setenv", "XDG_CACHE_HOME", "/state/cache", "--setenv", "XDG_DATA_HOME", "/state/data",
            "--setenv", "XDG_STATE_HOME", "/state/xdg-state",
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
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)


class Broker:
    def __init__(self, root, digest, lifeline):
        self.root, self.digest, self.lifeline = root, digest, lifeline
        self.turn = False
        self.lock = Lock()
        self.stop = Event()
        self.errors = []

    def serve(self, client):
        with client:
            client.settimeout(8)
            _pid, uid, _gid = struct.unpack("3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(uid == os.getuid())
            with client.makefile("rb") as stream:
                session = select_native(decode(stream.readline(LIMIT + 1)).get("argv"))
                with native_process(native_command(self.root, session, self.digest)) as process:
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
                        self.forward(client, process.stdout, message["type"] == "user")

    def forward(self, client, output, streaming):
        for _ in range(16 if streaming else 1):
            raw = output.readline(LIMIT + 1)
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


def run_proof(lifeline, binary):
    with TemporaryDirectory(prefix="oc-claude-proof-") as scratch:
        root = Path(scratch)
        for name in ("workspace", "state", "socket"):
            (root / name).mkdir(mode=0o700)
        seed(root, binary)
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
                result = capture(open_code_command(root), env=SYSTEM_ENV, timeout=25, limit=LIMIT, lifeline=lifeline)
            finally:
                broker.stop.set()
                thread.join()
        lifeline.check()
        if result.returncode or broker.errors or not broker.turn:
            raise Failure("local Claude fixture could not verify the isolated OpenCode turn")
        return verify_result(result.stdout, expected=REPLY)
