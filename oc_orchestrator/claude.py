"""Verify the local Claude Agent launch against independent synthetic namespaces."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, suppress
import hashlib
import hmac
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
from tempfile import mkdtemp
from threading import Event, Lock, Thread
import time

from .capture import CaptureError, capture, kill_group
from .claude_protocol import (
    LIMIT, REPLY, STOCK_MODEL, ProtocolError, decode, encode, require, select_native, validate_control_output, validate_sdk,
    validate_turn_output,
)
from .runtime import Failure, verify_result


OPENCODE_SHA256 = "2e0e4656521ca56e5ba16a00d48429958b8105b3fa6466710a4350e68759381f"
SYSTEM_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
PYTHON = "/usr/bin/python3"
PACKAGE = Path(__file__).resolve().parent


def config():
    return {
        "model": STOCK_MODEL, "update": "disable", "share": "disabled",
        "plugins": ["-opencode.tool.*"],
        "agents": {"fixture": {"mode": "primary",
                               "permissions": [{"action": "*", "resource": "*", "effect": "deny"}]}},
        "policies": [{"action": action, "resource": "*", "effect": "deny"}
                     for action in ("provider.use", "tool.use", "mcp.use", "skill.use", "plugin.use", "websearch.use")]
                    + [{"action": "provider.use", "resource": "claude-agent", "effect": "allow"}],
    }


def private_write(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content)


def fixture_instances(root):
    # The launcher checks its own package. Apply the same checks before importing the shared config reader.
    package = PACKAGE.parent / "oc_providers"
    for path in (package, package / "__init__.py", package / "config.py", package / "contracts.py"):
        info = path.lstat()
        kind = stat.S_ISDIR if path == package else stat.S_ISREG
        if not kind(info.st_mode) or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
            raise Failure("Claude fixture provider config source is untrusted")

    from oc_providers.config import load_provider_config
    from oc_providers.contracts import InstancePreflight, ProviderIntegrityError, ReadinessState

    directory = root / "provider-config"
    directory.mkdir(mode=0o700)
    private_write(directory / "providers.toml",
        b'[launch]\ndefault_provider = "claude/personal"\n'
        b'[providers.claude.personal]\nenabled = true\nauth_mode = "subscription"\n'
        b'[providers.claude.team]\nenabled = true\nauth_mode = "subscription"\n'
    )
    try:
        loaded = load_provider_config(config_dir=directory, sandbox_dir=root / "workspace")
    except ProviderIntegrityError:
        raise Failure("Claude fixture provider configuration could not be loaded") from None
    instances = {}
    if loaded is None or loaded.launch.default_provider is None:
        raise Failure("Claude fixture provider configuration has no default")
    for spec in loaded.instances:
        if (spec.kind != "claude" or not spec.enabled or spec.auth_mode != "subscription"
                or spec.credential_ref is not None or spec.cli_path is not None):
            raise Failure("Claude fixture provider configuration is unsupported")
        instances[spec.scoped_id] = InstancePreflight(
            spec, ReadinessState.READY, models=("haiku",), route_policy="offline fixture",
        )
    selected = next((item.spec.scoped_id for item in instances.values()
                     if item.spec.qualified_name == "/".join(loaded.launch.default_provider)), None)
    if selected is None:
        raise Failure("Claude fixture provider configuration has an unavailable default")
    return instances, selected


def seed(root):
    program = root / "program"
    config_dir = program / "config" / "opencode"
    for directory in (program, config_dir.parent, config_dir):
        directory.mkdir(mode=0o700)
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
            "--symlink", "usr/lib64", "/lib64", "--ro-bind", str(root / "program"), "/opt/proof"]


def open_code_command(root, stage):
    return [*namespace(root), "--bind", str(root / "state" / stage), "/state",
            "--ro-bind", str(root / "workspace"), "/workspace", "--chdir", "/workspace",
            "--ro-bind", str(root / "frontend" / stage), "/frontend",
            "--ro-bind", str(root / "socket" / stage), "/broker",
            "--setenv", "HOME", "/state", "--setenv", "XDG_CONFIG_HOME", "/opt/proof/config",
            "--setenv", "XDG_CACHE_HOME", "/state/cache", "--setenv", "XDG_DATA_HOME", "/state/data",
            "--setenv", "XDG_STATE_HOME", "/state/xdg-state", "--setenv", "TMPDIR", "/state/tmp",
            "--setenv", "OPENCODE_CLAUDE_PATH", "/opt/proof/claude-shim",
            "--setenv", "OPENCODE_DISABLE_MODELS_FETCH", "1", "--", PYTHON, "-IB", "/opt/proof/claude_launch.py", stage]


def native_command(root, slot, session, digest):
    return [*namespace(root), "--ro-bind", str(root / "profiles" / slot), "/private/native-profile",
            "--chdir", "/", "--", PYTHON, "-IB", "/opt/proof/claude_fixture.py", session or "", digest]


class RetirementUnverified(RuntimeError):
    """A native process could not be confirmed retired."""


@contextmanager
def native_process(command):
    # Popen.__exit__ waits without a deadline. Own the unbuffered pipes and the wait here.
    process = subprocess.Popen(command, env=SYSTEM_ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, start_new_session=True, bufsize=0)
    try:
        yield process
    finally:
        for pipe in (process.stdin, process.stdout):
            with suppress(OSError):
                pipe.close()
        try:
            if process.poll() is None:
                with suppress(OSError):
                    kill_group(process)
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            raise RetirementUnverified("native fixture retirement could not be verified") from None


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

    def verify_quiet(self):
        require(not self.buffer and not select.select([self.fd], [], [], 0)[0])

    def verify_closed(self):
        require(not self.buffer and select.select([self.fd], [], [], 3)[0])
        require(os.read(self.fd, 1) == b"")


class Broker:
    def __init__(self, root, lifeline, instances, profiles):
        self.root, self.lifeline, self.instances, self.profiles = root, lifeline, instances, profiles
        self.proposal_proof = None
        self.selection = None
        self.turn_proof = None
        self.epoch = 0
        self.sends = 0
        self.receipt = None
        self.proposal = None
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
        with self.lock:
            self.stop.set()
            for client in self.clients:
                with suppress(OSError):
                    client.shutdown(socket.SHUT_RDWR)
            for child in self.children:
                if child.poll() is None:
                    kill_group(child)

    def offer(self, slot, model):
        with self.lock:
            self.lifeline.check()
            require(not self.stop.is_set() and model in self.instances[slot].models)
            self.epoch += 1
            self.proposal = self.epoch, slot, model
            self.proposal_proof = secrets.token_hex(32)
            return {"slot": slot, "model": model, "epoch": self.epoch, "proof": self.proposal_proof}

    def identify(self, route, *, inference=False):
        require(type(route) is dict and set(route) == {"slot", "model", "epoch", "proof"})
        slot, model, epoch, proof = (route[key] for key in ("slot", "model", "epoch", "proof"))
        require(type(slot) is str and slot in self.instances)
        require(type(proof) is str and len(proof) == 64 and proof.isascii())
        require(type(model) is str and model in self.instances[slot].models and type(epoch) is int)
        binding = epoch, slot, model
        with self.lock:
            self.lifeline.check()
            require(not self.stop.is_set())
            if binding == self.proposal and not inference:
                expected = self.proposal_proof
            else:
                require(binding == self.selection and (not inference or self.sends == 0))
                expected = self.turn_proof
            require(hmac.compare_digest(expected, proof))
        return binding

    def activate(self, binding, observed_model):
        with self.lock:
            self.lifeline.check()
            if self.errors or self.clients or self.children:
                raise Failure("Claude fixture broker did not complete discovery cleanly")
            require(not self.stop.is_set() and self.proposal == binding and observed_model == STOCK_MODEL)
            self.turn_proof = secrets.token_hex(32)
            self.selection = binding
            self.proposal = self.proposal_proof = None
            epoch, slot, model = binding
            return {"slot": slot, "model": model, "epoch": epoch, "proof": self.turn_proof}

    def cancel(self):
        with self.lock:
            self.proposal = self.proposal_proof = None

    def dispatch(self, binding, write):
        with self.lock:
            self.lifeline.check()
            require(not self.stop.is_set() and self.selection == binding and self.sends == 0)
            self.sends += 1
            write()

    def serve(self, client):
        with client, self.own(self.clients, client):
            client.settimeout(8)
            _pid, uid, _gid = struct.unpack("3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(uid == os.getuid())
            with client.makefile("rb") as stream:
                header = decode(stream.readline(LIMIT + 1))
                require(set(header) == {"route", "argv"})
                session = select_native(header["argv"])
                binding = self.identify(header["route"], inference=session is not None)
                _epoch, slot, _model = binding
                command = native_command(self.root, slot, session, self.profiles[slot])
                with native_process(command) as process, self.own(self.children, process):
                    self.exchange(client, stream, process, binding, session)

    def exchange(self, client, stream, process, binding, session):
        output = NativeFrames(process.stdout)
        for position in range(2 if session is not None else 3):
            self.lifeline.check()
            request = validate_sdk(decode(stream.readline(LIMIT + 1)), session, position)
            if request["type"] == "user":
                self.finish_turn(client, process, output, binding, session, request)
                return
            process.stdin.write(encode(request))
            process.stdin.flush()
            reply = validate_control_output(decode(output.next_line()), request)
            if session is None and position == 2:
                process.stdin.close()
                output.verify_closed()
                require(process.wait(timeout=2) == 0)
            else:
                output.verify_quiet()
            self.lifeline.check()
            client.sendall(encode(reply))

    def finish_turn(self, client, process, output, binding, session, request):
        def send_prompt():
            process.stdin.write(encode(request))
            process.stdin.close()

        output.verify_quiet()
        self.dispatch(binding, send_prompt)
        replies = validate_turn_output([decode(output.next_line()) for _ in range(8)], session)
        output.verify_closed()
        require(process.wait(timeout=2) == 0)
        with self.lock:
            self.lifeline.check()
            require(not self.stop.is_set() and binding == self.selection)
            self.receipt = binding
            client.sendall(b"".join(encode(reply) for reply in replies))

    def record_error(self, error):
        with self.lock:
            self.errors.append(error)

    def serve_job(self, client):
        try:
            self.serve(client)
        except Exception as error:
            self.record_error(error)

    def poll(self, listener, finished):
        with ThreadPoolExecutor(max_workers=3) as pool:
            jobs = []
            try:
                while not (finished.is_set() or self.stop.is_set()) and self.lifeline.active():
                    try:
                        client, _address = listener.accept()
                    except TimeoutError:
                        continue
                    if finished.is_set() or len(jobs) == 5:
                        client.close()
                        self.record_error(ProtocolError("unexpected queued Claude fixture request"))
                        break
                    jobs.append(pool.submit(self.serve_job, client))

                if finished.is_set() and not self.stop.is_set():
                    self.check_finished_phase(listener, jobs)
            except (OSError, RuntimeError) as error:
                self.record_error(error)

    def check_finished_phase(self, listener, jobs):
        listener.setblocking(False)
        try:
            client, _address = listener.accept()
        except BlockingIOError:
            pass
        else:
            client.close()
            self.record_error(ProtocolError("unexpected queued Claude fixture request"))
        if any(not job.done() for job in jobs):
            self.record_error(ProtocolError("Claude fixture phase ended with active requests"))


def remove_scratch(root):
    # These directories can contain frontend-owned mode 000 trees. Restore access
    # only to real directories, after the frontend and broker have been retired.
    directories = [root]
    while directories:
        directory = directories.pop()
        mode = directory.lstat().st_mode
        if not stat.S_ISDIR(mode):
            raise Failure("Claude fixture scratch directory is invalid")
        if mode & stat.S_IRWXU != stat.S_IRWXU:
            # An O_PATH descriptor pins the directory without requiring traversal permission.
            # The proc link works on Linux kernels without fchmodat2.
            fd = os.open(directory, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.chmod(f"/proc/self/fd/{fd}", stat.S_IMODE(os.fstat(fd).st_mode) | stat.S_IRWXU)
            finally:
                os.close(fd)
        with os.scandir(directory) as entries:
            directories.extend(Path(entry.path) for entry in entries if entry.is_dir(follow_symlinks=False))
    shutil.rmtree(root)


def run_frontend(root, stage, lifeline, broker):
    return capture(open_code_command(root, stage), env=SYSTEM_ENV, timeout=25, limit=LIMIT, lifeline=lifeline,
                   on_revoke=broker.retire)


def run_stage(root, stage, lifeline, broker):
    address = root / "socket" / stage / "native.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        # The parent directory is already private. Tighten the socket before listening.
        listener.bind(str(address))
        address.chmod(0o600)
        listener.listen(3)
        listener.settimeout(.15)
        finished = Event()
        thread = Thread(target=broker.poll, args=(listener, finished), daemon=True)
        try:
            try:
                thread.start()
            except (OSError, RuntimeError):
                raise Failure("Claude fixture broker could not start") from None
            return run_frontend(root, stage, lifeline, broker)
        finally:
            finished.set()
            try:
                if thread.ident is not None:
                    thread.join(timeout=10)
            except (OSError, RuntimeError):
                raise RetirementUnverified("Claude fixture broker retirement could not be verified") from None
            if thread.is_alive():
                raise RetirementUnverified("Claude fixture broker is still running")
            with broker.lock:
                if (broker.children or broker.clients
                        or any(isinstance(error, RetirementUnverified) for error in broker.errors)):
                    raise RetirementUnverified("Claude fixture broker retirement could not be verified")


def run_proof(lifeline):
    root = Path(mkdtemp(prefix="oc-claude-proof-", dir="/tmp"))
    removable = True
    try:
        for name in ("workspace", "state", "state/discovery", "state/discovery/tmp", "state/turn", "state/turn/tmp",
                     "socket", "socket/discovery", "socket/turn", "profiles", "frontend", "frontend/discovery",
                     "frontend/turn"):
            (root / name).mkdir(mode=0o700)
        private_write(root / "workspace" / "job.txt", b"synthetic job data")
        seed(root)
        instances, selected = fixture_instances(root)
        profiles = {}
        for slot in instances:
            marker = secrets.token_bytes(48)
            private_write(root / "profiles" / slot, marker)
            profiles[slot] = hashlib.sha256(marker).hexdigest()
        broker = Broker(root, lifeline, instances, profiles)
        try:
            route = broker.offer(selected, "haiku")
            approved = broker.identify(route)
            private_write(root / "frontend" / "discovery" / "route.json", json.dumps(route).encode())
            discovery = run_stage(root, "discovery", lifeline, broker)
            with broker.lock:
                closed_discovery = not broker.errors and not broker.sends
            if discovery.returncode or discovery.stdout != STOCK_MODEL.encode() + b"\n" or not closed_discovery:
                raise Failure("local Claude fixture could not verify closed discovery")
            # A separate listener and proof are admitted only after discovery has closed cleanly.
            turn_route = broker.activate(approved, STOCK_MODEL)
            private_write(root / "frontend" / "turn" / "route.json", json.dumps(turn_route).encode())
            result = run_stage(root, "turn", lifeline, broker)
        except (CaptureError, subprocess.TimeoutExpired):
            raise Failure("local Claude fixture did not complete within its bound") from None
        except ProtocolError:
            raise Failure("local Claude fixture could not bind the approved route") from None
        except RetirementUnverified:
            removable = False
            raise Failure(f"Claude fixture retirement could not be verified: {root}") from None
        finally:
            try:
                broker.retire()
            except (OSError, RuntimeError):
                removable = False
                raise Failure(f"Claude fixture retirement could not be verified: {root}") from None
        lifeline.check()
        if result.returncode or broker.errors or broker.sends != 1 or broker.receipt != approved:
            raise Failure("local Claude fixture could not verify the isolated OpenCode turn")
        reply = verify_result(result.stdout, expected=REPLY)
    finally:
        if removable:
            try:
                remove_scratch(root)
            except (OSError, NotImplementedError):
                raise Failure(f"Claude fixture scratch could not be removed: {root}") from None
    if root.exists():
        raise Failure(f"Claude fixture scratch could not be removed: {root}")
    lifeline.check()
    return reply
