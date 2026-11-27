"""Own a disposable Full OpenCode TUI and its single, attended Google route."""

from contextlib import ExitStack, suppress
import json
import os
from pathlib import Path
import pwd
import secrets
import select
import signal
import subprocess
import sys
import termios
import threading
import time

from oc_orchestrator.owner import Lifeline
from oc_orchestrator.protocol import PORT
from oc_orchestrator.runtime import (
    CONTAINER_SHELL, FULL_ID, LABEL, OPEN_CODE, RELAY, RELAY_PYTHON,
    Failure, Placement, check_private_directory, podman, preflight, wait_relay,
)
from oc_providers.contracts import scoped_provider_id

from .control import (
    ArmControl, CONTROL_SOCKET, ControlError, DIRECTORY_FLAGS, owned_run, pinned_name,
    terminal, verify_binding,
)
from .route import TurnBroker


SHELL_TIME = 100
CONTAINER_TIME = 180
LAUNCH_TIME = 150
CLEANUP_TIME = 60
WORKER_CONFIG = "/etc/opencode/opencode.json"
AGENT = "restricted-text"
RELAY_SOURCE = Path(__file__).absolute().parents[1] / "oc_orchestrator/relay.py"


def project(target, worker_token):
    scope = scoped_provider_id("google", target.label)
    display = target.label
    deny = [{"action": "*", "resource": "*", "effect": "deny"}]
    policies = [{"action": action, "resource": "*", "effect": "deny"}
                for action in ("provider.use", "integration.connect", "mcp.use", "skill.use", "websearch.use")]
    policies.append({"action": "provider.use", "resource": scope, "effect": "allow"})
    return {"model": f"{scope}/{target.model}", "defaultAgent": AGENT, "update": "disable", "share": "disabled",
            "snapshots": False, "permissions": deny, "plugins": ["-opencode.tool.*"], "policies": policies,
            "agents": {AGENT: {"mode": "primary", "permissions": deny},
                       **{agent: {"disabled": True}
                          for agent in ("build", "plan", "general", "explore", "title", "summary", "compaction")}},
            "providers": {scope: {"name": display, "package": "@opencode/ai/providers/openai-compatible",
                                 "settings": {"baseURL": f"http://127.0.0.1:{PORT}/v1", "apiKey": worker_token},
                                 "models": {target.model: {"name": f"{target.model} - {display} [subscription]",
                                             "capabilities": {"tools": False, "input": ["text"], "output": ["text"]},
                                             "limit": {"context": 65536, "output": 2048}}}}}}


def seed_file(directory, name, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    with os.fdopen(os.open(name, flags, 0o600, dir_fd=directory), "wb") as seed:
        seed.write(data)
        seed.flush()
        os.fsync(seed.fileno())


def seed_run(directory, target, worker_token, proof):
    seed_file(directory, "opencode.json", json.dumps(project(target, worker_token)).encode("ascii"))
    os.mkdir("relay", 0o700, dir_fd=directory)
    relay = os.open("relay", DIRECTORY_FLAGS, dir_fd=directory)
    try:
        seed_file(relay, "relay.py", RELAY_SOURCE.read_bytes())
        seed_file(relay, "proof", proof)
        os.fsync(relay)
    finally:
        os.close(relay)
    os.fsync(directory)


class ShellPlacement(Placement):
    """Keep an acknowledgement record when container creation or retirement is uncertain."""

    def __init__(self, root, directory, lifeline):
        super().__init__(root, lifeline)
        self.directory = directory
        self.create_unconfirmed = False
        self.peer_unconfirmed = False

    def record(self, state):
        data = {"state": state, "podman_label": LABEL, "value": self.label,
                "containers": self.names, "ids": self.ids}
        seed_file(self.directory, "placement.next", json.dumps(data).encode("ascii"))
        os.replace("placement.next", "placement.json", src_dir_fd=self.directory, dst_dir_fd=self.directory)
        os.fsync(self.directory)

    def create(self, role, *args, **options):
        earlier_attempt = self.attempted
        self.record(f"creating-{role}")
        self.attempted = False
        try:
            return super().create(role, *args, **options)
        finally:
            self.create_unconfirmed |= self.attempted and role not in self.ids
            self.attempted |= earlier_attempt
            self.record(f"created-{role}" if role in self.ids else f"unconfirmed-{role}")

    def remember_recovered(self, role, identifier):
        super().remember_recovered(role, identifier)
        self.record("cleanup-pending")

    def close(self):
        # Keep the first-party identity even if an exact removal or inspection fails.
        try:
            self.record("cleanup-pending")
        finally:
            super().close()
        for identifier in self.ids.values():
            if podman("container", "exists", identifier, check=False).returncode != 1:
                raise Failure("Google shell container retirement could not be confirmed")
        if self.create_unconfirmed or self.peer_unconfirmed:
            raise Failure("Google shell placement needs inspection")


def remove_seeds(path, parent, directory):
    pinned_name(path, parent, directory)
    with suppress(FileNotFoundError):
        relay = os.open("relay", DIRECTORY_FLAGS, dir_fd=directory)
        try:
            for name in ("relay.py", "proof", "provider.sock"):
                with suppress(FileNotFoundError):
                    os.unlink(name, dir_fd=relay)
        finally:
            os.close(relay)
        os.rmdir("relay", dir_fd=directory)
    for name in (CONTROL_SOCKET, "opencode.json", "placement.next"):
        with suppress(FileNotFoundError):
            os.unlink(name, dir_fd=directory)
    pinned_name(path, parent, directory)
    if set(os.listdir(directory)) != {"placement.json"}:
        raise Failure("Google shell retained unexpected runtime state")
    os.unlink("placement.json", dir_fd=directory)
    os.rmdir(path.name, dir_fd=parent)


def create_pair(placement):
    environment = {"HOME": "/job-home", "TMPDIR": "/job-tmp", "XDG_CONFIG_HOME": "/job-home/config",
                   "XDG_CACHE_HOME": "/job-home/cache", "XDG_DATA_HOME": "/job-home/data",
                   "XDG_STATE_HOME": "/job-home/state", "TERM": "xterm-256color", "OPENCODE_CONFIG": WORKER_CONFIG,
                   "OPENCODE_CONFIG_PROJECT_DISABLE": "true", "OPENCODE_DISABLE_MODELS_FETCH": "true",
                   "OPENCODE_DISABLE_FREE_MODELS": "true", "OPENCODE_DISABLE_AUTOUPDATE": "true",
                   "OPENCODE_DISABLE_CLAUDE_CODE": "true"}
    idle = ("-c", f"exec sleep {CONTAINER_TIME}")
    # OpenTUI's pinned Bun FFI loader maps its private shared library from TMPDIR.
    worker = placement.create("open-code", OPEN_CODE, "none", placement.root / "opencode.json",
                              WORKER_CONFIG, environment, ("/job-home", "/job-tmp", "/workspace"),
                              CONTAINER_SHELL, *idle, exec_tmpfs=("/job-tmp",))
    relay = placement.create("relay", RELAY, f"container:{worker}", placement.root / "relay", "/fixture",
                             {}, (), CONTAINER_SHELL, *idle)
    placement.verify_pair(worker, relay)
    if podman("exec", worker, "opencode", "--version").stdout.strip() != b"opencode v2.3.0":
        raise Failure("unexpected Google shell OpenCode version")
    verify_prearm_refusal(relay)
    return worker, relay


def verify_prearm_refusal(relay):
    program = """import errno, os, socket, sys
port = int(sys.argv[1])
if os.listdir('/sys/class/net') != ['lo']:
    raise SystemExit(1)
for table in ('tcp', 'tcp6'):
    with open('/proc/net/' + table) as entries:
        next(entries)
        for row in entries:
            fields = row.split()
            if fields[3] == '0A' and int(fields[1].rsplit(':', 1)[1], 16) == port:
                raise SystemExit(1)
with socket.socket() as client:
    client.settimeout(1)
    if client.connect_ex(('127.0.0.1', port)) != errno.ECONNREFUSED:
        raise SystemExit(1)
"""
    podman("exec", relay, RELAY_PYTHON, "-IB", "-c", program, str(PORT))


def stop_listener(placement, worker, relay):
    placement.identity(relay, "relay")
    podman("rm", "--force", "--time", "1", "--ignore", relay)
    # Observe the original worker namespace after retiring the relay.
    podman("exec", worker, "/usr/bin/awk", "-v", f"port=:{PORT:04X}",
           '$4 == "0A" && substr($2, length($2)-4) == port {live=1} END {exit live}',
           "/proc/net/tcp", "/proc/net/tcp6")


def spawn_podman(*args, tty=False, **stdio):
    uid = os.getuid()
    home = pwd.getpwuid(uid).pw_dir
    runtime = f"/run/user/{uid}"
    env = {"PATH": "/usr/bin:/bin", "HOME": home, "LANG": "C.UTF-8", "TERM": "xterm-256color",
           "XDG_RUNTIME_DIR": runtime, "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime}/bus"}
    command = ["/usr/bin/host-spawn", "--cwd=/", "--pty" if tty else "--no-pty", "--env=", "/usr/bin/env", "-i",
               *(f"{key}={value}" for key, value in env.items()), "/usr/bin/timeout", "--kill-after=2s",
               f"{CONTAINER_TIME}s", "/usr/bin/podman", "--remote=false", "--default-mounts-file=/dev/null", *args]
    env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/host{runtime}/bus"
    return subprocess.Popen(command, env=env, cwd="/", close_fds=True, **stdio)


def attach(worker):
    return spawn_podman("exec", "--tty", "--interactive", "--workdir", "/workspace",
                        worker, "opencode", "/workspace", tty=True)


def prepare_ingress(relay):
    return spawn_podman("exec", "--interactive", relay, RELAY_PYTHON, "-IB", "/fixture/relay.py", "--owner-pipe",
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)


def wait_ingress(ingress, authorized):
    deadline = time.monotonic() + 5
    while authorized() and time.monotonic() < deadline:
        if select.select([ingress.stdout], [], [], .1)[0]:
            if os.read(ingress.stdout.fileno(), 2) == b"R" and ingress.poll() is None:
                return
            break
    raise Failure("Google shell relay could not prepare with the arm terminal present")


def stop_attach(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=2)


def open_peer(placement, peer_scope, target, cancelled):
    stack = ExitStack()
    try:
        session = stack.enter_context(target.open_session(cancelled))
    except BaseException:
        placement.peer_unconfirmed = True
        raise

    def retire():
        try:
            stack.close()
        except BaseException:
            placement.peer_unconfirmed = True
            raise
        finally:
            if getattr(session, "retirement_confirmed", False) is not True:
                placement.peer_unconfirmed = True

    peer_scope.callback(retire)
    return session


def run_placed(target, placement, workspace, parent, directory, lifeline, shell_terminal):
    child = None
    ingress = None
    pending = None
    arm_lock = threading.Lock()
    deadline = time.monotonic() + SHELL_TIME

    def active():
        return (lifeline.active() and time.monotonic() < deadline
                and (child is None or child.poll() is None))

    def authorized():
        with arm_lock:
            return active() and (pending is None or pending())

    proof = secrets.token_bytes(32)
    worker_token = secrets.token_urlsafe(32)
    seed_run(directory, target, worker_token, proof)
    pinned_name(workspace, parent, directory)
    with (ExitStack() as peer_scope,
          TurnBroker(workspace / "relay" / "provider.sock", proof, authorized=authorized, worker_token=worker_token,
                     model=target.model, system_digest=target.system_digest,
                     normalized_label=(target.label, target.system_baseline_label)
                     if hasattr(target, "system_baseline_label") else None) as broker,
          lifeline.revoke_on_loss(broker.revoke)):
        worker, relay = create_pair(placement)
        lifeline.check()
        pinned_name(workspace, parent, directory)

        def activate(confirmed, commit, ready):
            nonlocal ingress, pending
            with arm_lock:
                pending = confirmed
            if not authorized():
                raise Failure("Google shell owner left before arming")
            # Only the exact already-running isolated pair may serve this arm.
            for role, identity in (("open-code", worker), ("relay", relay)):
                if placement.identity(identity, role)["State"]["Running"] is not True:
                    raise Failure("Google shell placement left before arming")
            ingress = prepare_ingress(relay)
            wait_ingress(ingress, authorized)
            session = open_peer(placement, peer_scope, target, broker.cancelled)
            # Commit the exact confirmation under the broker fence while the
            # prepared ingress is still bound without listening.
            broker.arm(session, confirm=commit)
            if not authorized():
                raise Failure("Google shell owner left before the relay could listen")
            if os.write(ingress.stdin.fileno(), b"A") != 1:
                raise Failure("Google shell relay did not receive its arm")
            wait_relay(relay)
            with arm_lock:
                ready()
                pending = None

        with ArmControl(directory, workspace.name, worker, relay, target, shell_terminal) as control:
            print(f"Google shell run {workspace.name}. Open a second terminal to run "
                  f"oc-sandbox google arm {workspace.name} after checking the model.", flush=True)
            child = attach(worker)
            try:
                while active():
                    if control.consumed:
                        broker.receipt()
                        time.sleep(.1)
                    else:
                        control.step(deadline, active, activate)
                lifeline.check()
                if time.monotonic() >= deadline:
                    raise Failure("Google shell reached its time limit")
                return child.returncode
            finally:
                broker.revoke()
                try:
                    if ingress is not None:
                        try:
                            stop_listener(placement, worker, relay)
                        finally:
                            with ingress.stdin, ingress.stdout:
                                stop_attach(ingress)
                finally:
                    stop_attach(child)


def run_owned(target, lifeline, shell_terminal):
    os.umask(0o077)
    preflight()
    lifeline.check()
    with owned_run() as (workspace, parent, directory):
        placement = ShellPlacement(workspace, directory, lifeline)
        try:
            pinned_name(workspace, parent, directory)
            check_private_directory(workspace.parent)
            check_private_directory(workspace)
            placement.record("initializing")
            return run_placed(target, placement, workspace, parent, directory, lifeline, shell_terminal)
        finally:
            try:
                placement.close()
                remove_seeds(workspace, parent, directory)
                print("Google shell placement retired.", flush=True)
            except (Failure, OSError, ControlError):
                print(f"Google shell retained placement {workspace.name} for inspection.", file=sys.stderr, flush=True)
                raise


def interrupt(_number, _frame):
    raise KeyboardInterrupt


def wait_owned(pid, deadline):
    while time.monotonic() < deadline:
        ended, result = os.waitpid(pid, os.WNOHANG)
        if ended:
            return os.waitstatus_to_exitcode(result)
        time.sleep(.1)
    return None


def restore_terminal(settings):
    with suppress(OSError, termios.error):
        termios.tcsetattr(0, termios.TCSANOW, settings)


def run_shell(target):
    """Run the shell in a separate owner process with a kernel pipe lifeline."""
    verify_binding(target.label, target.model)
    if not isinstance(target.system_digest, str) or not FULL_ID.fullmatch(target.system_digest):
        raise Failure("invalid Google shell route digest")
    shell_terminal = terminal(os.getpid())
    settings = termios.tcgetattr(0)
    reader, writer = os.pipe()
    try:
        pid = os.fork()
    except BaseException:
        os.close(reader)
        os.close(writer)
        raise
    if pid == 0:
        os.close(writer)
        exit_code = 1
        try:
            os.setsid()
            exit_code = run_owned(target, Lifeline(reader), shell_terminal)
        except (Failure, ControlError) as error:
            print(f"Google shell: {error}", file=sys.stderr, flush=True)
        except KeyboardInterrupt:
            print("Google shell stopped (KeyboardInterrupt).", file=sys.stderr, flush=True)
        except (OSError, RuntimeError, TypeError, ValueError, KeyError) as error:
            from .native_text import NativeCliTextError

            if isinstance(error, NativeCliTextError):
                print(f"Google shell: {error}", file=sys.stderr, flush=True)
            else:
                print(f"Google shell stopped ({type(error).__name__}).", file=sys.stderr, flush=True)
        os.close(reader)
        restore_terminal(settings)
        os._exit(exit_code if isinstance(exit_code, int) and 0 <= exit_code < 256 else 1)

    os.close(reader)
    previous = {number: signal.signal(number, interrupt) for number in (signal.SIGHUP, signal.SIGTERM)}
    status = None
    try:
        status = wait_owned(pid, time.monotonic() + LAUNCH_TIME)
        if status is None:
            raise Failure("Google shell owner reached its time limit")
        return status if status >= 0 else 1
    except KeyboardInterrupt:
        return 130
    finally:
        os.close(writer)
        try:
            if status is None and wait_owned(pid, time.monotonic() + CLEANUP_TIME) is None:
                with suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
                raise Failure("Google shell owner cleanup was not confirmed")
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)
            restore_terminal(settings)
