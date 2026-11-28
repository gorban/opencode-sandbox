"""Run one sealed disposable guest fixture and own its paired attestations."""

from contextlib import contextmanager
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time


CAPSULE = Path("/home/.oc-gemini-cold-proof")
SOURCE = CAPSULE / "source"
CONTROLLER = CAPSULE / "google_home_controller.py"
MANIFEST = CAPSULE / "controller-manifest.json"
DRIVER = "tests/google_connect_driver.py"
ACCOUNT = "oc-gemini-proof"
HOME = "/home/oc-gemini-proof"
DEVBOX = "oc-proof-devbox"
PYTHON = "/usr/bin/python3"
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
POSITIVE = (b"Verified three named offline catalogs, two Flash candidates, zero prompts and six retired runtimes.\n"
            b"Scoped native inventory empty.\n")
FRAME_LIMIT = 4098
READY = b"R"
START = b"S"
OUTCOME = b"O"
RELEASE = b"L"
RETIRED = b"D"


class ControllerRefused(RuntimeError):
    """The exact fixture or protected controller deployment could not be verified."""


def require(condition):
    if not condition:
        raise ControllerRefused("Protected offline Google controller refused.")


def protected_directory(path):
    for leaf in (*reversed(path.parents), path):
        node = leaf.lstat()
        require(stat.S_ISDIR(node.st_mode) and node.st_uid == 0 and not node.st_mode & 0o022)


def protected_bytes(path, limit):
    protected_directory(path.parent)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags), "rb") as stream:
        original = os.fstat(stream.fileno())
        require(stat.S_ISREG(original.st_mode) and original.st_uid == 0 and original.st_nlink == 1
                and stat.S_IMODE(original.st_mode) == 0o444 and 0 < original.st_size <= limit)
        payload = stream.read(limit + 1)
        current = os.fstat(stream.fileno())
        require(len(payload) == original.st_size == current.st_size
                and original.st_mtime_ns == current.st_mtime_ns and original.st_ctime_ns == current.st_ctime_ns
                and os.path.samestat(current, path.lstat()))
    return payload


def exact_json(payload):
    def unique(items):
        result = dict(items)
        require(len(result) == len(items))
        return result

    result = json.loads(payload, object_pairs_hook=unique)
    require(type(result) is dict)
    return result


def hex_text(value, length):
    return type(value) is str and len(value) == length and re.fullmatch(r"[0-9a-f]+", value) is not None


def pinned_driver(manifest_digest):
    require(hex_text(manifest_digest, 64))
    raw = protected_bytes(MANIFEST, 32768)
    require(sha256(raw).hexdigest() == manifest_digest)
    manifest = exact_json(raw)
    require(manifest.keys() == {"tree", "controller", "source"} and hex_text(manifest["tree"], 40))
    require(sha256(protected_bytes(CONTROLLER, 131072)).hexdigest() == manifest["controller"])
    expected = manifest["source"]
    require(type(expected) is dict and 1 <= len(expected) <= 64 and DRIVER in expected)
    for path, checksum in expected.items():
        leaf = Path(path)
        require(str(leaf) == path and not leaf.is_absolute() and ".." not in leaf.parts
                and leaf.suffix == ".py" and hex_text(checksum, 64))
    directories = {str(parent) for name in expected for parent in Path(name).parents} - {"."}
    protected_directory(SOURCE)
    pending = set(expected) | directories
    for path in SOURCE.rglob("*"):
        relative = str(path.relative_to(SOURCE))
        require(relative in pending)
        pending.remove(relative)
    require(not pending)
    driver_bytes = None
    for name, checksum in expected.items():
        payload = protected_bytes(SOURCE / name, 1_048_576)
        require(sha256(payload).hexdigest() == checksum)
        if name == DRIVER:
            driver_bytes = payload
    driver_path = str(SOURCE / DRIVER)
    scope = {"__name__": "sealed_google_connect_driver", "__file__": driver_path}
    exec(compile(driver_bytes, driver_path, "exec"), scope)
    require(set(scope["SOURCE_FILES"]) == set(expected))
    return scope, manifest


def account_podman(user):
    require(user.pw_name == ACCOUNT and user.pw_uid > 0 and user.pw_gid > 0 and user.pw_dir == HOME)
    runtime = f"/run/user/{user.pw_uid}"
    return ("/usr/sbin/runuser", "-u", ACCOUNT, "--", "/usr/bin/env", "-i", f"HOME={HOME}",
            "PATH=/usr/bin:/bin", "LANG=C.UTF-8", f"XDG_RUNTIME_DIR={runtime}",
            f"DBUS_SESSION_BUS_ADDRESS=unix:path={runtime}/bus", "/usr/bin/podman", "--remote=false")


def inspect_devbox(prefix):
    status, raw = bounded_run((*prefix, "container", "inspect", "--format", "{{.Id}} {{.Name}} {{.State.Running}}",
                               DEVBOX), seconds=20, limit=512)
    identity, name, running = raw.decode("ascii").split()
    require(status == 0 and hex_text(identity, 64) and name in (DEVBOX, "/" + DEVBOX) and running == "true")
    return identity


def fixture_command():
    return (PYTHON, "-IBS", str(SOURCE / "tests/google-connect-fixture.py"), "--bound-catalog")


def dedicated_command(prefix, user, identity, pin):
    return (*prefix, "exec", "-i", "--user", f"{user.pw_uid}:{user.pw_gid}", identity,
            "/usr/bin/env", "-i", f"HOME={HOME}", "PATH=/usr/bin:/bin", "LANG=C.UTF-8",
            PYTHON, "-IBS", str(CONTROLLER), "--held-exec", pin)


def bounded_run(argv, *, seconds, limit, env=ENV):
    deadline = time.monotonic() + seconds
    output = bytearray()
    child = subprocess.Popen(argv, cwd="/", env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, start_new_session=True)
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(child.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not ready.select(remaining):
                    raise subprocess.TimeoutExpired(argv, seconds)
                block = os.read(child.stdout.fileno(), min(4096, limit + 1 - len(output)))
                if not block:
                    break
                output.extend(block)
                require(len(output) <= limit)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(argv, seconds)
        status = child.wait(timeout=remaining)
    except BaseException:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=5)
        raise
    finally:
        child.stdout.close()
    return status if status >= 0 else 128 - status, bytes(output)


class Frames:
    """Two fixed barriers over the owned exec pipes, without forwarding child stdin."""

    def __init__(self, reader, writer, deadline):
        self.reader = reader
        self.writer = writer
        self.deadline = deadline
        for fd in (reader, writer):
            os.set_blocking(fd, False)

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0)
        return remaining

    def ready(self, fd, event):
        with selectors.DefaultSelector() as selector:
            selector.register(fd, event)
            return bool(selector.select(self.remaining()))

    def read_exact(self, size):
        data = bytearray()
        while len(data) < size:
            require(self.ready(self.reader, selectors.EVENT_READ))
            block = os.read(self.reader, size - len(data))
            require(block)
            data.extend(block)
        return bytes(data)

    def read(self):
        size, = struct.unpack("!H", self.read_exact(2))
        require(0 < size <= FRAME_LIMIT)
        return self.read_exact(size)

    def write(self, message):
        require(0 < len(message) <= FRAME_LIMIT)
        data = memoryview(struct.pack("!H", len(message)) + message)
        while data:
            require(self.ready(self.writer, selectors.EVENT_WRITE))
            count = os.write(self.writer, data)
            require(count > 0)
            data = data[count:]

    def require_quiet(self):
        with selectors.DefaultSelector() as selector:
            selector.register(self.reader, selectors.EVENT_READ)
            self.remaining()
            require(not selector.select(0))

    def require_eof(self):
        require(self.ready(self.reader, selectors.EVENT_READ) and os.read(self.reader, 1) == b"")


def subreaper():
    # A reparented descendant remains visible even if it detached from the child group.
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(36, 1, 0, 0, 0) == 0)  # PR_SET_CHILD_SUBREAPER


def no_children():
    try:
        os.waitpid(-1, os.WNOHANG)
    except ChildProcessError:
        return
    raise ControllerRefused("Unexpected fixture descendant remains.")


def run_held_supervisor(pin):
    driver, manifest = pinned_driver(pin)
    seal = driver["guest"]()
    require(seal["tree"] == manifest["tree"] and seal["source"] == manifest["source"])
    require(os.getuid() == os.geteuid() == seal["uid"] and os.environ.get("HOME") == HOME)
    subreaper()
    no_children()
    driver["private_inventory"](seal["uid"])
    channel = Frames(sys.stdin.fileno(), sys.stdout.fileno(), time.monotonic() + 900)
    channel.require_quiet()
    channel.write(READY)
    require(channel.read() == START)
    channel.require_quiet()
    driver["check_home_before"](seal)
    status, output = bounded_run(fixture_command(), seconds=channel.remaining(), limit=4096,
                                 env=ENV | {"HOME": HOME})
    no_children()
    driver["private_inventory"](seal["uid"])
    channel.require_quiet()
    channel.write(OUTCOME + bytes((status,)) + output)
    require(channel.read() == RELEASE)
    # Root closes its input after the single release frame.
    channel.require_eof()
    no_children()
    driver["private_inventory"](seal["uid"])
    channel.write(RETIRED)
    return 0


@contextmanager
def held_client(argv):
    client = subprocess.Popen(argv, cwd="/", env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        yield client
    finally:
        try:
            if client.poll() is None:
                # Only the local Podman client is owned here. Its exit is not guest retirement.
                try:
                    os.killpg(client.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                client.wait(timeout=5)
        finally:
            client.stdin.close()
            client.stdout.close()


def observe_run(driver, argv):
    phase = "ready"
    try:
        with held_client(argv) as client:
            channel = Frames(client.stdout.fileno(), client.stdin.fileno(), time.monotonic() + 900)
            require(channel.read() == READY)
            channel.require_quiet()
            phase = "baseline"
            driver["begin_home_attestation"]()
            phase = "child"
            channel.write(START)
            frame = channel.read()
            require(len(frame) >= 2 and frame[:1] == OUTCOME)
            status, output = frame[1], frame[2:]
            require(status == 0 and output == POSITIVE)
            channel.require_quiet()
            phase = "capture"
            captured = driver["capture_home_after"]()
            channel.require_quiet()
            phase = "release"
            channel.write(RELEASE)
            client.stdin.close()
            require(channel.read() == RETIRED)
            channel.require_eof()
            require(client.wait(timeout=channel.remaining()) == 0)
        phase = "persist"
        result = driver["finish_home_attestation"](status, output, True, captured)
        if result == 0:
            print(POSITIVE.decode("ascii"), end="")
        return result
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt):
        driver["record_incomplete_home_attestation"](phase)
        return 1


def run_controller(manifest_digest):
    driver, manifest = pinned_driver(manifest_digest)
    seal_path = CAPSULE / "seal.json"
    if driver["absent"](seal_path):
        driver["install_seal"](manifest["tree"])
    seal = driver["proof_file"](seal_path)
    driver["validate_seal"](seal)
    require(seal["tree"] == manifest["tree"] and seal["source"] == manifest["source"])
    require(all(driver["absent"](CAPSULE / driver[name]) for name in ("HOME_BEFORE", "HOME_RESULT", "NATIVE_RESULT")))
    user = pwd.getpwnam(ACCOUNT)
    require(user.pw_uid == seal["uid"])
    prefix = account_podman(user)
    identity = inspect_devbox(prefix)
    return observe_run(driver, dedicated_command(prefix, user, identity, manifest_digest))


def main():
    try:
        require(Path(__file__).absolute() == CONTROLLER)
        require(sys.executable == PYTHON and sys.flags.isolated and sys.flags.dont_write_bytecode and sys.flags.no_site)
        require(all(Path(item).is_relative_to("/usr/lib") or Path(item).is_relative_to("/usr/lib64")
                    for item in sys.path))
        if len(sys.argv) == 3:
            _, action, pin = sys.argv
            require(action == "--held-exec" and os.getuid() == os.geteuid() > 0)
            return run_held_supervisor(pin)
        require(os.getuid() == os.geteuid() == 0)
        _, pin = sys.argv
        return run_controller(pin)
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt):
        print("Protected offline Google controller did not complete.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
