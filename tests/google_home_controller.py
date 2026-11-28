"""Run one sealed disposable guest fixture and own its paired attestations."""

from contextlib import contextmanager
import ctypes
from hashlib import sha256
from hmac import compare_digest
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import select
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
BINDING = CAPSULE / "capsule-binding.json"
BOOT_RUNTIME = Path("/run")
BOOT_LEASES = BOOT_RUNTIME / "oc-gemini-fixture-leases"
PROC = Path("/proc")
PROC_MAGIC = 0x9FA0
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
ATTEMPT = "allocation-attempt.json"
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
START_BYTES = 32
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


def directory_id(info):
    return [info.st_dev, info.st_ino]


def require_procfs(fd):
    # fstatfs's first Linux field is the native filesystem magic word.
    data = (ctypes.c_long * 32)()
    require(ctypes.CDLL(None, use_errno=True).fstatfs(fd, ctypes.byref(data)) == 0 and data[0] == PROC_MAGIC)


@contextmanager
def process_directory(pid):
    require(type(pid) is int and pid > 1)
    root = os.open(PROC, DIRECTORY)
    try:
        require_procfs(root)
        process = os.open(str(pid), DIRECTORY, dir_fd=root)
        try:
            require_procfs(process)
            require(os.fstat(root).st_dev == os.fstat(process).st_dev)
            yield process
        finally:
            os.close(process)
    finally:
        os.close(root)


def proc_bytes(process, leaf, limit):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(leaf, flags, dir_fd=process), "rb") as stream:
        require_procfs(stream.fileno())
        raw = stream.read(limit + 1)
    require(0 < len(raw) <= limit)
    return raw


def process_start_ticks(process, pid):
    raw = proc_bytes(process, "stat", 4096)
    header, separator, tail = raw.rpartition(b") ")
    fields = tail.split()
    require(separator and header.startswith(str(pid).encode("ascii") + b" (") and len(fields) >= 20)
    require(fields[19].isdigit() and 0 < int(fields[19]))
    return int(fields[19])


def require_root_status(process):
    raw = proc_bytes(process, "status", 16384)
    for name in (b"Uid:", b"Gid:"):
        records = [line.split() for line in raw.splitlines() if line.startswith(name)]
        require(records == [[name, b"0", b"0", b"0", b"0"]])


def controller_arguments(manifest_pin, binding_pin):
    return (PYTHON, "-IBS", str(CONTROLLER), manifest_pin, binding_pin)


def argument_digest(argv):
    return sha256(b"\0".join(os.fsencode(arg) for arg in argv) + b"\0").hexdigest()


def controller_identity(binding, manifest, manifest_pin, binding_pin):
    require(os.getresuid() == os.getresgid() == (0, 0, 0) and current_boot() == binding["boot"])
    pid = os.getpid()
    with process_directory(pid) as process:
        require_root_status(process)
        interpreter = os.stat(PYTHON)
        require(stat.S_ISREG(interpreter.st_mode) and interpreter.st_uid == 0 and not interpreter.st_mode & 0o022)
        require(os.path.samestat(interpreter, os.stat("exe", dir_fd=process)))
        script = sha256(protected_bytes(CONTROLLER, 131072)).hexdigest()
        require(script == manifest["controller"])
        argv = controller_arguments(manifest_pin, binding_pin)
        arguments = sha256(proc_bytes(process, "cmdline", 4096)).hexdigest()
        require(compare_digest(arguments, argument_digest(argv)))
        return {"pid": pid, "start_ticks": process_start_ticks(process, pid),
                "interpreter": directory_id(interpreter), "script": script, "argv": arguments}


def verify_allocator_parent(owner, pidfd):
    pid = owner["pid"]
    require(os.getppid() == pid and not select.select([pidfd], [], [], 0)[0])
    with process_directory(pid) as process:
        require_root_status(process)
        require(process_start_ticks(process, pid) == owner["start_ticks"])
    require(os.getppid() == pid and not select.select([pidfd], [], [], 0)[0])


def current_boot():
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(PROC / "sys/kernel/random/boot_id", flags), "rb") as stream:
        require_procfs(stream.fileno())
        boot = stream.read(38).decode("ascii").removesuffix("\n")
    require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot))
    return boot


def allocation_digest(attempt, value):
    require(type(value) is bytes and len(value) == START_BYTES)
    encoded = json.dumps({key: field for key, field in attempt.items() if key != "allocation"},
                         sort_keys=True, separators=(",", ":")).encode("ascii")
    return sha256(b"oc-gemini-fixture:allocation:v1\0" + encoded + b"\0" + value).hexdigest()


def deployment_binding(binding_pin, manifest_pin, manifest):
    require(hex_text(binding_pin, 64))
    raw = protected_bytes(BINDING, 4096)
    require(sha256(raw).hexdigest() == binding_pin)
    binding = exact_json(raw)
    require(binding.keys() == {"version", "capsule", "boot", "tree", "manifest_sha256", "capsule_id"})
    require(type(binding["version"]) is int and binding["version"] == 1 and hex_text(binding["capsule"], 32))
    require(binding["tree"] == manifest["tree"] and binding["manifest_sha256"] == manifest_pin)
    protected_directory(CAPSULE)
    identity = binding["capsule_id"]
    require(type(identity) is list and len(identity) == 2 and all(type(value) is int for value in identity))
    require(identity == directory_id(CAPSULE.lstat()) and binding["boot"] == current_boot())
    return binding


def boot_mount(path):
    argv = ("/usr/bin/findmnt", "-rn", "-o", "TARGET,FSTYPE,FSROOT", "--target", str(path))
    status, output = bounded_run(argv, seconds=5, limit=256)
    require(status == 0 and output.split() == [os.fsencode(BOOT_RUNTIME), b"tmpfs", b"/"])


def consume_boot_lease(binding, payload):
    require(os.getuid() == os.geteuid() == 0 and hex_text(binding["capsule"], 32))
    require(current_boot() == binding["boot"] and BOOT_LEASES.parent == BOOT_RUNTIME)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    protected_directory(BOOT_LEASES)
    runtime = os.open(BOOT_RUNTIME, flags)
    try:
        leases = os.open(BOOT_LEASES.name, flags, dir_fd=runtime)
        try:
            runtime_info, leases_info = os.fstat(runtime), os.fstat(leases)
            require(os.path.samestat(runtime_info, BOOT_RUNTIME.lstat()) and runtime_info.st_uid == 0
                    and not runtime_info.st_mode & 0o022 and leases_info.st_uid == 0
                    and stat.S_IMODE(leases_info.st_mode) == 0o700 and leases_info.st_dev == runtime_info.st_dev)
            boot_mount(BOOT_RUNTIME)
            boot_mount(BOOT_LEASES)
            verify_lease_directory(runtime, leases_info)
            write_boot_lease(leases, binding["capsule"], payload)
            verify_lease_directory(runtime, leases_info)
            require(os.path.samestat(runtime_info, BOOT_RUNTIME.lstat()) and current_boot() == binding["boot"])
        finally:
            os.close(leases)
    finally:
        os.close(runtime)


def verify_lease_directory(runtime, expected):
    named = os.stat(BOOT_LEASES.name, dir_fd=runtime, follow_symlinks=False)
    require(os.path.samestat(expected, named) and os.path.samestat(named, BOOT_LEASES.lstat())
            and named.st_uid == 0 and stat.S_IMODE(named.st_mode) == 0o700)


def write_boot_lease(directory, name, payload):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(name, flags, 0o600, dir_fd=directory)
    try:
        opened = os.fstat(fd)
        require(stat.S_ISREG(opened.st_mode) and opened.st_uid == 0
                and stat.S_IMODE(opened.st_mode) == 0o600 and opened.st_nlink == 1)
        require(os.write(fd, payload) == len(payload))
        os.fsync(fd)
        os.fsync(directory)
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
        require(os.path.samestat(opened, named) and named.st_uid == 0
                and stat.S_IMODE(named.st_mode) == 0o600 and named.st_nlink == 1 and named.st_size == len(payload))
    finally:
        os.close(fd)


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


def require_fixture_account(user):
    require(user.pw_name == ACCOUNT and user.pw_uid > 0 and user.pw_gid > 0 and user.pw_dir == HOME)


def account_podman(user):
    require_fixture_account(user)
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


def bounded_run(argv, *, seconds, limit, env=ENV, run_as=None, stdin=subprocess.DEVNULL):
    deadline = time.monotonic() + seconds
    output = bytearray()
    credentials = {}
    stderr = subprocess.STDOUT
    try:
        if run_as is not None:
            uid, gid = run_as
            require(uid > 0 and gid > 0)
            credentials = {"user": uid, "group": gid, "extra_groups": ()}
            stderr = subprocess.DEVNULL
        child = subprocess.Popen(argv, cwd="/", env=env, stdin=stdin, stdout=subprocess.PIPE,
                                 stderr=stderr, close_fds=True, start_new_session=True, **credentials)
    except BaseException as error:
        if stdin != subprocess.DEVNULL:
            cleanup_preserving(error, stdin.close)
        raise
    try:
        if stdin != subprocess.DEVNULL:
            stdin.close()
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
    except BaseException as error:
        if stdin != subprocess.DEVNULL:
            cleanup_preserving(error, stdin.close)
        cleanup_preserving(error, reap_subprocess, child)
        cleanup_preserving(error, child.stdout.close)
        raise
    child.stdout.close()
    return status if status >= 0 else 128 - status, bytes(output)


def cleanup_preserving(error, action, *args):
    try:
        action(*args)
    except BaseException:
        error.add_note("Protected fixture child or descriptor cleanup was not confirmed.")


def reap_subprocess(child):
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    finally:
        child.wait(timeout=5)


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


@contextmanager
def start_pipe(value):
    require(type(value) is bytes and len(value) == START_BYTES)
    stream = open_start_input(value)
    try:
        yield stream
    except BaseException as error:
        cleanup_preserving(error, stream.close)
        raise
    else:
        stream.close()


def open_start_input(value):
    reader, writer = os.pipe2(os.O_CLOEXEC)
    try:
        try:
            require(os.write(writer, value) == START_BYTES)
        except BaseException as error:
            cleanup_preserving(error, os.close, writer)
            raise
        os.close(writer)
        return os.fdopen(reader, "rb", buffering=0)
    except BaseException as error:
        cleanup_preserving(error, os.close, reader)
        raise


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
    frame = channel.read()
    require(len(frame) == START_BYTES + 1 and frame[:1] == START)
    channel.require_quiet()
    value = frame[1:]
    driver["authorize_home_start"](seal, value)
    with start_pipe(value) as stdin:
        del frame, value
        status, output = bounded_run(fixture_command(), seconds=channel.remaining(), limit=4096,
                                     env=ENV | {"HOME": HOME}, stdin=stdin)
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
            value = secrets.token_bytes(START_BYTES)
            driver["begin_home_attestation"](value)
            phase = "child"
            channel.write(START + value)
            del value
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


def allocate_case_process(pin, binding_pin, user, value):
    argv = (PYTHON, "-IBS", str(CONTROLLER), "--allocate-cases", pin, binding_pin)
    with start_pipe(value) as stdin:
        status, output = bounded_run(argv, seconds=10, limit=4096, run_as=(user.pw_uid, user.pw_gid), stdin=stdin)
    require(status == 0)
    return exact_json(output)


def run_case_allocator(pin, binding_pin):
    driver, manifest = pinned_driver(pin)
    value = driver["read_catalog_start"]()
    binding = deployment_binding(binding_pin, pin, manifest)
    user = pwd.getpwnam(ACCOUNT)
    require_fixture_account(user)
    driver["require_unprivileged_allocator"](user)
    raw = protected_bytes(CAPSULE / ATTEMPT, 4096)
    attempt = exact_json(raw)
    driver["validate_allocation_attempt"](attempt)
    owner = attempt["controller"]
    require(attempt["binding"] == binding_pin and attempt["manifest"] == pin
            and all(attempt[field] == binding[field] for field in ("capsule", "boot", "tree"))
            and attempt["account"] == {"uid": user.pw_uid, "gid": user.pw_gid})
    require(owner["script"] == manifest["controller"]
            and owner["argv"] == argument_digest(controller_arguments(pin, binding_pin))
            and owner["interpreter"] == directory_id(os.stat(PYTHON)))
    require(owner["pid"] == os.getppid())
    pidfd = os.pidfd_open(owner["pid"])
    try:
        verify_allocator_parent(owner, pidfd)
        require(compare_digest(attempt["allocation"], allocation_digest(attempt, value)))
        del value
        require(protected_bytes(CAPSULE / ATTEMPT, 4096) == raw and current_boot() == binding["boot"])
        verify_allocator_parent(owner, pidfd)
        records = driver["allocate_cases"]()
    finally:
        os.close(pidfd)
    print(json.dumps(records, sort_keys=True))
    return 0


def run_controller(manifest_digest, binding_digest):
    driver, manifest = pinned_driver(manifest_digest)
    binding = deployment_binding(binding_digest, manifest_digest, manifest)
    user = pwd.getpwnam(ACCOUNT)
    prefix = account_podman(user)
    seal_path = CAPSULE / "seal.json"
    prior = (seal_path, CAPSULE / "case-config", CAPSULE / ATTEMPT, CAPSULE / driver["HOME_BEFORE_STAGE"],
             *(CAPSULE / driver[name] for name in ("HOME_BEFORE", "HOME_RESULT", "NATIVE_RESULT")))
    require(all(driver["absent"](path) for path in prior))
    owner = controller_identity(binding, manifest, manifest_digest, binding_digest)
    value = secrets.token_bytes(START_BYTES)
    attempt = {"version": 2, "binding": binding_digest, "capsule": binding["capsule"], "boot": binding["boot"],
               "tree": manifest["tree"], "manifest": manifest_digest,
               "account": {"uid": user.pw_uid, "gid": user.pw_gid}, "controller": owner}
    attempt["allocation"] = allocation_digest(attempt, value)
    payload = json.dumps(attempt, sort_keys=True).encode("ascii")
    consume_boot_lease(binding, payload)
    require(directory_id(CAPSULE.lstat()) == binding["capsule_id"])
    attempt_path = CAPSULE / ATTEMPT
    driver["write_protected"](attempt_path, payload)
    require(protected_bytes(attempt_path, 4096) == payload)
    require(directory_id(CAPSULE.lstat()) == binding["capsule_id"])
    def allocate_once():
        nonlocal value
        require(value is not None)
        start, value = value, None
        require(deployment_binding(binding_digest, manifest_digest, manifest) == binding)
        require(controller_identity(binding, manifest, manifest_digest, binding_digest) == owner)
        require(protected_bytes(attempt_path, 4096) == payload)
        return allocate_case_process(manifest_digest, binding_digest, user, start)

    driver["install_seal"](manifest["tree"], allocate_once)
    require(value is None)
    seal = driver["proof_file"](seal_path)
    driver["validate_seal"](seal)
    require(seal["tree"] == manifest["tree"] and seal["source"] == manifest["source"]
            and seal["boot"] == binding["boot"])
    require(all(driver["absent"](CAPSULE / driver[name]) for name in ("HOME_BEFORE", "HOME_RESULT", "NATIVE_RESULT")))
    require(user.pw_uid == seal["uid"])
    identity = inspect_devbox(prefix)
    return observe_run(driver, dedicated_command(prefix, user, identity, manifest_digest))


def main():
    try:
        require(Path(__file__).absolute() == CONTROLLER)
        require(sys.executable == PYTHON and sys.flags.isolated and sys.flags.dont_write_bytecode and sys.flags.no_site)
        require(all(Path(item).is_relative_to("/usr/lib") or Path(item).is_relative_to("/usr/lib64")
                    for item in sys.path))
        if os.getuid() == os.geteuid() > 0:
            action = sys.argv[1]
            if action == "--allocate-cases":
                _, _, pin, binding = sys.argv
                return run_case_allocator(pin, binding)
            _, _, pin = sys.argv
            require(action == "--held-exec")
            return run_held_supervisor(pin)
        require(os.getuid() == os.geteuid() == 0)
        _, pin, binding = sys.argv
        return run_controller(pin, binding)
    except (OSError, ValueError, TypeError, KeyError, IndexError, RuntimeError,
            subprocess.SubprocessError, KeyboardInterrupt):
        print("Protected offline Google controller did not complete.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
