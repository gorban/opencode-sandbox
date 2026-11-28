"""Install and exercise the test-only OpenAI TLS projection in a disposable guest."""

import argparse
from array import array
from contextlib import contextmanager, suppress
import ctypes
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import select
import signal
import shutil
import socket
import ssl
import stat
import struct
import subprocess
import sys
from tempfile import TemporaryFile
from threading import Event, Thread


CAPSULE = Path("/home/.oc-stock-tools-proof")
PROJECTED_TREE = CAPSULE / "source"
HELPER_REL = Path("tests/e2e/stock_worker_tools_projection.py")
SUPERVISOR = Path("oc-openai-session.py")
LAUNCH_DRIVER = Path("tests/e2e/stock_worker_tools_guest.py")
PYTHON = Path("/usr/bin/python3")
UCRED = struct.Struct("3i")
ACCOUNT = "oc-gemini-proof"
TEST_HOME = Path("/home") / ACCOUNT
PRIVATE_LEAF = ".oc-stock-tools-proof"
LAUNCH_SOCKET = TEST_HOME / PRIVATE_LEAF / "launch.sock"
TOOLS_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
CASE_LABELS = frozenset({b"decline", b"tools", b"hosted", b"undeclared", b"held", b"vault"})
FIXTURE_PATHS = (
    HELPER_REL,
    Path("tests/e2e/stock_worker_tools_peer.py"),
    Path("tests/e2e/stock_worker_tools_host.py"),
    Path("tests/e2e/stock_worker_tools_capture.py"),
    Path("tests/e2e/stock_worker_tools_protocol.py"),
    Path("tests/e2e/stock_worker_tools_guest.py"),
    Path("tests/test_openai_connection.py"),
)
PATCHED_PATHS = {"oc_openai/responses.py"}

@dataclass(frozen=True)
class CapsuleState:
    uid: int
    source_sha256: str
    projection_sha256: str
    supervisor_sha256: str
    driver_sha256: str = ""


def path_digest(path):
    with path.open("rb") as raw:
        return hashlib.file_digest(raw, "sha256").hexdigest()


def inventory_digest(files):
    return hashlib.sha256(
        b"".join(
            f"{name}:{digest}\n".encode("ascii") for name, digest in sorted(files.items())
        )
    ).hexdigest()


def checked_node(path, *, directory, read_only=False):
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (not kind(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
            or (read_only and info.st_mode & 0o222) or (not directory and info.st_nlink != 1)):
        raise RuntimeError(f"The guest projection path has unsafe ownership or mode: {path.name}")


def projected_files(root, *, verify, read_only=False):
    found = {}
    for directory, subdirs, names in os.walk(root):
        parent = Path(directory)
        if verify:
            checked_node(parent, directory=True, read_only=read_only)
            for item in subdirs:
                checked_node(parent / item, directory=True, read_only=read_only)
        for item in names:
            path = parent / item
            if verify:
                checked_node(path, directory=False, read_only=read_only)
            found[str(path.relative_to(root))] = path_digest(path)
    return found


def capsule():
    if Path(__file__).absolute() != PROJECTED_TREE / HELPER_REL:
        raise RuntimeError("The fixture is outside its fixed root-owned guest projection")
    for path in (Path("/"), CAPSULE.parent, CAPSULE, PROJECTED_TREE):
        checked_node(path, directory=True)
    manifest_path = CAPSULE / "manifest.json"
    checked_node(CAPSULE, directory=True, read_only=True)
    checked_node(manifest_path, directory=False, read_only=True)
    manifest = json.loads(manifest_path.read_text())
    account = pwd.getpwnam(ACCOUNT)
    if (manifest.get("format") != 1 or account.pw_uid == 0 or Path(account.pw_dir) != TEST_HOME
            or os.getuid() != os.geteuid() or os.geteuid() != account.pw_uid
            or manifest.get("uid") != account.pw_uid):
        raise RuntimeError("The fixture requires the dedicated real and effective guest UID")
    files = projected_files(PROJECTED_TREE, verify=True, read_only=True)
    if files != manifest["files"] or inventory_digest(files) != manifest["projection_sha256"]:
        raise RuntimeError("The guest projection source changed")
    for name, digest in manifest["tls"].items():
        path = CAPSULE / name
        checked_node(path, directory=False, read_only=True)
        if path_digest(path) != digest:
            raise RuntimeError("A measured guest trust input changed")
    return CapsuleState(account.pw_uid, manifest["source_sha256"], manifest["projection_sha256"],
                        files[str(SUPERVISOR)], files[str(LAUNCH_DRIVER)])


def snapshot_inputs(source):
    for pattern in ("oc-sandbox", "oc-*.py", "oc_*.py"):
        yield from (path.relative_to(source) for path in source.glob(pattern))
    for package in source.glob("oc_*"):
        if package.is_dir():
            yield from (path.relative_to(source) for path in package.rglob("*.py"))
    yield from FIXTURE_PATHS


def describe_source(source):
    result = {}
    for name in snapshot_inputs(source):
        path = source / name
        if (not path.is_file() or path.resolve() != path
                or not 0 < path.stat().st_size <= 1024 * 1024):
            raise RuntimeError(f"The reviewed source input is missing or invalid: {name}")
        result[str(name)] = path_digest(path)
    return result


def project_sources(tree):
    # Apply the only test projection at the trusted TLS socket creation seam.
    responses = tree / "oc_openai/responses.py"
    source = responses.read_text()
    signature = "def _connect(host, cancellation):\n"
    boundary = "\n\ndef _validate_http(response):"
    if source.count(signature) != 1 or source.count(boundary) != 1:
        raise RuntimeError("The measured OpenAI TLS seam changed")
    start, previous = source.split(signature)
    _, tail = previous.split(boundary)
    hook = ("    projection = __import__('runpy').run_path("
            "str(__import__('pathlib').Path(__file__).parent.parent / "
            "'tests/e2e/stock_worker_tools_projection.py'))\n"
            "    return projection['open_stock_tls'](host, cancellation)\n")
    responses.write_text(start + signature + hook + boundary + tail)


def create_tls(target):
    env = {**TOOLS_ENV, "HOME": "/root"}
    infile = target / "fake-peer.pem"
    key = target / "fake-peer-key.pem"
    subprocess.run((
        "/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-days", "3", "-subj", "/CN=oc-stock-tools-proof-fixture",
        "-addext", "subjectAltName=DNS:api.openai.com,DNS:auth.openai.com",
        "-keyout", str(key), "-out", str(infile),
    ), env=env, check=True, capture_output=True, timeout=15)
    for path in (infile, key):
        path.chmod(0o444)
    return {path.name: path_digest(path) for path in (infile, key)}


def install(source, source_sha256):
    if os.getuid() != 0 or os.geteuid() != 0 or source.is_relative_to(TEST_HOME):
        raise RuntimeError("Install from the reviewed source outside the test user's home, as guest root")
    checked_node(CAPSULE.parent, directory=True)
    account = pwd.getpwnam(ACCOUNT)
    if account.pw_uid == 0 or Path(account.pw_dir) != TEST_HOME:
        raise RuntimeError("The guest test account is unavailable")
    for ancestor in (*source.parents, source):
        checked_node(ancestor, directory=True)
    files = describe_source(source)
    for name in files:
        checked_node(source / name, directory=False)
    if inventory_digest(files) != source_sha256:
        raise RuntimeError("The supplied source does not match the reviewed inventory")
    old_umask = os.umask(0o022)
    created = False
    try:
        CAPSULE.mkdir(mode=0o700)
        created = True
        PROJECTED_TREE.mkdir()
        for name in files:
            target = PROJECTED_TREE / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / name, target)
        if projected_files(PROJECTED_TREE, verify=True) != files:
            raise RuntimeError("The exact source copy could not be confirmed")
        project_sources(PROJECTED_TREE)
        projection = projected_files(PROJECTED_TREE, verify=True)
        changed = {name for name in files if projection[name] != files[name]}
        if changed != PATCHED_PATHS:
            raise RuntimeError("Unexpected source changes in the guest projection")
        tls = create_tls(CAPSULE)
        manifest = {"format": 1, "uid": account.pw_uid, "files": projection, "tls": tls,
                    "source_sha256": source_sha256, "projection_sha256": inventory_digest(projection)}
        (CAPSULE / "manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
        (CAPSULE / "manifest.json").chmod(0o444)
        for directory, _, names in os.walk(PROJECTED_TREE):
            for name in names:
                (Path(directory) / name).chmod(0o555 if name == "oc-sandbox" else 0o444)
            Path(directory).chmod(0o555)
        CAPSULE.chmod(0o555)
        return {"source_sha256": source_sha256, "projection_sha256": manifest["projection_sha256"]}
    except BaseException:
        if created:
            shutil.rmtree(CAPSULE)
        raise
    finally:
        os.umask(old_umask)


def fixture_modules():
    for directory in (PROJECTED_TREE, PROJECTED_TREE / "tests/e2e"):
        if str(directory) not in sys.path:
            sys.path.insert(0, str(directory))
    import stock_worker_tools_peer
    return stock_worker_tools_peer


def reap(child, *, check):
    try:
        status = child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=5)
        if check:
            raise RuntimeError("A fake peer did not retire")
    else:
        if check and status:
            raise RuntimeError("A fake peer returned an unsuccessful status")


def process_identity(pid):
    record = (Path("/proc") / str(pid) / "stat").read_bytes()
    fields = record.rsplit(b") ", 1)[1].split()
    return int(fields[1]), int(fields[19])


def process_start(pid):
    return process_identity(pid)[1]


def verify_process(pid, started, state, entry, digest):
    proc = Path("/proc") / str(pid)
    source = PROJECTED_TREE / entry
    checked_node(source, directory=False, read_only=True)
    interpreter = PYTHON.resolve(strict=True)
    checked_node(interpreter, directory=False)
    cmdline = b"\0".join((os.fsencode(PYTHON), b"-IB", os.fsencode(source), b""))
    status = (proc / "status").read_text()
    uid = next(line.split()[1:] for line in status.splitlines() if line.startswith("Uid:"))
    if (process_start(pid) != started or uid != [str(state.uid)] * 4
            or not os.path.samestat((proc / "exe").stat(), interpreter.stat())
            or (proc / "cmdline").read_bytes() != cmdline or (proc / "cwd").resolve() != PROJECTED_TREE
            or path_digest(source) != digest):
        raise RuntimeError("The fake peer owner is outside the measured supervisor")


def verify_supervisor(pid, started, state):
    verify_process(pid, started, state, SUPERVISOR, state.supervisor_sha256)


def in_launch_tree(supervisor, pane):
    pid = supervisor
    for _ in range(24):
        parent, started = process_identity(pid)
        if pid == pane[0]:
            return started == pane[1]
        if parent < 2 or parent == pid:
            return False
        pid = parent
    return False


@contextmanager
def launch_authority(state, case):
    """Hold one fixture-owned authorization for one measured tmux pane."""
    label = case.encode("ascii")
    if label not in CASE_LABELS:
        raise ValueError("Unqualified fixture scenario")
    owner = os.getpid()
    verify_process(owner, process_start(owner), state, LAUNCH_DRIVER, state.driver_sha256)
    info = LAUNCH_SOCKET.parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != state.uid or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError("The launch authority directory is not private")
    ready, stop = Event(), Event()
    pane = []
    approved = None

    def register(pid):
        if pane or pid < 2:
            raise RuntimeError("Invalid fixture pane registration")
        pane.append((pid, process_start(pid)))
        ready.set()

    def serve(listener):
        nonlocal approved
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            with conn:
                conn.settimeout(1)
                try:
                    pid, uid, _ = UCRED.unpack(conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, UCRED.size))
                    if uid != state.uid:
                        continue
                    purpose = conn.recv(16)
                    if purpose not in {b"launch", b"peer"} or not ready.wait(4) or stop.is_set():
                        continue
                    if purpose == b"peer":
                        # Resolve the parent from the authenticated caller PID.
                        # A child can confirm authorization but cannot grant it.
                        pid, _ = process_identity(pid)
                    started = process_start(pid)
                    verify_supervisor(pid, started, state)
                    candidate = (pid, started)
                    if not in_launch_tree(pid, pane[0]):
                        continue
                    if purpose == b"peer" and approved != candidate:
                        continue
                    if purpose == b"launch":
                        if approved is not None and approved != candidate:
                            continue
                        approved = candidate
                    conn.sendall(b"ok:" + label)
                except (OSError, RuntimeError):
                    continue

    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
        listener.bind(str(LAUNCH_SOCKET))
        owned_path = LAUNCH_SOCKET.lstat()
        try:
            LAUNCH_SOCKET.chmod(0o600)
            listener.settimeout(.1)
            listener.listen(4)
            thread = Thread(target=serve, args=(listener,), daemon=True)
            thread.start()
            try:
                yield register
            finally:
                stop.set()
                ready.set()
                thread.join(5)
                if thread.is_alive():
                    raise RuntimeError("Fixture launch authority failed to retire")
        finally:
            if not os.path.samestat(owned_path, LAUNCH_SOCKET.lstat()):
                raise RuntimeError("Fixture launch authority path changed")
            LAUNCH_SOCKET.unlink()


def require_authorized_launch(state, *, supervisor=None):
    fixture_directory = str(PROJECTED_TREE / "tests/e2e")
    if fixture_directory not in sys.path:
        sys.path.insert(0, fixture_directory)
    pid = os.getpid() if supervisor is None else supervisor
    purpose = b"launch" if supervisor is None else b"peer"
    started = process_start(pid)
    verify_supervisor(pid, started, state)
    from stock_worker_tools_host import verify_live
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel:
        channel.settimeout(5)
        try:
            channel.connect(str(LAUNCH_SOCKET))
            owner, uid, _ = UCRED.unpack(channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, UCRED.size))
            if uid != state.uid:
                raise RuntimeError("The launch authority has an unexpected UID")
            owner_started = process_start(owner)
            verify_process(owner, owner_started, state, LAUNCH_DRIVER, state.driver_sha256)
            owner_fd = os.pidfd_open(owner)
            try:
                channel.sendall(purpose)
                result = channel.recv(16)
                if not result.startswith(b"ok:") or result[3:] not in CASE_LABELS:
                    raise RuntimeError("The fixture driver did not authorize this supervisor")
                if supervisor is None:
                    verify_live(state)
                if (select.select([owner_fd], [], [], 0)[0] or process_start(owner) != owner_started
                        or process_start(pid) != started or (supervisor is not None and os.getppid() != pid)):
                    raise RuntimeError("The authorized launch lifetime changed")
                return result[3:].decode("ascii")
            finally:
                os.close(owner_fd)
        except OSError:
            raise RuntimeError("No authenticated fixture launch authority") from None


def receive_control(channel, message, expected_pid, uid, *, fd_wanted=False):
    width = array("i").itemsize
    data, ancillary, flags, _ = channel.recvmsg(
        16, socket.CMSG_SPACE(UCRED.size) + socket.CMSG_SPACE(4 * width), socket.MSG_CMSG_CLOEXEC,
    )
    passed = array("i")
    credentials = []
    unexpected = False
    try:
        for level, kind, raw in ancillary:
            if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                if len(raw) % width:
                    unexpected = True
                passed.frombytes(raw[:len(raw) - len(raw) % width])
            elif (level, kind) == (socket.SOL_SOCKET, socket.SCM_CREDENTIALS) and len(raw) == UCRED.size:
                credentials.append(UCRED.unpack(raw)[:2])
            else:
                unexpected = True
        if (data != message or flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC) or unexpected
                or credentials != [(expected_pid, uid)] or len(passed) != int(fd_wanted)):
            raise RuntimeError("The fake peer control envelope did not match this launch")
        return passed.pop() if fd_wanted else None
    finally:
        for descriptor in passed:
            os.close(descriptor)


def verify_private_socket(channel, kind, parent, uid):
    if (channel.family != socket.AF_UNIX or channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != kind
            or channel.getsockname() or channel.getpeername()
            or UCRED.unpack(channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, UCRED.size))[:2]
            != (parent, uid)):
        raise RuntimeError("The fake peer channel did not match the immediate owner")


@contextmanager
def spawn_peer(case, remote):
    state = capsule()
    parent = os.getpid()
    started = process_start(parent)
    if require_authorized_launch(state) != case:
        raise RuntimeError("The fixture case changed")
    # The inherited socket has no namespace address. The provider stream is
    # transferred after authenticating the spawned child, over this socket.
    readiness, inherited = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with readiness, inherited, TemporaryFile() as diagnostics:
        for channel in (readiness, inherited):
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            channel.settimeout(5)
        child = subprocess.Popen((
            str(PYTHON), "-IB", str(PROJECTED_TREE / HELPER_REL), "peer", case,
            str(parent), str(started), str(inherited.fileno()),
        ), cwd=PROJECTED_TREE, env={**TOOLS_ENV, "HOME": str(TEST_HOME)},
           pass_fds=(inherited.fileno(),), stderr=diagnostics,
           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        completed = False
        try:
            inherited.close()
            receive_control(readiness, b"ready", child.pid, state.uid)
            rights = [
                (socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", [remote.fileno()])),
            ]
            if readiness.sendmsg([case.encode()], rights) != len(case):
                raise RuntimeError("The fake peer channel transfer did not complete")
            receive_control(readiness, b"bound", child.pid, state.uid)
            yield child
            completed = True
        finally:
            for stream in (child.stdin, child.stdout):
                if stream is not None:
                    stream.close()
            try:
                reap(child, check=completed)
            finally:
                if not completed:
                    retained = os.pread(diagnostics.fileno(), 8192, 0)
                    locations = re.findall(rb'File "[^"\r\n]*/([A-Za-z0-9_.]+)", line ([0-9]+)', retained)
                    if locations:
                        location = b":".join(locations[-1]).decode("ascii")
                        peers = fixture_modules()
                        peers.receipt(TEST_HOME, f"peer_start_failed_{location}", peer_pid=child.pid)


def open_stock_tls(host, cancellation):
    from oc_openai.responses import API_HOST, AUTH_HOST
    if host not in {API_HOST, AUTH_HOST}:
        raise RuntimeError("The synthetic OpenAI peer refused the requested destination")
    case = require_authorized_launch(capsule())
    context = ssl.create_default_context(cafile=str(CAPSULE / "fake-peer.pem"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    plain, inherited = socket.socketpair()
    ready = Event()
    started = []

    def own_peer():
        peers = fixture_modules()
        try:
            with inherited, spawn_peer(case, inherited) as child:
                inherited.close()
                started.append(child.pid)
                ready.set()
        except (OSError, RuntimeError):
            if started:
                peers.receipt(TEST_HOME, "retirement_pending", peer_pid=started[0])
        else:
            peers.receipt(TEST_HOME, "retired", peer_pid=started[0])
        finally:
            ready.set()

    # The kernel's parent-death signal follows the creating thread. Keep that
    # thread alive until it has reaped the fake peer.
    Thread(target=own_peer, daemon=True).start()
    tls = None
    try:
        if not ready.wait(12) or not started:
            raise RuntimeError("The fixture could not start the synthetic OpenAI peer")
        plain.settimeout(8)
        cancellation.attach(plain)
        tls = context.wrap_socket(plain, server_hostname=host, suppress_ragged_eofs=False)
        cancellation.attach(tls)
        return tls
    except BaseException:
        if tls is not None:
            tls.close()
        plain.close()
        raise



def peer_main(case, owner_pid, started, channel_fd):
    state = capsule()
    if os.getppid() != owner_pid:
        raise RuntimeError("The fixture child is outside the launch lifetime")
    verify_supervisor(owner_pid, started, state)
    owner = os.pidfd_open(owner_pid)
    try:
        prctl = ctypes.CDLL(None, use_errno=True).prctl
        if (prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != owner_pid
                or select.select([owner], [], [], 0)[0] or process_start(owner_pid) != started):
            raise RuntimeError("The measured owner ended before the fake peer started")
        with socket.socket(fileno=channel_fd) as channel:
            # The descriptor is nonblocking across exec. The new Python socket
            # must also establish its own deadline before receiving.
            channel.settimeout(5)
            verify_private_socket(channel, socket.SOCK_SEQPACKET, owner_pid, state.uid)
            if require_authorized_launch(state, supervisor=owner_pid) != case:
                raise RuntimeError("The authorized peer case changed")
            channel.sendall(b"ready")
            data_fd = receive_control(channel, case.encode(), owner_pid, state.uid, fd_wanted=True)
            try:
                with socket.socket(fileno=os.dup(data_fd)) as stream:
                    verify_private_socket(stream, socket.SOCK_STREAM, owner_pid, state.uid)
                peers = fixture_modules()
                channel.sendall(b"bound")
                socket_fd, data_fd = data_fd, None
                peers.openai_peer(TEST_HOME, case, socket_fd,
                                  CAPSULE / "fake-peer.pem", CAPSULE / "fake-peer-key.pem")
            finally:
                if data_fd is not None:
                    os.close(data_fd)
    finally:
        os.close(owner)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    handlers = parser.add_subparsers(dest="action", required=True)
    source = handlers.add_parser("source")
    source.add_argument("tree", type=Path)
    install_parser = handlers.add_parser("install")
    install_parser.add_argument("tree", type=Path)
    install_parser.add_argument("source_sha256")
    handlers.add_parser("check")
    peer = handlers.add_parser("peer")
    peer.add_argument("case", choices=tuple(label.decode("ascii") for label in sorted(CASE_LABELS)))
    peer.add_argument("owner_pid", type=int)
    peer.add_argument("started", type=int)
    peer.add_argument("channel_fd", type=int)
    args = parser.parse_args()
    if args.action == "source":
        print(inventory_digest(describe_source(args.tree.resolve(strict=True))))
    elif args.action == "install":
        print(json.dumps(install(args.tree.resolve(strict=True), args.source_sha256), sort_keys=True))
    elif args.action == "check":
        print(json.dumps(vars(capsule()), sort_keys=True))
    else:
        peer_main(args.case, args.owner_pid, args.started, args.channel_fd)


if __name__ == "__main__":
    main()
