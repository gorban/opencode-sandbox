"""Host-only, attended arming for the restricted Google shell."""

from contextlib import ExitStack, contextmanager, suppress
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import select
import socket
import stat
import struct
import termios
import time

from oc_orchestrator.protocol import PROMPT
from oc_orchestrator.runtime import FULL_ID, scratch_parent
from oc_providers.contracts import is_valid_instance_label, is_valid_model_slug


RUN_ID = re.compile(r"[0-9a-f]{32}")
CONTROL_SOCKET = "arm.sock"
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
MAX_PACKET = 1024
CONFIRM_TIME = 45


class ControlError(RuntimeError):
    """A redacted control error for the operator."""


def check_run_id(run_id):
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise ControlError("invalid Google shell run ID")


def verify_binding(label, model):
    if not is_valid_instance_label(label) or not is_valid_model_slug(model) or not model.startswith("gemini-"):
        raise ControlError("invalid Google shell registration or model")


def check_directory(fd):
    info = os.fstat(fd)
    if not os.getuid() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ControlError("unsafe Google shell runtime directory")


@contextmanager
def control_root(*, create=False):
    parent = scratch_parent()
    with ExitStack() as pins:
        base = os.open(parent, DIRECTORY_FLAGS)
        pins.callback(os.close, base)
        check_directory(base)
        if create:
            with suppress(FileExistsError):
                os.mkdir("oc-gshell", 0o700, dir_fd=base)
        root = os.open("oc-gshell", DIRECTORY_FLAGS, dir_fd=base)
        pins.callback(os.close, root)
        check_directory(root)
        path = parent / "oc-gshell"
        if not os.path.samestat(path.lstat(), os.fstat(root)):
            raise ControlError("Google shell runtime directory changed")
        yield path, root


@contextmanager
def owned_run():
    """Serialize placement and block reuse while any earlier placement is unresolved."""
    with control_root(create=True) as (path, root), ExitStack() as pins:
        lock = os.open("owner.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                       0o600, dir_fd=root)
        pins.callback(os.close, lock)
        info = os.fstat(lock)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ControlError("unsafe Google shell runtime lock")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ControlError("a Google shell already owns the local slot") from None
        if set(os.listdir(root)) != {"owner.lock"}:
            raise ControlError("a retained Google shell placement needs inspection")
        run_id = secrets.token_hex(16)
        os.mkdir(run_id, 0o700, dir_fd=root)
        run = os.open(run_id, DIRECTORY_FLAGS, dir_fd=root)
        pins.callback(os.close, run)
        check_directory(run)
        yield path / run_id, root, run


def pinned_name(path, parent, directory):
    entry = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
    pinned = os.fstat(directory)
    if not os.path.samestat(entry, pinned) or not os.path.samestat(path.lstat(), pinned):
        raise ControlError("Google shell run directory changed")


def terminal(pid):
    """Pair the kernel's controlling terminal with the foreground peer's I/O."""
    try:
        proc = Path("/proc") / str(pid)
        # comm is parenthesized and can itself contain parentheses.
        fields = (proc / "stat").read_text().rpartition(") ")[2].split()
        group, session, tty_number, foreground = map(int, fields[2:6])
        incoming = (proc / "fd/0").stat()
        outgoing = (proc / "fd/1").stat()
        if (not tty_number or group != foreground or not stat.S_ISCHR(incoming.st_mode)
                or incoming.st_rdev != tty_number % (1 << 32) or not os.path.samestat(incoming, outgoing)):
            raise ControlError("Google shell control requires a foreground controlling terminal")
    except (OSError, ValueError, IndexError):
        raise ControlError("Google shell control requires a foreground controlling terminal") from None
    return incoming.st_dev, incoming.st_ino, incoming.st_rdev, session, fields[19]


def peer_pid(connection):
    pid, uid, _ = struct.unpack("=iII", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if pid <= 0 or uid != os.getuid():
        raise ControlError("Google shell control peer changed")
    return pid


def socket_path(directory):
    # The final name is checked as a socket without following links by the client.
    # Pin every parent of bind/connect through the directory descriptor.
    return f"/proc/self/fd/{directory}/{CONTROL_SOCKET}"


def encode(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")


def receive(connection, deadline, active):
    connection.setblocking(False)
    while active() and (remaining := deadline - time.monotonic()) > 0:
        readable, _, _ = select.select([connection], [], [], min(.1, remaining))
        if readable:
            data = connection.recv(MAX_PACKET + 1)
            if 0 < len(data) <= MAX_PACKET:
                return data
            break
    raise ControlError("Google shell arm exchange did not complete")


class ArmControl:
    """One owner, one incarnation and one confirmation from a different TTY."""

    def __init__(self, directory, run_id, worker, relay, target, shell_terminal):
        check_run_id(run_id)
        verify_binding(target.label, target.model)
        if not FULL_ID.fullmatch(worker) or not FULL_ID.fullmatch(relay) or worker == relay:
            raise ControlError("invalid Google shell placement identity")
        self.directory = directory
        self.shell_terminal = shell_terminal
        self.binding = {"run": run_id, "label": target.label, "model": target.model,
                        "worker": worker, "relay": relay, "prompt": PROMPT}
        self.consumed = False

    def __enter__(self):
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            self.listener.bind(socket_path(self.directory))
            os.chmod(CONTROL_SOCKET, 0o600, dir_fd=self.directory, follow_symlinks=False)
            self.listener.listen(1)
            self.listener.setblocking(False)
        except BaseException:
            self.listener.close()
            raise
        return self

    def __exit__(self, *_):
        self.listener.close()

    def step(self, deadline, active, activate):
        if self.consumed or not active():
            return
        readable, _, _ = select.select([self.listener], [], [], .1)
        if not readable:
            return
        connection, _ = self.listener.accept()
        with connection:
            try:
                pid = peer_pid(connection)
                peer = terminal(pid)
                if peer[:3] == self.shell_terminal[:3] or peer[3] == self.shell_terminal[3]:
                    raise ControlError("use a separate trusted terminal to arm the Google shell")
                offer = encode(self.binding | {"nonce": secrets.token_hex(32)})
                connection.settimeout(.2)
                connection.sendall(offer)
                limit = min(deadline, time.monotonic() + CONFIRM_TIME)
                if receive(connection, limit, active) != offer or terminal(pid) != peer or not active():
                    raise ControlError("Google shell arm confirmation changed")
            except (ControlError, OSError):
                with suppress(OSError):
                    connection.sendall(b"refused")
                return

            def confirmed():
                try:
                    # A readable socket after the one packet is EOF or a second packet.
                    return terminal(pid) == peer and not select.select([connection], [], [], 0)[0]
                except (ControlError, OSError, ValueError):
                    return False

            if not confirmed() or not active():
                return

            def acknowledge(packet):
                if not confirmed() or not active():
                    raise ControlError("Google shell arm terminal left during relay startup")
                try:
                    if connection.send(packet) == len(packet):
                        return
                except OSError:
                    pass
                raise ControlError("Google shell arm acknowledgement failed")

            committed = False
            armed = False

            def commit():
                nonlocal committed
                acknowledge(b"committed")
                committed = True

            def ready():
                nonlocal armed
                if not committed:
                    raise ControlError("Google shell arm has no committed confirmation")
                acknowledge(b"armed")
                armed = True

            self.consumed = True
            self.listener.close()
            try:
                activate(confirmed, commit, ready)
                if not armed:
                    raise ControlError("Google shell relay did not confirm readiness")
            finally:
                if committed and not armed:
                    with suppress(OSError):
                        connection.send(b"failed")


def offer_for(data, run_id):
    try:
        offer = json.loads(data)
        if (set(offer) != {"run", "nonce", "label", "model", "worker", "relay", "prompt"}
                or data != encode(offer) or offer["run"] != run_id or offer["prompt"] != PROMPT
                or not FULL_ID.fullmatch(offer["nonce"]) or not FULL_ID.fullmatch(offer["worker"])
                or not FULL_ID.fullmatch(offer["relay"]) or offer["worker"] == offer["relay"]):
            raise ValueError
        verify_binding(offer["label"], offer["model"])
    except (KeyError, TypeError, ValueError, RecursionError):
        raise ControlError("invalid or expired Google shell arm offer") from None
    return offer


def confirm(offer):
    if not termios.tcgetattr(0)[3] & termios.ICANON:
        raise ControlError("Google shell arm requires an ordinary terminal input line")
    termios.tcflush(0, termios.TCIFLUSH)
    print(f"Google route {offer['label']} · model {offer['model']} · prompt {PROMPT}", flush=True)
    print("Account: current workstation Antigravity login (ACP does not verify its identity).", flush=True)
    print("Type arm to authorize this one turn: ", end="", flush=True)
    ready, _, _ = select.select([0], [], [], CONFIRM_TIME)
    if not ready or os.read(0, 32) != b"arm\n" or select.select([0], [], [], 0)[0]:
        raise ControlError("Google shell arm confirmation refused")


def arm(run_id):
    """Confirm one visible model and fixed prompt on a separate trusted terminal."""
    check_run_id(run_id)
    foreground = terminal(os.getpid())
    try:
        with control_root() as (path, root), ExitStack() as pins:
            directory = os.open(run_id, DIRECTORY_FLAGS, dir_fd=root)
            pins.callback(os.close, directory)
            check_directory(directory)
            pinned_name(path / run_id, root, directory)
            entry = os.stat(CONTROL_SOCKET, dir_fd=directory, follow_symlinks=False)
            if not stat.S_ISSOCK(entry.st_mode) or entry.st_uid != os.getuid() or stat.S_IMODE(entry.st_mode) != 0o600:
                raise ControlError("unsafe Google shell arm socket")
            connection = pins.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET))
            connection.settimeout(2)
            connection.connect(socket_path(directory))
            peer_pid(connection)
            if not os.path.samestat(entry, os.stat(CONTROL_SOCKET, dir_fd=directory, follow_symlinks=False)):
                raise ControlError("Google shell arm socket changed")
            offer = receive(connection, time.monotonic() + 2, lambda: True)
            confirm(offer_for(offer, run_id))
            pinned_name(path / run_id, root, directory)
            if terminal(os.getpid()) != foreground:
                raise ControlError("Google shell arm terminal changed")
            connection.settimeout(1)
            connection.sendall(offer)
            deadline = time.monotonic() + 60
            if receive(connection, deadline, lambda: True) != b"committed":
                raise ControlError("Google shell arm confirmation did not commit")
            try:
                if receive(connection, deadline, lambda: True) != b"armed":
                    raise ControlError("Google shell relay did not confirm readiness")
            except (ControlError, OSError):
                raise ControlError("Google shell arm committed, but relay readiness was not confirmed") from None
    except (OSError, termios.error):
        raise ControlError("Google shell arm is unavailable") from None
    print("Google shell armed for one turn.", flush=True)
    return 0
