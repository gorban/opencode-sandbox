"""Fixed loopback relay for the isolated Gemini generation fixture."""

from contextlib import suppress
from enum import IntEnum
import os
from pathlib import Path
import select
import socket
import stat
import struct
from threading import Event, Thread
from time import monotonic

from .native_proxy import _pump
from .route import _send_once


CONTROL = "control.sock"
STARTUP = "startup.sock"
TURN = "turn.sock"
STARTUP_LIMIT = 3
STARTUP_SECONDS = 25
TURN_SECONDS = 20
HARD_SECONDS = 60
LOOPBACK = "127.0.0.1"
_PEERCRED = struct.Struct("=3i")
_FRAME = struct.Struct("!16sBB")


class ProxyRefused(RuntimeError):
    """The offline proxy cannot verify its phase or retirement."""


class Signal(IntEnum):
    START = 1
    STARTED = 2
    CLOSE_STARTUP = 3
    STARTUP_CLOSED = 4
    TURN_BOUND = 5
    OPEN_TURN = 6
    TURN_LISTENING = 7
    TURN_RETIRED = 8


def remaining(deadline):
    seconds = deadline - monotonic()
    if not 0 < seconds <= HARD_SECONDS:
        raise ProxyRefused("Gemini fixture proxy deadline is unavailable")
    return seconds


def recv_exact(connection, size, deadline):
    result = bytearray()
    while len(result) < size:
        connection.settimeout(remaining(deadline))
        block = connection.recv(size - len(result))
        if not block:
            raise ProxyRefused("Gemini fixture proxy control ended early")
        result.extend(block)
    return bytes(result)


def send_frame(connection, stamp, signal, deadline, *, count=0, check=lambda: None):
    packet = _FRAME.pack(stamp, signal, count)
    if not select.select([], [connection], [], remaining(deadline))[1]:
        raise ProxyRefused("Gemini fixture proxy control write expired")
    check()
    remaining(deadline)
    if _send_once(connection, packet) != len(packet):
        raise ProxyRefused("Gemini fixture proxy control write is unconfirmed")


def expect_frame(connection, stamp, signal, deadline, *, count=0):
    if _FRAME.unpack(recv_exact(connection, _FRAME.size, deadline)) != (stamp, signal, count):
        raise ProxyRefused("Gemini fixture proxy control phase differs")


def directory_identity(path):
    if not isinstance(path, Path):
        raise ProxyRefused("Gemini fixture proxy directory differs")
    info = path.lstat()
    if (not path.is_absolute() or path.resolve(strict=True) != path or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise ProxyRefused("Gemini fixture proxy directory is unavailable")
    return info


def peer_credentials(connection):
    if connection.family != socket.AF_UNIX:
        raise ProxyRefused("Gemini fixture proxy control peer differs")
    return _PEERCRED.unpack(connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _PEERCRED.size))


def _bind_loopback(port):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((LOOPBACK, port))
    except BaseException:
        listener.close()
        raise
    return listener


def _relay(local, directory, directory_pin, name, deadline):
    if not os.path.samestat(directory_pin, directory_identity(directory)):
        raise ProxyRefused("Gemini fixture proxy directory changed")
    target = directory / name
    node = target.lstat()
    if not stat.S_ISSOCK(node.st_mode) or node.st_uid != os.geteuid() or stat.S_IMODE(node.st_mode) != 0o600:
        raise ProxyRefused("Gemini fixture proxy connector changed")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as broker:
        broker.settimeout(remaining(deadline))
        broker.connect(str(target))
        if not os.path.samestat(node, target.lstat()):
            raise ProxyRefused("Gemini fixture proxy connector changed")
        _pump(local, broker, deadline)


class _StartupRelay:
    def __init__(self, listener, directory, directory_pin, deadline):
        self.listener = listener
        self.directory = directory
        self.directory_pin = directory_pin
        self.deadline = deadline
        self.complete = 0
        self.stop = Event()
        self.failed = False
        self.worker = Thread(target=self._run, daemon=True)

    def _run(self):
        try:
            self.listener.settimeout(.1)
            while not self.stop.is_set() and self.complete < STARTUP_LIMIT:
                remaining(self.deadline)
                try:
                    local, _ = self.listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    if self.stop.is_set():
                        return
                    raise
                with local:
                    if self.stop.is_set():
                        self.failed = True
                        return
                    _relay(local, self.directory, self.directory_pin, STARTUP, self.deadline)
                    self.complete += 1
        except (OSError, RuntimeError, ValueError):
            self.failed = True

    def close(self):
        self.stop.set()
        self.listener.close()

    def join(self):
        self.worker.join(max(0, self.deadline - monotonic()))
        if self.worker.is_alive() or self.failed or self.complete != STARTUP_LIMIT:
            raise ProxyRefused("Gemini fixture startup relay retirement is unconfirmed")


def run_fixture_proxy(directory, *, port, stamp, owner_pid, startup_deadline, hard_deadline):
    """Run the fixture relay with no inherited owner sockets.

    The trusted launcher must close its listeners in the child or exec with
    closed descriptors. All relay connects target fixed private Unix leaves.
    """
    if (type(port) is not int or not 1024 <= port <= 65535 or type(stamp) is not bytes or len(stamp) != 16
            or type(owner_pid) is not int or owner_pid <= 0 or startup_deadline >= hard_deadline):
        raise ProxyRefused("Gemini fixture proxy launch binding differs")
    directory_pin = directory_identity(directory)
    control_path = directory / CONTROL
    control_pin = control_path.lstat()
    if (not stat.S_ISSOCK(control_pin.st_mode) or control_pin.st_uid != os.geteuid()
            or stat.S_IMODE(control_pin.st_mode) != 0o600):
        raise ProxyRefused("Gemini fixture proxy control node differs")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control:
        control.settimeout(remaining(startup_deadline))
        control.connect(str(control_path))
        if (peer_credentials(control)[:2] != (owner_pid, os.geteuid())
                or not os.path.samestat(directory_pin, directory_identity(directory))
                or not os.path.samestat(control_pin, control_path.lstat())):
            raise ProxyRefused("Gemini fixture proxy control owner differs")
        expect_frame(control, stamp, Signal.START, startup_deadline)
        with _bind_loopback(port) as startup:
            startup.listen(STARTUP_LIMIT)
            relay = _StartupRelay(startup, directory, directory_pin, startup_deadline)
            relay.worker.start()
            try:
                send_frame(control, stamp, Signal.STARTED, startup_deadline)
                expect_frame(control, stamp, Signal.CLOSE_STARTUP, startup_deadline)
                # Close native TCP admission before joining the startup exchange.
                relay.close()
                send_frame(control, stamp, Signal.STARTUP_CLOSED, startup_deadline)
            except BaseException:
                relay.close()
                with suppress(ProxyRefused):
                    relay.join()
                raise
            relay.join()
        # No alternate address and no listening socket while the owner commits ACP_SENT.
        with _bind_loopback(port) as turn:
            send_frame(control, stamp, Signal.TURN_BOUND, startup_deadline, count=relay.complete)
            expect_frame(control, stamp, Signal.OPEN_TURN, hard_deadline)
            deadline = min(hard_deadline, monotonic() + TURN_SECONDS)
            turn.listen(1)
            send_frame(control, stamp, Signal.TURN_LISTENING, deadline)
            readable, _, _ = select.select([control, turn], [], [], remaining(deadline))
            if control in readable or turn not in readable:
                raise ProxyRefused("Gemini fixture turn owner retired before accept")
            turn.setblocking(False)
            local, _ = turn.accept()
            turn.close()
            with local:
                _relay(local, directory, directory_pin, TURN, deadline)
        send_frame(control, stamp, Signal.TURN_RETIRED, deadline, count=1)
        control.shutdown(socket.SHUT_WR)
        # Keep the original helper pinned through the owner's independent EOF
        # and counter checks. This receipt does not prove process exit.
        control.settimeout(remaining(deadline))
        if control.recv(1):
            raise ProxyRefused("Gemini fixture control has trailing data")
