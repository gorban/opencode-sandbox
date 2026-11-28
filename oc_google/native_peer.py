"""Pin a private Unix connector to the supervisor's native control group."""

from contextlib import contextmanager
import os
import select
import socket
import struct
from threading import Lock


_PEERPIDFD = getattr(socket, "SO_PEERPIDFD", 77)
_CREDENTIALS = struct.Struct("=3i")
_FD = struct.Struct("=i")


class NativePeerError(RuntimeError):
    """A native channel lacks its exact live owner."""


def _alive(pidfd):
    poll = select.poll()
    poll.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return not poll.poll(0)


class _NativePeer:
    def __init__(self, pid, pidfd, expected_group, read_cgroup):
        self._pid = pid
        self._pidfd = pidfd
        self._line = b"0::" + expected_group
        self._read = read_cgroup
        self._lock = Lock()

    def active(self):
        """Require that the pinned process remains in the same exact control group."""
        with self._lock:
            if self._pidfd is None or not _alive(self._pidfd):
                return False
            try:
                group = self._read(self._pid)
            except (OSError, RuntimeError):
                return False
            return (type(group) is bytes and len(group) <= 4096
                    and group.splitlines() == [self._line] and _alive(self._pidfd))

    def close(self):
        with self._lock:
            pidfd = self._pidfd
            self._pidfd = None
            if pidfd is not None:
                os.close(pidfd)


@contextmanager
def admit_native_peer(connection, *, expected_group: bytes, read_cgroup):
    """Verify one AF_UNIX peer before reading its protocol and hold its pidfd.

    The supervisor obtains the exact control group from the native invocation
    it started, verifies a shared PID namespace, and provides a bounded reader
    in that namespace. The caller owns the connection and revocation fence.
    """
    if (connection.family != socket.AF_UNIX or not os.geteuid()
            or type(expected_group) is not bytes or not expected_group.startswith(b"/")
            or len(expected_group) > 4091 or expected_group == b"/"
            or any(not 33 <= value <= 126 for value in expected_group)):
        raise NativePeerError("Invalid standalone Google ACP peer authority")
    try:
        pid, uid, _ = _CREDENTIALS.unpack(connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                               _CREDENTIALS.size))
        if pid <= 0 or uid != os.geteuid():
            raise NativePeerError("Standalone Google ACP peer credentials differ")
        pidfd, = _FD.unpack(connection.getsockopt(socket.SOL_SOCKET, _PEERPIDFD, _FD.size))
    except (OSError, struct.error):
        raise NativePeerError("Standalone Google ACP peer identity is unavailable") from None
    peer = _NativePeer(pid, pidfd, expected_group, read_cgroup)
    try:
        if not peer.active():
            raise NativePeerError("Standalone Google ACP peer is outside the expected native invocation")
        yield peer
    finally:
        peer.close()
