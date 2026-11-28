"""Exact foreground terminal identity and one nonblocking socket send."""

import ctypes
import os
from pathlib import Path
import socket
import stat


class ControlError(RuntimeError):
    """A redacted control error for the operator."""


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


_libc_send = ctypes.CDLL(None, use_errno=True).send
_libc_send.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int)
_libc_send.restype = ctypes.c_ssize_t


def _send_once(client, data, *, send=None):
    # Python socket.send restarts EINTR. A fenced write must spend one syscall.
    if send is None:
        send = _libc_send
    size = send(client.fileno(), data, len(data), socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
    if size < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return size
