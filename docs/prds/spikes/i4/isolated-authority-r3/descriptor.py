"""Linux anonymous descriptor protocol for the synthetic R3 experiment."""

from array import array
from dataclasses import dataclass
from enum import Enum
import json
import os
import re
import select
import socket
import struct


_MAX_PACKET = 1024
_CREDENTIALS = struct.Struct("=iii")
_FINGERPRINT = re.compile(r"[0-9a-f]{64}")


class Refusal(str, Enum):
    BAD_MESSAGE = "bad_message"
    WRONG_PEER = "wrong_peer"
    LOST_ENDPOINT = "lost_endpoint"
    WRONG_GRANT = "wrong_grant"
    OWNER_LOST = "owner_lost"
    MISSING_RECEIPT = "missing_receipt"
    INVALID_RECEIPT = "invalid_receipt"
    CONFLICT = "receipt_conflict"
    LOCK_BUSY = "continuity_lock_busy"
    INVALID_SCOPE_LOCK = "invalid_scope_lock"
    RECONCILIATION_REQUIRED = "receipt_reconciliation_required"
    STORAGE_UNCERTAIN = "receipt_storage_uncertain"
    TRANSITION_UNCERTAIN = "receipt_transition_uncertain"
    LOCAL_STORAGE_UNCERTAIN = "local_pair_storage_uncertain"
    PAIR_MISMATCH = "pair_mismatch"


class Denied(RuntimeError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason.value)


def fingerprint(value):
    return type(value) is str and _FINGERPRINT.fullmatch(value) is not None


def canonical(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def decode(packet):
    try:
        value = json.loads(packet.decode("ascii"))
        if type(value) is list and canonical(value) == packet:
            return value
    except (ValueError, RecursionError):
        pass
    raise Denied(Refusal.BAD_MESSAGE)


@dataclass(frozen=True)
class Peer:
    pid: int
    uid: int
    gid: int


def descriptor_pair():
    """The controller sets credential delivery before passing either end."""
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        for endpoint in (left, right):
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            endpoint.settimeout(2)
    except OSError:
        left.close()
        right.close()
        raise
    return left, right


class Channel:
    """Exact per-message sender identity for an inherited connected endpoint."""

    def __init__(self, endpoint, peer, peer_pidfd):
        # The launcher pins the live process before delivering the FD pair.
        # Opening a pidfd here by numeric PID could race process replacement.
        self.endpoint = endpoint
        self.peer = peer
        self._pidfd = peer_pidfd
        try:
            os.set_inheritable(peer_pidfd, False)
            endpoint.set_inheritable(False)
            endpoint.settimeout(2)
        except (OSError, ValueError):
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        try:
            self.endpoint.close()
        finally:
            if self._pidfd is not None:
                descriptor, self._pidfd = self._pidfd, None
                os.close(descriptor)

    def _require_process(self, refusal):
        if self._pidfd is None:
            raise Denied(refusal)
        poll = select.poll()
        poll.register(self._pidfd, select.POLLIN)
        if poll.poll(0):
            raise Denied(refusal)

    def send(self, value):
        self._require_process(Refusal.LOST_ENDPOINT)
        packet = canonical(value)
        if len(packet) > _MAX_PACKET:
            raise Denied(Refusal.BAD_MESSAGE)
        try:
            if self.endpoint.send(packet) != len(packet):
                raise Denied(Refusal.LOST_ENDPOINT)
        except OSError:
            raise Denied(Refusal.LOST_ENDPOINT) from None

    def receive(self):
        try:
            packet, control, flags, _ = self.endpoint.recvmsg(
                _MAX_PACKET, socket.CMSG_SPACE(_CREDENTIALS.size), socket.MSG_CMSG_CLOEXEC,
            )
        except OSError:
            raise Denied(Refusal.LOST_ENDPOINT) from None

        # Reject ancillary data besides the kernel credential, and close even
        # the descriptors delivered by a truncated SCM_RIGHTS message.
        for level, kind, payload in control:
            if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                descriptors = array("i")
                complete = len(payload) // descriptors.itemsize * descriptors.itemsize
                descriptors.frombytes(payload[:complete])
                for descriptor in descriptors:
                    socket.close(descriptor)
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise Denied(Refusal.BAD_MESSAGE)
        if not packet:
            raise Denied(Refusal.LOST_ENDPOINT)
        if len(control) != 1:
            raise Denied(Refusal.WRONG_PEER)
        level, kind, payload = control[0]
        if ((level, kind) != (socket.SOL_SOCKET, socket.SCM_CREDENTIALS)
                or len(payload) != _CREDENTIALS.size
                or Peer(*_CREDENTIALS.unpack(payload)) != self.peer):
            raise Denied(Refusal.WRONG_PEER)
        self._require_process(Refusal.LOST_ENDPOINT)
        return decode(packet)

    def require_idle_peer(self, refusal):
        self._require_process(refusal)
        poll = select.poll()
        try:
            poll.register(self.endpoint, select.POLLIN)
        except (OSError, ValueError):
            raise Denied(refusal) from None
        if poll.poll(0):
            raise Denied(refusal)
        self._require_process(refusal)


class OwnerGrant:
    """The measured launcher pins this exact synthetic slot before delivery."""

    def __init__(self, channel, approved_slot, approved_intent):
        if not fingerprint(approved_slot) or not fingerprint(approved_intent):
            raise ValueError("invalid pinned grant")
        self._channel = channel
        self._approved = ["owner", "launch", approved_slot, approved_intent]
        self._admitted = False
        self._used = False

    def admit(self):
        if self._used:
            raise Denied(Refusal.WRONG_GRANT)
        self._used = True
        if self._channel.receive() != self._approved:
            raise Denied(Refusal.WRONG_GRANT)
        self._channel.require_idle_peer(Refusal.OWNER_LOST)
        self._admitted = True

    def require_live(self, slot, intent):
        if not self._admitted or [slot, intent] != self._approved[2:]:
            raise Denied(Refusal.WRONG_GRANT)
        self._channel.require_idle_peer(Refusal.OWNER_LOST)
