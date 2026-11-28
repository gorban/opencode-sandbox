"""Independent monotonic continuity receipts for a synthetic-only holder."""

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
from hashlib import sha256
import os
import secrets
import stat
import time

from descriptor import Denied, Refusal, canonical, decode, fingerprint


_MAX_REVISION = (1 << 63) - 1
_MAX_RECORD = 1024
_LOCK = "installation.lock"
_RECEIPT = "continuity.json"
_LOCK_WAIT_SECONDS = 0.25


@dataclass(frozen=True)
class Commitment:
    scope: str
    journal: str
    revision: int
    pair_digest: str

    def __post_init__(self):
        if (not all(fingerprint(value) for value in (self.scope, self.journal, self.pair_digest))
                or type(self.revision) is not int or not 0 <= self.revision <= _MAX_REVISION):
            raise Denied(Refusal.BAD_MESSAGE)

    def wire(self):
        return [self.scope, self.journal, self.revision, self.pair_digest]

    @classmethod
    def parse(cls, value):
        if type(value) is not list or len(value) != 4:
            raise Denied(Refusal.BAD_MESSAGE)
        return cls(*value)

    @classmethod
    def for_pair(cls, scope, journal, revision, pair):
        journal_bytes, anchor_bytes = pair
        digest = sha256(
            b"isolated-holder-r3 pair\0" + sha256(journal_bytes).digest() + sha256(anchor_bytes).digest(),
        ).hexdigest()
        return cls(scope, journal, revision, digest)


def require_successor(prior, next_head):
    if (next_head.scope != prior.scope or next_head.journal != prior.journal
            or next_head.revision != prior.revision + 1 or next_head.pair_digest == prior.pair_digest):
        raise Denied(Refusal.CONFLICT)


def acquire_exclusive(descriptor):
    deadline = time.monotonic() + _LOCK_WAIT_SECONDS
    while time.monotonic() < deadline:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(remaining, 0.01))
    raise Denied(Refusal.LOCK_BUSY)


class ReceiptStore:
    """One controller generation, verified only by explicit fresh provisioning."""

    def __init__(self, directory, initial):
        if initial.revision != 0:
            raise ValueError("initial commitment must be at revision zero")
        self.directory = directory
        self.initial = initial
        self._installation = None
        self._published = None
        self._uncertain = False

    def _require_active(self):
        if self._installation is None or self._uncertain:
            raise Denied(Refusal.RECONCILIATION_REQUIRED)

    @contextmanager
    def _transaction(self, *, provisioning=False):
        if not provisioning and self._installation is None:
            raise Denied(Refusal.RECONCILIATION_REQUIRED)
        try:
            root = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                info = os.fstat(root)
                if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise Denied(Refusal.INVALID_RECEIPT)
                flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
                if provisioning:
                    flags |= os.O_CREAT | os.O_EXCL
                lock = os.open(_LOCK, flags, 0o600, dir_fd=root)
                try:
                    lock_info = self._require_private_info(os.fstat(lock))
                    acquire_exclusive(lock)
                    self._require_current_lock(root, lock, lock_info)
                    installation = (info.st_dev, info.st_ino, lock_info.st_dev, lock_info.st_ino)
                    if not provisioning:
                        self._require_active()
                        if installation != self._installation:
                            self._uncertain = True
                            raise Denied(Refusal.INVALID_RECEIPT)
                    yield root, installation
                finally:
                    os.close(lock)
            finally:
                os.close(root)
        except FileNotFoundError:
            if not provisioning:
                self._uncertain = True
            raise Denied(Refusal.MISSING_RECEIPT) from None
        except FileExistsError:
            raise Denied(Refusal.CONFLICT) from None
        except OSError:
            if not provisioning:
                self._uncertain = True
            raise Denied(Refusal.STORAGE_UNCERTAIN) from None

    @staticmethod
    def _require_private_info(info):
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise Denied(Refusal.INVALID_RECEIPT)
        return info

    def _require_current_lock(self, root, lock, opened):
        # A waiter can acquire a detached lock whose old descriptor is still
        # valid. Verify that the permanent name still identifies its inode.
        try:
            held = self._require_private_info(os.fstat(lock))
            named = self._require_private_info(os.stat(_LOCK, dir_fd=root, follow_symlinks=False))
            original = opened.st_dev, opened.st_ino
            if (held.st_dev, held.st_ino) != original or (named.st_dev, named.st_ino) != original:
                raise Denied(Refusal.INVALID_RECEIPT)
        except Denied:
            self._uncertain = True
            raise

    def _read(self, root):
        descriptor = os.open(_RECEIPT, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
        with os.fdopen(descriptor, "rb") as reader:
            self._require_private_info(os.fstat(reader.fileno()))
            raw = reader.read(_MAX_RECORD + 1)
        try:
            if len(raw) > _MAX_RECORD:
                raise Denied(Refusal.BAD_MESSAGE)
            record = decode(raw)
            if len(record) != 3 or record[0] != "r3" or record[1] not in ("witnessed", "pending"):
                raise Denied(Refusal.BAD_MESSAGE)
            head = Commitment.parse(record[2])
            if (head.scope, head.journal) != (self.initial.scope, self.initial.journal):
                raise Denied(Refusal.BAD_MESSAGE)
            if head.revision == 0 and (head != self.initial or record[1] != "witnessed"):
                raise Denied(Refusal.BAD_MESSAGE)
            if (record[1], head) != self._published:
                raise Denied(Refusal.BAD_MESSAGE)
        except Denied:
            self._uncertain = True
            raise Denied(Refusal.INVALID_RECEIPT) from None
        return record[1], head

    @staticmethod
    def _publish(root, phase, head, *, initial=False):
        temp = ".continuity-" + secrets.token_hex(12)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        descriptor = os.open(temp, flags, 0o600, dir_fd=root)
        try:
            with os.fdopen(descriptor, "wb") as writer:
                writer.write(canonical(["r3", phase, head.wire()]))
                writer.flush()
                os.fsync(writer.fileno())
            if initial:
                os.link(temp, _RECEIPT, src_dir_fd=root, dst_dir_fd=root)
                os.unlink(temp, dir_fd=root)
            else:
                os.replace(temp, _RECEIPT, src_dir_fd=root, dst_dir_fd=root)
            os.fsync(root)
        finally:
            try:
                os.unlink(temp, dir_fd=root)
            except FileNotFoundError:
                pass

    def _publish_verified(self, root, phase, head, *, initial=False):
        # A replace may be visible even if directory fsync fails. Lock out the
        # entire generation before attempting any write and restore it only
        # on a verified publication. Reads never sync or adopt visible bytes.
        self._uncertain = True
        self._publish(root, phase, head, initial=initial)
        self._published = phase, head
        self._uncertain = False

    def provision(self):
        """Called only by the synthetic installer on a separately fresh domain."""
        if self._installation is not None or self._uncertain:
            raise Denied(Refusal.CONFLICT)
        with self._transaction(provisioning=True) as (root, installation):
            self._publish_verified(root, "witnessed", self.initial, initial=True)
            self._installation = installation

    def head(self):
        with self._transaction() as (root, _):
            phase, head = self._read(root)
            if phase != "witnessed":
                raise Denied(Refusal.RECONCILIATION_REQUIRED)
            return head

    def commit(self, expected, proposed):
        require_successor(expected, proposed)
        with self._transaction() as (root, _):
            phase, head = self._read(root)
            if phase != "witnessed":
                raise Denied(Refusal.RECONCILIATION_REQUIRED)
            if head != expected:
                raise Denied(Refusal.CONFLICT)
            self._publish_verified(root, "pending", proposed)
        return proposed

    def witness(self, head):
        with self._transaction() as (root, _):
            phase, current = self._read(root)
            if phase != "pending" or current != head:
                raise Denied(Refusal.CONFLICT)
            self._publish_verified(root, "witnessed", head)


def _receipt_response(store, command, prior_acknowledgment):
    if command == ["head"]:
        return ["head", store.head().wire()], None
    if len(command) != 3:
        raise Denied(Refusal.BAD_MESSAGE)
    if command[0] == "commit":
        expected, proposed = map(Commitment.parse, command[1:])
        committed = store.commit(expected, proposed)
        challenge = secrets.token_hex(32)
        return ["committed", committed.wire(), challenge], (committed, challenge)
    if command[0] == "witness":
        witnessed = Commitment.parse(command[1])
        if (witnessed, command[2]) != prior_acknowledgment:
            raise Denied(Refusal.RECONCILIATION_REQUIRED)
        store.witness(witnessed)
        return None, None
    raise Denied(Refusal.BAD_MESSAGE)


def serve_receipts(channel, store):
    """One measured controller endpoint. A witness has no success response."""
    expected_witness = None
    while True:
        prior_acknowledgment, expected_witness = expected_witness, None
        command = None
        try:
            command = channel.receive()
            response, next_witness = _receipt_response(store, command, prior_acknowledgment)
        except Denied as failure:
            if failure.reason in (Refusal.LOST_ENDPOINT, Refusal.WRONG_PEER):
                return
            response, next_witness = ["denied", failure.reason.value], None
        if response is None:
            continue
        try:
            channel.send(response)
        except Denied:
            return
        expected_witness = next_witness
        if command and command[0] == "witness":
            return


class ReceiptClient:
    """Holder-side protocol client. A failed channel is never reused."""

    def __init__(self, channel):
        self._channel = channel
        self._failed = False

    def _receive(self, kind):
        reply = self._channel.receive()
        if len(reply) == 2 and reply[0] == "denied":
            try:
                reason = Refusal(reply[1])
            except ValueError:
                raise Denied(Refusal.BAD_MESSAGE) from None
            raise Denied(reason)
        if len(reply) != (3 if kind == "committed" else 2) or reply[0] != kind:
            raise Denied(Refusal.BAD_MESSAGE)
        return Commitment.parse(reply[1]), reply[2:]

    @contextmanager
    def _exchange(self):
        if self._failed:
            raise Denied(Refusal.LOST_ENDPOINT)
        try:
            yield
        except Denied:
            self._failed = True
            self._channel.close()
            raise

    def _head(self):
        self._channel.send(["head"])
        head, _ = self._receive("head")
        return head

    def require(self, expected):
        with self._exchange():
            if self._head() != expected:
                raise Denied(Refusal.PAIR_MISMATCH)

    def require_controller(self):
        with self._exchange():
            self._channel.require_idle_peer(Refusal.LOST_ENDPOINT)

    def advance(self, expected, proposed):
        require_successor(expected, proposed)
        with self._exchange():
            try:
                self._channel.send(["commit", expected.wire(), proposed.wire()])
                acknowledged, (challenge,) = self._receive("committed")
                if acknowledged != proposed:
                    raise Denied(Refusal.PAIR_MISMATCH)
                if not fingerprint(challenge):
                    raise Denied(Refusal.BAD_MESSAGE)
                # The controller accepts the acknowledgment-specific
                # challenge on the original channel only.
                self._channel.send(["witness", proposed.wire(), challenge])
                if self._head() != proposed:
                    raise Denied(Refusal.PAIR_MISMATCH)
            except Denied as failure:
                if failure.reason in (Refusal.LOST_ENDPOINT, Refusal.STORAGE_UNCERTAIN,
                                      Refusal.BAD_MESSAGE, Refusal.WRONG_PEER):
                    raise Denied(Refusal.TRANSITION_UNCERTAIN) from None
                raise


def advance_locked(client, expected, proposed, *, read_local, publish_local, require_authority, dispatch=None):
    """Run inside the holder's one canonical lock; use it for claim and settlement."""
    require_successor(expected, proposed)
    if read_local() != expected:
        raise Denied(Refusal.PAIR_MISMATCH)
    client.require(expected)
    require_authority()
    try:
        publish_local()
    except OSError:
        raise Denied(Refusal.LOCAL_STORAGE_UNCERTAIN) from None
    if read_local() != proposed:
        raise Denied(Refusal.PAIR_MISMATCH)
    client.advance(expected, proposed)
    client.require(proposed)
    if read_local() != proposed:
        raise Denied(Refusal.PAIR_MISMATCH)
    require_authority()
    client.require_controller()
    if dispatch is not None:
        dispatch()
