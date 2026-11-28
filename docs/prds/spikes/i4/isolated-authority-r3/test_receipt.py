"""Offline scratch tests. Only synthetic pair bytes and anonymous AF_UNIX sockets."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
import errno
import fcntl
from hashlib import sha256
import os
import secrets
from pathlib import Path
import select
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from descriptor import Channel, Denied, OwnerGrant, Peer, Refusal, canonical, decode, descriptor_pair, fingerprint
from receipt import Commitment, ReceiptClient, ReceiptStore, acquire_exclusive, advance_locked, serve_receipts


SCOPE = "a" * 64
JOURNAL = "b" * 64
SLOT = "c" * 64
INTENT = "d" * 64
OTHER_SLOT = "e" * 64
THIS_PROCESS = Peer(os.getpid(), os.getuid(), os.getgid())
ROOT = Path(__file__).resolve().parent
_MAX_LOCAL_FILE = 1024


def current_channel(endpoint):
    return Channel(endpoint, THIS_PROCESS, os.pidfd_open(THIS_PROCESS.pid))


def file_identity(info):
    return info.st_dev, info.st_ino


class LocalPair:
    """Minimal claim/settlement bytes for publication testing, not a spend journal."""

    def __init__(self, directory, lock_identity):
        self.directory = directory
        self.lock_identity = lock_identity

    def _require_lock(self, lock):
        try:
            pinned = os.fstat(lock)
            current = os.stat("scope.lock", dir_fd=self.directory, follow_symlinks=False)
        except OSError:
            raise Denied(Refusal.INVALID_SCOPE_LOCK) from None
        if (not stat.S_ISREG(pinned.st_mode) or stat.S_IMODE(pinned.st_mode) != 0o600
                or pinned.st_uid != os.geteuid() or pinned.st_nlink != 1
                or file_identity(pinned) != self.lock_identity or file_identity(current) != self.lock_identity):
            raise Denied(Refusal.INVALID_SCOPE_LOCK)

    @contextmanager
    def locked(self):
        try:
            info = os.fstat(self.directory)
            if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
                    or info.st_uid != os.geteuid()):
                raise Denied(Refusal.INVALID_SCOPE_LOCK)
            flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
            lock = os.open("scope.lock", flags, dir_fd=self.directory)
        except OSError:
            raise Denied(Refusal.INVALID_SCOPE_LOCK) from None
        try:
            self._require_lock(lock)
            acquire_exclusive(lock)
            self._require_lock(lock)
            yield
        finally:
            os.close(lock)

    @staticmethod
    def pair(revision, phase):
        journal = canonical([SCOPE, JOURNAL, revision, phase])
        return journal, canonical([JOURNAL, sha256(journal).hexdigest()])

    @staticmethod
    def commitment(revision, phase):
        return Commitment.for_pair(SCOPE, JOURNAL, revision, LocalPair.pair(revision, phase))

    def restore(self, pair, *, partial=False):
        names = ("journal",) if partial else ("journal", "anchor")
        for name, content in zip(names, pair):
            self._publish_file(name, content)

    def _publish_file(self, name, content):
        temp = ".pair-" + secrets.token_hex(12)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        descriptor = os.open(temp, flags, 0o600, dir_fd=self.directory)
        try:
            with os.fdopen(descriptor, "wb") as writer:
                writer.write(content)
                writer.flush()
                os.fsync(writer.fileno())
            os.replace(temp, name, src_dir_fd=self.directory, dst_dir_fd=self.directory)
            os.fsync(self.directory)
        finally:
            try:
                os.unlink(temp, dir_fd=self.directory)
            except FileNotFoundError:
                pass

    def read(self):
        try:
            journal, anchor = self.snapshot()
            scope, identity, revision, phase = decode(journal)
            if (scope, identity) != (SCOPE, JOURNAL) or self.pair(revision, phase) != (journal, anchor):
                raise ValueError
            return Commitment.for_pair(scope, identity, revision, (journal, anchor))
        except (Denied, OSError, ValueError):
            raise Denied(Refusal.PAIR_MISMATCH) from None

    def snapshot(self):
        return tuple(self._read_file(name) for name in ("journal", "anchor"))

    def _read_file(self, name):
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        descriptor = os.open(name, flags, dir_fd=self.directory)
        with os.fdopen(descriptor, "rb") as reader:
            info = os.fstat(reader.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_LOCAL_FILE:
                raise Denied(Refusal.PAIR_MISMATCH)
            content = reader.read(_MAX_LOCAL_FILE + 1)
        if len(content) > _MAX_LOCAL_FILE:
            raise Denied(Refusal.PAIR_MISMATCH)
        return content

    def advance(self, client, revision, phase, next_phase, guard, dispatch=None, *, partial=False):
        prior = self.commitment(revision, phase)
        proposed = self.commitment(revision + 1, next_phase)
        with self.locked():
            advance_locked(
                client, prior, proposed, read_local=self.read,
                publish_local=lambda: self.restore(self.pair(revision + 1, next_phase), partial=partial),
                require_authority=guard, dispatch=dispatch,
            )


def holder_child(receipt_fd, owner_fd, receipt_pidfd, owner_pidfd, scope_fd, lock_device, lock_inode,
                 controller, revision, phase, next_phase):
    """Fresh exec with pinned sockets, peers and local scope directory."""
    scope_fd = int(scope_fd)
    lock_identity = int(lock_device), int(lock_inode)
    peer = Peer(int(controller), os.getuid(), os.getgid())
    with ExitStack() as opened:
        opened.callback(os.close, scope_fd)
        os.set_inheritable(scope_fd, False)
        receipt = opened.enter_context(Channel(socket.socket(fileno=int(receipt_fd)), peer, int(receipt_pidfd)))
        owner = opened.enter_context(Channel(socket.socket(fileno=int(owner_fd)), peer, int(owner_pidfd)))
        client = ReceiptClient(receipt)
        grant = OwnerGrant(owner, SLOT, INTENT)
        try:
            grant.admit()
            settled = next_phase == "settled"
            dispatch = None if settled else lambda: print("fixture-dispatch", flush=True)
            LocalPair(scope_fd, lock_identity).advance(
                client, int(revision), phase, next_phase, lambda: grant.require_live(SLOT, INTENT), dispatch,
            )
            if settled:
                print("fixture-settlement", flush=True)
        except Denied as failure:
            print(failure.reason.value, flush=True)


class AcknowledgmentFault(Channel):
    def __init__(self, endpoint, peer, peer_pidfd, reply_fault):
        super().__init__(endpoint, peer, peer_pidfd)
        self.reply_fault = reply_fault

    def send(self, value):
        if value[0] == "committed":
            if self.reply_fault == "wrong":
                value[1][3] = "0" * 64
            if self.reply_fault == "lost":
                self.close()
                raise Denied(Refusal.LOST_ENDPOINT)
        super().send(value)


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.external = Path(scratch.name) / "controller"
        self.external.mkdir(mode=0o700)
        self.local_root = Path(scratch.name) / "holder"
        self.local_root.mkdir(mode=0o700)
        self.local_lock = self.local_root / "scope.lock"
        scope = os.open(self.local_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.addCleanup(os.close, scope)
        flags = os.O_RDONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        # Keep the original inode alive throughout the fixture, even if a test unlinks its name.
        lock_pin = os.open("scope.lock", flags, 0o600, dir_fd=scope)
        self.addCleanup(os.close, lock_pin)
        self.local = LocalPair(scope, file_identity(os.fstat(lock_pin)))
        self.initial_pair = self.local.pair(0, "initial")
        self.initial = self.local.commitment(0, "initial")
        self.claim = self.local.commitment(1, "claimed")
        self.settlement = self.local.commitment(2, "settled")
        self.local.restore(self.initial_pair)
        self.store = ReceiptStore(self.external, self.initial)
        self.store.provision()
        self.writes = 0

    def dispatch(self):
        self.writes += 1

    @staticmethod
    def allowed():
        """Supply successful owner authorization in tests focused on receipts."""
        return None

    @contextmanager
    def connected(self, *, reply_fault=None, store=None):
        holder, controller = descriptor_pair()
        store = self.store if store is None else store
        with (
            holder, controller,
            AcknowledgmentFault(controller, THIS_PROCESS, os.pidfd_open(THIS_PROCESS.pid), reply_fault) as channel,
            ThreadPoolExecutor(max_workers=1) as pool,
        ):
            connected = pool.submit(serve_receipts, channel, store)
            try:
                with current_channel(holder) as client:
                    yield client
            finally:
                holder.close()
                connected.result(timeout=3)

    def spawn(self, module, call, *arguments, pass_fds=(), stdin=subprocess.DEVNULL):
        source = f"import sys; sys.path.insert(0, sys.argv.pop(1)); from {module} import {call}; {call}(*sys.argv[1:])"
        return subprocess.Popen(
            [sys.executable, "-I", "-S", "-B", "-c", source, str(ROOT), *map(str, arguments)],
            env={}, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            pass_fds=pass_fds, text=True,
        )

    def run_holder(self, revision, phase, next_phase, *, reply_fault=None, store=None, timeout=6):
        receipt_fd, controller_fd = descriptor_pair()
        owner_fd, owner_peer = descriptor_pair()
        store = self.store if store is None else store
        with receipt_fd, controller_fd, owner_fd, owner_peer, ThreadPoolExecutor(max_workers=1) as pool:
            with ExitStack() as inherited_pins:
                pins = []
                for _ in range(2):
                    pidfd = os.pidfd_open(THIS_PROCESS.pid)
                    inherited_pins.callback(os.close, pidfd)
                    pins.append(pidfd)
                inherited = receipt_fd.fileno(), owner_fd.fileno(), *pins, self.local.directory
                process = self.spawn(
                    "test_receipt", "holder_child", *inherited, *self.local.lock_identity, os.getpid(),
                    revision, phase, next_phase, pass_fds=inherited,
                )
            with process:
                receipt_fd.close()
                owner_fd.close()
                peer = Peer(process.pid, os.getuid(), os.getgid())
                with AcknowledgmentFault(controller_fd, peer, os.pidfd_open(process.pid), reply_fault) as controller:
                    server = pool.submit(serve_receipts, controller, store)
                    owner_peer.send(canonical(["owner", "launch", SLOT, INTENT]))
                    try:
                        stdout, stderr = process.communicate(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate()
                        raise
                    server.result(timeout=3)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertEqual(stderr, "")
            return stdout.strip()

    @contextmanager
    def retained_peer(self, role):
        holder, peer = descriptor_pair()
        stop_read, stop_write = os.pipe()
        try:
            inherited = peer.fileno(), stop_read
            with holder, peer, self.spawn(
                "test_receipt", "peer_with_retained_socket", *inherited, role,
                pass_fds=inherited, stdin=subprocess.PIPE,
            ) as process:
                peer.close()
                identity = Peer(process.pid, os.getuid(), os.getgid())
                with Channel(holder, identity, os.pidfd_open(process.pid)) as channel:
                    try:
                        yield process, channel
                    finally:
                        if process.poll() is None:
                            process.kill()
                            process.communicate(timeout=3)
        finally:
            os.close(stop_write)
            os.close(stop_read)

    def require_exited_with_retained_socket(self, process, channel):
        stdout, stderr = process.communicate(input="x", timeout=3)
        self.assertEqual((process.returncode, stdout, stderr), (0, "", ""))
        self.assertEqual(select.select([channel.endpoint], [], [], 0)[0], [])

    def test_verified_controller_keeps_serving_after_holder_restart_only(self):
        self.assertEqual(self.run_holder(0, "initial", "claimed"), "fixture-dispatch")
        fresh = ReceiptStore(self.external, self.initial)
        self.assertEqual(self.run_holder(1, "claimed", "settled", store=fresh),
                         Refusal.RECONCILIATION_REQUIRED.value)
        self.assertEqual(self.run_holder(1, "claimed", "settled"), "fixture-settlement")
        self.assertEqual(self.store.head(), self.settlement)

    def test_claim_and_settlement_are_both_externally_witnessed(self):
        with self.connected() as channel:
            client = ReceiptClient(channel)
            self.local.advance(client, 0, "initial", "claimed", self.allowed, self.dispatch)
            self.assertEqual(self.store.head(), self.claim)
            self.local.advance(client, 1, "claimed", "settled", self.allowed)
            self.assertEqual(self.store.head(), self.settlement)
        self.assertEqual(self.writes, 1)

    def test_stale_consistent_pairs_after_claim_and_settlement_stop_before_local_publish(self):
        with self.connected() as channel:
            self.local.advance(ReceiptClient(channel), 0, "initial", "claimed", self.allowed, self.dispatch)
        claim_pair = self.local.snapshot()
        self.local.restore(self.initial_pair)
        with self.connected() as channel, self.assertRaises(Denied) as denial:
            self.local.advance(ReceiptClient(channel), 0, "initial", "claimed", self.allowed, self.dispatch)
        self.assertEqual(denial.exception.reason, Refusal.PAIR_MISMATCH)
        self.assertEqual(self.local.snapshot(), self.initial_pair)

        self.local.restore(claim_pair)
        with self.connected() as channel:
            self.local.advance(ReceiptClient(channel), 1, "claimed", "settled", self.allowed)
        self.local.restore(claim_pair)
        with self.connected() as channel, self.assertRaises(Denied) as denial:
            self.local.advance(ReceiptClient(channel), 1, "claimed", "settled", self.allowed)
        self.assertEqual(denial.exception.reason, Refusal.PAIR_MISMATCH)
        self.assertEqual(self.local.snapshot(), claim_pair)
        self.assertEqual(self.store.head(), self.settlement)
        self.assertEqual(self.writes, 1)

    def test_exact_claim_written_but_ack_lost_across_two_fresh_holder_execs(self):
        self.assertEqual(self.run_holder(0, "initial", "claimed", reply_fault="lost"),
                         Refusal.TRANSITION_UNCERTAIN.value)
        self.assertEqual(self.local.read(), self.claim)
        evidence = (self.external / "continuity.json").read_bytes()
        self.assertEqual(decode(evidence), ["r3", "pending", self.claim.wire()])

        self.assertEqual(self.run_holder(1, "claimed", "settled"), Refusal.RECONCILIATION_REQUIRED.value)
        rebooted_controller = ReceiptStore(self.external, self.initial)
        self.assertEqual(self.run_holder(1, "claimed", "settled", store=rebooted_controller),
                         Refusal.RECONCILIATION_REQUIRED.value)
        self.assertEqual(self.local.read(), self.claim)
        self.assertEqual((self.external / "continuity.json").read_bytes(), evidence)

        # The next authenticated holder cannot manufacture a witness for the
        # previous channel, even if it already knows the exact current digest.
        with self.connected() as channel:
            channel.send(["witness", self.claim.wire(), "0" * 64])
            self.assertEqual(channel.receive(), ["denied", Refusal.RECONCILIATION_REQUIRED.value])
        self.assertEqual((self.external / "continuity.json").read_bytes(), evidence)

    def test_exact_settlement_written_but_ack_lost_never_releases_headroom_on_restart(self):
        self.assertEqual(self.run_holder(0, "initial", "claimed"), "fixture-dispatch")
        self.assertEqual(self.run_holder(1, "claimed", "settled", reply_fault="lost"),
                         Refusal.TRANSITION_UNCERTAIN.value)
        self.assertEqual(self.local.read(), self.settlement)
        self.assertEqual(self.run_holder(2, "settled", "next-claim"), Refusal.RECONCILIATION_REQUIRED.value)
        self.assertEqual(self.run_holder(2, "settled", "next-claim", store=ReceiptStore(self.external, self.initial)),
                         Refusal.RECONCILIATION_REQUIRED.value)
        self.assertEqual(self.local.read(), self.settlement)

    def test_different_ack_is_not_witnessed(self):
        self.assertEqual(self.run_holder(0, "initial", "claimed", reply_fault="wrong"),
                         Refusal.PAIR_MISMATCH.value)
        self.assertEqual(self.local.read(), self.claim)
        self.assertEqual(self.run_holder(1, "claimed", "settled"), Refusal.RECONCILIATION_REQUIRED.value)

    def test_external_failure_before_commit_preserves_mismatch_and_next_holder_refuses(self):
        receipt = self.external / "continuity.json"
        previous = receipt.read_bytes()
        with patch.object(self.store, "_publish", side_effect=OSError(errno.EIO, "synthetic write failure")):
            self.assertEqual(self.run_holder(0, "initial", "claimed"), Refusal.TRANSITION_UNCERTAIN.value)
        self.assertEqual(self.local.read(), self.claim)
        self.assertEqual(receipt.read_bytes(), previous)
        self.assertEqual(self.run_holder(1, "claimed", "settled"), Refusal.RECONCILIATION_REQUIRED.value)

    def require_reconciliation_after_rename_sync_failure(self, *, restart_controller):
        self.assertEqual(self.run_holder(0, "initial", "claimed"), "fixture-dispatch")
        receipt = self.external / "continuity.json"
        witnessed = canonical(["r3", "witnessed", self.settlement.wire()])
        directory = self.external.stat()
        actual_sync = os.fsync
        faults = []

        def fail_after_witness_rename(descriptor):
            info = os.fstat(descriptor)
            if ((info.st_dev, info.st_ino) == (directory.st_dev, directory.st_ino)
                    and receipt.read_bytes() == witnessed and not faults):
                faults.append("post-rename")
                raise OSError(errno.EIO, "synthetic directory sync failure")
            return actual_sync(descriptor)

        with patch("receipt.os.fsync", side_effect=fail_after_witness_rename):
            self.assertEqual(self.run_holder(1, "claimed", "settled"), Refusal.TRANSITION_UNCERTAIN.value)
        self.assertEqual(faults, ["post-rename"])
        self.assertEqual(receipt.read_bytes(), witnessed)
        self.assertEqual(self.local.read(), self.settlement)
        store = ReceiptStore(self.external, self.initial) if restart_controller else self.store
        self.assertEqual(self.run_holder(2, "settled", "next-claim", store=store),
                         Refusal.RECONCILIATION_REQUIRED.value)
        self.assertEqual(receipt.read_bytes(), witnessed)
        self.assertEqual(self.local.read(), self.settlement)

    def test_post_witness_rename_sync_failure_poisoned_controller_cannot_promote(self):
        self.require_reconciliation_after_rename_sync_failure(restart_controller=False)

    def test_post_witness_rename_sync_failure_fresh_controller_cannot_promote(self):
        self.require_reconciliation_after_rename_sync_failure(restart_controller=True)

    def test_external_lock_wait_is_bounded_and_does_not_poison_clean_head(self):
        with self.connected() as channel:
            client = ReceiptClient(channel)
            with (self.external / "installation.lock").open("rb") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                start = time.monotonic()
                with self.assertRaises(Denied) as refusal:
                    client.require(self.initial)
                self.assertEqual(refusal.exception.reason, Refusal.LOCK_BUSY)
                self.assertLess(time.monotonic() - start, 1.5)
        self.assertEqual(self.store.head(), self.initial)

    def test_external_lock_replaced_while_waiting_cannot_change_receipt(self):
        path = self.external / "installation.lock"
        receipt = self.external / "continuity.json"
        evidence = receipt.read_bytes()
        waiting = threading.Event()
        replaced = threading.Event()
        actual_flock = fcntl.flock

        def observe_contention(descriptor, operation):
            try:
                actual_flock(descriptor, operation)
            except BlockingIOError:
                waiting.set()
                if not replaced.wait(1):
                    raise AssertionError("lock replacement did not complete")
                raise

        with path.open("rb") as holder, ThreadPoolExecutor(max_workers=1) as pool:
            actual_flock(holder, fcntl.LOCK_EX)
            with (patch("receipt.fcntl.flock", side_effect=observe_contention),
                  patch("receipt._LOCK_WAIT_SECONDS", 2)):
                result = pool.submit(self.store.commit, self.initial, self.claim)
                try:
                    self.assertTrue(waiting.wait(1), "controller did not wait on the original lock")
                    path.rename(path.with_name("detached.lock"))
                    path.touch(mode=0o600)
                finally:
                    actual_flock(holder, fcntl.LOCK_UN)
                    replaced.set()
                with self.assertRaises(Denied) as refusal:
                    result.result(timeout=3)

        self.assertEqual(refusal.exception.reason, Refusal.INVALID_RECEIPT)
        self.assertEqual(receipt.read_bytes(), evidence)
        with self.assertRaises(Denied) as refusal:
            self.store.head()
        self.assertEqual(refusal.exception.reason, Refusal.RECONCILIATION_REQUIRED)

    def test_local_scope_fifo_refused_in_bounded_child(self):
        self.local_lock.unlink()
        os.mkfifo(self.local_lock, mode=0o600)
        self.assertEqual(self.run_holder(0, "initial", "claimed", timeout=1.5),
                         Refusal.INVALID_SCOPE_LOCK.value)
        self.assertEqual(self.local.snapshot(), self.initial_pair)
        self.assertEqual(self.store.head(), self.initial)

    def test_local_scope_rejects_symlink_directory_and_other_private_inode(self):
        saved = self.local_lock.with_name("original")
        self.local_lock.rename(saved)
        try:
            self.local_lock.symlink_to(saved)
            self.assertEqual(self.run_holder(0, "initial", "claimed"), Refusal.INVALID_SCOPE_LOCK.value)
            self.local_lock.unlink()

            self.local_lock.mkdir(mode=0o700)
            self.assertEqual(self.run_holder(0, "initial", "claimed"), Refusal.INVALID_SCOPE_LOCK.value)
            self.local_lock.rmdir()

            self.local_lock.touch(mode=0o600)
            self.assertEqual(self.run_holder(0, "initial", "claimed"), Refusal.INVALID_SCOPE_LOCK.value)
            self.local_lock.unlink()
        finally:
            saved.rename(self.local_lock)
        self.assertEqual(self.local.snapshot(), self.initial_pair)
        self.assertEqual(self.store.head(), self.initial)

    def test_local_scope_rejects_nonprivate_directory_or_lock_and_linked_lock(self):
        self.local_root.chmod(0o750)
        self.assertEqual(self.run_holder(0, "initial", "claimed"), Refusal.INVALID_SCOPE_LOCK.value)
        self.local_root.chmod(0o700)

        self.local_lock.chmod(0o640)
        self.assertEqual(self.run_holder(0, "initial", "claimed"), Refusal.INVALID_SCOPE_LOCK.value)
        self.local_lock.chmod(0o600)

        alias = self.local_lock.with_name("alias")
        alias.hardlink_to(self.local_lock)
        self.assertEqual(self.run_holder(0, "initial", "claimed"), Refusal.INVALID_SCOPE_LOCK.value)
        alias.unlink()
        self.assertEqual(self.store.head(), self.initial)

    def test_local_scope_lock_wait_is_bounded_and_released(self):
        with self.local.locked():
            start = time.monotonic()
            self.assertEqual(self.run_holder(0, "initial", "claimed", timeout=1.5), Refusal.LOCK_BUSY.value)
            self.assertLess(time.monotonic() - start, 1.5)
        self.assertEqual(self.store.head(), self.initial)
        self.assertEqual(self.run_holder(0, "initial", "claimed"), "fixture-dispatch")
        self.assertEqual(self.store.head(), self.claim)

    def test_local_pair_rejects_oversize_and_nonregular_files_without_waiting(self):
        journal = self.local_root / "journal"
        journal.write_bytes(b" " * (_MAX_LOCAL_FILE + 1))
        self.assertEqual(self.run_holder(0, "initial", "claimed"), Refusal.PAIR_MISMATCH.value)
        journal.unlink()
        os.mkfifo(journal, mode=0o600)
        start = time.monotonic()
        self.assertEqual(self.run_holder(0, "initial", "claimed"), Refusal.PAIR_MISMATCH.value)
        self.assertLess(time.monotonic() - start, 1.5)
        self.assertEqual(self.store.head(), self.initial)

    def test_partial_pair_stays_inert_without_moving_receipt(self):
        with self.connected() as channel, self.assertRaises(Denied) as denial:
            self.local.advance(ReceiptClient(channel), 0, "initial", "claimed",
                               self.allowed, self.dispatch, partial=True)
        self.assertEqual(denial.exception.reason, Refusal.PAIR_MISMATCH)
        self.assertEqual(self.local.snapshot(), (self.local.pair(1, "claimed")[0], self.initial_pair[1]))
        self.assertEqual(self.store.head(), self.initial)
        self.assertEqual(self.writes, 0)

    def test_local_pair_loss_cannot_be_recreated_in_operation(self):
        for path in ("journal", "anchor"):
            (self.local_root / path).unlink()
        self.assertEqual(self.run_holder(0, "initial", "claimed"), Refusal.PAIR_MISMATCH.value)
        self.assertFalse((self.local_root / "journal").exists())
        self.assertFalse((self.local_root / "anchor").exists())
        self.assertEqual(self.store.head(), self.initial)

    def test_receipt_loss_cannot_be_recreated_in_operation(self):
        (self.external / "continuity.json").unlink()
        self.assertEqual(self.run_holder(0, "initial", "claimed"), Refusal.MISSING_RECEIPT.value)
        self.assertFalse((self.external / "continuity.json").exists())
        with self.assertRaises(Denied) as refusal:
            self.store.provision()
        self.assertEqual(refusal.exception.reason, Refusal.CONFLICT)
        self.assertEqual(self.local.snapshot(), self.initial_pair)

    def test_replaced_initial_identity_is_refused(self):
        wrong = Commitment("f" * 64, JOURNAL, 0, self.initial.pair_digest)
        (self.external / "continuity.json").write_bytes(canonical(["r3", "witnessed", wrong.wire()]))
        self.assertEqual(self.run_holder(0, "initial", "claimed"), Refusal.INVALID_RECEIPT.value)
        self.assertEqual(self.local.snapshot(), self.initial_pair)

    def test_cas_rejects_mismatched_prior_index_digest_and_replay(self):
        with self.connected() as channel:
            bad_index = Commitment(SCOPE, JOURNAL, 1, self.initial.pair_digest)
            bad_digest = Commitment(SCOPE, JOURNAL, 0, "0" * 64)
            for wrong in (bad_index, bad_digest):
                channel.send(["commit", wrong.wire(), self.claim.wire()])
                self.assertEqual(channel.receive(), ["denied", Refusal.CONFLICT.value])
            channel.send(["commit", self.initial.wire(), self.claim.wire()])
            kind, commitment, challenge = channel.receive()
            self.assertEqual((kind, commitment), ("committed", self.claim.wire()))
            self.assertTrue(fingerprint(challenge))
            channel.send(["witness", self.claim.wire(), challenge])
            channel.send(["head"])
            self.assertEqual(channel.receive(), ["head", self.claim.wire()])
            channel.send(["commit", self.initial.wire(), self.claim.wire()])
            self.assertEqual(channel.receive(), ["denied", Refusal.CONFLICT.value])

    def test_same_channel_cannot_witness_without_receiving_its_challenge(self):
        with self.connected() as channel:
            channel.send(["commit", self.initial.wire(), self.claim.wire()])
            # The peer can compute exact journal bytes before receiving the
            # acknowledgment. Those bytes do not prove acknowledgment.
            channel.send(["witness", self.claim.wire(), "0" * 64])
            self.assertEqual(channel.receive()[:2], ["committed", self.claim.wire()])
            self.assertEqual(channel.receive(), ["denied", Refusal.RECONCILIATION_REQUIRED.value])
        with self.assertRaises(Denied) as refusal:
            self.store.head()
        self.assertEqual(refusal.exception.reason, Refusal.RECONCILIATION_REQUIRED)

    def test_competing_scope_transitions_dispatch_only_once(self):
        def request(other):
            with self.connected() as channel:
                try:
                    self.local.advance(ReceiptClient(channel), 0, "initial", other, self.allowed, self.dispatch)
                except Denied as failure:
                    return failure.reason
            return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(request, ("profile-a-claim", "profile-b-claim")))
        self.assertCountEqual(results, [None, Refusal.PAIR_MISMATCH])
        self.assertEqual(self.store.head(), self.local.read())
        self.assertEqual(self.writes, 1)

    def test_owner_lost_after_commit_denies_dispatch(self):
        owner_fd, peer = descriptor_pair()
        with peer, current_channel(owner_fd) as owner, self.connected() as receipt:
            grant = OwnerGrant(owner, SLOT, INTENT)
            peer.send(canonical(["owner", "launch", SLOT, INTENT]))
            grant.admit()

            def authority():
                if self.local.read() == self.claim:
                    peer.close()
                grant.require_live(SLOT, INTENT)

            with self.assertRaises(Denied) as denial:
                self.local.advance(ReceiptClient(receipt), 0, "initial", "claimed", authority, self.dispatch)
        self.assertEqual(denial.exception.reason, Refusal.OWNER_LOST)
        self.assertEqual(self.store.head(), self.claim)
        self.assertEqual(self.writes, 0)

    def test_controller_lifeline_loss_after_fresh_head_denies_dispatch(self):
        holder, controller = descriptor_pair()
        with (
            current_channel(holder) as holder_channel, current_channel(controller) as controller_channel,
            ThreadPoolExecutor(max_workers=1) as pool,
        ):
            server = pool.submit(serve_receipts, controller_channel, self.store)
            client = ReceiptClient(holder_channel)

            def authority():
                if self.local.read() == self.claim:
                    controller.shutdown(socket.SHUT_RDWR)

            with self.assertRaises(Denied) as denial:
                self.local.advance(client, 0, "initial", "claimed", authority, self.dispatch)
            server.result(timeout=3)
        self.assertEqual(denial.exception.reason, Refusal.LOST_ENDPOINT)
        self.assertEqual(self.store.head(), self.claim)
        self.assertEqual(self.writes, 0)

    def test_owner_exit_with_retained_socket_denies_dispatch(self):
        with self.retained_peer("owner") as (process, owner), self.connected() as receipt:
            grant = OwnerGrant(owner, SLOT, INTENT)
            grant.admit()

            def authority():
                if self.local.read() == self.claim:
                    self.require_exited_with_retained_socket(process, owner)
                grant.require_live(SLOT, INTENT)

            with self.assertRaises(Denied) as denial:
                self.local.advance(ReceiptClient(receipt), 0, "initial", "claimed", authority, self.dispatch)
        self.assertEqual(denial.exception.reason, Refusal.OWNER_LOST)
        self.assertEqual(self.store.head(), self.claim)
        self.assertEqual(self.writes, 0)

    def test_controller_exit_with_retained_socket_fails_independent_liveness_check(self):
        with self.retained_peer("controller") as (process, controller):
            client = ReceiptClient(controller)
            client.require(self.initial)
            client.require_controller()
            self.require_exited_with_retained_socket(process, controller)
            with self.assertRaises(Denied) as denial:
                client.require_controller()
        self.assertEqual(denial.exception.reason, Refusal.LOST_ENDPOINT)

    def test_wrong_grant_role_cross_slot_and_replay_fail(self):
        for role, slot in (("worker", SLOT), ("owner", OTHER_SLOT)):
            with self.subTest(role=role, slot=slot):
                left, right = descriptor_pair()
                with right, current_channel(left) as owner:
                    grant = OwnerGrant(owner, SLOT, INTENT)
                    right.send(canonical([role, "launch", slot, INTENT]))
                    with self.assertRaises(Denied) as denial:
                        grant.admit()
                self.assertEqual(denial.exception.reason, Refusal.WRONG_GRANT)
        left, right = descriptor_pair()
        with right, current_channel(left) as owner:
            grant = OwnerGrant(owner, SLOT, INTENT)
            right.send(canonical(["owner", "launch", SLOT, INTENT]))
            grant.admit()
            with self.assertRaises(Denied) as denial:
                grant.admit()
            self.assertEqual(denial.exception.reason, Refusal.WRONG_GRANT)
            with self.assertRaises(Denied) as denial:
                grant.require_live(OTHER_SLOT, INTENT)
            self.assertEqual(denial.exception.reason, Refusal.WRONG_GRANT)

    def test_inherited_endpoint_from_other_same_uid_process_cannot_impersonate_owner(self):
        left, right = descriptor_pair()
        with right, current_channel(left) as owner:
            with self.spawn("test_receipt", "unrelated_child", right.fileno(), pass_fds=(right.fileno(),)) as other:
                stdout, stderr = other.communicate(timeout=3)
                self.assertEqual((other.returncode, stdout, stderr), (0, "", ""))
            grant = OwnerGrant(owner, SLOT, INTENT)
            with self.assertRaises(Denied) as denial:
                grant.admit()
            self.assertEqual(denial.exception.reason, Refusal.WRONG_PEER)


def peer_with_retained_socket(descriptor, stop_read, role):
    stop_read = int(stop_read)
    endpoint = socket.socket(fileno=int(descriptor))
    if os.fork() == 0:
        for fd in (0, 1, 2):
            os.close(fd)
        try:
            os.read(stop_read, 1)
        finally:
            os._exit(0)
    os.close(stop_read)
    with endpoint:
        if role == "owner":
            endpoint.send(canonical(["owner", "launch", SLOT, INTENT]))
        else:
            if decode(endpoint.recv(1024)) != ["head"]:
                raise ValueError("invalid fixture probe")
            head = LocalPair.commitment(0, "initial")
            endpoint.send(canonical(["head", head.wire()]))
        sys.stdin.read(1)


def unrelated_child(descriptor):
    with socket.socket(fileno=int(descriptor)) as endpoint:
        endpoint.send(canonical(["owner", "launch", SLOT, INTENT]))


if __name__ == "__main__":
    unittest.main()
