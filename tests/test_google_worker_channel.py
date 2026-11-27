"""Verify the private retained worker channel using only synthetic local sockets."""

from array import array
from contextlib import suppress
from copy import copy, deepcopy
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import pickle
import shutil
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import RLock
import unittest
from unittest.mock import Mock, patch

from oc_google import worker_channel as channel
from oc_orchestrator import protocol


MODEL = "gemini-fixture"
PROOF = b"p" * protocol.PROOF_SIZE
TOKEN = b"fixture-worker"
SYSTEM = "Synthetic system.\nToday's date: Wed Nov 25 2026"
SYSTEM_DIGEST = sha256(b"Synthetic system.\nToday's date: [date]").hexdigest()
WORKER_ID = "a" * 64
RELAY_ID = "b" * 64
WORKER_GROUP = b"/worker-fixture.scope"
RELAY_GROUP = b"/relay-fixture.scope"

RELAY = """
from array import array
import os
import socket
import sys

address, number, mode = sys.argv[1:]
adopted = int(number)
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control:
    control.connect(address)
    rights = (socket.SOL_SOCKET, socket.SCM_RIGHTS, array('i', [adopted]))
    if mode == 'early-rights':
        control.sendmsg([b'p' * 32], [rights])
    else:
        control.sendall(b'p' * 32)
    if mode == 'missing':
        control.sendall(b'F')
    elif mode in ('two', 'truncated'):
        count = 2 if mode == 'two' else 4
        extra = (socket.SOL_SOCKET, socket.SCM_RIGHTS, array('i', [adopted] * count))
        control.sendmsg([b'F'], [extra])
    else:
        control.sendmsg([b'F'], [rights])
        if mode == 'extra-message':
            control.sendmsg([b'F'], [rights])
os.close(adopted)
sys.stdin.buffer.read(1)
"""

FOREIGN_WORKER = """
from array import array
import socket
import subprocess
import sys

descriptor, port, ip = sys.argv[1:]
subprocess.run([ip, 'link', 'set', 'lo', 'up'], check=True)
with socket.socket(fileno=int(descriptor)) as out:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(('127.0.0.1', int(port)))
        listener.listen(1)
        with socket.create_connection(listener.getsockname(), timeout=2) as worker:
            accepted, _ = listener.accept()
            with accepted:
                rights = (socket.SOL_SOCKET, socket.SCM_RIGHTS, array('i', [worker.fileno(), accepted.fileno()]))
                out.sendmsg([b'F'], [rights])
"""


class WorkerChannelTest(unittest.TestCase):
    def setUp(self):
        if not hasattr(os, "pidfd_open"):
            self.skipTest("Linux pidfd support is required")
        self.root = Path(self.enterContext(TemporaryDirectory(prefix="oc-worker-")))
        self.address = self.root / "handoff"
        self.control_listener = self.enterContext(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        self.control_listener.bind(str(self.address))
        self.control_listener.listen(2)
        self.control_listener.settimeout(3)
        self.local_listener = self.enterContext(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        self.local_listener.bind(("127.0.0.1", 0))
        self.local_listener.listen(1)
        self.local_listener.settimeout(3)
        self.port = self.local_listener.getsockname()[1]
        self.owner = True
        self.worker_present = True
        self.fence = RLock()
        self.genuine_retirement = None
        self.groups = {os.getpid(): b"0::" + WORKER_GROUP + b"\n"}
        self.claim = Mock(return_value=True)
        self.check_worker = Mock(side_effect=lambda placement: self.worker_present and placement is self.placement)
        self.check_retirement = Mock(side_effect=lambda receipt: self.genuine_retirement is receipt)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reference:
            self.reference = channel.WorkerNamespaceReference(
                reference, worker_id=WORKER_ID, run="test-run", epoch="epoch-1", probe_id="independent-reference",
            )

    def stop(self, proc):
        if proc.stdin is not None:
            proc.stdin.close()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
        return proc.returncode

    def proc(self, source, args=(), *, pass_fds=()):
        proc = subprocess.Popen(
            [sys.executable, "-IB", "-c", source, *args], stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, pass_fds=pass_fds,
            env={"PATH": "/usr/bin:/bin"},
        )
        self.addCleanup(self.stop, proc)
        return proc

    def pin(self, pid, group):
        self.groups[pid] = b"0::" + group + b"\n"
        fd = os.pidfd_open(pid)
        try:
            return self.enterContext(channel.ProcessPin(
                pid=pid, uid=os.getuid(), pidfd=fd, cgroup=group, read_cgroup=self.groups.__getitem__,
            ))
        finally:
            os.close(fd)

    def fixture(self, *, mode="exact", foreign=False, wrong_pid=False, wrong_group=False,
                distinct_worker=False, token=TOKEN, extra=b""):
        if foreign:
            worker, accepted = self.foreign_worker()
        else:
            worker = socket.create_connection(("127.0.0.1", self.port), timeout=3)
            accepted, _ = self.local_listener.accept()
        worker = self.enterContext(worker)
        worker.settimeout(3)
        with accepted:
            relay = self.proc(RELAY, (str(self.address), str(accepted.fileno()), mode), pass_fds=(accepted.fileno(),))
            proc = self.proc("import sys; sys.stdin.buffer.read(1)") if wrong_pid else relay
            if distinct_worker:
                self.worker_proc = self.proc("import sys; sys.stdin.buffer.read(1)")
            worker_pin = self.pin(self.worker_proc.pid if distinct_worker else os.getpid(), WORKER_GROUP)
            relay_pin = self.pin(proc.pid, RELAY_GROUP)
            if wrong_group:
                self.groups[relay.pid] = b"0::/other-fixture.scope\n"
            self.placement = channel.WorkerPlacement(
                worker_id=WORKER_ID, worker_image="c" * 64, relay_id=RELAY_ID, relay_image="d" * 64,
                run="test-run", route="google--personal", epoch="epoch-1", network_mode="none",
                relay_network_mode=f"container:{WORKER_ID}", worker=worker_pin, relay=relay_pin,
                reference=self.reference,
            )
        retained = self.enterContext(channel.RetainedWorkerChannel(
            self.placement, port=self.port, model=MODEL, system_digest=SYSTEM_DIGEST,
            worker_token=TOKEN, proof=PROOF, fence=self.fence, owner_current=lambda: self.owner,
            worker_current=self.check_worker, retirement_current=self.check_retirement, claim_delivery=self.claim,
        ))
        body = json.dumps(dict(protocol.OPTIONS, model=MODEL, messages=[
            {"role": "system", "content": SYSTEM}, {"role": "user", "content": protocol.PROMPT},
        ])).encode("ascii")
        head = (f"POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\n"
                f"Authorization: Bearer {token.decode()}\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n\r\n").encode("ascii")
        worker.sendall(head + body + extra)
        control, _ = self.control_listener.accept()
        self.addCleanup(control.close)
        return retained, relay, worker, control, body

    def foreign_worker(self):
        unshare, ip = shutil.which("unshare"), shutil.which("ip")
        if not unshare or not ip:
            self.skipTest("unshare and ip are required for a separate loopback network namespace")
        parent, child = socket.socketpair()
        with parent, child:
            command = [unshare, "--user", "--map-root-user", "--net", sys.executable, "-IB", "-c", FOREIGN_WORKER,
                       str(child.fileno()), str(self.port), ip]
            proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.PIPE, pass_fds=(child.fileno(),))
            child.close()
            try:
                parent.settimeout(4)
                width = array("i").itemsize
                marker, messages, flags, _ = parent.recvmsg(1, socket.CMSG_SPACE(width * 2), socket.MSG_CMSG_CLOEXEC)
            finally:
                try:
                    _, stderr = proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate()
                    raise
            if proc.returncode and b"Operation not permitted" in stderr:
                self.skipTest("private network namespace creation refused on this host")
            self.assertEqual(proc.returncode, 0, stderr)
            self.assertEqual((marker, flags & socket.MSG_CTRUNC, len(messages)), (b"F", 0, 1))
            fds = array("i")
            fds.frombytes(messages[0][2])
            worker, accepted = (socket.socket(fileno=fd) for fd in fds)
            self.assertNotEqual(channel._cookie(accepted, channel._NETNS_COOKIE), self.reference.cookie)
            self.assertEqual(accepted.getsockname(), ("127.0.0.1", self.port))
            return worker, accepted

    def seal(self, retained, relay, control):
        adoption = retained.adopt(control)
        retained.close_admission()
        self.assertEqual(self.stop(relay), 0)
        receipt = channel.RelayRetirement(adoption, RELAY_ID)
        self.genuine_retirement = receipt
        retained.seal(receipt)
        return adoption, receipt

    def read_all(self, worker):
        data = bytearray()
        with suppress(ConnectionResetError):
            while chunk := worker.recv(8192):
                data.extend(chunk)
        return bytes(data)

    def test_delivery_keeps_the_exact_channel_during_admission_close_and_relay_retirement(self):
        retained, relay, worker, control, body = self.fixture()
        adoption, retirement = self.seal(retained, relay, control)
        self.assertEqual(adoption.request_digest, sha256(body).hexdigest())
        later_control, other = socket.socketpair()
        with later_control, other:
            with self.assertRaisesRegex(channel.WorkerChannelError, "admission is closed"):
                retained.adopt(later_control)
        result = retained.deliver()
        answer = self.read_all(worker)
        self.assertEqual(answer, protocol.text_reply_bytes(MODEL))
        self.assertEqual(result, channel.DeliveryReceipt(True, len(answer), True))
        self.claim.assert_called_once_with(adoption, retirement)
        with self.assertRaisesRegex(channel.WorkerChannelError, "delivery is not available"):
            retained.deliver()

    def test_correct_live_relay_cannot_adopt_same_shape_socket_from_another_namespace(self):
        retained, relay, worker, control, _ = self.fixture(foreign=True)
        with self.assertRaisesRegex(channel.WorkerChannelError, "namespace differs"):
            retained.adopt(control)
        self.stop(relay)
        self.assertEqual(self.read_all(worker), b"")
        self.claim.assert_not_called()

    def test_refuses_missing_rights(self):
        self.assert_invalid_handoff("missing")

    def test_refuses_extra_rights(self):
        self.assert_invalid_handoff("two")

    def test_refuses_truncated_rights(self):
        self.assert_invalid_handoff("truncated")

    def test_refuses_second_ancillary_message(self):
        self.assert_invalid_handoff("extra-message")

    def test_refuses_descriptor_attached_to_preliminary_proof(self):
        self.assert_invalid_handoff("early-rights")

    def assert_invalid_handoff(self, mode):
        retained, relay, worker, control, _ = self.fixture(mode=mode)
        fd_count = len(os.listdir("/proc/self/fd"))
        with self.assertRaises(channel.WorkerChannelError):
            retained.adopt(control)
        self.assertEqual(len(os.listdir("/proc/self/fd")), fd_count - 1)
        self.stop(relay)
        self.assertEqual(self.read_all(worker), b"")
        self.claim.assert_not_called()

    def test_wrong_relay_pid_cannot_adopt(self):
        retained, relay, worker, control, _ = self.fixture(wrong_pid=True)
        with self.assertRaisesRegex(channel.WorkerChannelError, "peer credentials differ"):
            retained.adopt(control)
        self.stop(relay)
        self.assertEqual(self.read_all(worker), b"")

    def test_right_relay_pid_in_wrong_group_cannot_adopt(self):
        retained, relay, worker, control, _ = self.fixture(wrong_group=True)
        with self.assertRaisesRegex(channel.WorkerChannelError, "process or cgroup differs"):
            retained.adopt(control)
        self.stop(relay)
        self.assertEqual(self.read_all(worker), b"")

    def test_wrong_worker_bearer_cannot_adopt(self):
        retained, relay, worker, control, _ = self.fixture(token=b"sibling-worker-bearer")
        with self.assertRaisesRegex(channel.WorkerChannelError, "fixed request refused"):
            retained.adopt(control)
        self.stop(relay)
        self.assertEqual(self.read_all(worker), b"")

    def test_pipelined_suffix_cannot_adopt(self):
        retained, relay, worker, control, _ = self.fixture(extra=b"x")
        with self.assertRaisesRegex(channel.WorkerChannelError, "fixed request refused"):
            retained.adopt(control)
        self.stop(relay)
        self.assertEqual(self.read_all(worker), b"")

    def test_forged_retirement_evidence_cannot_seal(self):
        retained, relay, worker, control, _ = self.fixture()
        adoption = retained.adopt(control)
        retained.close_admission()
        self.stop(relay)
        self.genuine_retirement = channel.RelayRetirement(adoption, RELAY_ID)
        with self.assertRaisesRegex(channel.WorkerChannelError, "retirement is unconfirmed"):
            retained.seal(replace(self.genuine_retirement))
        self.assertEqual(self.read_all(worker), b"")
        self.claim.assert_not_called()

    def test_observer_receipt_while_exact_relay_is_alive_cannot_seal(self):
        retained, _, worker, control, _ = self.fixture()
        adoption = retained.adopt(control)
        retained.close_admission()
        self.genuine_retirement = channel.RelayRetirement(adoption, RELAY_ID)
        with self.assertRaisesRegex(channel.WorkerChannelError, "retirement is unconfirmed"):
            retained.seal(self.genuine_retirement)
        self.assertEqual(self.read_all(worker), b"")
        self.claim.assert_not_called()

    def test_loss_during_durable_claim_cannot_write(self):
        retained, relay, worker, control, _ = self.fixture()
        self.seal(retained, relay, control)

        def revoke_during_claim(*_):
            self.owner = False
            retained.revoke()
            return True

        self.claim.side_effect = revoke_during_claim
        with patch.object(channel, "_send_once") as write:
            with self.assertRaises(channel.WorkerChannelError):
                retained.deliver()
            write.assert_not_called()
        self.assertEqual(self.read_all(worker), b"")
        self.assertEqual(retained.delivery, channel.DeliveryReceipt())

    def test_worker_loss_after_relay_retirement_cannot_write(self):
        retained, relay, worker, control, _ = self.fixture()
        self.seal(retained, relay, control)
        self.worker_present = False
        with self.assertRaisesRegex(channel.WorkerChannelError, "worker or owner is no longer current"):
            retained.deliver()
        self.assertEqual(self.read_all(worker), b"")
        self.claim.assert_not_called()

    def test_exact_worker_process_exit_blocks_delivery(self):
        retained, relay, worker, control, _ = self.fixture(distinct_worker=True)
        self.seal(retained, relay, control)
        self.assertEqual(self.stop(self.worker_proc), 0)
        with self.assertRaisesRegex(channel.WorkerChannelError, "worker or owner is no longer current"):
            retained.deliver()
        self.assertEqual(self.read_all(worker), b"")
        self.claim.assert_not_called()

    def test_reused_descriptor_number_is_not_written_or_closed(self):
        retained, relay, worker, control, _ = self.fixture()
        self.seal(retained, relay, control)
        sibling = self.enterContext(socket.create_connection(("127.0.0.1", self.port), timeout=3))
        replacement, _ = self.local_listener.accept()
        with replacement:
            fd = retained._client.fileno()
            os.dup2(replacement.fileno(), fd, inheritable=False)
            try:
                with self.assertRaisesRegex(channel.WorkerChannelError, "descriptor changed"):
                    retained.deliver()
                self.assertEqual(os.fstat(fd).st_ino, os.fstat(replacement.fileno()).st_ino)
                sibling.setblocking(False)
                with self.assertRaises(BlockingIOError):
                    sibling.recv(8192)
            finally:
                os.close(fd)
        self.assertEqual(self.read_all(worker), b"")
        self.claim.assert_not_called()

    def test_changed_socket_cookie_refuses_same_descriptor_without_destroying_it(self):
        retained, relay, worker, control, _ = self.fixture()
        self.seal(retained, relay, control)
        original = channel._cookie
        fd = retained._client.fileno()

        def changed(connection, option):
            value = original(connection, option)
            return value + 1 if option == channel._COOKIE else value

        try:
            with patch.object(channel, "_cookie", side_effect=changed):
                with self.assertRaisesRegex(channel.WorkerChannelError, "descriptor changed"):
                    retained.deliver()
            self.assertGreater(os.fstat(fd).st_ino, 0)
            worker.setblocking(False)
            with self.assertRaises(BlockingIOError):
                worker.recv(8192)
        finally:
            with suppress(OSError):
                os.close(fd)
        worker.settimeout(3)
        self.assertEqual(self.read_all(worker), b"")
        self.claim.assert_not_called()

    def test_exclusive_objects_cannot_be_cloned_or_pickled_to_open_a_second_attempt(self):
        retained, relay, worker, control, _ = self.fixture()
        for subject in (retained, self.placement.worker, self.placement.relay):
            for duplicate in (copy, deepcopy, pickle.dumps):
                with self.subTest(subject=type(subject).__name__, operation=duplicate.__name__):
                    with self.assertRaisesRegex(TypeError, "exclusive ownership"):
                        duplicate(subject)
        self.seal(retained, relay, control)
        peer, second = socket.socketpair()
        with peer, second:
            with self.assertRaisesRegex(channel.WorkerChannelError, "admission is closed"):
                retained.adopt(second)
        with patch.object(channel, "_send_once", wraps=channel._send_once) as send:
            self.assertTrue(retained.deliver().complete)
            with self.assertRaisesRegex(channel.WorkerChannelError, "delivery is not available"):
                retained.deliver()
            send.assert_called_once()
        self.assertEqual(self.read_all(worker), protocol.text_reply_bytes(MODEL))
        self.claim.assert_called_once()

    def test_process_pin_does_not_close_a_reused_fd_number(self):
        pin = self.pin(os.getpid(), WORKER_GROUP)
        fd = pin._fd
        reader, writer = os.pipe()
        try:
            os.dup2(reader, fd, inheritable=False)
            pin.close()
            self.assertFalse(pin.active())
            pin.close()
            os.write(writer, b"Q")
            self.assertEqual(os.read(fd, 1), b"Q")
        finally:
            with suppress(OSError):
                os.close(fd)
            os.close(reader)
            os.close(writer)

    def test_control_rebind_before_cancellation_preserves_the_foreign_socket(self):
        self.assert_rebound_control_preserved(cancel=True)

    def test_control_rebind_before_adoption_unwind_preserves_the_foreign_socket(self):
        self.assert_rebound_control_preserved(cancel=False)

    def assert_rebound_control_preserved(self, *, cancel):
        retained, relay, worker, control, _ = self.fixture()
        fd = control.fileno()
        unrelated, peer = socket.socketpair()

        def swap(*_):
            os.dup2(unrelated.fileno(), fd, inheritable=False)
            if cancel:
                retained.revoke()
            raise OSError("synthetic failed adoption")

        with unrelated, peer:
            try:
                with patch.object(channel, "_receive_proof", side_effect=swap):
                    with self.assertRaises(channel.WorkerChannelError):
                        retained.adopt(control)
                self.assertEqual(os.fstat(fd).st_ino, os.fstat(unrelated.fileno()).st_ino)
                peer.sendall(b"X")
                self.assertEqual(unrelated.recv(1), b"X")
            finally:
                with suppress(OSError):
                    os.close(fd)
        self.stop(relay)
        self.assertEqual(self.read_all(worker), b"")
        self.claim.assert_not_called()

    def test_uncertain_write_uses_one_syscall_and_cannot_retry(self):
        retained, relay, worker, control, _ = self.fixture()
        self.seal(retained, relay, control)
        with patch.object(channel, "_send_once", side_effect=InterruptedError) as write:
            with self.assertRaises(InterruptedError):
                retained.deliver()
            with self.assertRaisesRegex(channel.WorkerChannelError, "delivery is not available"):
                retained.deliver()
            write.assert_called_once()
        self.assertEqual(retained.delivery, channel.DeliveryReceipt(True, None, False))
        self.assertEqual(self.read_all(worker), b"")

    def test_partial_write_is_not_completed_or_repeated(self):
        retained, relay, worker, control, _ = self.fixture()
        self.seal(retained, relay, control)
        syscall = channel._send_once
        with patch.object(channel, "_send_once", side_effect=lambda sock, data: syscall(sock, data[:10])) as write:
            with self.assertRaisesRegex(channel.WorkerChannelError, "write was incomplete"):
                retained.deliver()
            with self.assertRaisesRegex(channel.WorkerChannelError, "delivery is not available"):
                retained.deliver()
            write.assert_called_once()
        self.claim.assert_called_once()
        self.assertEqual(retained.delivery, channel.DeliveryReceipt(True, 10, False))
        self.assertEqual(self.read_all(worker), protocol.text_reply_bytes(MODEL)[:10])


if __name__ == "__main__":
    unittest.main()
