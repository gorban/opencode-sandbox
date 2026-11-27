"""Exercise the exact fixture proxy sockets on local loopback."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import copy, deepcopy
import errno
import os
from pathlib import Path
import pickle
import select
import signal
import socket
import struct
from tempfile import TemporaryDirectory
from threading import RLock
import unittest
from unittest.mock import patch

from oc_google import generation, generation_phase, generation_proxy, native_peer
from test_google_generation import request, response


class FixturePhaseTest(unittest.TestCase):
    def setUp(self):
        if not os.geteuid():
            self.skipTest("The proxy fixture uses a non-root workstation account")
        probe, counterpart = socket.socketpair()
        with probe, counterpart:
            try:
                fd, = struct.unpack("=i", probe.getsockopt(socket.SOL_SOCKET, native_peer._PEERPIDFD, 4))
            except OSError:
                self.skipTest("The proxy fixture requires SO_PEERPIDFD")
            os.close(fd)
        self.root = Path(self.enterContext(TemporaryDirectory(prefix="oc-google-phase-")))
        self.binding = generation.GenerationBinding(object(), object(), 1, generation.MODEL_ALIAS)
        self.sent = False
        self.live = True
        self.receipt = object()
        self.capability = object()
        self.claim_live = False
        self.scope = None
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as port:
            port.bind((generation_proxy.LOOPBACK, 0))
            self.port = port.getsockname()[1]

    def current_sent(self, binding, receipt):
        return binding is self.binding and receipt is self.receipt and self.sent

    def current_claim(self, binding, receipt, claim):
        return (self.current_sent(binding, receipt) and claim is self.capability
                and self.claim_live and (self.root / "fixture-claim").read_bytes() == b"destination-claimed")

    def claim_destination(self, binding, receipt, effect):
        self.assertTrue(self.current_sent(binding, receipt))
        path = self.root / "fixture-claim"
        with path.open("xb") as record:
            record.write(b"destination-claimed")
            record.flush()
            os.fsync(record.fileno())
        directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        self.claim_live = True
        try:
            return effect(self.capability)
        finally:
            self.claim_live = False
            path.unlink()

    def destination(self):
        return generation.FakeDestination(response(), end_of_input=True)

    @contextmanager
    def helper(self, phase, pause_at_listen=None, *, expect_success=True):
        owner = os.getpid()
        launch = phase.launch
        child = os.fork()
        if child == 0:
            phase._control_listener.close()
            phase._startup.close()
            os.close(phase._root_fd)
            # The fixture child may reach exactly these private Unix listeners.
            # Refuse DNS and every destination socket outside those leaves.
            connect = socket.socket.connect
            leaves = {str(self.root / name) for name in ("control.sock", "startup.sock", "turn.sock")}
            sent_frame = generation_proxy.send_frame

            def private_connect(sock, address):
                if sock.family != socket.AF_UNIX or address not in leaves:
                    raise AssertionError("Unexpected nonprivate fixture dial")
                return connect(sock, address)

            def pause(*args, **kwargs):
                sent_frame(*args, **kwargs)
                if pause_at_listen is not None and args[2] is generation_proxy.Signal.TURN_LISTENING:
                    if not select.select([pause_at_listen], [], [], 3)[0]:
                        raise AssertionError("The test did not release the exact helper")
                    os.read(pause_at_listen, 1)

            try:
                with patch.object(socket.socket, "connect", new=private_connect), \
                        patch.object(socket, "getaddrinfo", side_effect=AssertionError("Unexpected DNS")), \
                        patch.object(generation_proxy, "send_frame", side_effect=pause):
                    generation_proxy.run_fixture_proxy(
                        launch.directory, port=launch.port, stamp=launch.stamp, owner_pid=owner,
                        startup_deadline=launch.startup_deadline, hard_deadline=launch.hard_deadline,
                    )
            except (OSError, RuntimeError, ValueError):
                os._exit(2)
            except BaseException:
                os._exit(3)
            os._exit(0)
        pidfd = os.pidfd_open(child)
        try:
            yield child
        finally:
            try:
                if not select.select([pidfd], [], [], 3)[0]:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                    os.waitpid(child, 0)
                    self.fail("The fixture helper did not settle")
                _, status = os.waitpid(child, 0)
                exit_code = os.waitstatus_to_exitcode(status)
                if expect_success is None:
                    self.assertIn(exit_code, (0, 2))
                else:
                    self.assertEqual(exit_code, 0 if expect_success else 2)
            finally:
                os.close(pidfd)

    @contextmanager
    def fixture(self, pause_at_listen=None, *, expect_success=True, wrong_pid=False):
        with generation_phase.FixturePhase(
            self.root, port=self.port, binding=self.binding, fence=RLock(),
            authorized=lambda binding: self.live and binding is self.binding,
            verify_helper=lambda scope: scope is self.scope,
            sent_receipt_is_current=self.current_sent, destination_claim_is_current=self.current_claim,
        ) as phase:
            with self.helper(phase, pause_at_listen, expect_success=expect_success) as child:
                self.scope = generation_phase.HelperPlacement(child + int(wrong_pid), os.geteuid(),
                                                              b"/fixture.service", "a" * 32)
                try:
                    yield phase
                finally:
                    if phase.receipt().phase is not generation_phase.Phase.COMPLETE:
                        phase.revoke()
        self.assertEqual(list(self.root.iterdir()), [])

    def attach(self, phase):
        def membership(pid):
            self.assertEqual(pid, self.scope.pid)
            return b"0::/fixture.service\n"

        phase.attach(self.scope, read_cgroup=membership)

    def receive(self, connection):
        result = bytearray()
        while True:
            try:
                chunk = connection.recv(4096)
            except ConnectionResetError:
                return bytes(result)
            if not chunk:
                return bytes(result)
            result.extend(chunk)
            self.assertLessEqual(len(result), 32768)

    def dial(self):
        native = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            native.settimeout(3)
            native.connect((generation_proxy.LOOPBACK, self.port))
        except BaseException:
            native.close()
            raise
        return native

    def client(self, packet):
        with self.dial() as native:
            native.sendall(packet)
            native.shutdown(socket.SHUT_WR)
            return self.receive(native)

    def prepare(self, phase):
        self.attach(phase)

        def startup(connection, _deadline):
            self.assertEqual(self.receive(connection), b"fixture-startup")
            connection.sendall(b"ready")

        def drive():
            return [self.client(b"fixture-startup") for _ in range(generation_proxy.STARTUP_LIMIT)]

        with ThreadPoolExecutor(max_workers=1) as runner:
            task = runner.submit(drive)
            phase.service_startup(startup)
            self.assertEqual(task.result(timeout=3), [b"ready"] * generation_proxy.STARTUP_LIMIT)
        phase.prepare_turn()
        self.assertEqual(phase.receipt().phase, generation_phase.Phase.BOUND)

    def finish(self, phase, attempt, packet=None, **options):
        options.setdefault("claim_destination", self.claim_destination)
        with ThreadPoolExecutor(max_workers=1) as runner:
            native = runner.submit(self.client, request() if packet is None else packet)
            receipt = phase.serve_turn(attempt, **options)
            return native.result(timeout=3), receipt

    def test_real_loopback_rebind_and_fast_eligible_post_activation(self):
        with self.fixture() as phase:
            self.prepare(phase)
            self.sent = True
            phase.activate(self.receipt)
            attempt = self.destination()
            wire, observed = self.finish(phase, attempt)
            self.assertEqual(wire, response())
            self.assertEqual(observed, generation_phase.PhaseReceipt(
                generation_phase.Phase.COMPLETE, 3, 1, 1, 1, False, True,
            ))
            self.assertIsNotNone(attempt.receipt())
            self.assertNotIn(str(self.root), repr(observed))
            self.assertNotIn(str(self.port), repr(observed))

    def test_pre_sent_bound_only_loopback_refusal_holds_without_fake_write(self):
        with self.fixture(expect_success=False) as phase:
            self.prepare(phase)
            with self.assertRaises(ConnectionRefusedError):
                self.dial()
            self.sent = True
            with self.assertRaisesRegex(generation_proxy.ProxyRefused, "TCP attempt failure"):
                phase.activate(self.receipt)
            observed = phase.receipt()
            self.assertEqual(observed.phase, generation_phase.Phase.HELD)
            self.assertTrue(observed.refusal_observed)
            self.assertEqual(observed.fake_writes, 0)
            with self.assertRaisesRegex(generation_proxy.ProxyRefused, "phase"):
                phase.activate(self.receipt)

    def test_bound_turn_unix_node_and_loopback_never_listen_without_current_sent_proof(self):
        # A stale proof fails before either admission is opened. Probe the
        # Unix node, which does not increment the TCP observation counter.
        with self.fixture(expect_success=False) as phase:
            self.prepare(phase)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as native:
                self.assertEqual(native.connect_ex(str(self.root / "turn.sock")), errno.ECONNREFUSED)
            with self.assertRaisesRegex(generation_proxy.ProxyRefused, "ACP sent"):
                phase.activate(self.receipt)
            self.assertEqual(phase.receipt().owner_turn_accepts, 0)

    def test_revoke_inside_durable_sent_check_does_not_publish_admission(self):
        with self.fixture(expect_success=False) as phase:
            self.prepare(phase)
            proof = phase._sent_receipt_is_current

            def revoke_at_proof(binding, receipt):
                current = proof(binding, receipt)
                phase.revoke()
                return current

            self.sent = True
            with patch.object(phase, "_sent_receipt_is_current", side_effect=revoke_at_proof):
                with self.assertRaisesRegex(generation_proxy.ProxyRefused, "owner retired"):
                    phase.activate(self.receipt)
            self.assertEqual(phase.receipt().owner_turn_accepts, 0)

    def test_counter_sample_requires_same_independently_pinned_namespace(self):
        with self.fixture(expect_success=False) as phase:
            self.prepare(phase)
            self.sent = True
            self.assertEqual(os.stat(phase._network_path).st_ino, os.fstat(phase._network_fd).st_ino)
            with TemporaryDirectory() as different:
                # Supply a stable descriptor for a different inode, even though
                # the genuine helper's exact proc path stays unchanged.
                fd = os.open(different, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with patch.object(phase, "_network_fd", fd):
                        with self.assertRaisesRegex(generation_proxy.ProxyRefused, "namespace changed"):
                            phase.activate(self.receipt)
                finally:
                    os.close(fd)
            self.assertEqual(phase.receipt().fake_writes, 0)

    def test_refusal_after_durable_sent_but_before_proxy_listen_holds(self):
        with self.fixture(expect_success=False) as phase:
            self.prepare(phase)
            self.sent = True
            send = phase._send

            def refuse_then_send(operation, deadline):
                if operation is generation_proxy.Signal.OPEN_TURN:
                    with self.assertRaises(ConnectionRefusedError):
                        self.dial()
                send(operation, deadline)

            with patch.object(phase, "_send", side_effect=refuse_then_send):
                with self.assertRaisesRegex(generation_proxy.ProxyRefused, "TCP attempt failure"):
                    phase.activate(self.receipt)
            self.assertEqual(phase.receipt().fake_writes, 0)
            self.assertTrue(phase.receipt().refusal_observed)

    def test_two_connected_clients_yield_one_accepted_request_and_one_fake_write(self):
        reader, writer = os.pipe()
        try:
            with self.fixture(pause_at_listen=reader, expect_success=None) as phase:
                self.prepare(phase)
                self.sent = True
                phase.activate(self.receipt)
                with self.dial() as first, self.dial() as second:
                    for client in (first, second):
                        client.sendall(request())
                        client.shutdown(socket.SHUT_WR)
                    os.write(writer, b"g")
                    try:
                        observed = phase.serve_turn(self.destination(), claim_destination=self.claim_destination)
                    except generation_proxy.ProxyRefused as error:
                        # Linux can report the discarded queued connection as
                        # a refusal. R3 holds when the counter changes.
                        self.assertIn("TCP attempt failure", str(error))
                        observed = phase.receipt()
                        self.assertTrue(observed.refusal_observed)
                        self.assertIs(observed.phase, generation_phase.Phase.HELD)
                    replies = [self.receive(first), self.receive(second)]
                    self.assertTrue(all(reply in (response(), b"") for reply in replies))
                    self.assertLessEqual(replies.count(response()), 1)
                self.assertEqual(observed.owner_turn_accepts, 1)
                self.assertLessEqual(observed.fake_writes, 1)
                if observed.phase is generation_phase.Phase.COMPLETE:
                    self.assertEqual((observed.helper_turn_accepts, observed.fake_writes, replies.count(response())),
                                     (1, 1, 1))
        finally:
            os.close(reader)
            os.close(writer)

    def test_scope_refuses_shallow_deep_and_serialized_copies(self):
        with self.fixture(expect_success=False) as phase:
            self.prepare(phase)
            for duplicate in (copy, deepcopy, pickle.dumps):
                with self.subTest(operation=duplicate.__name__):
                    with self.assertRaisesRegex(TypeError, "cannot be copied or serialized"):
                        duplicate(phase)
            self.assertEqual(phase.receipt().phase, generation_phase.Phase.BOUND)

    def test_old_startup_and_control_nodes_refuse_at_bound(self):
        with self.fixture(expect_success=False) as phase:
            self.prepare(phase)
            for leaf in (generation_proxy.STARTUP, generation_proxy.CONTROL):
                with self.subTest(leaf=leaf), socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as attempt:
                    attempt.settimeout(1)
                    self.assertEqual(attempt.connect_ex(str(self.root / leaf)), errno.ECONNREFUSED)

    def test_missing_destination_claim_holds_before_any_fake_write(self):
        with self.fixture(expect_success=False) as phase:
            self.prepare(phase)
            self.sent = True
            phase.activate(self.receipt)
            sink = self.destination()
            with self.dial() as native:
                native.sendall(request())
                native.shutdown(socket.SHUT_WR)
                with self.assertRaisesRegex(generation_proxy.ProxyRefused, "durable destination claim is unavailable"):
                    phase.serve_turn(sink)
                self.assertEqual(self.receive(native), b"")
            self.assertIsNone(sink.receipt())
            self.assertEqual(phase.receipt().owner_turn_accepts, 0)
            self.assertEqual(phase.receipt().fake_writes, 0)

    def test_invalid_capability_holds_even_with_a_valid_durable_claim(self):
        with self.fixture(expect_success=False) as phase:
            self.prepare(phase)
            self.sent = True
            phase.activate(self.receipt)
            sink = self.destination()

            def wrong_claim(binding, receipt, effect):
                return self.claim_destination(binding, receipt, lambda _claim: effect(object()))

            with ThreadPoolExecutor(max_workers=1) as runner:
                native = runner.submit(self.client, request())
                with self.assertRaisesRegex(generation_proxy.ProxyRefused, "durable destination claim differs"):
                    phase.serve_turn(sink, claim_destination=wrong_claim)
                self.assertEqual(native.result(timeout=3), b"")
            self.assertIsNone(sink.receipt())
            self.assertEqual(phase.receipt().fake_writes, 0)

    def test_sent_receipt_change_during_counter_observation_holds_before_open(self):
        with self.fixture(expect_success=False) as phase:
            self.prepare(phase)
            self.sent = True
            read_counter = generation_phase.tcp_attempt_fails

            def lose_sent_during_audit(pid):
                count = read_counter(pid)
                self.sent = False
                return count

            send = phase._send
            with patch.object(generation_phase, "tcp_attempt_fails", side_effect=lose_sent_during_audit), \
                    patch.object(phase, "_send", wraps=send) as commands:
                with self.assertRaisesRegex(generation_proxy.ProxyRefused, "ACP sent"):
                    phase.activate(self.receipt)
            commands.assert_not_called()
            self.assertEqual(phase.receipt().owner_turn_accepts, 0)

    def test_sent_receipt_is_rechecked_at_exact_open_control_write(self):
        with self.fixture(expect_success=False) as phase:
            self.prepare(phase)
            self.sent = True
            send = generation_phase.send_frame

            def lose_sent_after_listen(*args, **kwargs):
                self.assertIs(args[2], generation_proxy.Signal.OPEN_TURN)
                self.sent = False
                return send(*args, **kwargs)

            with patch.object(generation_phase, "send_frame", side_effect=lose_sent_after_listen), \
                    patch.object(generation_proxy, "_send_once", wraps=generation_proxy._send_once) as write:
                with self.assertRaisesRegex(generation_proxy.ProxyRefused, "ACP sent"):
                    phase.activate(self.receipt)
            write.assert_not_called()
            self.assertEqual(phase.receipt().owner_turn_accepts, 0)

    def test_external_owner_loss_inside_final_sent_proof_blocks_open_control_write(self):
        with self.fixture(expect_success=False) as phase:
            self.prepare(phase)
            self.sent = True
            at_control_write = False
            send = generation_phase.send_frame

            def verify_and_lose_owner(binding, receipt):
                current = self.current_sent(binding, receipt)
                if at_control_write:
                    self.assertTrue(current)
                    self.live = False
                return current

            def open_control(*args, **kwargs):
                nonlocal at_control_write
                self.assertIs(args[2], generation_proxy.Signal.OPEN_TURN)
                at_control_write = True
                return send(*args, **kwargs)

            with patch.object(phase, "_sent_receipt_is_current", side_effect=verify_and_lose_owner), \
                    patch.object(generation_phase, "send_frame", side_effect=open_control), \
                    patch.object(generation_proxy, "_send_once", wraps=generation_proxy._send_once) as write:
                with self.assertRaisesRegex(generation_proxy.ProxyRefused, "owner retired"):
                    phase.activate(self.receipt)
            self.assertFalse(self.live)
            write.assert_not_called()
            self.assertIs(phase.receipt().phase, generation_phase.Phase.HELD)

    def test_external_owner_loss_inside_final_destination_proof_blocks_fake_write(self):
        for boundary in ("dispatch", "sink"):
            with self.subTest(boundary=boundary), self.fixture(expect_success=False) as phase:
                self.live = True
                self.sent = False
                self.prepare(phase)
                self.sent = True
                phase.activate(self.receipt)
                sink = self.destination()
                next_claim_is_final = False
                project = generation.project_generation
                write = sink.write

                def project_exact_packet(*args, **kwargs):
                    nonlocal next_claim_is_final
                    packet = project(*args, **kwargs)
                    if boundary == "dispatch":
                        next_claim_is_final = True
                    return packet

                def write_at_sink(*args, **kwargs):
                    nonlocal next_claim_is_final
                    if boundary == "sink":
                        next_claim_is_final = True
                    return write(*args, **kwargs)

                def verify_and_lose_owner(binding, receipt, capability):
                    current = self.current_claim(binding, receipt, capability)
                    if next_claim_is_final:
                        self.assertTrue(current)
                        self.live = False
                    return current

                with ThreadPoolExecutor(max_workers=1) as runner:
                    native = runner.submit(self.client, request())
                    with patch.object(phase, "_destination_claim_is_current", side_effect=verify_and_lose_owner), \
                            patch.object(generation, "project_generation", side_effect=project_exact_packet), \
                            patch.object(sink, "write", side_effect=write_at_sink) as write_call:
                        with self.assertRaisesRegex(generation_proxy.ProxyRefused, "owner retired"):
                            phase.serve_turn(sink, claim_destination=self.claim_destination)
                    self.assertEqual(native.result(timeout=3), b"")
                self.assertFalse(self.live)
                if boundary == "dispatch":
                    write_call.assert_not_called()
                else:
                    write_call.assert_called_once()
                self.assertIsNone(sink.receipt())
                self.assertEqual(phase.receipt().fake_writes, 0)
                self.assertIs(phase.receipt().phase, generation_phase.Phase.HELD)

    def test_wrong_pid_cannot_receive_a_control_command(self):
        with self.fixture(expect_success=False, wrong_pid=True) as phase:
            with self.assertRaisesRegex(generation_proxy.ProxyRefused, "peer identity"):
                self.attach(phase)
            self.assertEqual(phase.receipt().startup_eofs, 0)

    def test_wrong_turn_envelope_consumes_accept_and_cannot_retry(self):
        with self.fixture(expect_success=False) as phase:
            self.prepare(phase)
            self.sent = True
            phase.activate(self.receipt)
            attempt = self.destination()
            with ThreadPoolExecutor(max_workers=1) as runner, \
                    patch.object(self, "claim_destination", wraps=self.claim_destination) as claim:
                native = runner.submit(self.client, b"not a fixture request")
                with self.assertRaises(generation.GenerationRefused):
                    phase.serve_turn(attempt, claim_destination=claim)
                self.assertEqual(native.result(timeout=3), b"")
                claim.assert_not_called()
            observed = phase.receipt()
            self.assertEqual((observed.owner_turn_accepts, observed.fake_writes), (1, 0))
            with self.assertRaises(generation_proxy.ProxyRefused):
                phase.serve_turn(attempt, claim_destination=self.claim_destination)

    def test_invalid_fake_response_holds_and_retains_the_actual_complete_write_count(self):
        with self.fixture(expect_success=False) as phase:
            self.prepare(phase)
            self.sent = True
            phase.activate(self.receipt)
            sink = generation.FakeDestination(response() + b"unexpected", end_of_input=True)
            with ThreadPoolExecutor(max_workers=1) as runner:
                native = runner.submit(self.client, request())
                with self.assertRaises(generation.GenerationRefused):
                    phase.serve_turn(sink, claim_destination=self.claim_destination)
                self.assertEqual(native.result(timeout=3), b"")
            self.assertIsNotNone(sink.receipt())
            self.assertEqual(phase.receipt().fake_writes, 1)
            self.assertFalse(phase.receipt().connector_retired)

    def test_double_dispatch_call_stays_spent_even_if_claim_catches_refusal(self):
        with self.fixture(expect_success=False) as phase:
            self.prepare(phase)
            self.sent = True
            phase.activate(self.receipt)
            attempt = self.destination()

            def claim(binding, receipt, dispatch):
                self.assertIs(binding, self.binding)
                self.assertIs(receipt, self.receipt)
                def repeated(capability):
                    result = dispatch(capability)
                    with self.assertRaisesRegex(generation_proxy.ProxyRefused, "effect was spent"):
                        dispatch(capability)
                    return result

                return self.claim_destination(binding, receipt, repeated)

            with ThreadPoolExecutor(max_workers=1) as runner:
                native = runner.submit(self.client, request())
                with self.assertRaisesRegex(generation_proxy.ProxyRefused, "owner retired"):
                    phase.serve_turn(attempt, claim_destination=claim)
                self.assertEqual(native.result(timeout=3), b"")
            self.assertIsNotNone(attempt.receipt())
            self.assertEqual(phase.receipt().phase, generation_phase.Phase.HELD)
