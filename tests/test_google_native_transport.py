"""Verify metadata CONNECT and private TLS admission without network I/O."""

from collections import deque
from contextlib import contextmanager, nullcontext
import os
from pathlib import Path
import socket
import stat
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from oc_google.metadata_destination import MetadataRoute
from oc_google import auth_offer, native_peer, native_transport
from test_google_auth_offer import offer, request


_AUTHORITY = b"oauth2.googleapis.com:443"
_CONNECT = b"CONNECT " + _AUTHORITY + b" HTTP/1.1\r\nHost: " + _AUTHORITY + b"\r\n\r\n"


class Peer:
    def __init__(self, *chunks):
        self.chunks = deque(chunks)
        self.writes = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True

    def settimeout(self, timeout):
        if not 0 < timeout <= 2:
            raise AssertionError("unbounded metadata socket")

    def recv(self, amount):
        return self.chunks.popleft() if self.chunks else b""

    def sendall(self, packet):
        self.writes.append(packet)


@contextmanager
def admit_fixture_peer(_connection, *, expected_group, read_cgroup):
    # The read end is live until close, so the exact group checks are exercised
    # without requiring the test runner to support the SO_PEERPIDFD sockopt.
    read_fd, write_fd = os.pipe()
    peer = native_peer._NativePeer(os.getpid(), read_fd, expected_group, read_cgroup)
    try:
        if not peer.active():
            raise AssertionError("The synthetic peer did not authenticate")
        yield peer
    finally:
        peer.close()
        os.close(write_fd)


class NativeTransportTest(unittest.TestCase):
    def setUp(self):
        self.owner = Mock()
        self.owner.active.return_value = True
        self.peer_admission = self.enterContext(patch.object(
            native_transport, "admit_native_peer", return_value=nullcontext(self.owner),
        ))
        self.tls = Mock()
        self.tls.selected_alpn_protocol.return_value = "http/1.1"
        self.context = Mock()
        self.context.wrap_socket.return_value = nullcontext(self.tls)

    def test_tls_context_refuses_password_requests_without_terminal_input(self):
        def needs_password(*args, password):
            password()

        context = Mock()
        context.load_cert_chain.side_effect = needs_password
        with patch.object(native_transport.ssl, "SSLContext", return_value=context):
            with self.assertRaisesRegex(native_transport.NativeTransportError, "cannot require interactive credentials"):
                native_transport.native_server_context(MetadataRoute.TOKEN, certificate="fixture.pem", key="fixture.key")

    def open(self, peer, route=MetadataRoute.TOKEN):
        return native_transport.open_native_metadata_channel(
            peer, route=route, deadline=time.monotonic() + 1, expected_group=b"/fixture",
            read_cgroup=Mock(), context=self.context, authorized=lambda: True,
        )

    def test_fragmented_exact_connect_exposes_owned_tls_channel(self):
        peer = Peer(_CONNECT[:27], _CONNECT[27:])
        with self.open(peer) as channel:
            self.assertIs(channel.stream, self.tls)
            self.assertTrue(channel.active())
            self.owner.active.return_value = False
            self.assertFalse(channel.active())
        self.assertTrue(peer.closed)
        self.assertEqual(peer.writes, [b"HTTP/1.1 200 Connection established\r\n\r\n"])
        self.context.wrap_socket.assert_called_once_with(peer, server_side=True)

    def test_denies_wrong_host_pipelining_or_trailing_headers_before_reply(self):
        for wire in (_CONNECT.replace(_AUTHORITY, b"other.invalid:443"), _CONNECT + b"x",
                     _CONNECT[:-2] + b"Extra: yes\r\n\r\n", b"x" * 4096):
            peer = Peer(wire)
            with self.assertRaises(native_transport.NativeTransportError):
                with self.open(peer):
                    self.fail("Unexpected CONNECT permitted")
            self.assertEqual(peer.writes, [])
            self.assertTrue(peer.closed)
        self.context.wrap_socket.assert_not_called()

    def test_owner_loss_before_connect_reply_never_starts_tls(self):
        self.owner.active.side_effect = [True, False]
        peer = Peer(_CONNECT)
        with self.assertRaises(native_transport.NativeTransportError):
            with self.open(peer):
                self.fail("Retired owner permitted")
        self.assertEqual(peer.writes, [])
        self.context.wrap_socket.assert_not_called()

    def test_owner_loss_during_final_cgroup_read_withholds_connect_reply(self):
        self.peer_admission.side_effect = admit_fixture_peer
        live = True
        reads = 0

        def read_group(pid):
            nonlocal live, reads
            self.assertEqual(pid, os.getpid())
            reads += 1
            if reads == 3:
                live = False
            return b"0::/fixture\n"

        server, connector = socket.socketpair()
        with server, connector:
            connector.settimeout(1)
            connector.sendall(_CONNECT)
            with self.assertRaisesRegex(native_transport.NativeTransportError, "owner retired"):
                with native_transport.open_native_metadata_channel(
                    server, route=MetadataRoute.TOKEN, deadline=time.monotonic() + 1,
                    expected_group=b"/fixture", read_cgroup=read_group, context=self.context,
                    authorized=lambda: live,
                ):
                    self.fail("Native TLS started after owner loss")
            self.assertEqual(connector.recv(128), b"")
        self.assertEqual(reads, 3)
        self.context.wrap_socket.assert_not_called()

    def test_owner_loss_during_browser_cgroup_read_withholds_private_forward_or_success_ack(self):
        self.peer_admission.side_effect = admit_fixture_peer
        for during in ("forward", "acknowledge"):
            with self.subTest(during=during), tempfile.TemporaryDirectory() as directory:
                live = True
                cancel_during_read = False

                def read_group(pid):
                    nonlocal live
                    self.assertEqual(pid, os.getpid())
                    if cancel_during_read:
                        live = False
                    return b"0::/fixture\n"

                with native_transport.open_native_browser_listener(
                    Path(directory), expected_group=lambda: b"/fixture", read_cgroup=read_group,
                    authorized=lambda: live,
                ) as (path, receive), socket.socket(socket.AF_UNIX) as connector:
                    connector.connect(str(path))
                    with socket.socket(socket.AF_INET) as reserve:
                        reserve.bind((auth_offer.HOST, 0))
                        port = reserve.getsockname()[1]
                    connector.sendall((offer(port) + "\n").encode("ascii"))
                    with receive(time.monotonic() + 2) as (_, gate):
                        gate.activate()
                        consume = gate._consume

                        def cancel_at_ack(callback, address):
                            nonlocal cancel_during_read
                            accepted = consume(callback, address)
                            cancel_during_read = True
                            return accepted

                        with socket.create_connection((auth_offer.HOST, port), timeout=1) as browser:
                            browser.sendall(request(port))
                            browser.shutdown(socket.SHUT_WR)
                            if during == "forward":
                                cancel_during_read = True
                                gate.serve_one()
                                connector.setblocking(False)
                                with self.assertRaises(BlockingIOError):
                                    connector.recv(4096)
                            else:
                                with patch.object(gate, "_consume", side_effect=cancel_at_ack):
                                    gate.serve_one()
                                self.assertEqual(gate.outcome, auth_offer.Outcome.UNCERTAIN)
                                connector.settimeout(1)
                                self.assertTrue(connector.recv(4096).startswith(b"GET /?"))
                            self.assertEqual(browser.recv(4096), auth_offer.acknowledgement(False))
                        self.assertIsNone(gate.take_forwarded())
                        self.assertFalse(live)

    def test_userinfo_is_an_owner_only_route(self):
        peer = Peer(_CONNECT)
        with self.assertRaises(native_transport.NativeTransportError):
            with self.open(peer, MetadataRoute.USERINFO):
                self.fail("Unexpected native userinfo accepted")
        self.peer_admission.assert_not_called()
        self.assertTrue(peer.closed)

    def test_private_unix_listener_admits_only_its_ordered_connector(self):
        with tempfile.TemporaryDirectory() as directory:
            with native_transport.open_native_metadata_listener(
                Path(directory), contexts={MetadataRoute.TOKEN: self.context},
                expected_group=lambda: b"/fixture", read_cgroup=Mock(), authorized=lambda: True,
            ) as (path, accept):
                self.assertEqual(stat.S_IMODE(path.lstat().st_mode), 0o600)
                with self.assertRaises(native_transport.NativeTransportError), accept(
                    MetadataRoute.USERINFO, time.monotonic() + 1,
                ):
                    self.fail("Unexpected native userinfo accepted")
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connector:
                    connector.settimeout(1)
                    connector.connect(str(path))
                    connector.sendall(_CONNECT)
                    with accept(MetadataRoute.TOKEN, time.monotonic() + 1) as channel:
                        self.assertTrue(channel.active())
                        self.assertEqual(connector.recv(128), b"HTTP/1.1 200 Connection established\r\n\r\n")
            self.assertFalse(path.exists())

    def test_failed_browser_admission_consumes_the_listener_offer(self):
        with tempfile.TemporaryDirectory() as directory:
            with native_transport.open_native_browser_listener(
                Path(directory), expected_group=lambda: b"/fixture", read_cgroup=Mock(), authorized=lambda: True,
            ) as (path, receive):
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connector:
                    connector.connect(str(path))
                    connector.sendall(b"invalid.example\n")
                    with self.assertRaisesRegex(native_transport.NativeTransportError, "Invalid Google native sign-in link"):
                        with receive(time.monotonic() + 1):
                            self.fail("Invalid browser offer passed")
                with self.assertRaisesRegex(native_transport.NativeTransportError, "owner retired"):
                    with receive(time.monotonic() + 1):
                        self.fail("Consumed browser offer restarted")

    def test_waiting_for_ownership_ends_on_cancellation(self):
        listener = Mock()
        listener.accept.side_effect = TimeoutError
        owner = iter((True, True, False))
        with self.assertRaisesRegex(native_transport.NativeTransportError, "owner retired"):
            native_transport._accept_owned(listener, time.monotonic() + 60, lambda: next(owner))
        self.assertEqual(listener.accept.call_count, 2)
        self.assertTrue(all(call.args[0] <= .1 for call in listener.settimeout.call_args_list))
