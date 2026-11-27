"""Exercise Google route framing, resolution and authority with fake sockets."""

import base64
from collections import deque
from inspect import getclosurevars
import os
import socket
import ssl
from threading import Event, Thread
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from oc_google import metadata_destination as destination
from oc_google.auth_offer import CLIENT_ID
from oc_google.token_diagnostic import TokenStage


BEARER = b"Bearer synthetic-access"
BASIC = b"Basic " + base64.b64encode(CLIENT_ID.encode("ascii") + b":synthetic-secret")
IPV4 = ("8.8.8.8", 443)
IPV6 = ("2001:4860:4860::8888", 443, 0, 0)
JSON = b'{"fixture":true}'


def record(address=IPV4, *, family=socket.AF_INET):
    return family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", address


def response(payload=JSON, *, status=b"HTTP/1.1 200 OK", headers=()):
    return b"\r\n".join((
        status,
        b"Content-Type: application/json; charset=UTF-8",
        b"Content-Length: " + str(len(payload)).encode("ascii"),
        *headers,
    )) + b"\r\n\r\n" + payload


class FakeChannel:
    def __init__(self, *chunks):
        self.chunks = deque(chunks)
        self.close_count = 0
        self.sent = []
        self.timeout = None
        self.send_limit = None
        self.alpn = "http/1.1"
        self.connect = Mock()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close_count += 1

    def settimeout(self, timeout):
        self.timeout = timeout

    def selected_alpn_protocol(self):
        return self.alpn

    def send(self, packet):
        self.sent.append(packet)
        return len(packet) if self.send_limit is None else self.send_limit

    def recv(self, count):
        chunk = self.chunks.popleft() if self.chunks else b""
        if isinstance(chunk, Exception):
            raise chunk
        if len(chunk) > count:
            self.chunks.appendleft(chunk[count:])
        return chunk[:count]


class MetadataDestinationTest(unittest.TestCase):
    def setUp(self):
        self.raw = FakeChannel()
        self.tls = FakeChannel(response())
        self.context = Mock()
        self.context.wrap_socket.return_value = self.tls
        self.resolve = self.enterContext(patch.object(destination.socket, "getaddrinfo", return_value=[record()]))
        self.socket = self.enterContext(patch.object(destination.socket, "socket", return_value=self.raw))
        self.trust = self.enterContext(patch.object(destination, "_system_tls_context", return_value=self.context))

    def exchange(self, route=destination.MetadataRoute.USERINFO, *, authorization=BEARER, body=b"",
                 deadline=None, deliver=lambda send: send()):
        return destination.exchange(route, authorization=authorization, body=body,
                                    deadline=time.monotonic() + 1 if deadline is None else deadline,
                                    deliver=deliver)

    def test_each_literal_route_uses_exact_method_target_and_no_proxy(self):
        cases = (
            (destination.MetadataRoute.TOKEN, "oauth2.googleapis.com", b"POST /token", b"code=fixture", BASIC),
            (destination.MetadataRoute.USERINFO, "www.googleapis.com", b"GET /oauth2/v2/userinfo?fields=id", b"", BEARER),
            (destination.MetadataRoute.LOAD_CODE_ASSIST, "cloudcode-pa.googleapis.com",
             b"POST /v1internal:loadCodeAssist", b"{}", BEARER),
            (destination.MetadataRoute.FETCH_AVAILABLE_MODELS, "daily-cloudcode-pa.googleapis.com",
             b"POST /v1internal:fetchAvailableModels", b"{}", BEARER),
        )
        for route, host, target, body, auth in cases:
            with self.subTest(route=route):
                self.tls.chunks = deque([response()])
                self.tls.sent.clear()
                with patch.dict(os.environ, {"HTTPS_PROXY": "http://synthetic.invalid:7890"}):
                    self.assertEqual(self.exchange(route, authorization=auth, body=body), JSON)
                head, sent_body = self.tls.sent[0].split(b"\r\n\r\n")
                self.assertEqual(head.split(b"\r\n", 1)[0], target + b" HTTP/1.1")
                self.assertEqual(sent_body, body)
                self.assertIn(b"\r\nHost: " + host.encode(), head)
                self.assertIn(b"\r\nAuthorization: " + auth, head)
                self.assertIn(b"\r\nAccept: application/json", head)
                self.assertIn(b"\r\nAccept-Encoding: identity", head)
                self.assertIn(b"\r\nConnection: close", head)
                if body:
                    self.assertIn(b"\r\nContent-Length: " + str(len(body)).encode(), head)
                else:
                    self.assertNotIn(b"Content-Length", head)
                    self.assertNotIn(b"Content-Type", head)
                self.resolve.assert_called_with(host, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
                self.context.wrap_socket.assert_called_with(self.raw, server_hostname=host, suppress_ragged_eofs=False)
        self.assertEqual(self.raw.close_count, 4)
        self.assertEqual(self.tls.close_count, 4)

    def test_refresh_token_post_has_no_alternate_authorization_header(self):
        self.assertEqual(self.exchange(destination.MetadataRoute.TOKEN, authorization=None, body=b"refresh=fixture"), JSON)
        head, body = self.tls.sent[0].split(b"\r\n\r\n")
        self.assertNotIn(b"Authorization:", head)
        self.assertIn(b"Content-Type: application/x-www-form-urlencoded", head)
        self.assertEqual(body, b"refresh=fixture")

    def test_unknown_route_wrong_credentials_and_request_shapes_fail_before_dns(self):
        cases = (
            ("streamGenerateContent", BEARER, b"{}"),
            (destination.MetadataRoute.USERINFO, BEARER, b"{}"),
            (destination.MetadataRoute.USERINFO, BASIC, b""),
            (destination.MetadataRoute.USERINFO, BEARER + b"\r\nX-Test: injected", b""),
            (destination.MetadataRoute.USERINFO, None, b""),
            (destination.MetadataRoute.TOKEN, BEARER, b"code=fixture"),
            (destination.MetadataRoute.TOKEN, None, b"x" * 8193),
            (destination.MetadataRoute.LOAD_CODE_ASSIST, BEARER, b""),
        )
        for route, auth, body in cases:
            with self.subTest(route=route), self.assertRaises(destination.MetadataDestinationError):
                self.exchange(route, authorization=auth, body=body)
        self.resolve.assert_not_called()
        self.socket.assert_not_called()

    def test_rejects_whole_resolution_if_any_answer_is_nonpublic_or_invalid(self):
        bad_ipv4 = ("0.0.0.0", "127.0.0.1", "10.0.0.1", "169.254.1.1", "100.64.0.1",
                    "192.0.2.1", "224.0.0.1", "240.0.0.1", "synthetic.invalid")
        bad_ipv6 = ("::", "::1", "fe80::1", "fc00::1", "::ffff:8.8.8.8", "ff02::1",
                    "2001:db8::1", "fec0::1", "2002:7f00:1::1")
        bad = [record((ip, 443)) for ip in bad_ipv4]
        bad.extend(record((ip, 443, 0, 0), family=socket.AF_INET6) for ip in bad_ipv6)
        bad.extend((record(("8.8.8.8", 80)), record(("8.8.8.8", 443), family=socket.AF_INET6),
                    record(("2001:4860:4860::8888", 443, 0, 4), family=socket.AF_INET6)))
        for answer in bad:
            self.resolve.return_value = [record(), answer]
            with self.subTest(answer=answer), self.assertRaises(destination.MetadataDestinationError):
                self.exchange()
        for answers in ([], [record()] * 33):
            self.resolve.return_value = answers
            with self.assertRaises(destination.MetadataDestinationError):
                self.exchange()
        self.socket.assert_not_called()

    def test_numeric_ipv6_connect_and_no_fallback_after_one_failed_attempt(self):
        self.resolve.return_value = [record(IPV6, family=socket.AF_INET6), record()]
        self.raw.connect.side_effect = OSError("sensitive fixture transport detail")
        with self.assertRaises(destination.MetadataDestinationError) as denied:
            self.exchange()
        self.assertNotIn("sensitive fixture", str(denied.exception))
        self.assertIsNone(denied.exception.__context__)
        self.socket.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        self.raw.connect.assert_called_once_with(IPV6)
        self.context.wrap_socket.assert_not_called()
        self.assertEqual(self.raw.close_count, 1)

    def test_tls_mismatch_has_no_application_write(self):
        self.context.wrap_socket.side_effect = ssl.SSLCertVerificationError("synthetic certificate")
        gate = Mock()
        with self.assertRaises(destination.MetadataDestinationError):
            self.exchange(deliver=gate)
        gate.assert_not_called()
        self.assertEqual(self.tls.sent, [])
        self.assertEqual(self.raw.close_count, 1)

    def test_dns_deadline_prevents_connect_even_if_lookup_finishes_late(self):
        release = Event()

        def slow(*_args, **_kwargs):
            release.wait(1)
            return [record()]

        self.resolve.side_effect = slow
        try:
            with self.assertRaises(destination.MetadataDestinationError):
                self.exchange(deadline=time.monotonic() + .03)
        finally:
            release.set()
        self.socket.assert_not_called()
        self.assertEqual(self.tls.sent, [])

    def test_excessive_finite_deadline_is_rejected_before_dns(self):
        for deadline in (time.monotonic() + 3600, 1e30):
            with self.subTest(deadline=deadline), self.assertRaisesRegex(destination.MetadataDestinationError, "deadline"):
                self.exchange(deadline=deadline)
        self.resolve.assert_not_called()
        self.socket.assert_not_called()

    def test_retained_delivery_callback_releases_packet_and_tls_channel(self):
        retained = []

        def deliver(send):
            retained.append(send)
            send()

        self.assertEqual(self.exchange(deliver=deliver), JSON)
        callback, = retained
        with self.assertRaises(destination.MetadataDestinationError):
            callback()
        captured = getclosurevars(callback).nonlocals
        self.assertFalse(any(value is self.tls for value in captured.values()))
        self.assertFalse(any(isinstance(value, bytes) and BEARER in value for value in captured.values()))
        self.assertEqual(len(self.tls.sent), 1)

    def test_delivery_is_synchronous_single_use_and_does_not_retry_short_writes(self):
        stale = []
        with self.assertRaises(destination.MetadataDestinationError):
            self.exchange(deliver=stale.append)
        with self.assertRaises(destination.MetadataDestinationError):
            stale[0]()
        self.assertEqual(self.tls.sent, [])

        def double(send):
            send()
            with self.assertRaises(destination.MetadataDestinationError):
                send()

        self.assertEqual(self.exchange(deliver=double), JSON)
        self.assertEqual(len(self.tls.sent), 1)
        self.tls.send_limit = 1
        with self.assertRaisesRegex(destination.MetadataDestinationError, "write was incomplete"):
            self.exchange()
        self.assertEqual(len(self.tls.sent), 2)

    def test_timeout_preparation_cannot_bypass_final_write_authority(self):
        live = True
        sink = Mock()

        def timeout(_value):
            nonlocal live
            live = False

        def deliver(send):
            if live:
                send()

        sink.settimeout.side_effect = timeout
        with self.assertRaisesRegex(destination.MetadataDestinationError, "request was not sent"):
            destination._send_under_gate(sink, b"fixture", time.monotonic() + 1, deliver)
        sink.settimeout.assert_called_once_with(0)
        sink.send.assert_not_called()

    def test_deadline_is_checked_again_after_durable_admission(self):
        sink = Mock()
        clock = Mock(return_value=10)

        def deliver(send):
            clock.return_value = 12
            send()

        with patch.object(destination.time, "monotonic", clock):
            with self.assertRaisesRegex(destination.MetadataDestinationError, "deadline expired"):
                destination._send_under_gate(sink, b"fixture", 11, deliver)
        sink.send.assert_not_called()

    def test_wrong_thread_cannot_invoke_owner_write(self):
        rejected = []

        def gate(send):
            def crossing():
                try:
                    send()
                except destination.MetadataDestinationError:
                    rejected.append(True)

            worker = Thread(target=crossing)
            worker.start()
            worker.join()

        with self.assertRaises(destination.MetadataDestinationError):
            self.exchange(deliver=gate)
        self.assertEqual(rejected, [True])
        self.assertEqual(self.tls.sent, [])

    def test_denies_redirect_http2_duplicate_or_ambiguous_body_and_trailing_data(self):
        invalid = (
            [response(status=b"HTTP/1.1 302 Found", headers=(b"Location: https://example.invalid",))],
            [response(status=b"HTTP/1.0 200 OK")],
            [response(headers=(b"Transfer-Encoding: chunked",))],
            [response(headers=(b"Content-Encoding: gzip",))],
            [response(headers=(b"Content-Encoding: identity", b"content-encoding: identity"))],
            [response(headers=(b"Content-Length: 15",))],
            [response(headers=(b"Content-Length : 15",))],
            [response(headers=(b"Connection: keep-alive",))],
            [response(headers=(b" Trailer: bogus",))],
            [response().replace(b"application/json", b"text/plain")],
            [response().replace(b"Content-Length: 16\r\n", b"")],
            [response()[:-1]],
            [response(), b"trailing fixture"],
            [b"x" * 8193],
            [response(payload=b"x" * 1025)],
        )
        for chunks in invalid:
            self.tls.chunks = deque(chunks)
            with self.assertRaises(destination.MetadataDestinationError):
                self.exchange()
        self.tls.alpn = "h2"
        with self.assertRaisesRegex(destination.MetadataDestinationError, "TLS protocol"):
            self.exchange()

    def test_completed_initial_token_write_observes_only_fixed_response_stages(self):
        marker = b"synthetic-reply-marker"
        route = destination.MetadataRoute.TOKEN
        cases = (
            (TokenStage.HTTP_400, [response(status=b"HTTP/1.1 400 " + marker), b"unopened"]),
            (TokenStage.HTTP_401_403, [response(status=b"HTTP/1.1 401 " + marker)]),
            (TokenStage.HTTP_401_403, [response(status=b"HTTP/1.1 403 " + marker)]),
            (TokenStage.HTTP_429, [response(status=b"HTTP/1.1 429 " + marker)]),
            (TokenStage.HTTP_5XX, [response(status=b"HTTP/1.1 599 " + marker)]),
            (TokenStage.HTTP_OTHER, [response(status=b"HTTP/1.1 418 " + marker)]),
            (TokenStage.CHUNKED, [response(headers=(b"Transfer-Encoding: Chunked",))]),
            (TokenStage.HEADER, [response(headers=(b"Content-Type: " + marker,))]),
            (TokenStage.FRAMING, [response()[:-1]]),
            (TokenStage.TRAILING, [response(), marker]),
            (TokenStage.TLS_EOF, [response(), ssl.SSLEOFError(marker.decode())]),
            (TokenStage.TRANSPORT, [response(), TimeoutError(marker.decode())]),
        )
        for stage, chunks in cases:
            with self.subTest(stage=stage):
                self.tls.chunks = deque(chunks)
                self.tls.sent.clear()
                observed = []
                deliver = destination._ObservedDelivery(route, lambda send: send(), observed.append)
                with self.assertRaises(destination.MetadataDestinationError) as rejected:
                    self.exchange(route, authorization=BASIC, body=b"code=fixture", deliver=deliver)
                self.assertEqual(len(self.tls.sent), 1)
                self.assertEqual(observed, [rejected.exception])
                self.assertIs(rejected.exception.token_stage, stage)
                self.assertNotIn(marker.decode(), str(rejected.exception))
                if stage is TokenStage.HTTP_400:
                    self.assertEqual(list(self.tls.chunks), [b"unopened"])

    def test_short_token_send_cannot_observe_any_response(self):
        route = destination.MetadataRoute.TOKEN
        observed = []
        deliver = destination._ObservedDelivery(route, lambda send: send(), observed.append)
        self.tls.send_limit = 1
        raw = response(status=b"HTTP/1.1 400 synthetic")
        self.tls.chunks = deque([raw])
        with self.assertRaisesRegex(destination.MetadataDestinationError, "write was incomplete"):
            self.exchange(route, authorization=BASIC, body=b"code=fixture", deliver=deliver)
        self.assertEqual(observed, [])
        self.assertEqual(list(self.tls.chunks), [raw])

    def test_bounded_identity_json_can_arrive_in_multiple_reads(self):
        wire = response(headers=(b"Content-Encoding: identity",))
        self.tls.chunks = deque(wire[pos:pos + 3] for pos in range(0, len(wire), 3))
        self.assertEqual(self.exchange(), JSON)
        self.assertGreater(self.tls.timeout, 0)


class SystemTrustTest(unittest.TestCase):
    def test_explicit_system_ca_locations_ignore_ambient_overrides(self):
        paths = SimpleNamespace(cafile="/fake/override", capath="/fake/override-dir",
                                openssl_cafile="/system/ca.pem", openssl_capath="/system/roots")
        with (patch.object(destination.ssl, "get_default_verify_paths", return_value=paths),
              patch.object(destination.ssl, "SSLContext") as constructor,
              patch.object(destination.os.path, "isfile", side_effect=lambda path: path == paths.openssl_cafile),
              patch.object(destination.os.path, "isdir", side_effect=lambda path: path == paths.openssl_capath),
              patch.dict(os.environ, {"SSL_CERT_FILE": paths.cafile, "SSL_CERT_DIR": paths.capath,
                                      "SSLKEYLOGFILE": "/fake/keys"})):
            context = destination._system_tls_context()
        constructor.assert_called_once_with(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations.assert_called_once_with(cafile="/system/ca.pem", capath="/system/roots")
        context.set_alpn_protocols.assert_called_once_with(["http/1.1"])
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)


if __name__ == "__main__":
    unittest.main()
