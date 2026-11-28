"""Exercise native enrollment request framing with synthetic read-only peers."""

import base64
from collections import deque
from dataclasses import FrozenInstanceError
import pickle
import time
import unittest

from oc_google.auth_offer import CLIENT_ID
from oc_google.metadata_destination import MetadataRoute
from oc_google.metadata_ingress import MetadataIngressError, read_cold_refresh_request, read_enrollment_request
from test_google_oauth_exchange import refresh_form


ACCESS = b"Bearer fixture-native-access"
CLIENT = b"Basic " + base64.b64encode(CLIENT_ID.encode("ascii") + b":fixture-native-secret")
CODE_FORM = (
    b"grant_type=authorization_code&code=fixture-code&code_verifier=fixture-verifier&"
    b"redirect_uri=http%3A%2F%2F127.0.0.1%3A48081%2F"
)
LOAD = b'{"metadata":{"fixture":true}}'


def packet(route, *, body=None, changes=None, request_line=None, extra=()):
    host, method, target, media, _, _ = route.value
    if body is None:
        body = CODE_FORM if route is MetadataRoute.TOKEN else LOAD
    if request_line is None:
        request_line = method + b" " + target + b" HTTP/1.1"
    fields = {
        b"Host": host.encode("ascii"),
        b"Content-Type": media,
        b"Content-Length": str(len(body)).encode("ascii"),
        b"Authorization": CLIENT if route is MetadataRoute.TOKEN else ACCESS,
        b"Accept-Encoding": b"gzip, deflate",
        b"User-Agent": b"Standalone fixture",
        b"Connection": b"keep-alive" if route is MetadataRoute.TOKEN else b"close",
    }
    if route is MetadataRoute.TOKEN:
        fields[b"Accept"] = b"application/json"
    if changes:
        fields.update(changes)
    lines = [name + b": " + value for name, value in fields.items() if value is not None]
    return b"\r\n".join((request_line, *lines, *extra)) + b"\r\n\r\n" + body


class FakePeer:
    def __init__(self, *chunks):
        self.chunks = deque(chunks)
        self.reads = []
        self.timeouts = []

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def recv(self, size):
        self.reads.append(size)
        chunk = self.chunks.popleft() if self.chunks else b""
        if isinstance(chunk, Exception):
            raise chunk
        if len(chunk) > size:
            self.chunks.appendleft(chunk[size:])
        return chunk[:size]


class NativeMetadataIngressTest(unittest.TestCase):
    def read(self, *chunks, route=MetadataRoute.TOKEN, deadline=None):
        peer = FakePeer(*chunks)
        return read_enrollment_request(peer, route=route, deadline=time.monotonic() + 1 if deadline is None else deadline)

    def test_cold_refresh_framing_is_separate_from_initial_code_exchange(self):
        wire = packet(MetadataRoute.TOKEN, body=refresh_form(), changes={
            b"Authorization": None, b"X-Goog-Api-Client": b"synthetic-google-client",
        })
        cold = read_cold_refresh_request(FakePeer(wire), deadline=time.monotonic() + 1)
        self.assertIs(cold.route, MetadataRoute.TOKEN)
        self.assertIsNone(cold.authorization)
        self.assertEqual(cold.body, refresh_form())
        with self.assertRaises(MetadataIngressError):
            self.read(wire)
        peer = FakePeer(packet(MetadataRoute.TOKEN))
        deadline = time.monotonic() + 1
        with self.assertRaises(MetadataIngressError):
            read_cold_refresh_request(peer, deadline=deadline)

    def test_measured_token_request_yields_immutable_redacted_application_data(self):
        enrollment = self.read(packet(MetadataRoute.TOKEN), TimeoutError())
        self.assertIs(enrollment.route, MetadataRoute.TOKEN)
        self.assertEqual(enrollment.authorization, CLIENT)
        self.assertEqual(enrollment.body, CODE_FORM)
        self.assertNotIn(CLIENT.decode(), repr(enrollment))
        self.assertNotIn("fixture-code", repr(enrollment))
        with self.assertRaises(FrozenInstanceError):
            enrollment.body = b"other"
        with self.assertRaisesRegex(TypeError, "must remain in memory"):
            pickle.dumps(enrollment)

    def test_measured_load_code_assist_across_fragmented_headers_and_body(self):
        wire = packet(MetadataRoute.LOAD_CODE_ASSIST)
        enrollment = self.read(*(wire[index:index + 3] for index in range(0, len(wire), 3)),
                               route=MetadataRoute.LOAD_CODE_ASSIST)
        self.assertEqual((enrollment.route, enrollment.authorization, enrollment.body),
                         (MetadataRoute.LOAD_CODE_ASSIST, ACCESS, LOAD))

    def test_unavailable_routes_cannot_read_a_native_connection(self):
        for route in (MetadataRoute.USERINFO, MetadataRoute.FETCH_AVAILABLE_MODELS,
                      "streamGenerateContent", ("POST", "/token")):
            peer = FakePeer(packet(MetadataRoute.TOKEN))
            with self.subTest(route=route):
                deadline = time.monotonic() + 1
                with self.assertRaisesRegex(MetadataIngressError, "route is unavailable"):
                    read_enrollment_request(peer, route=route, deadline=deadline)
            self.assertEqual(peer.reads, [])

    def test_rejects_cross_phase_nonliteral_and_non_http11_request_lines(self):
        for request_line in (
            b"POST /v1internal:loadCodeAssist HTTP/1.1",
            b"POST /v1internal:streamGenerateContent?alt=sse HTTP/1.1",
            b"POST /v1internal:fetchAvailableModels HTTP/1.1",
            b"GET /oauth2/v2/userinfo?fields=id HTTP/1.1",
            b"GET /token HTTP/1.1", b"POST /token HTTP/1.0", b"POST /token HTTP/2",
            b"POST /token?extra=1 HTTP/1.1", b"POST /%74oken HTTP/1.1",
            b"POST https://oauth2.googleapis.com/token HTTP/1.1",
        ):
            with self.subTest(request_line=request_line):
                wire = packet(MetadataRoute.TOKEN, request_line=request_line)
                with self.assertRaisesRegex(MetadataIngressError, "request route"):
                    self.read(wire)

    def test_rejects_wrong_host_media_authorization_or_hop_values(self):
        for key, value in (
            (b"Host", b"oauth2.googleapis.com:443"), (b"Host", b"cloudcode-pa.googleapis.com"),
            (b"Host", b"oauth2.googleapis.com.synthetic.invalid"),
            (b"Content-Type", b"application/json"),
            (b"Content-Type", b"application/x-www-form-urlencoded; charset=utf-8"),
            (b"Connection", b"upgrade"), (b"Authorization", ACCESS),
            (b"Authorization", b"Basic malformed"), (b"Authorization", b"Basic " + base64.b64encode(b"other:fixture")),
        ):
            with self.subTest(key=key):
                wire = packet(MetadataRoute.TOKEN, changes={key: value})
                with self.assertRaises(MetadataIngressError):
                    self.read(wire)
        for value in (CLIENT, b"Bearer bad token", b"Bearer"):
            with self.subTest(value=value):
                wire = packet(MetadataRoute.LOAD_CODE_ASSIST, changes={b"Authorization": value})
                with self.assertRaises(MetadataIngressError):
                    self.read(wire, route=MetadataRoute.LOAD_CODE_ASSIST)

    def test_rejects_duplicate_extra_missing_and_unclean_headers(self):
        for changes, extra in (
            ({}, (b"Transfer-Encoding: chunked",)),
            ({}, (b"Content-Encoding: identity",)),
            ({}, (b"Expect: 100-continue",)),
            ({}, (b"X-Extra: fixture",)),
            ({b"Accept": None}, (b"accept-encoding: fixture",)),
            ({b"Accept": None}, (b"content-length: 100",)),
            ({b"Accept": None}, ()),
            ({b"Accept": None}, (b"Accept : application/json",)),
            ({b"Accept": None}, (b" Accept: application/json",)),
            ({b"Accept": None}, (b"Accept:\tapplication/json",)),
            ({b"Accept": b"application/json "}, ()),
            ({b"Accept": b"application/\x00json"}, ()),
            ({b"Accept": b"application/\x80json"}, ()),
            ({b"Accept": b"x" * 4097}, ()),
        ):
            with self.subTest(changes=changes, extra=extra):
                wire = packet(MetadataRoute.TOKEN, changes=changes, extra=extra)
                with self.assertRaises(MetadataIngressError):
                    self.read(wire)
        wire = packet(MetadataRoute.LOAD_CODE_ASSIST, extra=(b"Accept: application/json",))
        with self.assertRaises(MetadataIngressError):
            self.read(wire, route=MetadataRoute.LOAD_CODE_ASSIST)

    def test_rejects_noncanonical_oversized_or_partial_length(self):
        wire = packet(MetadataRoute.TOKEN)
        for value in (None, b"0", b"00", b"+5", b"5,5", b"8193", b"9" * 30, b" 5"):
            with self.subTest(value=value):
                bad_length = packet(MetadataRoute.TOKEN, changes={b"Content-Length": value})
                with self.assertRaises(MetadataIngressError):
                    self.read(bad_length)
        for partial in (wire[:-1], wire.split(b"\r\n\r\n", 1)[0], b"x" * 8193):
            with self.assertRaises(MetadataIngressError):
                self.read(partial)
        oversized = packet(MetadataRoute.LOAD_CODE_ASSIST, body=b"x" * 32769)
        with self.assertRaises(MetadataIngressError):
            self.read(oversized, route=MetadataRoute.LOAD_CODE_ASSIST)

    def test_detects_body_overrun_at_head_body_boundary_and_socket_lookahead(self):
        wire = packet(MetadataRoute.TOKEN)
        head, tail = wire.split(b"\r\n\r\n")
        for chunks in ((wire + b"x",), (head + b"\r\n\r\n", tail + b"x"), (wire, wire)):
            with self.subTest(chunks=len(chunks)), self.assertRaisesRegex(MetadataIngressError, "Unexpected bytes"):
                self.read(*chunks)

    def test_deadline_and_transport_errors_are_bounded_and_redacted(self):
        wire = packet(MetadataRoute.TOKEN)
        peer = FakePeer(wire, TimeoutError())
        read_enrollment_request(peer, route=MetadataRoute.TOKEN, deadline=time.monotonic() + 25)
        self.assertTrue(all(0 < timeout <= 2.5 for timeout in peer.timeouts))
        peer = FakePeer(wire)
        deadline = time.monotonic() - 1
        with self.assertRaises(MetadataIngressError):
            read_enrollment_request(peer, route=MetadataRoute.TOKEN, deadline=deadline)
        self.assertEqual(peer.reads, [])
        error = OSError("synthetic-not-for-repr")
        with self.assertRaises(MetadataIngressError) as denied:
            self.read(error)
        self.assertNotIn("synthetic-not-for-repr", str(denied.exception))
        self.assertIsNone(denied.exception.__context__)


if __name__ == "__main__":
    unittest.main()
