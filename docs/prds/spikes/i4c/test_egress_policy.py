"""Offline regression checks for native enrollment CONNECT admission."""

import runpy
from pathlib import Path
import socket
import unittest


POLICY = runpy.run_path(str(Path(__file__).with_name("egress-policy.py")))
Refused = POLICY["Refused"]
AUTHORITY = b"oauth2.googleapis.com:443"
REQUEST = b"CONNECT " + AUTHORITY + b" HTTP/1.1\r\nHost: " + AUTHORITY + b"\r\n"


class EgressPolicyTest(unittest.TestCase):
    def test_native_shape_through_unix_socket(self):
        client, writer = socket.socketpair()
        with client, writer:
            writer.sendall(REQUEST[:12])
            writer.sendall(REQUEST[12:] + b"User-Agent: fixture\r\n\r\n")
            self.assertEqual(POLICY["read_connect"](client), "oauth2.googleapis.com")

    def test_other_destinations_and_ambiguous_framing_are_refused(self):
        invalid = (
            REQUEST.replace(AUTHORITY, b"gemini.example:443") + b"\r\n",
            REQUEST.replace(AUTHORITY, b"127.0.0.1:443") + b"\r\n",
            REQUEST.replace(b"HTTP/1.1", b"HTTP/1.0") + b"\r\n",
            REQUEST + b"Host: override.example:443\r\n\r\n",
            REQUEST + b"Transfer-Encoding: chunked\r\n\r\n",
            REQUEST + b" Content-Length: 0\r\n\r\n",
            REQUEST + b"\r\ntrailing bytes",
            b"CONNECT " + AUTHORITY + b" HTTP/1.1\r\n\r\n",
        )
        for wire in invalid:
            with self.subTest(wire=wire), self.assertRaises(Refused):
                POLICY["enrollment_authority"](wire)

    def test_dns_must_return_only_global_numeric_addresses(self):
        def rows(*addresses):
            return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", address) for family, address in addresses]

        public = (socket.AF_INET, ("8.8.8.8", 443))
        self.assertEqual(POLICY["resolve_token_endpoint"](resolve=lambda *_a, **_k: rows(public)), (public,))
        for forbidden in ((socket.AF_INET, ("10.0.0.1", 443)), (socket.AF_INET, ("224.0.0.1", 443)),
                          (socket.AF_INET6, ("::ffff:8.8.8.8", 443, 0, 0)),
                          (socket.AF_INET6, ("fe80::1", 443, 0, 1))):
            with self.subTest(address=forbidden), self.assertRaises(Refused):
                POLICY["resolve_token_endpoint"](resolve=lambda *_a, **_k: rows(public, forbidden))


if __name__ == "__main__":
    unittest.main()
