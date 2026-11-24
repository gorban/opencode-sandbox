"""Bound the resolver and race one TLS-only diagnostic against retirement."""

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Event
import time
import unittest
from unittest.mock import patch

import oc_antigravity_connector as connector
import oc_antigravity_dns as dns


def wire(*addresses):
    rows = [[family, socket.SOCK_STREAM, socket.IPPROTO_TCP, address] for family, address in addresses]
    return json.dumps(rows).encode("ascii")


class ResolverTest(unittest.TestCase):
    def test_all_answers_are_validated_before_selection(self):
        valid = (socket.AF_INET, ["8.8.8.8", 443])
        valid6 = (socket.AF_INET6, ["2001:4860:4860::8888", 443, 0, 0])
        expected = ((socket.AF_INET, ("8.8.8.8", 443)),
                    (socket.AF_INET6, ("2001:4860:4860::8888", 443, 0, 0)))
        self.assertEqual(dns.validate_answers(wire(valid, valid6, valid)), expected)
        forbidden = ((socket.AF_INET, ["127.0.0.1", 443]), (socket.AF_INET, ["224.0.0.1", 443]),
                     (socket.AF_INET, ["8.8.8.8", 80]), (socket.AF_INET6, ["::ffff:8.8.8.8", 443, 0, 0]),
                     (socket.AF_INET6, ["fe80::1", 443, 0, 2]), (socket.AF_INET6, ["::1", 443, 0, 0]),
                     (socket.AF_INET6, ["64:ff9b::a00:1", 443, 0, 0]),
                     (socket.AF_INET6, ["2002:a00:100::", 443, 0, 0]))
        for address in forbidden:
            with self.subTest(address=address), self.assertRaises(dns.ResolverError):
                dns.validate_answers(wire(valid, address))
        with self.assertRaises(dns.ResolverError):
            dns.validate_answers(wire(*[valid] * 33))

    def test_stalled_and_oversize_resolvers_are_killed_and_reaped(self):
        cases = (("import time; time.sleep(10)", .15),
                 ("import os,time; os.write(1,b'x'*4097); time.sleep(10)", 1.0),
                 ("import os,time; os.close(1); time.sleep(10)", .15))
        for code, lifetime in cases:
            children = []
            real = subprocess.Popen

            def record(*args, **kwargs):
                child = real(*args, **kwargs)
                children.append(child)
                return child

            with self.subTest(code=code), patch.object(dns.subprocess, "Popen", side_effect=record):
                command = [sys.executable, "-IBS", "-c", code]
                deadline = time.monotonic() + lifetime
                started = time.monotonic()
                with self.assertRaises(dns.ResolverError):
                    dns.capture_resolver(command, deadline=deadline)
                self.assertLess(time.monotonic() - started, lifetime + .65)
                self.assertEqual(len(children), 1)
                self.assertEqual(children[0].returncode, -9)


class DiagnosticTest(unittest.TestCase):
    def setUp(self):
        self.listener = self.enterContext(socket.socket())
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(2)
        self.owner = os.pidfd_open(os.getpid())
        self.addCleanup(os.close, self.owner)
        self.attempt = connector.DiagnosticAttempt(dns.HOSTS[0], owner_fd=self.owner, deadline=time.monotonic() + 5)
        self.addCleanup(self.attempt.revoke)
        self.context = ssl.create_default_context()

    def resolve_locally(self, _hostname, *, deadline):
        self.assertGreater(deadline, time.monotonic())
        return socket.AF_INET, self.listener.getsockname()

    def test_revoke_after_connect_writes_no_client_hello(self):
        self.attempt.connect(resolver=self.resolve_locally)
        with self.listener.accept()[0] as peer:
            self.attempt.revoke()
            with self.assertRaises(connector.ConnectorError):
                connector.certificate_handshake(self.attempt, self.context)
            self.assertEqual(peer.recv(1), b"")

    def test_revoke_during_handshake_closes_peer(self):
        self.attempt.connect(resolver=self.resolve_locally)
        with self.listener.accept()[0] as peer, ThreadPoolExecutor(max_workers=1) as worker:
            peer.settimeout(1)
            handshake = worker.submit(connector.certificate_handshake, self.attempt, self.context)
            with peer.makefile("rb") as wire_reader:
                header = wire_reader.read(5)
                self.assertEqual(header[:2], b"\x16\x03")
                length = int.from_bytes(header[3:], "big")
                self.assertEqual(len(wire_reader.read(length)), length)
                self.attempt.revoke()
                with self.assertRaises(connector.ConnectorError):
                    handshake.result(2)
                self.assertEqual(wire_reader.read(1), b"")

    def test_late_resolution_cannot_dial_a_revoked_attempt(self):
        entered, release = Event(), Event()

        def resolver(hostname, *, deadline):
            entered.set()
            if not release.wait(2):
                raise TimeoutError()
            return self.resolve_locally(hostname, deadline=deadline)

        with ThreadPoolExecutor(max_workers=1) as worker:
            connection = worker.submit(self.attempt.connect, resolver=resolver)
            try:
                self.assertTrue(entered.wait(1))
                self.attempt.revoke()
            finally:
                release.set()
            with self.assertRaises(connector.ConnectorError):
                connection.result(2)
        self.listener.setblocking(False)
        with self.assertRaises(BlockingIOError):
            self.listener.accept()

    def test_failed_resolution_consumes_the_only_slot(self):
        looked_up = []

        def fail_lookup(hostname, *, deadline):
            looked_up.append(hostname)
            raise dns.ResolverError("synthetic test")

        with self.assertRaises(dns.ResolverError):
            self.attempt.connect(resolver=fail_lookup)
        with self.assertRaises(connector.ConnectorError):
            self.attempt.connect(resolver=fail_lookup)
        self.assertEqual(looked_up, [dns.HOSTS[0]])

    def test_validated_tls_negotiates_without_application_bytes(self):
        binary = Path("/usr/bin/openssl")
        launcher = [str(binary)]
        scratch_root = None
        if not binary.is_file():
            host_spawn = Path("/usr/bin/host-spawn")
            scratch_root = Path(f"/run/user/{os.getuid()}")
            if not host_spawn.is_file() or not scratch_root.is_dir():
                self.skipTest("OpenSSL fixture generator unavailable")
            launcher = [str(host_spawn), "--no-pty", str(binary)]
        with TemporaryDirectory(prefix="oc-tls-test-", dir=scratch_root) as scratch:
            cert, key = Path(scratch) / "cert.pem", Path(scratch) / "key.pem"
            req = [*launcher, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                   "-noenc", "-days", "1", "-subj", "/CN=Synthetic TLS probe",
                   "-addext", f"subjectAltName=DNS:{dns.HOSTS[0]}", "-keyout", str(key), "-out", str(cert)]
            subprocess.run(req, check=True, timeout=5, stdin=subprocess.DEVNULL, capture_output=True)
            server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server.load_cert_chain(cert, key)
            server.num_tickets = 0
            client = ssl.create_default_context(cafile=cert)
            self.attempt.connect(resolver=self.resolve_locally)
            with self.listener.accept()[0] as tcp_peer, ThreadPoolExecutor(max_workers=1) as worker:
                tcp_peer.settimeout(2)
                result = worker.submit(connector.certificate_handshake, self.attempt, client)
                with server.wrap_socket(tcp_peer, server_side=True) as tls_peer:
                    self.assertIn(result.result(2), ("TLSv1.2", "TLSv1.3"))
                    self.attempt.revoke()
                    self.assertEqual(tls_peer.recv(1), b"")


if __name__ == "__main__":
    unittest.main()
