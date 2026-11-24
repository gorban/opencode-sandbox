"""Check that revocation fences concrete Unix dials and every forwarded chunk."""

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import runpy
import socket
import ssl
from tempfile import TemporaryDirectory
from threading import Event
import time
import unittest


MODULE = runpy.run_path(str(Path(__file__).with_name("offline-tunnel.py")))
Attempt = MODULE["OfflineAttempt"]
Closed = MODULE["AttemptClosed"]
TOKEN, USERINFO = MODULE["PHASES"]


def synthetic_dns(host, port, **_options):
    if host not in (TOKEN, USERINFO) or port != 443:
        raise AssertionError("unexpected synthetic DNS lookup")
    return ((socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", port)),)


def hello_for(host):
    output = ssl.MemoryBIO()
    connection = ssl.create_default_context().wrap_bio(ssl.MemoryBIO(), output, server_hostname=host)
    try:
        connection.do_handshake()
    except ssl.SSLWantReadError:
        return output.read()
    raise AssertionError("expected a synthetic ClientHello")


class TunnelTest(unittest.TestCase):
    def setUp(self):
        self.scratch = self.enterContext(TemporaryDirectory())
        self.path = str(Path(self.scratch) / "peer.sock")
        self.observer = self.enterContext(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        self.observer.bind(self.path)
        self.observer.listen()
        self.observer.settimeout(1)
        self.attempt = Attempt("fixture-generation", deadline=time.monotonic() + 8,
                               expected_pid=os.getpid(), expected_uid=os.getuid())
        self.addCleanup(self.attempt.revoke)

    def provision(self, host=TOKEN):
        client, caller = socket.socketpair()
        self.enterContext(client)
        self.enterContext(caller)
        caller.settimeout(1)
        tunnel = self.attempt.admit(client, host=host)
        authority = f"{host}:443".encode()
        caller.sendall(b"CONNECT " + authority + b" HTTP/1.1\r\nHost: " + authority + b"\r\n\r\n")
        hello = hello_for(host)
        with ThreadPoolExecutor(max_workers=1) as worker:
            result = worker.submit(self.attempt.hello, tunnel)
            approval = MODULE["TLS"]["ESTABLISHED"]
            with caller.makefile("rb") as response:
                self.assertEqual(response.read(len(approval)), approval)
            caller.sendall(hello)
            self.assertEqual(result.result(2), hello)
        return tunnel, caller, hello

    def dial(self, tunnel, resolver=synthetic_dns):
        return self.attempt.dial(tunnel, fake_resolve=resolver, fake_path=self.path)

    def test_cancel_during_dns_closes_provisional_client_and_prevents_dial(self):
        tunnel, caller, _hello = self.provision()
        entered, finish = Event(), Event()

        def blocked_dns(*args, **kwargs):
            entered.set()
            if not finish.wait(2):
                raise TimeoutError()
            return synthetic_dns(*args, **kwargs)

        with ThreadPoolExecutor(max_workers=1) as worker:
            result = worker.submit(self.dial, tunnel, blocked_dns)
            try:
                self.assertTrue(entered.wait(1))
                self.attempt.revoke()
                self.assertEqual(caller.recv(1), b"")
            finally:
                finish.set()
            with self.assertRaises(Closed):
                result.result(2)
        self.observer.setblocking(False)
        with self.assertRaises(BlockingIOError):
            self.observer.accept()

    def test_cancel_closes_the_client_before_its_hello(self):
        client, caller = socket.socketpair()
        with client, caller, ThreadPoolExecutor(max_workers=1) as worker:
            caller.settimeout(1)
            tunnel = self.attempt.admit(client, host=TOKEN)
            authority = f"{TOKEN}:443".encode()
            caller.sendall(b"CONNECT " + authority + b" HTTP/1.1\r\nHost: " + authority + b"\r\n\r\n")
            result = worker.submit(self.attempt.hello, tunnel)
            approval = MODULE["TLS"]["ESTABLISHED"]
            with caller.makefile("rb") as response:
                self.assertEqual(response.read(len(approval)), approval)
            self.attempt.revoke()
            with self.assertRaises((OSError, MODULE["TLS"]["Refused"])):
                result.result(2)
            self.assertEqual(caller.recv(1), b"")

    def test_cancel_after_dial_prevents_first_forward(self):
        tunnel, caller, hello = self.provision()
        self.dial(tunnel)
        with self.observer.accept()[0] as fake:
            self.attempt.connected(tunnel)
            self.attempt.revoke()
            with self.assertRaises(Closed):
                self.attempt.write(tunnel, hello)
            self.assertEqual(fake.recv(1), b"")
            self.assertEqual(caller.recv(1), b"")

    def test_revocation_after_a_write_preserves_only_accepted_bytes_and_closes(self):
        tunnel, caller, hello = self.provision()
        self.dial(tunnel)
        with self.observer.accept()[0] as fake:
            self.attempt.connected(tunnel)
            with self.assertRaises(Closed):
                self.attempt.write(tunnel, b"not the validated hello")
            sent = self.attempt.write(tunnel, hello)
            self.assertGreater(sent, 0)
            self.attempt.revoke()
            for to_peer in (False, True):
                with self.assertRaises(Closed):
                    self.attempt.write(tunnel, b"late", to_peer=to_peer)
            with fake.makefile("rb") as stream:
                self.assertEqual(stream.read(), hello[:sent])
            self.assertEqual(caller.recv(1), b"")
        another, other_end = socket.socketpair()
        with another, other_end:
            with self.assertRaises(Closed):
                self.attempt.admit(another, host=USERINFO)

    def test_userinfo_admission_waits_for_token_tunnel_retirement(self):
        premature, other_end = socket.socketpair()
        with premature, other_end:
            with self.assertRaises(Closed):
                self.attempt.admit(premature, host=USERINFO)
        token, _caller, hello = self.provision()
        self.dial(token)
        with self.observer.accept()[0]:
            self.attempt.connected(token)
            self.attempt.write(token, hello)
            self.attempt.finish(token)
        userinfo, _caller, _hello = self.provision(host=USERINFO)
        self.assertEqual(userinfo.host, USERINFO)
        with self.assertRaises(Closed):
            self.dial(token)


if __name__ == "__main__":
    unittest.main()
