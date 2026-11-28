"""Exercise the native proxy with a local socket and no external destination."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import socket
import tempfile
import time
import unittest
from unittest.mock import patch

from oc_google.native_proxy import NativeProxyError, open_loopback_proxy, relay_connection


class NativeProxyTest(unittest.TestCase):
    def test_fixed_unix_connector_preserves_both_halves_and_eof(self):
        with tempfile.TemporaryDirectory() as temporary, open_loopback_proxy() as loopback, \
                socket.socket(socket.AF_UNIX) as unix, ThreadPoolExecutor(max_workers=1) as pool:
            self.assertEqual(loopback.getsockname()[0], "127.0.0.1")
            connector = Path(temporary) / "metadata.sock"
            unix.bind(str(connector))
            unix.listen(1)
            unix.settimeout(2)
            result = pool.submit(relay_connection, loopback, connector, time.monotonic() + 2)
            with socket.create_connection(loopback.getsockname(), timeout=2) as client, unix.accept()[0] as broker:
                broker.settimeout(2)
                client.sendall(b"native")
                client.shutdown(socket.SHUT_WR)
                with broker.makefile("rb") as stream:
                    self.assertEqual(stream.read(20), b"native")
                broker.sendall(b"metadata")
                broker.shutdown(socket.SHUT_WR)
                with client.makefile("rb") as stream:
                    self.assertEqual(stream.read(20), b"metadata")
            result.result(timeout=2)

    def test_extra_bytes_do_not_pass_the_wire_bound(self):
        with tempfile.TemporaryDirectory() as temporary, open_loopback_proxy() as loopback, \
                socket.socket(socket.AF_UNIX) as unix, ThreadPoolExecutor(max_workers=1) as pool:
            connector = Path(temporary) / "metadata.sock"
            unix.bind(str(connector))
            unix.listen(1)
            unix.settimeout(2)
            with patch("oc_google.native_proxy._WIRE_LIMIT", 1):
                result = pool.submit(relay_connection, loopback, connector, time.monotonic() + 2)
                with socket.create_connection(loopback.getsockname(), timeout=2) as client, unix.accept()[0] as broker:
                    broker.settimeout(2)
                    client.sendall(b"ab")
                    client.shutdown(socket.SHUT_WR)
                    with self.assertRaises(NativeProxyError):
                        result.result(timeout=2)
                    self.assertEqual(broker.recv(20), b"")
