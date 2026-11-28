"""Verify the native sign-in connector pins the original callback socket."""

from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlencode
import unittest

from oc_google import native_browser
from test_google_auth_offer import offer


class NativeBrowserTest(unittest.TestCase):
    def test_callback_redirect_has_exact_local_shape(self):
        self.assertEqual(native_browser.callback_port(offer(54321)), 54321)
        for port in (1023, 65536, 9222, 8401, 8416):
            with self.subTest(port=port), self.assertRaises(ValueError):
                native_browser.callback_port(offer(54321, redirect_uri=f"http://127.0.0.1:{port}/"))
        for raw in (offer(54321) + "#fragment", offer(54321, redirect_uri="http://localhost:54321/"),
                    offer(54321) + "&" + urlencode({"redirect_uri": "http://127.0.0.1:54321/"})):
            with self.assertRaises(ValueError):
                native_browser.callback_port(raw)

    def test_replacement_listener_receives_no_callback(self):
        with tempfile.TemporaryDirectory() as directory, socket.socket(socket.AF_UNIX) as owner, \
                socket.socket(socket.AF_INET) as native, ThreadPoolExecutor(max_workers=1) as pool:
            path = Path(directory) / "browser.sock"
            owner.bind(str(path))
            owner.listen(1)
            owner.settimeout(3)
            native.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            native.bind(("127.0.0.1", 0))
            native.listen(1)
            native.settimeout(3)
            port = native.getsockname()[1]
            with patch.object(native_browser, "_CONNECTOR", str(path)), \
                    patch.object(native_browser.sys, "stdout", SimpleNamespace(buffer=BytesIO())):
                handoff = pool.submit(native_browser._handoff, offer(port))
                with owner.accept()[0] as control, native.accept()[0] as exact, socket.socket() as replacement:
                    native.close()
                    replacement.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    replacement.bind(("127.0.0.1", port))
                    replacement.listen(1)
                    replacement.settimeout(.1)
                    exact.settimeout(2)
                    control.settimeout(2)
                    with control.makefile("rb") as stream:
                        self.assertEqual(stream.readline(), offer(port).encode() + b"\n")
                    packet = b"GET /?code=fixture HTTP/1.1\r\n\r\n"
                    control.sendall(packet)
                    self.assertEqual(exact.recv(256), packet)
                    with self.assertRaises(TimeoutError):
                        replacement.accept()
                handoff.result(timeout=3)
