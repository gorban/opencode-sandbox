#!/usr/bin/python3 -IBS
"""Forward the native private callback through the owner, without opening a browser."""

import re
from pathlib import Path
import select
import socket
import subprocess
import sys
import time
from urllib.parse import parse_qsl, urlsplit


_CONNECTOR = "/run/oc-transport/browser.sock"
_OFFER_LIMIT = 8192
_CALLBACK_LIMIT = 8192
_CALLBACK_SECONDS = 180
_REDIRECT = re.compile(r"http://127[.]0[.]0[.]1:([1-9][0-9]{3,4})/\Z", re.ASCII)


def callback_port(link):
    if not 0 < len(link) <= _OFFER_LIMIT or not all(33 <= ord(char) <= 126 for char in link):
        raise ValueError
    target = urlsplit(link)
    if ((target.scheme, target.netloc, target.path) != ("https", "accounts.google.com", "/o/oauth2/v2/auth")
            or target.fragment):
        raise ValueError
    redirects = [value for key, value in parse_qsl(target.query, strict_parsing=True, max_num_fields=16,
                                                   keep_blank_values=True) if key == "redirect_uri"]
    match = _REDIRECT.fullmatch(redirects[0]) if len(redirects) == 1 else None
    if match is None:
        raise ValueError
    port = int(match[1])
    if not 1024 <= port <= 65535 or port == 9222 or 8401 <= port <= 8416:
        raise ValueError
    return port


def _callback(owner, deadline):
    result = bytearray()
    while b"\r\n\r\n" not in result:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or len(result) == _CALLBACK_LIMIT:
            raise ValueError
        owner.settimeout(remaining)
        block = owner.recv(_CALLBACK_LIMIT - len(result))
        if not block:
            raise ValueError
        result.extend(block)
    if not result.startswith(b"GET /?") or result.find(b"\r\n\r\n") != len(result) - 4:
        raise ValueError
    return result


def _handoff(link):
    port = callback_port(link)
    listeners = []
    for table in ("tcp", "tcp6"):
        for row in Path(f"/proc/net/{table}").read_text(encoding="ascii").splitlines()[1:]:
            _, local, _, state, *_ = row.split()
            address, separator, number = local.partition(":")
            if separator and int(number, 16) == port and state == "0A":
                listeners.append((table, address))
    if listeners != [("tcp", "0100007F")]:
        raise ValueError
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as callback, socket.socket(socket.AF_UNIX) as owner:
        callback.settimeout(2)
        callback.connect(("127.0.0.1", port))
        owner.settimeout(2)
        owner.connect(_CONNECTOR)
        owner.sendall(link.encode("ascii") + b"\n")
        sys.stdout.buffer.write(b"R")
        sys.stdout.buffer.flush()
        deadline = time.monotonic() + _CALLBACK_SECONDS
        request = _callback(owner, deadline)
        callback.sendall(request)
        # The broker still needs the peer's live identity when it consumes the
        # callback evidence. Hold both channels until the broker closes its side.
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError
        owner.settimeout(remaining)
        if owner.recv(1):
            raise ValueError


def _start_handoff(link):
    callback_port(link)
    # Native waits for BROWSER to exit before handling the HTTP callback. The
    # helper below keeps the pinned Unix peer alive under the same service.
    child = subprocess.Popen([sys.executable, "-IBS", __file__, "--owned-callback"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        with child.stdin:
            child.stdin.write(link.encode("ascii") + b"\n")
        with child.stdout:
            ready, _, _ = select.select((child.stdout,), (), (), 3)
            if not ready or child.stdout.read(1) != b"R":
                raise ValueError
    except BaseException:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=2)
        raise


if __name__ == "__main__":
    try:
        offer, = sys.argv[1:]
        if offer == "--owned-callback":
            raw = sys.stdin.buffer.readline(_OFFER_LIMIT + 2)
            if not raw.endswith(b"\n") or sys.stdin.buffer.read(1):
                raise ValueError
            _handoff(raw[:-1].decode("ascii"))
        else:
            _start_handoff(offer)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise SystemExit(1) from None
