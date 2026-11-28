"""Admit only the expected metadata tunnel on an owned native connector."""

from contextlib import contextmanager
from dataclasses import dataclass
import os
import socket
import ssl
import stat
import time
from threading import Lock
from typing import Callable

from .auth_offer import CallbackGate, Refused, bind_callback, validate_offer
from .metadata_destination import MetadataRoute, _remaining
from .native_browser import callback_port
from .native_peer import admit_native_peer


_ROUTES = frozenset({MetadataRoute.TOKEN, MetadataRoute.LOAD_CODE_ASSIST, MetadataRoute.FETCH_AVAILABLE_MODELS})
_CONNECT_LIMIT = 4096
_DELIMITER = b"\r\n\r\n"
_ESTABLISHED = b"HTTP/1.1 200 Connection established\r\n\r\n"


_SIGN_IN_OWNER_RETIRED = "Google native sign-in owner retired"


class NativeTransportError(RuntimeError):
    """The private connector did not present an expected metadata tunnel."""


@dataclass(frozen=True, slots=True)
class NativeChannel:
    stream: object
    active: Callable[[], bool]


@contextmanager
def _private_listener(directory, name):
    node = directory.lstat()
    if (not directory.is_absolute() or not stat.S_ISDIR(node.st_mode) or node.st_uid != os.geteuid()
            or stat.S_IMODE(node.st_mode) != 0o700 or directory.resolve(strict=True) != directory):
        raise NativeTransportError("Native metadata listener needs a private directory")
    path = directory / name
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        created = path.lstat()
        try:
            path.chmod(0o600)
            listener.listen(1)
            yield path, listener
        finally:
            try:
                current = path.lstat()
            except FileNotFoundError:
                if directory.exists():
                    raise NativeTransportError("Native metadata listener path disappeared") from None
            else:
                if not os.path.samestat(current, created):
                    raise NativeTransportError("Native metadata listener path changed")
                path.unlink()


def _accept_owned(listener, deadline, authorized):
    while authorized() is True:
        listener.settimeout(min(.1, _remaining(deadline)))
        try:
            connection, _ = listener.accept()
        except TimeoutError:
            continue
        if authorized() is True:
            return connection
        connection.close()
    raise NativeTransportError("Google native owner retired while accepting a peer")


@contextmanager
def open_native_metadata_listener(directory, *, contexts, expected_group, read_cgroup, authorized):
    """Open one owner-private Unix listener and expose the enrollment accept contract.

    The supervisor owns the fresh directory and mounts only the socket into
    its connector's namespace. Any failed accept aborts the entire phase.
    """
    with _private_listener(directory, "metadata.sock") as (path, listener):

        @contextmanager
        def accept(route, deadline):
            if type(route) is not MetadataRoute or route not in _ROUTES or authorized() is not True:
                raise NativeTransportError("Native metadata listener is unavailable")
            context = contexts.get(route)
            if context is None:
                raise NativeTransportError("No certificate for the expected metadata route")
            group = expected_group()
            connection = _accept_owned(listener, deadline, authorized)
            with open_native_metadata_channel(
                connection, route=route, deadline=deadline, expected_group=group,
                read_cgroup=read_cgroup, context=context, authorized=authorized,
            ) as channel:
                yield channel

        yield path, accept


def _read_offer(connection, deadline):
    data = bytearray()
    while b"\n" not in data:
        if len(data) == 8193:
            raise NativeTransportError("Google native sign-in link exceeded its byte limit")
        connection.settimeout(min(2, _remaining(deadline)))
        block = connection.recv(8193 - len(data))
        if not block:
            raise NativeTransportError("Incomplete Google native sign-in link")
        data.extend(block)
    if data.find(b"\n") != len(data) - 1:
        raise NativeTransportError("Unexpected trailing Google native sign-in data")
    try:
        raw = data[:-1].decode("ascii")
        port = callback_port(raw)
        validate_offer(raw, port)
    except (ValueError, Refused):
        raise NativeTransportError("Invalid Google native sign-in link") from None
    return raw, port


def _peer_authorized(peer, authorized, deadline):
    """Recheck the phase owner after the potentially blocking cgroup read."""
    return (time.monotonic() < deadline and authorized() is True and peer.active()
            and authorized() is True and time.monotonic() < deadline)


@contextmanager
def open_native_browser_listener(directory, *, expected_group, read_cgroup, authorized, fence=None):
    """Receive one native browser offer and hold its independently verified callback."""
    with _private_listener(directory, "browser.sock") as (path, listener):
        spent = False
        claim = Lock()

        @contextmanager
        def receive(deadline):
            nonlocal spent
            with claim:
                if spent:
                    raise NativeTransportError(_SIGN_IN_OWNER_RETIRED)
                spent = True
            if authorized() is not True:
                raise NativeTransportError(_SIGN_IN_OWNER_RETIRED)
            group = expected_group()
            connection = _accept_owned(listener, deadline, authorized)
            with connection, admit_native_peer(connection, expected_group=group, read_cgroup=read_cgroup) as peer:
                def active():
                    return _peer_authorized(peer, authorized, deadline)

                if not active():
                    raise NativeTransportError(_SIGN_IN_OWNER_RETIRED)
                raw, port = _read_offer(connection, deadline)
                with bind_callback(port) as callback:
                    gate = CallbackGate(callback, connection, native_port=port, authorized=active, deadline=deadline,
                                        fence=fence)
                    try:
                        yield gate.accept_offer(raw), gate
                    finally:
                        gate.revoke()

        yield path, receive


def native_server_context(route: MetadataRoute, *, certificate, key):
    """Use the supervisor's short-lived private certificate, only for this route's SNI."""
    if type(route) is not MetadataRoute or route not in _ROUTES:
        raise NativeTransportError("Invalid native metadata route")
    host = route.value[0]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    def refuse_passphrase():
        raise NativeTransportError("Google metadata TLS key cannot require interactive credentials")

    context.load_cert_chain(certificate, key, password=refuse_passphrase)

    def check_sni(_socket, name, _context):
        if name != host:
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        return None

    context.set_servername_callback(check_sni)
    return context


def _read_connect(connection, authority, deadline):
    packet = bytearray()
    while _DELIMITER not in packet:
        if len(packet) == _CONNECT_LIMIT:
            raise NativeTransportError("Native metadata tunnel header exceeded its limit")
        connection.settimeout(min(2, _remaining(deadline)))
        block = connection.recv(_CONNECT_LIMIT - len(packet))
        if not block:
            raise NativeTransportError("Incomplete native metadata tunnel header")
        packet.extend(block)
    expected = (b"CONNECT " + authority + b" HTTP/1.1\r\nHost: " + authority + _DELIMITER)
    if packet != expected:
        raise NativeTransportError("Unexpected native metadata tunnel authority")


@contextmanager
def open_native_metadata_channel(
    connection, *, route, deadline, expected_group, read_cgroup, context, authorized,
):
    """Authenticate the private Unix connector before admitting one local TLS request.

    No network connection is opened here. The owning supervisor provides one
    route-specific certificate context and closes the listener on retirement.
    """
    with connection:
        if type(route) is not MetadataRoute or route not in _ROUTES:
            raise NativeTransportError("Invalid native metadata route")
        with admit_native_peer(connection, expected_group=expected_group, read_cgroup=read_cgroup) as peer:
            def active():
                return _peer_authorized(peer, authorized, deadline)

            if not active():
                raise NativeTransportError("Native metadata tunnel owner retired")
            authority = route.value[0].encode("ascii") + b":443"
            _read_connect(connection, authority, deadline)
            connection.settimeout(min(2, _remaining(deadline)))
            if not active():
                raise NativeTransportError("Native metadata tunnel owner retired")
            connection.sendall(_ESTABLISHED)
            connection.settimeout(min(2, _remaining(deadline)))
            with context.wrap_socket(connection, server_side=True) as stream:
                if stream.selected_alpn_protocol() not in (None, "http/1.1") or not active():
                    raise NativeTransportError("Native metadata TLS channel is unavailable")
                yield NativeChannel(stream, active)
