"""Fence one authenticated OpenCode request and one offline ACP text response."""

from contextlib import ExitStack, suppress
import ctypes
from dataclasses import dataclass
import hmac
import os
import select
import socket
import threading
import time

from oc_orchestrator import protocol


_libc_send = ctypes.CDLL(None, use_errno=True).send
_libc_send.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int)
_libc_send.restype = ctypes.c_ssize_t


def _send_once(client, data):
    # Python socket.send restarts EINTR. A fenced write must spend one syscall.
    size = _libc_send(client.fileno(), data, len(data), socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
    if size < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return size


@dataclass(frozen=True)
class BrokerReceipt:
    """Count answer bytes only, with None for an uncertain delivery syscall."""

    claims: int
    answers: int
    refusals: int
    response_bytes: int | None
    request_body: bytes | None


class TextBroker:
    """The owner supplies the initialized synthetic session and its lifeline."""

    def __init__(self, address, proof, *, authorized, port=protocol.PORT):
        if len(proof) != protocol.PROOF_SIZE:
            raise ValueError("Invalid broker proof size")
        self._proof = proof
        self._authorized = authorized
        self._port = port
        self._lock = threading.Lock()
        self._revoked = threading.Event()
        self._connection = None
        self._session = None
        self._claims = 0
        self._answers = 0
        self._refusals = 0
        self._response_bytes = 0
        self._request_body = None
        self._error = None
        self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self._listener.bind(str(address))
            os.chmod(address, 0o600)
            self._listener.listen(2)
            self._listener.setblocking(False)
            self._poll = select.poll()
            self._poll.register(self._listener, select.POLLIN)
        except BaseException:
            self._listener.close()
            raise
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        try:
            self._thread.start()
        except BaseException:
            self.revoke()
            raise
        return self

    def __exit__(self, exc_type, *_):
        self.revoke()
        self._thread.join(protocol.IDLE + 1)
        if self._thread.is_alive():
            raise RuntimeError("The offline ACP broker did not stop")
        if exc_type is None:
            self.receipt()

    def cancelled(self):
        """ACP waits can call this without taking the admission fence."""
        return self._revoked.is_set() or not self._authorized()

    def arm(self, session):
        with self._lock:
            if session is None or self._session is not None or self.cancelled():
                raise RuntimeError("The offline ACP broker cannot arm this session")
            # Discard handoffs already queued before the arming boundary.
            # Fail closed if the private socket cannot be drained promptly.
            for _ in range(8):
                try:
                    stale, _ = self._listener.accept()
                except BlockingIOError:
                    # The accept loop stays fenced while the drained queue arms.
                    break
                stale.close()
                self._refusals += 1
            else:
                raise RuntimeError("The offline ACP broker could not drain pre-arm handoffs")
            if self.cancelled():
                raise RuntimeError("The owner exited before the broker armed")
            self._session = session

    def revoke(self):
        with self._lock:
            self._revoked.set()
            if self._connection is not None:
                with suppress(OSError):
                    self._connection.shutdown(socket.SHUT_RDWR)
            self._listener.close()

    def _snapshot(self):
        return BrokerReceipt(self._claims, self._answers, self._refusals,
                             self._response_bytes, self._request_body)

    def outcome(self):
        """Capture the local counts even if the ACP transcript failed."""
        with self._lock:
            return self._snapshot()

    def receipt(self):
        """Raise any settled broker failure in the owner thread."""
        with self._lock:
            if self._error is not None:
                raise self._error
            return self._snapshot()

    def _serve(self):
        try:
            while not self.cancelled():
                if not self._poll.poll(200):
                    continue
                with self._lock:
                    if self.cancelled():
                        return
                    try:
                        control, _ = self._listener.accept()
                    except BlockingIOError:
                        continue
                    self._connection = control
                    session = self._session
                if not self._handle(control, session):
                    return
        except Exception as error:
            with self._lock:
                self._error = error
        finally:
            self._close_route_and_retire_peer()

    def _close_route_and_retire_peer(self):
        self.revoke()
        with self._lock:
            session = self._session
        if session is None:
            return
        try:
            session.retire()
        except Exception as error:
            with self._lock:
                if self._error is None:
                    self._error = error
                else:
                    self._error.add_note(f"Offline ACP peer retirement also failed: {error}")

    def _handle(self, control, session):
        with ExitStack() as sockets:
            sockets.enter_context(control)
            try:
                settled = session is not None and self._process(control, session, sockets)
            except Exception as error:
                # Settle before closing the client, which can unblock the owner.
                with self._lock:
                    self._error = error
                    self._refusals += 1
                self.revoke()
                return False
            finally:
                with self._lock:
                    self._connection = None
            if not settled:
                with self._lock:
                    self._refusals += 1
        return True

    def _process(self, control, session, sockets):
        deadline = time.monotonic() + protocol.TOTAL
        try:
            proof = protocol.fixed_bytes(control, protocol.PROOF_SIZE, deadline)
            if not hmac.compare_digest(proof, self._proof):
                return False
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            control.settimeout(min(protocol.IDLE, remaining))
            client = sockets.enter_context(protocol.receive_client(control, self._port))
        except (OSError, protocol.Refused):
            return False
        with self._lock:
            if self.cancelled():
                return False
            self._connection = client
        try:
            body = protocol.request_body(client, deadline, self._port)
            protocol.accept_text(body)
        except (OSError, ValueError, RecursionError):
            return self._refuse(client)
        return self._deliver(client, session, body)

    def _refuse(self, client):
        with self._lock:
            self._refusals += 1
            if not self.cancelled():
                with suppress(OSError):
                    _send_once(client, protocol.REFUSAL)
        return True

    def _deliver(self, client, session, body):
        # Explicit revoke shares this fence. Physical owner EOF after a final
        # readiness check can race the syscall and counts as an in-flight write.
        with self._lock:
            replay = bool(self._claims)
            if not replay:
                if self.cancelled():
                    return False
                self._claims += 1
                self._request_body = body
                session.send_prompt()
        if replay:
            return self._refuse(client)
        text = session.complete()
        if type(text) is not str or text != "ok":
            raise RuntimeError("The offline ACP transcript did not verify exact fixture text")
        response = protocol.reply_bytes(protocol.FIXTURE_EVENTS)
        with self._lock:
            if self.cancelled():
                return False
            try:
                self._response_bytes = _send_once(client, response)
            except OSError:
                self._response_bytes = None
                return False
            if self._response_bytes != len(response):
                return False
            self._answers += 1
            return True
