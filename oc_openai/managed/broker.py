"""Private, single-turn OpenAI Responses broker."""

import contextlib
import hmac
import os
import select
import secrets
import socket
import stat
import threading
import time

from . import protocol
from .relay import GRANT_POLL, PEER_CLOSED, PROOF_PREFIX, read_exact
from .relay_receipt import MAX_REQUEST, MAX_RESPONSE, RECEIPT, REQUEST_LENGTH, RESPONSE_HEADER
from .runtime import WORKER_MODEL

_PARSE_SECONDS = 5
_RESPONSE_SECONDS = 75
_MAX_CLIENTS = 8
_DENIED = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


def _shutdown(peer):
    with contextlib.suppress(OSError):
        peer.shutdown(socket.SHUT_RDWR)


class Broker:
    def __init__(self, job, responses, before_dispatch):
        self.job = job
        self._responses = responses
        self._before_dispatch = before_dispatch
        self._state = threading.Condition()
        self._stopped = threading.Event()
        self.done = threading.Event()
        self._clients = {}
        self._phase = "pending"
        self._initial = None
        self._cancel = None
        self._listener = None
        self._thread = None
        self._socket_id = None

    def start(self):
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._listener = listener
        path = self.job.provider_socket
        listener.bind(str(path))
        path.chmod(0o600)
        details = path.lstat()
        self._socket_id = (details.st_dev, details.st_ino)
        listener.listen(_MAX_CLIENTS)
        listener.settimeout(GRANT_POLL)
        self._thread = threading.Thread(target=self._accept, name="oc-openai-broker", daemon=True)
        self._thread.start()

    def matches_managed_binding(self, path, lease, proof):
        details = path.lstat()
        return (path == self.job.provider_socket and lease is self.job.lease and proof is self.job.relay_proof
                and stat.S_ISSOCK(details.st_mode) and details.st_uid == os.getuid()
                and stat.S_IMODE(details.st_mode) == 0o600
                and (details.st_dev, details.st_ino) == self._socket_id and not self._stopped.is_set())

    def activate(self):
        with self._state:
            protocol.require(self._phase == "pending" and not self._stopped.is_set())
            self._phase = "initial"

    def _accept(self):
        while not self._stopped.is_set():
            try:
                peer, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with self._state:
                if self._stopped.is_set() or len(self._clients) >= _MAX_CLIENTS:
                    peer.close()
                    continue
                thread = threading.Thread(target=self._handle, args=(peer,), daemon=True)
                self._clients[peer] = thread
                thread.start()

    def _reserve(self, raw):
        lease = self.job.lease
        until = time.monotonic() + _PARSE_SECONDS
        with self._state:
            while self._phase == "initial_receipt" and lease.active() and time.monotonic() < until:
                self._state.wait(timeout=GRANT_POLL)
        with lease.fence(), self._state:
            phase = self._phase
            protocol.require(lease.active() and phase in ("initial", "continuation") and not self._stopped.is_set())
            output = None if phase == "initial" else self._initial
            protocol.request(raw, WORKER_MODEL, output)
            if phase == "continuation":
                self.job.assert_file(protocol.PROOF_BYTES)
            body = protocol.body_for(self.job.model, output)
            self._phase = phase + "_dispatch"
            cancel = self._cancel = threading.Event()
            try:
                self._before_dispatch(phase)
                protocol.require(lease.active() and not self._stopped.is_set())
            except Exception:
                self._phase = "failed"
                cancel.set()
                self.done.set()
                raise
            return phase, body, cancel

    def _watch(self, peer, cancel, finished, deadline):
        """Watch the private relay peer without reading its receipt bytes."""
        poll = select.poll()
        poll.register(peer, select.POLLRDHUP)
        while not finished.is_set():
            if (self._stopped.is_set() or not self.job.lease.active()
                    or time.monotonic() >= deadline
                    or any(flags & PEER_CLOSED for _, flags in poll.poll(int(GRANT_POLL * 1000)))):
                cancel.set()
                return

    def _response(self, peer, phase, body, cancel):
        deadline = min(time.monotonic() + _RESPONSE_SECONDS, self.job.lease.deadline_ns / 1e9)
        finished = threading.Event()
        watcher = threading.Thread(target=self._watch, args=(peer, cancel, finished, deadline), daemon=True)
        watcher.start()
        try:
            protocol.require(self.job.lease.active() and not cancel.is_set())
            events = iter(self._responses(body, deadline=deadline, cancelled=cancel))
            try:
                terminal = protocol.validate(events, self.job.model, phase == "initial", cancel)
            finally:
                if hasattr(events, "close"):
                    events.close()
            protocol.require(time.monotonic() < deadline and not cancel.is_set())
            return terminal
        finally:
            finished.set()
            watcher.join(timeout=2 * GRANT_POLL)

    @staticmethod
    def _send(peer, request_id, response):
        protocol.require(0 < len(response) <= MAX_RESPONSE)
        peer.settimeout(_PARSE_SECONDS)
        peer.sendall(RESPONSE_HEADER.pack(request_id, len(response)) + response)

    def _confirm(self, peer, phase, terminal, request_id, size):
        receipt = RECEIPT.unpack(read_exact(peer, RECEIPT.size, time.monotonic() + _PARSE_SECONDS))
        protocol.require(receipt == (request_id, self.job.generation, size) and peer.recv(1) == b"")
        with self.job.lease.fence(), self._state:
            protocol.require(self.job.lease.active() and not self._stopped.is_set()
                             and self._phase == phase + "_receipt")
            if phase == "initial":
                self._initial = tuple(terminal["output"])
                self._phase = "continuation"
            else:
                self._phase = "complete"
                self.done.set()
            self._state.notify_all()

    def _handle(self, peer):
        phase = None
        confirmed = False
        proof = False
        request_id = secrets.token_bytes(16)
        try:
            deadline = time.monotonic() + _PARSE_SECONDS
            expected = PROOF_PREFIX + self.job.relay_proof
            proof = hmac.compare_digest(read_exact(peer, len(expected), deadline), expected)
            protocol.require(proof)
            size, = REQUEST_LENGTH.unpack(read_exact(peer, REQUEST_LENGTH.size, deadline))
            protocol.require(0 < size <= MAX_REQUEST)
            raw = read_exact(peer, size, deadline)
            phase, body, cancel = self._reserve(raw)
            terminal = self._response(peer, phase, body, cancel)
            frames = b"".join(protocol.project({**terminal, "model": WORKER_MODEL}))
            response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n"
                        + f"Content-Length: {len(frames)}\r\n\r\n".encode("ascii") + frames)
            with self.job.lease.fence(), self._state:
                protocol.require(self.job.lease.active() and not self._stopped.is_set())
                self._phase = phase + "_receipt"
            self._send(peer, request_id, response)
            self._confirm(peer, phase, terminal, request_id, len(response))
            confirmed = True
        except Exception:
            if phase is None and proof:
                with contextlib.suppress(OSError, EOFError):
                    self._send(peer, request_id, _DENIED)
                    # Keep the socket open until the relay can consume the
                    # refusal. This receipt carries no grant or phase change.
                    read_exact(peer, RECEIPT.size, time.monotonic() + 1)
        finally:
            if phase is not None and not confirmed:
                with self._state:
                    self._phase = "failed"
                    self._cancel.set()
                    self.done.set()
                    self._state.notify_all()
            with self._state:
                _shutdown(peer)
                peer.close()
                self._clients.pop(peer, None)

    def complete(self, call_id):
        with self._state:
            return self._phase == "complete" and self._initial[1]["call_id"] == call_id

    def close(self):
        self._stopped.set()
        with self._state:
            if self._cancel is not None:
                self._cancel.set()
            self._state.notify_all()
            peers = list(self._clients.items())
            for peer, _ in peers:
                _shutdown(peer)
        if self._listener is not None:
            self._listener.close()
        if self._thread is not None:
            self._thread.join(timeout=1)
        deadline = time.monotonic() + 2
        for _, thread in peers:
            thread.join(timeout=max(0, deadline - time.monotonic()))
        if any(thread.is_alive() for _, thread in peers):
            raise protocol.Refused("Managed broker shutdown unconfirmed")
        path = self.job.provider_socket
        if self._socket_id is not None and path.exists():
            details = path.lstat()
            if (details.st_dev, details.st_ino) == self._socket_id:
                path.unlink()
