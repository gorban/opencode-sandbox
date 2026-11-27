"""Host ownership and one-shot phase admission for the offline Gemini proxy."""

from contextlib import ExitStack, contextmanager, suppress
from dataclasses import dataclass, field
from enum import Enum, auto
from hashlib import sha256
import os
from pathlib import Path
import re
import select
import socket
import stat
from threading import get_ident
from time import monotonic

from .generation import FakeDestination, GenerationAttempt, GenerationBinding, project_generation
from .generation_proxy import (
    CONTROL, HARD_SECONDS, STARTUP, STARTUP_LIMIT, STARTUP_SECONDS, TURN, TURN_SECONDS,
    ProxyRefused, Signal, _FRAME, directory_identity, expect_frame, peer_credentials, remaining, send_frame,
)
from .native_peer import _alive, admit_native_peer
from .route import _send_once


_MAX_REQUEST = 8192 + 24576
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class Phase(Enum):
    NEW = auto()
    STARTING = auto()
    STARTUP = auto()
    STARTUP_WORK = auto()
    STARTUP_COMPLETE = auto()
    CLOSING_STARTUP = auto()
    BOUND = auto()
    BINDING_JOURNAL = auto()
    OPENING = auto()
    LISTENING = auto()
    ACCEPTING = auto()
    COMPLETE = auto()
    HELD = auto()


@dataclass(frozen=True, slots=True)
class HelperPlacement:
    """Supervisor-attested credentials of the exact private proxy unit."""

    pid: int
    uid: int
    cgroup: bytes = field(repr=False)
    invocation: str = field(repr=False)

    def __post_init__(self):
        if (type(self.pid) is not int or self.pid <= 0 or type(self.uid) is not int or self.uid <= 0
                or type(self.cgroup) is not bytes or not self.cgroup.startswith(b"/") or self.cgroup == b"/"
                or type(self.invocation) is not str or re.fullmatch(r"[a-f0-9]{32}", self.invocation) is None):
            raise ProxyRefused("Gemini fixture proxy placement is unavailable")


@dataclass(frozen=True, slots=True)
class ProxyLaunch:
    """Private arguments for the fixed helper, inherited from its exact owner."""

    directory: Path = field(repr=False)
    port: int = field(repr=False)
    stamp: bytes = field(repr=False)
    owner_pid: int = field(repr=False)
    startup_deadline: float
    hard_deadline: float


@dataclass(frozen=True, slots=True)
class PhaseReceipt:
    """Record observed phase outcomes without exposing local endpoints."""

    phase: Phase
    startup_eofs: int
    helper_turn_accepts: int
    owner_turn_accepts: int
    fake_writes: int
    refusal_observed: bool
    connector_retired: bool


@dataclass(frozen=True, slots=True, eq=False)
class _JournalExpectation:
    proxy_binding: GenerationBinding
    journal_binding: object
    fence: object


@dataclass(frozen=True, slots=True, eq=False)
class _JoinCapability:
    nonce: bytes = field(repr=False)

    def __reduce_ex__(self, _protocol):
        raise TypeError("Gemini fixture journal setup cannot be copied or serialized")


class _JoinInstaller:
    """Keep the private one-use capability with the original supervisor."""

    __slots__ = ("__phase", "__capability")

    def __init__(self, phase, capability):
        self.__phase = phase
        self.__capability = capability

    def __reduce_ex__(self, _protocol):
        raise TypeError("Gemini fixture journal setup cannot be copied or serialized")

    def __call__(self, journal_binding, *, proxy_binding, fence):
        self.__phase._install_journal(self.__capability, journal_binding, proxy_binding=proxy_binding, fence=fence)


class _PeerPin:
    """Pin the exact socket and original kernel peer across observer calls."""

    def __init__(self, connection, peer, placement):
        self.connection = connection
        self.peer = peer
        self.placement = placement
        self.socket_identity = os.fstat(connection.fileno())
        self.pidfd_identity = os.fstat(peer._pidfd)

    def active(self):
        return self.peer.active()

    def locally_current(self, placement):
        with self.peer._lock:
            pidfd = self.peer._pidfd
            return (placement is self.placement and pidfd is not None
                    and os.path.samestat(self.socket_identity, os.fstat(self.connection.fileno()))
                    and os.path.samestat(self.pidfd_identity, os.fstat(pidfd))
                    and peer_credentials(self.connection)[:2] == (placement.pid, placement.uid)
                    and _alive(pidfd))


def _local_cgroup(pid):
    # Keep the kernel's local view independently of the supervisor's exact
    # host cgroup reader, whose path may be relative to another namespace.
    with open(f"/proc/{pid}/cgroup", "rb") as membership:
        raw = membership.read(4097)
    if not raw or len(raw) > 4096:
        raise ProxyRefused("Gemini fixture local cgroup observation is unavailable")
    return raw


def tcp_attempt_fails(pid):
    """Read the namespace-wide counter through the verified helper's proc path."""
    with open(f"/proc/{pid}/net/snmp", "rb") as counters:
        raw = counters.read(65537)
    tcp = [line.split()[1:] for line in raw.splitlines() if line.startswith(b"Tcp: ")]
    if len(raw) > 65536 or len(tcp) != 2 or len(tcp[0]) != len(tcp[1]) or tcp[0].count(b"AttemptFails") != 1:
        raise ProxyRefused("Gemini fixture TCP observation is unavailable")
    field = tcp[1][tcp[0].index(b"AttemptFails")]
    if not field.isdigit() or len(field) > 20:
        raise ProxyRefused("Gemini fixture TCP observation is unavailable")
    return int(field)


@contextmanager
def _node(root, root_fd, name):
    # Bind through the pinned directory, and drop only the inode we created.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(f"/proc/self/fd/{root_fd}/{name}")
        identity = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        try:
            os.chmod(name, 0o600, dir_fd=root_fd, follow_symlinks=False)
            current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            if (not os.path.samestat(current, identity) or not stat.S_ISSOCK(current.st_mode)
                    or current.st_uid != os.geteuid() or stat.S_IMODE(current.st_mode) != 0o600
                    or not os.path.samestat(directory_identity(root), os.fstat(root_fd))):
                raise ProxyRefused("Gemini fixture proxy socket node differs")
            yield server
        finally:
            current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            if not os.path.samestat(current, identity):
                raise ProxyRefused("Gemini fixture proxy socket node changed")
            os.unlink(name, dir_fd=root_fd)


def _read_eof(connection, deadline, limit):
    body = bytearray()
    while True:
        connection.settimeout(remaining(deadline))
        block = connection.recv(min(4096, limit - len(body) + 1))
        if not block:
            return bytes(body)
        body.extend(block)
        if len(body) > limit:
            raise ProxyRefused("Gemini fixture proxy received extra input")


class FixturePhase:
    """Join two proxy phases using an owner-supplied durable sent-proof check.

    The proof callback takes the exact scope and owner receipt. It must check
    the same durable ACP_SENT lineage through retirement under the supplied
    revocation fence. The independent destination verifier must confirm the
    exact one-use DESTINATION_CLAIMED capability from the same durable run
    while its effect is open. Native bytes never supply either proof.
    """

    def __init__(self, directory, *, port, binding, fence, authorized, verify_helper,
                 sent_receipt_is_current=None, destination_claim_is_current=None, _join_key=None):
        joined = _join_key is not None
        valid_mode = (sent_receipt_is_current is None
                      and destination_claim_is_current is None) if joined else (
                          callable(sent_receipt_is_current) and callable(destination_claim_is_current))
        if (type(binding) is not GenerationBinding or fence is None
                or type(port) is not int or not 1024 <= port <= 65535
                or not valid_mode):
            raise ProxyRefused("Gemini fixture phase binding differs")
        self._binding = binding
        self._fence = fence
        self._authorized = authorized
        self._verify_helper = verify_helper
        self._sent_receipt_is_current = sent_receipt_is_current
        self._destination_claim_is_current = destination_claim_is_current
        self._joined = joined
        self._join_key = _join_key
        self._journal_expectation = None
        start = monotonic()
        self.launch = ProxyLaunch(directory, port, os.urandom(16), os.getpid(),
                                  start + STARTUP_SECONDS, start + HARD_SECONDS)
        self._phase = Phase.NEW
        self._resources = ExitStack()
        self._control_listener = self._startup = self._turn = self._control = None
        self._helper = self._original_helper = self._control_peer = self._accepted = None
        self._read_cgroup = self._network_fd = None
        self._baseline = self._sent_receipt = self._journal_run = None
        self._startup_eofs = self._helper_accepts = self._owner_accepts = self._fake_writes = 0
        self._refusal = self._connector_retired = False

    @classmethod
    def joined(cls, directory, *, port, binding, fence, authorized, verify_helper):
        """Create a journal-only phase and a separate supervisor setup installer."""
        from .generation_journal import _RLOCK

        if type(fence) is not _RLOCK:
            raise ProxyRefused("Gemini fixture phase binding differs")
        capability = _JoinCapability(os.urandom(32))
        # The phase can verify identity without retaining the capability.
        key = (id(capability), sha256(capability.nonce).digest())
        phase = cls(directory, port=port, binding=binding, fence=fence, authorized=authorized,
                    verify_helper=verify_helper, _join_key=key)
        return phase, _JoinInstaller(phase, capability)

    def _install_journal(self, capability, journal_binding, *, proxy_binding, fence):
        from .generation_journal import Binding

        with self._fence:
            key = self._join_key
            if (key is None or type(capability) is not _JoinCapability or id(capability) != key[0]
                    or sha256(capability.nonce).digest() != key[1]):
                raise ProxyRefused("Gemini fixture journal setup is unavailable")
            self._join_key = None
            if (os.getpid() != self.launch.owner_pid or self._phase is not Phase.STARTING
                    or proxy_binding is not self._binding or fence is not self._fence
                    or type(journal_binding) is not Binding or journal_binding.epoch != proxy_binding.epoch
                    or journal_binding.model != proxy_binding.alias):
                raise ProxyRefused("Gemini fixture journal setup differs")
            self._journal_expectation = _JournalExpectation(proxy_binding, journal_binding, fence)

    def __reduce_ex__(self, _protocol):
        raise TypeError("Gemini fixture phase ownership cannot be copied or serialized")

    def __enter__(self):
        with self._step(Phase.NEW, Phase.STARTING):
            with ExitStack() as resources:
                root = self.launch.directory
                identity = directory_identity(root)
                self._root_fd = os.open(root, _DIRECTORY)
                resources.callback(os.close, self._root_fd)
                if not os.path.samestat(identity, os.fstat(self._root_fd)):
                    raise ProxyRefused("Gemini fixture proxy directory changed")
                self._control_listener = resources.enter_context(_node(root, self._root_fd, CONTROL))
                self._control_listener.listen(1)
                self._startup = resources.enter_context(_node(root, self._root_fd, STARTUP))
                self._startup.listen(STARTUP_LIMIT)
                self._resources = resources.pop_all()
        return self

    def __exit__(self, exc_type, *_):
        try:
            if exc_type is not None or self._phase is not Phase.COMPLETE:
                self.revoke()
        finally:
            self._resources.close()

    def revoke(self):
        with self._fence:
            self._phase = Phase.HELD
            if self._journal_run is not None:
                self._journal_run.revoke()
            for sock in (self._control_listener, self._startup, self._turn, self._control, self._accepted):
                if sock is not None:
                    with suppress(OSError):
                        sock.shutdown(socket.SHUT_RDWR)
                    sock.close()

    def receipt(self):
        with self._fence:
            return PhaseReceipt(self._phase, self._startup_eofs, self._helper_accepts, self._owner_accepts,
                                self._fake_writes, self._refusal, self._connector_retired)

    @contextmanager
    def _step(self, expected, running):
        try:
            with self._fence:
                if self._phase is not expected:
                    raise ProxyRefused("Gemini fixture proxy phase is unavailable")
                self._phase = running
            yield
        except OSError:
            self.revoke()
            raise ProxyRefused("Gemini fixture proxy transport did not settle") from None
        except BaseException:
            self.revoke()
            raise

    def _check_live(self, deadline):
        remaining(deadline)
        if self._phase is Phase.HELD:
            raise ProxyRefused("Gemini fixture proxy owner retired")

    def _check_owner(self, deadline):
        self._check_live(deadline)
        if self._authorized(self._binding) is not True:
            raise ProxyRefused("Gemini fixture proxy owner retired")
        self._check_live(deadline)

    def _check_helper(self, deadline):
        self._check_owner(deadline)
        if self._verify_helper(self._helper) is not True:
            raise ProxyRefused("Gemini fixture proxy invocation changed")
        if self._control_peer is not None and not self._control_peer.active():
            raise ProxyRefused("Gemini fixture proxy control peer retired")
        self._check_owner(deadline)

    def _check_output_authority(self, deadline, peer=None):
        self._check_helper(deadline)
        if peer is not None and not peer.active():
            raise ProxyRefused("Gemini fixture turn peer retired")
        self._check_owner(deadline)

        self._check_output_pins(deadline, peer)

    def _check_output_pins(self, deadline, peer):
        # No observer callback follows these local checks. They settle the
        # pins even when the last owner/cgroup observation changed a peer.
        if self._helper is not self._original_helper:
            raise ProxyRefused("Gemini fixture proxy invocation changed")
        self._verify_network()
        if _local_cgroup(self._helper.pid) != self._local_membership:
            raise ProxyRefused("Gemini fixture proxy local cgroup changed")
        if (self._control is not self._control_peer.connection
                or not self._control_peer.locally_current(self._original_helper)):
            raise ProxyRefused("Gemini fixture proxy control peer retired")
        if peer is not None and (self._accepted is not peer.connection
                                 or not peer.locally_current(self._original_helper)):
            raise ProxyRefused("Gemini fixture turn peer retired")
        self._check_live(deadline)

    def _verify_network(self):
        if not os.path.samestat(os.fstat(self._network_fd), os.stat(self._network_path)):
            raise ProxyRefused("Gemini fixture proxy network namespace changed")

    def _audit(self, deadline):
        self._check_helper(deadline)
        self._verify_network()
        count = tcp_attempt_fails(self._helper.pid)
        self._check_helper(deadline)
        self._verify_network()
        self._check_owner(deadline)
        if self._baseline is None:
            self._baseline = count
        elif count != self._baseline:
            self._refusal = True
            raise ProxyRefused("Gemini fixture proxy observed a TCP attempt failure")

    def _send(self, signal, deadline):
        check = self._check_sent if signal is Signal.OPEN_TURN else self._check_output_authority
        send_frame(self._control, self.launch.stamp, signal, deadline, check=lambda: check(deadline))

    def _expect(self, signal, deadline, *, count=0):
        expect_frame(self._control, self.launch.stamp, signal, deadline, count=count)
        self._check_helper(deadline)

    def _accept(self, listener, deadline):
        while True:
            self._check_owner(deadline)
            listener.settimeout(min(.1, remaining(deadline)))
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            return connection

    @contextmanager
    def _owned_connection(self, listener, deadline, *, turn=False):
        with self._accept(listener, deadline) as connection:
            with self._fence:
                if turn:
                    listener.close()
                    self._owner_accepts = 1
                self._check_owner(deadline)
                self._accepted = connection
            try:
                yield connection
            finally:
                with self._fence:
                    self._accepted = None

    @contextmanager
    def _peer(self, connection, deadline):
        self._check_helper(deadline)
        placement = self._original_helper
        if self._helper is not placement or peer_credentials(connection)[:2] != (placement.pid, placement.uid):
            raise ProxyRefused("Gemini fixture proxy peer identity differs")
        with admit_native_peer(connection, expected_group=placement.cgroup, read_cgroup=self._read_cgroup) as peer:
            yield _PeerPin(connection, peer, placement)

    def attach(self, helper, *, read_cgroup):
        """Authenticate exactly one helper before sending the first command."""
        deadline = self.launch.startup_deadline
        with self._step(Phase.STARTING, Phase.STARTUP_WORK):
            if type(helper) is not HelperPlacement:
                raise ProxyRefused("Gemini fixture proxy helper differs")
            self._helper = self._original_helper = helper
            self._read_cgroup = read_cgroup
            control = self._resources.enter_context(self._accept(self._control_listener, deadline))
            self._control_listener.close()
            self._control = control
            self._control_peer = self._resources.enter_context(self._peer(control, deadline))
            with self._fence:
                self._check_helper(deadline)
                self._network_path = f"/proc/{helper.pid}/ns/net"
                self._network_fd = os.open(self._network_path, os.O_RDONLY | os.O_CLOEXEC)
                self._resources.callback(os.close, self._network_fd)
                self._local_membership = _local_cgroup(helper.pid)
                self._audit(deadline)
                self._send(Signal.START, deadline)
            self._expect(Signal.STARTED, deadline)
            with self._fence:
                self._audit(deadline)
                self._phase = Phase.STARTUP

    def service_startup(self, handler):
        """Accept each exact startup connection, and independently verify its EOF."""
        deadline = self.launch.startup_deadline
        with self._step(Phase.STARTUP, Phase.STARTUP_WORK):
            for _ in range(STARTUP_LIMIT):
                with self._owned_connection(self._startup, deadline) as connection, self._peer(connection, deadline) as peer:
                    with self._fence:
                        self._check_output_authority(deadline, peer)
                    handler(connection, deadline)
                    connection.shutdown(socket.SHUT_WR)
                    _read_eof(connection, deadline, 0)
                    if not peer.active():
                        raise ProxyRefused("Gemini fixture startup peer retired early")
                    with self._fence:
                        self._check_helper(deadline)
                        self._startup_eofs += 1
            with self._fence:
                self._audit(deadline)
                self._phase = Phase.STARTUP_COMPLETE

    def prepare_turn(self):
        """Close all startup admission before binding a non-listening turn node."""
        deadline = self.launch.startup_deadline
        with self._step(Phase.STARTUP_COMPLETE, Phase.CLOSING_STARTUP):
            with self._fence:
                if self._joined and (self._journal_expectation is None
                                     or self._journal_expectation.journal_binding.launch
                                     != self._original_helper.invocation):
                    raise ProxyRefused("Gemini fixture journal setup differs")
                self._audit(deadline)
                self._startup.close()
                self._audit(deadline)
                self._send(Signal.CLOSE_STARTUP, deadline)
            self._expect(Signal.STARTUP_CLOSED, deadline)
            with self._fence:
                self._audit(deadline)
            self._expect(Signal.TURN_BOUND, deadline, count=self._startup_eofs)
            with self._fence:
                self._audit(deadline)
                self._turn = self._resources.enter_context(_node(self.launch.directory, self._root_fd, TURN))
                self._audit(deadline)
                self._phase = Phase.BOUND

    def _check_sent(self, deadline, peer=None):
        self._audit(deadline)
        if (self._sent_receipt is None
                or self._sent_receipt_is_current(self._binding, self._sent_receipt) is not True):
            raise ProxyRefused("Gemini fixture durable ACP sent receipt differs")
        self._check_output_authority(deadline, peer)

    def _check_destination_claim(self, capability, deadline, peer):
        self._check_sent(deadline, peer)
        if (capability is None
                or self._destination_claim_is_current(self._binding, self._sent_receipt, capability) is not True):
            raise ProxyRefused("Gemini fixture durable destination claim differs")
        self._check_output_authority(deadline, peer)

    def bind_journal(self, run, sent_receipt, *, proxy_binding, journal_binding):
        """Match the first durable receipt to the supervisor's pinned expectation."""
        from .generation_journal import Phase as JournalPhase, _Run

        try:
            with self._fence:
                expected = self._journal_expectation
                if (self._phase is not Phase.BOUND or expected is None or self._journal_run is not None
                        or proxy_binding is not expected.proxy_binding or expected.proxy_binding is not self._binding
                        or expected.fence is not self._fence or journal_binding is not expected.journal_binding
                        or type(run) is not _Run or run._control.binding is not expected.journal_binding
                        or run._owner_fence() is not expected.fence
                        or run._files.anchor.enrollment.generation != expected.journal_binding.generation
                        or expected.journal_binding.launch != self._original_helper.invocation
                        or type(run._control.deadline) not in (int, float)
                        or not 0 < run._control.deadline < float("inf")):
                    raise ProxyRefused("Gemini fixture journal run differs")
                self._phase = Phase.BINDING_JOURNAL
                run.verify_acp_sent(sent_receipt)
                self._check_owner(run._control.deadline)
                run._verify_local_acp_sent(sent_receipt, phase=JournalPhase.ACP_SENT)
                self._check_output_pins(run._control.deadline, None)
                self._sent_receipt = sent_receipt
                self._journal_run = run
                self._phase = Phase.BOUND
        except BaseException:
            self.revoke()
            raise

    def _activate_journal(self, sent_receipt, run):
        from .generation_journal import Phase as JournalPhase

        with self._fence:
            if run is not self._journal_run or sent_receipt is not self._sent_receipt:
                raise ProxyRefused("Gemini fixture journal run or ACP sent receipt differs")
            deadline = min(self._deadline, run._control.deadline)
            self._deadline = deadline
        self._observe_turn_authority(deadline)
        packet = _FRAME.pack(self.launch.stamp, Signal.OPEN_TURN, 0)
        try:
            writable = select.select([], [self._control], [], remaining(deadline))[1]
        except ValueError:
            raise ProxyRefused("Gemini fixture journal arm is unavailable") from None
        if not writable:
            raise ProxyRefused("Gemini fixture journal arm expired")
        with self._fence:
            self._check_journal_turn(run, deadline, journal_phase=JournalPhase.ACP_SENT)
            self._turn.listen(1)
            self._check_journal_turn(run, deadline, journal_phase=JournalPhase.ACP_SENT)
            if _send_once(self._control, packet) != len(packet):
                raise ProxyRefused("Gemini fixture proxy control write is unconfirmed")
        self._expect(Signal.TURN_LISTENING, deadline)
        self._observe_turn_authority(deadline)
        with self._fence:
            self._check_journal_turn(run, deadline, journal_phase=JournalPhase.ACP_SENT)
            self._phase = Phase.LISTENING

    def activate(self, sent_receipt, *, journal_run=None):
        """Listen only after the current exact durable ACP_SENT is visible to the owner."""
        with self._step(Phase.BOUND, Phase.OPENING):
            with self._fence:
                self._deadline = min(self.launch.hard_deadline, monotonic() + TURN_SECONDS)
            if self._joined:
                if journal_run is None or self._journal_run is None:
                    raise ProxyRefused("Gemini fixture journal run differs")
                self._activate_journal(sent_receipt, journal_run)
                return
            if journal_run is not None:
                raise ProxyRefused("Gemini fixture journal run differs")
            with self._fence:
                self._sent_receipt = sent_receipt
                self._check_sent(self._deadline)
                self._turn.listen(1)
                self._send(Signal.OPEN_TURN, self._deadline)
            self._expect(Signal.TURN_LISTENING, self._deadline)
            with self._fence:
                self._check_sent(self._deadline)
                self._phase = Phase.LISTENING

    @contextmanager
    def _turn_request(self, deadline):
        with self._owned_connection(self._turn, deadline, turn=True) as connection:
            with self._peer(connection, deadline) as peer:
                yield connection, peer, _read_eof(connection, deadline, _MAX_REQUEST)

    def _send_turn_reply(self, connection, reply, deadline, *, check, observe=None):
        packet = (b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n"
                  b"Content-Length: " + str(len(reply)).encode("ascii") + b"\r\n\r\n" + reply)
        try:
            writable = select.select([], [connection], [], remaining(deadline))[1]
        except ValueError:
            raise ProxyRefused("Gemini fixture native reply is unavailable") from None
        if not writable:
            raise ProxyRefused("Gemini fixture native reply expired")
        if observe is not None:
            observe()
        with self._fence:
            check()
            if _send_once(connection, packet) != len(packet):
                raise ProxyRefused("Gemini fixture native reply is unconfirmed")
            connection.shutdown(socket.SHUT_WR)

    def _retire_turn(self, deadline, *, check, observe=None):
        self._expect(Signal.TURN_RETIRED, deadline, count=1)
        _read_eof(self._control, deadline, 0)
        if observe is not None:
            observe()
        with self._fence:
            check()
            self._helper_accepts = 1
            self._connector_retired = True
            self._control.shutdown(socket.SHUT_WR)
            self._phase = Phase.COMPLETE

    def _observe_turn_authority(self, deadline, peer=None):
        self._audit(deadline)
        if peer is not None and not peer.active():
            raise ProxyRefused("Gemini fixture turn peer retired")

    def _check_journal_turn(self, run, deadline, peer=None, *, journal_phase):
        run.verify_acp_sent(self._sent_receipt)
        self._check_owner(deadline)
        run._verify_local_acp_sent(self._sent_receipt, phase=journal_phase)
        self._check_output_pins(deadline, peer)

    def _journal_turn_reply(self, destination, run, request, deadline, peer):
        from .generation_journal import Operation, Phase as JournalPhase, SettlementEvidence, WriteEvidence

        durable_phase = JournalPhase.ACP_SENT

        def check():
            self._check_journal_turn(run, deadline, peer, journal_phase=durable_phase)

        def current_scope(binding):
            if binding is not self._binding:
                return False
            with self._fence:
                check()
            return True

        attempt = GenerationAttempt(self._binding, destination, authorized=current_scope)
        try:
            self._observe_turn_authority(deadline, peer)
            prepared = attempt.prepare(self._binding, request, end_of_input=True, deadline=deadline)
            fake_write = None

            def write_effect(proof):
                nonlocal fake_write

                def admit():
                    run.verify_acp_sent(self._sent_receipt)
                    run.verify_in_flight(proof, Operation.DESTINATION)
                    self._check_owner(deadline)
                    run._verify_local_acp_sent(self._sent_receipt, phase=durable_phase)
                    run._verify_local_destination(proof)
                    self._check_output_pins(deadline, peer)
                    return True

                try:
                    fake_write = attempt.write_prepared(prepared, admit=admit)
                finally:
                    self._fake_writes = attempt.receipt().complete_requests
                return WriteEvidence(destination, fake_write.byte_count, fake_write.packet_digest.hex())

            with self._fence:
                check()
                claim = run.issue(Operation.DESTINATION)
                durable_phase = JournalPhase.DESTINATION_CLAIMED
                pending = run.write_once(claim, write_effect, target=destination, data=prepared._packet)

            completion = attempt.observe(fake_write)
            self._observe_turn_authority(deadline, peer)
            with self._fence:
                check()
                reply = attempt.settle(fake_write, completion)
                observed = SettlementEvidence(pending, destination, fake_write.byte_count,
                                              fake_write.packet_digest.hex())
                run.settle(pending, observed)
                return reply
        except BaseException:
            attempt.revoke()
            raise

    def serve_journal_turn(self, destination, run):
        """Serve the private R2 fixture from the exact journal run that armed it."""
        from .generation_journal import Phase as JournalPhase

        with self._step(Phase.LISTENING, Phase.ACCEPTING):
            if type(destination) is not FakeDestination:
                raise ProxyRefused("Gemini fixture destination is unavailable")
            if not self._joined or run is None or run is not self._journal_run:
                raise ProxyRefused("Gemini fixture journal run differs")
            deadline = self._deadline
            with self._fence:
                self._check_journal_turn(run, deadline, journal_phase=JournalPhase.ACP_SENT)
            with self._turn_request(deadline) as (connection, peer, request):
                reply = self._journal_turn_reply(destination, run, request, deadline, peer)
                self._send_turn_reply(
                    connection, reply, deadline,
                    check=lambda: self._check_journal_turn(run, deadline, peer, journal_phase=JournalPhase.DESTINATION_SETTLED),
                    observe=lambda: self._observe_turn_authority(deadline, peer),
                )
            self._retire_turn(
                deadline,
                check=lambda: self._check_journal_turn(run, deadline, journal_phase=JournalPhase.DESTINATION_SETTLED),
                observe=lambda: self._observe_turn_authority(deadline),
            )
        return self.receipt()

    def serve_turn(self, destination, *, claim_destination=None):
        """Accept one connection and require the owner to consume an exact destination claim.

        The claim driver receives the binding, sent receipt, and effect. The
        driver passes the exact durable capability into the effect and returns
        its result only after durable settlement.
        """
        with self._step(Phase.LISTENING, Phase.ACCEPTING):
            if type(destination) is not FakeDestination:
                raise ProxyRefused("Gemini fixture destination is unavailable")
            if self._joined or not callable(claim_destination):
                raise ProxyRefused("Gemini fixture durable destination claim is unavailable")
            deadline = self._deadline
            with self._turn_request(deadline) as (connection, peer, request):
                # Reject malformed native input before asking the owner to
                # make a durable claim. The attempt reprojects the exact
                # immutable packet at the fake destination boundary.
                project_generation(request, end_of_input=True)
                reply = capability = None
                entered = False
                live_effect = True
                effect_owner = get_ident()
                def current_scope(binding):
                    if binding is not self._binding:
                        return False
                    self._check_destination_claim(capability, deadline, peer)
                    return True
                attempt = GenerationAttempt(self._binding, destination, authorized=current_scope)
                def dispatch(claim=None):
                    nonlocal entered, reply, capability
                    # Reject another thread without waiting on the owner's
                    # fence, which the synchronous claim driver still holds.
                    if get_ident() != effect_owner:
                        raise ProxyRefused("Gemini fixture destination effect has a different owner")
                    with self._fence:
                        if entered or not live_effect:
                            self.revoke()
                            raise ProxyRefused("Gemini fixture destination effect was spent")
                        entered = True
                        capability = claim
                        self._check_destination_claim(capability, deadline, peer)
                        try:
                            reply = attempt.run(self._binding, request, end_of_input=True)
                        finally:
                            self._fake_writes = attempt.receipt().complete_requests
                        self._check_sent(deadline, peer)
                        return reply
                try:
                    with self._fence:
                        self._check_sent(deadline, peer)
                        result = claim_destination(self._binding, self._sent_receipt, dispatch)
                        if not entered or reply is None or result is not reply or self._fake_writes != 1:
                            raise ProxyRefused("Gemini fixture destination effect is unconfirmed")
                        self._check_sent(deadline, peer)
                finally:
                    live_effect = False
                self._send_turn_reply(connection, reply, deadline, check=lambda: self._check_sent(deadline, peer))
            self._retire_turn(deadline, check=lambda: self._check_sent(deadline))
        return self.receipt()
