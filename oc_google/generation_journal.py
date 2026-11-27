"""One durable generation hold for a sealed synthetic registration fixture."""

from collections.abc import Callable
from contextlib import ExitStack, contextmanager, suppress
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from hashlib import sha256
import json
import os
import secrets
from threading import RLock, get_ident
from time import monotonic

from . import registration as reg
from .generation import MODEL_ALIAS


_STATE = "generation.json"
_AUTHORITY = "generation.authority"
_LATCH = "generation.latch"
_TEMP = ".generation-save-"
_PARKED = ".generation-held-"
_SECRET = b"synthetic D1 fixture profile bytes\n"
_POLICY = sha256(b"synthetic durable generation fixture: fixed Flash text turn v1").hexdigest()
_DIRTY = b"!"
_HELD = b"H"
_RLOCK = type(RLock())
_FIXTURE_DIR = "generation-fixtures"
_FIXTURE_LABEL = "generation-fixture"
_FIXTURE_BUILD = sha256(b"oc-sandbox synthetic durable generation fixture v1").hexdigest()
_MAX_WRITE_BYTES = 32768


class GenerationHeld(reg.RegistrationUnavailable):
    """The sealed fixture cannot safely acquire or advance generation authority."""

    def __init__(self):
        super().__init__("Google synthetic generation is held or unavailable")


class Phase(StrEnum):
    UNSTARTED = "unstarted"
    LAUNCH_HELD = "launch-held"
    ACP_CLAIMED = "acp-claimed"
    ACP_SENT = "acp-sent"
    DESTINATION_CLAIMED = "destination-claimed"
    DESTINATION_SETTLED = "destination-settled"
    DELIVERY_CLAIMED = "delivery-claimed"
    SETTLED = "settled"


class Operation(StrEnum):
    ACP = "acp"
    DESTINATION = "destination"
    DELIVERY = "delivery"


_STEPS = {
    Operation.ACP: (Phase.LAUNCH_HELD, Phase.ACP_CLAIMED, Phase.ACP_SENT),
    Operation.DESTINATION: (Phase.ACP_SENT, Phase.DESTINATION_CLAIMED, Phase.DESTINATION_SETTLED),
    Operation.DELIVERY: (Phase.DESTINATION_SETTLED, Phase.DELIVERY_CLAIMED, Phase.SETTLED),
}
_SENT_PHASES = (Phase.ACP_SENT, Phase.DESTINATION_CLAIMED, Phase.DESTINATION_SETTLED)


def _digest(data):
    return sha256(data).hexdigest()


def _json(fields):
    return json.dumps(fields, separators=(",", ":"), sort_keys=True).encode("ascii") + b"\n"


@dataclass(frozen=True, slots=True)
class Binding:
    generation: str
    profile_digest: str
    credential_digest: str
    epoch: int
    model: str
    policy_digest: str
    launch: str


@dataclass(frozen=True, slots=True)
class FixtureAnchor:
    """External receipt and original bootstrap FD retained by the fixture supervisor."""

    enrollment: reg.Enrollment
    lock: reg.FileIdentity
    directory: reg.FileIdentity
    registration: reg.FileIdentity
    registration_digest: str
    credential: reg.FileIdentity
    credential_digest: str
    authority: reg.FileIdentity
    authority_digest: str
    latch: reg.FileIdentity
    bootstrap: reg.FileIdentity
    bootstrap_fd: int
    bootstrap_ctime_ns: int

    def binding(self, *, epoch, launch):
        if type(epoch) is not int or not 0 < epoch < 2**63 or not reg._hex(launch, 32):
            raise GenerationHeld()
        profile = _digest(_json(asdict(self.enrollment.profile_identity)))
        return Binding(self.enrollment.generation, profile, self.credential_digest, epoch, MODEL_ALIAS, _POLICY, launch)


@dataclass(frozen=True, slots=True, eq=False)
class Capability:
    operation: Operation


@dataclass(frozen=True, slots=True, eq=False)
class _Observation:
    capability: Capability


@dataclass(frozen=True, slots=True, eq=False)
class WriteEvidence:
    """Result of one bounded write to the exact private target."""

    target: object
    byte_count: int
    packet_sha256: str


@dataclass(frozen=True, slots=True, eq=False)
class WriteReceipt:
    """A pending write, still requiring independent settlement observations."""

    operation: Operation
    target: object
    byte_count: int
    packet_sha256: str
    _origin: object = field(default=None, repr=False)


@dataclass(frozen=True, slots=True, eq=False)
class SettlementEvidence:
    """Trusted adapter projection of exact observations made outside the fence."""

    write: WriteReceipt
    target: object
    byte_count: int
    packet_sha256: str
    closure: object | None = None


@dataclass(frozen=True, slots=True, eq=False)
class AcpSentReceipt:
    """The original journal-owned proof of durable ACP_SENT."""

    write: WriteReceipt


@dataclass(frozen=True, slots=True, eq=False)
class _InFlight:
    operation: Operation
    pid: int
    thread: int
    target: object
    byte_count: int
    packet_sha256: str
    settlement_guard: object | None


def _matches_write(target, count, digest, evidence):
    return (evidence.target is target and type(evidence.byte_count) is int and evidence.byte_count == count
            and type(evidence.packet_sha256) is str and evidence.packet_sha256 == digest)


def _read(directory, leaf, fd):
    before = os.fstat(fd)
    if not reg._private_file(before) or not 0 <= before.st_size <= reg._LIMIT:
        raise GenerationHeld()
    data = os.pread(fd, reg._LIMIT + 1, 0)
    after = os.fstat(fd)
    entry = os.stat(leaf, dir_fd=directory, follow_symlinks=False)
    if (not reg._private_file(entry) or not os.path.samestat(entry, after)
            or (len(data), before.st_ctime_ns, before.st_mtime_ns) != (entry.st_size, entry.st_ctime_ns, entry.st_mtime_ns)
            or len(data) != before.st_size):
        raise GenerationHeld()
    return reg.FileIdentity.of(after), data


def _open(pins, directory, leaf, *, writable=False):
    fd = os.open(leaf, (os.O_RDWR if writable else os.O_RDONLY) | reg._FILE, dir_fd=directory)
    pins.callback(os.close, fd)
    return fd


def _read_leaf(directory, leaf):
    with ExitStack() as pins:
        return _read(directory, leaf, _open(pins, directory, leaf))


def _record(enrollment, phase, binding=None):
    return _json({"version": 1, "registration": enrollment.registration_id, "generation": enrollment.generation,
                  "phase": phase.value, "binding": None if binding is None else asdict(binding)})


def _check_metadata(slot, record, fd, profile, key_fd):
    reg._verify_binding(slot, record, profile, key_fd)
    if (record.phase is not reg.Phase.COLD_RETIREMENT_OBSERVED or record.metadata_pending
            or record.enrollment_metadata_spent != len(reg._ENROLLMENT_ROUTES)
            or record.cold_metadata_spent != len(reg._COLD_ROUTES)
            or os.pread(slot.lock, 1, 0)):
        raise GenerationHeld()
    identity, body = _read(slot.directory.fd, reg._RECORD, fd)
    if reg._decode(body) != record:
        raise GenerationHeld()
    return identity, _digest(body)


class FixtureRegistrationJournal(reg.RegistrationJournal):
    """Route fixture slots outside the normal registration and profile namespace."""

    def __init__(self):
        super().__init__(_FIXTURE_LABEL)

    def _registration_root(self, pins, create):
        root = reg._state_root(pins, create)
        directory, _ = reg._child(pins, root, _FIXTURE_DIR, create=create, private=True)
        return directory

    def status(self):
        raise GenerationHeld()

    def begin(self, build_digest):
        raise GenerationHeld()

    def _exact(self, enrollment, phase, *, authorized=None):
        raise GenerationHeld()

    def _exact_fixture(self, enrollment, *, authorized=None):
        return super()._exact(enrollment, reg.Phase.COLD_RETIREMENT_OBSERVED, authorized=authorized)


class GenerationJournal:
    """Fixture-only run and writer admission over the existing registration flock."""

    def __init__(self, journal, anchor):
        if (type(journal) is not FixtureRegistrationJournal or type(anchor) is not FixtureAnchor
                or type(anchor.enrollment) is not reg.Enrollment
                or journal.label != anchor.enrollment.label or anchor.enrollment.build_digest != _FIXTURE_BUILD
                or anchor.credential_digest != _digest(_SECRET)):
            raise GenerationHeld()
        self._journal = journal
        self._anchor = anchor

    @contextmanager
    def _fresh(self, *, authorized=None):
        try:
            with self._journal._exact_fixture(self._anchor.enrollment, authorized=authorized) as view:
                yield _Files(self._anchor, *view)
        except (OSError, reg.RegistrationUnavailable):
            raise GenerationHeld() from None

    def status(self):
        """Expose freshness only after replay-resistant verification of the anchor."""
        with self._fresh():
            return Phase.UNSTARTED

    def fixture_writer(self, marker):
        """Exercise the same guard on an otherwise valid synthetic state mutation."""
        if type(marker) is not int or not 0 <= marker < 10000:
            raise GenerationHeld()
        with self._fresh() as files:
            reg._write_private(files.directory, f"fixture-writer-{marker}", b"synthetic writer reached the slot\n")

    @contextmanager
    def launch(self, binding, *, fence, authorized, deadline=None):
        if (type(binding) is not Binding or type(fence) is not _RLOCK or not callable(authorized)
                or (deadline is not None and (type(deadline) not in (float, int)
                                              or not monotonic() < deadline < float("inf")))
                or any(type(value) is not str for value in (
                    binding.generation, binding.profile_digest, binding.credential_digest, binding.model,
                    binding.policy_digest, binding.launch,
                ))
                or binding != self._anchor.binding(epoch=binding.epoch, launch=binding.launch)):
            raise GenerationHeld()

        def current():
            return authorized(binding) is True and (deadline is None or monotonic() < deadline)

        with self._fresh(authorized=current) as files:
            control = _LeaseControl(binding, fence, authorized, deadline, os.getpid())
            files._authority.control = control
            run = _Run(files, control)
            try:
                run._launch()
                yield run
            finally:
                run.revoke()


@dataclass(frozen=True, slots=True, eq=False)
class _LeaseControl:
    """The immutable owner, synchronization, and mode of one exact lease."""

    binding: Binding
    fence: object
    authorized: Callable[[Binding], bool]
    deadline: float | None
    pid: int


@dataclass(slots=True)
class _LeaseAuthority:
    """Mutable state of one held registration lease, shared by every run view."""

    phase: Phase = Phase.UNSTARTED
    control: _LeaseControl | None = None
    revoked: bool = False
    busy: bool = False
    checking: bool = False
    capability: Capability | None = None
    in_flight: _InFlight | None = None
    flight_checked: bool = False
    pending: WriteReceipt | None = None
    pending_guard: Callable[[SettlementEvidence], None] | None = None
    sent: AcpSentReceipt | None = None


class _Files:
    """Pin the registration, immutable authority, and independent save latch."""

    def __init__(self, anchor, slot, record, profile, pins, key_fd):
        self._authority = _LeaseAuthority()
        self.anchor, self.slot, self.record, self.profile, self.key_fd = anchor, slot, record, profile, key_fd
        self.directory = slot.directory.fd
        self.registration_fd = _open(pins, self.directory, reg._RECORD)
        self.authority_fd = _open(pins, self.directory, _AUTHORITY)
        self.latch_fd = _open(pins, self.directory, _LATCH, writable=True)
        self.current = (anchor.bootstrap, _record(anchor.enrollment, Phase.UNSTARTED))
        self.latch_value = b""
        # The fixture supervisor keeps this original inode open across child
        # restarts. A recycled pathname/device/inode tuple cannot substitute it.
        if (_read(self.directory, _STATE, anchor.bootstrap_fd) != self.current
                or os.fstat(anchor.bootstrap_fd).st_ctime_ns != anchor.bootstrap_ctime_ns
                or any(name.startswith(_TEMP) for name in os.listdir(self.directory))):
            raise GenerationHeld()
        self.verify()

    def verify(self):
        anchor, slot = self.anchor, self.slot
        if (reg.FileIdentity.of(os.fstat(slot.lock)) != anchor.lock
                or reg.FileIdentity.of(os.fstat(self.directory)) != anchor.directory
                or self.record.credential_identity != anchor.credential
                or _check_metadata(slot, self.record, self.registration_fd, self.profile, self.key_fd)
                != (anchor.registration, anchor.registration_digest)
                or _digest(reg._credential_bytes(self.profile, self.record)) != anchor.credential_digest):
            raise GenerationHeld()
        authority, body = _read(self.directory, _AUTHORITY, self.authority_fd)
        if ((authority, _digest(body)) != (anchor.authority, anchor.authority_digest)
                or _read(self.directory, _LATCH, self.latch_fd) != (anchor.latch, self.latch_value)
                or _read_leaf(self.directory, _STATE) != self.current
                or any(name.startswith(_PARKED) for name in os.listdir(self.directory))):
            raise GenerationHeld()

    def _latch(self, value):
        info = os.fstat(self.latch_fd)
        entry = os.stat(_LATCH, dir_fd=self.directory, follow_symlinks=False)
        if (not reg._private_file(entry) or not os.path.samestat(entry, info)
                or reg.FileIdentity.of(info) != self.anchor.latch):
            raise GenerationHeld()
        if os.pwrite(self.latch_fd, value, 0) != len(value):
            raise GenerationHeld()
        os.fsync(self.latch_fd)
        self.latch_value = value

    def _hold_after_failed_save(self):
        try:
            self._latch(_DIRTY)
        except (OSError, GenerationHeld):
            # Leave the separately pinned lease inode untouched if the latch cannot sync.
            identity, _ = _read(self.directory, _LATCH, self.latch_fd)
            if identity != self.anchor.latch:
                raise GenerationHeld()
            os.rename(_LATCH, _PARKED + secrets.token_hex(16), src_dir_fd=self.directory, dst_dir_fd=self.directory)
            os.fsync(self.directory)

    def _retain_after_error(self, error):
        try:
            self._hold_after_failed_save()
        except (OSError, GenerationHeld):
            error.add_note("Google synthetic generation latch still requires inspection")

    def save(self, phase, binding, check):
        check()
        temporary = _TEMP + secrets.token_hex(16)
        try:
            self._latch(_DIRTY)
            body = _record(self.anchor.enrollment, phase, binding)
            reg._write_private(self.directory, temporary, body)
            candidate = _read_leaf(self.directory, temporary)
            if candidate[1] != body:
                raise GenerationHeld()
            check()
            os.replace(temporary, _STATE, src_dir_fd=self.directory, dst_dir_fd=self.directory)
            self.current = candidate
            os.fsync(self.directory)
            check()
            self._latch(_HELD)
            check()
        except BaseException as error:
            self._retain_after_error(error)
            raise
        finally:
            with suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=self.directory)


@dataclass(frozen=True, slots=True)
class _Run:
    _files: _Files
    _control: _LeaseControl

    def _owner_fence(self):
        if (type(self._files) is not _Files or type(self._control) is not _LeaseControl
                or self._files._authority.control is not self._control or os.getpid() != self._control.pid):
            raise GenerationHeld()
        return self._control.fence

    def revoke(self):
        with self._owner_fence():
            authority = self._files._authority
            authority.revoked = True
            authority.capability = None
            authority.in_flight = authority.pending = authority.sent = None
            authority.pending_guard = None
            authority.flight_checked = False

    def _check(self, local=None):
        self._owner_fence()
        authority = self._files._authority
        deadline = self._control.deadline
        if authority.revoked or authority.checking or (deadline is not None and monotonic() >= deadline):
            raise GenerationHeld()
        authority.checking = True
        try:
            self._files.verify()
            if self._control.authorized(self._control.binding) is not True or authority.revoked:
                raise GenerationHeld()
            self._files.verify()
            if local is not None:
                local()
            if authority.revoked or (deadline is not None and monotonic() >= deadline):
                raise GenerationHeld()
        finally:
            authority.checking = False

    @contextmanager
    def _transition(self):
        self._owner_fence()
        authority = self._files._authority
        if authority.busy or authority.revoked or authority.checking:
            raise GenerationHeld()
        authority.busy = True
        try:
            self._check()
            yield
        except BaseException:
            self.revoke()
            raise
        finally:
            authority.busy = False

    def _save(self, phase, *, local=None):
        def check():
            self._check(local)

        self._files.save(phase, self._control.binding, check)
        try:
            check()
        except BaseException as error:
            if local is not None:
                self._files._retain_after_error(error)
            raise
        self._files._authority.phase = phase

    def _launch(self):
        with self._owner_fence(), self._transition():
            self._save(Phase.LAUNCH_HELD)

    def issue(self, operation):
        """Persist a claim before issuing its exact one-use capability."""
        with self._owner_fence():
            authority = self._files._authority
            if (type(operation) is not Operation or authority.phase != _STEPS[operation][0]
                    or authority.capability is not None):
                raise GenerationHeld()
            with self._transition():
                self._save(_STEPS[operation][1])
                authority.capability = Capability(operation)
                return authority.capability

    def consume(self, capability, effect):
        """Spend before the bounded synthetic effect and settle only its exact observation."""
        with self._owner_fence():
            authority = self._files._authority
            if (self._control.deadline is not None or type(capability) is not Capability
                    or capability is not authority.capability or not callable(effect)):
                raise GenerationHeld()
            with self._transition():
                authority.capability = None
                self._effect(capability, effect)
                self._save(_STEPS[capability.operation][2])

    def _check_phase(self, phase):
        self._check()
        if (self._files._authority.phase is not phase
                or self._files.current[1] != _record(self._files.anchor.enrollment, phase, self._control.binding)):
            raise GenerationHeld()

    def write_once(self, capability, effect, *, target, data, settlement_guard=None):
        """Spend an issued capability before the adapter's bounded synchronous write."""
        with self._owner_fence():
            authority = self._files._authority
            if (self._control.deadline is None or type(capability) is not Capability or capability is not authority.capability
                    or not callable(effect) or authority.pending is not None):
                raise GenerationHeld()
            with self._transition():
                authority.capability = None
                if target is None or type(data) is not bytes or not 0 < len(data) <= _MAX_WRITE_BYTES:
                    raise GenerationHeld()
                operation = capability.operation
                if settlement_guard is not None and (operation is not Operation.DELIVERY or not callable(settlement_guard)):
                    raise GenerationHeld()
                self._check_phase(_STEPS[operation][1])
                digest = _digest(data)
                proof = _InFlight(operation, self._control.pid, get_ident(), target, len(data), digest, settlement_guard)
                authority.in_flight = proof
                authority.pending_guard = settlement_guard
                try:
                    evidence = effect(proof)
                    checked = authority.flight_checked
                finally:
                    authority.in_flight = None
                    authority.flight_checked = False
                self._check_phase(_STEPS[operation][1])
                if type(evidence) is not WriteEvidence or not checked or not _matches_write(target, len(data), digest, evidence):
                    raise GenerationHeld()
                authority.pending = WriteReceipt(operation, target, len(data), digest, self._control)
                return authority.pending

    def verify_in_flight(self, proof, operation, *, target=None, data=None, settlement_guard=None):
        """Verify the exact write claim synchronously just before its effect."""
        if (type(proof) is not _InFlight or proof.pid != os.getpid() or proof.thread != get_ident()
                or proof.operation is not operation):
            raise GenerationHeld()
        with self._owner_fence():
            authority = self._files._authority
            if proof is not authority.in_flight or not authority.busy or authority.checking:
                raise GenerationHeld()
            if target is not None or data is not None:
                if (target is not proof.target or type(data) is not bytes or len(data) != proof.byte_count
                        or _digest(data) != proof.packet_sha256):
                    raise GenerationHeld()
            if settlement_guard is not None and (settlement_guard is not proof.settlement_guard
                                                 or settlement_guard is not authority.pending_guard):
                raise GenerationHeld()
            try:
                self._check_phase(_STEPS[operation][1])
            except BaseException:
                self.revoke()
                raise
            authority.flight_checked = True

    def settle(self, receipt, evidence):
        """Settle once from immutable evidence already verified by the adapter."""
        with self._owner_fence():
            if self._control.deadline is None:
                raise GenerationHeld()
            with self._transition():
                authority = self._files._authority
                pending, authority.pending = authority.pending, None
                guard, authority.pending_guard = authority.pending_guard, None
                if (type(receipt) is not WriteReceipt or receipt is not pending or type(evidence) is not SettlementEvidence
                        or evidence.write is not receipt
                        or not _matches_write(receipt.target, receipt.byte_count, receipt.packet_sha256, evidence)
                        or (guard is None and evidence.closure is not None)):
                    raise GenerationHeld()
                operation = receipt.operation
                self._check_phase(_STEPS[operation][1])
                self._save(_STEPS[operation][2], local=(lambda: guard(evidence)) if guard is not None else None)
                if operation is Operation.ACP:
                    authority.sent = AcpSentReceipt(receipt)

    def acp_sent(self):
        """Return the original ACP-sent evidence while its delivery phase permits it."""
        with self._owner_fence():
            receipt = self._files._authority.sent
            self.verify_acp_sent(receipt)
            return receipt

    def verify_acp_sent(self, receipt):
        with self._owner_fence():
            authority = self._files._authority
            if (type(receipt) is not AcpSentReceipt or receipt is not authority.sent
                    or authority.phase not in _SENT_PHASES or authority.checking):
                raise GenerationHeld()
            try:
                self._check_phase(authority.phase)
            except BaseException:
                self.revoke()
                raise

    def _effect(self, capability, effect):
        self._owner_fence()
        observation = None
        live = True
        called = False

        def observe():
            nonlocal called, observation
            with self._owner_fence():
                if not live or called:
                    raise GenerationHeld()
                called = True
                self._check()
                observation = _Observation(capability)
                return observation

        try:
            result = effect(observe)
        finally:
            live = False
        if observation is None or result is not observation:
            raise GenerationHeld()
        self._check()
