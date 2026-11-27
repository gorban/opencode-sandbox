"""One durable generation hold for a sealed synthetic registration fixture."""

from contextlib import ExitStack, contextmanager, suppress
from dataclasses import asdict, dataclass
from enum import StrEnum
from hashlib import sha256
import json
import os
import secrets
from threading import RLock

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
    def launch(self, binding, *, fence, authorized):
        if (type(binding) is not Binding or type(fence) is not _RLOCK or not callable(authorized)
                or any(type(value) is not str for value in (
                    binding.generation, binding.profile_digest, binding.credential_digest, binding.model,
                    binding.policy_digest, binding.launch,
                ))
                or binding != self._anchor.binding(epoch=binding.epoch, launch=binding.launch)):
            raise GenerationHeld()
        with self._fresh(authorized=lambda: authorized(binding)) as files:
            run = _Run(files, binding, fence, authorized)
            try:
                run._launch()
                yield run
            finally:
                run.revoke()


class _Files:
    """Pin the registration, immutable authority, and independent save latch."""

    def __init__(self, anchor, slot, record, profile, pins, key_fd):
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
            try:
                self._hold_after_failed_save()
            except (OSError, GenerationHeld):
                error.add_note("Google synthetic generation latch still requires inspection")
            raise
        finally:
            with suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=self.directory)


class _Run:
    def __init__(self, files, binding, fence, authorized):
        self._files = files
        self._binding = binding
        self._fence = fence
        self._authorized = authorized
        self._phase = Phase.UNSTARTED
        self._revoked = False
        self._busy = False
        self._capability = None

    def revoke(self):
        with self._fence:
            self._revoked = True
            self._capability = None

    def _check(self):
        if self._revoked:
            raise GenerationHeld()
        self._files.verify()
        if self._authorized(self._binding) is not True or self._revoked:
            raise GenerationHeld()
        self._files.verify()

    @contextmanager
    def _transition(self):
        if self._busy or self._revoked:
            raise GenerationHeld()
        self._busy = True
        try:
            self._check()
            yield
        except BaseException:
            self.revoke()
            raise
        finally:
            self._busy = False

    def _save(self, phase):
        self._files.save(phase, self._binding, self._check)
        self._check()
        self._phase = phase

    def _launch(self):
        with self._fence, self._transition():
            self._save(Phase.LAUNCH_HELD)

    def issue(self, operation):
        """Persist a claim before issuing its exact one-use capability."""
        with self._fence:
            if (type(operation) is not Operation or self._phase != _STEPS[operation][0]
                    or self._capability is not None):
                raise GenerationHeld()
            with self._transition():
                self._save(_STEPS[operation][1])
                self._capability = Capability(operation)
                return self._capability

    def consume(self, capability, effect):
        """Spend before the bounded synthetic effect and settle only its exact observation."""
        with self._fence:
            if type(capability) is not Capability or capability is not self._capability or not callable(effect):
                raise GenerationHeld()
            with self._transition():
                self._capability = None
                self._effect(capability, effect)
                self._save(_STEPS[capability.operation][2])

    def _effect(self, capability, effect):
        observation = None
        live = True
        called = False

        def observe():
            nonlocal called, observation
            with self._fence:
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
