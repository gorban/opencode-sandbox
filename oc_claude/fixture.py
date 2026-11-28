"""Own the sealed text turn for the offline Claude fixture."""

from contextlib import contextmanager
from dataclasses import dataclass, field
import secrets
from threading import Lock
from typing import Protocol

from .fixture_custody import PinnedProfile, ProfilePin
from .fixture_protocol import (
    FixtureError, read_answer, require, status_expiry,
    user_frame, valid_id, validate_prompt, verify_ready,
)


STATUS_SECONDS = 2
TURN_SECONDS = 6
RETIRE_SECONDS = 2
LOCK_WAIT_SECONDS = .01


class OwnedChild(Protocol):
    pin: ProfilePin
    session: str
    pipe_buf: int

    def read_frame(self, deadline, cancel) -> bytes: ...
    def verify_quiet(self) -> None: ...
    def is_live(self) -> bool: ...
    def write_once(self, packet) -> int: ...
    def close_input(self) -> None: ...
    def finish(self, deadline, cancel) -> None: ...
    def retire(self, deadline) -> bool: ...


class FixtureLauncher(Protocol):
    def start(self, profile, mode, deadline, cancel) -> OwnedChild: ...


@dataclass(frozen=True, eq=False)
class ReadyBinding:
    profile: PinnedProfile = field(repr=False)
    pin: ProfilePin = field(repr=False)


@dataclass(frozen=True)
class Unavailable:
    reason: str = "unavailable"


class FixtureAuthority:
    """A one-use host approval for one exact fixture user request."""

    def __init__(self, binding, model, text):
        validate_prompt(text)
        require(isinstance(binding, ReadyBinding) and model == binding.pin.model)
        self._binding, self._model, self._text = binding, model, text
        self._lock = Lock()
        self._reserved = False
        self._spent = False

    def try_fence(self):
        return self._lock.acquire(blocking=False)

    def release_fence(self):
        self._lock.release()

    def _match(self, binding, model, text):
        require(binding is self._binding and model == self._model and text == self._text)

    def reserve(self, binding, model, text):
        self._match(binding, model, text)
        require(not self._reserved)
        self._reserved = True

    def try_claim(self, binding, model, text):
        """Check and consume the latch under the caller's held selection fence."""
        self._match(binding, model, text)
        require(self._reserved and not self._spent)
        self._spent = True


def _check(cancel, now, deadline):
    if cancel.is_set():
        raise FixtureError("cancelled")
    if now() >= deadline:
        raise FixtureError("deadline_exceeded")


@contextmanager
def _fences(guards, cancel, now, deadline):
    acquired = []
    try:
        while len(acquired) != len(guards):
            _check(cancel, now, deadline)
            for guard in guards:
                if not guard.try_fence():
                    break
                acquired.append(guard)
            if len(acquired) != len(guards):
                _unlock(acquired)
                cancel.wait(max(0, min(LOCK_WAIT_SECONDS, deadline - now())))
        yield
    finally:
        _unlock(acquired)


def _unlock(acquired):
    while acquired:
        acquired.pop().release_fence()


def _require_binding(binding):
    binding.profile.require_current(binding.pin)
    if binding.profile.expired():
        raise FixtureError("cancelled")


def _error(error):
    if isinstance(error, FixtureError):
        return error.reason
    if isinstance(error, KeyboardInterrupt):
        return "cancelled"
    return "provider_failed"


def _run_owned(profile, mode, launcher, exchange, deadline, cancel, now):
    child = None
    attempted = False

    def mark_attempted():
        nonlocal attempted
        attempted = True

    try:
        profile.verify_directory()
        _check(cancel, now, deadline)
        child = launcher.start(profile, mode, deadline, cancel)
        require(child.pin is profile.snapshot())
        result = exchange(child, mark_attempted)
        reason = None
    except (Exception, KeyboardInterrupt) as error:
        reason = _error(error)
    finally:
        if child is not None:
            try:
                retired = child.retire(now() + RETIRE_SECONDS)
            except (Exception, KeyboardInterrupt):
                retired = False
            if retired is not True:
                raise FixtureError("retirement_unverified", possible_send=attempted) from None
    if reason == "retirement_unverified":
        raise FixtureError(reason, possible_send=attempted)
    if cancel.is_set():
        reason = "cancelled"
    elif reason not in ("cancelled", "integrity_error") and now() >= deadline:
        reason = "deadline_exceeded"
    if reason is not None:
        raise FixtureError(reason, possible_send=attempted)
    return result, attempted


def probe_fixture(profile, launcher, cancel):
    now = profile.now
    deadline = now() + STATUS_SECONDS
    pin = profile.snapshot()
    with _fences((profile,), cancel, now, deadline):
        profile.require_current(pin)
        if profile.expired():
            return Unavailable()

    def exchange(child, _mark_attempted):
        expires_at = status_expiry(child.read_frame(deadline, cancel), pin)
        child.finish(deadline, cancel)
        return expires_at

    expires_at, _attempted = _run_owned(profile, "status", launcher, exchange, deadline, cancel, now)
    with _fences((profile,), cancel, now, deadline):
        _check(cancel, now, deadline)
        profile.require_current(pin)
        if profile.expired() or expires_at is None:
            return Unavailable()
    return ReadyBinding(profile, pin)


def run_fixture_text(binding, model, text, launcher, authority, cancel):
    validate_prompt(text)
    require(type(binding) is ReadyBinding and type(authority) is FixtureAuthority and model == binding.pin.model)
    now = binding.profile.now
    deadline = now() + TURN_SECONDS
    guards = (binding.profile, authority)
    with _fences(guards, cancel, now, deadline):
        _require_binding(binding)
        authority.reserve(binding, model, text)

    def exchange(child, mark_attempted):
        require(valid_id(child.session))
        ready_deadline = deadline - TURN_SECONDS + STATUS_SECONDS
        verify_ready(child.read_frame(ready_deadline, cancel), binding.pin, child.session)
        challenge = secrets.token_hex(16)
        packet = user_frame(child.session, challenge, text, child.pipe_buf)
        child.verify_quiet()
        binding.profile.verify_directory()
        with _fences(guards, cancel, now, deadline):
            _require_binding(binding)
            require(child.pin is binding.pin and child.is_live())
            binding.profile.verify_directory()
            child.verify_quiet()
            _check(cancel, now, deadline)
            authority.try_claim(binding, model, text)
            _check(cancel, now, deadline)
            _require_binding(binding)
            mark_attempted()
            try:
                require(child.write_once(packet) == len(packet))
            except (OSError, FixtureError):
                raise FixtureError("send_uncertain") from None
        child.close_input()
        def read_turn_frame():
            with _fences((binding.profile,), cancel, now, deadline):
                _require_binding(binding)
            return child.read_frame(deadline, cancel)

        answer = read_answer(read_turn_frame, child.session, challenge, model)
        child.finish(deadline, cancel)
        return answer

    answer, attempted = _run_owned(binding.profile, "turn", launcher, exchange, deadline, cancel, now)
    try:
        binding.profile.verify_directory()
        with _fences(guards, cancel, now, deadline):
            _require_binding(binding)
            _check(cancel, now, deadline)
    except FixtureError as error:
        raise FixtureError(error.reason, possible_send=attempted) from None
    return answer
