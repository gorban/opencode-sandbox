"""Private installation registry and foreground guard for saved OpenAI registrations."""

from contextlib import contextmanager
from dataclasses import dataclass, field
import fcntl
import os
from pathlib import Path
import re
import secrets
import uuid

from .connection_state import CREATE_FLAGS, ConnectionError, Store, _directory, _regular


_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}")
_LOCAL_ID = re.compile(r"[A-Za-z0-9_-]{43}")
_DIRECTORY_ID = re.compile(r"[0-9a-f]{32}")
_CLIENT_ID = re.compile(r"[!-~]{1,512}")
_HOST_ID = re.compile(r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_MAX_REGISTRATIONS = 16


def valid_label(value: object) -> bool:
    return type(value) is str and _LABEL.fullmatch(value) is not None


class ProfileError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Profile:
    label: str
    directory: Path
    host_id: str
    epoch: str
    client_id: str | None = field(repr=False)
    retiring: bool = False
    selected: bool = False


@dataclass(frozen=True)
class Candidate:
    profile: Profile
    pending_generation: str


@dataclass(frozen=True)
class RegistryView:
    saved: tuple[Profile, ...]
    active: Profile | None
    unpublished: tuple[Profile, ...] = ()


def _matches(value, pattern):
    return type(value) is str and pattern.fullmatch(value) is not None


def _validate_entry(label, entry, directories, clients):
    if (
        not valid_label(label) or type(entry) is not dict
        or set(entry) != {"key", "client_id", "pending", "retiring"}
        or not _matches(entry["key"], _DIRECTORY_ID) or entry["key"] in directories
        or (entry["pending"] is not None and not _matches(entry["pending"], _LOCAL_ID))
        or type(entry["retiring"]) is not bool
    ):
        raise ProfileError("profile_storage_unavailable")
    directories.add(entry["key"])
    client_id = entry["client_id"]
    if client_id is not None:
        if not _matches(client_id, _CLIENT_ID) or client_id in clients:
            raise ProfileError("profile_storage_unavailable")
        clients.add(client_id)
    elif entry["retiring"]:
        raise ProfileError("profile_storage_unavailable")


def _validate(state):
    if (
        set(state) != {"version", "host_id", "epoch", "active", "registrations"}
        or type(state["version"]) is not int or state["version"] != 1
        or not _matches(state["host_id"], _HOST_ID)
        or not _matches(state["epoch"], _LOCAL_ID)
        or type(state["registrations"]) is not dict
        or len(state["registrations"]) > _MAX_REGISTRATIONS
    ):
        raise ProfileError("profile_storage_unavailable")
    directories = set()
    clients = set()
    for label, entry in state["registrations"].items():
        _validate_entry(label, entry, directories, clients)
    active = state["active"]
    if active is not None and (
        not valid_label(active) or not state["registrations"].get(active, {}).get("client_id")
    ):
        raise ProfileError("profile_storage_unavailable")


class Profiles:
    def __init__(self, root: Path):
        self._root = Path(root)
        self._store = Store(self._root / "profiles")

    @contextmanager
    def _state(self, *, create=False):
        try:
            with self._store.locked(create=create) as directory:
                state = self._store.read(directory)
                if state:
                    _validate(state)
                yield directory, state
        except ConnectionError as error:
            if error.code in {
                "untrusted_connection_path", "untrusted_connection_file", "invalid_connection_state",
                "connection_storage_busy", "connection_storage_unavailable",
            }:
                raise ProfileError("profile_storage_unavailable") from None
            raise

    def _write(self, directory, state):
        _validate(state)
        self._store.write(directory, state)

    def _profile(self, state, label):
        entry = state["registrations"][label]
        return Profile(
            label, self._root / "registrations" / entry["key"], state["host_id"], state["epoch"],
            entry["client_id"], entry["retiring"], state["active"] == label,
        )

    def snapshot(self) -> RegistryView:
        with self._state() as (_, state):
            if not state:
                return RegistryView((), None)
            saved = tuple(
                self._profile(state, label) for label, entry in sorted(state["registrations"].items())
                if entry["client_id"] is not None
            )
            unpublished = tuple(
                self._profile(state, label) for label, entry in sorted(state["registrations"].items())
                if entry["client_id"] is None
            )
            active = state["active"]
            return RegistryView(saved, self._profile(state, active) if active is not None else None, unpublished)

    def list(self) -> tuple[Profile, ...]:
        return self.snapshot().saved

    def selected(self) -> Profile | None:
        return self.snapshot().active

    def begin(self, label: str, *, reclaim=None) -> Candidate:
        return self._begin(label, reclaim, abandoned_pending=False)

    def _begin(self, label: str, reclaim, *, abandoned_pending: bool) -> Candidate:
        if not valid_label(label):
            raise ProfileError("profile_invalid_label")
        with self._state(create=True) as (directory, state):
            if not state:
                state = {
                    "version": 1,
                    "host_id": uuid.uuid4().urn,
                    "epoch": secrets.token_urlsafe(32),
                    "active": None,
                    "registrations": {},
                }
            entries = state["registrations"]
            if label not in entries:
                if len(entries) >= _MAX_REGISTRATIONS:
                    self._make_room(state, reclaim, abandoned_pending=abandoned_pending)
                entries[label] = {"key": secrets.token_hex(16), "client_id": None, "pending": None, "retiring": False}
            pending = secrets.token_urlsafe(32)
            entries[label]["pending"] = pending
            self._write(directory, state)
            return Candidate(self._profile(state, label), pending)

    def _make_room(self, state, reclaim, *, abandoned_pending: bool):
        if reclaim is not None:
            entries = state["registrations"]
            for label, entry in entries.items():
                if (
                    entry["client_id"] is None and (abandoned_pending or entry["pending"] is None)
                    and reclaim(self._profile(state, label)) is True
                ):
                    # Reuse only the registry slot. The opaque directory remains untouched.
                    del entries[label]
                    return
        raise ProfileError("profile_limit")

    @contextmanager
    def connect_candidate(self, label: str, *, reclaim=None):
        """Own the sign-in attempt through exact cleanup, independently of inference and retirement."""
        with self._exclusive("connect.lock", "profile_connect_busy"):
            candidate = self._begin(label, reclaim, abandoned_pending=True)
            try:
                yield candidate
            finally:
                self.abandon(candidate, reclaim=reclaim)

    def abandon(self, candidate: Candidate, *, reclaim=None) -> None:
        with self._state() as (directory, state):
            label = candidate.profile.label
            entries = state.get("registrations", {})
            entry = entries.get(label)
            if (
                entry is not None and entry["pending"] == candidate.pending_generation
                and self._profile(state, label).directory == candidate.profile.directory
            ):
                if entry["client_id"] is None and reclaim is not None and reclaim(self._profile(state, label)) is True:
                    del entries[label]
                else:
                    entry["pending"] = None
                self._write(directory, state)

    def _candidate_entry(self, state, candidate):
        label = candidate.profile.label
        entry = state.get("registrations", {}).get(label)
        if (entry is None or self._profile(state, label) != candidate.profile
                or entry["pending"] != candidate.pending_generation):
            raise ProfileError("profile_stale")
        return entry

    @contextmanager
    def authorize(self, candidate: Candidate):
        """Hold the exact selection and attempt fence for one short local action."""
        with self._state() as (_, state):
            self._candidate_entry(state, candidate)
            yield

    def foreground(self):
        return self._exclusive("foreground.lock", "profile_busy")

    @contextmanager
    def _exclusive(self, name, busy):
        try:
            directory = _directory(self._store.path, create=True)
            try:
                mutex = os.open(
                    name, os.O_RDWR | os.O_NONBLOCK | os.O_CREAT | CREATE_FLAGS,
                    0o600, dir_fd=directory,
                )
            finally:
                os.close(directory)
        except (OSError, ConnectionError):
            raise ProfileError("profile_storage_unavailable") from None
        try:
            try:
                _regular(mutex)
                fcntl.flock(mutex, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ProfileError(busy) from None
            except (OSError, ConnectionError):
                raise ProfileError("profile_storage_unavailable") from None
            yield
        finally:
            os.close(mutex)

    @contextmanager
    def publish(self, candidate: Candidate, client_id: str, callback=None):
        if not _matches(client_id, _CLIENT_ID):
            raise ProfileError("profile_client_conflict")
        label = candidate.profile.label
        with self.foreground(), self._state() as (directory, state):
            entry = self._candidate_entry(state, candidate)
            entries = state["registrations"]
            if (
                entry["client_id"] not in (None, client_id)
                or any(other["client_id"] == client_id for name, other in entries.items() if name != label)
            ):
                raise ProfileError("profile_client_conflict")
            if callback is not None:
                active = state["active"]
                callback(self._profile(state, active) if active is not None else None, candidate.profile)
            yield candidate.profile
            entry.update(client_id=client_id, pending=None, retiring=False)
            state.update(active=label, epoch=secrets.token_urlsafe(32))
            self._write(directory, state)

    def select(self, label: str, callback) -> Profile:
        if not valid_label(label):
            raise ProfileError("profile_invalid_label")
        with self.foreground(), self._state() as (directory, state):
            entry = state.get("registrations", {}).get(label)
            if entry is None or entry["client_id"] is None:
                raise ProfileError("profile_unknown")
            if entry["retiring"]:
                raise ProfileError("profile_retiring")
            active = state["active"]
            callback(self._profile(state, active) if active is not None else None, self._profile(state, label))
            state.update(active=label, epoch=secrets.token_urlsafe(32))
            self._write(directory, state)
            return self._profile(state, label)

    def with_selected(self, label: str, epoch: str, callback):
        """Run callback under the registry mutex only while (label, epoch) is active and non-retiring."""
        with self.selected_fence(label, epoch) as profile:
            return callback(profile)

    @contextmanager
    def selected_fence(self, label: str, epoch: str):
        """Hold the registry mutex while (label, epoch) remains active and non-retiring."""
        with self._state() as (_directory, state):
            if not state or state.get("active") != label or state.get("epoch") != epoch:
                raise ProfileError("profile_stale")
            entry = state["registrations"].get(label)
            if entry is None or entry["client_id"] is None or entry["retiring"]:
                raise ProfileError("profile_retiring")
            yield self._profile(state, label)

    def begin_disconnect(self, before_retirement, *, inactive_filter=None) -> Profile | None:
        with self._state() as (directory, state):
            if not state:
                return None
            label = state.get("active")
            entries = state["registrations"]
            targets = [label] if label is not None else []
            for name, entry in sorted(entries.items()):
                if name == label:
                    continue
                if (entry["pending"] is not None or entry["client_id"] is None
                        or (inactive_filter is not None and inactive_filter(self._profile(state, name)))):
                    targets.append(name)
            for name in targets:
                fenced = before_retirement(self._profile(state, name))
                if fenced is not False and entries[name]["client_id"] is not None:
                    entries[name]["retiring"] = True
            state["epoch"] = secrets.token_urlsafe(32)
            self._write(directory, state)
            return self._profile(state, label) if label is not None else None
