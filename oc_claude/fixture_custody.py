"""Exclusive scratch custody for the synthetic Claude fixture."""

import ctypes
from dataclasses import dataclass, field
import os
from pathlib import Path
import secrets
import shutil
import stat
from threading import Lock
import time

from .fixture_protocol import ACCOUNT, MODEL, FixtureError, encode, require, valid_id


ANCHOR = Path("/dev/shm")
_MARKER = ".claude-fixture-custody"
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
_NAMES = set()
_NAMES_LOCK = Lock()
_RECOVERY_PREFIX = "occlaude-"
_RENAME_NOREPLACE = 1


def _directory_identity(info, *, uid):
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and stat.S_IMODE(info.st_mode) == 0o700)
    return info.st_dev, info.st_ino


def _open_private_dir(name, parent):
    fd = os.open(name, _DIR_FLAGS, dir_fd=parent)
    try:
        return fd, _directory_identity(os.fstat(fd), uid=os.geteuid())
    except BaseException:
        os.close(fd)
        raise


def _verify_anchor(fd):
    info = os.fstat(fd)
    parent = os.stat(ANCHOR.parent, follow_symlinks=False)
    require(stat.S_ISDIR(parent.st_mode) and not parent.st_mode & 0o022)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == parent.st_uid and info.st_mode & stat.S_ISVTX)
    fdinfo = Path(f"/proc/self/fdinfo/{fd}").read_text().splitlines()
    ids = [line.split()[1] for line in fdinfo if line.startswith("mnt_id:")]
    require(len(ids) == 1)
    for row in Path("/proc/self/mountinfo").read_text().splitlines():
        before, _separator, after = row.partition(" - ")
        fields = before.split()
        if fields[0] == ids[0]:
            require(fields[4] == str(ANCHOR) and after.split()[0] == "tmpfs")
            return info.st_dev
    raise FixtureError("integrity_error")


def _new_name():
    return "oc-claude-" + secrets.token_hex(16)


def _same_private_dir(name, parent, expected):
    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    return _directory_identity(info, uid=os.geteuid()) == expected


def _rename_without_replacing(source, source_fd, target, target_fd):
    try:
        rename = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError:
        raise FixtureError("retirement_unverified") from None
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(source_fd, os.fsencode(source), target_fd, os.fsencode(target), _RENAME_NOREPLACE):
        raise OSError(ctypes.get_errno(), "fixture scratch rename refused")


class PinnedFixtureScratch:
    """Retain the exact scratch pins through registry close and fixture retirement."""

    def __init__(self, anchor_fd, dir_fd, path, identity, *, recovery_lock, pending):
        self._anchor = os.dup(anchor_fd)
        try:
            self.fd = os.dup(dir_fd)
        except OSError:
            os.close(self._anchor)
            raise
        self.path = path
        self._identity = identity
        self._recovery_lock = recovery_lock
        self._pending = pending

    def __enter__(self):
        return self

    def __exit__(self, *_error):
        os.close(self.fd)
        os.close(self._anchor)

    def require_reachable(self):
        require(_same_private_dir(self.path.name, self._anchor, self._identity))
        require(_directory_identity(os.fstat(self.fd), uid=os.geteuid()) == self._identity)

    def recovery_names(self):
        return tuple(name for name in os.listdir(self.fd) if name.startswith(_RECOVERY_PREFIX))

    def expect_recovery(self, name):
        with self._recovery_lock:
            self.require_reachable()
            require(name not in self._pending)
            receipt = object()
            self._pending[name] = receipt
            return receipt

    def confirm_recovery(self, name, receipt):
        with self._recovery_lock:
            require(name in self._pending and self._pending[name] is receipt)
            del self._pending[name]

    def _move_owned_scratch(self, quarantine):
        # The private quarantine has no user-supplied children. If a swap won
        # the path-to-rename race, put the entry back without overwriting a new one.
        _rename_without_replacing(self.path.name, self._anchor, "scratch", quarantine)
        try:
            require(_same_private_dir("scratch", quarantine, self._identity))
        except (OSError, FixtureError):
            _rename_without_replacing("scratch", quarantine, self.path.name, self._anchor)
            raise

    def _delete_owned_contents(self):
        # Descend from the already-held original fd, never from the moved pathname.
        for name in os.listdir(self.fd):
            info = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                shutil.rmtree(name, dir_fd=self.fd)
            else:
                os.unlink(name, dir_fd=self.fd)

    def _quarantine_and_remove(self):
        name = ".oc-claude-retire-" + secrets.token_hex(16)
        os.mkdir(name, mode=0o700, dir_fd=self._anchor)
        quarantine, identity = _open_private_dir(name, self._anchor)
        try:
            self._move_owned_scratch(quarantine)
            if self.recovery_names():
                _rename_without_replacing("scratch", quarantine, self.path.name, self._anchor)
                raise FixtureError("retirement_unverified")
            self._delete_owned_contents()
            require(_same_private_dir("scratch", quarantine, self._identity))
            os.rmdir("scratch", dir_fd=quarantine)
        finally:
            # Keep an uncertain move or a held original. Directory removal
            # succeeds only when this exact quarantine has no remaining entry.
            try:
                if _same_private_dir(name, self._anchor, identity) and not os.listdir(quarantine):
                    os.rmdir(name, dir_fd=self._anchor)
            finally:
                os.close(quarantine)

    def remove(self):
        try:
            with self._recovery_lock:
                self.require_reachable()
                require(not self._pending and shutil.rmtree.avoids_symlink_attacks and not self.recovery_names())
                self._quarantine_and_remove()
        except (OSError, FixtureError):
            raise FixtureError("retirement_unverified") from None


@dataclass(frozen=True)
class ProfilePin:
    instance: str
    generation: int
    registry_id: str = field(repr=False)
    profile_id: str = field(repr=False)
    directory_identity: tuple[int, int] = field(repr=False)
    account_tag: str = field(repr=False)
    model: str
    executable_identity: str
    expires_at: int


class PinnedProfile:
    def __init__(self, anchor, root, root_identity, fd, pin, now, wall):
        self._anchor = anchor
        self._root, self._root_identity = root, root_identity
        self.fd, self._pin = fd, pin
        self.now, self._wall = now, wall
        start = now()
        remaining = pin.expires_at - wall()
        self._expiry_deadline = start + max(0, remaining)
        self._lock = Lock()
        self._active, self._expired = True, remaining <= 0
        self._images = (
            encode({"profile": pin.profile_id, "account": pin.account_tag, "model": pin.model,
                    "expires_at": pin.expires_at}),
            ("synthetic-only-" + pin.profile_id).encode("ascii"),
        )

    def snapshot(self):
        return self._pin

    def image_bytes(self):
        return self._images

    def try_fence(self):
        return self._lock.acquire(blocking=False)

    def release_fence(self):
        self._lock.release()

    def require_current(self, pin):
        # Called only with the custody fence held.
        if not self._active:
            raise FixtureError("cancelled")
        require(pin is self._pin)

    def expired(self):
        # Generation-owned state, checked only with the custody fence held.
        if self.now() >= self._expiry_deadline or self._wall() >= self._pin.expires_at:
            self._expired = True
        return self._expired

    def verify_directory(self):
        # The only filesystem check on the final fence. Both lookups are confined
        # to the known owner-controlled tmpfs, without reading any file contents.
        parent = None
        try:
            parent, root_info = _open_private_dir(self._root, self._anchor)
            require(root_info == self._root_identity)
            leaf = os.stat(self._pin.profile_id, dir_fd=parent, follow_symlinks=False)
            require(_directory_identity(leaf, uid=os.geteuid()) == self._pin.directory_identity)
        except OSError:
            raise FixtureError("integrity_error") from None
        finally:
            if parent is not None:
                os.close(parent)

    def revoke(self, cancel):
        cancel.set()
        with self._lock:
            self._active = False

    def close(self):
        with self._lock:
            self._active = False
            os.close(self.fd)


class FixtureCustody:
    """Create a private registry and burn its unique name for this supervisor."""

    def __init__(self, *, now=time.monotonic, wall=time.time):
        self._profiles, self._retired = {}, []
        self._registry_lock = Lock()
        self._recovery_lock = Lock()
        self._pending_recovery = {}
        self._now, self._wall = now, wall
        self._root_fd = None
        self._anchor_fd = os.open(ANCHOR, _DIR_FLAGS)
        try:
            device = _verify_anchor(self._anchor_fd)
            self._root_name = _new_name()
            require(self._root_name.startswith("oc-claude-") and valid_id(self._root_name.removeprefix("oc-claude-")))
            with _NAMES_LOCK:
                require(self._root_name not in _NAMES)
                _NAMES.add(self._root_name)
            os.mkdir(self._root_name, mode=0o700, dir_fd=self._anchor_fd)
            self._root_fd, self._root_identity = _open_private_dir(self._root_name, self._anchor_fd)
            require(self._root_identity[0] == device)
            marker = os.open(_MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=self._root_fd)
            os.close(marker)
        except BaseException as error:
            if self._root_fd is not None:
                os.close(self._root_fd)
            os.close(self._anchor_fd)
            if isinstance(error, OSError):
                raise FixtureError("integrity_error") from None
            raise
        self.root = ANCHOR / self._root_name

    def __enter__(self):
        return self

    def __exit__(self, *_error):
        # The fixture owner joins all workers before closing the registry.
        if self._root_fd is not None:
            for profile in [*self._profiles.values(), *self._retired]:
                profile.close()
            os.close(self._root_fd)
            self._root_fd = None
            os.close(self._anchor_fd)

    def pin_scratch(self):
        require(self._root_fd is not None)
        return PinnedFixtureScratch(
            self._anchor_fd, self._root_fd, self.root, self._root_identity,
            recovery_lock=self._recovery_lock, pending=self._pending_recovery,
        )

    def enroll(self, instance, generation, *, profile_id, account_tag, model, executable_identity, expires_at,
               cancel=None):
        require(self._root_fd is not None)
        require(valid_id(instance, MODEL) and type(generation) is int and generation > 0)
        require(valid_id(profile_id) and valid_id(account_tag, ACCOUNT) and valid_id(model, MODEL))
        require(valid_id(executable_identity, ACCOUNT) and type(expires_at) is int and 0 <= expires_at < 1 << 63)
        try:
            fd, identity = _open_private_dir(profile_id, self._root_fd)
        except OSError:
            raise FixtureError("integrity_error") from None
        try:
            with self._registry_lock:
                old = self._profiles.get(instance)
                if old is not None:
                    require(cancel is not None and generation > old.snapshot().generation)
                require(identity[0] == self._root_identity[0])
                require(all(profile.snapshot().directory_identity != identity
                            for profile in [*self._profiles.values(), *self._retired]))
                pin = ProfilePin(instance, generation, self._root_name, profile_id, identity, account_tag, model,
                                 executable_identity, expires_at)
                profile = PinnedProfile(self._anchor_fd, self._root_name, self._root_identity, fd, pin,
                                        self._now, self._wall)
                profile.verify_directory()
                if old is not None:
                    old.revoke(cancel)
                    self._retired.append(old)
                self._profiles[instance] = profile
        except BaseException:
            os.close(fd)
            raise

    def open(self, instance, generation):
        require(self._root_fd is not None)
        with self._registry_lock:
            profile = self._profiles.get(instance)
        require(profile is not None and profile.snapshot().generation == generation)
        profile.verify_directory()
        return profile
