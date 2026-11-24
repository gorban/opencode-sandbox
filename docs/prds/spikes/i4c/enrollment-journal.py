"""Synthetic enrollment generation persistence outside the native mount."""

from contextlib import contextmanager, suppress
import fcntl
import json
import os
import re
import secrets
import stat


class EnrollmentError(ValueError):
    """The private registration record is unavailable or cannot advance."""


def verify_file(fd):
    info = os.fstat(fd)
    if (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600
            or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
        raise EnrollmentError("unsafe enrollment file")


def no_duplicates(pairs):
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise EnrollmentError("duplicate enrollment field")
    return fields


def read_current(directory):
    try:
        fd = os.open("generation.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as state:
        verify_file(fd)
        payload = state.read(1025)
    if len(payload) > 1024:
        raise EnrollmentError("oversized enrollment record")
    record = json.loads(payload, object_pairs_hook=no_duplicates)
    if (type(record) is not dict or set(record) != {"generation", "state"}
            or type(record["generation"]) is not str or not re.fullmatch(r"[0-9a-f]{32}", record["generation"])
            or record["state"] not in ("pending", "ready", "abandoned")):
        raise EnrollmentError("invalid enrollment record")
    return record


def durable_replace(directory, generation, state):
    name = "proposed-" + secrets.token_hex(16)
    staged = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_EXCL | os.O_CREAT, 0o600, dir_fd=directory)
    try:
        with os.fdopen(staged, "w", encoding="ascii") as receipt:
            json.dump({"generation": generation, "state": state}, receipt)
            receipt.write("\n")
            receipt.flush()
            os.fsync(receipt.fileno())
        os.replace(name, "generation.json", src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        with suppress(FileNotFoundError):
            os.unlink(name, dir_fd=directory)


class Journal:
    def __init__(self, root):
        self.root = root

    @contextmanager
    def locked(self):
        directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise EnrollmentError("unsafe enrollment directory")
            fd = os.open("lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
            with os.fdopen(fd, "rb") as lock:
                verify_file(lock.fileno())
                fcntl.flock(lock, fcntl.LOCK_EX)
                yield directory
        finally:
            os.close(directory)

    def current(self):
        with self.locked() as directory:
            return read_current(directory)

    def begin(self):
        with self.locked() as directory:
            if read_current(directory) is not None:
                raise EnrollmentError("registration already has a generation")
            generation = secrets.token_hex(16)
            durable_replace(directory, generation, "pending")
        return generation

    def transition(self, generation, state):
        if state not in ("ready", "abandoned"):
            raise EnrollmentError("invalid enrollment transition")
        with self.locked() as directory:
            current = read_current(directory)
            if current != {"generation": generation, "state": "pending"}:
                raise EnrollmentError("pending enrollment generation changed")
            durable_replace(directory, generation, state)
