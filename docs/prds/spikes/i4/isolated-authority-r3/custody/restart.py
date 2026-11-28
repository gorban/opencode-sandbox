"""Durable synthetic retention and fresh-controller refusal evidence."""

from contextlib import contextmanager
from hashlib import sha256
import os
from pathlib import Path
import re
import select
import stat

from bootstrap import CustodyRefused, _native_procfs, _read_text
from descriptor import Denied, Refusal, canonical, decode
from receipt import Commitment, ReceiptStore
from test_receipt import LocalPair


_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_LIMIT = 1 << 18
_HANDLE = re.compile(r"r[0-9a-f]{32}")
_SCRATCH = re.compile(r"r[a-z0-9_]{8}")
_RESUME = "resume.json"
_RECEIPT = "continuity.json"


def _require(condition, reason):
    if not condition:
        raise CustodyRefused(reason)


def _boot_id(proc):
    fd = os.dup(proc)
    try:
        for part in ("sys", "kernel", "random"):
            child = os.open(part, _DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = child
        value = _read_text(fd, "boot_id", 64).strip()
    finally:
        os.close(fd)
    _require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value), "boot identity unavailable")
    return value


def _start(proc, pid):
    fd = os.open(str(pid), _DIRECTORY, dir_fd=proc)
    try:
        record = _read_text(fd, "stat", 4096)
    finally:
        os.close(fd)
    command_end = record.rfind(")")
    fields = record[command_end + 1:].split()
    if not record.startswith(f"{pid} (") or len(fields) < 20 or not fields[19].isdecimal():
        raise CustodyRefused("process lifetime unavailable")
    return int(fields[19])


@contextmanager
def _kernel():
    proc = os.open("/proc", _DIRECTORY)
    try:
        _native_procfs(proc)
        _require(os.readlink("self", dir_fd=proc) == str(os.getpid()), "unexpected procfs view")
        yield proc
    finally:
        os.close(proc)


def lifetime(pid=None):
    pid = os.getpid() if pid is None else pid
    with _kernel() as proc:
        return [_boot_id(proc), pid, _start(proc, pid)]


def require_retired(before):
    now = lifetime()
    _require(type(before) is list and len(before) == 3 and before[0] == now[0] and before != now
             and type(before[1]) is int and type(before[2]) is int and 1 < before[1] and 0 < before[2],
             "cannot confirm old controller lifetime")
    old_pid = before[1]
    try:
        pidfd = os.pidfd_open(old_pid)
    except ProcessLookupError:
        return now
    try:
        with _kernel() as proc:
            try:
                start = _start(proc, old_pid)
            except FileNotFoundError:
                start = before[2]
        if start == before[2]:
            poll = select.poll()
            poll.register(pidfd, select.POLLIN)
            _require(any(events & select.POLLIN for _, events in poll.poll(0)),
                     "previous controller is still live or retirement is unavailable")
    finally:
        os.close(pidfd)
    return now


def _read_at(root, leaf, uid):
    descriptor = os.open(leaf, _FILE, dir_fd=root)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        _require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1
                 and not stat.S_IMODE(info.st_mode) & 0o077 and info.st_size <= _LIMIT,
                 "unsafe retained fixture file")
        content = stream.read(_LIMIT + 1)
        named = os.stat(leaf, dir_fd=root, follow_symlinks=False)
        _require((named.st_dev, named.st_ino) == (info.st_dev, info.st_ino) and len(content) <= _LIMIT,
                 "retained fixture file changed")
    return content


def _record_tree(directory, root_device, uid, excluded, entries, prefix=""):
    for name in sorted(os.listdir(directory)):
        relative = prefix + name
        if relative in excluded:
            continue
        _require(len(entries) < 512 and relative.count("/") < 12 and len(relative) < 512,
                 "retained fixture evidence exceeds bounds")
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
        _require(info.st_dev == root_device and info.st_uid == uid, "unexpected retained fixture owner or mount")
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISDIR(info.st_mode):
            _require(not mode & 0o022, "unprotected retained fixture directory")
            child = os.open(name, _DIRECTORY, dir_fd=directory)
            try:
                opened = os.fstat(child)
                _require((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino),
                         "retained fixture directory changed")
                entries.append([relative + "/", mode, info.st_ino])
                _record_tree(child, root_device, uid, excluded, entries, relative + "/")
            finally:
                os.close(child)
        else:
            value = sha256(_read_at(directory, name, uid)).hexdigest()
            entries.append([relative, mode, info.st_ino, value])


def snapshot(path, uid, *, excluded=()):
    descriptor = os.open(path, _DIRECTORY)
    try:
        info = os.fstat(descriptor)
        _require(info.st_uid == uid and stat.S_IMODE(info.st_mode) == 0o700, "unsafe retention root")
        entries = []
        _record_tree(descriptor, info.st_dev, uid, excluded, entries)
        return [info.st_dev, info.st_ino, entries]
    finally:
        os.close(descriptor)


def retain(receipt, state):
    root = os.open(receipt, _DIRECTORY)
    try:
        create = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(_RESUME, create, 0o600, dir_fd=root)
        with os.fdopen(fd, "wb") as stream:
            payload = canonical(["r3-restart-v1", state])
            _require(len(payload) <= _LIMIT, "retained handoff exceeds bound")
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(root)
    finally:
        os.close(root)


def load_retained(receipt, controller_uid):
    root = os.open(receipt, _DIRECTORY)
    try:
        info = os.fstat(root)
        _require((info.st_uid, stat.S_IMODE(info.st_mode)) == (controller_uid, 0o700), "unsafe receipt retention root")
        decoded = decode(_read_at(root, _RESUME, controller_uid))
    finally:
        os.close(root)
    if len(decoded) != 2 or decoded[0] != "r3-restart-v1" or type(decoded[1]) is not dict:
        raise CustodyRefused("unexpected retained handoff")
    return decoded[1]


def capture(receipt, scope, legacy, ids):
    return {
        "receipt": snapshot(receipt, ids["controller"], excluded={_RESUME}),
        "scope": snapshot(scope, ids["holder"]),
        "legacy": snapshot(legacy, ids["legacy"]),
    }


def verify_retained(receipt, scope, legacy, ids, record):
    before = capture(receipt, scope, legacy, ids)
    seal = snapshot(receipt, ids["controller"])
    _require(before == record["snapshot"], "retained fixture evidence disagrees")
    descriptor = os.open(scope, _DIRECTORY)
    try:
        local = LocalPair(descriptor, tuple(record["lock"]))
        current = local.read()
    finally:
        os.close(descriptor)
    receipt_fd = os.open(receipt, _DIRECTORY)
    try:
        contents = decode(_read_at(receipt_fd, _RECEIPT, ids["controller"]))
    finally:
        os.close(receipt_fd)
    _require(contents == ["r3", "witnessed", current.wire()] and record["head"] == current.wire(),
             "retained holder pair is not the exact witnessed head")
    fresh = ReceiptStore(receipt, Commitment.parse(record["initial"]))
    try:
        fresh.head()
    except Denied as failure:
        _require(failure.reason == Refusal.RECONCILIATION_REQUIRED, "unexpected fresh controller refusal")
    else:
        raise CustodyRefused("fresh controller acquired authority")
    _require(capture(receipt, scope, legacy, ids) == before
             and snapshot(receipt, ids["controller"]) == seal, "fresh refusal modified retained state")
    return {"fresh_controller_refused": True, "new_authorizations": 0, "new_holder_sends": 0,
            "receipt_unchanged": True, "legacy_history_preserved": True}


def retained_paths(handle, holder_mount, receipt_mount, scratch_root, state):
    _require(_HANDLE.fullmatch(handle) and _SCRATCH.fullmatch(state["scope"]) and _SCRATCH.fullmatch(state["scratch"]),
             "unexpected retained fixture names")
    return receipt_mount / handle, holder_mount / state["scope"], scratch_root / state["scratch"] / "legacy"
