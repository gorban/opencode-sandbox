"""Measured, bounded synthetic role entry points."""

import errno
from hashlib import sha256
import os
from pathlib import Path
import re
import select
import socket
import stat
import sys

from bootstrap import (
    CustodyRefused, proc_self, receive_bootstrap, role_accounts, verify_role, verify_role_record, verify_role_stdio,
    verify_root_parent,
)
from descriptor import Channel, Denied, OwnerGrant, Peer, Refusal, canonical, decode, fingerprint
from receipt import ReceiptClient, advance_locked
from test_receipt import LocalPair


USAGE_BYTES = b"fixture settlement\n"
JOB_KEYS = {"job", "relay", "input"}
JOB = {"job": "synthetic-job", "relay": "none", "input": "readable fixture"}
_PHASE = re.compile(r"[a-z0-9-]{1,48}")
_DENY = {errno.EACCES, errno.EPERM}
_OWNER_FDS = frozenset({"bootstrap", "controller_pidfd", "owner"})
_ROLE_FDS = {
    "owner": _OWNER_FDS,
    "holder": _OWNER_FDS | {"receipt", "scope"},
    "legacy": frozenset(),
    "legacy-probe": frozenset(),
    "sibling": frozenset(),
    "worker": frozenset(),
}


def require_role_fds(role, descriptors):
    expected = _ROLE_FDS.get(role)
    if (expected is None or type(descriptors) is not dict or descriptors.keys() != expected
            or any(type(fd) is not int or fd <= 2 for fd in descriptors.values())
            or len(set(descriptors.values())) != len(expected)):
        raise CustodyRefused("inherited descriptors do not match the fixed role purposes")
    return descriptors


def _bounded_regular(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise CustodyRefused("invalid fixture input type")
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise CustodyRefused("fixture input exceeds bound")
    return data


def _audit(event, args):
    if event == "socket.__new__" and args[1] not in (socket.AF_UNIX, -1):
        raise CustodyRefused("unexpected Internet socket")
    if event in {"socket.bind", "socket.connect", "socket.sendto"} and args[0].family != socket.AF_UNIX:
        raise CustodyRefused("unexpected Internet endpoint")
    if event in {"socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr",
                 "subprocess.Popen", "os.system", "os.posix_spawn", "os.exec"}:
        raise CustodyRefused("unexpected external operation")


def enable_offline_guard():
    sys.addaudithook(_audit)


def _socket(fd):
    try:
        endpoint = socket.socket(fileno=fd)
    except OSError:
        os.close(fd)
        raise
    try:
        if (endpoint.family != socket.AF_UNIX or endpoint.type != socket.SOCK_SEQPACKET
                or not endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) or endpoint.getsockname()):
            raise CustodyRefused("invalid inherited authority socket")
        # Linux may autobind the peer to an abstract address when it sends a
        # packet with SO_PASSCRED enabled. No filesystem endpoint is expected.
        peer = endpoint.getpeername()
        if isinstance(peer, str) and peer:
            raise CustodyRefused("unexpected filesystem authority endpoint")
        endpoint.set_inheritable(False)
        return endpoint
    except BaseException:
        endpoint.close()
        raise


def _require_scope_lock(scope, lock_identity, identity):
    info = os.stat("scope.lock", dir_fd=scope, follow_symlinks=False)
    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or (info.st_uid, info.st_gid) != identity or [info.st_dev, info.st_ino] != lock_identity):
        raise CustodyRefused("inherited holder scope does not match its pinned lock")


def _verify_descriptor_objects(fds, identity, lock_identity, *, standard):
    objects = set(standard)
    try:
        for purpose, fd in fds.items():
            info = os.fstat(fd)
            object_id = info.st_dev, info.st_ino
            if object_id in objects:
                raise CustodyRefused("inherited role purposes alias the same descriptor object")
            objects.add(object_id)
            if purpose == "scope":
                if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
                        or (info.st_uid, info.st_gid) != identity):
                    raise CustodyRefused("invalid inherited holder scope")
                _require_scope_lock(fd, lock_identity, identity)
            elif purpose != "controller_pidfd":
                if not stat.S_ISSOCK(info.st_mode):
                    raise CustodyRefused("invalid inherited authority socket")
                _socket(os.dup(fd)).close()
    except OSError:
        raise CustodyRefused("inherited role descriptor is unavailable or has the wrong kind") from None


def _protected_probe(path, *, directory=False):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    if directory:
        flags |= os.O_DIRECTORY
    try:
        fd = os.open(path, flags)
    except OSError as failure:
        if failure.errno in _DENY:
            return
        raise CustodyRefused("synthetic protected target not verified") from None
    os.close(fd)
    raise CustodyRefused("synthetic protected target was accessible")


def probe_role(role, config):
    protected = Path(config["registration"])
    peers = [Path("/proc") / str(pid) / "fd" for pid in config["protected_pids"]]
    _protected_probe(protected)
    for path in peers:
        _protected_probe(path, directory=True)
    if role == "worker":
        import json

        job = json.loads(_bounded_regular(config["projection"], 1024))
        if type(job) is not dict or set(job) != JOB_KEYS or job != JOB:
            raise CustodyRefused("worker projection differs")
    return {"protected_reads": 0, "job_readable": role == "worker"}


def intent_for(binding, slot):
    return sha256(canonical(["fixture-turn", binding, slot, "one-synthetic-turn", 1, 1])).hexdigest()


def _binding(registration, profile):
    rows = decode(_bounded_regular(registration, 1024))
    matches = [value for value in rows if type(value) is list and len(value) == 3 and value[0] == profile]
    if (len(matches) != 1 or not all(fingerprint(value) for value in matches[0][1:])):
        raise CustodyRefused("holder binding is missing")
    return sha256(canonical(matches[0])).hexdigest()


def _mark_send(scope, slot):
    name = "send-" + slot
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=scope)
    with os.fdopen(fd, "wb") as stream:
        stream.write(USAGE_BYTES)
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(scope)


def _owner(config, owner_socket, holder, holder_pidfd):
    with Channel(owner_socket, holder, holder_pidfd) as channel:
        if config["fault"] == "owner-exit":
            return {"owner": "exited"}
        frame = ["owner", "launch", config["slot"], config["intent"]]
        if config["fault"] == "wrong-role":
            frame[0] = "worker"
        elif config["fault"] == "wrong-slot":
            frame[2] = "0" * 64
        channel.send(frame)
        if config["fault"] == "revoked":
            channel.endpoint.shutdown(socket.SHUT_WR)
        with channel.endpoint:
            channel.endpoint.settimeout(6)
            if channel.endpoint.recv(1):
                raise CustodyRefused("unexpected traffic on owner channel")
    return {"owner": "closed"}


def _scope_gate(pair, receipt, slot):
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    lock = os.open("scope.lock", flags, dir_fd=pair.directory)
    try:
        pair._require_lock(lock)
        receipt.send(["scope-gate", slot, list(pair.lock_identity)])
        if receipt.receive() != ["scope-gate-open", slot]:
            raise CustodyRefused("controller did not release the scope gate")
        pair._require_lock(lock)
    finally:
        os.close(lock)


def _claim_contender(pair, client, config, claimed, authority):
    revision, slot, profile = config["revision"], config["slot"], config["profile"]
    other = {"first": "second", "second": "first"}[profile]
    expected = pair.commitment(revision, config["phase"])
    proposed = pair.commitment(revision + 1, claimed)
    locked = False
    try:
        with pair.locked():
            locked = True
            current = pair.read()
            if current != expected:
                competing = (pair.commitment(revision + 1, "claimed-" + other),
                             pair.commitment(revision + 2, "settled-" + other))
                if current not in competing:
                    raise CustodyRefused("canonical scope does not contain the other contender")
                client.require(current)
                authority()
                return Refusal.PAIR_MISMATCH
            advance_locked(client, expected, proposed, read_local=pair.read,
                           publish_local=lambda: pair.restore(pair.pair(revision + 1, claimed)),
                           require_authority=authority, dispatch=lambda: _mark_send(pair.directory, slot))
    except Denied as failure:
        if not locked and failure.reason is Refusal.LOCK_BUSY:
            authority()
            return Refusal.LOCK_BUSY
        raise CustodyRefused("contender failed outside canonical scope competition") from failure
    return None


def _holder(config, scope, receipt, owner):
    pair = LocalPair(scope, tuple(config["lock"]))
    grant = OwnerGrant(owner, config["slot"], config["intent"])
    client = ReceiptClient(receipt)
    binding = _binding(config["registration"], config["profile"])
    if not fingerprint(config["slot"]) or intent_for(binding, config["slot"]) != config["intent"]:
        raise CustodyRefused("holder route binding changed")
    revision, phase = config["revision"], config["phase"]
    if type(revision) is not int or revision < 0 or not _PHASE.fullmatch(phase):
        raise CustodyRefused("invalid fixture revision")
    if config["fault"] == "revoked":
        poll = select.poll()
        poll.register(owner.endpoint, select.POLLRDHUP)
        if not poll.poll(1500):
            raise CustodyRefused("revocation was not observable")
    grant.admit()
    if config["fault"] == "replay":
        grant.admit()
    authority = lambda: grant.require_live(config["slot"], config["intent"])
    claimed = "claimed-" + config["profile"]
    settled = "settled-" + config["profile"]
    if config.get("contending"):
        _scope_gate(pair, receipt, config["slot"])
        loss = _claim_contender(pair, client, config, claimed, authority)
        if loss is not None:
            return {"refused": loss.value}
    else:
        pair.advance(client, revision, phase, claimed, authority, lambda: _mark_send(scope, config["slot"]),
                     partial=config["fault"] == "partial")
    pair.advance(client, revision + 1, claimed, settled, authority)
    return {"sends": 1, "settled": True}


def _run_measured(role, config, proc):
    fds = config["fds"]
    primary = Peer(*config["controller"])
    pidfd = fds["controller_pidfd"]
    for descriptor in fds.values():
        os.set_inheritable(descriptor, False)
    received = receive_bootstrap(_socket(fds["bootstrap"]), proc, primary, pidfd,
                                 {purpose: tuple(ids) for purpose, ids in config["purposes"].items()})
    if role == "owner":
        holder, holder_pidfd = received["holder"]
        try:
            return _owner(config, _socket(fds["owner"]), holder, holder_pidfd)
        finally:
            os.close(pidfd)
    owner, owner_pidfd = received["owner"]
    try:
        with (Channel(_socket(fds["receipt"]), primary, pidfd) as receipt,
              Channel(_socket(fds["owner"]), owner, owner_pidfd) as owner_channel):
            return _holder(config, fds["scope"], receipt, owner_channel)
    finally:
        os.close(fds["scope"])


def run_role(role, config, report):
    enable_offline_guard()
    fds = require_role_fds(role, config["fds"])
    descriptors = list(fds.values())
    with proc_self(inherited=descriptors) as proc:
        standard = verify_role_stdio(report, proc=proc)
        uid, gid = verify_role_record(role, config, role_accounts())
        verify_role(proc, uid, gid)
        _verify_descriptor_objects(fds, (uid, gid), config.get("lock"), standard=standard)
        for descriptor in descriptors:
            os.set_inheritable(descriptor, False)
        if role in ("owner", "holder"):
            verified = verify_root_parent(proc, assertion=config["controller"], pidfd=config["fds"]["controller_pidfd"])
            config = {**config, "controller": [verified.pid, verified.uid, verified.gid]}
            try:
                return _run_measured(role, config, proc)
            except Denied as failure:
                return {"refused": failure.reason.value}
        verify_root_parent(proc)
        if role == "legacy":
            from legacy import run_legacy

            return run_legacy(config["scratch"], Path(config["legacy"]), config["protected"])
        if role in ("legacy-probe", "sibling", "worker"):
            return probe_role(role, config)
    raise CustodyRefused("unknown measured role")
