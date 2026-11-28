"""One-shot controller bootstrap for the Linux custody fixture."""

from array import array
from contextlib import contextmanager
import fcntl
import os
import pwd
import select
import socket
import stat
import struct

from descriptor import Peer, canonical, decode


_PACKET_MAX = 1024
_PROC_MAX = 16384
_PROC_SUPER_MAGIC = 0x9FA0
_CRED = struct.Struct("=iii")
_INT_BYTES = array("i").itemsize
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


ACCOUNTS = {"holder": "r3holder", "owner": "r3owner", "legacy": "r3legacy", "worker": "r3worker"}
PEER_PURPOSES = {"owner": ("holder",), "holder": ("owner",)}


class CustodyRefused(RuntimeError):
    """The synthetic run must stop without using the supplied authority."""


def _read_text(directory, name, maximum):
    fd = os.open(name, _FILE, dir_fd=directory)
    with os.fdopen(fd, "rb") as handle:
        raw = handle.read(maximum + 1)
    if len(raw) > maximum:
        raise CustodyRefused("kernel record exceeds bound")
    return raw.decode("ascii")


def _field(text, key):
    prefix = key + ":"
    values = [line[len(prefix):].split() for line in text.splitlines() if line.startswith(prefix)]
    if len(values) != 1:
        raise CustodyRefused("missing or duplicate kernel field")
    return values[0]


def _native_procfs(descriptor):
    import ctypes

    # The first native-long field of Linux struct statfs is the filesystem
    # type. The aligned buffer is larger than Linux's supported statfs structs.
    data = (ctypes.c_long * 32)()
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.fstatfs(descriptor, ctypes.byref(data)) != 0 or data[0] != _PROC_SUPER_MAGIC:
        raise CustodyRefused("procfs identity unavailable")


@contextmanager
def proc_self(*, inherited=None):
    proc = os.open("/proc", _DIRECTORY)
    try:
        own = str(os.getpid())
        if os.readlink("self", dir_fd=proc) != own:
            raise CustodyRefused("procfs PID view disagrees")
        self_dir = os.open(own, _DIRECTORY, dir_fd=proc)
        try:
            # Inventory only inherited authority. Loading ctypes can create
            # a verifier-owned library FD, so check before loading it.
            if inherited is not None:
                verify_descriptors(self_dir, inherited, proc_root=proc)
            _native_procfs(proc)
            status = _read_text(self_dir, "status", _PROC_MAX)
            if _field(status, "Pid") != [own] or _field(status, "NSpid") != [own]:
                raise CustodyRefused("unexpected PID namespace view")
            yield self_dir
        finally:
            os.close(self_dir)
    finally:
        os.close(proc)


def _require_alive(pidfd):
    poll = select.poll()
    poll.register(pidfd, select.POLLIN)
    if poll.poll(0):
        raise CustodyRefused("pinned peer exited")


def verify_pidfd(proc, pidfd, expected_pid):
    if type(expected_pid) is not int or expected_pid <= 0 or os.get_inheritable(pidfd):
        raise CustodyRefused("invalid expected process descriptor")
    _require_alive(pidfd)
    info_dir = os.open("fdinfo", _DIRECTORY, dir_fd=proc)
    try:
        record = _read_text(info_dir, str(pidfd), _PACKET_MAX)
    finally:
        os.close(info_dir)
    expected = [str(expected_pid)]
    if _field(record, "Pid") != expected or _field(record, "NSpid") != expected:
        raise CustodyRefused("pidfd does not identify expected process")
    _require_alive(pidfd)


def role_accounts():
    roles = {}
    for role, name in ACCOUNTS.items():
        record = pwd.getpwnam(name)
        roles[role] = record.pw_uid, record.pw_gid
    if (len({uid for uid, _ in roles.values()}) != len(roles)
            or len({gid for _, gid in roles.values()}) != len(roles)
            or any(not uid or not gid for uid, gid in roles.values())):
        raise CustodyRefused("isolated guest roles not provisioned")
    return {**roles, "legacy-probe": roles["legacy"], "sibling": roles["legacy"]}


def verify_role_record(role, config, identities):
    expected = identities.get(role)
    claimed = config["uid"], config["gid"]
    if expected is None or any(type(value) is not int for value in claimed) or claimed != expected:
        raise CustodyRefused("role cannot select its own account")
    purposes = {name: list(identities[name]) for name in PEER_PURPOSES.get(role, ())}
    if config.get("purposes", {}) != purposes:
        raise CustodyRefused("role cannot select expected peer accounts")
    return expected


def _parent_status(pid):
    root = os.open("/proc", _DIRECTORY)
    try:
        _native_procfs(root)
        descriptor = os.open(str(pid), _DIRECTORY, dir_fd=root)
        try:
            return _read_text(descriptor, "status", _PROC_MAX)
        finally:
            os.close(descriptor)
    finally:
        os.close(root)


def verify_root_parent(proc, *, assertion=None, pidfd=None):
    parent = os.getppid()
    expected = Peer(parent, 0, 0)
    if parent <= 1 or (assertion is not None and assertion != [parent, 0, 0]):
        raise CustodyRefused("immediate root controller identity disagrees")
    if pidfd is not None:
        verify_pidfd(proc, pidfd, parent)
    status = _parent_status(parent)
    if (_field(status, "Pid") != [str(parent)] or _field(status, "NSpid") != [str(parent)]
            or _field(status, "Uid") != ["0"] * 4 or _field(status, "Gid") != ["0"] * 4
            or os.getppid() != parent):
        raise CustodyRefused("non-root or displaced controller parent")
    if pidfd is not None:
        verify_pidfd(proc, pidfd, parent)
    return expected


def verify_role(proc, uid, gid):
    status = _read_text(proc, "status", _PROC_MAX)
    if (_field(status, "Uid") != [str(uid)] * 4 or _field(status, "Gid") != [str(gid)] * 4
            or _field(status, "Groups") or _field(status, "NoNewPrivs") != ["1"]
            or os.getsid(0) != os.getpid()):
        raise CustodyRefused("unexpected role credentials or session")
    for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        value = _field(status, field)
        if len(value) != 1 or value[0] != "0000000000000000":
            raise CustodyRefused("retained role capabilities")


def _descriptor_id(info):
    return info.st_dev, info.st_ino


def _require_access(fd, access):
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    if flags & os.O_PATH or flags & os.O_ACCMODE != access:
        raise CustodyRefused("fixture standard descriptor has unexpected access direction")


def verify_role_stdio(report, *, proc=None):
    """Verify role stdio before inputs, including the controller-pinned pipe."""
    null = os.stat("/dev/null", follow_symlinks=False)
    if not stat.S_ISCHR(null.st_mode) or (os.major(null.st_rdev), os.minor(null.st_rdev)) != (1, 3):
        raise CustodyRefused("fixed null device unavailable")
    for fd, direction in ((0, os.O_RDONLY), (2, os.O_WRONLY)):
        held = os.fstat(fd)
        if not stat.S_ISCHR(held.st_mode) or held.st_rdev != null.st_rdev or _descriptor_id(held) != _descriptor_id(null):
            raise CustodyRefused("unexpected fixture null descriptor")
        _require_access(fd, direction)

    writer = os.fstat(1)
    identity = _descriptor_id(writer)
    if not stat.S_ISFIFO(writer.st_mode) or identity != report:
        raise CustodyRefused("unexpected fixture report descriptor")
    _require_access(1, os.O_WRONLY)
    name = os.readlink("/proc/self/fd/1") if proc is None else os.readlink("fd/1", dir_fd=proc)
    if name != f"pipe:[{writer.st_ino}]":
        raise CustodyRefused("fixture report descriptor is not an anonymous pipe")
    return {_descriptor_id(null), identity}


def verify_descriptors(proc, allowed, *, proc_root):
    for fd in (0, 1, 2):
        if stat.S_ISSOCK(os.fstat(fd).st_mode):
            with socket.socket(fileno=os.dup(fd)) as endpoint:
                if endpoint.family != socket.AF_UNIX:
                    raise CustodyRefused("unexpected Internet descriptor")
    directory = os.open("fd", _DIRECTORY, dir_fd=proc)
    try:
        # listdir(fd) uses an internal duplicate which is already closed
        # on return. Report only still-open entries from the kernel listing.
        observed = set()
        for name in os.listdir(directory):
            try:
                os.fstat(int(name))
            except OSError:
                continue
            observed.add(int(name))
        if observed != {0, 1, 2, proc, proc_root, directory, *allowed}:
            raise CustodyRefused("unexpected role descriptors")
    finally:
        os.close(directory)


def _send(endpoint, frame, fds=()):
    message = canonical(frame)
    if len(message) > _PACKET_MAX:
        raise CustodyRefused("bootstrap payload exceeds bound")
    fds = array("i", fds)
    controls = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)] if fds else []
    if endpoint.sendmsg([message], controls) != len(message):
        raise CustodyRefused("incomplete bootstrap send")


def send_bootstrap(endpoint, peers, descriptors):
    purposes = list(peers)
    rows = [[name, peers[name].pid, peers[name].uid, peers[name].gid] for name in purposes]
    _send(endpoint, ["r3", "peers", rows])
    _send(endpoint, ["r3", "pidfds", purposes], [descriptors[name] for name in purposes])


def _controls(message, descriptors):
    identities = []
    rights_messages = 0
    valid = True
    for level, kind, data in message:
        if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
            rights_messages += 1
            full = len(data) // _INT_BYTES * _INT_BYTES
            rights = array("i")
            rights.frombytes(data[:full])
            descriptors.extend(rights)
            valid = valid and bool(full) and full == len(data)
        elif (level, kind) == (socket.SOL_SOCKET, socket.SCM_CREDENTIALS) and len(data) == _CRED.size:
            identities.append(Peer(*_CRED.unpack(data)))
        else:
            valid = False
    return identities, rights_messages, valid


def _close_fds(descriptors):
    for descriptor in descriptors:
        os.close(descriptor)


def _receive(endpoint, controller, pidfd, count):
    _require_alive(pidfd)
    ancillary = socket.CMSG_SPACE(_CRED.size) + socket.CMSG_SPACE(_INT_BYTES * max(count, 1))
    packet, controls, flags, _ = endpoint.recvmsg(_PACKET_MAX, ancillary, socket.MSG_CMSG_CLOEXEC)
    descriptors = []
    try:
        identities, rights_messages, valid = _controls(controls, descriptors)
        if (flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or identities != [controller] or not valid
                or len(descriptors) != count or rights_messages != int(count > 0)):
            raise CustodyRefused("unexpected bootstrap ancillary data")
        _require_alive(pidfd)
        return decode(packet), descriptors
    except BaseException:
        _close_fds(descriptors)
        raise


def _parse_peers(message, role_ids, controller):
    if len(message) != 3 or message[:2] != ["r3", "peers"] or type(message[2]) is not list:
        raise CustodyRefused("invalid bootstrap metadata")
    expected = list(role_ids)
    rows = message[2]
    if len(rows) != len(expected):
        raise CustodyRefused("unexpected bootstrap roles")
    peers = {}
    seen = {controller.pid}
    for name, row in zip(expected, rows):
        if (type(row) is not list or len(row) != 4 or row[0] != name
                or any(type(value) is not int for value in row[1:])
                or row[1] <= 0 or row[1] in seen or tuple(row[2:]) != role_ids[name]):
            raise CustodyRefused("unexpected bootstrap role identity")
        peers[name] = Peer(*row[1:])
        seen.add(row[1])
    return peers


def receive_bootstrap(endpoint, proc, controller, controller_pidfd, role_ids):
    """Return validated peers and owned pidfds. The bootstrap endpoint always closes."""
    with endpoint:
        endpoint.set_inheritable(False)
        endpoint.settimeout(2)
        verify_pidfd(proc, controller_pidfd, controller.pid)
        metadata, _ = _receive(endpoint, controller, controller_pidfd, 0)
        peers = _parse_peers(metadata, role_ids, controller)
        frame, descriptors = _receive(endpoint, controller, controller_pidfd, len(peers))
        try:
            if frame != ["r3", "pidfds", list(peers)]:
                raise CustodyRefused("unexpected bootstrap descriptor purposes")
            for peer, fd in zip(peers.values(), descriptors):
                verify_pidfd(proc, fd, peer.pid)
            _require_alive(controller_pidfd)
            return {role: (peer, fd) for (role, peer), fd in zip(peers.items(), descriptors)}
        except BaseException:
            _close_fds(descriptors)
            raise
