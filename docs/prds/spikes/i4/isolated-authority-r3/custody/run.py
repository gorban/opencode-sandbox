#!/usr/bin/python3
"""Build, check or run the synthetic R3 sealed appliance fixture."""

from contextlib import ExitStack
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
import os
import re
from pathlib import Path
import secrets
import selectors
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from threading import Barrier, BrokenBarrierError
import time


_SCRIPT = Path(__file__).resolve(strict=True)
_SOURCE = Path("/opt/oc-r3/appliance")
_SEALED_RUNNER = _SOURCE / "custody" / "run.py"
if __name__ == "__main__":
    sealed_entry = sys.argv[1:2] in (["sealed"], ["restart"])
    if sealed_entry or os.geteuid() == 0:
        if (not sealed_entry or os.geteuid() != 0 or _SCRIPT != _SEALED_RUNNER
                or len(sys.argv) < 3 or os.environ != {"OC_R3_PREIMPORT": sys.argv[2]}):
            if sys.argv[1:2] != ["role"]:
                print('{"result":"sealed_unavailable"}')
            sys.exit(2)
# The sealed service invokes the fixed interpreter in isolated mode. The
# normal-user build command supports the checked-out source arrangement.
sys.path[:0] = [str(_SCRIPT.parent), str(_SCRIPT.parent.parent / "spike"), str(_SCRIPT.parent.parent)]

from bootstrap import (
    ACCOUNTS, CustodyRefused, _read_text, proc_self, role_accounts, send_bootstrap,
    verify_pidfd, verify_role_stdio,
)
from descriptor import Channel, Denied, Peer, Refusal, canonical, descriptor_pair, fingerprint
from measurement import build_bundle
from preflight import CORRECTED_OVERLAY, PLAN_OVERLAY, MeasurementRefused, verify_bundle
from restart import capture, lifetime, load_retained, require_retired, retain, retained_paths, verify_retained
from receipt import ReceiptStore, serve_receipts
from roles import JOB, USAGE_BYTES, intent_for, require_role_fds, run_role
from test_receipt import LocalPair


_HOLDER_MOUNT = Path("/mnt/r3h")
_RECEIPT_MOUNT = Path("/mnt/r3c")
_SCRATCH_ROOT = Path("/run/oc-r3")
_SCRATCH_ANCESTOR_MODE = 0o755
_OPEN_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_POSITIVE_LEGACY = {"canonical": 1, "alternate": 1, "canary": 1, "proof": 3, "ordinary": 1, "protected": 0}
_FAILURE = {"refused": "custody_refused"}
_MAX_REPORT = 1024


class Unavailable(CustodyRefused):
    """Sealed placement or its prerequisites are absent."""


def _require(condition, error):
    if not condition:
        raise CustodyRefused(error)


def _private_root(path, mode):
    info = path.lstat()
    if (path.resolve(strict=True) != path or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != mode):
        raise Unavailable("unsafe fixture root")
    return info


def _mount_identity(path, proc):
    info = _private_root(path, 0o711)
    descriptor = os.open(path, _OPEN_DIR)
    fdinfo = os.open("fdinfo", _OPEN_DIR, dir_fd=proc)
    try:
        fd_record = _read_text(fdinfo, str(descriptor), 1024)
    finally:
        os.close(fdinfo)
        os.close(descriptor)
    identifiers = [line.split()[1] for line in fd_record.splitlines() if line.startswith("mnt_id:")]
    if len(identifiers) != 1 or not identifiers[0].isdecimal():
        raise Unavailable("missing fixture mount identity")
    mount_id = identifiers[0]
    mounts = _read_text(proc, "mountinfo", 1 << 20)
    if not any(parts[:1] == [mount_id] and parts[4:5] == [str(path)]
               for parts in (line.split() for line in mounts.splitlines())):
        raise Unavailable("fixture root is not the expected mount")
    return mount_id, info.st_dev


def _sealed_preflight(pin, evidence):
    if (os.geteuid() != 0 or _SCRIPT != _SEALED_RUNNER
            or not sys.flags.isolated or not sys.flags.no_site or not sys.flags.dont_write_bytecode
            or not fingerprint(pin) or not fingerprint(evidence)):
        raise Unavailable("sealed service preconditions unavailable")
    if os.environ != {"OC_R3_PREIMPORT": pin}:
        raise Unavailable("independent pre-import measurement required")
    if not {name for _, name in socket.if_nameindex()} <= {"lo"}:
        raise Unavailable("guest network adapter must be detached")
    if set(os.listdir("/sys/class/net")) - {"lo"}:
        raise Unavailable("guest network device detected")
    try:
        _private_root(_SCRATCH_ROOT, _SCRATCH_ANCESTOR_MODE)
        with proc_self(inherited=()) as proc:
            holder = _mount_identity(_HOLDER_MOUNT, proc)
            receipt = _mount_identity(_RECEIPT_MOUNT, proc)
        measured = verify_bundle(_SOURCE, pin, sealed=True)
        identities = role_accounts()
    except (KeyError, OSError, CustodyRefused, MeasurementRefused):
        raise Unavailable("sealed appliance prerequisites unavailable") from None
    if measured["overlay"] != CORRECTED_OVERLAY:
        raise Unavailable("independently reviewed receipt overlay required")
    if holder[0] == receipt[0] or holder[1] == receipt[1]:
        raise Unavailable("receipt and holder must use different filesystems")
    return identities, holder, receipt


def _role_command(uid, gid, role):
    return ["/usr/bin/setpriv", "--reuid", str(uid), "--regid", str(gid), "--clear-groups",
            "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all", "--no-new-privs", "--",
            "/usr/bin/python3", "-I", "-S", "-B", str(_SCRIPT), "role", role]


def _retire_role(process):
    try:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=4)
    finally:
        process.stdout.close()


def _spawn_report(command, env, inherited, children):
    cleanup_failures = []

    def close_parent(fd):
        try:
            os.close(fd)
        except OSError as failure:
            cleanup_failures.append(failure)

    process = None
    reader = None
    try:
        with ExitStack() as opened:
            flags = os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            stdin = os.open("/dev/null", os.O_RDONLY | flags)
            opened.callback(close_parent, stdin)
            stderr = os.open("/dev/null", os.O_WRONLY | flags)
            opened.callback(close_parent, stderr)
            incoming, outgoing = os.pipe2(os.O_CLOEXEC)
            opened.callback(close_parent, outgoing)
            try:
                reader = os.fdopen(incoming, "rb")
            except BaseException:
                close_parent(incoming)
                raise
            identity = os.fstat(outgoing)
            process = subprocess.Popen(
                [*command, str(identity.st_dev), str(identity.st_ino)], env=env,
                stdin=stdin, stdout=outgoing, stderr=stderr,
                close_fds=True, pass_fds=tuple(inherited), start_new_session=True,
            )
            process.stdout = reader
            children.append(process)
        if cleanup_failures:
            raise cleanup_failures.pop(0)
    except BaseException as primary:
        try:
            if process is not None:
                _retire_role(process)
            elif reader is not None:
                reader.close()
        except (OSError, subprocess.TimeoutExpired) as failure:
            primary.add_note(f"Measured role cleanup failed ({type(failure).__name__})")
        if cleanup_failures:
            primary.add_note("Parent descriptor cleanup also failed")
        raise
    return process


def _write_owned(path, data, identity):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        os.fchown(handle.fileno(), *identity)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _read_report(process):
    deadline = time.monotonic() + 12
    stdout = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise CustodyRefused("measured role exceeded deadline")
            chunk = os.read(process.stdout.fileno(), _MAX_REPORT + 1 - len(stdout))
            if not chunk:
                break
            stdout.extend(chunk)
            if len(stdout) > _MAX_REPORT:
                raise CustodyRefused("measured role report exceeds bound")
    try:
        status = process.wait(timeout=max(0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        raise CustodyRefused("measured role exceeded deadline") from None
    if status not in (0, 3):
        raise CustodyRefused("unexpected measured role exit")
    try:
        result = json.loads(stdout)
    except ValueError:
        raise CustodyRefused("invalid measured role report") from None
    if type(result) is not dict:
        raise CustodyRefused("invalid measured role report")
    return result


def _history(root):
    evidence = {}
    for index, path in enumerate(root.rglob("*")):
        if index >= 512 or len(path.relative_to(root).parts) > 12:
            raise CustodyRefused("legacy evidence exceeds bounds")
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if (not stat.S_ISREG(info.st_mode) or info.st_size > 1 << 18 or info.st_nlink != 1
                or len(evidence) >= 256):
            raise CustodyRefused("unsafe legacy evidence path")
        evidence[str(path.relative_to(root))] = sha256(path.read_bytes()).digest()
    return evidence


def _peer(process, identity):
    return Peer(process.pid, *identity)


class Appliance:
    def __init__(self, identities):
        self.identities = {**identities, "sibling": identities["legacy"], "legacy-probe": identities["legacy"]}
        self.group = Path(tempfile.mkdtemp(prefix="r", dir=_SCRATCH_ROOT))
        self.group.chmod(_SCRATCH_ANCESTOR_MODE)
        self.receipt = _RECEIPT_MOUNT / ("r" + secrets.token_hex(16))
        self.receipt.mkdir(mode=0o700)
        self.scope = Path(tempfile.mkdtemp(prefix="r", dir=_HOLDER_MOUNT))
        self.children = []
        self.stored = [self.group, self.scope, self.receipt]
        self.roots = {root: (root.stat().st_dev, root.stat().st_ino) for root in self.stored}
        self.homes = {}
        for role in ACCOUNTS:
            path = self.group / role
            path.mkdir(mode=0o700)
            os.chown(path, *identities[role])
            self.homes[role] = path
        scope_owner = identities["holder"]
        os.chown(self.scope, *scope_owner)
        self.legacy_home = self.homes["legacy"]
        self.registration = self.scope / "r"
        self.rows = [[name, secrets.token_hex(32), secrets.token_hex(32)] for name in ("first", "second")]
        _write_owned(self.registration, canonical(self.rows), scope_owner)
        self.projection = self.homes["worker"] / "job"
        _write_owned(self.projection, json.dumps(JOB, separators=(",", ":")).encode(), identities["worker"])
        self.scope_fd = os.open(self.scope, _OPEN_DIR)
        self.lock = os.open("scope.lock", os.O_RDONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                            0o600, dir_fd=self.scope_fd)
        os.fchown(self.lock, *scope_owner)
        lock = os.fstat(self.lock)
        self.local = LocalPair(self.scope_fd, (lock.st_dev, lock.st_ino))
        self.initial = self.local.pair(0, "initial")
        self.restore(self.initial)
        self.store = ReceiptStore(self.receipt, self.local.commitment(0, "initial"))
        self.store.provision()

    def restore(self, pair):
        self.local.restore(pair)
        for name in ("journal", "anchor"):
            os.chown(name, *self.identities["holder"], dir_fd=self.scope_fd, follow_symlinks=False)
        os.fsync(self.scope_fd)

    def spawn(self, role, config, fds=None):
        uid, gid = self.identities[role]
        inherited = require_role_fds(role, {} if fds is None else fds)
        full = {**config, "uid": uid, "gid": gid, "fds": inherited}
        encoded = json.dumps(full, separators=(",", ":"))
        if len(encoded) > 8192:
            raise CustodyRefused("role config exceeds limit")
        home = self.homes["legacy" if role in ("legacy-probe", "sibling") else role]
        return _spawn_report(_role_command(uid, gid, role), {"HOME": str(home), "OC_R3_ROLE": encoded},
                             inherited.values(), self.children)

    def count(self):
        files = sorted(self.scope.glob("send-*"))
        if len(files) > 2 or any(file.read_bytes() != USAGE_BYTES for file in files):
            raise CustodyRefused("invalid fixture counter evidence")
        return len(files)

    def launch(self, stack, pool, revision, phase, profile, *, fault="none", route_mismatch=False, gate=None):
        controller_sock, receipt = descriptor_pair()
        holder_sock, owner_sock = descriptor_pair()
        holder_root, holder_boot = descriptor_pair()
        owner_root, owner_boot = descriptor_pair()
        for endpoint in (controller_sock, receipt, holder_sock, owner_sock, holder_root, holder_boot, owner_root, owner_boot):
            stack.enter_context(endpoint)
        controller_pidfd = os.pidfd_open(os.getpid())
        stack.callback(os.close, controller_pidfd)
        root = Peer(os.getpid(), os.getuid(), os.getgid())
        slot = secrets.token_hex(32)
        row = next(row for row in self.rows if row[0] == profile)
        requested = [profile, "0" * 64, row[-1]] if route_mismatch else row
        intent = intent_for(sha256(canonical(requested)).hexdigest(), slot)
        common = {"controller": [root.pid, root.uid, root.gid], "slot": slot, "intent": intent, "fault": fault}
        owner = self.spawn("owner", {**common, "purposes": {"holder": self.identities["holder"]}},
                           {"controller_pidfd": controller_pidfd, "bootstrap": owner_boot.fileno(),
                            "owner": owner_sock.fileno()})
        holder = self.spawn("holder", {**common, "purposes": {"owner": self.identities["owner"]},
                                       "profile": profile, "registration": str(self.registration), "revision": revision,
                                       "phase": phase, "lock": self.local.lock_identity, "contending": gate is not None},
                            {"controller_pidfd": controller_pidfd, "bootstrap": holder_boot.fileno(),
                             "owner": holder_sock.fileno(), "receipt": receipt.fileno(), "scope": self.scope_fd})
        for endpoint in (owner_boot, owner_sock, holder_boot, holder_sock, receipt):
            endpoint.close()
        owner_pin = os.pidfd_open(owner.pid)
        stack.callback(os.close, owner_pin)
        holder_pin = os.pidfd_open(holder.pid)
        stack.callback(os.close, holder_pin)
        with proc_self() as proc:
            verify_pidfd(proc, owner_pin, owner.pid)
            verify_pidfd(proc, holder_pin, holder.pid)
        controller = stack.enter_context(Channel(controller_sock, _peer(holder, self.identities["holder"]),
                                                 os.dup(holder_pin)))
        if gate is None:
            server = pool.submit(serve_receipts, controller, self.store)
        else:
            server = pool.submit(_serve_contender, controller, self.store, gate, slot, self.local.lock_identity)
        return (owner, holder, owner_root, holder_root, owner_pin, holder_pin, controller, server)

    def release(self, job, *, wrong_peer=False):
        owner, holder, owner_root, holder_root, owner_pin, holder_pin, *_ = job
        with owner_root, holder_root, ExitStack() as opened:
            if wrong_peer:
                owner_pin = os.pidfd_open(os.getpid())
                opened.callback(os.close, owner_pin)
            send_bootstrap(owner_root, {"holder": _peer(holder, self.identities["holder"])}, {"holder": holder_pin})
            send_bootstrap(holder_root, {"owner": _peer(owner, self.identities["owner"])}, {"owner": owner_pin})

    @staticmethod
    def report(job):
        owner, holder, *_, controller, server = job
        try:
            result = _read_report(holder)
            owner_result = _read_report(owner)
            _require(owner_result in ({"owner": "closed"}, {"owner": "exited"}, _FAILURE,
                                      {"refused": "lost_endpoint"}), "unexpected owner report")
            return result
        finally:
            controller.close()
            server.result(timeout=3)

    def probe(self, job):
        owner, holder, *_ = job
        test_config = {"protected_pids": [owner.pid, holder.pid], "registration": str(self.registration),
                       "projection": str(self.projection)}
        probes = {role: self.spawn(role, test_config) for role in ("legacy-probe", "sibling", "worker")}
        for role, process in probes.items():
            result = _read_report(process)
            _require(result == {"protected_reads": 0, "job_readable": role == "worker"},
                     "fixture custody exclusion failed")

    def drain(self, primary=None):
        failures = []

        def attempt(retire, resource):
            try:
                retire(resource)
            except (OSError, subprocess.TimeoutExpired) as failure:
                failures.append(failure)

        for process in reversed(self.children):
            attempt(_retire_role, process)
        for descriptor in (self.lock, self.scope_fd):
            attempt(os.close, descriptor)
        if failures and primary is not None:
            primary.add_note("Measured appliance retirement was incomplete")
        elif failures:
            raise failures[0]

    def cleanup(self):
        for root, expected in self.roots.items():
            info = root.lstat()
            _require((info.st_dev, info.st_ino) == expected and stat.S_ISDIR(info.st_mode)
                     and shutil.rmtree.avoids_symlink_attacks, "scratch identity changed")
        for root in self.stored:
            shutil.rmtree(root)


def _one(appliance, revision, phase, profile, *, wrong_peer=False, **options):
    with ExitStack() as stack, ThreadPoolExecutor(max_workers=1) as pool:
        job = appliance.launch(stack, pool, revision, phase, profile, **options)
        appliance.release(job, wrong_peer=wrong_peer)
        return appliance.report(job)


def _serve_contender(channel, store, gate, slot, lock):
    _require(channel.receive() == ["scope-gate", slot, list(lock)], "wrong canonical contention gate")
    try:
        gate.wait()
    except BrokenBarrierError:
        raise CustodyRefused("both exact holders did not reach the canonical scope gate") from None
    channel.send(["scope-gate-open", slot])
    serve_receipts(channel, store)


def _contending(appliance):
    accepted = {"sends": 1, "settled": True}
    canonical_losses = ({"refused": Refusal.LOCK_BUSY.value}, {"refused": Refusal.PAIR_MISMATCH.value})
    gate = Barrier(2, timeout=2)
    with ExitStack() as stack, ThreadPoolExecutor(max_workers=2) as pool:
        first = appliance.launch(stack, pool, 0, "initial", "first", gate=gate)
        second = appliance.launch(stack, pool, 0, "initial", "second", gate=gate)
        appliance.probe(first)
        _require(appliance.count() == 0, "exclusive probes changed holder counter")
        appliance.release(first)
        appliance.release(second)
        results = [appliance.report(first), appliance.report(second)]
    _require(results.count(accepted) == 1 and appliance.count() == 1
             and any(result in canonical_losses for result in results), "contending launch verdict mismatch")
    return "second" if results[0] == accepted else "first"


def _accept(appliance):
    legacy = _read_report(appliance.spawn("legacy", {"scratch": str(appliance.legacy_home),
                                                     "legacy": str(_SOURCE / "legacy"),
                                                     "protected": str(appliance.scope)}))
    _require(legacy == _POSITIVE_LEGACY, "exact legacy paths did not match")
    old = _history(appliance.legacy_home)
    _require(appliance.count() == 0, "legacy changed holder counter")
    accepted = {"sends": 1, "settled": True}
    for fault in ("owner-exit", "wrong-role", "wrong-slot", "replay", "revoked"):
        result = _one(appliance, 0, "initial", "first", fault=fault)
        _require("refused" in result and appliance.count() == 0
                 and appliance.local.read() == appliance.store.head(), "bad owner grant changed holder state")
    result = _one(appliance, 0, "initial", "first", wrong_peer=True)
    _require(result == _FAILURE and appliance.count() == 0, "wrong peer descriptor was admitted")
    result = _one(appliance, 0, "initial", "first", route_mismatch=True)
    _require(result == _FAILURE and appliance.count() == 0, "wrong holder binding was admitted")

    lost = _contending(appliance)
    settled = "settled-first" if lost == "second" else "settled-second"
    _require(_one(appliance, 2, settled, lost) == accepted and appliance.count() == 2,
             "holder restart and second profile failed")
    latest = appliance.store.head()
    _require(latest.revision == 4 and latest == appliance.local.read(), "holder settlement mismatch")
    unverified = ReceiptStore(appliance.receipt, appliance.local.commitment(0, "initial"))
    try:
        unverified.head()
    except Denied as failure:
        _require(failure.reason == Refusal.RECONCILIATION_REQUIRED, "wrong controller restart result")
    else:
        raise CustodyRefused("controller reconstructed authority")
    exact_settled_pair = appliance.local.snapshot()
    appliance.restore(appliance.initial)
    result = _one(appliance, 0, "initial", "first")
    _require(result == {"refused": "pair_mismatch"} and appliance.count() == 2 and appliance.store.head() == latest,
             "stale holder pair was accepted")
    appliance.restore(exact_settled_pair)
    _require(appliance.local.read() == latest and _history(appliance.legacy_home) == old,
             "holder or legacy retained evidence differs")
    return {"same_pid_store_refused": True, "holder_sends": 2, "legacy_sends": sum(legacy.values()), "legacy_history_preserved": True,
            "protected_reads": 0, "worker_job_readable": True, "holder_only_restore_refused": True}


def _accept_failures(identities):
    for fault, expected in (("partial", "pair_mismatch"), ("receipt-loss", "missing_receipt")):
        appliance = Appliance(identities)
        try:
            if fault == "receipt-loss":
                (appliance.receipt / "continuity.json").unlink()
            result = _one(appliance, 0, "initial", "first", fault=fault)
            _require(result == {"refused": expected} and appliance.count() == 0,
                     "partial or lost fixture state was accepted")
            if fault == "partial":
                _require(appliance.store.head().revision == 0, "partial local publication updated the receipt")
            else:
                _require(appliance.local.snapshot() == appliance.initial
                         and not (appliance.receipt / "continuity.json").exists(), "receipt loss was repaired")
        except BaseException as primary:
            appliance.drain(primary)
            raise
        appliance.drain()
        appliance.cleanup()


def _retained_ids(roles):
    return {"controller": 0, "holder": roles["holder"][0], "legacy": roles["legacy"][0]}


def _sealed(pin, evidence):
    roles, holder, receipt = _sealed_preflight(pin, evidence)
    controller = lifetime()
    appliance = Appliance(roles)
    try:
        result = _accept(appliance)
        initial = appliance.local.commitment(0, "initial").wire()
        head = appliance.store.head().wire()
    except BaseException as primary:
        appliance.drain(primary)
        raise
    appliance.drain()
    _accept_failures(roles)
    state = {
        "controller": controller, "children_reaped": True, "bundle_pin": pin, "storage_pin": evidence,
        "holder_mount": list(holder), "receipt_mount": list(receipt), "scope": appliance.scope.name,
        "scratch": appliance.group.name, "scratch_inode": list(appliance.roots[appliance.group]),
        "lock": list(appliance.local.lock_identity), "initial": initial, "head": head,
        "snapshot": capture(appliance.receipt, appliance.scope, appliance.legacy_home, _retained_ids(roles)),
    }
    retain(appliance.receipt, state)
    return {**result, "partial_and_loss_refused": True, "holder_mount": list(holder), "receipt_mount": list(receipt),
            "external_custody_evidence": evidence, "restart_handle": appliance.receipt.name,
            "result": "sealed_synthetic_retained"}


def _restart(pin, evidence, handle):
    roles, holder, controller_volume = _sealed_preflight(pin, evidence)
    if not re.fullmatch(r"r[0-9a-f]{32}", handle):
        raise Unavailable("invalid restart fixture handle")
    try:
        state = load_retained(_RECEIPT_MOUNT / handle, 0)
        _require(state["children_reaped"] is True and state["bundle_pin"] == pin and state["storage_pin"] == evidence
                 and state["holder_mount"] == list(holder) and state["receipt_mount"] == list(controller_volume),
                 "retained installation does not match")
        receipt, scope, legacy = retained_paths(handle, _HOLDER_MOUNT, _RECEIPT_MOUNT, _SCRATCH_ROOT, state)
        scratch = _private_root(legacy.parent, _SCRATCH_ANCESTOR_MODE)
        _require([scratch.st_dev, scratch.st_ino] == state["scratch_inode"], "retained scratch root changed")
        fresh = require_retired(state["controller"])
        _require(capture(receipt, scope, legacy, _retained_ids(roles)) == state["snapshot"],
                 "retained installation cannot be verified")
    except (CustodyRefused, Denied, OSError, KeyError, TypeError, ValueError):
        raise Unavailable("retained installation unavailable") from None
    result = verify_retained(receipt, scope, legacy, _retained_ids(roles), state)
    _require(shutil.rmtree.avoids_symlink_attacks, "scratch cleanup guard unavailable")
    for path, expected in ((legacy.parent, state["scratch_inode"]),
                           (scope, state["snapshot"]["scope"][:2]), (receipt, state["snapshot"]["receipt"][:2])):
        info = path.lstat()
        _require(stat.S_ISDIR(info.st_mode) and [info.st_dev, info.st_ino] == expected,
                 "retained fixture identity changed during cleanup")
    for root in (legacy.parent, scope, receipt):
        shutil.rmtree(root)
    return {**result, "original_lifetime": sha256(canonical(state["controller"])).hexdigest(),
            "fresh_lifetime": sha256(canonical(fresh)).hexdigest(), "external_custody_evidence": evidence,
            "result": "sealed_restart_refused"}


def _role_main(role, report):
    if os.geteuid() == 0 or _SCRIPT != _SEALED_RUNNER or not sys.flags.isolated:
        raise Unavailable("measured child entry unavailable")
    if set(os.environ) != {"HOME", "OC_R3_ROLE"} or len(os.environ["OC_R3_ROLE"]) > 8192:
        raise Unavailable("invalid measured child environment")
    config = json.loads(os.environ["OC_R3_ROLE"])
    if role == "legacy":
        sys.path[:0] = [str(_SOURCE / "legacy"), str(_SOURCE / "legacy" / "tests")]
    return run_role(role, config, report)


def _entry(args, report):
    if len(args) in (3, 4) and args[0] == "bundle" and os.geteuid() != 0:
        pin = build_bundle(args[1], args[2], args[3] if len(args) == 4 else PLAN_OVERLAY)
        return {"manifest_sha256": pin, "result": "offline_bundle_prepared"}
    if len(args) == 3 and args[0] == "verify" and os.geteuid() != 0:
        return {**verify_bundle(args[1], args[2]), "result": "offline_measurement_passed"}
    if len(args) == 3 and args[0] == "sealed":
        return _sealed(args[1], args[2])
    if len(args) == 4 and args[0] == "restart":
        return _restart(args[1], args[2], args[3])
    if report is not None:
        return _role_main(args[1], report)
    raise Unavailable("invalid fixture invocation")


def main(args):
    report = None
    if args[:1] == ["role"]:
        # Even a negative report must never be written to an unverified FD.
        try:
            if len(args) != 4 or not all(re.fullmatch(r"\d{1,20}", value, re.ASCII) for value in args[2:]):
                return 3
            report = int(args[2]), int(args[3])
            verify_role_stdio(report)
        except (CustodyRefused, OSError):
            return 3
    try:
        result = _entry(args, report)
        print(json.dumps(result, separators=(",", ":")))
        return 0
    except Unavailable:
        print(json.dumps({"result": "sealed_unavailable"}, separators=(",", ":")))
        return 2
    except (CustodyRefused, MeasurementRefused, Denied, OSError, ValueError, TypeError, KeyError,
            subprocess.TimeoutExpired):
        print(json.dumps(_FAILURE, separators=(",", ":")))
        return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
