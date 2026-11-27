"""Own a bounded systemd user invocation of the standalone ACP server."""

from contextlib import contextmanager, nullcontext, suppress
from dataclasses import dataclass, field
import os
from pathlib import Path
import pwd
import re
import select
import signal
import subprocess
import time

from oc_orchestrator.runtime import Failure, check_private_directory, host

from .native_namespace import (
    NativeNamespaceError, prepare_cold_namespace, prepare_enrollment_namespace, prepare_signed_out_namespace,
)
from .registration import ColdReplica, PinnedProfile


class NativeRetirementUnconfirmed(NativeNamespaceError):
    """Private runtime state must be retained until exact ownership is reconciled."""


def retain_cleanup_failure(primary: BaseException | None, uncertainty: BaseException, cause: BaseException):
    """Keep typed cleanup evidence without changing the primary error chain."""
    if primary is None:
        raise uncertainty from cause
    uncertainty.__cause__ = cause
    primary.cleanup_uncertainties = getattr(primary, "cleanup_uncertainties", ()) + (uncertainty,)
    primary.add_note(str(uncertainty))


@dataclass(frozen=True, slots=True)
class NativeInvocation:
    unit: str
    invocation_id: str
    group: bytes
    pid: int


@dataclass(frozen=True, slots=True)
class NativeService:
    unit: str
    process: subprocess.Popen
    description: str
    enrollment_scope: object | None = None
    attested: NativeInvocation | None = field(default=None, init=False)
    retired: NativeInvocation | None = field(default=None, init=False)

    def control_group(self):
        """Read the running generated unit's absolute cgroup in the host namespace."""
        return self.invocation().group

    def invocation(self):
        """Verify the exact active unit and the shared host PID namespace."""
        try:
            host_pid_namespace = host("readlink", "/proc/self/ns/pid", timeout=2).stdout.strip()
            if host_pid_namespace != os.readlink("/proc/self/ns/pid").encode("ascii"):
                raise NativeNamespaceError("Google native peer and supervisor PID namespaces differ")
            result = host("systemctl", "--user", "show",
                          "--property=Id,ActiveState,ControlGroup,InvocationID,Description,MainPID",
                          self.unit, timeout=2)
        except (Failure, OSError):
            raise NativeNamespaceError("Google native control group is unavailable") from None
        pairs = [line.split(b"=", 1) for line in result.stdout.splitlines() if b"=" in line]
        fields = dict(pairs)
        unit, group, invocation = self.unit.encode("ascii"), fields.get(b"ControlGroup", b""), fields.get(b"InvocationID", b"")
        pid = fields.get(b"MainPID", b"")
        if (len(pairs) != 6 or fields.get(b"Id") != unit or fields.get(b"ActiveState") != b"active"
                or fields.get(b"Description") != self.description.encode("ascii")
                or re.fullmatch(rb"/[A-Za-z0-9_/ .@:-]{1,1023}", group) is None or b".." in group.split(b"/")
                or group.rsplit(b"/", 1)[-1] != unit or re.fullmatch(rb"[a-f0-9]{32}", invocation) is None
                or re.fullmatch(rb"[1-9][0-9]{0,9}", pid) is None or self.process.poll() is not None):
            raise NativeNamespaceError("Google native control group does not match the invocation")
        return NativeInvocation(self.unit, invocation.decode("ascii"), group, int(pid))


def read_host_cgroup(pid):
    """Read peer membership from the host side of the shared PID namespace."""
    if type(pid) is not int or not 0 < pid < 2**31:
        raise NativeNamespaceError("Invalid native connector PID")
    # A procfs mount exposed in devbox still renders membership relative to
    # devbox's cgroup namespace. The reader must itself run on the host.
    return host("cat", f"/proc/{pid}/cgroup", timeout=2).stdout


def _spawn(namespace):
    uid = os.getuid()
    runtime = f"/run/user/{uid}"
    environment = {
        "PATH": "/usr/bin:/bin", "HOME": pwd.getpwuid(uid).pw_dir, "LANG": "C.UTF-8",
        "XDG_RUNTIME_DIR": runtime, "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime}/bus",
    }
    command = ["/usr/bin/host-spawn", "--cwd=/", "--no-pty", "--env=", "/usr/bin/env", "-i",
               *(f"{key}={value}" for key, value in environment.items()), *namespace.argv]
    environment["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/host{runtime}/bus"
    return subprocess.Popen(command, cwd="/", env=environment, close_fds=True,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)


def _pin(service):
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline and service.process.poll() is None:
        try:
            original = service.invocation()
        except NativeNamespaceError:
            time.sleep(.025)
            continue
        fd = os.pidfd_open(original.pid)
        try:
            ready = select.poll()
            ready.register(fd, select.POLLIN)
            if (read_host_cgroup(original.pid).splitlines() != [b"0::" + original.group]
                    or service.invocation() != original or ready.poll(0)):
                raise NativeNamespaceError("Google native process changed during identity proof")
            return original, fd
        except BaseException:
            os.close(fd)
            raise
    raise NativeNamespaceError("Could not establish exact Google native invocation ownership")


def _stop(service, identity, fd, after_stop=None):
    # A name can be recycled. Signal only the kernel-pinned original PID. Its
    # systemd service has KillMode=control-group and retires its own children.
    primary = None
    try:
        try:
            signal.pidfd_send_signal(fd, signal.SIGTERM)
        except ProcessLookupError:
            pass
        if after_stop is not None:
            after_stop()
    except BaseException as error:
        primary = error
    try:
        _verify_retired(service, identity, fd)
    except BaseException as error:
        retirement = error
        if not isinstance(retirement, NativeRetirementUnconfirmed):
            retirement = NativeRetirementUnconfirmed("Standalone Google ACP retirement verification was interrupted")
            retirement.__cause__ = error
        if primary is None:
            if retirement is error:
                raise
            raise retirement
        primary.add_note("Google native service retirement remains unconfirmed")
        raise primary from retirement
    if primary is not None:
        raise primary


def _close_pipes(process):
    for pipe in (process.stdin, process.stdout):
        with suppress(OSError):
            pipe.close()


def _pid_exited(fd):
    poll = select.poll()
    poll.register(fd, select.POLLIN)
    return any(event & select.POLLIN for _, event in poll.poll(0))


def _verify_retired(service, identity, fd):
    process = service.process
    try:
        _close_pipes(process)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
            raise NativeRetirementUnconfirmed("Standalone Google ACP launch status is uncertain") from None
        receipt = host("systemctl", "--user", "show", "--property=ActiveState,ControlGroup",
                       identity.unit, timeout=5, check=False)
        cgroup = host("test", "!", "-e", "/sys/fs/cgroup" + identity.group.decode("ascii"),
                      timeout=2, check=False)
    except (Failure, OSError, subprocess.TimeoutExpired):
        raise NativeRetirementUnconfirmed("Could not verify standalone Google ACP retirement") from None
    if not _pid_exited(fd) or receipt.returncode or cgroup.returncode or sorted(receipt.stdout.splitlines()) not in (
        [b"ActiveState=inactive", b"ControlGroup="], [b"ActiveState=failed", b"ControlGroup="],
    ):
        raise NativeRetirementUnconfirmed("Could not verify standalone Google ACP retirement")
    object.__setattr__(service, "retired", identity)


@contextmanager
def _run_service(namespace, after_stop=None, *, enrollment_scope=None, reserve_spawn=None, fence=None,
                 replica=None, custody=None, authorized=None):
    with nullcontext() if fence is None else fence:
        if reserve_spawn is not None:
            reserve_spawn()
        if custody is not None:
            custody.before_spawn(namespace.unit)
        if authorized is not None and authorized() is not True:
            if custody is not None:
                custody.no_spawn()
            if replica is not None:
                replica._failed_to_spawn()
            raise NativeNamespaceError("Google native launch owner retired before spawn")
        try:
            process = _spawn(namespace)
        except OSError:
            if custody is not None:
                custody.no_spawn()
            if replica is not None:
                replica._failed_to_spawn()
            raise
    service = NativeService(namespace.unit, process, namespace.description, enrollment_scope)
    try:
        identity, fd = _pin(service)
    except BaseException as pin_error:
        try:
            _close_pipes(process)
            if process.poll() is None:
                with suppress(ProcessLookupError):
                    process.kill()
            process.wait(timeout=3)
        finally:
            raise NativeRetirementUnconfirmed("Google native launch ownership could not be attested") from pin_error
    object.__setattr__(service, "attested", identity)
    failure = None
    try:
        try:
            if custody is not None:
                custody.attest(identity)
            if replica is not None:
                replica._bind(service, identity)
            yield service
        except BaseException as primary:
            try:
                _stop(service, identity, fd)
            except NativeRetirementUnconfirmed as retirement:
                primary.add_note("Google native service retirement remains unconfirmed")
                raise primary from retirement
            raise
        else:
            _stop(service, identity, fd, after_stop)
    except BaseException as error:
        failure = error
        raise
    finally:
        try:
            if custody is not None and service.retired is not None:
                custody.retire(service.retired)
        except BaseException as cleanup:
            uncertainty = NativeRetirementUnconfirmed("Google native retirement custody receipt requires inspection.")
            retain_cleanup_failure(failure, uncertainty, cleanup)
        finally:
            os.close(fd)


def open_signed_out_service(root, build):
    """Run the isolated signed-out fixture, leaving root custody with its owner.

    An unverified retirement raises. The caller must retain its private staging
    tree on such a failure. This runner does not allow a connector or OAuth.
    """
    check_private_directory(root)
    return _run_service(prepare_signed_out_namespace(root, build))


def open_cold_service(root, build, *, replica, connector, ca, authorized, fence, after_stop=None, custody=None):
    """Run the same owner placement with the sole private metadata connector mounted."""
    if type(replica) is not ColdReplica or replica.root != root or fence is None or not callable(authorized):
        raise NativeNamespaceError("Google cold launch requires its staged replica")
    check_private_directory(root)
    profile = replica.mount_path()
    check_private_directory(profile)
    namespace = prepare_cold_namespace(root, build, profile=profile, mount_source=replica.mount_source(),
                                       connector=connector, ca=ca, unit=replica.unit)
    return _run_service(namespace, after_stop, reserve_spawn=lambda: replica.reserve_spawn(authorized),
                        fence=fence, replica=replica, custody=custody, authorized=authorized)


def open_enrollment_service(root, build, *, profile, connector, ca, browser, authorized, fence,
                            after_stop=None, unit=None, custody=None):
    """Run the isolated native consent handoff, with no direct network or browser launch."""
    if (type(profile) is not PinnedProfile or profile.reserve_enrollment_spawn is None
            or fence is None or not callable(authorized)):
        raise NativeNamespaceError("Google enrollment launch requires its pinned profile")
    check_private_directory(root)
    check_private_directory(profile.path)
    info = os.fstat(profile.fd)
    if not os.path.samestat(info, profile.path.lstat()):
        raise NativeNamespaceError("Google enrollment profile changed before launch")
    source = Path(f"/proc/{os.getpid()}/fd/{profile.fd}"), info.st_dev, info.st_ino
    namespace = prepare_enrollment_namespace(root, build, profile=profile.path, mount_source=source,
                                             connector=connector, ca=ca, browser=browser, unit=unit)
    return _run_service(namespace, after_stop, enrollment_scope=profile.phase_scope,
                        reserve_spawn=lambda: profile.reserve_enrollment_spawn(authorized), fence=fence, custody=custody, authorized=authorized)
