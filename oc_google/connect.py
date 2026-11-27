"""Attended, link-only enrollment with workstation-owned metadata transport."""

from contextlib import ExitStack, contextmanager, suppress
import ctypes
import errno
from fcntl import F_GETFL, fcntl, ioctl
import os
import secrets
import select
import shutil
import signal
import stat
from threading import RLock
import termios
import time

from oc_orchestrator.runtime import check_private_directory, host, scratch_parent
from oc_providers.config import _account_home, _open_trusted_dir, load_provider_config
from oc_providers.contracts import is_valid_instance_label

from .auth_offer import CallbackDiagnostic
from .control import terminal
from .metadata_destination import MetadataRoute, exchange
from .metadata_workflow import CallbackWorkflowError, MetadataRuntime, enroll_metadata, reopen_metadata
from .native_artifacts import stage_standalone, verify_standalone_source
from .native_namespace import public_certificate
from .native_service import NativeRetirementUnconfirmed, retain_cleanup_failure
from .registration import RegistrationJournal, _absent, _DIRECTORY, _write_private
from .token_diagnostic import LoadBodyReason, PostTokenDiagnostic, PostTokenStage, TokenDiagnostic, TokenStage


_libc_write = ctypes.CDLL(None, use_errno=True).write
_libc_write.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t)
_libc_write.restype = ctypes.c_ssize_t

_TIOCGDEV = 0x80045432
_TIOCGPTN = 0x80045430
_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGTSTP, signal.SIGCONT,
            signal.SIGTTIN, signal.SIGTTOU)
_CONSENT = (
    "Sign in to Google Antigravity using a personal account on this workstation.\n"
    "The Google grant includes these scopes:\n"
    "  https://www.googleapis.com/auth/cloud-platform\n"
    "    Broad access to Google Cloud resources available to this account.\n"
    "  https://www.googleapis.com/auth/userinfo.email\n"
    "    Authorizes email metadata. The broker requests only the opaque account ID.\n"
    "  https://www.googleapis.com/auth/aicode\n"
    "    Authorizes Google coding service access.\n"
    "The offline refresh grant stays in a private workstation profile. This attempt uses "
    "only sign-in, account verification, account metadata, and model catalog requests. "
    "It sends zero inference prompts. Open the link yourself in a browser on this "
    "workstation and keep this terminal in the foreground.\n"
    "Continue? [y/N] "
)
_CALLBACK_DETAILS = {
    CallbackDiagnostic.FRAMING: "The callback request framing was invalid.",
    CallbackDiagnostic.TARGET: "The callback request target or Host was invalid.",
    CallbackDiagnostic.PARAMETERS: "The callback parameters were invalid.",
    CallbackDiagnostic.HEADER_REFERER: "The callback Referer header was refused.",
    CallbackDiagnostic.HEADER_ORIGIN: "The callback Origin header was refused.",
    CallbackDiagnostic.HEADER_DNT: "The callback DNT header was refused.",
    CallbackDiagnostic.HEADER_COOKIE: "The callback Cookie header was refused.",
    CallbackDiagnostic.HEADER_CONTENT_LENGTH: "The callback Content-Length header was refused.",
    CallbackDiagnostic.HEADER_TRANSFER_ENCODING: "The callback Transfer-Encoding header was refused.",
    CallbackDiagnostic.HEADER_SEC_PURPOSE: "The callback Sec-Purpose header was refused.",
    CallbackDiagnostic.HEADER_OTHER: "A callback header was invalid or unapproved.",
    CallbackDiagnostic.HEADER_DUPLICATE: "A callback header was duplicated.",
    CallbackDiagnostic.AUTHORITY_UNAVAILABLE: "Callback authority was unavailable.",
    CallbackDiagnostic.HANDOFF_UNCONFIRMED: "The local callback handoff could not be confirmed.",
    CallbackDiagnostic.SIGN_IN_DENIED: "The callback reported that sign-in was denied.",
    CallbackDiagnostic.NO_MATCHING_CALLBACK: "No matching callback was accepted.",
    CallbackDiagnostic.FORWARDED_BEFORE_METADATA: "The callback was forwarded, but metadata setup did not begin.",
}
_TOKEN_DETAILS = {
    TokenStage.HTTP_400: "The token endpoint returned HTTP 400.",
    TokenStage.HTTP_401_403: "The token endpoint returned HTTP 401 or 403.",
    TokenStage.HTTP_429: "The token endpoint returned HTTP 429.",
    TokenStage.HTTP_5XX: "The token endpoint returned a server error.",
    TokenStage.HTTP_OTHER: "The token endpoint returned an unexpected HTTP status.",
    TokenStage.CHUNKED: "The token reply had invalid chunked framing.",
    TokenStage.HEADER: "The token reply had an invalid header.",
    TokenStage.DUPLICATE_HEADER: "The token reply had a duplicate header.",
    TokenStage.FRAMING: "The token reply framing was incomplete or incompatible.",
    TokenStage.TRAILING: "The token reply contained unexpected trailing data.",
    TokenStage.TLS_EOF: "The token reply lacked a complete authenticated TLS close.",
    TokenStage.TRANSPORT: "The token reply transport did not settle.",
    TokenStage.GRANT_SHAPE: "The token grant had an incompatible response format.",
    TokenStage.GRANT_SCOPE_LIST: "The token grant had a malformed or duplicate scope list.",
    TokenStage.GRANT_SCOPE_UNKNOWN: "The token grant included an unapproved permission.",
    TokenStage.GRANT_SCOPE_RESOURCE: "The token grant lacked a required resource permission.",
    TokenStage.GRANT_SCOPE_EMAIL: "The token grant lacked an approved email permission.",
    TokenStage.GRANT_BEARER: "The token grant had incompatible bearer fields.",
    TokenStage.GRANT_IDENTITY: "The token grant had an incompatible identity field.",
    TokenStage.GRANT_REFRESH: "The token grant had incompatible refresh fields.",
    TokenStage.USERINFO_PRE_WRITE: "The token grant passed validation. UserInfo setup failed before its write.",
}
_POST_TOKEN_DETAILS = {
    PostTokenStage.LOAD_ADMISSION: "The LOAD request or its local admission did not settle.",
    PostTokenStage.LOAD_HTTP_REPLY: "The LOAD HTTP reply was refused.",
    PostTokenStage.LOAD_BODY: "The LOAD metadata body was refused.",
    PostTokenStage.LOAD_NATIVE_REPLY: "The LOAD reply could not be delivered to the native process.",
    PostTokenStage.AUTH_COMPLETE: "The native sign-in completion was refused.",
    PostTokenStage.ENROLLMENT_DRAIN: "The retired native sign-in dialogue could not be verified.",
    PostTokenStage.ENROLLMENT_COMMIT: "The final enrollment record could not be committed.",
    PostTokenStage.COLD_REFRESH: "The cold refresh was refused.",
    PostTokenStage.COLD_SUBJECT: "The cold account continuity check was refused.",
    PostTokenStage.COLD_CATALOG: "The cold metadata catalog was refused.",
    PostTokenStage.COLD_ACP_COMPLETE: "The native cold session completion was refused.",
    PostTokenStage.COLD_DRAIN: "The retired native cold dialogue could not be verified.",
    PostTokenStage.COLD_COMMIT: "The final cold metadata record could not be committed.",
}
_LOAD_BODY_DETAILS = {
    LoadBodyReason.SIZE: "body size",
    LoadBodyReason.JSON_OBJECT: "JSON object encoding",
    LoadBodyReason.STRUCTURE_LIMITS: "structure limits",
    LoadBodyReason.TOP_LEVEL_FIELDS: "top-level field allowlist",
    LoadBodyReason.CURRENT_TIER: "current tier structure",
    LoadBodyReason.ORIGINAL_PROJECT: "original project",
    LoadBodyReason.PAID_TIER: "paid tier structure",
    LoadBodyReason.CONSUMER_PROJECT_POLICY: "consumer and project policy",
    LoadBodyReason.OPTIONAL_METADATA: "optional metadata",
    LoadBodyReason.ALTERNATIVE_TIER_POLICY: "alternative tier policy",
}


class ConnectError(RuntimeError):
    """A fixed enrollment refusal for the workstation operator."""


class CustodyUnconfirmed(ConnectError):
    """Retain the exact affected private enrollment runtime for inspection."""


def needs_custody_inspection(error, *, include_context=False):
    """Project typed custody uncertainty as a safe operator instruction."""
    seen = set()
    types = (CustodyUnconfirmed, NativeRetirementUnconfirmed)
    pending = [error]
    while pending:
        error = pending.pop()
        if error is None or id(error) in seen:
            continue
        if isinstance(error, types) or getattr(error, "cleanup_uncertainties", ()):
            return True
        seen.add(id(error))
        pending.append(error.__cause__)
        if include_context:
            pending.append(error.__context__)
    return False


def _write_enrollment_detail(owner, error, token_diagnostic, post_diagnostic):
    if needs_custody_inspection(error):
        return
    if isinstance(error, CallbackWorkflowError) and type(error.diagnostic) is CallbackDiagnostic:
        detail = "Google sign-in callback: " + _CALLBACK_DETAILS[error.diagnostic]
    elif error.__cause__ is None and not getattr(error, "__notes__", ()):
        stage = token_diagnostic.stage(error)
        if stage is not None:
            detail = "Google sign-in token reply: " + _TOKEN_DETAILS[stage]
        else:
            stage = post_diagnostic.stage(error)
            if stage is None or needs_custody_inspection(error, include_context=True):
                return
            detail = "Google enrollment metadata: " + _POST_TOKEN_DETAILS[stage]
            if stage is PostTokenStage.LOAD_BODY:
                reasons = post_diagnostic.load_body_reasons(error)
                if reasons:
                    detail += " Failed checks include " + ", ".join(_LOAD_BODY_DETAILS[reason] for reason in reasons) + "."
    else:
        return
    with suppress(OSError, ConnectError):
        owner.write_once(detail + "\n")


class _TerminalOwner:
    def __init__(self, fd):
        self.fd = fd
        self.fence = RLock()
        self.cancelled = False
        self.signal = None
        self.deadline = time.monotonic() + 260
        self.identity = self._identify()

    def _identify(self):
        identity = terminal(os.getpid())
        device = ioctl(self.fd, _TIOCGDEV, bytes(4))
        if os.tcgetpgrp(self.fd) != os.getpgrp() or identity[3] != os.getsid(0):
            raise ConnectError("Google sign-in requires a foreground workstation terminal.")
        for fd, insufficient_access in ((0, os.O_WRONLY), (1, os.O_RDONLY)):
            if (fcntl(fd, F_GETFL) & os.O_ACCMODE) == insufficient_access:
                raise ConnectError("Google sign-in requires readable input and writable output.")
            try:
                ioctl(fd, _TIOCGPTN, bytes(4))
            except OSError as error:
                if error.errno != errno.ENOTTY:
                    raise
            else:
                raise ConnectError("Google sign-in requires a controlling terminal.")
            if ioctl(fd, _TIOCGDEV, bytes(4)) != device:
                raise ConnectError("Google sign-in input and output must share a controlling terminal.")
        return identity, device

    def mark_signal(self, number, _frame):
        self.signal = number

    def authorized(self):
        with self.fence:
            if self.cancelled or self.signal is not None or time.monotonic() >= self.deadline:
                self.cancelled = True
                return False
            try:
                valid = self._identify() == self.identity
            except (OSError, RuntimeError, ValueError):
                valid = False
            self.cancelled = not valid or self.signal is not None or time.monotonic() >= self.deadline
            return not self.cancelled

    def _ready(self, events, deadline):
        poll = select.poll()
        poll.register(self.fd, events)
        while self.authorized() and time.monotonic() < deadline:
            ready = poll.poll(max(1, int(min(.1, deadline - time.monotonic()) * 1000)))
            if ready:
                observed = ready[0][1]
                if observed & (select.POLLERR | select.POLLHUP | select.POLLNVAL):
                    self.cancelled = True
                    return False
                return bool(observed & events)
        return False

    def write_once(self, message):
        payload = message.encode("ascii")
        if not 0 < len(payload) <= 8300 or not self._ready(select.POLLOUT, time.monotonic() + .2):
            self.cancelled = True
            raise ConnectError("Google sign-in terminal write was unavailable.")
        with self.fence:
            try:
                if self.authorized() and _libc_write(self.fd, payload, len(payload)) == len(payload) and self.authorized():
                    return
            except OSError:
                pass
            self.cancelled = True
            raise ConnectError("Google sign-in terminal write did not settle.")

    def consent(self, label):
        if not self.authorized():
            return False
        try:
            termios.tcflush(self.fd, termios.TCIFLUSH)
        except OSError:
            self.cancelled = True
            return False
        self.write_once(f"Google registration {label}\n{_CONSENT}")
        deadline = time.monotonic() + 45
        answer = b""
        while len(answer) < 4 and self._ready(select.POLLIN, deadline):
            try:
                byte = os.read(self.fd, 1)
            except OSError:
                break
            if byte in (b"\n", b"\r"):
                if answer in (b"y", b"Y") and self.authorized():
                    return True
                break
            if not byte:
                break
            answer += byte
        self.cancelled = True
        return False

    def offer(self, offer):
        self.write_once(f"Google sign-in link for this workstation\n{offer.url}\n")


@contextmanager
def _attended_owner():
    fd = os.open("/dev/tty", os.O_RDWR | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with ExitStack() as clean:
        clean.callback(os.close, fd)
        owner = _TerminalOwner(fd)
        for number in _SIGNALS:
            old = signal.signal(number, owner.mark_signal)
            clean.callback(signal.signal, number, old)
        if not owner.authorized():
            raise ConnectError("Google sign-in requires a foreground workstation terminal.")
        yield owner


def _preflight(parent):
    uid = os.geteuid()
    if not uid or uid != os.getuid():
        raise ConnectError("Google sign-in requires a non-root workstation account.")
    bridge = os.lstat("/usr/bin/host-spawn")
    if not stat.S_ISREG(bridge.st_mode) or bridge.st_uid != 0 or bridge.st_mode & 0o022:
        raise ConnectError("Google sign-in requires a trusted host bridge.")
    if (host("id", "-ru").stdout.strip() != str(uid).encode("ascii")
            or host("readlink", "/proc/self/ns/net", timeout=2).stdout.strip()
            != os.readlink("/proc/self/ns/net").encode("ascii")):
        raise ConnectError("Google sign-in requires the workstation loopback and account.")
    check_private_directory(parent)
    for path in ("/usr/bin/openssl", "/usr/bin/bwrap", "/usr/bin/systemd-run", "/usr/bin/systemctl",
                 "/usr/bin/python3", "/usr/bin/sh", "/usr/bin/env"):
        receipt = host("stat", "-Lc", "%u %a", "--", path, timeout=2).stdout.split()
        if len(receipt) != 2 or receipt[0] != b"0" or int(receipt[1], 8) & 0o022:
            raise ConnectError("Google sign-in requires protected workstation tools.")
        host("test", "-f", path, timeout=2)
        host("test", "-x", path, timeout=2)


@contextmanager
def _artifacts():
    home = _account_home()
    sandbox = (home / "opencode-sandbox").resolve()
    path = home / ".local/share/oc-sandbox/google/standalone-1.5.2"
    fd = _open_trusted_dir(path, sandbox=sandbox)
    if fd is None:
        raise ConnectError("Install the pinned Google standalone ACP pair in the workstation artifact directory.")
    try:
        yield fd
        current = _open_trusted_dir(path, sandbox=sandbox)
        if current is None:
            raise ConnectError("The Google standalone artifact directory changed during staging.")
        try:
            if not os.path.samestat(os.fstat(current), os.fstat(fd)):
                raise ConnectError("The Google standalone artifact directory changed during staging.")
        finally:
            os.close(current)
    finally:
        os.close(fd)


class _RuntimeCustody:
    def __init__(self, parent, parent_fd, root, root_fd, label, cold):
        self.parent = parent
        self.parent_fd = parent_fd
        self.root = root
        self.root_fd = root_fd
        self.label = label
        self.cold = cold
        self.quarantine = "." + root.name + "-retire"
        self.record = None
        self.unit = None
        self.identity = None
        self.cleanable = True
        self.cold_replica_managed = False

    def bind(self, record):
        if self.record is not None:
            raise CustodyUnconfirmed("Google enrollment custody is already bound.")
        self.record = record

    def _verify(self, name, fd):
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        original = os.fstat(self.root_fd)
        if (not os.path.samestat(info, original) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise CustodyUnconfirmed("Google enrollment runtime identity changed.")
        return original

    def _verify_parent(self):
        if not os.path.samestat(self.parent.lstat(), os.fstat(self.parent_fd)):
            raise CustodyUnconfirmed("Google enrollment runtime parent changed.")

    def before_spawn(self, unit):
        self.cleanable = False
        self._verify_parent()
        original = self._verify(self.root.name, self.parent_fd)
        if self.unit is not None or self.record is None:
            raise CustodyUnconfirmed("Google enrollment launch custody changed.")
        self.unit = unit
        self.record("launch", {"label": self.label, "root": str(self.root), "device": original.st_dev,
                               "inode": original.st_ino, "unit": unit})
        self._verify_parent()
        self._verify(self.root.name, self.parent_fd)

    def attest(self, identity):
        if identity.unit != self.unit or self.identity is not None:
            raise CustodyUnconfirmed("Google enrollment process identity changed.")
        self.record("attested", self._process(identity))
        self.identity = identity

    def _process(self, identity):
        return {"unit": self.unit, "invocation": identity.invocation_id,
                "pid": identity.pid, "cgroup": identity.group.decode("ascii")}

    def no_spawn(self, replica):
        self.record("no-spawn", {"unit": self.unit})
        if replica is not None:
            replica._failed_to_spawn(lambda: self.cleanable)
        self.cleanable = True

    def delegate_cold_cleanup(self):
        self.cold_replica_managed = True

    def retire(self, identity):
        if self.identity is None:
            return
        if identity != self.identity:
            raise CustodyUnconfirmed("Google enrollment retirement identity changed.")
        self.record("retired", self._process(identity))
        self.cleanable = True

    def cleanup(self):
        if not self.cleanable:
            raise CustodyUnconfirmed("Google enrollment cleanup requires inspection.")
        self._verify_parent()
        if not _absent(self.quarantine, directory=self.parent_fd):
            raise CustodyUnconfirmed("Google enrollment cleanup quarantine requires inspection.")
        if _absent(self.root.name, directory=self.parent_fd):
            if not self.cold or os.fstat(self.root_fd).st_nlink != 0:
                raise CustodyUnconfirmed("Google enrollment runtime disappearance requires inspection.")
            return
        self._verify(self.root.name, self.parent_fd)
        if self.cold and (self.cold_replica_managed or not _absent("profile", directory=self.root_fd)):
            raise CustodyUnconfirmed("Google cold replica cleanup requires inspection.")
        os.mkdir(self.quarantine, 0o700, dir_fd=self.parent_fd)
        quarantine_fd = os.open(self.quarantine, _DIRECTORY, dir_fd=self.parent_fd)
        try:
            os.rename(self.root.name, "runtime", src_dir_fd=self.parent_fd, dst_dir_fd=quarantine_fd)
            self._verify("runtime", quarantine_fd)
            shutil.rmtree("runtime", dir_fd=quarantine_fd)
        finally:
            os.close(quarantine_fd)
        os.rmdir(self.quarantine, dir_fd=self.parent_fd)
        self._verify_parent()
        if (os.fstat(self.root_fd).st_nlink != 0 or not _absent(self.root.name, directory=self.parent_fd)
                or not _absent(self.quarantine, directory=self.parent_fd)):
            raise CustodyUnconfirmed("Google enrollment cleanup could not confirm removal.")


@contextmanager
def _private_runtime(parent, label, cold, owner):
    with ExitStack() as clean:
        parent_fd = os.open(parent, _DIRECTORY)
        clean.callback(os.close, parent_fd)
        info = os.fstat(parent_fd)
        if (not os.path.samestat(info, parent.lstat()) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ConnectError("Google enrollment runtime parent is unavailable.")
        if not owner.authorized():
            raise ConnectError("Google sign-in cancelled.")
        name = "oc-g-" + secrets.token_hex(12)
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        try:
            root_fd = os.open(name, _DIRECTORY, dir_fd=parent_fd)
        except OSError as error:
            raise CustodyUnconfirmed("Google enrollment runtime creation requires inspection.") from error
        clean.callback(os.close, root_fd)
        custody = _RuntimeCustody(parent, parent_fd, parent / name, root_fd, label, cold)
        failure = None
        try:
            yield custody
        except BaseException as error:
            failure = error
            raise
        finally:
            try:
                custody.cleanup()
            except BaseException as cleanup:
                uncertainty = CustodyUnconfirmed("Google enrollment cleanup requires inspection.")
                retain_cleanup_failure(failure, uncertainty, cleanup)


def _prepare_runtime(custody, source):
    root = custody.root
    check_private_directory(root)
    native = root / "native"
    os.mkdir("native", 0o700, dir_fd=custody.root_fd)
    build = stage_standalone(source, native)
    cert, key, config = (root / name for name in ("metadata.pem", "metadata-key.pem", "openssl.cnf"))
    routes = [MetadataRoute.TOKEN, MetadataRoute.LOAD_CODE_ASSIST]
    if custody.cold:
        routes.append(MetadataRoute.FETCH_AVAILABLE_MODELS)
    names = ", ".join("DNS:" + route.value[0] for route in routes)
    _write_private(custody.root_fd, config.name, (
        "[req]\ndistinguished_name=dn\nprompt=no\nx509_extensions=extensions\n"
        "[dn]\nCN=oc-sandbox Google private metadata\n"
        f"[extensions]\nsubjectAltName={names}\n"
    ).encode("ascii"))
    host("sh", "-c", 'umask 077; exec /usr/bin/env -i HOME="$1" PATH=/usr/bin:/bin LANG=C '
         '/usr/bin/openssl req -new -x509 -newkey rsa:2048 -nodes -sha256 -days 1 '
         '-config "$2" -out "$3" -keyout "$4" </dev/null', "oc-sandbox-google", str(root), str(config),
         str(cert), str(key), timeout=6)
    actual = host("env", "-i", f"HOME={root}", "PATH=/usr/bin:/bin", "LANG=C", "/usr/bin/openssl",
                  "x509", "-in", str(cert), "-noout", "-ext", "subjectAltName", timeout=2).stdout.splitlines()
    if ([line.strip() for line in actual] != [b"X509v3 Subject Alternative Name:", names.encode("ascii")]):
        raise ConnectError("Google enrollment certificate scope did not match its phase.")
    public_certificate(cert)
    info = key.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise ConnectError("Google enrollment private TLS key is unavailable.")
    return MetadataRuntime(root, build, cert, key, custody)


def connect_for(label):
    """Run the exact public command only on an attended workstation."""
    if not is_valid_instance_label(label):
        raise ConnectError("Invalid Google registration label.")
    config = load_provider_config()
    spec = config.get("google", label) if config is not None else None
    if spec is None or not spec.enabled or spec.auth_mode != "subscription" or spec.cli_path is not None:
        raise ConnectError("Enable the Google subscription registration without a CLI override in providers.toml.")
    parent = scratch_parent()
    with _attended_owner() as owner:
        _preflight(parent)
        token_diagnostic = TokenDiagnostic()
        post_diagnostic = PostTokenDiagnostic()
        try:
            with ExitStack() as initial_root, ExitStack() as cold_root:
                with _artifacts() as source:
                    verify_standalone_source(source)
                    if not owner.consent(label):
                        raise ConnectError("Google sign-in cancelled.")
                    initial = _prepare_runtime(initial_root.enter_context(_private_runtime(parent, label, False, owner)), source)
                    cold = _prepare_runtime(cold_root.enter_context(_private_runtime(parent, label, True, owner)), source)
                journal = RegistrationJournal(label)
                enrollment = enroll_metadata(journal, initial, disclose_offer=owner.offer, destination=exchange,
                                             authorized=owner.authorized, fence=owner.fence,
                                             diagnostic=token_diagnostic, post_diagnostic=post_diagnostic)
                initial_root.close()
                with owner.fence:
                    owner.deadline = min(owner.deadline, time.monotonic() + 18)
                reopen_metadata(journal, enrollment, cold, destination=exchange, authorized=owner.authorized,
                                fence=owner.fence, post_diagnostic=post_diagnostic)
        except (OSError, ValueError, RuntimeError) as error:
            try:
                _write_enrollment_detail(owner, error, token_diagnostic, post_diagnostic)
            finally:
                post_diagnostic.clear()
            raise
        with owner.fence:
            owner.write_once(f"Verified Google registration {label} for workstation metadata.\n")
    return 0
