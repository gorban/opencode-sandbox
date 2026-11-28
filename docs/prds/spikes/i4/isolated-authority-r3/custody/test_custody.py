"""Offline regression cases for the sealed appliance source."""

from contextlib import ExitStack, contextmanager, nullcontext, redirect_stdout
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import select
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parent
SPIKE = ROOT.parent / "spike" if (ROOT.parent / "spike").is_dir() else ROOT.parent
sys.path[:0] = [str(ROOT), str(SPIKE)]

from bootstrap import (
    ACCOUNTS, CustodyRefused, _send, proc_self, receive_bootstrap, role_accounts, send_bootstrap,
    verify_pidfd, verify_role_record, verify_root_parent,
)
from descriptor import Denied, Peer, canonical, descriptor_pair
from preflight import (
    LEGACY, PLAN_OVERLAY, MeasurementRefused, _mount_record, _open_root, _run_checked, scan, verify_bundle,
)
from run import Appliance, _contending, _one, _role_command, _spawn_report, main


CONTROLLER = Peer(os.getpid(), os.getuid(), os.getgid())


@contextmanager
def idle_child():
    process = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", "import sys; sys.stdin.buffer.read(1)"],
                               env={}, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        yield process
    finally:
        try:
            process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.resources = self.enterContext(ExitStack())
        self.proc = self.resources.enter_context(proc_self())
        self.root_fd = self.pidfd(CONTROLLER.pid)
        self.roles = {}
        self.descriptors = {}
        for name in ("first", "second"):
            process = self.resources.enter_context(idle_child())
            self.roles[name] = Peer(process.pid, os.getuid(), os.getgid())
            self.descriptors[name] = self.pidfd(process.pid)
        self.ids = {name: (peer.uid, peer.gid) for name, peer in self.roles.items()}

    def pidfd(self, pid):
        fd = os.pidfd_open(pid)
        self.resources.callback(os.close, fd)
        return fd

    def deliver(self, descriptors):
        sender, receiver = descriptor_pair()
        with sender, receiver:
            send_bootstrap(sender, self.roles, descriptors)
            return receive_bootstrap(receiver, self.proc, CONTROLLER, self.root_fd, self.ids)

    def open_descriptors(self):
        result = set()
        for name in os.listdir("/proc/self/fd"):
            try:
                os.fstat(int(name))
            except OSError:
                continue
            result.add(int(name))
        return result

    def require_rejected(self, descriptors):
        before = self.open_descriptors()
        with self.assertRaises(CustodyRefused):
            self.deliver(descriptors)
        self.assertEqual(self.open_descriptors(), before)

    def test_exact_pidfd_role_bindings_pass_and_are_close_on_exec(self):
        returned = self.deliver(self.descriptors)
        try:
            for role, (peer, fd) in returned.items():
                self.assertEqual(peer, self.roles[role])
                self.assertFalse(os.get_inheritable(fd))
                verify_pidfd(self.proc, fd, peer.pid)
        finally:
            for _, fd in returned.values():
                os.close(fd)

    def test_swapped_genuine_descriptors_are_closed_and_refused(self):
        self.require_rejected({"first": self.descriptors["second"], "second": self.descriptors["first"]})

    def test_live_unrelated_process_is_not_an_authority(self):
        with idle_child() as unrelated:
            descriptor = self.pidfd(unrelated.pid)
            self.require_rejected({**self.descriptors, "first": descriptor})

    def test_exited_expected_process_is_refused(self):
        with idle_child() as exited:
            self.roles["first"] = Peer(exited.pid, os.getuid(), os.getgid())
            descriptor = self.pidfd(exited.pid)
        self.require_rejected({**self.descriptors, "first": descriptor})

    def test_actual_file_descriptor_is_not_a_pidfd(self):
        fd = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        self.require_rejected({**self.descriptors, "first": fd})

    def test_first_frame_cannot_supply_descriptors_and_extra_rights_are_closed(self):
        before = self.open_descriptors()
        sender, receiver = descriptor_pair()
        with sender, receiver:
            _send(sender, ["r3", "peers", []], [self.root_fd] * 5)
            with self.assertRaises(CustodyRefused):
                receive_bootstrap(receiver, self.proc, CONTROLLER, self.root_fd, self.ids)
        self.assertEqual(self.open_descriptors(), before)

    def test_unexpected_kernel_sender_identity_fails(self):
        sender, receiver = descriptor_pair()
        with sender, receiver:
            send_bootstrap(sender, self.roles, self.descriptors)
            wrong = Peer(CONTROLLER.pid, CONTROLLER.uid + 1, CONTROLLER.gid)
            with self.assertRaises(CustodyRefused):
                receive_bootstrap(receiver, self.proc, wrong, self.root_fd, self.ids)


class MeasurementTests(unittest.TestCase):
    def setUp(self):
        self.source = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        (self.source / "spike").mkdir(mode=0o755)
        self.payload = self.source / "spike" / "receipt.py"
        self.payload.write_text("synthetic\n")
        entries = scan(self.source, os.getuid(), manifest_pending=True)
        manifest = canonical(["r3-custody", LEGACY, PLAN_OVERLAY, "a" * 40, entries])
        (self.source / "manifest").write_bytes(manifest)
        self.pin = sha256(manifest).hexdigest()

    def test_exact_measurement_works_offline(self):
        self.assertEqual(verify_bundle(self.source, self.pin)["legacy"], LEGACY)

    def test_manifest_pin_and_changed_source_fail_closed(self):
        with self.assertRaises(MeasurementRefused):
            verify_bundle(self.source, "0" * 64)
        self.payload.write_text("different")
        with self.assertRaises(MeasurementRefused):
            verify_bundle(self.source, self.pin)

    def test_extra_file_and_link_fail_closed(self):
        extra = self.source / "surprise"
        extra.touch()
        with self.assertRaises(MeasurementRefused):
            verify_bundle(self.source, self.pin)
        extra.unlink()
        self.payload.unlink()
        self.payload.symlink_to("/dev/null")
        with self.assertRaises((MeasurementRefused, OSError)):
            verify_bundle(self.source, self.pin)

    def test_root_runner_unavailable_from_checkout(self):
        response = io.StringIO()
        with redirect_stdout(response):
            status = main(["sealed", "a" * 64, "b" * 64])
        self.assertEqual(status, 2)
        self.assertIn("sealed_unavailable", response.getvalue())

    def test_fixed_role_command_has_no_privilege_or_environment_fallback(self):
        command = _role_command(22211, 22212, "holder")
        self.assertEqual(command[:5], ["/usr/bin/setpriv", "--reuid", "22211", "--regid", "22212"])
        self.assertIn("--clear-groups", command)
        self.assertIn("--no-new-privs", command)
        self.assertIn("--bounding-set=-all", command)
        self.assertIn("/usr/bin/python3", command)
        self.assertEqual(command[-2:], ["role", "holder"])


class StartupEnvironmentTests(unittest.TestCase):
    pin = "1" * 64
    evidence = "2" * 64
    posix = {"LC_ALL": "C"}
    controller = {**posix, "OC_R3_PREIMPORT": pin}

    def probe(self, source, environment, *arguments):
        return subprocess.run(
            ["/usr/bin/python3", "-I", "-S", "-B", "-c", source, str(ROOT), self.pin, self.evidence, *arguments],
            env=environment, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=5,
        )

    def test_bootstrap_exact_environment_and_actual_exec(self):
        scratch = Path(self.enterContext(tempfile.TemporaryDirectory()))
        entry = scratch / "inert-entry.py"
        entry.write_text("import json, os, sys\nprint(json.dumps([dict(os.environ), sys.argv[1]]))\n")
        source = r"""
from contextlib import nullcontext
from pathlib import Path
import sys
root, pin, evidence, scratch = sys.argv[1:]
sys.path.insert(0, root)
import preflight
preflight.BOOTSTRAP = Path(preflight.__file__).resolve()
preflight.os.getuid = preflight.os.geteuid = lambda: 0
preflight._install_pins = lambda _pin: None
preflight._run_checked = lambda _root, _pin, args, activate, sealed: activate(Path(scratch), args)
with open("/dev/null", "rb") as dummy:
    preflight._proc_self = lambda **_flags: nullcontext(dummy.fileno())
    raise SystemExit(preflight.main(["sealed", pin, evidence]))
"""
        # On Fedora the former empty env was already nonempty by this point.
        observed = self.probe("import json, os; print(json.dumps(dict(os.environ)))", {})
        self.assertIn(json.loads(observed.stdout), ({}, {"LC_CTYPE": "C.UTF-8"}))
        accepted = self.probe(source, self.posix, str(entry.resolve()))
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertEqual(json.loads(accepted.stdout), [self.controller, "sealed"])
        for environment in ({}, {"LC_ALL": "C.UTF-8"},
                            {**self.posix, "LC_CTYPE": "C.UTF-8"}, {**self.posix, "HOME": "/fixture"}):
            with self.subTest(environment=environment):
                rejected = self.probe(source, environment, str(entry.resolve()))
                self.assertEqual(rejected.returncode, 2, rejected.stderr)
                self.assertEqual(json.loads(rejected.stdout), {"result": "preimport_refused"})

    def test_measured_controller_import_gate_checks_the_same_environment(self):
        source = r"""
from pathlib import Path
from types import ModuleType
from unittest.mock import patch
import runpy, sys
root, pin, evidence = sys.argv[1:]
entry = Path(root) / "run.py"
real_resolve = Path.resolve
class ImportReached(Exception):
    pass

class Tripwire(ModuleType):
    def __getattr__(self, name):
        raise ImportReached

def resolve(path, **kwargs):
    if path == entry:
        return Path("/opt/oc-r3/appliance/custody/run.py")
    return real_resolve(path, **kwargs)
sys.argv = [str(entry), "sealed", pin, evidence]
sys.modules["bootstrap"] = Tripwire("bootstrap")
with patch("os.geteuid", return_value=0), patch.object(Path, "resolve", resolve):
    try:
        runpy.run_path(str(entry), run_name="__main__")
    except ImportReached:
        print("candidate import reached")
"""
        accepted = self.probe(source, self.controller)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertEqual(accepted.stdout, "candidate import reached\n")
        for environment in (self.posix, {"OC_R3_PREIMPORT": self.pin},
                            {**self.controller, "OC_R3_PREIMPORT": "0" * 64},
                            {**self.controller, "LC_CTYPE": "C.UTF-8"}):
            with self.subTest(environment=environment):
                rejected = self.probe(source, environment)
                self.assertEqual(rejected.returncode, 2, rejected.stderr)
                self.assertEqual(json.loads(rejected.stdout), {"result": "sealed_unavailable"})

    def test_controller_preflight_refuses_wrong_or_additional_environment(self):
        source = r"""
from contextlib import nullcontext
from pathlib import Path
import json, sys
root, pin, evidence = sys.argv[1:]
sys.path[:0] = [root, str(Path(root).parent / "spike"), str(Path(root).parent)]
import run
run.os.geteuid = lambda: 0
run._SCRIPT = Path("/opt/oc-r3/appliance/custody/run.py")
run.socket.if_nameindex = lambda: [(1, "lo")]
run.os.listdir = lambda _path: ["lo"]
run._private_root = lambda *_args: None
run.proc_self = lambda **_flags: nullcontext(0)
run._mount_identity = lambda path, _proc: (path.name, len(path.name) if path.name == "r3h" else 11)
run.verify_bundle = lambda *_args, **_kwargs: {"overlay": run.CORRECTED_OVERLAY}
run.role_accounts = lambda: {}
try:
    run._sealed_preflight(pin, evidence)
except run.Unavailable:
    print("refused")
else:
    print(json.dumps(dict(run.os.environ)))
"""
        accepted = self.probe(source, self.controller)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertEqual(json.loads(accepted.stdout), self.controller)
        for environment in (self.posix, {"OC_R3_PREIMPORT": self.pin},
                            {**self.controller, "OC_R3_PREIMPORT": "0" * 64},
                            {**self.controller, "LC_ALL": "C.UTF-8"},
                            {**self.controller, "LC_CTYPE": "C.UTF-8"},
                            {**self.controller, "HOME": "/fixture"}):
            with self.subTest(environment=environment):
                rejected = self.probe(source, environment)
                self.assertEqual(rejected.returncode, 0, rejected.stderr)
                self.assertEqual(rejected.stdout, "refused\n")

    def test_spawned_role_observes_exact_environment_and_rejects_variations(self):
        source = r"""
from pathlib import Path
import json, os, sys
root = sys.argv[1]
sys.path[:0] = [root, str(Path(root).parent / "spike"), str(Path(root).parent)]
import run
run._SCRIPT = Path("/opt/oc-r3/appliance/custody/run.py")
run.run_role = lambda role, config, report: {"role": role, "config": config, "environment": dict(os.environ)}
try:
    print(json.dumps(run._role_main("worker", (0, 0))))
except run.Unavailable:
    print("refused")
"""
        from run import _read_report, _retire_role

        home = Path(self.enterContext(tempfile.TemporaryDirectory()))
        fixture = SimpleNamespace(identities={"worker": (1000, 1000)}, homes={"worker": home}, children=[])
        with patch("run._role_command", return_value=["/usr/bin/python3", "-I", "-S", "-B", "-c", source, str(ROOT)]):
            process = Appliance.spawn(fixture, "worker", {})
        self.addCleanup(_retire_role, process)
        accepted = _read_report(process)
        config = {"uid": 1000, "gid": 1000, "fds": {}}
        expected = {**self.posix, "HOME": str(home), "OC_R3_ROLE": json.dumps(config, separators=(",", ":"))}
        self.assertEqual(accepted, {"role": "worker", "config": config, "environment": expected})
        for environment in ({**expected, "LC_ALL": "C.UTF-8"},
                            {**expected, "LC_CTYPE": "C.UTF-8"}, {**expected, "PYTHONCOERCECLOCALE": "0"},
                            *(dict((key, value) for key, value in expected.items() if key != unset)
                              for unset in expected)):
            with self.subTest(environment=environment):
                rejected = self.probe(source, environment)
                self.assertEqual(rejected.returncode, 0, rejected.stderr)
                self.assertEqual(rejected.stdout, "refused\n")


class IndependentPreflightTests(unittest.TestCase):
    def setUp(self):
        self.scratch = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.source = self.scratch / "appliance"
        custody = self.source / "custody"
        custody.mkdir(parents=True, mode=0o700)
        self.marker = self.scratch / "entered"
        self.entry = custody / "run.py"
        self.entry.write_text(f"from pathlib import Path\nPath({str(self.marker)!r}).touch()\n")
        self.manifest = self.source / "manifest"
        self.pin = self._measure()

    def _measure(self):
        entries = scan(self.source, os.getuid())
        manifest = canonical(["r3-custody", LEGACY, PLAN_OVERLAY, "a" * 40, entries])
        self.manifest.write_bytes(manifest)
        return sha256(manifest).hexdigest()

    def enter(self, path, args):
        subprocess.run([sys.executable, "-I", "-S", "-B", str(path), *args],
                       env={}, stdin=subprocess.DEVNULL, check=True, timeout=4)

    def test_valid_measurement_precedes_marker_offline(self):
        _run_checked(self.source, self.pin, (), self.enter, sealed=False)
        self.assertTrue(self.marker.exists())

    def test_changed_entry_and_extra_directory_never_exec(self):
        original = self.entry.read_bytes()
        self.entry.write_text("raise AssertionError('must not execute')")
        with self.assertRaises(MeasurementRefused):
            _run_checked(self.source, self.pin, (), self.enter, sealed=False)
        self.entry.write_bytes(original)
        (self.source / "extra").mkdir(mode=0o700)
        with self.assertRaises(MeasurementRefused):
            _run_checked(self.source, self.pin, (), self.enter, sealed=False)
        self.assertFalse(self.marker.exists())

    def test_noncanonical_manifest_is_not_executed_even_with_matching_digest(self):
        raw = self.manifest.read_bytes() + b" "
        self.manifest.write_bytes(raw)
        changed_pin = sha256(raw).hexdigest()
        with self.assertRaises(MeasurementRefused):
            _run_checked(self.source, changed_pin, (), self.enter, sealed=False)
        self.assertFalse(self.marker.exists())

    def test_mount_refusals_leave_marker_absent_with_otherwise_matching_manifest(self):
        self.assertEqual(verify_bundle(self.source, self.pin)["overlay"], PLAN_OVERLAY)
        raw = f"41 12 8:1 / {self.source} ro - ext4 /dev/fixture ro\n".encode()
        cases = (
            (raw + f"42 41 8:2 / {self.source}/custody rw - ext4 /dev/nested rw\n".encode(), "41"),
            (raw, "99"),
            (raw.replace(b"/dev/fixture ro", b"/dev/fixture rw"), "41"),
            (raw + b"42 12 8:1 / /unrelated-alias ro - ext4 /dev/fixture ro\n", "41"),
        )
        for records, selected in cases:
            with self.subTest(selected=selected, lines=records.count(b"\n")):
                def mount(_proc, _descriptor, path, records=records, selected=selected):
                    return _mount_record(records, path, selected, "8:1")

                with (patch("preflight._open_root", side_effect=lambda path, sealed: _open_root(path, sealed=False)),
                      patch("preflight._SealedMount", side_effect=mount), self.assertRaises(MeasurementRefused)):
                    _run_checked(self.source, self.pin, (), self.enter, sealed=True)
                self.assertFalse(self.marker.exists())


class RolePreflightTests(unittest.TestCase):
    def test_reserved_roles_pin_config_without_same_uid_alias(self):
        recorded = {name: SimpleNamespace(pw_uid=1200 + index, pw_gid=1300 + index)
                    for index, name in enumerate(ACCOUNTS.values())}
        with patch("bootstrap.pwd.getpwnam", side_effect=recorded.__getitem__):
            roles = role_accounts()
            self.assertEqual(roles["legacy"], roles["sibling"])
            uid, gid = roles["holder"]
            owner = list(roles["owner"])
            config = {"uid": uid, "gid": gid, "purposes": {"owner": owner}}
            self.assertEqual(verify_role_record("holder", config, roles), (uid, gid))
            for changed in ({**config, "uid": roles["legacy"][0]}, {**config, "purposes": {"owner": [1, 2]}}):
                with self.assertRaises(CustodyRefused):
                    verify_role_record("holder", changed, roles)
            recorded["r3worker"] = recorded["r3owner"]
            with self.assertRaises(CustodyRefused):
                role_accounts()

    def test_assumed_root_parent_requires_kernel_exact_pidfd_and_status(self):
        with proc_self() as proc, idle_child() as other:
            parent = os.getpid()
            parent_pin = os.pidfd_open(parent)
            other_pin = os.pidfd_open(other.pid)
            self.addCleanup(os.close, parent_pin)
            self.addCleanup(os.close, other_pin)
            root_status = f"Pid: {parent}\nNSpid: {parent}\nUid: 0 0 0 0\nGid: 0 0 0 0\n"
            with (patch("bootstrap.os.getppid", return_value=parent),
                  patch("bootstrap._parent_status", return_value=root_status)):
                self.assertEqual(verify_root_parent(proc, assertion=[parent, 0, 0], pidfd=parent_pin),
                                 Peer(parent, 0, 0))
                for assertion, pin in (([other.pid, 0, 0], parent_pin), ([parent, 0, 0], other_pin)):
                    with self.assertRaises(CustodyRefused):
                        verify_root_parent(proc, assertion=assertion, pidfd=pin)
            non_root_status = root_status.replace("Uid: 0 0 0 0", "Uid: 1234 1234 1234 1234")
            with (patch("bootstrap.os.getppid", return_value=parent),
                  patch("bootstrap._parent_status", return_value=non_root_status),
                  self.assertRaises(CustodyRefused)):
                verify_root_parent(proc, assertion=[parent, 0, 0], pidfd=parent_pin)


class RoleDescriptorTests(unittest.TestCase):
    def setUp(self):
        self.resources = self.enterContext(ExitStack())
        self.scope = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.scope.chmod(0o700)
        lock = self.scope / "scope.lock"
        lock.touch(mode=0o600)
        lock_info = lock.stat()
        self.scope_fd = os.open(self.scope, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.resources.callback(os.close, self.scope_fd)
        self.pin = os.pidfd_open(os.getpid())
        self.resources.callback(os.close, self.pin)
        self.identities = {"owner": (2101, 3101), "holder": (2102, 3102), "legacy": (2103, 3103)}
        self.identities["worker"] = (2104, 3104)
        self.fds = {"controller_pidfd": self.pin}
        for purpose in ("bootstrap", "owner", "receipt"):
            endpoint, peer = descriptor_pair()
            self.resources.enter_context(endpoint)
            self.resources.enter_context(peer)
            self.fds[purpose] = endpoint.fileno()
        self.lock = [lock_info.st_dev, lock_info.st_ino]
        self.scope_owner = os.getuid(), os.getgid()
        self.identities["holder"] = self.scope_owner
        self.fds["scope"] = self.scope_fd

    def invoke(self, role, descriptors, *, admitted=False, standard=()):
        from roles import run_role

        uid, gid = self.identities[role]
        counterpart = "holder" if role == "owner" else "owner"
        config = {"uid": uid, "gid": gid, "purposes": {counterpart: list(self.identities[counterpart])},
                  "controller": [os.getpid(), 0, 0], "fds": descriptors, "lock": self.lock}
        with (patch("roles.enable_offline_guard"), patch("roles.proc_self", return_value=nullcontext(3)),
              patch("roles.role_accounts", return_value=self.identities), patch("roles.verify_role"),
              patch("roles.verify_role_stdio", return_value=standard),
              patch("roles.verify_root_parent", return_value=Peer(os.getpid(), 0, 0)),
              patch("roles._run_measured", return_value={"ok": True}) as activate):
            if admitted:
                self.assertEqual(run_role(role, config, (0, 0)), {"ok": True})
                activate.assert_called_once()
            else:
                with self.assertRaises(CustodyRefused):
                    run_role(role, config, (0, 0))
                activate.assert_not_called()

    def test_exact_owner_and_holder_maps_pass_before_activation(self):
        descriptors = {purpose: self.fds[purpose] for purpose in ("controller_pidfd", "bootstrap", "owner")}
        self.invoke("owner", descriptors, admitted=True)
        self.invoke("holder", self.fds, admitted=True)

    def test_owner_rejects_accidental_holder_scope_descriptor(self):
        descriptors = {purpose: self.fds[purpose] for purpose in ("controller_pidfd", "bootstrap", "owner", "scope")}
        self.invoke("owner", descriptors)
        controller = SimpleNamespace(identities=self.identities)
        with patch("run.subprocess.Popen") as spawn, self.assertRaises(CustodyRefused):
            Appliance.spawn(controller, "owner", {}, descriptors)
        spawn.assert_not_called()

    def test_holder_rejects_unexpected_descriptor_even_when_config_names_it(self):
        unexpected = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        self.resources.callback(os.close, unexpected)
        self.invoke("holder", {**self.fds, "extra": unexpected})

    def test_holder_refuses_missing_purpose_standard_fd_and_alias(self):
        missing = {purpose: fd for purpose, fd in self.fds.items() if purpose != "receipt"}
        self.invoke("holder", missing)
        self.invoke("holder", {**self.fds, "receipt": 2})
        same_endpoint = os.dup(self.fds["bootstrap"])
        self.resources.callback(os.close, same_endpoint)
        self.invoke("holder", {**self.fds, "receipt": same_endpoint})

    def test_holder_rejects_wrong_kind_unconnected_socket_and_unpinned_scope(self):
        self.invoke("holder", {**self.fds, "scope": self.fds["owner"], "owner": self.scope_fd})
        endpoint = self.resources.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET))
        endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self.invoke("holder", {**self.fds, "owner": endpoint.fileno()})
        elsewhere = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (elsewhere / "scope.lock").touch(mode=0o600)
        other_fd = os.open(elsewhere, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.resources.callback(os.close, other_fd)
        self.invoke("holder", {**self.fds, "scope": other_fd})

    def test_kernel_inventory_rejects_undeclared_inherited_fd_in_clean_process(self):
        source = r"""
from pathlib import Path
import sys
root, kind = sys.argv[1:]
sys.path[:0] = [root, str(Path(root).parent / "spike"), str(Path(root).parent)]
if kind == "role":
    from bootstrap import CustodyRefused as Refused, proc_self
    context = proc_self(inherited=())
else:
    from preflight import MeasurementRefused as Refused, _proc_self
    context = _proc_self(check_inherited=True)
try:
    with context:
        print("checked")
except Refused:
    print("refused")
"""
        fd = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        self.resources.callback(os.close, fd)
        for kind in ("role", "preflight"):
            for inherited, expected in (((), b"checked\n"), ((fd,), b"refused\n")):
                with self.subTest(kind=kind, inherited=bool(inherited)):
                    actual = subprocess.check_output(
                        [sys.executable, "-I", "-S", "-B", "-c", source, str(ROOT), kind],
                        env={}, stdin=subprocess.DEVNULL, pass_fds=inherited, timeout=4,
                    )
                    self.assertEqual(actual, expected)

    def test_report_object_cannot_alias_an_inherited_authority(self):
        incoming, outgoing = os.pipe2(os.O_CLOEXEC)
        for fd in (incoming, outgoing):
            self.resources.callback(os.close, fd)
        report = os.fstat(incoming)
        self.invoke("holder", {**self.fds, "controller_pidfd": outgoing},
                    standard={(report.st_dev, report.st_ino)})

    def test_ordinary_roles_have_no_control_descriptor_purpose(self):
        from roles import require_role_fds

        for role in ("legacy", "legacy-probe", "sibling", "worker"):
            with self.subTest(role=role):
                self.assertEqual(require_role_fds(role, {}), {})
                with self.assertRaises(CustodyRefused):
                    require_role_fds(role, {"scope": self.scope_fd})


class RoleStdioTests(unittest.TestCase):
    def setUp(self):
        self.resources = self.enterContext(ExitStack())
        self.scratch = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.marker = self.scratch / "role-adopted"
        self.stdin = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        self.stderr = os.open("/dev/null", os.O_WRONLY | os.O_CLOEXEC)
        for fd in (self.stdin, self.stderr):
            self.resources.callback(os.close, fd)

    def pipe(self):
        incoming, outgoing = os.pipe2(os.O_CLOEXEC)
        for fd in (incoming, outgoing):
            self.resources.callback(os.close, fd)
        os.set_blocking(incoming, False)
        return incoming, outgoing

    @staticmethod
    def read_available(fd):
        try:
            return os.read(fd, 4096)
        except BlockingIOError:
            return b""

    def start(self, *, stdin=None, stderr=None, stdout=None, pin=None, redirected_stdin=None):
        source = r"""
from pathlib import Path
import os, sys
root, marker, dev, inode, redirected_stdin = sys.argv[1:]
sys.path[:0] = [root, str(Path(root).parent / "spike"), str(Path(root).parent)]
import run
if redirected_stdin:
    fd = int(redirected_stdin)
    os.dup2(fd, 0)
    os.close(fd)
def enter(*_args):
    Path(marker).touch()
    return {"ok": True}
run._role_main = enter
raise SystemExit(run.main(["role", "owner", dev, inode]))
"""
        self.marker.unlink(missing_ok=True)
        incoming, outgoing = self.pipe()
        identity = os.fstat(outgoing if pin is None else pin)
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", "-c", source, str(ROOT), str(self.marker),
             str(identity.st_dev), str(identity.st_ino), "" if redirected_stdin is None else str(redirected_stdin)],
            env={}, stdin=self.stdin if stdin is None else stdin,
            stdout=outgoing if stdout is None else stdout, stderr=self.stderr if stderr is None else stderr,
            pass_fds=() if redirected_stdin is None else (redirected_stdin,), timeout=4,
        )
        return result.returncode, self.read_available(incoming)

    def test_genuine_null_directions_and_the_exact_anonymous_report_writer_pass(self):
        self.assertEqual(self.start(), (0, b'{"ok":true}\n'))
        self.assertTrue(self.marker.exists())

    def test_stdio_authority_substitutes_are_silent_before_role_state(self):
        scope = os.open(self.scratch, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        pin = os.pidfd_open(os.getpid())
        for fd in (scope, pin):
            self.resources.callback(os.close, fd)
        authority, peer = descriptor_pair()
        self.resources.enter_context(authority)
        self.resources.enter_context(peer)
        for label, configuration in (
            # Python itself rejects a directory during stream startup. Redirect
            # after interpreter setup to exercise the role boundary directly.
            ("scope stdin", {"redirected_stdin": scope}),
            ("pidfd stderr", {"stderr": pin}),
            ("authority stdin", {"stdin": authority.fileno()}),
            ("authority stderr", {"stderr": authority.fileno()}),
            ("authority stdout", {"stdout": authority.fileno()}),
        ):
            with self.subTest(label=label):
                self.assertEqual(self.start(**configuration), (3, b""))
                self.assertFalse(self.marker.exists())
        self.assertFalse(select.select([peer], [], [], 0)[0])

    def test_mismatched_pipe_or_access_direction_refused(self):
        incoming, outgoing = self.pipe()
        wrong_in = os.open("/dev/null", os.O_WRONLY | os.O_CLOEXEC)
        wrong_err = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        for fd in (wrong_in, wrong_err):
            self.resources.callback(os.close, fd)
        for label, configuration in (
            ("different pipe", {"stdout": outgoing}),
            ("report read end", {"stdout": incoming, "pin": outgoing}),
            ("null stdin writer", {"stdin": wrong_in}),
            ("null stderr reader", {"stderr": wrong_err}),
        ):
            with self.subTest(label=label):
                self.assertEqual(self.start(**configuration), (3, b""))
                self.assertFalse(self.marker.exists())
        self.assertEqual(self.read_available(incoming), b"")

    def test_pinned_named_fifo_is_not_a_report_pipe(self):
        named = self.scratch / "fifo"
        os.mkfifo(named, 0o600)
        incoming = os.open(named, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        outgoing = os.open(named, os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        for fd in (incoming, outgoing):
            self.resources.callback(os.close, fd)
        self.assertEqual(self.start(stdout=outgoing, pin=outgoing), (3, b""))
        self.assertFalse(self.marker.exists())
        self.assertEqual(self.read_available(incoming), b"")


class RestartTests(unittest.TestCase):
    def test_no_retirement_claim_for_live_process_or_self(self):
        from restart import lifetime, require_retired

        own = lifetime()
        with self.assertRaises(CustodyRefused):
            require_retired(own)
        controller = self.enterContext(idle_child())
        live = lifetime(controller.pid)
        with self.assertRaises(CustodyRefused):
            require_retired(live)

    def test_retired_controller_and_new_exec_use_same_retained_bytes(self):
        scratch = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        setup = r"""
import json, os, sys
from pathlib import Path
root = Path(sys.argv[1])
custody = Path(sys.argv[2])
sys.path[:0] = [str(custody), str(custody.parent / "spike"), str(custody.parent)]
from receipt import ReceiptStore
from restart import capture, lifetime, retain
from test_receipt import LocalPair, file_identity
scope, receipt, legacy = [root / name for name in ("holder", "receipt", "legacy")]
for directory in (scope, receipt, legacy):
    directory.mkdir(mode=0o700)
history = legacy / "historical"
history.touch(mode=0o600)
history.write_bytes(b"immutable historical fixture")
lock = scope / "scope.lock"
lock.touch(mode=0o600)
fd = os.open(scope, os.O_RDONLY | os.O_DIRECTORY)
lock_id = file_identity(lock.stat())
try:
    pair = LocalPair(fd, lock_id)
    zero = pair.commitment(0, "initial")
    exact = pair.commitment(1, "settled")
    pair.restore(pair.pair(1, "settled"))
    store = ReceiptStore(receipt, zero)
    store.provision()
    store.commit(zero, exact)
    store.witness(exact)
    assert store.head() == pair.read()
finally:
    os.close(fd)
ids = {name: os.getuid() for name in ("controller", "holder", "legacy")}
retain(receipt, {"controller": lifetime(), "lock": list(lock_id), "initial": zero.wire(), "head": exact.wire(),
                 "snapshot": capture(receipt, scope, legacy, ids)})
"""
        verify = r"""
import json, os, sys
from pathlib import Path
root = Path(sys.argv[1])
custody = Path(sys.argv[2])
sys.path[:0] = [str(custody), str(custody.parent / "spike"), str(custody.parent)]
from restart import load_retained, require_retired, verify_retained
scope, receipt, legacy = [root / name for name in ("holder", "receipt", "legacy")]
record = load_retained(receipt, os.getuid())
fresh = require_retired(record["controller"])
ids = {name: os.getuid() for name in ("controller", "holder", "legacy")}
evidence = verify_retained(receipt, scope, legacy, ids, record)
print(json.dumps({**evidence, "distinct_pid": fresh[1] != record["controller"][1]}))
"""
        python = [sys.executable, "-I", "-S", "-B", "-c"]
        subprocess.run([*python, setup, str(scratch), str(ROOT)], env={}, check=True, timeout=5)
        result = subprocess.check_output([*python, verify, str(scratch), str(ROOT)], env={}, timeout=5)
        self.assertEqual(json.loads(result), {"fresh_controller_refused": True, "new_authorizations": 0,
                                             "new_holder_sends": 0, "receipt_unchanged": True,
                                             "legacy_history_preserved": True, "distinct_pid": True})


class QualificationRegressions(unittest.TestCase):
    def test_legacy_scratch_has_readable_protected_ancestor_and_private_home(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        for leaf in ("holder", "receipt", "scratch"):
            (root / leaf).mkdir(mode=0o700)
        identities = {role: (os.getuid(), os.getgid()) for role in ACCOUNTS}
        with (patch("run._HOLDER_MOUNT", root / "holder"), patch("run._RECEIPT_MOUNT", root / "receipt"),
              patch("run._SCRATCH_ROOT", root / "scratch")):
            appliance = Appliance(identities)
            try:
                mode = stat.S_IMODE(appliance.group.stat().st_mode)
                # Give this same-UID test the ancestor permissions that a
                # dropped nonowner would see. No account or privilege change.
                appliance.group.chmod((mode & 0o007) * 0o111)
                try:
                    directory = os.open(appliance.group, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    os.close(directory)
                finally:
                    appliance.group.chmod(mode)
                self.assertEqual(mode, 0o755)
                self.assertEqual(stat.S_IMODE(appliance.legacy_home.stat().st_mode), 0o700)
            finally:
                appliance.drain()
                appliance.cleanup()

    def test_unrelated_loser_is_not_credited_as_scope_contention(self):
        from run import _accept, _FAILURE, _POSITIVE_LEGACY

        appliance = Mock()
        appliance.count.return_value = 0
        appliance.local.read.return_value = appliance.store.head.return_value = "initial"

        def report(_job):
            if appliance.report.call_count == 1:
                return {"sends": 1, "settled": True}
            appliance.count.return_value = 1
            return {"refused": "wrong_grant"}

        def before_contention(_appliance, revision, *_args, **options):
            if revision:
                self.fail("unrelated loser was credited as a contender")
            return _FAILURE if options.get("wrong_peer") or options.get("route_mismatch") else {"refused": "wrong_grant"}

        appliance.report.side_effect = report
        with (patch("run._read_report", return_value=_POSITIVE_LEGACY), patch("run._history"),
              patch("run._one", side_effect=before_contention),
              self.assertRaisesRegex(CustodyRefused, "contending launch")):
            _accept(appliance)

    def test_unauthenticated_scope_gate_cannot_release_other_holder(self):
        from run import _serve_contender

        channel, store, gate = Mock(), Mock(), Mock()
        channel.receive.return_value = ["scope-gate", "unrelated", [1, 2]]
        with self.assertRaises(CustodyRefused):
            _serve_contender(channel, store, gate, "expected", (1, 2))
        gate.wait.assert_not_called()
        channel.send.assert_not_called()

    def test_spawn_parent_close_fault_reaps_already_owned_child(self):
        process = Mock()
        process.poll.return_value = None
        process.pid = 123
        process.returncode = None
        owns_child = []
        fault = OSError("synthetic parent descriptor close")

        def spawn(*_args, **_kwargs):
            owns_child.append(process)
            return process

        actual_close = os.close
        failed = False

        def close(fd):
            nonlocal failed
            actual_close(fd)
            if owns_child and not failed:
                failed = True
                raise fault

        fixture = SimpleNamespace(identities={"owner": (1000, 1000)}, homes={"owner": "/synthetic"}, children=[])
        incoming = {"bootstrap": 3, "controller_pidfd": 4, "owner": 5}
        with (patch("run.subprocess.Popen", side_effect=spawn), patch("run.os.close", side_effect=close),
              self.assertRaises(OSError) as failure):
            Appliance.spawn(fixture, "owner", {}, incoming)
        self.assertIs(failure.exception, fault)
        self.assertEqual(fixture.children, [process])
        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=4)
        self.assertTrue(process.stdout.closed)


    def test_spawn_error_is_not_replaced_by_parent_close_fault(self):
        original = OSError("synthetic spawn failure")
        attempted = False
        actual_close = os.close

        def spawn(*_args, **_kwargs):
            nonlocal attempted
            attempted = True
            raise original

        def close(fd):
            actual_close(fd)
            if attempted:
                raise OSError("synthetic close failure after spawn")

        fixture = SimpleNamespace(identities={"worker": (1000, 1000)}, homes={"worker": "/synthetic"}, children=[])
        with (patch("run.subprocess.Popen", side_effect=spawn), patch("run.os.close", side_effect=close),
              self.assertRaises(OSError) as failure):
            Appliance.spawn(fixture, "worker", {})
        self.assertIs(failure.exception, original)
        self.assertIn("Parent descriptor cleanup also failed", original.__notes__)
        self.assertEqual(fixture.children, [])


class RoleWiringTests(unittest.TestCase):
    def test_unprivileged_processes_wire_one_owner_and_holder_turn(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        for leaf in ("holder", "receipt", "scratch"):
            (root / leaf).mkdir(mode=0o700)

        def same_uid_spawn(appliance, role, config, fds):
            # Test only the protocol wiring. The sealed entry explicitly
            # rejects all-same-UID roles and is never invoked here.
            script = '''
import json, os, sys
from pathlib import Path
root, role, wire, device, inode = sys.argv[1:]
sys.path[:0] = [root, str(Path(root).parent / "spike"), str(Path(root).parent)]
from bootstrap import proc_self, verify_role_stdio
from descriptor import Denied
from roles import _run_measured, _verify_descriptor_objects, require_role_fds
config = json.loads(wire)
fds = require_role_fds(role, config["fds"])
with proc_self(inherited=fds.values()) as proc:
    standard = verify_role_stdio((int(device), int(inode)), proc=proc)
    _verify_descriptor_objects(fds, (os.getuid(), os.getgid()), config.get("lock"), standard=standard)
    try:
        result = _run_measured(role, config, proc)
    except Denied as failure:
        result = {"refused": failure.reason.value}
print(json.dumps(result))
'''
            child = _spawn_report([sys.executable, "-I", "-S", "-B", "-c", script, str(ROOT), role,
                                   json.dumps({**config, "fds": fds})], {}, fds.values(), appliance.children)
            return child

        roles = {role: (os.getuid(), os.getgid()) for role in ("holder", "owner", "legacy", "worker")}
        with (patch("run._HOLDER_MOUNT", root / "holder"), patch("run._RECEIPT_MOUNT", root / "receipt"),
              patch("run._SCRATCH_ROOT", root / "scratch"), patch.object(Appliance, "spawn", same_uid_spawn)):
            appliance = Appliance(roles)
            try:
                wrong = _one(appliance, 0, "initial", "first", fault="wrong-role")
                self.assertEqual(wrong, {"refused": "wrong_grant"})
                self.assertEqual(appliance.count(), 0)
                with patch.object(appliance, "probe") as probe:
                    lost = _contending(appliance)
                probe.assert_called_once()
                won = "second" if lost == "first" else "first"
                self.assertEqual(appliance.count(), 1)
                self.assertEqual(appliance.store.head(), appliance.local.commitment(2, "settled-" + won))
                self.assertEqual(_one(appliance, 2, "settled-" + won, lost), {"sends": 1, "settled": True})
                self.assertEqual(appliance.count(), 2)
            finally:
                appliance.drain()
            appliance.cleanup()


if __name__ == "__main__":
    unittest.main()
