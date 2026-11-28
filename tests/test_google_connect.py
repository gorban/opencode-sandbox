"""Exercise attended enrollment boundaries with local fixtures only."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager, nullcontext, redirect_stderr, suppress
import errno
from hashlib import sha256
from io import StringIO
import json
import os
from pathlib import Path
import pty
import select
import shutil
import signal
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import RLock
import time
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import oc_google

import google_connect_driver as offline
import google_home_controller as controller
from google_connect_driver import run_connect

from oc_google import auth_offer, connect, metadata_workflow, native_artifacts
from oc_google.native_service import NativeInvocation, NativeRetirementUnconfirmed
from oc_google.token_diagnostic import (
    CurrentTierDetail, LoadBodyReason, OriginalProjectDetail, PostTokenDiagnostic, PostTokenStage, TokenDiagnostic,
    TokenStage, scoped_post_token,
)


class OfflineGuestGuardTest(unittest.TestCase):
    def seal(self, uid, boot="00000000-0000-0000-0000-000000000001"):
        cases = {
            label: {"case": f"/run/user/{uid}/oc-g-connect-fixture-{index:08d}",
                    "config": "2" * 64, "root_id": [0, index * 3 + 1], "home_id": [0, index * 3 + 2],
                    "sandbox_id": [0, index * 3 + 3]}
            for index, label in enumerate(offline.LABELS)
        }
        return {"version": 1, "uid": uid, "boot": boot, "tree": "1" * 40,
                "source": dict.fromkeys(offline.SOURCE_FILES, "3" * 64), "firewall": "4" * 64, "cases": cases}

    def test_loopback_firewall_refuses_extra_rules_or_an_accept_default(self):
        import json

        name = "oc_gemini_fixture"
        base = {"family": "inet", "table": name}
        def match(left, right):
            return {"match": {"left": left, "right": right, "op": "=="}}
        loopback = [match({"meta": {"key": "oifname"}}, "lo"), {"accept": None}]
        reply = [
            match({"ct": {"key": "direction"}}, "reply"),
            match({"payload": {"protocol": "tcp", "field": "sport"}}, 22),
            match({"ct": {"key": "state"}}, "established"), {"accept": None},
        ]
        chains = [{"chain": {**base, "name": hook, "type": "filter", "hook": hook, "prio": 0, "policy": "drop"}}
                  for hook in ("output", "forward")]
        table = [{"table": {"family": "inet", "name": name}}, *chains,
                 *({"rule": {**base, "chain": "output", "expr": rule}} for rule in (loopback, reply))]
        def data(entries):
            return json.dumps({"nftables": entries}).encode("ascii")

        self.assertRegex(offline.firewall(data(table)), r"^[0-9a-f]{64}$")
        extra_rule = {"rule": {**base, "chain": "output", "expr": [{"accept": None}]}}
        extra_rule_data = data([*table, extra_rule])
        with self.assertRaises(offline.Refused):
            offline.firewall(extra_rule_data)
        chains[0]["chain"]["policy"] = "accept"
        accept_default_data = data(table)
        with self.assertRaises(offline.Refused):
            offline.firewall(accept_default_data)

    def test_projection_changes_only_account_home_and_binds_sealed_descriptor(self):
        root = Path(__file__).resolve().parents[1]
        original = (root / offline.CONFIG).read_text(encoding="utf-8")
        home = Path("/run/user/1001/oc-g-connect-fixture-abcd1234/home")
        output = offline.project_config(original, home)
        start = original.index("def _account_home()")
        end = original.index("def default_config_dir()")
        self.assertEqual(output[:start], original[:start])
        self.assertEqual(output[output.index("def default_config_dir()"):], original[end:])
        self.assertIn(f"    return Path({str(home)!r})", output)
        self.assertIn('env_home = os.environ.get("HOME")', output)
        with patch.object(offline, "copied_source", return_value={"fixture": "digest"}):
            seal = {"uid": 1001, "tree": "fixture", "cases": {"fixture-alpha": {"config": "digest"}}}
            fd = offline.prepare_descriptor(home.parent, "fixture-alpha", seal)
        try:
            self.assertEqual(offline.read_descriptor(fd)["label"], "fixture-alpha")
            with self.assertRaises(OSError):
                os.write(fd, b"tampered")
        finally:
            os.close(fd)

    def test_real_exchange_refused_before_any_config_lookup(self):
        case = Path("/fixture")
        config = Mock()
        with self.assertRaises(offline.Refused):
            offline.case_precheck(config, case / "home", case / "home/opencode-sandbox", "fixture-alpha", 1001)
        self.assertEqual(config.mock_calls, [])

    def test_stale_boot_or_unexpected_uid_refuses_before_runtime(self):
        uid = os.getuid()
        seal = self.seal(uid)
        with patch.object(offline, "protected"), patch.object(offline, "proof_file", return_value=seal), \
                patch.object(offline, "account", return_value=Mock(pw_uid=uid)), \
                patch.object(offline, "topology", return_value="new") as topology, \
                patch.object(offline, "bridge") as bridge:
            with self.assertRaises(offline.Refused):
                offline.guest()
            topology.assert_called_once_with(bridge)
            bridge.assert_not_called()
            topology.reset_mock()
            seal["uid"] = uid + 1
            with self.assertRaises(offline.Refused):
                offline.guest()
            topology.assert_not_called()
            bridge.assert_not_called()

    def test_valid_projected_home_drives_config_and_exact_vendor_resolution(self):
        original = (Path(__file__).resolve().parents[1] / offline.CONFIG).read_text(encoding="utf-8")
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            sandbox = home / "opencode-sandbox"
            config_dir, artifact = home / ".config/oc-sandbox", home / offline.ARTIFACT
            old_umask = os.umask(0o077)
            try:
                for path in (sandbox, config_dir, artifact):
                    path.mkdir(mode=0o700, parents=True)
            finally:
                os.umask(old_umask)
            label = "fixture-alpha"
            (config_dir / "providers.toml").write_text(
                f'[providers.google.{label}]\nenabled = true\nauth_mode = "subscription"\n', encoding="ascii",
            )
            names = ("agy_acp_server.par", "localharness_external")
            for name in names:
                (artifact / name).write_bytes(b"fixture")
            vendor = dict.fromkeys(names, (7, sha256(b"fixture").hexdigest()))
            module = ModuleType("oc_providers.config")
            module.__package__ = "oc_providers"
            marker = SimpleNamespace(SYNTHETIC_FIXTURE_EXCHANGE=True)
            with patch.dict(sys.modules, {"oc_providers.config": module}):
                exec(compile(offline.project_config(original, home), "projected-config.py", "exec"), module.__dict__)
                with patch.object(connect, "_account_home", module._account_home), \
                        patch.object(oc_google, "metadata_destination", marker), \
                        patch.object(offline, "PINS", vendor), patch.object(native_artifacts, "_PINNED", vendor), \
                        patch.dict(os.environ, {"HOME": str(home)}):
                    def check():
                        offline.case_precheck(module, home, sandbox, label, os.getuid())
                    check()
                    with patch.dict(os.environ, {"HOME": str(root)}):
                        with self.assertRaises((offline.Refused, RuntimeError)):
                            check()
                    with self.assertRaises(offline.Refused):
                        offline.case_precheck(module, home, sandbox, "fixture-beta", os.getuid())
                    node = offline.checked_node
                    def aliased(path, *args, **kwargs):
                        return node(sandbox if path == artifact else path, *args, **kwargs)
                    with patch.object(offline, "checked_node", side_effect=aliased):
                        with self.assertRaises(offline.Refused):
                            check()
                    (artifact / names[0]).write_bytes(b"changed")
                    with self.assertRaises(offline.Refused):
                        check()

    def test_case_pin_refuses_replacement_and_nonempty_sandbox(self):
        uid = os.getuid()
        with TemporaryDirectory() as temporary:
            runtime = Path(temporary) / str(uid)
            case = runtime / "oc-g-connect-fixture-abcd1234"
            home = case / "home"
            sandbox = home / "opencode-sandbox"
            for directory in (runtime, case, home, sandbox):
                directory.mkdir(mode=0o700)
            case_record = {"case": str(case), "home_id": offline.identity(home.stat()), "config": "2" * 64,
                           "root_id": offline.identity(case.stat()), "sandbox_id": offline.identity(sandbox.stat())}
            seal = {"uid": uid, "cases": {"fixture-alpha": case_record}}
            with patch.object(offline, "USER_RUNTIME", runtime.parent):
                with offline.case_paths(seal, "fixture-alpha") as found:
                    self.assertEqual(found, (case, home, sandbox))
                marker = sandbox / "unexpected"
                marker.touch()
                paths = offline.case_paths(seal, "fixture-alpha")
                with self.assertRaises(offline.Refused, msg="Nonempty sandbox reached enrollment"):
                    self.enterContext(paths)
                marker.unlink()
                sandbox.rename(sandbox.with_name("retained"))
                sandbox.mkdir(mode=0o700)
                paths = offline.case_paths(seal, "fixture-alpha")
                with self.assertRaises(offline.Refused, msg="Replacement sandbox reached enrollment"):
                    self.enterContext(paths)
                case.rename(case.with_name("replaced"))
                case.mkdir(mode=0o700)
                paths = offline.case_paths(seal, "fixture-alpha")
                with self.assertRaises(offline.Refused, msg="Replacement case reached enrollment"):
                    self.enterContext(paths)

    def test_boot_and_pid_identity_precede_firewall_and_source(self):
        uid = os.getuid()
        boot = "00000000-0000-0000-0000-000000000001"
        seal = self.seal(uid, boot)
        receipts = (str(uid).encode("ascii"), b"net:[10]", b"pid:[20]")
        with patch.object(offline, "protected"), patch.object(offline, "proof_file", return_value=seal), \
                patch.object(offline, "account", return_value=Mock(pw_uid=uid)), \
                patch.object(offline, "topology", return_value=boot), \
                patch.object(offline, "local_placement", return_value=boot) as local, \
                patch.object(offline, "bridge", side_effect=receipts) as bridge, \
                patch.object(os, "readlink", side_effect=("net:[10]", "pid:[21]")):
            with self.assertRaises(offline.Refused):
                offline.guest()
            self.assertEqual([call.args for call in bridge.call_args_list],
                             [("/usr/bin/id", "-ru"), ("/usr/bin/readlink", "/proc/self/ns/net"),
                              ("/usr/bin/readlink", "/proc/self/ns/pid")])
            bridge.reset_mock()
            local.return_value = "alternate-boot"
            with self.assertRaises(offline.Refused):
                offline.guest()
            bridge.assert_not_called()

    def test_nonobject_and_duplicate_proof_rejected(self):
        for data in (b'[]', b'{"label":"one","label":"two"}'):
            with self.subTest(data=data), self.assertRaises(offline.Refused):
                offline.read_proof(data)

    def test_malformed_nested_case_rejected_before_any_host_or_vendor_call(self):
        uid = os.getuid()
        for invalid in ([], {}, {"case": "/fixture"},
                        self.seal(uid)["cases"]["fixture-beta"] | {"root_id": [0, True]},
                        self.seal(uid)["cases"]["fixture-beta"] | {"config": "malformed"},
                        self.seal(uid)["cases"]["fixture-beta"] | {"case": "/fixture"}):
            with self.subTest(invalid=invalid):
                seal = self.seal(uid)
                seal["cases"]["fixture-beta"] = invalid
                with patch.object(offline, "protected"), patch.object(offline, "proof_file", return_value=seal), \
                        patch.object(offline, "account", return_value=Mock(pw_uid=uid)) as account, \
                        patch.object(offline, "topology") as topology, patch.object(offline, "bridge") as bridge, \
                        patch.object(offline, "vendor_pair") as vendor:
                    with self.assertRaises(offline.Refused):
                        offline.guest()
                    for operation in (account, topology, bridge, vendor):
                        operation.assert_not_called()

    def test_home_fingerprint_checks_fixed_cap_and_all_entries(self):
        with TemporaryDirectory() as temporary:
            home = Path(temporary)
            (home / "directory").mkdir(mode=0o700)
            leaf = home / "directory" / "file"
            leaf.touch(mode=0o600)
            (home / "another").touch()
            with patch.object(offline, "TEST_HOME", home), patch.object(offline, "HOME_ENTRY_LIMIT", 4):
                baseline = offline.home_snapshot(os.getuid())
                self.assertEqual(baseline[0], 4)
                self.assertRegex(baseline[1], r"^[0-9a-f]{64}$")
                self.assertEqual(offline.home_snapshot(os.getuid()), baseline)
                leaf.chmod(0o400)
                self.assertNotEqual(offline.home_snapshot(os.getuid()), baseline)
                (home / "above-cap").touch()
                with self.assertRaises(offline.Refused):
                    offline.home_snapshot(os.getuid())

    def test_targeted_ordinary_check_avoids_restricted_store(self):
        uid = os.getuid()
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = root / "rootless-store"
            store.mkdir(mode=0o700)
            (root / ".config").mkdir(mode=0o700)
            opened = os.open

            def read_directory(path, *args, **kwargs):
                if path == "rootless-store":
                    raise PermissionError("opaque subordinate UID directory")
                return opened(path, *args, **kwargs)
            with patch.object(offline, "TEST_HOME", root), \
                    patch.object(offline.os, "open", side_effect=read_directory) as read:
                offline.ordinary_provider_roots(uid, offline.identity(root.stat()))
                self.assertNotIn("rootless-store", [call.args[0] for call in read.call_args_list])
                with self.assertRaises(PermissionError):
                    offline.home_snapshot(uid)

    def test_invalid_provider_leaf_or_parent_refuses_targeted_check(self):
        for case in ("leaf", "dangling leaf", "parent symlink", "parent file", "inaccessible parent"):
            with self.subTest(case=case), TemporaryDirectory() as temporary:
                root = Path(temporary)
                config = root / ".config"
                if case == "parent symlink":
                    config.symlink_to(root / "missing")
                elif case == "parent file":
                    config.touch()
                else:
                    config.mkdir(mode=0o700)
                    target = config / "oc-sandbox"
                    if case == "leaf":
                        target.mkdir()
                    if case == "dangling leaf":
                        target.symlink_to(root / "missing")

                opened = os.open

                def read_directory(path, *args, **kwargs):
                    if case == "inaccessible parent" and path == ".config":
                        raise PermissionError("fixture blocked directory")
                    return opened(path, *args, **kwargs)
                with patch.object(offline, "TEST_HOME", root), patch.object(offline.os, "open", side_effect=read_directory):
                    uid = os.getuid()
                    home_id = offline.identity(root.stat())
                    with self.assertRaises((offline.Refused, PermissionError)):
                        offline.ordinary_provider_roots(uid, home_id)

    def test_unbound_home_before_refuses_before_targeted_walk(self):
        scope = {"uid": 1000, "tree": "1" * 40, "boot": "0" * 36, "home_id": [2, 6], "seal": "2" * 64}
        before = {"version": 1, "scope": scope, "entries": 65_956, "sha256": "3" * 64}
        for case, changed in (
            ("valid", before), ("wrong seal", before | {"scope": scope | {"seal": "4" * 64}}),
            ("wrong tree", before | {"scope": scope | {"tree": "4" * 40}}),
            ("wrong boot", before | {"scope": scope | {"boot": "4" * 36}}),
            ("wrong uid", before | {"scope": scope | {"uid": 1001}}),
            ("wrong home inode", before | {"scope": scope | {"home_id": [2, 7]}}),
            ("invalid digest", before | {"sha256": "invalid"}),
            ("malformed", before | {"entries": False}), ("missing", FileNotFoundError()),
            ("already settled", before),
        ):
            with self.subTest(case=case), patch.object(offline, "home_evidence_scope", return_value=scope), \
                    patch.object(offline, "absent", return_value=case != "already settled"), \
                    patch.object(offline, "proof_file", side_effect=[changed]), \
                    patch.object(offline, "ordinary_provider_roots") as targeted:
                if case == "valid":
                    offline.check_home_before({})
                    targeted.assert_called_once_with(1000, [2, 6])
                else:
                    with self.assertRaises((offline.Refused, FileNotFoundError)):
                        offline.check_home_before({})
                    targeted.assert_not_called()

    def test_root_controller_binds_before_and_requires_real_completion(self):
        uid = max(os.getuid(), 1)
        seal = self.seal(uid)
        scope = {"uid": uid, "tree": seal["tree"], "boot": seal["boot"], "home_id": [2, 6], "seal": "2" * 64}
        evidence = {"entries": 65_956, "sha256": "3" * 64}
        with TemporaryDirectory() as temporary:
            capsule = Path(temporary)
            case, home = capsule / "case", capsule / "case/home"
            sandbox = home / "opencode-sandbox"
            sandbox.mkdir(parents=True)
            with patch.object(offline, "CAPSULE", capsule), \
                    patch.object(offline, "root_home_scope", return_value=(seal, scope)), \
                    patch.object(offline, "case_paths", return_value=nullcontext((case, home, sandbox))), \
                    patch.object(offline, "capture_home_evidence", return_value=evidence):
                offline.begin_home_attestation()
                before = json.loads((capsule / offline.HOME_BEFORE).read_text())
                self.assertEqual(before, {"version": 1, "scope": scope, **evidence})
                self.assertEqual(stat.S_IMODE((capsule / offline.HOME_BEFORE).stat().st_mode), 0o444)
                with self.assertRaises(offline.Refused):
                    offline.begin_home_attestation()

            captured = {"scope": scope, "home_before_sha256": "6" * 64, "after": evidence}
            for after, complete in ((evidence, True), (evidence | {"sha256": "4" * 64}, False)):
                with self.subTest(complete=complete), patch.object(offline, "CAPSULE", capsule), \
                        patch.object(offline, "root_home_scope", return_value=(seal, scope)), \
                        patch.object(offline, "verified_home_before", return_value=before), \
                        patch.object(offline, "absent", return_value=True), \
                        patch.object(offline, "capture_home_evidence") as outside_window, \
                        patch.object(offline, "write_protected") as write, patch("builtins.print") as display:
                    def read_record(path):
                        if path.name == offline.HOME_BEFORE:
                            return before
                        return json.loads(write.call_args.args[1])

                    def digest_record(path):
                        if path.name == offline.NATIVE_RESULT:
                            return sha256(write.call_args.args[1]).hexdigest()
                        return "6" * 64

                    with patch.object(offline, "proof_file", side_effect=read_record), \
                            patch.object(offline, "digest", side_effect=digest_record):
                        self.assertEqual(offline.finish_home_attestation(
                            0, controller.POSITIVE, True, captured | {"after": after}), int(not complete))
                    outside_window.assert_not_called()
                    native_write, home_write = (call.args for call in write.call_args_list)
                    self.assertEqual(native_write[0].name, offline.NATIVE_RESULT)
                    self.assertEqual(home_write[0].name, offline.HOME_RESULT)
                    receipt = json.loads(home_write[1])
                    self.assertEqual(receipt["native_result_sha256"], sha256(native_write[1]).hexdigest())
                    self.assertEqual(receipt["home_before_sha256"], "6" * 64)
                    self.assertEqual(receipt["after"], after)
                    self.assertEqual(receipt["completed"], complete)
                    self.assertEqual((receipt["scope"], receipt["exit_status"]), (scope, 0))
                    self.assertEqual(display.called, complete)

    def test_incomplete_receipt_withholds_after_and_custody(self):
        scope = {"fixture": "scope"}
        with TemporaryDirectory() as temporary, patch.object(offline, "CAPSULE", Path(temporary)), \
                patch.object(offline, "root_home_scope", return_value=({}, scope)), \
                patch.object(offline, "capture_home_evidence") as after:
            offline.record_incomplete_home_attestation("release")
            receipt = json.loads((offline.CAPSULE / offline.HOME_RESULT).read_text())
            self.assertEqual(receipt, {"version": 1, "scope": scope, "phase": "release", "after": None,
                                       "home_unchanged": None, "completed": False, "custody": "unconfirmed"})
            self.assertFalse((offline.CAPSULE / offline.NATIVE_RESULT).exists())
            after.assert_not_called()

    def test_absence_revalidates_each_ancestor_link(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            share = root / ".local/share"
            path = Path(".local/share/oc-sandbox/google/standalone-1.5.2")
            (root / path.parent).mkdir(parents=True)
            original_stat = os.stat

            def swap(name, *args, **kwargs):
                if name == path.name:
                    share.rename(share.with_name("old-share"))
                    share.mkdir()
                    raise FileNotFoundError()
                return original_stat(name, *args, **kwargs)

            fd = os.open(root, offline.DIRECTORY)
            try:
                with patch.object(offline.os, "stat", side_effect=swap), self.assertRaises(offline.Refused):
                    offline.require_absent_beneath(fd, path)
            finally:
                os.close(fd)

    def test_controller_refuses_tampered_source_before_driver_code(self):
        with TemporaryDirectory() as temporary:
            source = Path(temporary)
            (source / controller.DRIVER).parent.mkdir()
            entry = source / controller.DRIVER
            entry.write_bytes(b"raise AssertionError('must not import driver')")
            helper = source / "helper.py"
            helper.write_bytes(b"altered")
            self_bytes = b"measured controller"
            manifest = {"tree": "1" * 40, "controller": sha256(self_bytes).hexdigest(),
                        "source": {controller.DRIVER: sha256(entry.read_bytes()).hexdigest(),
                                   "helper.py": sha256(b"expected").hexdigest()}}
            payload = json.dumps(manifest).encode("ascii")

            def read(path, _):
                if path == controller.CONTROLLER:
                    return self_bytes
                if path == controller.MANIFEST:
                    return payload
                return path.read_bytes()

            with patch.object(controller, "SOURCE", source), patch.object(controller, "protected_directory"), \
                    patch.object(controller, "protected_bytes", side_effect=read):
                digest = sha256(payload).hexdigest()
                with self.assertRaises(controller.ControllerRefused):
                    controller.pinned_driver(digest)
                with self.assertRaises(controller.ControllerRefused):
                    controller.pinned_driver("0" * 64)

    def test_controller_owns_exact_held_exec_vector(self):
        seal = {"uid": 1000, "tree": "1" * 40, "source": {}}
        user = SimpleNamespace(pw_uid=1000, pw_gid=1001, pw_name="oc-gemini-proof",
                               pw_dir="/home/oc-gemini-proof")
        driver = {"absent": Mock(return_value=False), "proof_file": Mock(return_value=seal),
                  "validate_seal": Mock(), "HOME_BEFORE": "home-before", "HOME_RESULT": "home-result",
                  "NATIVE_RESULT": "native-result"}
        driver["absent"].side_effect = lambda path: path.name != "seal.json"
        with patch.object(controller, "pinned_driver", return_value=(driver, seal)), \
                patch.object(controller.pwd, "getpwnam", return_value=user), \
                patch.object(controller, "inspect_devbox", return_value="a" * 64) as inspect, \
                patch.object(controller, "observe_run", return_value=0) as owned:
            pin = "c" * 64
            self.assertEqual(controller.run_controller(pin), 0)
            args = owned.call_args.args[1]
            prefix, = inspect.call_args.args
            self.assertEqual(args, (*prefix, "exec", "-i", "--user", "1000:1001", "a" * 64,
                                    "/usr/bin/env", "-i", "HOME=/home/oc-gemini-proof", "PATH=/usr/bin:/bin",
                                    "LANG=C.UTF-8", "/usr/bin/python3", "-IBS",
                                    "/home/.oc-gemini-cold-proof/google_home_controller.py", "--held-exec", pin))

    def test_two_barriers_hold_transport_through_capture_and_retirement(self):
        good = controller.OUTCOME + b"\0" + controller.POSITIVE
        for case, messages, status, interrupted, phase, captures in (
            ("positive", (controller.READY, good, controller.RETIRED), 0, None, None, True),
            ("wrong ready", (controller.RELEASE,), 0, None, "ready", False),
            ("early EOF", (controller.READY, controller.ControllerRefused()), 0, None, "child", False),
            ("wrong status", (controller.READY, controller.OUTCOME + b"\1" + controller.POSITIVE),
             0, None, "child", False),
            ("duplicate ready", (controller.READY, controller.READY), 0, None, "child", False),
            ("duplicate outcome", (controller.READY, good, good), 0, None, "release", True),
            ("capture exception", (controller.READY, good), 0, "capture_home_after", "capture", True),
            ("wrong retire", (controller.READY, good, controller.READY), 0, None, "release", True),
            ("duplicate retire", (controller.READY, good, controller.RETIRED), 0, "require_eof", "release", True),
            ("client failure", (controller.READY, good, controller.RETIRED), 7, None, "release", True),
        ):
            with self.subTest(case=case):
                owner = Mock()
                client = owner.client
                channel = owner.channel
                driver = {name: getattr(owner, name) for name in (
                    "begin_home_attestation", "capture_home_after", "finish_home_attestation",
                    "record_incomplete_home_attestation",
                )}
                driver["finish_home_attestation"].return_value = 0
                channel.read.side_effect = messages
                client.wait.return_value = status
                if interrupted == "capture_home_after":
                    owner.capture_home_after.side_effect = PermissionError()
                elif interrupted == "require_eof":
                    channel.require_eof.side_effect = controller.ControllerRefused()
                with patch.object(controller, "held_client", return_value=nullcontext(client)), \
                        patch.object(controller, "Frames", return_value=channel), patch("builtins.print"):
                    self.assertEqual(controller.observe_run(driver, ("fixture",)), int(phase is not None))
                self.assertEqual(owner.capture_home_after.called, captures)
                if phase is None:
                    owner.record_incomplete_home_attestation.assert_not_called()
                    self.assertEqual([call[0] for call in owner.mock_calls if call[0] in {
                        "channel.read", "begin_home_attestation", "channel.write", "capture_home_after",
                        "client.stdin.close", "channel.require_eof", "client.wait", "finish_home_attestation",
                    }], ["channel.read", "begin_home_attestation", "channel.write", "channel.read",
                         "capture_home_after", "channel.write", "client.stdin.close", "channel.read",
                         "channel.require_eof", "client.wait", "finish_home_attestation"])
                    owner.finish_home_attestation.assert_called_once_with(
                        0, controller.POSITIVE, True, owner.capture_home_after.return_value,
                    )
                else:
                    owner.finish_home_attestation.assert_not_called()
                    owner.record_incomplete_home_attestation.assert_called_once_with(phase)

    def test_supervisor_owns_child_and_refuses_unexpected_descendant(self):
        uid = 1000
        seal = {"uid": uid, "tree": "1" * 40, "source": {}}
        for unexpected in (False, True):
            with self.subTest(unexpected=unexpected):
                owner = Mock()
                driver = {"guest": Mock(return_value=seal), "private_inventory": owner.inventory,
                          "check_home_before": owner.before}
                channel = owner.channel
                channel.read.side_effect = (controller.START, controller.RELEASE)
                child_check = [None, controller.ControllerRefused()] if unexpected else [None] * 3
                with patch.object(controller, "pinned_driver", return_value=(driver, seal)), \
                        patch.object(controller.os, "getuid", return_value=uid), \
                        patch.object(controller.os, "geteuid", return_value=uid), \
                        patch.dict(os.environ, {"HOME": controller.HOME}), \
                        patch.object(controller, "subreaper", owner.subreaper), \
                        patch.object(controller, "no_children", side_effect=child_check), \
                        patch.object(controller, "Frames", return_value=channel), \
                        patch.object(controller, "bounded_run", return_value=(0, controller.POSITIVE)) as child:
                    if unexpected:
                        with self.assertRaises(controller.ControllerRefused):
                            controller.run_held_supervisor("pin")
                        channel.write.assert_called_once_with(controller.READY)
                    else:
                        self.assertEqual(controller.run_held_supervisor("pin"), 0)
                        self.assertEqual([call.args[0] for call in channel.write.call_args_list],
                                         [controller.READY, controller.OUTCOME + b"\0" + controller.POSITIVE,
                                          controller.RETIRED])
                        self.assertEqual(owner.inventory.call_count, 3)
                    child.assert_called_once_with(controller.fixture_command(), seconds=channel.remaining.return_value,
                                                   limit=4096, env=controller.ENV | {"HOME": controller.HOME})

    def test_real_pipe_transport_holds_creation_and_release_outside_observation(self):
        import textwrap

        script = textwrap.dedent("""
            import os, struct, sys
            from pathlib import Path
            store = Path(sys.argv[1])
            def send(payload):
                os.write(1, struct.pack("!H", len(payload)) + payload)
            def receive(expected):
                size, = struct.unpack("!H", os.read(0, 2))
                assert os.read(0, size) == expected
            store.write_text("exec open")
            send(b"R")
            receive(b"S")
            send(b"O" + bytes((0,)) + bytes.fromhex(sys.argv[2]))
            receive(b"L")
            assert os.read(0, 1) == b""
            store.write_text("exec released")
            send(b"D")
        """)
        with TemporaryDirectory() as temporary:
            store = Path(temporary) / "synthetic-database"
            store.write_text("exec not created")
            window = []

            def begin():
                window.append(store.read_text())

            def capture():
                window.append(store.read_text())
                return tuple(window)

            def finish(status, output, verified, held):
                self.assertEqual((status, output, verified), (0, controller.POSITIVE, True))
                self.assertEqual(held, ("exec open", "exec open"))
                self.assertEqual(store.read_text(), "exec released")
                return 0

            incomplete = Mock()
            driver = {"begin_home_attestation": begin, "capture_home_after": capture,
                      "finish_home_attestation": finish, "record_incomplete_home_attestation": incomplete}
            argv = (sys.executable, "-IBS", "-c", script, str(store), controller.POSITIVE.hex())
            with patch("builtins.print"):
                self.assertEqual(controller.observe_run(driver, argv), 0)
            incomplete.assert_not_called()

    def test_controller_bounds_owned_process_output_and_time(self):
        status, output = controller.bounded_run((sys.executable, "-IBS", "-c", "print('synthetic'); raise SystemExit(7)"),
                                                seconds=3, limit=32)
        self.assertEqual((status, output), (7, b"synthetic\n"))
        with self.assertRaises(controller.ControllerRefused):
            controller.bounded_run((sys.executable, "-IBS", "-c", "print('x' * 100)"), seconds=3, limit=32)
        with self.assertRaises(subprocess.TimeoutExpired):
            controller.bounded_run((sys.executable, "-IBS", "-c", "import time; time.sleep(10)"),
                                   seconds=0.1, limit=32)

    def test_other_case_config_refused_before_import(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(offline, "CAPSULE", root), patch.object(offline, "SOURCE", root / "source"), \
                    patch.object(offline, "protected", return_value=Mock(st_mode=0o444)):
                protected_source = offline.SOURCE / offline.CONFIG
                protected_source.parent.mkdir(parents=True)
                original = (Path(__file__).resolve().parents[1] / offline.CONFIG).read_text(encoding="utf-8")
                protected_source.write_text(original, encoding="utf-8")
                label = "fixture-alpha"
                target = root / "case-config" / label / "config.py"
                target.parent.mkdir(parents=True)
                target.write_text(offline.project_config(original, root / "other-home"), encoding="utf-8")
                seal = {"cases": {label: {"config": sha256(target.read_bytes()).hexdigest()}}}
                with self.assertRaises(offline.Refused):
                    offline.load_projected_config(seal, label, root / "correct-home")

    def test_ordinary_home_directory_swap_refuses_without_traversal(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, outside = root / "ordinary", root / "outside"
            home.mkdir(mode=0o700)
            outside.mkdir(mode=0o700)
            (home / "sub").mkdir(mode=0o700)
            open_dir = os.open

            def swap(path, *args, **kwargs):
                if path == "sub":
                    (home / "sub").rename(home / "retained")
                    (home / "sub").symlink_to(outside)
                return open_dir(path, *args, **kwargs)
            with patch.object(offline, "TEST_HOME", home), patch.object(offline.os, "open", side_effect=swap):
                with self.assertRaises((offline.Refused, OSError)):
                    offline.home_snapshot(os.getuid())

    def test_source_shadow_and_symlink_refused(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid = root / "driver.py"
            valid.touch(mode=0o400)
            root.chmod(0o500)
            try:
                self.assertEqual(set(offline.copied_source(root, os.getuid(), ("driver.py",))), {"driver.py"})
                root.chmod(0o700)
                shadow = root / "provider.py"
                shadow.symlink_to(valid)
                root.chmod(0o500)
                with self.assertRaises(offline.Refused):
                    offline.copied_source(root, os.getuid(), ("driver.py",))
            finally:
                root.chmod(0o700)

    def test_ordinary_home_inventory_does_not_follow_and_detects_change(self):
        with TemporaryDirectory() as temporary:
            base = Path(temporary)
            home = base / "home"
            home.mkdir(mode=0o700)
            target = base / "unread"
            target.mkdir()
            (home / "link").symlink_to(target)
            with patch.object(offline, "TEST_HOME", home):
                before = offline.home_snapshot(os.getuid())
                (target / "ignored").touch()
                self.assertEqual(offline.home_snapshot(os.getuid()), before)
                (home / "changed").touch()
                self.assertNotEqual(offline.home_snapshot(os.getuid()), before)
                (home / ".config").symlink_to(target)
                with self.assertRaises(offline.Refused):
                    offline.home_snapshot(os.getuid())


class TerminalOwnerTest(unittest.TestCase):
    def setUp(self):
        self.identity = self.enterContext(patch.object(connect._TerminalOwner, "_identify", return_value=(1, 2)))
        self.owner = connect._TerminalOwner(7)
        self.enterContext(patch.object(self.owner, "_ready", return_value=True))

    def test_short_offer_is_single_shot_and_revokes(self):
        with patch.object(connect, "_libc_write", return_value=1) as write:
            with self.assertRaises(connect.ConnectError):
                self.owner.offer(SimpleNamespace(url="https://example.invalid/synthetic"))
            self.assertFalse(self.owner.authorized())
        expected = b"Google sign-in link for this workstation\nhttps://example.invalid/synthetic\n"
        write.assert_called_once_with(7, expected, len(expected))

    def test_lost_foreground_stays_revoked_after_return(self):
        self.identity.return_value = (1, 3)
        self.assertFalse(self.owner.authorized())
        self.identity.return_value = (1, 2)
        self.assertFalse(self.owner.authorized())

    def test_job_control_signal_during_offer_revokes_after_write(self):
        def signal_and_write(_fd, data, _length):
            self.owner.mark_signal(signal.SIGCONT, None)
            return len(data)

        with patch.object(connect, "_libc_write", side_effect=signal_and_write) as write:
            with self.assertRaises(connect.ConnectError):
                self.owner.offer(SimpleNamespace(url="https://example.invalid/synthetic"))
            self.assertFalse(self.owner.authorized())
        write.assert_called_once()

    def test_queued_bytes_are_flushed_before_bounded_consent_read(self):
        calls = Mock()
        calls.read.side_effect = [b"y", b"\n"]
        with patch.object(connect.termios, "tcflush", calls.flush), patch.object(self.owner, "write_once", calls.notice), \
                patch.object(connect.os, "read", calls.read):
            self.assertTrue(self.owner.consent("fixture"))
        self.assertEqual([item[0] for item in calls.mock_calls], ["flush", "notice", "read", "read"])
        text = calls.notice.call_args.args[0]
        for wording in ("cloud-platform", "Broad access", "userinfo.email", "aicode", "offline refresh", "zero inference"):
            self.assertIn(wording, text)


    def test_decline_blank_timeout_or_read_race_latches_rejection(self):
        for label, chunks, ready in (
            ("decline", [b"n", b"\n"], True),
            ("blank", [b"\n"], True),
            ("timeout", [], False),
            ("read race", [BlockingIOError(errno.EAGAIN, "fixture input race")], True),
        ):
            with self.subTest(label=label):
                self.owner.cancelled = False
                with patch.object(connect.termios, "tcflush"), patch.object(self.owner, "write_once"), \
                        patch.object(self.owner, "_ready", return_value=ready), \
                        patch.object(connect.os, "read", side_effect=chunks):
                    self.assertFalse(self.owner.consent("fixture"))
                self.assertFalse(self.owner.authorized())


class TerminalDescriptorTest(unittest.TestCase):
    def test_tty_identity_requires_readable_input_and_writable_output(self):
        def tty_ioctl(fd, operation, _buffer):
            if operation == connect._TIOCGPTN:
                raise OSError(errno.ENOTTY, "fixture terminal slave")
            return b"tty1"

        for input_mode, output_mode in ((os.O_WRONLY, os.O_RDWR), (os.O_RDWR, os.O_RDONLY)):
            with self.subTest(input_mode=input_mode, output_mode=output_mode), \
                    patch.object(connect, "terminal", return_value=(1, 2, 3, 4, 5)), \
                    patch.object(connect, "ioctl", side_effect=tty_ioctl), \
                    patch.object(connect.os, "tcgetpgrp", return_value=6), \
                    patch.object(connect.os, "getpgrp", return_value=6), \
                    patch.object(connect.os, "getsid", return_value=4), \
                    patch.object(connect, "fcntl", create=True,
                                 side_effect=lambda fd, _operation: (input_mode, output_mode)[fd]):
                with self.assertRaisesRegex(connect.ConnectError, "readable input and writable output"):
                    connect._TerminalOwner(7)


class ConnectTest(unittest.TestCase):
    def test_google_fixture_driver_refuses_unsealed_connect(self):
        driver = Path(__file__).with_name("google_connect_driver.py")
        with TemporaryDirectory(prefix="oc-google-unsealed-") as path:
            home = Path(path)
            result = subprocess.run(
                [sys.executable, "-IBS", str(driver), "--fixture", "fixture-alpha", "2"],
                env={"HOME": str(home)}, stdin=subprocess.DEVNULL, capture_output=True, timeout=5, check=False,
            )
            self.assertEqual((result.returncode, result.stdout), (1, b""))
            self.assertEqual(result.stderr, b"Offline Google fixture refused before enrollment.\n")
            self.assertEqual(list(home.iterdir()), [])

    def test_cli_path_is_refused_before_terminal_or_resources(self):
        spec = SimpleNamespace(enabled=True, auth_mode="subscription", cli_path="/path/ignored")
        with patch.object(connect, "load_provider_config", return_value=Mock(get=Mock(return_value=spec))), \
                patch.object(connect, "_attended_owner") as attended, patch.object(connect, "RegistrationJournal") as journal:
            with self.assertRaisesRegex(connect.ConnectError, "without a CLI override"):
                connect.connect_for("fixture")
        attended.assert_not_called()
        journal.assert_not_called()

    def test_consent_refusal_precedes_runtime_openssl_and_journal(self):
        spec = SimpleNamespace(enabled=True, auth_mode="subscription", cli_path=None)
        owner = Mock(consent=Mock(return_value=False))
        with patch.object(connect, "load_provider_config", return_value=Mock(get=Mock(return_value=spec))), \
                patch.object(connect, "_attended_owner", return_value=nullcontext(owner)), \
                patch.object(connect, "_preflight"), patch.object(connect, "_private_runtime") as place, \
                patch.object(connect, "_artifacts", return_value=nullcontext(1)), \
                patch.object(connect, "verify_standalone_source", create=True) as source_check, \
                patch.object(connect, "host") as host, patch.object(connect, "RegistrationJournal") as journal:
            with self.assertRaisesRegex(connect.ConnectError, "cancelled"):
                connect.connect_for("fixture")
        source_check.assert_called_once_with(1)
        owner.consent.assert_called_once_with("fixture")
        place.assert_not_called()
        host.assert_not_called()
        journal.assert_not_called()

    def test_missing_or_untrusted_artifact_refuses_before_consent_or_effects(self):
        spec = SimpleNamespace(enabled=True, auth_mode="subscription", cli_path=None)
        owner = Mock()
        for failure in ("missing", "symlink", "writable", "size"):
            with self.subTest(failure=failure), TemporaryDirectory() as path:
                source = Path(path)
                (source / "companion").write_bytes(b"fixture")
                member = source / "standalone"
                if failure == "symlink":
                    member.symlink_to(source / "companion")
                elif failure != "missing":
                    member.write_bytes(b"x" if failure == "size" else b"fixture")
                    member.chmod(0o620 if failure == "writable" else 0o600)
                source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with patch.object(connect, "load_provider_config", return_value=Mock(get=Mock(return_value=spec))), \
                            patch.object(connect, "_attended_owner", return_value=nullcontext(owner)), \
                            patch.object(connect, "_preflight"), patch.object(connect, "_private_runtime") as place, \
                            patch.object(connect, "_artifacts", return_value=nullcontext(source_fd)), \
                            patch.object(native_artifacts, "_PINNED", {"standalone": (7, ""), "companion": (7, "")}), \
                            patch.object(connect, "host") as host, patch.object(connect, "RegistrationJournal") as journal:
                        with self.assertRaises(native_artifacts.NativeArtifactError):
                            connect.connect_for("fixture")
                finally:
                    os.close(source_fd)
                owner.consent.assert_not_called()
                place.assert_not_called()
                host.assert_not_called()
                journal.assert_not_called()

    def test_preflight_verifies_the_exact_host_shell_and_env_tools(self):
        def host(tool, *args, **_kwargs):
            if args == ("-c", "%u %f", "--", "/usr/bin/xdg-open"):
                return Mock(returncode=0, stdout=b"0 81a4\n")
            replies = {
                "id": b"1000\n", "readlink": b"net:[123]\n",
                "stat": b"0 755\n", "test": b"",
            }
            return Mock(stdout=replies[tool])

        bridge = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        with patch.object(connect.os, "getuid", return_value=1000), \
                patch.object(connect.os, "geteuid", return_value=1000), \
                patch.object(connect.os, "lstat", return_value=bridge), \
                patch.object(connect.os, "readlink", return_value="net:[123]"), \
                patch.object(connect, "check_private_directory"), patch.object(connect, "host", side_effect=host) as verify:
            connect._preflight(Path("/fixture"))
        for path in ("/usr/bin/sh", "/usr/bin/env"):
            self.assertIn(("stat", "-Lc", "%u %a", "--", path), [call.args for call in verify.call_args_list])
            self.assertIn(("test", "-x", path), [call.args for call in verify.call_args_list])

        verify.assert_any_call("stat", "-c", "%u %f", "--", "/usr/bin/xdg-open", timeout=2, check=False)
        self.assertEqual([call.args for call in verify.call_args_list if "/usr/bin/xdg-open" in call.args], [
            ("stat", "-c", "%u %f", "--", "/usr/bin/xdg-open"),
        ])

    def test_unsafe_xdg_open_refuses_public_connect_before_consent_or_resources(self):
        spec = SimpleNamespace(enabled=True, auth_mode="subscription", cli_path=None)
        config = Mock(get=Mock(return_value=spec))
        bridge = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        target = ("-c", "%u %f", "--", "/usr/bin/xdg-open")
        for case, status, stdout in (
            ("missing", 1, b""),
            ("link", 0, b"0 a1ff\n"),
            ("directory", 0, b"0 41ed\n"),
            ("fifo", 0, b"0 11a4\n"),
            ("untrusted owner", 0, b"1000 81ed\n"),
            ("group writable", 0, b"0 81fd\n"),
            ("other writable", 0, b"0 81ef\n"),
            ("bad format", 0, b"0 81_8\n"),
            ("extra data", 0, b"0 81ed\nhost-output-marker\n"),
        ):
            with self.subTest(case=case):
                owner, output = Mock(), StringIO()

                def host(tool, *args, **kwargs):
                    if args == target:
                        return Mock(returncode=status, stdout=stdout, stderr=b"host-error-marker")
                    return Mock(stdout={"id": b"1000\n", "readlink": b"net:[123]\n",
                                        "stat": b"0 755\n", "test": b""}[tool])

                with patch.object(connect, "load_provider_config", return_value=config), \
                        patch.object(connect, "_attended_owner", return_value=nullcontext(owner)), \
                        patch.object(connect.os, "getuid", return_value=1000), \
                        patch.object(connect.os, "geteuid", return_value=1000), \
                        patch.object(connect.os, "lstat", return_value=bridge), \
                        patch.object(connect.os, "readlink", return_value="net:[123]"), \
                        patch.object(connect, "check_private_directory"), \
                        patch.object(connect, "host", side_effect=host) as verify, \
                        patch.object(connect, "_artifacts", side_effect=AssertionError("artifact access")) as artifacts, \
                        patch.object(connect, "_private_runtime") as runtime, \
                        patch.object(connect, "RegistrationJournal") as journal, \
                        patch.object(connect, "enroll_metadata") as enroll, redirect_stderr(output):
                    self.assertEqual(run_connect("fixture"), 1)
                self.assertEqual(output.getvalue(), "oc-sandbox google: "
                                 "Google sign-in requires a protected /usr/bin/xdg-open on the workstation.\n")
                verify.assert_any_call("stat", *target, timeout=2, check=False)
                owner.consent.assert_not_called()
                artifacts.assert_not_called()
                runtime.assert_not_called()
                journal.assert_not_called()
                enroll.assert_not_called()

    def test_runtime_refuses_wrong_certificate_sans_or_nonprivate_tls_key(self):
        for failure in ("san", "key"):
            with self.subTest(failure=failure), TemporaryDirectory() as path:
                root = Path(path)
                key = root / "metadata-key.pem"
                key.touch(mode=0o600)
                key.chmod(0o640)
                root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                custody = SimpleNamespace(root=root, root_fd=root_fd, cold=False)
                output = (b"X509v3 Subject Alternative Name:\n DNS:oauth2.googleapis.com, DNS:cloudcode-pa.googleapis.com\n"
                          if failure == "key" else b"X509v3 Subject Alternative Name:\n DNS:other.invalid\n")
                message = "private TLS key" if failure == "key" else "certificate scope"
                try:
                    mkdir = os.mkdir
                    with patch.object(connect, "stage_standalone"), patch.object(connect, "check_private_directory"), \
                            patch.object(connect, "public_certificate"), patch.object(connect, "host", return_value=Mock(stdout=output)), \
                            patch.object(connect.os, "mkdir", wraps=mkdir) as make_directory:
                        with self.assertRaisesRegex(connect.ConnectError, message):
                            connect._prepare_runtime(custody, 1)
                    make_directory.assert_called_once_with("native", 0o700, dir_fd=root_fd)
                finally:
                    os.close(root_fd)

    def test_success_follows_initial_and_cold_cleanups_and_uses_compiled_exchange(self):
        events = []
        spec = SimpleNamespace(enabled=True, auth_mode="subscription", cli_path=None)
        owner = SimpleNamespace(fence=RLock(), deadline=float("inf"), authorized=lambda: True, offer=Mock(), consent=lambda _: True,
                                write_once=lambda _: events.append("reported"))

        @contextmanager
        def place(parent, label, cold, owner):
            yield cold
            events.append(("clean", cold))

        enrollment = object()

        def inspect_reopen(*args, runtime_scope, **kwargs):
            with runtime_scope:
                events.append("cold")

        with patch.object(connect, "load_provider_config", return_value=Mock(get=Mock(return_value=spec))), \
                patch.object(connect, "_attended_owner", return_value=nullcontext(owner)), \
                patch.object(connect, "_preflight"), patch.object(connect, "_private_runtime", place), \
                patch.object(connect, "_artifacts", return_value=nullcontext(1)), \
                patch.object(connect, "verify_standalone_source", create=True), \
                patch.object(connect, "_prepare_runtime", side_effect=lambda custody, _: custody), \
                patch.object(connect, "enroll_metadata", return_value=enrollment) as enroll, \
                patch.object(connect, "reopen_metadata", side_effect=inspect_reopen) as reopen:
            self.assertEqual(connect.connect_for("fixture"), 0)
        self.assertEqual(events, [("clean", False), "cold", ("clean", True), "reported"])
        self.assertIs(enroll.call_args.kwargs["destination"], connect.exchange)
        self.assertIs(reopen.call_args.kwargs["destination"], connect.exchange)
        self.assertIs(reopen.call_args.args[1], enrollment)

    def test_invalid_label_stops_before_config(self):
        with patch.object(connect, "load_provider_config") as config:
            with self.assertRaisesRegex(connect.ConnectError, "Invalid Google registration label"):
                connect.connect_for("../../sandbox")
        config.assert_not_called()


class RuntimeCustodyTest(unittest.TestCase):
    def setUp(self):
        self.parent = Path(self.enterContext(TemporaryDirectory()))
        self.owner = Mock(authorized=Mock(return_value=True))
        self.unit = "oc-google-acp-" + "1" * 24 + ".service"
        self.identity = NativeInvocation(self.unit, "2" * 32, b"/fixture", 123)

    def test_unknown_launch_retains_root_and_exact_durable_launch_record(self):
        record = Mock()
        with ExitStack() as runtime:
            custody = runtime.enter_context(connect._private_runtime(self.parent, "fixture", False, self.owner))
            root = custody.root
            custody.bind(record)
            custody.before_spawn(self.unit)
            with self.assertRaisesRegex(connect.CustodyUnconfirmed, "requires inspection"):
                runtime.close()
        self.assertTrue(root.is_dir())
        event, data = record.call_args.args
        self.assertEqual((event, data["label"], data["root"], data["unit"], data["inode"]),
                         ("launch", "fixture", str(root), self.unit, root.stat().st_ino))

    def test_verified_retirement_permits_exact_runtime_and_private_key_cleanup(self):
        record = Mock()
        with connect._private_runtime(self.parent, "fixture", False, self.owner) as custody:
            root = custody.root
            (root / "local.key").touch(mode=0o600)
            custody.bind(record)
            custody.before_spawn(self.unit)
            custody.attest(self.identity)
            custody.retire(self.identity)
        self.assertEqual([item.args[0] for item in record.call_args_list], ["launch", "attested", "retired"])
        self.assertFalse(root.exists())
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_runtime_cleanup_failure_preserves_active_error_and_cause(self):
        cause = ValueError("fixture original cause")
        primary = connect.ConnectError("Google sign-in cancelled.")
        storage = OSError("fixture cleanup failed")

        with patch.object(connect._RuntimeCustody, "cleanup", side_effect=storage):
            with self.assertRaises(connect.ConnectError) as caught:
                with connect._private_runtime(self.parent, "fixture", False, self.owner) as custody:
                    root = custody.root
                    raise primary from cause
        self.assertIs(caught.exception, primary)
        self.assertIs(primary.__cause__, cause)
        uncertainty, = primary.cleanup_uncertainties
        self.assertIsInstance(uncertainty, connect.CustodyUnconfirmed)
        self.assertIs(uncertainty.__cause__, storage)
        self.assertTrue(root.is_dir())

    def test_public_error_projection_keeps_safe_primary_and_inspection_notice(self):

        def cancelled(_label):
            with connect._private_runtime(self.parent, "fixture", False, self.owner) as custody:
                custody.bind(Mock())
                custody.before_spawn(self.unit)
                raise connect.ConnectError("Google sign-in cancelled.")

        output = StringIO()
        with patch.object(connect, "connect_for", side_effect=cancelled), redirect_stderr(output):
            self.assertEqual(run_connect("fixture"), 1)
        self.assertEqual(output.getvalue().splitlines(), [
            "oc-sandbox google: Google sign-in cancelled.",
            "oc-sandbox google: Google enrollment cleanup requires inspection.",
        ])
        self.assertEqual(len(list(self.parent.iterdir())), 1)

    def test_keyboard_interrupt_preserves_redacted_cancellation_and_exit_code(self):
        output = StringIO()
        with patch.object(connect, "connect_for", side_effect=KeyboardInterrupt("private fixture detail")), \
                redirect_stderr(output):
            self.assertEqual(run_connect("fixture"), 130)
        self.assertEqual(output.getvalue(), "oc-sandbox google: Google sign-in cancelled.\n")

    def test_callback_diagnostic_uses_only_original_foreground_pty(self):
        self.assert_diagnostic_uses_original_pty(
            "callback", b"Google sign-in callback: The callback Referer header was refused.",
            b"synthetic-referer-marker",
        )

    def test_token_diagnostic_uses_only_original_foreground_pty(self):
        self.assert_diagnostic_uses_original_pty(
            "token", b"Google sign-in token reply: The token endpoint returned HTTP 400.",
            b"synthetic-token-marker",
        )

    def test_token_scope_diagnostic_uses_only_original_foreground_pty(self):
        self.assert_diagnostic_uses_original_pty(
            "scope", b"Google sign-in token reply: The token grant included an unapproved permission.",
            b"synthetic-unapproved-permission",
        )

    def test_token_diagnostic_text_covers_every_stage(self):
        self.assertEqual(set(connect._TOKEN_DETAILS), set(TokenStage))
        self.assertEqual(set(connect._POST_TOKEN_DETAILS), set(PostTokenStage))
        self.assertEqual(set(connect._LOAD_BODY_DETAILS), set(LoadBodyReason))
        for mapping, detail in (
            (connect._CURRENT_TIER_DETAILS, CurrentTierDetail),
            (connect._ORIGINAL_PROJECT_DETAILS, OriginalProjectDetail),
        ):
            self.assertEqual(set(mapping), set(detail))
            self.assertEqual(len(set(mapping.values())), len(detail))

    def test_post_token_load_body_uses_only_original_foreground_pty(self):
        self.assert_diagnostic_uses_original_pty(
            "load", b"Google enrollment metadata: The LOAD metadata body was refused. Failed checks include "
            b"top-level field allowlist, current tier structure, original project. "
            b"Current tier check found an explicit null. Original project check found a missing key.",
            b"synthetic-load-marker",
        )

    def test_load_body_details_only_use_the_bounded_exact_failure_snapshot(self):
        token = TokenDiagnostic()
        error = ValueError("synthetic raw exception")
        error.load_body_reasons = tuple(reversed(tuple(LoadBodyReason)))
        tier = max(CurrentTierDetail, key=lambda detail: len(connect._CURRENT_TIER_DETAILS[detail]))
        project = max(OriginalProjectDetail, key=lambda detail: len(connect._ORIGINAL_PROJECT_DETAILS[detail]))
        error.load_account_details = tier, project
        post = PostTokenDiagnostic()
        post.mark(error, PostTokenStage.LOAD_BODY)
        error.load_body_reasons = ("synthetic altered reason",)
        error.load_account_details = ("synthetic altered tier", "synthetic altered project")
        owner = Mock()
        connect._write_enrollment_detail(owner, error, token, post)
        line = owner.write_once.call_args.args[0]
        expected = ", ".join(connect._LOAD_BODY_DETAILS[reason] for reason in LoadBodyReason)
        self.assertEqual(line, "Google enrollment metadata: The LOAD metadata body was refused. "
                              f"Failed checks include {expected}. "
                              f"Current tier check found {connect._CURRENT_TIER_DETAILS[tier]}. "
                              f"Original project check found {connect._ORIGINAL_PROJECT_DETAILS[project]}.\n")
        self.assertLess(len(line.encode("ascii")), 512)
        for other, scope in ((ValueError(str(error)), post), (error, PostTokenDiagnostic())):
            owner.reset_mock()
            connect._write_enrollment_detail(owner, other, token, scope)
            owner.write_once.assert_not_called()
        owner.reset_mock()
        error.__context__ = ValueError("synthetic replaced context")
        connect._write_enrollment_detail(owner, error, token, post)
        owner.write_once.assert_not_called()

    def test_invalid_load_reason_metadata_keeps_the_plain_body_message(self):
        token, post, owner = TokenDiagnostic(), PostTokenDiagnostic(), Mock()
        error = ValueError("synthetic raw exception")
        error.load_body_reasons = (LoadBodyReason.SIZE, "synthetic open category")
        post.mark(error, PostTokenStage.LOAD_BODY)
        connect._write_enrollment_detail(owner, error, token, post)
        owner.write_once.assert_called_once_with("Google enrollment metadata: The LOAD metadata body was refused.\n")

    def test_unvalidated_load_account_details_keep_existing_top_level_reasons(self):
        pair = (CurrentTierDetail.NULL, OriginalProjectDetail.ABSENT)
        both = (LoadBodyReason.CURRENT_TIER, LoadBodyReason.ORIGINAL_PROJECT)
        for reasons, details in (
            (both, None), (both, list(pair)), (both, pair[::-1]), (both, pair[:1]),
            (both, pair + (CurrentTierDetail.NULL,)), (both, (CurrentTierDetail.NULL, "synthetic raw detail")),
            ((LoadBodyReason.CURRENT_TIER,), pair), ((LoadBodyReason.ORIGINAL_PROJECT,), pair),
        ):
            error = ValueError("synthetic raw exception")
            error.load_body_reasons = reasons
            error.load_account_details = details
            post, owner = PostTokenDiagnostic(), Mock()
            post.mark(error, PostTokenStage.LOAD_BODY)
            connect._write_enrollment_detail(owner, error, TokenDiagnostic(), post)
            existing = ", ".join(connect._LOAD_BODY_DETAILS[reason] for reason in reasons)
            owner.write_once.assert_called_once_with("Google enrollment metadata: The LOAD metadata body was refused. "
                                                    f"Failed checks include {existing}.\n")

    def test_post_token_detail_cannot_preempt_token_callback_or_inherit_custody(self):
        callback = metadata_workflow.CallbackWorkflowError(auth_offer.CallbackDiagnostic.NO_MATCHING_CALLBACK)
        token = RuntimeError("fixture token")
        token.token_stage = TokenStage.HTTP_400
        token_diagnostic = TokenDiagnostic()
        token_diagnostic.mark(token)
        for error, expected in (
            (callback, "Google sign-in callback: No matching callback was accepted.\n"),
            (token, "Google sign-in token reply: The token endpoint returned HTTP 400.\n"),
        ):
            with self.subTest(error=type(error).__name__):
                post = PostTokenDiagnostic()
                post.mark(error, PostTokenStage.LOAD_BODY)
                owner = Mock()
                connect._write_enrollment_detail(owner, error, token_diagnostic, post)
                owner.write_once.assert_called_once_with(expected)
        original = RuntimeError("original fixture failure")
        original.__context__ = NativeRetirementUnconfirmed("fixture custody uncertainty")
        post = PostTokenDiagnostic()
        post.mark(original, PostTokenStage.LOAD_BODY)
        owner = Mock()
        for error, attempt in (
            (original, post), (RuntimeError(str(original)), post), (original, PostTokenDiagnostic()),
        ):
            connect._write_enrollment_detail(owner, error, token_diagnostic, attempt)
        owner.write_once.assert_not_called()
        replaced_context = RuntimeError("fixture failure before cleanup")
        post = PostTokenDiagnostic()
        post.mark(replaced_context, PostTokenStage.LOAD_BODY)
        replaced_context.__context__ = RuntimeError("fixture cleanup replaced the context")
        connect._write_enrollment_detail(owner, replaced_context, token_diagnostic, post)
        owner.write_once.assert_not_called()

    def assert_diagnostic_uses_original_pty(self, kind, expected_stage, marker):
        generic = b"oc-sandbox google: Workstation enrollment did not complete.\n"

        terminal_states = (("foreground", "background") if kind == "callback"
                           else ("foreground", "background", "interrupted", "custody"))
        if kind == "load":
            terminal_states += ("expired",)
        for terminal_state in terminal_states:
            with self.subTest(terminal_state=terminal_state):
                stderr = self.parent / f"stderr-{terminal_state}"
                runtime = self.parent / f"runtime-{terminal_state}"
                runtime.mkdir(mode=0o700)
                process, terminal = pty.fork()
                if process == 0:
                    with stderr.open("wb") as stream:
                        os.dup2(stream.fileno(), 2)
                    sys.stderr = os.fdopen(2, "w", buffering=1)
                    try:
                        self.run_pty_diagnostic_fixture(run_connect, runtime, terminal_state, kind)
                    except BaseException:
                        os._exit(2)
                    os._exit(0)

                output = bytearray()
                deadline = time.monotonic() + 5
                finished = False
                try:
                    while time.monotonic() < deadline:
                        if not select.select([terminal], [], [], .05)[0]:
                            continue
                        try:
                            chunk = os.read(terminal, 4096)
                        except OSError as error:
                            if error.errno != errno.EIO:
                                raise
                            chunk = b""
                        if not chunk:
                            finished = True
                            break
                        output.extend(chunk)
                        self.assertLess(len(output), 8192)
                finally:
                    if not finished:
                        with suppress(ProcessLookupError):
                            os.kill(process, signal.SIGKILL)
                    os.close(terminal)
                    _, status = os.waitpid(process, 0)
                self.assertTrue(finished)
                self.assertEqual(os.waitstatus_to_exitcode(status), 0)
                self.assertEqual(list(runtime.iterdir()), [])
                expected_stderr = generic
                if terminal_state == "custody":
                    expected_stderr += b"oc-sandbox google: Google enrollment cleanup requires inspection.\n"
                self.assertEqual(stderr.read_bytes(), expected_stderr)
                self.assertEqual(bytes(output).strip(), expected_stage if terminal_state == "foreground" else b"")
                self.assertNotIn(marker, output)
                self.assertNotIn(marker, stderr.read_bytes())
                runtime.rmdir()

    @staticmethod
    def run_pty_diagnostic_fixture(run_connect, runtime, terminal_state, kind):
        spec = SimpleNamespace(enabled=True, auth_mode="subscription", cli_path=None)
        original_runtime = connect._private_runtime
        original_cleanup = connect._RuntimeCustody.cleanup
        blocker = None
        read_fd, write_fd = os.pipe()

        @contextmanager
        def place(parent, label, cold, owner):
            nonlocal blocker
            try:
                with original_runtime(parent, label, cold, owner) as custody:
                    yield custody
            finally:
                if terminal_state == "interrupted" and not cold:
                    os.kill(os.getpid(), signal.SIGINT)
                if terminal_state == "expired" and not cold:
                    owner.deadline = time.monotonic() - 1
                if terminal_state == "background" and not cold:
                    assert not list(runtime.iterdir())
                    blocker = os.fork()
                    if blocker == 0:
                        os.close(write_fd)
                        os.read(read_fd, 1)
                        os._exit(0)
                    os.setpgid(blocker, blocker)
                    os.tcsetpgrp(0, blocker)

        def cleanup(custody):
            original_cleanup(custody)
            if terminal_state == "custody" and not custody.cold:
                raise OSError("synthetic cleanup uncertainty")

        def refuse_callback(*args, authorized, fence, **kwargs):
            from test_google_auth_offer import exchange, offer, placement, request

            with placement(authorized=authorized, opened=False) as (gate, _recorder, port), \
                    ThreadPoolExecutor(max_workers=1) as browser:
                disclosed = gate.accept_offer(offer(port))
                payload = request(port, extra_headers=b"Referer: https://fixture.invalid/synthetic-referer-marker\x00\r\n")
                reply = browser.submit(exchange, port, payload)
                owner = SimpleNamespace(fence=fence, authorizes_offer=lambda _: True, active=authorized)
                try:
                    metadata_workflow._receive_callback(
                        disclosed, gate, notify=lambda _: None, deadline=time.monotonic() + 2, owner=owner,
                        profile=None,
                    )
                finally:
                    assert reply.result(timeout=3) == auth_offer.acknowledgement(False)

        def refuse_token(*args, authorized, fence, destination, diagnostic=None, post_diagnostic=None, **kwargs):
            from oc_google import enrollment, metadata_destination
            from test_google_enrollment import BEARER, LOAD_REQUEST, SUBJECT
            from test_google_metadata_destination import FakeChannel, IPV4, response
            from test_google_oauth_exchange import AUTHORIZATION, CODE, SCOPE, STATE, form, grant, offer

            if kind == "scope":
                channels = (FakeChannel(response(grant(scope=SCOPE + " synthetic-unapproved-permission"))),)
            elif kind == "load":
                channels = (
                    FakeChannel(response(grant())), FakeChannel(response(SUBJECT)),
                    FakeChannel(response(b'{"synthetic-load-marker":1,"currentTier":null}')),
                )
            else:
                channels = (FakeChannel(response(status=b"HTTP/1.1 400 synthetic-token-marker")),)
            trust = Mock(wrap_socket=Mock(side_effect=channels))
            gate = Mock(take_forwarded=Mock(return_value=auth_offer.Callback(STATE, CODE)))
            route_type = metadata_destination.MetadataRoute
            routes = (route_type.TOKEN, route_type.USERINFO, route_type.LOAD_CODE_ASSIST)
            sent = []

            def spend(route, send):
                with fence:
                    assert authorized()
                    assert route is routes[len(sent)]
                    send()
                    sent.append(route)

            # Passing the optional observer only when the launcher supplied it
            # also lets this PTY regression run against the unchanged baseline.
            options = {} if diagnostic is None else {"diagnostic": diagnostic}
            with patch.object(metadata_destination.socket, "socket", return_value=FakeChannel()), \
                    patch.object(metadata_destination, "_resolve", return_value=(2, IPV4)), \
                    patch.object(metadata_destination, "_system_tls_context", return_value=trust):
                try:
                    verified = enrollment.verify_initial_exchange(
                        offer=offer(), callback_gate=gate, authorization=AUTHORIZATION, form=form(),
                        bind_subject=Mock(), deadline=time.monotonic() + 2, spend=spend,
                        destination=destination, **options,
                    )
                    if kind == "load":
                        live = scoped_post_token(post_diagnostic, fence, authorized)
                        verified.load_code_assist(authorization=BEARER, body=LOAD_REQUEST, post_diagnostic=live)
                finally:
                    assert len(sent) == len(channels)
                    assert all(len(channel.sent) == 1 for channel in channels)

        refuse = refuse_callback if kind == "callback" else refuse_token
        try:
            with patch.object(connect, "load_provider_config", return_value=Mock(get=Mock(return_value=spec))), \
                    patch.object(connect, "scratch_parent", return_value=runtime), \
                    patch.object(connect, "_preflight"), patch.object(connect, "_private_runtime", place), \
                    patch.object(connect, "_artifacts", return_value=nullcontext(1)), \
                    patch.object(connect, "verify_standalone_source"), \
                    patch.object(connect, "_prepare_runtime"), patch.object(connect, "RegistrationJournal"), \
                    patch.object(connect._TerminalOwner, "consent", return_value=True), \
                    patch.object(connect._RuntimeCustody, "cleanup", autospec=True, side_effect=cleanup), \
                    patch.object(connect, "enroll_metadata", side_effect=refuse):
                assert run_connect("fixture") == 1
        finally:
            os.close(write_fd)
            os.close(read_fd)
            if blocker is not None:
                os.waitpid(blocker, 0)

    def test_diagnostic_write_refusal_or_cleanup_uncertainty_preserves_primary_error(self):
        spec = SimpleNamespace(enabled=True, auth_mode="subscription", cli_path=None)
        for uncertain in (False, True):
            with self.subTest(uncertain=uncertain), TemporaryDirectory(dir=self.parent) as directory:
                runtime = Path(directory)
                owner = Mock(fence=RLock(), authorized=Mock(return_value=True), consent=Mock(return_value=True))
                primary = metadata_workflow.CallbackWorkflowError(auth_offer.CallbackDiagnostic.HEADER_REFERER)
                original_cleanup = connect._RuntimeCustody.cleanup

                def cleanup(custody):
                    original_cleanup(custody)
                    if uncertain and not custody.cold:
                        raise OSError("synthetic cleanup failure")

                def refuse_write(_message):
                    self.assertEqual(list(runtime.iterdir()), [])
                    raise connect.ConnectError("synthetic diagnostic output refusal")

                owner.write_once.side_effect = refuse_write
                with patch.object(connect, "load_provider_config", return_value=Mock(get=Mock(return_value=spec))), \
                        patch.object(connect, "scratch_parent", return_value=runtime), \
                        patch.object(connect, "_preflight"), patch.object(connect, "_attended_owner",
                                                                          return_value=nullcontext(owner)), \
                        patch.object(connect, "_artifacts", return_value=nullcontext(1)), \
                        patch.object(connect, "verify_standalone_source"), \
                        patch.object(connect, "_prepare_runtime"), patch.object(connect, "RegistrationJournal"), \
                        patch.object(connect, "enroll_metadata", side_effect=primary), \
                        patch.object(connect._RuntimeCustody, "cleanup", autospec=True, side_effect=cleanup):
                    with self.assertRaises(metadata_workflow.CallbackWorkflowError) as result:
                        connect.connect_for("fixture")
                self.assertIs(result.exception, primary)
                self.assertEqual(connect.needs_custody_inspection(primary), uncertain)
                self.assertEqual(owner.write_once.call_count, 0 if uncertain else 1)

    def test_cold_runtime_does_not_replace_replica_cleanup(self):
        with ExitStack() as runtime:
            custody = runtime.enter_context(connect._private_runtime(self.parent, "fixture", True, self.owner))
            replica = custody.root / "profile"
            replica.mkdir()
            with self.assertRaisesRegex(connect.CustodyUnconfirmed, "requires inspection"):
                runtime.close()
        self.assertTrue(replica.is_dir())

    def test_cold_disappearance_with_quarantine_requires_inspection(self):
        with ExitStack() as runtime:
            custody = runtime.enter_context(connect._private_runtime(self.parent, "fixture", True, self.owner))
            quarantine = self.parent / custody.quarantine
            os.rename(custody.root, quarantine)
            with self.assertRaisesRegex(connect.CustodyUnconfirmed, "requires inspection"):
                runtime.close()
        self.assertTrue(quarantine.is_dir())
