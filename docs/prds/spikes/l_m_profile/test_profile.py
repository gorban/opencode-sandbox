from copy import deepcopy
from pathlib import Path
from subprocess import CompletedProcess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, call, patch

import probe_profile
from oc_plan import CompiledPlanResult, compile_plan
from oc_schema import sha256_canonical_json
from profile_checks import MAX_LISTENER_TABLE, _chrome_response, _verify_listeners, verify_services
from profile_plan import (
    CDP_SERVICE, PG_SERVICE, PROFILE, WORKER_REF, FixtureCatalog, ProfileError, compile_fixture, lower, verify_image,
)
from profile_services import (
    LABEL, PODMAN_DEFAULT_CAPS, ROLE, Sidecars, _arguments, _check_ports, _check_sandbox_settings, _namespace_ids, recipe,
)
from runtime import JobRuntimeError


WORKER_ID = "a" * 64
PG_ID = "b" * 64
RELAY_ID = "d" * 64


class PlanTests(TestCase):
    def test_catalog_lists_the_same_services_when_archives_are_requested(self):
        catalog = FixtureCatalog()
        self.assertEqual(catalog.list_ids("service", include_archived=True), [CDP_SERVICE, PG_SERVICE])

    def test_compiler_omits_only_the_requested_service(self):
        full = compile_fixture(without_chromium=False)
        partial = compile_fixture(without_chromium=True)
        self.assertEqual(set(full.services), {PG_SERVICE, CDP_SERVICE})
        self.assertEqual(partial.services, (PG_SERVICE,))
        self.assertNotEqual(full.digest, partial.digest)

    def test_reject_malformed_selection_even_with_a_fresh_digest(self):
        reference = compile_plan(FixtureCatalog(), PROFILE)
        for name, mutate in (
            ("wrong factory", lambda plan: plan["services"][0].update(factory_id="example")),
            ("wrong image", lambda plan: plan["services"][0].update(image=WORKER_REF)),
            ("wrong service env", lambda plan: plan["services"][0].update(env={"FOO": "bar"})),
            ("duplicate service", lambda plan: plan["services"].append(plan["services"][0])),
            ("port exposure", lambda plan: plan["endpoints"][0].update(host_port=9222)),
            ("wrong platform", lambda plan: plan["worker"].update(arch="arm64")),
            ("unexpected resources", lambda plan: plan["services"][0]["resources"].update(memory="9g")),
            ("changed authentication", lambda plan: plan["endpoints"][0].update(requires_auth=True)),
            ("unexpected bundle", lambda plan: plan["bundles"].append("poc/extra")),
            ("unexpected version", lambda plan: plan.update(schema_version=2)),
            ("unexpected MCP", lambda plan: plan["role_contract"]["opencode_config"]["mcp"].update(example={})),
        ):
            with self.subTest(name=name):
                plan = deepcopy(reference.plan)
                mutate(plan)
                with self.assertRaises(ProfileError):
                    lower(CompiledPlanResult(plan, sha256_canonical_json(plan), reference.drift, reference.closure_digest))

    def test_reject_wrong_plan_digest(self):
        reference = compile_plan(FixtureCatalog(), PROFILE)
        with self.assertRaisesRegex(ProfileError, "digest"):
            lower(CompiledPlanResult(reference.plan, "0" * 64, reference.drift, reference.closure_digest))

    def test_image_requires_exact_local_identity_and_repository_pin(self):
        metadata = {"Id": WORKER_ID, "Os": "linux", "Architecture": "amd64", "RepoDigests": [WORKER_REF]}
        inspect = Mock(return_value=metadata)
        for image in (WORKER_ID, f"sha256:{WORKER_ID}"):
            with self.subTest(image=image):
                inspect.reset_mock()
                verify_image(probe_profile._local_image_id(image), WORKER_REF, inspect)
                inspect.assert_called_once_with("image", "inspect", WORKER_ID)
        for update in ({"Id": PG_ID}, {"RepoDigests": []}, {"Architecture": "arm64"}):
            with self.subTest(update=update), self.assertRaises(ProfileError):
                verify_image(WORKER_ID, WORKER_REF, Mock(return_value={**metadata, **update}))
        inspect.reset_mock()
        with self.assertRaises(ProfileError):
            verify_image("--help", WORKER_REF, inspect)
        inspect.assert_not_called()

    def test_plan_only_does_not_call_podman(self):
        with patch.object(probe_profile, "inspected") as inspect:
            result = probe_profile.run(SimpleNamespace(plan_only=True, without_chromium=True))
        self.assertEqual(result, 0)
        inspect.assert_not_called()


class SidecarTests(TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        job = Mock(root=self.root, ids={"worker": WORKER_ID, "relay": RELAY_ID})
        job._identity.return_value = {
            "ProcessLabel": "system_u:system_r:container_t:s0:c1,c2",
            "MountLabel": "system_u:object_r:container_file_t:s0:c1,c2",
        }
        with patch("profile_services._namespace_ids", return_value={"net": b"net:[1]"}):
            self.sidecars = Sidecars(job)
        self.spec = recipe(CDP_SERVICE, PG_ID, self.root)

    def inspected(self, *_args):
        role = self.spec.name
        return {
            "Id": PG_ID, "Name": self.sidecars.names[role], "Image": PG_ID,
            "Config": {"Labels": {LABEL: self.sidecars.run, ROLE: role}, "User": "65534:65534"},
            "HostConfig": {"PortBindings": {"9222/tcp": [{"HostPort": "9222"}]}},
            "NetworkSettings": {}, "Mounts": [], "State": {"Running": False},
        }

    @patch("profile_services.podman")
    def test_published_port_mismatch_leaves_entrypoint_unstarted(self, podman):
        podman.return_value = CompletedProcess([], 0, stdout=PG_ID.encode(), stderr=b"")
        with patch("profile_services.inspected", side_effect=self.inspected), self.assertRaisesRegex(ProfileError, "published"):
            self.sidecars.start(self.spec)
        self.assertEqual(podman.call_count, 1)
        self.assertEqual(podman.call_args.args[0], "create")
        self.assertEqual(self.sidecars.recorded, {self.spec.name: PG_ID})

    @patch("profile_services.podman")
    def test_partial_startup_cleanup_uses_exact_verified_id(self, podman):
        podman.return_value = CompletedProcess([], 0, stdout=PG_ID.encode(), stderr=b"")
        with patch("profile_services.inspected", side_effect=self.inspected):
            with self.assertRaises(ProfileError):
                self.sidecars.start(self.spec)
            podman.side_effect = (
                CompletedProcess([], 0, stdout=b"", stderr=b""),
                CompletedProcess([], 0, stdout=b"", stderr=b""),
                CompletedProcess([], 1, stdout=b"", stderr=b""),
            )
            self.sidecars.close()
        self.assertEqual(podman.call_args_list[1].args, ("rm", "--force", "--time", "0", PG_ID))
        self.assertEqual(podman.call_args_list[-1].args, ("container", "exists", PG_ID))

    @patch("profile_services.podman")
    def test_uncertain_create_recovers_exact_id_but_retains_pending_receipt(self, podman):
        podman.side_effect = [
            JobRuntimeError("fixture create timed out"),
            CompletedProcess([], 0, stdout=PG_ID.encode() + b"\n"),
            CompletedProcess([], 0),
            CompletedProcess([], 0, stdout=b""),
            CompletedProcess([], 1),
        ]
        with self.assertRaises(JobRuntimeError):
            self.sidecars.start(self.spec)
        with patch("profile_services.inspected", side_effect=self.inspected), self.assertRaisesRegex(ProfileError, "unconfirmed"):
            self.sidecars.close()
        self.assertEqual(self.sidecars.recorded, {self.spec.name: PG_ID})
        self.assertEqual(podman.call_args_list[2].args, ("rm", "--force", "--time", "0", PG_ID))
        self.assertIn('"pending": ["chromium"]', self.sidecars.path.read_text())

    @patch("profile_services.podman")
    def test_failed_id_receipt_can_be_persisted_and_reclaimed(self, podman):
        remember = self.sidecars._remember

        def fail_second_write():
            if self.sidecars.ids:
                raise OSError("fixture write failed")
            remember()

        with patch.object(self.sidecars, "_remember", side_effect=fail_second_write):
            podman.return_value = CompletedProcess([], 0, stdout=PG_ID.encode())
            with self.assertRaises(OSError):
                self.sidecars.start(self.spec)
        podman.side_effect = (
            CompletedProcess([], 0, stdout=PG_ID.encode() + b"\n"),
            CompletedProcess([], 0),
            CompletedProcess([], 0, stdout=b""),
            CompletedProcess([], 1),
        )
        with patch("profile_services.inspected", side_effect=self.inspected):
            self.sidecars.close()
        self.assertEqual(self.sidecars.recorded, {self.spec.name: PG_ID})
        self.assertEqual(podman.call_args_list[2].args, ("rm", "--force", "--time", "0", PG_ID))

    def test_missing_explicit_capability_drop_is_rejected(self):
        settings = {"ReadonlyRootfs": True, "SecurityOpt": ["no-new-privileges"]}
        with self.assertRaisesRegex(ProfileError, "sandbox settings"):
            _check_sandbox_settings({"HostConfig": settings})
        _check_sandbox_settings({"HostConfig": {**settings, "CapDrop": ["ALL"]}})
        _check_sandbox_settings({"HostConfig": {**settings, "CapDrop": sorted(PODMAN_DEFAULT_CAPS)}})

    def test_network_attachment_address_is_rejected(self):
        details = {"HostConfig": {}, "NetworkSettings": {"Networks": {"none": {"Gateway": "192.0.2.1"}}}}
        with self.assertRaisesRegex(ProfileError, "unexpected network settings"):
            _check_ports(details)

    @patch("profile_services.podman", return_value=CompletedProcess([], 0, stdout=b""))
    def test_empty_namespace_acceptance_is_rejected(self, _podman):
        with self.assertRaisesRegex(ProfileError, "incomplete namespace"):
            _namespace_ids(WORKER_ID)

    def test_cleanup_closes_broker_then_removes_sidecars_then_worker(self):
        order = Mock()
        job, broker, sidecars = Mock(), Mock(), Mock()
        order.attach_mock(job, "job")
        order.attach_mock(broker, "broker")
        order.attach_mock(sidecars, "sidecars")
        with patch("probe_profile.signal.signal"):
            self.assertIsNone(probe_profile._cleanup(job, broker, sidecars, None))
        self.assertEqual(order.mock_calls, [call.broker.close(), call.sidecars.close(), call.job.close()])

    def test_writeable_profile_state_uses_tmpfs_only(self):
        arguments = _arguments(self.spec, WORKER_ID, "fixture", "run")
        self.assertNotIn("--publish", arguments)
        self.assertNotIn("--volume", arguments)
        self.assertIn("--read-only", arguments)
        self.assertIn("--pull=never", arguments)


class WireTests(TestCase):
    def test_cdp_checks_response_identity_and_http_status(self):
        response = b'HTTP/1.1 200 OK\r\n\r\n{"Browser":"Chrome/157","Protocol-Version":"1.3"}'
        self.assertTrue(_chrome_response(response))
        self.assertFalse(_chrome_response(response.replace(b"200", b"404")))
        self.assertFalse(_chrome_response(response.replace(b"Chrome", b"fixture")))

    @patch("profile_checks.podman")
    def test_listener_inventory_rejects_an_unexpected_bind(self, podman):
        pg = b"0: 0100007F:1538 00000000:0000 0A\n"
        browser = b"1: 0100007F:2406 00000000:0000 0A\n"
        podman.return_value = CompletedProcess([], 0, stdout=pg + browser, stderr=b"")
        _verify_listeners(WORKER_ID, True)
        with self.assertRaises(ProfileError):
            _verify_listeners(WORKER_ID, False)
        podman.return_value.stdout = pg + browser.replace(b"0100007F", b"00000000")
        with self.assertRaises(ProfileError):
            _verify_listeners(WORKER_ID, True)
        podman.return_value.stdout = pg + b"1: 00000000:1111 00000000:0000 0A\n"
        with self.assertRaisesRegex(ProfileError, "non-loopback TCP listener"):
            _verify_listeners(WORKER_ID, False)

    @patch("profile_checks.podman")
    def test_oversized_listener_table_is_rejected_before_parsing(self, podman):
        podman.return_value = CompletedProcess([], 0, stdout=b" " * (MAX_LISTENER_TABLE + 1))
        with self.assertRaisesRegex(ProfileError, "exceeds the byte limit"):
            _verify_listeners(WORKER_ID, False)
        for call in podman.call_args_list:
            self.assertEqual(call.args[2:6], ("busybox", "head", "-c", str(MAX_LISTENER_TABLE + 1)))

    @patch("profile_checks.podman")
    def test_compiled_selection_rejects_missing_and_unexpected_sidecars(self, podman):
        for omitted, ids in (
            (False, {"postgres": PG_ID}),
            (True, {"postgres": PG_ID, "chromium": "c" * 64}),
        ):
            with self.subTest(omitted=omitted):
                sidecars = Mock(ids=ids, recorded=ids.copy(), pending=set())
                selection = compile_fixture(without_chromium=omitted)
                with self.assertRaisesRegex(ProfileError, "compiled selection"):
                    verify_services(Mock(), sidecars, selection)
        podman.assert_not_called()
