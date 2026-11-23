from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from subprocess import CompletedProcess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

import probe_profile
from oc_plan import compile_plan
from oc_schema import sha256_canonical_json
from profile_checks import _chrome_response, _verify_listeners
from profile_plan import (
    CDP_SERVICE, PG_SERVICE, PROFILE, WORKER_REF, FixtureCatalog, ProfileError, compile_fixture, lower, verify_image,
)
from profile_services import ROLE, LABEL, Sidecars, _arguments, recipe
from runtime import JobRuntimeError


WORKER_ID = "a" * 64
PG_ID = "b" * 64


class PlanTests(TestCase):
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
        ):
            with self.subTest(name=name):
                plan = deepcopy(reference.plan)
                mutate(plan)
                with self.assertRaises(ProfileError):
                    lower(replace(reference, plan=plan, plan_digest=sha256_canonical_json(plan)))

    def test_reject_wrong_plan_digest(self):
        reference = compile_plan(FixtureCatalog(), PROFILE)
        with self.assertRaisesRegex(ProfileError, "digest"):
            lower(replace(reference, plan_digest="0" * 64))

    def test_image_requires_exact_local_identity_and_repository_pin(self):
        metadata = {"Id": WORKER_ID, "Os": "linux", "Architecture": "amd64", "RepoDigests": [WORKER_REF]}
        inspect = Mock(return_value=metadata)
        verify_image(WORKER_ID, WORKER_REF, inspect)
        inspect.assert_called_once_with("image", "inspect", WORKER_ID)
        for update in ({"Id": PG_ID}, {"RepoDigests": []}, {"Architecture": "arm64"}):
            with self.subTest(update=update), self.assertRaises(ProfileError):
                verify_image(WORKER_ID, WORKER_REF, Mock(return_value={**metadata, **update}))

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
        job = Mock(root=self.root, ids={"worker": WORKER_ID})
        job._identity.return_value = {
            "ProcessLabel": "system_u:system_r:container_t:s0:c1,c2",
            "MountLabel": "system_u:object_r:container_file_t:s0:c1,c2",
        }
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
    def test_uncertain_create_retains_receipt_without_guessing_identity(self, podman):
        podman.side_effect = JobRuntimeError("fixture create timed out")
        with self.assertRaises(JobRuntimeError):
            self.sidecars.start(self.spec)
        with self.assertRaisesRegex(ProfileError, "unconfirmed"):
            self.sidecars.close()
        self.assertEqual(podman.call_count, 1)
        self.assertIn('"pending": ["chromium"]', self.sidecars.path.read_text())

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
