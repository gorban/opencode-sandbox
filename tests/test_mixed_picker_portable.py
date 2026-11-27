"""Test the isolated supervisor seam and mixed-provider projection with fake hardware."""

from hashlib import sha256
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
SOURCE_PACKAGE = "oc_mixed_picker_fixture/__init__.py"
BOOTSTRAP = "oc-openai-session.py"
FINAL_CALL = b"    return run_interactive_session(launch_spec, StreamTerminal(sys.stdin, sys.stdout, sys.stderr))"
FIXTURE_CALL = (
    b'    fixture = _load_package("oc_mixed_picker_fixture")\n'
    b"    return fixture.run(run_interactive_session, launch_spec, "
    b"StreamTerminal(sys.stdin, sys.stdout, sys.stderr))"
)
SCOPES = ("google--personal", "openai--personal", "openai--work")
MODEL = "opal-v2"


def source_manifest(files):
    digest = sha256()
    for path, data in sorted(files.items()):
        digest.update(f"{path}\0{sha256(data).hexdigest()}\n".encode())
    return digest.hexdigest()


def replace_bootstrap(data):
    if data.splitlines().count(FINAL_CALL) != 1 or data.count(FINAL_CALL) != 1:
        raise ValueError("supervisor call anchor changed")
    return data.replace(FINAL_CALL, FIXTURE_CALL, 1)


class Snapshot:
    def __init__(self, root):
        self.root = root
        paths = [REPO / "oc-sandbox", REPO / BOOTSTRAP]
        for package in ("oc_providers", "oc_openai"):
            paths.extend((REPO / package).rglob("*.py"))
        self.original = {str(p.relative_to(REPO)): p.read_bytes() for p in paths}
        self.expected = dict(self.original)
        self.expected[BOOTSTRAP] = replace_bootstrap(self.original[BOOTSTRAP])
        self.expected[SOURCE_PACKAGE] = Path(__file__).with_name("mixed_picker_portable.py").read_bytes()
        self.identity = (source_manifest(self.original), source_manifest(self.expected))
        root.mkdir(mode=0o700)
        for path, data in self.expected.items():
            dest = root / path
            dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            dest.write_bytes(data)
            dest.chmod(0o500 if path == "oc-sandbox" else 0o400)
        for directory in sorted(root.iterdir()):
            if directory.is_dir():
                for child in directory.rglob("*"):
                    if child.is_dir():
                        child.chmod(0o500)
                directory.chmod(0o500)
        root.chmod(0o500)
        self.verify()

    def verify(self):
        files = {}
        for node in (self.root, *self.root.rglob("*")):
            info = node.lstat()
            if info.st_mode & 0o222:
                raise ValueError("snapshot has a writable node")
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("snapshot has an unsafe source")
            files[str(node.relative_to(self.root))] = node.read_bytes()
        if source_manifest(files) != self.identity[1]:
            raise ValueError("snapshot digest differs")
        original = dict(files)
        del original[SOURCE_PACKAGE]
        original[BOOTSTRAP] = original[BOOTSTRAP].replace(FIXTURE_CALL, FINAL_CALL, 1)
        if source_manifest(original) != self.identity[0]:
            raise ValueError("base source digest differs")

    def close(self):
        for node in (self.root, *self.root.rglob("*")):
            if node.is_dir() and not node.is_symlink():
                node.chmod(0o700)


class FixtureCase:
    def __init__(self, root, *, target, ui_mode, case, projected):
        self.root = root
        self.home = root / "home"
        self.sandbox = self.home / "opencode-sandbox"
        (self.sandbox / "fixture-work").mkdir(mode=0o700, parents=True)
        config = self.home / ".config" / "oc-sandbox"
        config.mkdir(mode=0o700, parents=True)
        for leaf in ("jobs", "locks", "evidence", "exposure"):
            (root / leaf).mkdir(mode=0o700)
        toml = (
            f'[launch]\ndefault_provider = "{projected.replace("--", "/")}"\n'
            f'default_model = "{MODEL}"\n'
        )
        for scope in SCOPES:
            kind, label = scope.split("--")
            toml += f'[providers.{kind}.{label}]\nenabled = true\nauth_mode = "subscription"\n'
        (config / "providers.toml").write_text(toml)
        (root / "case.json").write_text(json.dumps({"target": target, "mode": case, "ui_mode": ui_mode}))
        (root / "ambient").write_text('{"scoped_provider_id":"wrong-scope","approved_model":"wrong-model"}')
        self.spec = {
            "instance": "fixture", "pod": "oc-fixture", "agent": "oc-fixture-agent",
            "relay": "oc-fixture-openai-relay", "relay_image": "c" * 64, "agent_image": "d" * 64,
            "agent_mem": "2g", "level": "s0:c100,c200", "sandbox": str(self.sandbox), "cwd": "fixture-work",
            "home_vol": "oc-fixture-openai-home", "chromium": "oc-fixture-chromium",
            "postgres": "", "pg_secret": "", "dind": "", "dind_run": "",
            "provider_filter": "", "cli_ui_mode": ui_mode,
        }
        self.snapshot = Snapshot(root / "source")

    def run(self, *, fd3=None, pass_fd=True):
        self.snapshot.verify()
        path = self.root / "spec.json"
        path.write_bytes(json.dumps(self.spec).encode() if fd3 is None else fd3)
        redirect = '3<"$3"' if pass_fd else "3<&-"
        return subprocess.run(
            ["/bin/bash", "-c", f'exec "$1" -IB "$2" {redirect} 4<"$4"', "_", sys.executable,
             str(self.snapshot.root / BOOTSTRAP), str(path), str(self.root / "ambient")],
            env={"PATH": "/usr/bin:/bin", "HOME": str(self.home)},
            stdin=subprocess.DEVNULL, capture_output=True, timeout=15, text=True, check=False,
        )

    def result(self):
        return json.loads((self.root / "observations.json").read_text())


class MixedPickerPortableTests(unittest.TestCase):
    def fixture(self, *, target=SCOPES[0], ui_mode="default", case="positive", projected=None):
        work = tempfile.TemporaryDirectory(prefix="oc-mix-", dir="/tmp")
        self.addCleanup(work.cleanup)
        fixture = FixtureCase(
            Path(work.name), target=target, ui_mode=ui_mode, case=case, projected=projected or target,
        )
        self.addCleanup(fixture.snapshot.close)
        return fixture

    def test_snapshot_preserves_original_launcher_and_supervisor_except_final_call(self):
        snapshot = self.fixture().snapshot
        self.assertEqual((snapshot.root / "oc-sandbox").read_bytes(), snapshot.original["oc-sandbox"])
        actual = (snapshot.root / BOOTSTRAP).read_bytes()
        self.assertEqual(actual.replace(FIXTURE_CALL, FINAL_CALL, 1), snapshot.original[BOOTSTRAP])
        self.assertNotEqual(*snapshot.identity)
        for invalid in (b"no anchor", FINAL_CALL + b"\n" + FINAL_CALL):
            with self.assertRaisesRegex(ValueError, "anchor changed"):
                replace_bootstrap(invalid)
        copied = snapshot.root / BOOTSTRAP
        copied.chmod(0o600)
        copied.write_bytes(actual + b"\n")
        copied.chmod(0o400)
        with self.assertRaisesRegex(ValueError, "snapshot digest differs"):
            snapshot.verify()

    def test_missing_malformed_or_oversize_fd3_never_enters_fixture(self):
        fixture = self.fixture()
        for arguments in ({"pass_fd": False}, {"fd3": b"{"}, {"fd3": b" " * 65537}):
            with self.subTest(arguments=list(arguments)):
                invoked = fixture.run(**arguments)
                self.assertEqual(invoked.returncode, 1, invoked.stderr)
                self.assertIn("trusted workstation supervisor unavailable", invoked.stderr)
                self.assertFalse((fixture.root / "observations.json").exists())

    def test_projection_cannot_be_rewritten_to_fit_the_approval(self):
        fixture = self.fixture(projected=SCOPES[1])
        invoked = fixture.run()
        self.assertEqual(invoked.returncode, 1, invoked.stderr)
        result = fixture.result()
        self.assertEqual(result["raw_route"], f"{SCOPES[1]}/{MODEL}")
        self.assertEqual(result["gate"]["scoped_provider_id"], SCOPES[0])
        self.assertEqual(result["writes"], [])
        self.assertEqual(result["placement_events"], [])
        self.assertEqual(result["remaining_jobs"], [])

    def test_cancelled_workstation_confirmation_starts_no_slots(self):
        fixture = self.fixture(case="cancelled")
        invoked = fixture.run()
        self.assertEqual(invoked.returncode, 1, invoked.stdout + invoked.stderr)
        result = fixture.result()
        self.assertIn("Start interactive OpenCode", result["confirmation"])
        self.assertEqual(result["writes"], [])
        self.assertEqual(result["placement_events"], [])
        self.assertIsNone(result["raw_route"])

    def test_each_fresh_full_case_sends_once_only_through_the_exact_projected_model(self):
        for scope in SCOPES:
            with self.subTest(scope=scope):
                fixture = self.fixture(target=scope)
                invoked = fixture.run()
                self.assertEqual(invoked.returncode, 0, invoked.stdout + invoked.stderr)
                self.assertIn(f"Initial active model: {scope}/{MODEL}", invoked.stdout)
                result = fixture.result()
                self.assertFalse(result["mini_argument"])
                self.assert_exact_attribution(result, scope)

    def test_mini_fd3_intent_reaches_projected_placement_and_same_closed_slots(self):
        # Portable spec/placement parity. The real Mini frontend has a separate owner.
        fixture = self.fixture(ui_mode="mini")
        invoked = fixture.run()
        self.assertEqual(invoked.returncode, 0, invoked.stdout + invoked.stderr)
        self.assertIn("OpenCode Mini (--mini)", invoked.stdout)
        result = fixture.result()
        self.assertTrue(result["mini_argument"])
        self.assert_exact_attribution(result, SCOPES[0])

    def test_wrong_projected_model_evidence_owner_loss_and_config_drift_produce_no_fixture_writes(self):
        for case, evidence, expected in (
            ("wrong-model-evidence", "wrong_model_evidence_refused", True), ("owner-loss", "owner_loss", 401),
            ("config-drift", "config_drift", 502),
        ):
            with self.subTest(case=case):
                fixture = self.fixture(case=case)
                invoked = fixture.run()
                self.assertEqual(invoked.returncode, 0, invoked.stdout + invoked.stderr)
                result = fixture.result()
                self.assertEqual(result[evidence], expected)
                self.assertEqual(result["writes"], [])
                self.assertEqual(result["gate"]["admitted_writes"], 0)
                self.assertEqual(result["live_containers"], [])
                self.assertEqual(result["remaining_jobs"], [])

    def test_rejects_wrong_bearer_from_mounted_worker_config(self):
        fixture = self.fixture(case="wrong-bearer")
        invoked = fixture.run()
        self.assertEqual(invoked.returncode, 1, invoked.stdout + invoked.stderr)
        result = fixture.result()
        self.assertEqual(result["runner_worker_id"], result["worker_id"])
        self.assertNotIn("worker_routes_checked", result)
        self.assertEqual(result["writes"], [])
        self.assertEqual(result["gate"]["admitted_writes"], 0)
        self.assertEqual(result["live_containers"], [])
        self.assertEqual(result["remaining_jobs"], [])
        self.assertNotIn("wrong-projected-fixture-bearer", invoked.stdout + invoked.stderr)

    def test_unpinned_fake_worker_placement_is_refused(self):
        fixture = self.fixture()
        fixture.spec["agent_image"] = "e" * 64
        invoked = fixture.run()
        self.assertEqual(invoked.returncode, 1, invoked.stdout + invoked.stderr)
        self.assertIn("launch spec differs from the pinned portable fixture", invoked.stderr)
        self.assertFalse((fixture.root / "observations.json").exists())

    def test_rejects_wrong_relay_port_in_discovery_and_replacement_create_args(self):
        for case in ("wrong-discovery-port", "wrong-turn-port"):
            with self.subTest(case=case):
                fixture = self.fixture(case=case)
                invoked = fixture.run()
                self.assertEqual(invoked.returncode, 1, invoked.stdout + invoked.stderr)
                result = fixture.result()
                rejected, = (event[1] for event in result["placement_events"] if event[0] == "reject-relay-argv")
                self.assertFalse(any(event[:2] == ["bound", rejected] for event in result["placement_events"]))
                self.assertEqual(result["writes"], [])
                self.assertEqual(result["gate"]["admitted_writes"], 0)
                self.assertEqual(result["live_containers"], [])
                self.assertEqual(result["live_ports"], [])
                self.assertEqual(result["remaining_jobs"], [])

    def test_rejects_tool_fields_in_delivered_sse_envelope_and_nested_usage(self):
        for case in ("tool-event-field", "nested-tool-field"):
            with self.subTest(case=case):
                fixture = self.fixture(case=case)
                invoked = fixture.run()
                self.assertEqual(invoked.returncode, 1, invoked.stdout + invoked.stderr)
                result = fixture.result()
                self.assertEqual(result["sse_refusal"], "unexpected field in fixture SSE")
                self.assertNotIn("received_sse", result)
                self.assertEqual(len(result["writes"]), 1)
                self.assertTrue(result["gate"]["exact_ok_delivered"])
                self.assertEqual(result["live_containers"], [])
                self.assertEqual(result["live_ports"], [])

    def test_owner_loss_after_claim_stops_the_fake_transport_write(self):
        fixture = self.fixture(case="owner-loss-after-claim")
        invoked = fixture.run()
        self.assertEqual(invoked.returncode, 0, invoked.stdout + invoked.stderr)
        result = fixture.result()
        self.assertEqual(result["owner_loss_after_claim"], 401)
        self.assertEqual(result["gate"]["admitted_writes"], 1)
        self.assertEqual(result["writes"], [])
        self.assertNotIn("received_sse", result)
        self.assertEqual(result["live_ports"], [])

    def test_wrong_mounted_model_is_refused_before_any_projected_request(self):
        fixture = self.fixture(case="wrong-mounted-model")
        invoked = fixture.run()
        self.assertEqual(invoked.returncode, 1, invoked.stdout + invoked.stderr)
        result = fixture.result()
        self.assertEqual(result["raw_route"], f"{SCOPES[0]}/{MODEL}")
        self.assertEqual(result["mounted_model"], f"{SCOPES[1]}/opal-v1")
        self.assertFalse(any(event[0] == "worker-request" for event in result["placement_events"]))
        self.assertEqual(result["writes"], [])
        self.assertEqual(result["gate"]["admitted_writes"], 0)
        self.assertEqual(result["live_ports"], [])

    def assert_exact_attribution(self, result, scope):
        ports = {key: value["port"] for key, value in result["slots"].items()}
        self.assertEqual(ports, dict(zip(SCOPES, range(8401, 8404))))
        for key, item in result["slots"].items():
            self.assertEqual(item["endpoint"], f"http://127.0.0.1:{ports[key]}/v1")
            self.assertEqual(set(item["models"]), {"opal-v1", "opal-v2"})
            self.assertTrue(item["zero_tools"])
        self.assertEqual(len({item["models"][MODEL] for item in result["slots"].values()}), 3)
        self.assertEqual(result["unique_bearers"], 3)
        self.assertEqual(set(result["pre_arm"].values()), {403})
        self.assertEqual(set(result["cross_slot"].values()), {401})
        self.assertEqual(set(result["siblings_after_arm"].values()), {403})
        self.assertEqual(result["sibling_bearer_to_turn"], {other: 401 for other in SCOPES if other != scope})
        self.assertEqual(result["wrong_model"], 403)
        self.assertEqual(result["automatic_prompt"], 403)
        self.assertEqual(result["tool_request"], 400)
        self.assertTrue(result["retired_discovery"])
        self.assertTrue(result["fresh_incarnation"])
        self.assertEqual(result["replay"], 403)
        self.assertTrue(result["rearm_refused"])
        self.assertTrue(result["worker_routes_checked"])
        self.assertEqual(result["received_sse"], {"text": "ok", "completed": True, "tool_parts": 0, "events": 8})
        self.assertEqual(result["runner_worker_id"], result["worker_id"])
        self.assertEqual(result["mounted_model"], f"{scope}/{MODEL}")
        self.assertEqual(result["live_ports"], [])
        self.assertIn(["create", result["worker_id"]], result["placement_events"])
        self.assertIn(["remove", result["worker_id"]], result["placement_events"])
        self.assertEqual(result["live_containers"], [])
        self.assertEqual(result["remaining_jobs"], [])
        self.assertEqual(len(result["writes"]), 1)
        written, binding, body = result["writes"][0]
        gate = result["gate"]
        self.assertEqual(written, scope)
        self.assertEqual(binding, {
            "scope": scope, "registration_id": binding["registration_id"],
            "generation": gate["credential_generation"], "epoch": gate["selection_epoch"],
            "incarnation": gate["job_incarnation"], "launch_id": gate["run_id"],
            "pod": "a" * 64, "placement": "sandbox", "auth_mode": gate["auth_mode"],
            "route_policy": gate["route_policy"],
        })
        self.assertRegex(binding["registration_id"], r"^[0-9a-f]{32}$")
        self.assertEqual(body, {
            "model": MODEL, "input": [{"type": "message", "role": "user", "content": "Reply with exactly: ok"}],
            "store": False, "stream": True,
        })
        self.assertEqual(gate["tool_call_count"], 0)
        self.assertTrue(gate["exact_ok_delivered"])
        events = result["placement_events"]
        deferred, = (event[1] for event in events if event[0] == "relay" and event[2])
        self.assertEqual(deferred, gate["verified_relay_id"])
        self.assertLess(events.index(["verify", deferred, gate["job_incarnation"]]),
                        events.index(["bound", deferred, ports[scope]]))
        self.assertLess(events.index(["bound", deferred, ports[scope]]),
                        events.index(["worker-request", deferred, ports[scope]]))


if __name__ == "__main__":
    unittest.main()
