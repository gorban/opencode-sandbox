"""Exercise registry and connection publication through the workstation facade."""

from contextlib import contextmanager
import json
from pathlib import Path
import os
import pwd
import select
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from oc_openai.acceptance import run_attended
from oc_openai import cli
from oc_openai.connection import Connection, ConnectionError
from oc_openai.profile_backend import ProfileBackend
from oc_openai.profiles import ProfileError
from test_openai_connection import FixtureBrowser, FixtureTransport, FixtureVerifier
from test_openai_live import Terminal, proposal_events
from test_openai_worker import fixture_events


class ProofTransport(FixtureTransport):
    @contextmanager
    def responses(self, body, bearer, cancellation, dispatch):
        cancellation.check()
        dispatch(lambda: self.calls.append(("synthetic", "proof", body, None)))
        if "instructions" in body:
            yield fixture_events(body, deadline=time.monotonic() + 5, cancelled=cancellation.event)
        else:
            yield proposal_events()


class ProfileBackendTests(unittest.TestCase):
    def setUp(self):
        def _forbid_host_browser(url):
            raise AssertionError(f"unit test attempted to open host browser: {url}")

        self.enterContext(patch("oc_openai.connection._open_host_browser", side_effect=_forbid_host_browser))
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        self.state = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="oc-i4a-profile-", dir=home)))
        self.transports = {}
        self.transport_type = FixtureTransport
        self.backends = {}

    def connection(self, path):
        if path not in self.backends:
            browser = FixtureBrowser()
            browser.client = f"oaiapp_{path.name}"
            transport = self.transport_type()
            self.transports[path] = transport
            self.backends[path] = Connection(path, transport=transport, verifier=FixtureVerifier(), browser=browser)
        return self.backends[path]

    def backend(self, *, reviewed=True):
        return ProfileBackend(self.state, connection=self.connection, reviewed=reviewed)

    def test_pending_code_review_does_not_start_or_create_profile(self):
        backend = self.backend(reviewed=False)
        with self.assertRaises(cli.RouteUnavailable) as blocked:
            backend.connect("fixture")
        self.assertIs(blocked.exception.reason, cli.Reason.QUALIFICATION)
        self.assertEqual(list(self.state.iterdir()), [])
        self.assertFalse(self.backends)

    def test_verified_credentials_without_registry_publication_are_recoverable(self):
        backend = self.backend()
        backend.connect("previous")
        previous = backend.connection()
        original = backend.profiles._write
        def fail_selection(directory, state):
            if state["active"] == "additional":
                raise ProfileError("profile_storage_unavailable")
            original(directory, state)
        with patch.object(backend.profiles, "_write", side_effect=fail_selection):
            with self.assertRaisesRegex(ProfileError, "profile_storage_unavailable"):
                backend.connect("additional")
        self.assertEqual(backend.connection(), previous)
        sent = sum(len(transport.calls) for transport in self.transports.values())
        backend.connect("additional")
        self.assertEqual(sum(len(transport.calls) for transport in self.transports.values()), sent)
        self.assertEqual(backend.connection().label, "additional")
        backend.select("previous")
        again = backend.connection()
        self.assertEqual(again.registration_id, previous.registration_id)
        self.assertNotEqual(again.selection_epoch, previous.selection_epoch)

    def test_new_same_label_credentials_recover_after_registry_write_failure(self):
        backend = self.backend()
        backend.connect("personal")
        previous = backend.connection()
        self.assertTrue(backend.disconnect())
        original = backend.profiles._write
        def fail_completion(directory, state):
            if not state["registrations"]["personal"]["retiring"]:
                raise ProfileError("profile_storage_unavailable")
            original(directory, state)
        with patch.object(backend.profiles, "_write", side_effect=fail_completion):
            with self.assertRaisesRegex(ProfileError, "profile_storage_unavailable"):
                backend.connect("personal")
        self.assertIsNone(backend.connection())
        backend.connect("personal")
        self.assertNotEqual(backend.connection().generation, previous.generation)

    def test_interruption_before_registry_retirement_cannot_revive_old_binding(self):
        backend = self.backend()
        backend.connect("fixture")
        old = backend.connection()
        with patch.object(backend.profiles, "_write", side_effect=ProfileError("profile_storage_unavailable")):
            with self.assertRaisesRegex(ProfileError, "profile_storage_unavailable"):
                backend.disconnect()
        self.assertIsNone(backend.connection())
        self.assertEqual(backend.active_label(), "fixture")
        self.assertFalse(backend.status().saved[0].connected)
        selected = backend.profiles.selected()
        self.assertNotEqual(self.connection(selected.directory).status(), "connected")
        backend.connect("fixture")
        self.assertNotEqual(backend.connection().generation, old.generation)
        self.assertEqual(old.label, selected.label)

    def test_failed_local_retirement_does_not_publish_a_retired_selection(self):
        backend = self.backend()
        backend.connect("fixture")
        selected = backend.profiles.selected()
        binding = backend.connection()
        connection = self.connection(selected.directory)
        with patch.object(connection, "begin_disconnect", side_effect=ConnectionError("connection_storage_busy")):
            with self.assertRaises(cli.RouteUnavailable):
                backend.disconnect()
        self.assertEqual(backend.profiles.selected(), selected)
        self.assertEqual(backend.connection(), binding)
        self.assertTrue(backend.disconnect())
        self.assertIsNone(backend.connection())

    def test_disconnect_preserves_inactive_connected_registration_with_recovery_candidate(self):
        backend = self.backend()
        backend.connect("personal")
        personal = backend.profiles.selected()
        backend.connect("work")
        backend.profiles.begin("personal")
        sent = len(self.transports[personal.directory].calls)
        self.assertTrue(backend.disconnect())
        self.assertEqual(backend.status().saved, (
            cli.SavedProfile("personal", True), cli.SavedProfile("work", False),
        ))
        self.assertEqual(len(self.transports[personal.directory].calls), sent)

    def test_failed_local_prerequisite_allocates_no_registrations(self):
        backend = self.backend()
        with patch.object(FixtureVerifier, "preflight", side_effect=ConnectionError("openai_jose_prerequisite_missing")):
            for index in range(20):
                with self.assertRaises(cli.RouteUnavailable):
                    backend.connect(f"failed-{index}")
        self.assertEqual(list(self.state.iterdir()), [])
        self.assertEqual(backend.status().saved, ())
        backend.connect("works")
        self.assertEqual(backend.active_label(), "works")

    def test_clean_failed_signin_releases_capacity_without_deleting_directory(self):
        backend = self.backend()
        with patch.object(FixtureBrowser, "__call__", side_effect=ConnectionError("fixture_browser_unavailable")):
            for index in range(20):
                with self.assertRaises(cli.RouteUnavailable):
                    backend.connect(f"failed-{index}")
        self.assertEqual(backend.profiles.snapshot().unpublished, ())
        self.assertGreater(len(tuple((self.state / "registrations").iterdir())), 16)
        backend.connect("works")
        self.assertEqual(backend.active_label(), "works")

    def test_cancelled_browser_releases_capacity_after_disconnect_finishes(self):
        backend = self.backend()
        cancelled = backend.profiles.begin("cancelled")
        for index in range(15):
            backend.profiles.begin(f"reserved-{index}")
        connection = self.connection(cancelled.profile.directory)
        connection._browser.hold = True
        finishing = threading.Event()
        release = threading.Event()
        signed_in = []
        disconnected = []
        finish = connection.finish_disconnect

        def hold_finish(retirement):
            finishing.set()
            if not release.wait(4):
                raise AssertionError("fixture failed to release disconnect")
            return finish(retirement)

        def connect():
            try:
                backend.connect("cancelled")
            except cli.RouteUnavailable as error:
                signed_in.append(error)

        sign_in = threading.Thread(target=connect, daemon=True)
        sign_out = threading.Thread(target=lambda: disconnected.append(backend.disconnect()), daemon=True)
        with patch.object(connection, "finish_disconnect", side_effect=hold_finish):
            sign_in.start()
            try:
                self.assertTrue(connection._browser.ready.wait(3))
                sign_out.start()
                self.assertTrue(finishing.wait(3))
                sign_in.join(3)
                self.assertFalse(sign_in.is_alive())
                self.assertEqual(len(signed_in), 1)
                self.assertEqual(len(backend.profiles.snapshot().unpublished), 16)
                self.assertFalse(connection.reclaimable_registration())
            finally:
                release.set()
                sign_in.join(3)
                if sign_out.ident is not None:
                    sign_out.join(3)
        self.assertEqual(disconnected, [True])
        self.assertTrue(connection.reclaimable_registration())
        backend.connect("new")
        self.assertEqual(backend.active_label(), "new")
        self.assertTrue(cancelled.profile.directory.exists())

    def test_connect_lifetime_refuses_concurrent_attempt_and_recovers_crashed_claim(self):
        for disconnect, possible_exchange in ((False, False), (True, False), (False, True), (True, True)):
            with self.subTest(disconnect=disconnect, possible_exchange=possible_exchange):
                state = self.state / f"claims-{int(disconnect)}-{int(possible_exchange)}"
                backend = ProfileBackend(state, connection=self.connection, reviewed=True)
                for index in range(15):
                    saved = backend.profiles.begin(f"saved-{index}")
                    with backend.profiles.publish(saved, f"oaiapp_fixture_{index}"):
                        pass
                process = subprocess.Popen(
                    [sys.executable, "-B", "-c", """
from pathlib import Path
import sys
import time
from oc_openai.connection_state import Store
from oc_openai.profiles import Profiles

profiles = Profiles(Path(sys.argv[1]))
with profiles.connect_candidate("crashed") as candidate:
    store = Store(candidate.profile.directory)
    pending = {"expires": time.time() + 300}
    if sys.argv[2] == "1":
        pending.update(consumed=True, may_have_sent=True)
    with profiles.authorize(candidate), store.locked(create=True) as directory:
        store.write(directory, {"generation": "g" * 43, "pending": pending})
    print("ready", flush=True)
    sys.stdin.readline()
    import os
    os._exit(0)
""", str(state), str(int(possible_exchange))],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                try:
                    self.assertTrue(select.select([process.stdout], [], [], 3)[0])
                    self.assertEqual(process.stdout.readline().strip(), "ready")
                    snapshot = backend.profiles.snapshot()
                    self.assertEqual(len(snapshot.unpublished), 1)
                    crashed = snapshot.unpublished[0]
                    with self.assertRaisesRegex(ProfileError, "^profile_connect_busy$"):
                        backend.connect("new")
                    self.assertEqual(backend.profiles.snapshot(), snapshot)
                finally:
                    process.communicate(input="exit\n", timeout=4)
                self.assertEqual(process.returncode, 0)
                self.assertEqual(backend.profiles.snapshot().unpublished, (crashed,))
                if disconnect:
                    self.assertIs(backend.disconnect(), not possible_exchange)
                if possible_exchange:
                    with self.assertRaisesRegex(ProfileError, "^profile_limit$"):
                        backend.connect("new")
                    (retained,) = backend.profiles.snapshot().unpublished
                    self.assertEqual((retained.label, retained.directory), (crashed.label, crashed.directory))
                    self.assertIn(cli.SavedProfile("crashed", False, True, False), backend.status().saved)
                    self.assertEqual(backend.active_label(), "saved-14")
                else:
                    backend.connect("new")
                    self.assertEqual(backend.active_label(), "new")
                    self.assertEqual(backend.profiles.snapshot().unpublished, ())
                self.assertTrue(crashed.directory.exists())

    def test_acknowledged_callback_survives_crash_before_exchange_and_preserves_slot(self):
        backend = self.backend()
        for index in range(15):
            saved = backend.profiles.begin(f"saved-{index}")
            with backend.profiles.publish(saved, f"oaiapp_fixture_{index}"):
                pass
        tests = Path(__file__).resolve().parent
        result = subprocess.run([sys.executable, "-B", "-c", """
import contextlib
import os
from pathlib import Path
import sys
from oc_openai.connection import Connection
from oc_openai.profiles import Profiles
from test_openai_connection import FixtureBrowser, FixtureTransport, FixtureVerifier

profiles = Profiles(Path(sys.argv[1]))
browser = FixtureBrowser()
transport = FixtureTransport()
with profiles.connect_candidate("crashed") as candidate:
    connection = Connection(candidate.profile.directory, transport=transport,
                            verifier=FixtureVerifier(), browser=browser)
    admissions = 0

    @contextlib.contextmanager
    def authorize():
        global admissions
        admissions += 1
        if admissions == 2:
            if not browser.finished.wait(2) or browser.assertions is not None or transport.calls:
                raise RuntimeError("Expected callback acknowledgement before provider request")
            print("HTTP 200 received; no provider request", flush=True)
            os._exit(73)
        with profiles.authorize(candidate):
            yield

    connection.connect(installation_host=candidate.profile.host_id, authorization=authorize)
""", str(self.state)], cwd=tests.parent, env={**os.environ, "PYTHONPATH": str(tests)},
            capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertEqual(result.stdout.strip(), "HTTP 200 received; no provider request")
        (crashed,) = backend.profiles.snapshot().unpublished
        self.assertEqual(crashed.label, "crashed")
        record = json.loads((crashed.directory / "state.json").read_bytes())
        self.assertEqual(set(record), {"version", "generation", "host_id", "profile",
                                       "pending", "registration_observed"})
        self.assertIs(record["registration_observed"], True)
        self.assertEqual(set(record["pending"]), {"expires"})
        self.assertFalse(self.connection(crashed.directory).revocation_unconfirmed())
        with self.assertRaisesRegex(ProfileError, "^profile_limit$"):
            backend.connect("new")
        self.assertEqual(backend.profiles.snapshot().unpublished, (crashed,))
        self.assertFalse(any(transport.calls for transport in self.transports.values()))

    def test_cross_process_disconnect_orders_pending_first_exchange(self):
        for send_first in (False, True):
            with self.subTest(send_first=send_first):
                state = self.state / f"case-{int(send_first)}"
                release = threading.Event()
                browser = FixtureBrowser()
                browser.hold = not send_first
                transport = FixtureTransport()
                if send_first:
                    transport.token_block = release
                failures = []

                def connection(path):
                    return Connection(path, transport=transport, verifier=FixtureVerifier(), browser=browser)

                backend = ProfileBackend(state, connection=connection, reviewed=True)

                def sign_in():
                    try:
                        backend.connect("pending")
                    except Exception as error:
                        failures.append(error)

                thread = threading.Thread(target=sign_in, daemon=True)
                thread.start()
                try:
                    self.assertTrue(browser.ready.wait(3))
                    if send_first:
                        self.assertTrue(transport.token_started.wait(3))
                    process = subprocess.run(
                        [sys.executable, "-B", "-c", """
from pathlib import Path
import sys
sys.path.insert(0, "tests")
from oc_openai.connection import Connection
from oc_openai.profile_backend import ProfileBackend
from test_openai_connection import FixtureBrowser, FixtureTransport, FixtureVerifier

def connection(path):
    return Connection(path, transport=FixtureTransport(), verifier=FixtureVerifier(), browser=FixtureBrowser())

backend = ProfileBackend(Path(sys.argv[1]), connection=connection)
print(backend.disconnect())
""", str(state)],
                        capture_output=True, text=True, timeout=5, check=True,
                    )
                    self.assertEqual(process.stdout.strip(), "False" if send_first else "True")
                    if not send_first:
                        browser.send()
                finally:
                    release.set()
                    thread.join(4)
                self.assertFalse(thread.is_alive())
                self.assertEqual(len(failures), 1)
                self.assertIsNone(backend.active_label())
                self.assertEqual(transport.token_started.is_set(), send_first)
                if send_first:
                    self.assertEqual(backend.status().saved, (cli.SavedProfile("pending", False, True, False),))
                else:
                    self.assertFalse(any(profile.revocation_unconfirmed for profile in backend.status().saved))

    @unittest.skipUnless(os.environ.get("OC_OPENAI_WORKER_REAL") == "1", "requires pinned Podman/devbox host")
    def test_pinned_opencode_via_attended_proof_and_real_broker_with_fake_openai(self):
        self.transport_type = ProofTransport
        backend = self.backend()
        backend.connect("personal")
        terminal = Terminal(True, True)
        self.assertEqual(run_attended(terminal, backend_factory=lambda: backend), 0, terminal.output)
        selected = backend.profiles.selected()
        self.connection(selected.directory).require_switchable()
        proof_requests = [call for call in self.transports[selected.directory].calls if call[0] == "synthetic"]
        self.assertEqual(len(proof_requests), 3)
        self.assertTrue(backend.disconnect())
