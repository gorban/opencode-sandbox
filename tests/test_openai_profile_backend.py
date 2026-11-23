"""Exercise registry and connection publication through the workstation facade."""

from contextlib import contextmanager
from pathlib import Path
import os
import pwd
import tempfile
import time
import unittest
from unittest.mock import patch

from oc_openai import cli
from oc_openai.connection import Connection
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
        with self.assertRaises(cli.RouteUnavailable):
            backend.connect("fixture")
        self.assertIsNone(backend.connection())
        self.assertFalse(backend.status().saved[0].connected)
        selected = backend.profiles.selected()
        self.assertNotEqual(self.connection(selected.directory).status(), "connected")
        self.assertEqual(old.label, selected.label)

    @unittest.skipUnless(os.environ.get("OC_OPENAI_WORKER_REAL") == "1", "requires pinned Podman/devbox host")
    def test_pinned_opencode_via_attended_cli_and_real_broker_with_fake_openai(self):
        self.transport_type = ProofTransport
        backend = self.backend()
        backend.connect("personal")
        terminal = Terminal(True, True)
        self.assertEqual(cli.run(("accept",), terminal=terminal, backend_factory=lambda: backend), 0, terminal.output)
        selected = backend.profiles.selected()
        self.connection(selected.directory).require_switchable()
        proof_requests = [call for call in self.transports[selected.directory].calls if call[0] == "synthetic"]
        self.assertEqual(len(proof_requests), 3)
        self.assertTrue(backend.disconnect())
