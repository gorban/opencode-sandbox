"""Exercise the durable-to-proxy join in a private, offline fixture."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import socket
from tempfile import TemporaryDirectory
from threading import Event, RLock
from time import monotonic
import unittest
from unittest.mock import patch

from oc_google import generation, generation_journal as journal, generation_phase, generation_proxy, registration
from oc_google.generation_proxy import ProxyRefused
from test_google_generation import request, response
from test_google_generation_journal import provision
import test_google_generation_phase as proxy_tests


class JournalTurnTest(unittest.TestCase):
    def setUp(self):
        self.proxy = proxy_tests.FixturePhaseTest()
        self.addCleanup(self.proxy.doCleanups)
        self.proxy.setUp()
        self.home = Path(self.enterContext(TemporaryDirectory(prefix="oc-google-private-join-")))
        self.enterContext(patch.object(registration, "_account_home", return_value=self.home))
        self.registration = journal.FixtureRegistrationJournal()
        self.fence = RLock()
        self.journal_observer = lambda: None
        self.slot_root = self.home / ".local/state/oc-sandbox/google" / journal._FIXTURE_DIR
        self.slot = self.slot_root / "registrations" / self.registration.label

    def durable_phase(self):
        return journal.Phase(json.loads((self.slot / journal._STATE).read_bytes())["phase"])

    def publish(self, run, operation):
        packet = b"synthetic journal operation\n"
        digest = sha256(packet).hexdigest()
        owner, observer = socket.socketpair()
        with owner, observer:
            owner.setblocking(False)
            observer.settimeout(1)

            def exact_write(proof):
                run.verify_in_flight(proof, operation)
                return journal.WriteEvidence(owner, owner.send(packet), digest)

            capability = run.issue(operation)
            write = run.write_once(capability, exact_write, target=owner, data=packet)
            owner.shutdown(socket.SHUT_WR)
            self.assertEqual(observer.recv(len(packet) + 1), packet)
            self.assertEqual(observer.recv(1), b"")
            run.settle(write, journal.SettlementEvidence(write, owner, len(packet), digest))
        return run.acp_sent()

    @contextmanager
    def session(self, *, expect_success=False, activate=True, run_fence=None, bind=True):
        p = self.proxy
        with generation_phase.FixturePhase(
            p.root, port=p.port, binding=p.binding, fence=self.fence,
            authorized=lambda binding: p.live and binding is p.binding,
            verify_helper=lambda helper: helper is p.scope,
            sent_receipt_is_current=lambda *_: self.fail("legacy receipt verifier in journal turn"),
            destination_claim_is_current=lambda *_: self.fail("legacy claim verifier in journal turn"),
        ) as phase:
            # The helper forks before any D1 file is provisioned or opened.
            with p.helper(phase, expect_success=expect_success) as child:
                p.scope = generation_phase.HelperPlacement(child, os.geteuid(), b"/fixture.service", "a" * 32)
                try:
                    p.prepare(phase)
                    anchor = provision(self.registration, self.addCleanup)
                    ledger = journal.GenerationJournal(self.registration, anchor)
                    binding = anchor.binding(epoch=p.binding.epoch, launch="a" * 32)
                    fence = self.fence if run_fence is None else run_fence
                    def journal_owner(value):
                        self.journal_observer()
                        return value is binding

                    with ledger.launch(binding, fence=fence, authorized=journal_owner,
                                       deadline=monotonic() + 20) as run:
                        sent = self.publish(run, journal.Operation.ACP)
                        if bind:
                            phase.bind_journal(run, sent, proxy_binding=p.binding, journal_binding=binding)
                        if activate:
                            phase.activate(sent, journal_run=run)
                        yield phase, run, sent
                    with self.assertRaises(journal.GenerationHeld):
                        ledger.status()
                    with self.assertRaises(journal.GenerationHeld):
                        with ledger.launch(binding, fence=self.fence, authorized=lambda _: True,
                                           deadline=monotonic() + 1):
                            self.fail("the spent generation reopened")
                finally:
                    if phase.receipt().phase is not generation_phase.Phase.COMPLETE:
                        phase.revoke()
        self.assertEqual(list(p.root.iterdir()), [])

    def test_write_and_observe_settle_before_native_publication(self):
        with self.session(expect_success=True) as (phase, run, sent):
            sink = self.proxy.destination()
            fake_write, fake_read, fake_retire = sink.write, sink.read, sink.retire
            actual_send = generation_phase._send_once
            journal_verify = journal._Run.verify_in_flight
            destination_proof = []

            def track_in_flight(view, proof, operation):
                if operation is journal.Operation.DESTINATION:
                    self.assertIs(view, run)
                    destination_proof.append(proof)
                return journal_verify(view, proof, operation)

            def write(*args, **kwargs):
                self.assertTrue(self.fence._is_owned())
                self.assertEqual(self.durable_phase(), journal.Phase.DESTINATION_CLAIMED)
                return fake_write(*args, **kwargs)

            def read(*args, **kwargs):
                self.assertFalse(self.fence._is_owned())
                self.assertEqual(self.durable_phase(), journal.Phase.DESTINATION_CLAIMED)
                proof, = destination_proof
                with self.assertRaises(journal.GenerationHeld):
                    run.verify_in_flight(proof, journal.Operation.DESTINATION)
                return fake_read(*args, **kwargs)

            def retire(*args, **kwargs):
                self.assertFalse(self.fence._is_owned())
                self.assertEqual(self.durable_phase(), journal.Phase.DESTINATION_CLAIMED)
                return fake_retire(*args, **kwargs)

            def send(*args, **kwargs):
                self.assertTrue(self.fence._is_owned())
                self.assertEqual(self.durable_phase(), journal.Phase.DESTINATION_SETTLED)
                return actual_send(*args, **kwargs)

            with ThreadPoolExecutor(max_workers=1) as runner:
                native = runner.submit(self.proxy.client, request())
                with patch.object(sink, "write", side_effect=write) as writer, \
                        patch.object(sink, "read", side_effect=read) as observer, \
                        patch.object(sink, "retire", side_effect=retire) as retirement, \
                        patch.object(journal._Run, "verify_in_flight", new=track_in_flight), \
                        patch.object(generation_phase, "_send_once", side_effect=send) as native_send:
                    receipt = phase.serve_journal_turn(sink, run)
                self.assertEqual(native.result(timeout=3), response())
            writer.assert_called_once()
            observer.assert_called_once()
            retirement.assert_called_once()
            native_send.assert_called_once()
            self.assertEqual(receipt.phase, generation_phase.Phase.COMPLETE)
            self.assertEqual(receipt.fake_writes, 1)
            self.assertTrue(receipt.connector_retired)
            run.verify_acp_sent(sent)

    def test_foreign_or_copied_acp_receipt_cannot_arm_proxy(self):
        with self.session(activate=False) as (phase, run, sent):
            with self.assertRaisesRegex(ProxyRefused, "journal run or ACP sent receipt differs"):
                phase.activate(copy(sent), journal_run=run)
            self.assertIs(phase.receipt().phase, generation_phase.Phase.HELD)
            self.assertEqual(phase.receipt().owner_turn_accepts, 0)
            self.assertEqual(self.durable_phase(), journal.Phase.ACP_SENT)

    def test_journal_must_share_the_exact_proxy_fence(self):
        with self.session(activate=False, run_fence=RLock(), bind=False) as (phase, run, sent):
            with self.assertRaisesRegex(ProxyRefused, "journal run differs"):
                phase.bind_journal(run, sent, proxy_binding=self.proxy.binding, journal_binding=run._control.binding)
            self.assertEqual(phase.receipt().owner_turn_accepts, 0)
            self.assertEqual(self.durable_phase(), journal.Phase.ACP_SENT)

    def test_genuine_foreign_run_with_shared_fence_epoch_and_model_cannot_arm(self):
        with self.session(activate=False) as (phase, run, _):
            with TemporaryDirectory(prefix="oc-google-foreign-join-") as path, \
                    patch.object(registration, "_account_home", return_value=Path(path)):
                independent = journal.FixtureRegistrationJournal()
                anchor = provision(independent, self.addCleanup)
                ledger = journal.GenerationJournal(independent, anchor)
                binding = anchor.binding(epoch=run._control.binding.epoch, launch="b" * 32)
                with ledger.launch(binding, fence=self.fence, authorized=lambda value: value is binding,
                                   deadline=monotonic() + 10) as foreign:
                    foreign_sent = self.publish(foreign, journal.Operation.ACP)
                    self.assertEqual(binding.model, run._control.binding.model)
                    with self.assertRaisesRegex(ProxyRefused, "journal run or ACP sent receipt differs"):
                        phase.activate(foreign_sent, journal_run=foreign)
                    foreign.verify_acp_sent(foreign_sent)
            self.assertEqual(phase.receipt().owner_turn_accepts, 0)
            self.assertIs(phase.receipt().phase, generation_phase.Phase.HELD)
            self.assertEqual(self.durable_phase(), journal.Phase.ACP_SENT)

    def test_owned_but_already_claimed_or_settled_journal_cannot_arm(self):
        for settled in (False, True):
            # Use an independently provisioned fixture for each durable schedule.
            with self.subTest(settled=settled), TemporaryDirectory(prefix="oc-google-spent-join-") as path:
                self.home = Path(path)
                self.slot = (self.home / ".local/state/oc-sandbox/google" / journal._FIXTURE_DIR
                             / "registrations" / self.registration.label)
                with patch.object(registration, "_account_home", return_value=self.home), \
                        self.session(activate=False) as (phase, run, sent):
                    if settled:
                        self.publish(run, journal.Operation.DESTINATION)
                        expected = journal.Phase.DESTINATION_SETTLED
                    else:
                        run.issue(journal.Operation.DESTINATION)
                        expected = journal.Phase.DESTINATION_CLAIMED
                    with patch.object(generation_phase, "_send_once", wraps=generation_phase._send_once) as wire:
                        with self.assertRaises(journal.GenerationHeld):
                            phase.activate(sent, journal_run=run)
                    wire.assert_not_called()
                    self.assertEqual(phase.receipt().owner_turn_accepts, 0)
                    self.assertIs(phase.receipt().phase, generation_phase.Phase.HELD)
                    self.assertEqual(self.durable_phase(), expected)

    def test_stalled_arm_observer_does_not_block_revoke(self):
        with self.session(activate=False) as (phase, run, sent):
            observer = phase._verify_helper
            entered, resume = Event(), Event()

            def blocked(helper):
                self.assertFalse(self.fence._is_owned())
                entered.set()
                if not resume.wait(5):
                    raise AssertionError("the fixture did not release the arm observer")
                return observer(helper)

            with ThreadPoolExecutor(max_workers=2) as threads, \
                    patch.object(phase, "_verify_helper", side_effect=blocked), \
                    patch.object(generation_phase, "_send_once", wraps=generation_phase._send_once) as wire:
                arm = threads.submit(phase.activate, sent, journal_run=run)
                try:
                    self.assertTrue(entered.wait(1))
                    threads.submit(phase.revoke).result(timeout=1)
                finally:
                    resume.set()
                with self.assertRaises((ProxyRefused, journal.GenerationHeld)):
                    arm.result(timeout=2)
                wire.assert_not_called()
            self.assertEqual(self.durable_phase(), journal.Phase.ACP_SENT)
            self.assertIs(phase.receipt().phase, generation_phase.Phase.HELD)

    def test_same_ledger_copy_cannot_replace_the_exact_armed_run(self):
        with self.session() as (phase, run, _):
            sink = self.proxy.destination()
            with self.assertRaisesRegex(ProxyRefused, "journal run differs"):
                phase.serve_journal_turn(sink, copy(run))
            self.assertIsNone(sink.receipt())
            self.assertIs(phase.receipt().phase, generation_phase.Phase.HELD)
            self.assertEqual(self.durable_phase(), journal.Phase.ACP_SENT)

    def test_legacy_driver_cannot_bypass_an_armed_journal(self):
        with self.session() as (phase, _, _sent):
            sink = self.proxy.destination()
            with self.assertRaisesRegex(ProxyRefused, "destination claim is unavailable"):
                phase.serve_turn(sink, claim_destination=lambda *_: self.fail("legacy claim called"))
            self.assertIsNone(sink.receipt())
            self.assertEqual(self.durable_phase(), journal.Phase.ACP_SENT)

    def test_malformed_turn_does_not_charge_destination_claim(self):
        with self.session() as (phase, run, _):
            sink = self.proxy.destination()
            with ThreadPoolExecutor(max_workers=1) as runner:
                native = runner.submit(self.proxy.client, b"synthetic malformed wire")
                with self.assertRaises(generation.GenerationRefused):
                    phase.serve_journal_turn(sink, run)
                self.assertEqual(native.result(timeout=3), b"")
            self.assertIsNone(sink.receipt())
            self.assertEqual(self.durable_phase(), journal.Phase.ACP_SENT)

    def test_blocked_reply_observation_allows_immediate_shared_owner_revoke(self):
        with self.session() as (phase, run, _):
            sink = self.proxy.destination()
            original_read = sink.read
            entered, resume = Event(), Event()

            def blocked_read(*args, **kwargs):
                self.assertFalse(self.fence._is_owned())
                entered.set()
                if not resume.wait(5):
                    raise AssertionError("the fixture did not release its blocking observer")
                return original_read(*args, **kwargs)

            with ThreadPoolExecutor(max_workers=3) as runner, patch.object(sink, "read", side_effect=blocked_read):
                native = runner.submit(self.proxy.client, request())
                server = runner.submit(phase.serve_journal_turn, sink, run)
                try:
                    self.assertTrue(entered.wait(1))
                    self.assertEqual(self.durable_phase(), journal.Phase.DESTINATION_CLAIMED)
                    self.assertIsNotNone(sink.receipt())
                    runner.submit(phase.revoke).result(timeout=1)
                    self.assertEqual(native.result(timeout=1), b"")
                    with self.assertRaises(journal.GenerationHeld):
                        run.issue(journal.Operation.DESTINATION)
                finally:
                    resume.set()
                with self.assertRaises((ProxyRefused, journal.GenerationHeld)):
                    server.result(timeout=2)
            self.assertEqual(phase.receipt().fake_writes, 1)
            self.assertIs(phase.receipt().phase, generation_phase.Phase.HELD)
            self.assertEqual(self.durable_phase(), journal.Phase.DESTINATION_CLAIMED)

    def test_private_observation_cannot_publish_if_durable_settlement_fails(self):
        with self.session() as (phase, run, _):
            sink = self.proxy.destination()
            original_save = journal._Files.save
            attempted_settlement = Event()

            def fail_commit(files, next_phase, *args, **kwargs):
                if next_phase is journal.Phase.DESTINATION_SETTLED:
                    self.assertTrue(self.fence._is_owned())
                    self.assertTrue(sink.confirms_retirement(sink.receipt(), sink._retirement))
                    attempted_settlement.set()
                    raise OSError("synthetic durable settlement failure")
                return original_save(files, next_phase, *args, **kwargs)

            with ThreadPoolExecutor(max_workers=1) as runner:
                native = runner.submit(self.proxy.client, request())
                with patch.object(journal._Files, "save", new=fail_commit), \
                        patch.object(generation_phase, "_send_once", wraps=generation_phase._send_once) as native_send:
                    with self.assertRaises(ProxyRefused):
                        phase.serve_journal_turn(sink, run)
                native_send.assert_not_called()
                self.assertEqual(native.result(timeout=3), b"")
            self.assertTrue(attempted_settlement.is_set())
            self.assertEqual(phase.receipt().fake_writes, 1)
            self.assertEqual(self.durable_phase(), journal.Phase.DESTINATION_CLAIMED)
            self.assertIs(phase.receipt().phase, generation_phase.Phase.HELD)

    def test_successful_return_without_durable_settlement_cannot_publish(self):
        with self.session() as (phase, run, _):
            sink = self.proxy.destination()
            with ThreadPoolExecutor(max_workers=1) as runner:
                native = runner.submit(self.proxy.client, request())
                with patch.object(journal._Run, "settle", return_value=None) as ignored, \
                        patch.object(generation_phase, "_send_once", wraps=generation_phase._send_once) as native_send:
                    with self.assertRaises(journal.GenerationHeld):
                        phase.serve_journal_turn(sink, run)
                ignored.assert_called_once()
                native_send.assert_not_called()
                self.assertEqual(native.result(timeout=3), b"")
            self.assertTrue(sink.confirms_retirement(sink.receipt(), sink._retirement))
            self.assertIs(phase.receipt().phase, generation_phase.Phase.HELD)
            self.assertEqual(self.durable_phase(), journal.Phase.DESTINATION_CLAIMED)

    def revoking_owner_after_proof(self, run, ready):
        verify = journal._Run.verify_acp_sent
        owner = lambda binding: self.proxy.live and binding is self.proxy.binding
        proof_seen = False

        def observe(view, receipt):
            nonlocal proof_seen
            verify(view, receipt)
            proof_seen |= ready()

        def authorized(binding):
            if proof_seen:
                run.revoke()
            return owner(binding)

        return observe, authorized

    def test_last_phase_callback_revoking_d1_blocks_open_control_write(self):
        with self.session(activate=False) as (phase, run, sent):
            def ready():
                return bool(phase._turn.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN))

            observe, authorized = self.revoking_owner_after_proof(run, ready)
            with patch.object(journal._Run, "verify_acp_sent", new=observe), \
                    patch.object(phase, "_authorized", side_effect=authorized), \
                    patch.object(generation_phase, "_send_once", wraps=generation_phase._send_once) as wire, \
                    patch.object(generation_proxy, "_send_once", wraps=generation_proxy._send_once) as legacy_wire:
                with self.assertRaises(journal.GenerationHeld):
                    phase.activate(sent, journal_run=run)
            wire.assert_not_called()
            legacy_wire.assert_not_called()
            self.assertEqual(self.durable_phase(), journal.Phase.ACP_SENT)
            self.assertIs(phase.receipt().phase, generation_phase.Phase.HELD)

    def test_last_phase_callback_revoking_d1_blocks_native_reply(self):
        with self.session() as (phase, run, _):
            sink = self.proxy.destination()
            observe, authorized = self.revoking_owner_after_proof(
                run, lambda: self.durable_phase() is journal.Phase.DESTINATION_SETTLED,
            )
            with ThreadPoolExecutor(max_workers=1) as threads:
                native = threads.submit(self.proxy.client, request())
                with patch.object(journal._Run, "verify_acp_sent", new=observe), \
                        patch.object(phase, "_authorized", side_effect=authorized), \
                        patch.object(generation_phase, "_send_once", wraps=generation_phase._send_once) as wire:
                    with self.assertRaises(journal.GenerationHeld):
                        phase.serve_journal_turn(sink, run)
                self.assertEqual(native.result(timeout=3), b"")
            wire.assert_not_called()
            self.assertEqual(self.durable_phase(), journal.Phase.DESTINATION_SETTLED)
            self.assertEqual(phase.receipt().fake_writes, 1)
            self.assertIs(phase.receipt().phase, generation_phase.Phase.HELD)

    def test_last_phase_callback_revoking_d1_blocks_fake_write(self):
        with self.session() as (phase, run, _):
            sink = self.proxy.destination()
            sink_entered = False
            sink_proof_checks = 0
            actual_write = sink.write

            def write(*args, **kwargs):
                nonlocal sink_entered
                sink_entered = True
                return actual_write(*args, **kwargs)

            def final_admit():
                nonlocal sink_proof_checks
                if sink_entered:
                    sink_proof_checks += 1
                # The split sink checks current scope twice, then calls the
                # joined journal admission check immediately before accepting.
                return sink_proof_checks == 3

            observe, authorized = self.revoking_owner_after_proof(run, final_admit)
            with ThreadPoolExecutor(max_workers=1) as threads:
                native = threads.submit(self.proxy.client, request())
                with patch.object(journal._Run, "verify_acp_sent", new=observe), \
                        patch.object(phase, "_authorized", side_effect=authorized), \
                        patch.object(sink, "write", side_effect=write):
                    with self.assertRaises(journal.GenerationHeld):
                        phase.serve_journal_turn(sink, run)
                self.assertEqual(native.result(timeout=3), b"")
            self.assertTrue(sink_entered)
            self.assertEqual(sink_proof_checks, 3)
            self.assertIsNone(sink.receipt())
            self.assertEqual(self.durable_phase(), journal.Phase.DESTINATION_CLAIMED)
            self.assertIs(phase.receipt().phase, generation_phase.Phase.HELD)

    def lose_proxy_owner_in_d1(self, ready, *, check_number=1):
        checks = 0
        triggered = Event()

        def observe():
            nonlocal checks
            if ready():
                checks += 1
                if checks == check_number:
                    self.proxy.live = False
                    triggered.set()

        self.journal_observer = observe
        return triggered

    def test_last_d1_callback_retiring_proxy_blocks_open_control_write(self):
        with self.session(activate=False, expect_success=None) as (phase, run, sent):
            triggered = self.lose_proxy_owner_in_d1(
                lambda: bool(phase._turn.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)),
            )
            with patch.object(generation_phase, "_send_once", wraps=generation_phase._send_once) as wire:
                with self.assertRaises(ProxyRefused):
                    phase.activate(sent, journal_run=run)
            self.assertTrue(triggered.is_set())
            wire.assert_not_called()
            self.assertEqual(self.durable_phase(), journal.Phase.ACP_SENT)
            self.assertIs(phase.receipt().phase, generation_phase.Phase.HELD)

    def test_last_d1_callback_retiring_proxy_blocks_fake_write(self):
        with self.session(expect_success=None) as (phase, run, _):
            sink = self.proxy.destination()
            verify = journal._Run.verify_in_flight
            checking_destination = False
            triggered = self.lose_proxy_owner_in_d1(lambda: checking_destination)

            def track_in_flight(view, proof, operation):
                nonlocal checking_destination
                self.assertIs(operation, journal.Operation.DESTINATION)
                checking_destination = True
                try:
                    return verify(view, proof, operation)
                finally:
                    checking_destination = False

            with ThreadPoolExecutor(max_workers=1) as threads:
                native = threads.submit(self.proxy.client, request())
                with patch.object(journal._Run, "verify_in_flight", new=track_in_flight):
                    with self.assertRaises(ProxyRefused):
                        phase.serve_journal_turn(sink, run)
                self.assertEqual(native.result(timeout=3), b"")
            self.assertTrue(triggered.is_set())
            self.assertIsNone(sink.receipt())
            self.assertEqual(phase.receipt().fake_writes, 0)
            self.assertEqual(self.durable_phase(), journal.Phase.DESTINATION_CLAIMED)
            self.assertIs(phase.receipt().phase, generation_phase.Phase.HELD)

    def test_last_d1_callback_retiring_proxy_blocks_native_reply(self):
        with self.session(expect_success=None) as (phase, run, _):
            sink = self.proxy.destination()
            checking_reply = False
            actual_send = phase._send_turn_reply
            triggered = self.lose_proxy_owner_in_d1(lambda: checking_reply)

            def send_reply(connection, reply, deadline, *, check, observe):
                def check_reply():
                    nonlocal checking_reply
                    checking_reply = True
                    try:
                        check()
                    finally:
                        checking_reply = False

                return actual_send(connection, reply, deadline, check=check_reply, observe=observe)

            with ThreadPoolExecutor(max_workers=1) as threads:
                native = threads.submit(self.proxy.client, request())
                with patch.object(phase, "_send_turn_reply", new=send_reply), \
                        patch.object(generation_phase, "_send_once", wraps=generation_phase._send_once) as wire:
                    with self.assertRaises(ProxyRefused):
                        phase.serve_journal_turn(sink, run)
                self.assertEqual(native.result(timeout=3), b"")
            self.assertTrue(triggered.is_set())
            wire.assert_not_called()
            self.assertTrue(sink.confirms_retirement(sink.receipt(), sink._retirement))
            self.assertEqual(self.durable_phase(), journal.Phase.DESTINATION_SETTLED)
            self.assertEqual(phase.receipt().fake_writes, 1)
            self.assertIs(phase.receipt().phase, generation_phase.Phase.HELD)

    def test_interruption_after_claim_and_before_fake_write_is_held(self):
        with self.session() as (phase, run, _):
            sink = self.proxy.destination()

            def interruption(*args, **kwargs):
                self.assertEqual(self.durable_phase(), journal.Phase.DESTINATION_CLAIMED)
                raise InterruptedError("synthetic write interruption")

            with ThreadPoolExecutor(max_workers=1) as runner:
                native = runner.submit(self.proxy.client, request())
                with patch.object(sink, "write", side_effect=interruption) as write:
                    with self.assertRaises(ProxyRefused):
                        phase.serve_journal_turn(sink, run)
                self.assertEqual(native.result(timeout=3), b"")
            write.assert_called_once()
            self.assertIsNone(sink.receipt())
            self.assertEqual(phase.receipt().fake_writes, 0)
            self.assertEqual(self.durable_phase(), journal.Phase.DESTINATION_CLAIMED)
