"""Exercise the joined synthetic delivery with actual disposable pipes and sockets."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, suppress
from copy import copy, deepcopy
from dataclasses import replace
from hashlib import sha256
import os
from pathlib import Path
import socket
import subprocess
import sys
from threading import Event, RLock
from time import monotonic
import unittest
from unittest.mock import patch

from oc_google import generation_delivery as delivery
from oc_google import generation_journal as journal
from oc_google import generation_phase as proxy
from oc_google import worker_channel as channel
from oc_google.native_generation_transcript import (
    GenerationTranscript, NaturalExitReceipt, TranscriptUnavailable, UnitRetirementReceipt,
)
from oc_google.native_service import NativeInvocation
from oc_orchestrator import protocol

import test_google_generation_journal as journal_fixture
import test_google_native_generation_transcript as transcript_fixture
import test_google_worker_channel as worker_fixture


class JoinedDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.journal = journal_fixture.GenerationJournalTests()
        self.addCleanup(self.journal.doCleanups)
        self.journal.setUp()
        self.worker = worker_fixture.WorkerChannelTest()
        self.addCleanup(self.worker.doCleanups)
        self.worker.setUp()
        self.worker.fence = self.journal.fence
        binding = self.journal.binding
        self.delivery_owner = journal._DeliveryOwner(binding, self.journal.fence)
        with patch.object(worker_fixture, "MODEL", binding.model):
            self.channel, self.relay, self.client, self.control, _ = self.worker.fixture(
                distinct_worker=True, delivery_owner=self.delivery_owner,
            )
        self.adoption, self.relay_retirement = self.worker.seal(self.channel, self.relay, self.control)
        self.packet = protocol.text_reply_bytes(binding.model)
        self.before_authority = self.after_authority = None

    def provision_native(self, *, mode="ok", prove_exit=True, settle_destination=True, monitor_worker=True,
                         monitor_channel_owner=True):
        wire = transcript_fixture.update("ok") + transcript_fixture.terminal()
        child = subprocess.Popen(
            [sys.executable, "-IBS", "-c", transcript_fixture._PEER, wire.hex(), mode], bufsize=0,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        self.addCleanup(transcript_fixture.cleanup_child, child)
        pidfd = os.pidfd_open(child.pid)
        self.addCleanup(os.close, pidfd)
        self.invocation = NativeInvocation("fixture.service", "a" * 32, b"/fixture.service", child.pid)
        fence = self.journal.fence

        def authorized(binding):
            if self.before_authority is not None:
                self.before_authority()
            current = (binding is self.journal.current and (not monitor_channel_owner or self.worker.owner)
                       and (not monitor_worker or self.worker.placement.worker.alive()))
            if self.after_authority is not None:
                self.after_authority()
            return current

        self.run_lease = self.enterContext(self.journal.journal.launch(
            self.journal.binding, fence=fence, authorized=authorized, deadline=monotonic() + 10,
            delivery_owner=self.delivery_owner,
        ))
        self.transcript = self.enterContext(GenerationTranscript(
            child.stdin, child.stdout, invocation=self.invocation, pidfd=pidfd,
            session_id=transcript_fixture._SESSION, deadline=monotonic() + 5, fence=fence,
            authorized=lambda: authorized(self.journal.binding),
        ))
        command = b"synthetic prompt\n"
        cap = self.run_lease.issue(journal.Operation.ACP)
        digest = sha256(command).hexdigest()

        def write_prompt(proof):
            self.run_lease.verify_in_flight(proof, journal.Operation.ACP)
            self.prior_acp_proof = proof
            return journal.WriteEvidence(self.invocation, os.write(child.stdin.fileno(), command), digest)

        acp = self.run_lease.write_once(cap, write_prompt, target=self.invocation, data=command)
        self.run_lease.settle(acp, journal.SettlementEvidence(acp, self.invocation, len(command), digest))
        sent = self.run_lease.acp_sent()
        if settle_destination:
            receipt, observation = self.journal.split_write(self.run_lease, self.run_lease.issue(journal.Operation.DESTINATION))
            self.run_lease.settle(receipt, observation)
        self.proxy_retirement = delivery.ProxyRetirementObservation(
            sent, self.invocation, proxy.PhaseReceipt(proxy.Phase.COMPLETE, 3, 1, 1, 1, False, True),
        )
        self.native_retirement = UnitRetirementReceipt(self.invocation, True, True)
        self.transcript.read_to_eof()
        if prove_exit:
            self.transcript.attest_exit(lambda invocation, _: NaturalExitReceipt(
                invocation, os.CLD_EXITED, child.wait(timeout=2), 0, True,
            ))

    def deliver(self, **overrides):
        parameters = dict(adopted=self.adoption, relay_retirement=self.relay_retirement, transcript=self.transcript,
                          native_retirement=self.native_retirement, proxy_retirement=self.proxy_retirement)
        return delivery.deliver_worker(self.run_lease, self.channel, **(parameters | overrides))

    def test_caller_holding_shared_fence_cannot_start_delivery_and_can_retry_after_release(self):
        self.provision_native()
        retained = self.channel._client
        with (patch.object(self.transcript, "finish", wraps=self.transcript.finish) as finish,
              patch.object(self.channel, "prepare_delivery", wraps=self.channel.prepare_delivery) as prepare,
              patch.object(channel, "_send_once", wraps=channel._send_once) as once):
            with self.journal.fence, self.assertRaises(channel.WorkerChannelError) as refusal:
                self.deliver()
            once.assert_not_called()
            finish.assert_not_called()
            prepare.assert_not_called()
            self.assertEqual(str(refusal.exception), "Joined worker delivery requires the owner fence to be released")
            self.assertEqual(self.journal.phase(), journal.Phase.DESTINATION_SETTLED)
            self.assertIs(self.channel._client, retained)
            self.assertFalse(self.channel.delivery.attempted)

            self.assertEqual(self.deliver(), channel.DeliveryReceipt(True, len(self.packet), True))
            once.assert_called_once()
            finish.assert_called_once()
            prepare.assert_called_once()
        self.assertEqual(self.journal.phase(), journal.Phase.SETTLED)
        self.assertEqual(self.worker.read_all(self.client), self.packet)
        self.assertEqual(retained.fileno(), -1)

    def test_exact_observations_one_real_send_and_verified_close_settle_delivery(self):
        self.provision_native()
        phases = []
        send = channel._send_once
        close = self.channel.close_written
        check_worker = self.worker.check_worker.side_effect

        def observe_worker(placement):
            self.assertFalse(self.journal.fence._is_owned())
            return check_worker(placement)

        def write(sock, data):
            phases.append(self.journal.phase())
            self.assertEqual(data, self.packet)
            return send(sock, data)

        def close_written(prepared, receipt):
            self.assertFalse(self.journal.fence._is_owned())
            self.assertEqual(self.journal.phase(), journal.Phase.DELIVERY_CLAIMED)
            return close(prepared, receipt)

        with (patch.object(channel, "_send_once", side_effect=write) as send_once,
              patch.object(self.channel, "close_written", side_effect=close_written),
              patch.object(self.worker.check_worker, "side_effect", observe_worker)):
            self.assertEqual(self.deliver(), channel.DeliveryReceipt(True, len(self.packet), True))
            send_once.assert_called_once()
        self.worker.claim.assert_not_called()
        self.assertEqual(phases, [journal.Phase.DELIVERY_CLAIMED])
        self.assertEqual(self.worker.read_all(self.client), self.packet)
        self.assertEqual(self.journal.phase(), journal.Phase.SETTLED)
        self.assertIsNone(self.channel._client)
        with self.assertRaises((journal.GenerationHeld, channel.WorkerChannelError)):
            self.deliver()

    def test_partial_send_cannot_settle_or_retry_even_with_later_cleanup(self):
        self.provision_native()
        send = channel._send_once
        with patch.object(channel, "_send_once", side_effect=lambda sock, data: send(sock, data[:10])) as once:
            with self.assertRaisesRegex(channel.WorkerChannelError, "incomplete"):
                self.deliver()
            with self.assertRaises(journal.GenerationHeld):
                self.deliver()
            once.assert_called_once()
        self.assertEqual(self.worker.read_all(self.client), self.packet[:10])
        self.assertEqual(self.journal.phase(), journal.Phase.DELIVERY_CLAIMED)

    def test_unconfirmed_channel_close_holds_after_one_complete_send(self):
        self.provision_native()
        with (patch.object(self.channel, "close_written", side_effect=OSError("synthetic close failed")),
              patch.object(channel, "_send_once", wraps=channel._send_once) as once):
            with self.assertRaises(OSError):
                self.deliver()
            with self.assertRaises(journal.GenerationHeld):
                self.deliver()
            once.assert_called_once()
        self.assertEqual(self.worker.read_all(self.client), self.packet)
        self.assertEqual(self.journal.phase(), journal.Phase.DELIVERY_CLAIMED)

    def test_replacement_after_send_is_neither_closed_nor_counted_as_closure(self):
        self.provision_native()
        sibling = self.enterContext(socket.create_connection(("127.0.0.1", self.worker.port), timeout=3))
        replacement, _ = self.worker.local_listener.accept()
        send = channel._send_once
        fd = self.channel._client.fileno()
        with replacement:
            def write(sock, data):
                sent = send(sock, data)
                os.dup2(replacement.fileno(), fd, inheritable=False)
                return sent

            try:
                with patch.object(channel, "_send_once", side_effect=write) as once:
                    with self.assertRaisesRegex(channel.WorkerChannelError, "changed at closure"):
                        self.deliver()
                    once.assert_called_once()
                self.assertTrue(os.path.samestat(os.fstat(fd), os.fstat(replacement.fileno())))
                sibling.sendall(b"x")
                self.assertEqual(replacement.recv(1), b"x")
            finally:
                with suppress(OSError):
                    os.close(fd)
        self.assertEqual(self.worker.read_all(self.client), self.packet)
        self.assertEqual(self.journal.phase(), journal.Phase.DELIVERY_CLAIMED)

    def assert_prepare_namespace_loss(self, kind):
        self.provision_native()
        moved = False
        pid = self.worker.worker_proc.pid
        namespace_path = f"/proc/{pid}/ns/{kind}"
        alternate_kind = "mnt" if kind == "net" else "net"
        alternate = f"/proc/{pid}/ns/{alternate_kind}"
        original_open, identity = os.open, channel._proc_ns_identity

        def owner():
            nonlocal moved
            if self.channel._phase is channel._Phase.PREPARING:
                moved = True
            return True

        def sample(process, namespace):
            return identity(process, alternate_kind if moved and process == pid and namespace == kind else namespace)

        def open_namespace(path, *args, **kwargs):
            # On the earlier revision, the replacement observation and open
            # must agree so prepare would mistake it for the original pin.
            return original_open(alternate if moved and path == namespace_path else path, *args, **kwargs)

        with (patch.object(self.channel, "_owner_current", owner),
              patch.object(channel, "_proc_ns_identity", sample),
              patch.object(os, "open", open_namespace),
              patch.object(channel, "_send_once", wraps=channel._send_once) as once):
            with self.assertRaisesRegex(channel.WorkerChannelError, "placement is no longer current"):
                self.deliver()
            once.assert_not_called()
        self.assertTrue(moved)
        self.assertIsNone(self.worker.worker_proc.poll())
        self.assertEqual(self.worker.read_all(self.client), b"")
        self.assertEqual(self.journal.phase(), journal.Phase.DESTINATION_SETTLED)

    def test_prepare_callback_cannot_rebaseline_original_network_namespace(self):
        self.assert_prepare_namespace_loss("net")

    def test_prepare_callback_cannot_rebaseline_original_mount_namespace(self):
        self.assert_prepare_namespace_loss("mnt")

    def new_adoption(self):
        worker = worker_fixture.WorkerChannelTest()
        self.addCleanup(worker.doCleanups)
        worker.setUp()
        worker.fence = self.journal.fence
        binding = self.journal.binding
        owner = journal._DeliveryOwner(binding, worker.fence)
        with patch.object(worker_fixture, "MODEL", binding.model):
            retained, relay, client, control, _ = worker.fixture(distinct_worker=True, delivery_owner=owner)
        return worker, retained, relay, client, control

    def test_namespace_reference_requires_actual_creating_probe(self):
        worker, retained, _, _, _ = self.new_adoption()
        worker_pin = worker.placement.worker
        another_process = self.worker.placement.worker
        reference = retained._placement.reference
        with ExitStack() as resources:
            with self.assertRaisesRegex(channel.WorkerChannelError, "namespace probe is unavailable"):
                channel.WorkerNamespaceReference.from_verified_probe(
                    worker=worker_pin, probe=another_process, resources=resources,
                    worker_id=reference.worker_id, run=reference.run, epoch=reference.epoch, probe_id=reference.probe_id,
                )

    def test_worker_placement_drift_after_probe_prevents_adoption(self):
        worker, retained, _, client, control = self.new_adoption()
        observed = 0
        proc_identity = channel._proc_ns_identity

        def observe(placement):
            nonlocal observed
            observed += 1
            return placement is worker.placement

        def sample(pid, kind):
            device, inode = proc_identity(pid, kind)
            drift = pid == worker.worker_proc.pid and kind == "mnt" and observed == 3
            return device, inode + drift

        with patch.object(worker.check_worker, "side_effect", observe), patch.object(channel, "_proc_ns_identity", sample):
            with self.assertRaisesRegex(channel.WorkerChannelError, "placement is no longer current"):
                retained.adopt(control)
        self.assertEqual(observed, 3)
        self.assertIsNone(retained._adopted)
        self.assertEqual(worker.read_all(client), b"")

    def test_foreign_probe_cannot_replace_original_even_in_same_namespace(self):
        worker, retained, _, client, control = self.new_adoption()
        original = retained._placement.reference
        foreign = self.channel._placement.reference
        self.assertEqual(original.cookie, foreign.cookie)
        self.assertIsNot(original, foreign)
        observed = 0

        def observe(placement):
            nonlocal observed
            observed += 1
            if observed == 3:
                retained._placement = replace(placement, reference=foreign)
            return True

        with patch.object(worker.check_worker, "side_effect", observe):
            with self.assertRaisesRegex(channel.WorkerChannelError, "placement is no longer current"):
                retained.adopt(control)
        self.assertEqual(observed, 3)
        self.assertIsNone(retained._adopted)
        self.assertEqual(worker.read_all(client), b"")

    def test_foreign_owner_on_same_fence_cannot_claim_worker_delivery(self):
        self.provision_native()
        unrelated = journal._DeliveryOwner(self.journal.binding, self.journal.fence)
        with patch.object(self.channel, "_delivery_owner", unrelated):
            with self.assertRaisesRegex(channel.WorkerChannelError, "journal is unavailable"):
                self.deliver()
        self.assertEqual(self.journal.phase(), journal.Phase.DESTINATION_SETTLED)
        self.assertFalse(self.channel.delivery.attempted)

    def test_channel_observation_cannot_send_after_revoking_journal(self):
        self.provision_native()
        invalidated = False

        def observe():
            nonlocal invalidated
            if self.channel._phase is channel._Phase.SPENT:
                self.run_lease.revoke()
                invalidated = True
            return True

        with (patch.object(self.channel, "_owner_current", observe),
              patch.object(channel, "_send_once", wraps=channel._send_once) as once):
            with self.assertRaises(journal.GenerationHeld):
                self.deliver()
            once.assert_not_called()
        self.assertTrue(invalidated)
        self.assertEqual(self.journal.phase(), journal.Phase.DELIVERY_CLAIMED)
        self.assertEqual(self.worker.read_all(self.client), b"")

    def make_channel_from_used_pin(self, owner):
        source = self.channel
        return channel.RetainedWorkerChannel(
            source._placement, port=source._port, model=source._model, system_digest=source._system_digest,
            worker_token=source._worker_token, proof=source._proof, fence=source._fence,
            owner_current=source._owner_current, worker_current=source._worker_current,
            retirement_current=source._retirement_current, claim_delivery=source._claim_delivery,
            delivery_owner=owner,
        )

    def test_original_placement_cannot_be_copied_reused_or_downgraded(self):
        reference = self.channel._placement.reference
        for pin in (reference, reference._adoption):
            for clone in (copy, deepcopy):
                with self.assertRaises(TypeError):
                    clone(pin)
        with self.assertRaisesRegex(channel.WorkerChannelError, "placement was already spent"):
            self.make_channel_from_used_pin(journal._DeliveryOwner(self.journal.binding, self.journal.fence))
        with self.assertRaisesRegex(channel.WorkerChannelError, "joined worker authority is unavailable"):
            self.make_channel_from_used_pin(None)

    def test_failed_adoption_releases_owned_namespace_fds_immediately(self):
        worker, retained, _, _, control = self.new_adoption()
        placement = retained._placement.reference._adoption
        fds = (placement.network[0], placement.mount[0])
        with patch.object(worker.check_worker, "side_effect", lambda _: False):
            with self.assertRaises(channel.WorkerChannelError):
                retained.adopt(control)
        for fd in fds:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_placement_cleanup_does_not_close_foreign_reused_descriptor(self):
        placement = self.channel._placement.reference._adoption
        fd = placement.network[0]
        foreign = os.open(self.worker.root, os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.dup2(foreign, fd, inheritable=False)
            self.channel.revoke()
            self.assertTrue(os.path.samestat(os.fstat(fd), os.fstat(foreign)))
        finally:
            os.close(fd)
            os.close(foreign)

    def test_terminal_delivery_releases_owned_namespace_fds_immediately(self):
        placement = self.channel._placement.reference._adoption
        fds = (placement.network[0], placement.mount[0])
        self.provision_native()
        self.assertTrue(self.deliver().complete)
        for fd in fds:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def assert_revoke_during_placement_observation(self, stage):
        worker, retained, relay, client, control = self.new_adoption()
        entered, resume, revoked = Event(), Event(), Event()
        observed_under_fence = []

        def pause(_):
            observed_under_fence.append(self.journal.fence._is_owned())
            entered.set()
            if not resume.wait(timeout=5):
                self.fail("placement observer did not resume")
            return True

        if stage == "adopt":
            observer = worker.check_worker
            operation = lambda: retained.adopt(control)
        else:
            adopted = retained.adopt(control)
            retained.close_admission()
            self.assertEqual(worker.stop(relay), 0)
            receipt = channel.RelayRetirement(adopted, worker_fixture.RELAY_ID)
            observer = worker.check_retirement if stage == "retirement" else worker.check_worker
            if stage == "seal":
                worker.genuine_retirement = receipt
            operation = lambda: retained.seal(receipt)

        def revoke():
            retained.revoke()
            revoked.set()

        with ThreadPoolExecutor(max_workers=2) as threads, patch.object(observer, "side_effect", pause):
            attempt = threads.submit(operation)
            try:
                self.assertTrue(entered.wait(timeout=2))
                revoker = threads.submit(revoke)
                self.assertTrue(revoked.wait(timeout=1), "placement observer blocked the revoker")
            finally:
                resume.set()
            revoker.result(timeout=2)
            with self.assertRaises((journal.GenerationHeld, channel.WorkerChannelError)):
                attempt.result(timeout=2)
        self.assertEqual(observed_under_fence, [False])
        self.assertEqual(worker.read_all(client), b"")
        self.assertIsNone(retained._retirement)

    def test_revocation_can_finish_during_joined_adoption_observer(self):
        self.assert_revoke_during_placement_observation("adopt")

    def test_revocation_can_finish_during_joined_seal_worker_observer(self):
        self.assert_revoke_during_placement_observation("seal")

    def test_revocation_can_finish_during_joined_retirement_observer(self):
        self.assert_revoke_during_placement_observation("retirement")

    def test_joined_journal_cannot_claim_delivery_before_channel_prepares_exact_plan(self):
        self.provision_native()
        with self.assertRaises(journal.GenerationHeld):
            self.run_lease.issue(journal.Operation.DELIVERY)
        self.assertEqual(self.journal.phase(), journal.Phase.DESTINATION_SETTLED)

    def test_joined_channel_refuses_legacy_entry_before_any_prepare(self):
        with patch.object(channel, "_send_once", wraps=channel._send_once) as once:
            with self.assertRaises(channel.WorkerChannelError):
                self.channel.deliver()
            once.assert_not_called()
        self.worker.claim.assert_not_called()

    def lose_joined_owner(self):
        self.worker.owner = False
        self.delivery_owner.revoke()

    def test_final_journal_proof_cannot_send_after_channel_owner_loss(self):
        self.provision_native(monitor_channel_owner=False)
        checking = False
        observed = Event()
        verify = journal._Run.verify_in_flight

        def verify_effect(run, proof, operation, **kwargs):
            nonlocal checking
            checking = operation is journal.Operation.DELIVERY
            try:
                return verify(run, proof, operation, **kwargs)
            finally:
                checking = False

        def invalidate():
            if checking and not observed.is_set():
                self.lose_joined_owner()
                observed.set()

        self.after_authority = invalidate
        with (patch.object(journal._Run, "verify_in_flight", new=verify_effect),
              patch.object(channel, "_send_once", wraps=channel._send_once) as once):
            with self.assertRaises((journal.GenerationHeld, channel.WorkerChannelError)):
                self.deliver()
            once.assert_not_called()
        self.assertTrue(observed.is_set())
        self.assertEqual(self.worker.read_all(self.client), b"")
        self.assertEqual(self.journal.phase(), journal.Phase.DELIVERY_CLAIMED)

    def assert_owner_loss_during_save(self, barrier):
        self.provision_native(monitor_channel_owner=False)
        save = journal._Files.save
        checking = False
        checks = 0

        def settle(files, phase, binding, check):
            nonlocal checking
            if phase is journal.Phase.SETTLED:
                checking = True
            return save(files, phase, binding, check)

        def invalidate():
            nonlocal checks
            if checking:
                checks += 1
                if checks == barrier:
                    self.lose_joined_owner()

        self.after_authority = invalidate
        with (patch.object(journal._Files, "save", settle),
              patch.object(channel, "_send_once", wraps=channel._send_once) as once):
            with self.assertRaises((journal.GenerationHeld, channel.WorkerChannelError)):
                self.deliver()
            self.assertEqual(checks, barrier)
            self.assertIs(self.run_lease._files._authority.phase, journal.Phase.DELIVERY_CLAIMED)
            if barrier >= 3:
                self.assertEqual(self.journal.phase(), journal.Phase.SETTLED)
            if barrier >= 2:
                self.assertEqual((self.journal.slot / journal._LATCH).read_bytes(), journal._DIRTY)
            self.worker.owner = True
            self.after_authority = None
            with self.assertRaises((journal.GenerationHeld, channel.WorkerChannelError)):
                self.deliver()
            once.assert_called_once()
        self.assertEqual(self.worker.read_all(self.client), self.packet)

    def test_owner_loss_at_settlement_save_entry(self):
        self.assert_owner_loss_during_save(1)

    def test_owner_loss_after_settlement_candidate_is_synced(self):
        self.assert_owner_loss_during_save(2)

    def test_owner_loss_after_settlement_record_replacement(self):
        self.assert_owner_loss_during_save(3)

    def test_owner_loss_after_settlement_latch_sync(self):
        self.assert_owner_loss_during_save(4)

    def test_owner_loss_after_settlement_save_returns(self):
        self.assert_owner_loss_during_save(5)

    def assert_revoke_after_send_before_closer(self, method):
        self.provision_native()
        retained = self.channel._client
        gap, after_gap, closing, finish, revoked = (Event() for _ in range(5))
        actual = getattr(socket.socket, method)
        operations = []

        def skip_normal_closer(prepared, receipt):
            self.assertTrue(receipt.complete)
            gap.set()
            if not after_gap.wait(timeout=5):
                self.fail("delivery did not leave the post-send gap")
            raise OSError("synthetic interruption before normal closer")

        def pause(sock, *args):
            if sock is retained:
                operations.append(self.journal.fence._is_owned())
                closing.set()
                if not finish.wait(timeout=5):
                    self.fail("reserved cleanup did not resume")
            return actual(sock, *args)

        def revoke():
            self.channel.revoke()
            revoked.set()

        with (ThreadPoolExecutor(max_workers=2) as threads,
              patch.object(self.channel, "close_written", side_effect=skip_normal_closer),
              patch.object(socket.socket, method, new=pause),
              patch.object(channel, "_send_once", wraps=channel._send_once) as once):
            result = threads.submit(self.deliver)
            try:
                self.assertTrue(gap.wait(timeout=2))
                threads.submit(revoke)
                self.assertTrue(revoked.wait(timeout=1), "revoker tried to close the completed socket")
                self.assertFalse(closing.is_set())
                after_gap.set()
                self.assertTrue(closing.wait(timeout=2))
                threads.submit(self.channel.revoke).result(timeout=1)
            finally:
                after_gap.set()
                finish.set()
            with self.assertRaisesRegex(OSError, "interruption before normal closer"):
                result.result(timeout=2)
            once.assert_called_once()
        self.assertEqual(operations, [False])
        self.assertEqual(retained.fileno(), -1)
        self.assertIsNone(self.channel._closed_write)
        self.assertEqual(self.journal.phase(), journal.Phase.DELIVERY_CLAIMED)
        self.assertEqual(self.worker.read_all(self.client), self.packet)

    def test_post_send_revocation_does_not_block_on_actual_shutdown(self):
        self.assert_revoke_after_send_before_closer("shutdown")

    def test_post_send_revocation_does_not_block_on_actual_close(self):
        self.assert_revoke_after_send_before_closer("close")

    def test_journal_failure_after_complete_send_discards_reserved_socket(self):
        self.provision_native()
        retained = self.channel._client
        actual_shutdown = socket.socket.shutdown
        verify = journal._Run._check_phase
        observed = []

        def fail_after_send(run, phase):
            if phase is journal.Phase.DELIVERY_CLAIMED and self.channel.delivery.complete:
                raise journal.GenerationHeld()
            return verify(run, phase)

        def observe_shutdown(sock, *args):
            if sock is retained:
                observed.append(self.journal.fence._is_owned())
            return actual_shutdown(sock, *args)

        with (patch.object(journal._Run, "_check_phase", new=fail_after_send),
              patch.object(socket.socket, "shutdown", new=observe_shutdown),
              patch.object(self.channel, "close_written", wraps=self.channel.close_written) as closer,
              self.assertRaises(journal.GenerationHeld)):
            self.deliver()
        closer.assert_not_called()
        self.assertEqual(observed, [False])
        self.assertEqual(retained.fileno(), -1)
        self.assertIsNone(self.channel._closed_write)
        self.assertEqual(self.journal.phase(), journal.Phase.DELIVERY_CLAIMED)
        self.assertEqual(self.worker.read_all(self.client), self.packet)

    def assert_real_close_operation_failure(self, method):
        self.provision_native()
        retained = self.channel._client
        actual = getattr(socket.socket, method)
        operations = []

        def fail_original(sock, *args):
            if sock is retained:
                operations.append(self.journal.fence._is_owned())
                if method == "close":
                    actual(sock, *args)
                raise OSError("synthetic socket syscall failure")
            return actual(sock, *args)

        with (patch.object(socket.socket, method, new=fail_original),
              patch.object(channel, "_send_once", wraps=channel._send_once) as once):
            with self.assertRaisesRegex(OSError, "socket syscall failure"):
                self.deliver()
            once.assert_called_once()
        self.assertEqual(operations, [False])
        self.assertEqual(retained.fileno(), -1)
        self.assertIsNone(self.channel._closed_write)
        self.assertEqual(self.journal.phase(), journal.Phase.DELIVERY_CLAIMED)
        self.assertEqual(self.worker.read_all(self.client), self.packet)

    def test_actual_shutdown_failure_cannot_mint_closure(self):
        self.assert_real_close_operation_failure("shutdown")

    def test_actual_close_failure_cannot_mint_closure(self):
        self.assert_real_close_operation_failure("close")

    def test_close_written_refuses_caller_who_keeps_shared_fence(self):
        self.provision_native()
        close = self.channel.close_written

        def verify_and_close(prepared, receipt):
            with self.journal.fence, self.assertRaisesRegex(channel.WorkerChannelError, "fence to be released"):
                close(prepared, receipt)
            return close(prepared, receipt)

        with patch.object(self.channel, "close_written", verify_and_close):
            self.assertTrue(self.deliver().complete)
        self.assertEqual(self.journal.phase(), journal.Phase.SETTLED)
        self.assertEqual(self.worker.read_all(self.client), self.packet)

    def assert_revoke_during_closure(self, method):
        self.provision_native()
        retained = self.channel._client
        entered, resume, revoked = Event(), Event(), Event()
        actual = getattr(socket.socket, method)
        operations = []

        def pause(sock, *args):
            if sock is retained:
                operations.append(self.journal.fence._is_owned())
                entered.set()
                if not resume.wait(timeout=5):
                    self.fail("closure did not resume")
            return actual(sock, *args)

        def revoke():
            self.channel.revoke()
            revoked.set()

        def duplicate():
            return self.channel.close_written(self.channel._prepared, self.channel._delivery)

        with (ThreadPoolExecutor(max_workers=2) as threads,
              patch.object(socket.socket, method, new=pause),
              patch.object(channel, "_send_once", wraps=channel._send_once) as once):
            result = threads.submit(self.deliver)
            try:
                self.assertTrue(entered.wait(timeout=2))
                retirement = threads.submit(revoke)
                self.assertTrue(revoked.wait(timeout=1), "actual socket closure blocked the revoker")
                with self.assertRaises(channel.WorkerChannelError):
                    threads.submit(duplicate).result(timeout=2)
            finally:
                resume.set()
            retirement.result(timeout=2)
            with self.assertRaises((journal.GenerationHeld, channel.WorkerChannelError)):
                result.result(timeout=2)
            once.assert_called_once()
        self.assertEqual(operations, [False])
        self.assertIsNone(self.channel._closed_write)
        self.assertEqual(self.journal.phase(), journal.Phase.DELIVERY_CLAIMED)
        self.assertEqual(self.worker.read_all(self.client), self.packet)

    def test_revocation_can_finish_during_actual_worker_shutdown(self):
        self.assert_revoke_during_closure("shutdown")

    def test_revocation_can_finish_during_actual_worker_close(self):
        self.assert_revoke_during_closure("close")

    def test_worker_exit_in_final_callback_holds_one_claim_without_send(self):
        self.provision_native()

        def owner():
            if self.channel._phase is channel._Phase.SPENT:
                self.assertEqual(self.worker.stop(self.worker.worker_proc), 0)
            return True

        with patch.object(self.channel, "_owner_current", owner), patch.object(channel, "_send_once") as once:
            with self.assertRaises((journal.GenerationHeld, channel.WorkerChannelError)):
                self.deliver()
            once.assert_not_called()
        self.assertEqual(self.worker.read_all(self.client), b"")
        self.assertEqual(self.journal.phase(), journal.Phase.DELIVERY_CLAIMED)

    def test_worker_exit_after_verified_close_cannot_settle(self):
        self.provision_native()
        close = self.channel.close_written

        def close_and_lose_worker(prepared, receipt):
            finished = close(prepared, receipt)
            self.assertEqual(self.worker.stop(self.worker.worker_proc), 0)
            return finished

        with patch.object(self.channel, "close_written", close_and_lose_worker):
            with self.assertRaises(journal.GenerationHeld):
                self.deliver()
        self.assertEqual(self.journal.phase(), journal.Phase.DELIVERY_CLAIMED)
        self.assertEqual(self.worker.read_all(self.client), self.packet)

    def test_worker_exit_during_durable_settlement_recheck_cannot_settle(self):
        self.provision_native(monitor_worker=False)
        verify = self.channel.verify_closed_write

        def close_check(closure):
            verify(closure)
            self.before_authority = lambda: self.worker.stop(self.worker.worker_proc)

        with patch.object(self.channel, "verify_closed_write", close_check):
            with self.assertRaises((journal.GenerationHeld, channel.WorkerChannelError)):
                self.deliver()
        self.assertEqual(self.worker.read_all(self.client), self.packet)
        self.assertEqual(self.journal.phase(), journal.Phase.DELIVERY_CLAIMED)

    def test_worker_exit_after_final_record_rename_leaves_settlement_held(self):
        self.provision_native(monitor_worker=False)
        replace_file = os.replace
        stopped = False

        def replace_then_stop(source, target, **kwargs):
            nonlocal stopped
            replace_file(source, target, **kwargs)
            if target == journal._STATE and self.journal.phase() is journal.Phase.SETTLED:
                self.assertEqual(self.worker.stop(self.worker.worker_proc), 0)
                stopped = True

        with (patch.object(os, "replace", replace_then_stop),
              patch.object(channel, "_send_once", wraps=channel._send_once) as once,
              self.assertRaises((journal.GenerationHeld, channel.WorkerChannelError))):
            self.deliver()
        self.assertTrue(stopped)
        once.assert_called_once()
        self.assertEqual(self.worker.read_all(self.client), self.packet)
        self.assertEqual((self.journal.slot / journal._LATCH).read_bytes(), journal._DIRTY)

    def test_worker_exit_after_final_latch_commit_restores_dirty_hold(self):
        self.provision_native(monitor_worker=False)
        save = journal._Files.save

        def save_then_stop(files, phase, binding, check):
            save(files, phase, binding, check)
            if phase is journal.Phase.SETTLED:
                self.assertEqual((self.journal.slot / journal._LATCH).read_bytes(), journal._HELD)
                self.assertEqual(self.worker.stop(self.worker.worker_proc), 0)

        with (patch.object(journal._Files, "save", save_then_stop),
              patch.object(channel, "_send_once", wraps=channel._send_once) as once,
              self.assertRaises((journal.GenerationHeld, channel.WorkerChannelError))):
            self.deliver()
        once.assert_called_once()
        self.assertEqual(self.worker.read_all(self.client), self.packet)
        self.assertEqual((self.journal.slot / journal._LATCH).read_bytes(), journal._DIRTY)

    def test_missing_natural_exit_proof_refuses_delivery_before_claim(self):
        self.provision_native(mode="fail", prove_exit=False)
        with patch.object(channel, "_send_once") as once, self.assertRaises(TranscriptUnavailable):
            self.deliver()
        once.assert_not_called()
        self.assertEqual(self.journal.phase(), journal.Phase.DESTINATION_SETTLED)
        self.assertEqual(self.worker.read_all(self.client), b"")

    def test_foreign_native_retirement_refuses_delivery_before_claim(self):
        self.provision_native()
        foreign = replace(self.native_retirement, invocation=replace(self.invocation))
        with patch.object(channel, "_send_once") as once, self.assertRaises(channel.WorkerChannelError):
            self.deliver(native_retirement=foreign)
        once.assert_not_called()
        self.assertEqual(self.journal.phase(), journal.Phase.DESTINATION_SETTLED)

    def test_proxy_retirement_mismatch_prevents_claim(self):
        self.run_negative_retirement("proxy")

    def run_negative_retirement(self, proof):
        self.provision_native()
        overrides = {}
        if proof == "proxy":
            unconfirmed = replace(self.proxy_retirement.receipt, connector_retired=False)
            overrides["proxy_retirement"] = replace(self.proxy_retirement, receipt=unconfirmed)
        else:
            self.worker.genuine_retirement = None
        with patch.object(channel, "_send_once") as once, self.assertRaises(channel.WorkerChannelError):
            self.deliver(**overrides)
        once.assert_not_called()
        self.assertEqual(self.journal.phase(), journal.Phase.DESTINATION_SETTLED)

    def test_failed_relay_retirement_observation_prevents_claim(self):
        self.run_negative_retirement("relay")

    def test_destination_not_durably_settled_leaves_delivery_unclaimed(self):
        self.provision_native(settle_destination=False)
        with patch.object(channel, "_send_once") as once, self.assertRaises(journal.GenerationHeld):
            self.deliver()
        once.assert_not_called()
        self.assertEqual(self.journal.phase(), journal.Phase.ACP_SENT)

    def test_foreign_owner_fence_is_refused_before_consuming_terminal_or_claiming(self):
        self.provision_native()
        with (patch.object(self.channel, "_fence", RLock()),
              patch.object(channel, "_send_once") as once, self.assertRaises(channel.WorkerChannelError)):
            self.deliver()
        once.assert_not_called()
        self.assertEqual(self.journal.phase(), journal.Phase.DESTINATION_SETTLED)
        self.assertEqual(self.deliver(), channel.DeliveryReceipt(True, len(self.packet), True))

    def test_prepared_join_channel_cannot_call_legacy_delivery_or_accept_copied_plan(self):
        self.provision_native()
        prepared = self.channel.prepare_delivery(self.adoption, self.relay_retirement, run=self.run_lease)
        with patch.object(channel, "_send_once") as once:
            with self.assertRaises(channel.WorkerChannelError):
                self.channel.deliver()
            with self.assertRaises(channel.WorkerChannelError):
                self.channel.write_prepared(replace(prepared), run=self.run_lease, proof=None)
            once.assert_not_called()
        self.worker.claim.assert_not_called()
        self.assertEqual(self.journal.phase(), journal.Phase.DESTINATION_SETTLED)

    def test_prepared_plan_refuses_foreign_run_before_reading_its_proof(self):
        self.provision_native()
        prepared = self.channel.prepare_delivery(self.adoption, self.relay_retirement, run=self.run_lease)
        foreign = replace(self.run_lease, _control=replace(self.run_lease._control))
        with patch.object(channel, "_send_once") as once, self.assertRaisesRegex(
            channel.WorkerChannelError, "journal is unavailable",
        ):
            self.channel.write_prepared(prepared, run=foreign, proof=self.prior_acp_proof)
        once.assert_not_called()
        self.assertEqual(self.journal.phase(), journal.Phase.DESTINATION_SETTLED)

    def test_prepared_plan_refuses_a_live_delivery_proof_from_another_journal(self):
        self.provision_native()
        prepared = self.channel.prepare_delivery(self.adoption, self.relay_retirement, run=self.run_lease)
        other = journal_fixture.GenerationJournalTests()
        self.addCleanup(other.doCleanups)
        other.setUp()
        other.fence = self.journal.fence
        with other.launch(deadline=monotonic() + 5) as foreign:
            for operation in (journal.Operation.ACP, journal.Operation.DESTINATION):
                receipt, observation = other.split_write(foreign, foreign.issue(operation))
                foreign.settle(receipt, observation)
            cap = foreign.issue(journal.Operation.DELIVERY)

            def effect(foreign_proof):
                foreign.verify_in_flight(foreign_proof, journal.Operation.DELIVERY)
                return self.channel.write_prepared(prepared, run=self.run_lease, proof=foreign_proof)

            with patch.object(channel, "_send_once") as once, self.assertRaises(journal.GenerationHeld):
                foreign.write_once(cap, effect, target=prepared, data=prepared.packet)
            once.assert_not_called()
            self.assertEqual(other.phase(), journal.Phase.DELIVERY_CLAIMED)
        self.assertEqual(self.journal.phase(), journal.Phase.DESTINATION_SETTLED)

    def test_prepared_plan_refuses_wrong_role_proof(self):
        self.provision_native()
        prepared = self.channel.prepare_delivery(self.adoption, self.relay_retirement, run=self.run_lease)
        with patch.object(channel, "_send_once") as once:
            with self.assertRaises(journal.GenerationHeld):
                self.channel.write_prepared(prepared, run=self.run_lease, proof=self.prior_acp_proof)
            once.assert_not_called()
        self.assertEqual(self.journal.phase(), journal.Phase.DESTINATION_SETTLED)

    def test_prepared_plan_refuses_absent_proof(self):
        self.provision_native()
        prepared = self.channel.prepare_delivery(self.adoption, self.relay_retirement, run=self.run_lease)
        with patch.object(channel, "_send_once") as once, self.assertRaises(journal.GenerationHeld):
            self.channel.write_prepared(prepared, run=self.run_lease, proof=None)
        once.assert_not_called()
        self.assertEqual(self.journal.phase(), journal.Phase.DESTINATION_SETTLED)

    def test_prepared_plan_refuses_reconstructed_live_delivery_proof(self):
        self.provision_native()
        prepared = self.channel.prepare_delivery(self.adoption, self.relay_retirement, run=self.run_lease)
        guard = self.channel.settlement_guard(prepared, run=self.run_lease)
        cap = self.run_lease.issue(journal.Operation.DELIVERY)

        def effect(proof):
            return self.channel.write_prepared(prepared, run=self.run_lease, proof=replace(proof))

        with patch.object(channel, "_send_once") as once, self.assertRaises(journal.GenerationHeld):
            self.run_lease.write_once(cap, effect, target=prepared, data=prepared.packet, settlement_guard=guard)
        once.assert_not_called()
        self.assertEqual(self.journal.phase(), journal.Phase.DELIVERY_CLAIMED)

    def test_prepared_plan_refuses_a_previously_live_delivery_proof(self):
        self.provision_native()
        prepared = self.channel.prepare_delivery(self.adoption, self.relay_retirement, run=self.run_lease)
        cap = self.run_lease.issue(journal.Operation.DELIVERY)
        captured = []
        digest = sha256(prepared.packet).hexdigest()

        def effect(proof):
            self.run_lease.verify_in_flight(proof, journal.Operation.DELIVERY)
            captured.append(proof)
            return journal.WriteEvidence(prepared, len(prepared.packet), digest)

        guard = self.channel.settlement_guard(prepared, run=self.run_lease)
        with patch.object(channel, "_send_once") as once:
            with self.assertRaisesRegex(channel.WorkerChannelError, "delivery write is unconfirmed"):
                self.run_lease.write_once(cap, effect, target=prepared, data=prepared.packet, settlement_guard=guard)
            with self.assertRaises(journal.GenerationHeld):
                self.channel.write_prepared(prepared, run=self.run_lease, proof=captured[0])
            once.assert_not_called()
        self.assertEqual(self.journal.phase(), journal.Phase.DELIVERY_CLAIMED)

    def assert_wrong_write_binding_refused(self, variant):
        self.provision_native()
        prepared = self.channel.prepare_delivery(self.adoption, self.relay_retirement, run=self.run_lease)
        guard = self.channel.settlement_guard(prepared, run=self.run_lease)
        capability = self.run_lease.issue(journal.Operation.DELIVERY)
        target = replace(prepared) if variant == "plan" else prepared
        data = b"x" + prepared.packet[1:] if variant == "packet" else prepared.packet
        bound_guard = {"missing-guard": None, "other-guard": lambda _: None}.get(variant, guard)

        def effect(proof):
            return self.channel.write_prepared(prepared, run=self.run_lease, proof=proof)

        with patch.object(channel, "_send_once") as once, self.assertRaises(journal.GenerationHeld):
            self.run_lease.write_once(capability, effect, target=target, data=data, settlement_guard=bound_guard)
        once.assert_not_called()
        self.assertEqual(self.journal.phase(), journal.Phase.DELIVERY_CLAIMED)

    def test_prepared_plan_refuses_delivery_proof_for_other_plan(self):
        self.assert_wrong_write_binding_refused("plan")

    def test_prepared_plan_refuses_delivery_proof_for_other_packet(self):
        self.assert_wrong_write_binding_refused("packet")

    def test_prepared_plan_refuses_delivery_proof_without_expected_guard(self):
        self.assert_wrong_write_binding_refused("missing-guard")

    def test_prepared_plan_refuses_delivery_proof_with_substituted_guard(self):
        self.assert_wrong_write_binding_refused("other-guard")

    def assert_non_original_closure_held(self, *, cloned):
        self.provision_native(monitor_worker=False)
        close = self.channel.close_written

        def substitute_after_close(prepared, receipt):
            actual = close(prepared, receipt)
            return replace(actual) if cloned else None

        with (patch.object(self.channel, "close_written", substitute_after_close),
              patch.object(self.channel, "verify_closed_write", return_value=None),
              patch.object(channel, "_send_once", wraps=channel._send_once) as once,
              self.assertRaises((journal.GenerationHeld, channel.WorkerChannelError))):
            self.deliver()
        once.assert_called_once()
        self.assertEqual(self.worker.read_all(self.client), self.packet)
        self.assertEqual(self.journal.phase(), journal.Phase.DELIVERY_CLAIMED)

    def test_missing_closure_leaves_one_send_held(self):
        self.assert_non_original_closure_held(cloned=False)

    def test_cloned_closure_leaves_one_send_held(self):
        self.assert_non_original_closure_held(cloned=True)

    def test_worker_cgroup_drift_during_last_callback_refuses_write(self):
        self.provision_native(monitor_worker=False)
        moved = False
        def group(pid):
            return Path(f"/proc/{pid}/cgroup").read_bytes()

        def owner():
            nonlocal moved
            if self.channel._phase is channel._Phase.SPENT:
                moved = True
            return True

        def observe(pid):
            return b"0::/changed-synthetic.scope\n" if moved else group(pid)

        with (patch.object(self.channel, "_owner_current", owner),
              patch.object(channel, "_proc_cgroups", observe, create=True),
              patch.object(channel, "_send_once", wraps=channel._send_once) as once,
              self.assertRaisesRegex(channel.WorkerChannelError, "placement is no longer current")):
            self.deliver()
        self.assertTrue(moved)
        self.assertIsNone(self.worker.worker_proc.poll())
        once.assert_not_called()
        self.assertEqual(self.journal.phase(), journal.Phase.DELIVERY_CLAIMED)

    def test_worker_namespace_drift_after_closure_refuses_settlement(self):
        self.provision_native(monitor_worker=False)
        moved = False
        close = self.channel.close_written

        def close_and_move(prepared, receipt):
            nonlocal moved
            observed = close(prepared, receipt)
            moved = True
            return observed

        def observe(pid):
            info = os.stat(f"/proc/{pid}/ns/net")
            return info.st_dev, info.st_ino + int(moved)

        with (patch.object(self.channel, "close_written", close_and_move),
              patch.object(channel, "_proc_netns_identity", observe, create=True),
              patch.object(channel, "_send_once", wraps=channel._send_once) as once,
              self.assertRaisesRegex(channel.WorkerChannelError, "placement is no longer current")):
            self.deliver()
        self.assertIsNone(self.worker.worker_proc.poll())
        once.assert_called_once()
        self.assertEqual(self.worker.read_all(self.client), self.packet)
        self.assertEqual(self.journal.phase(), journal.Phase.DELIVERY_CLAIMED)

    def test_settlement_guard_is_rejected_for_a_destination_write(self):
        self.provision_native(settle_destination=False)
        where = object()
        cap = self.run_lease.issue(journal.Operation.DESTINATION)
        with self.assertRaises(journal.GenerationHeld):
            self.run_lease.write_once(cap, lambda _: self.fail("non-delivery guard reached effect"),
                                      target=where, data=b"synthetic destination", settlement_guard=lambda _: None)
        self.assertEqual(self.journal.phase(), journal.Phase.DESTINATION_CLAIMED)

    def test_exact_prepared_plan_cannot_write_using_a_noop_claim_callback(self):
        self.provision_native()
        try:
            prepared = self.channel.prepare_delivery(self.adoption, self.relay_retirement, run=self.run_lease)
        except TypeError:
            prepared = self.channel.prepare_delivery(self.adoption, self.relay_retirement)
        with patch.object(channel, "_send_once", wraps=channel._send_once) as once:
            with self.assertRaises((TypeError, channel.WorkerChannelError, journal.GenerationHeld)):
                self.channel.write_prepared(prepared, verify_claim=lambda: None)
            once.assert_not_called()
        self.assertEqual(self.journal.phase(), journal.Phase.DESTINATION_SETTLED)
