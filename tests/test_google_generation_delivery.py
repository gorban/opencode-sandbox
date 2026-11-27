"""Exercise the joined synthetic delivery with actual disposable pipes and sockets."""

from contextlib import suppress
from dataclasses import replace
from hashlib import sha256
import os
from pathlib import Path
import socket
import subprocess
import sys
from threading import RLock
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
        with patch.object(worker_fixture, "MODEL", binding.model):
            self.channel, self.relay, self.client, self.control, _ = self.worker.fixture(distinct_worker=True)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reference:
            reference_pin = channel.WorkerNamespaceReference(
                reference, worker_id=self.worker.placement.worker_id, run=binding.launch,
                epoch=str(binding.epoch), probe_id="joined-reference",
            )
        worker_pid = self.worker.worker_proc.pid
        membership = Path(f"/proc/{worker_pid}/cgroup").read_bytes().splitlines()
        if len(membership) != 1 or not membership[0].startswith(b"0::/") or membership[0] == b"0::/":
            self.skipTest("joined fixture requires a non-root unified worker cgroup")
        member, = membership
        worker_pin = self.worker.pin(worker_pid, member.removeprefix(b"0::"))
        placement = replace(self.worker.placement, run=binding.launch, epoch=str(binding.epoch),
                            reference=reference_pin, worker=worker_pin)
        self.channel._placement = self.worker.placement = placement
        self.adoption, self.relay_retirement = self.worker.seal(self.channel, self.relay, self.control)
        self.packet = protocol.text_reply_bytes(binding.model)
        self.before_authority = None

    def provision_native(self, *, mode="ok", prove_exit=True, settle_destination=True, monitor_worker=True):
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
            return (binding is self.journal.current and self.worker.owner
                    and (not monitor_worker or self.worker.placement.worker.alive()))

        self.run_lease = self.enterContext(self.journal.launch(authorized=authorized, deadline=monotonic() + 10))
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
        cap = self.run_lease.issue(journal.Operation.DELIVERY)

        def effect(proof):
            return self.channel.write_prepared(prepared, run=self.run_lease, proof=replace(proof))

        with patch.object(channel, "_send_once") as once, self.assertRaises(journal.GenerationHeld):
            self.run_lease.write_once(cap, effect, target=prepared, data=prepared.packet)
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

        self.run_lease.write_once(cap, effect, target=prepared, data=prepared.packet)
        with patch.object(channel, "_send_once") as once, self.assertRaises(journal.GenerationHeld):
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
              self.assertRaises(channel.WorkerChannelError)):
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
