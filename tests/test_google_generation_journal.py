"""Exercise durable generation authority only in disposable synthetic accounts."""

from contextlib import ExitStack, suppress
from copy import copy
from dataclasses import replace
import errno
import json
import os
from pathlib import Path
import secrets
import select
import signal
from tempfile import TemporaryDirectory
from threading import Event, RLock, Thread
from time import monotonic
import unittest
from unittest.mock import patch

from oc_google import generation_journal as gen
from oc_google import registration as reg


_DEADLINE = 3
_STEPS = (gen.Operation.ACP, gen.Operation.DESTINATION, gen.Operation.DELIVERY)


def provision(journal, keep_fd):
    """Provision on the fixture's previously absent slot and retain an independent receipt."""
    with journal._locked(create=True) as slot, ExitStack() as pins:
        if not slot.new:
            raise gen.GenerationHeld()
        directory = slot.directory.fd
        registration, generation, attempt = (secrets.token_hex(16) for _ in range(3))
        profile = reg._profile(pins, slot, generation, create=True)
        enrollment = reg.Enrollment(journal.label, registration, generation, attempt, gen._FIXTURE_BUILD,
                                    reg.FileIdentity.of(os.fstat(profile.fd)), reg._create_subject_key(slot, generation))
        key_fd = reg._open_subject_key(pins, slot, enrollment)
        native, _ = reg._child(pins, profile, "antigravity-acp", create=True, private=True, exclusive=True)
        reg._write_private(native.fd, "acp_token.json", gen._SECRET)
        record = reg._Record(
            1, enrollment, reg.FileIdentity.of(os.fstat(slot.lock)), reg.Phase.COLD_RETIREMENT_OBSERVED,
            credential_identity=reg._credential(pins, profile), subject_digest=gen._digest(b"synthetic D1 fixture subject"),
            enrollment_metadata_spent=len(reg._ENROLLMENT_ROUTES), cold_metadata_spent=len(reg._COLD_ROUTES),
        )
        slot.store(record, recheck=lambda: reg._verify_binding(slot, record, profile, key_fd))
        registration_id, registration_digest = gen._check_metadata(
            slot, record, gen._open(pins, directory, reg._RECORD), profile, key_fd,
        )
        authority = secrets.token_hex(32).encode("ascii") + b"\n"
        initial = gen._record(enrollment, gen.Phase.UNSTARTED)
        reg._write_private(directory, gen._AUTHORITY, authority)
        reg._write_private(directory, gen._LATCH, b"")
        temporary = gen._TEMP + secrets.token_hex(16)
        reg._write_private(directory, temporary, initial)
        os.replace(temporary, gen._STATE, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
        authority_id, authority_body = gen._read_leaf(directory, gen._AUTHORITY)
        latch, latch_body = gen._read_leaf(directory, gen._LATCH)
        bootstrap_fd = gen._open(pins, directory, gen._STATE)
        bootstrap, bootstrap_body = gen._read(directory, gen._STATE, bootstrap_fd)
        if (authority_body, latch_body, bootstrap_body) != (authority, b"", initial):
            raise gen.GenerationHeld()
        retained_fd = os.dup(bootstrap_fd)
        keep_fd(os.close, retained_fd)
        return gen.FixtureAnchor(enrollment, record.lock_identity, reg.FileIdentity.of(os.fstat(directory)),
                                 registration_id, registration_digest, record.credential_identity, gen._digest(gen._SECRET),
                                 authority_id, gen._digest(authority), latch, bootstrap, retained_fd,
                                 os.fstat(bootstrap_fd).st_ctime_ns)


class GenerationJournalTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(reg, "_account_home", side_effect=lambda: self.home))
        self.enterContext(patch.object(reg, "_LOCK_TIME", .075))
        self.create_fixture()

    def create_fixture(self):
        home = self.enterContext(TemporaryDirectory(prefix="oc-google-generation-journal-"))
        self.home = Path(home)
        self.registration = gen.FixtureRegistrationJournal()
        self.anchor = provision(self.registration, self.addCleanup)
        self.journal = gen.GenerationJournal(self.registration, self.anchor)
        self.binding = self.anchor.binding(epoch=1, launch="a" * 32)
        self.current = self.binding
        self.fence = RLock()
        root = self.home / ".local/state/oc-sandbox/google" / gen._FIXTURE_DIR
        self.slot = root / "registrations" / self.registration.label
        self.metadata = self.slot / reg._RECORD
        self.lock = self.slot / reg._LOCK
        self.credential = root / "profiles" / self.anchor.enrollment.generation / "antigravity-acp/acp_token.json"
        self.baseline = (self.metadata.read_bytes(), self.lock.stat().st_ino, self.metadata.stat().st_ino,
                         self.credential.read_bytes(), self.credential.stat().st_ino)

    def launch(self, *, authorized=None, deadline=None):
        owner = authorized if authorized is not None else lambda binding: self.current is binding
        return self.journal.launch(self.binding, fence=self.fence, authorized=owner, deadline=deadline)

    def split_write(self, run, capability, *, write=None):
        target = object()
        data = ("synthetic " + capability.operation.value).encode("ascii")

        def effect(proof):
            run.verify_in_flight(proof, capability.operation)
            count = len(data) if write is None else write(data)
            return gen.WriteEvidence(target, count, gen._digest(data))

        receipt = run.write_once(capability, effect, target=target, data=data)
        return receipt, gen.SettlementEvidence(receipt, target, len(data), gen._digest(data))

    def phase(self):
        return gen.Phase(json.loads((self.slot / gen._STATE).read_bytes())["phase"])

    def check_unchanged(self):
        self.assertEqual(self.baseline, (self.metadata.read_bytes(), self.lock.stat().st_ino,
                                       self.metadata.stat().st_ino, self.credential.read_bytes(),
                                       self.credential.stat().st_ino))
        self.assertEqual(self.lock.read_bytes(), b"")

    def check_held(self):
        reopened = gen.GenerationJournal(gen.FixtureRegistrationJournal(), self.anchor)
        with self.assertRaisesRegex(gen.GenerationHeld, "held or unavailable"):
            reopened.fixture_writer(2)
        self.assertFalse((self.slot / "fixture-writer-2").exists())
        with self.assertRaises(gen.GenerationHeld):
            reopened.status()
        with self.assertRaises(gen.GenerationHeld):
            with reopened.launch(self.binding, fence=self.fence, authorized=lambda _: True):
                self.fail("held generation was reacquired")

    def test_entire_state_machine_preserves_original_registration_and_settles_once(self):
        self.assertEqual(self.journal.status(), gen.Phase.UNSTARTED)
        self.journal.fixture_writer(1)
        self.assertEqual((self.slot / "fixture-writer-1").read_bytes(), b"synthetic writer reached the slot\n")
        with self.launch() as run:
            self.assertEqual(self.phase(), gen.Phase.LAUNCH_HELD)
            for operation in _STEPS:
                start, claim, settled = gen._STEPS[operation]
                self.assertEqual(self.phase(), start)
                capability = run.issue(operation)
                self.assertEqual(self.phase(), claim)
                with self.assertRaises(gen.GenerationHeld):
                    run.issue(operation)
                with self.assertRaises(gen.GenerationHeld):
                    run.consume(replace(capability), lambda _: self.fail("forged capability reached effect"))
                run.consume(capability, lambda observe: observe())
                self.assertEqual(self.phase(), settled)
                with self.assertRaises(gen.GenerationHeld):
                    run.consume(capability, lambda _: self.fail("spent capability reached effect"))
                self.check_unchanged()
        self.assertEqual(self.phase(), gen.Phase.SETTLED)
        self.check_held()

    def test_provisioning_never_rebuilds_an_existing_slot_even_if_both_files_disappear(self):
        (self.slot / gen._STATE).unlink()
        (self.slot / gen._AUTHORITY).unlink()
        with self.assertRaises(gen.GenerationHeld):
            provision(self.registration, self.addCleanup)
        self.check_held()
        self.check_unchanged()
        with self.assertRaises(reg.RegistrationUnavailable):
            self.registration.status()

    def test_stale_fresh_bytes_and_recycled_inode_tuple_cannot_rearm_the_slot(self):
        state = self.slot / gen._STATE
        initial = state.read_bytes()
        with self.launch():
            pass
        self.assertEqual((self.slot / gen._LATCH).read_bytes(), gen._HELD)
        # The supervisor still holds the unlinked original even after generation
        # publication replaced the pathname.
        self.assertEqual(os.fstat(self.anchor.bootstrap_fd).st_nlink, 0)
        state.write_bytes(initial)
        (self.slot / gen._LATCH).write_bytes(b"")
        read_leaf = gen._read_leaf

        def stale_inode(directory, leaf):
            identity, body = read_leaf(directory, leaf)
            return (self.anchor.bootstrap, body) if leaf == gen._STATE else (identity, body)

        with patch.object(gen, "_read_leaf", stale_inode):
            self.check_held()

    def test_missing_corrupt_replaced_or_parked_receipts_refuse_fresh_admission(self):
        for control in ("missing-state", "state-corrupt", "state-inode", "authority-inode", "authority-bytes",
                        "latch-inode", "latch-dirty", "latch-missing", "latch-parked", "state-hardlink", "state-symlink"):
            with self.subTest(control=control):
                self.create_fixture()
                state = self.slot / gen._STATE
                authority = self.slot / gen._AUTHORITY
                latch = self.slot / gen._LATCH
                if control == "missing-state":
                    state.unlink()
                elif control == "state-corrupt":
                    state.write_bytes(b'{"phase":true}')
                elif control.endswith("-inode"):
                    leaf = {"state-inode": state, "authority-inode": authority, "latch-inode": latch}[control]
                    replacement = self.slot / "replacement"
                    replacement.write_bytes(leaf.read_bytes())
                    replacement.chmod(0o600)
                    replacement.replace(leaf)
                elif control == "authority-bytes":
                    authority.write_bytes(b"different fixture authority\n")
                elif control == "latch-dirty":
                    latch.write_bytes(b"!")
                elif control == "latch-missing":
                    latch.unlink()
                elif control == "latch-parked":
                    (self.slot / (gen._PARKED + "known")).touch()
                elif control == "state-hardlink":
                    os.link(state, self.slot / "extra-link")
                else:
                    state.rename(self.slot / "saved")
                    state.symlink_to("saved")
                self.check_held()
                self.check_unchanged()

    def test_registration_and_synthetic_credential_tampering_fail_closed(self):
        for control in ("metadata-inode", "metadata-bytes", "incomplete-counts", "credential-inode", "credential-bytes",
                        "lock-inode"):
            with self.subTest(control=control):
                self.create_fixture()
                if control.endswith("-inode"):
                    original = {"metadata-inode": self.metadata, "credential-inode": self.credential,
                                "lock-inode": self.lock}[control]
                    replacement = original.parent / "replacement"
                    replacement.write_bytes(original.read_bytes())
                    replacement.chmod(0o600)
                    replacement.replace(original)
                elif control == "metadata-bytes":
                    self.metadata.write_bytes(self.metadata.read_bytes() + b"\n")
                elif control == "incomplete-counts":
                    record = json.loads(self.metadata.read_bytes())
                    record["cold_metadata_spent"] = 3
                    self.metadata.write_bytes(gen._json(record))
                else:
                    self.credential.write_bytes(b"other synthetic fixture content\n")
                self.check_held()

    def test_metadata_mutators_cannot_reach_the_fixture_even_with_replaced_marker_and_missing_ledger(self):
        plain = reg.RegistrationJournal(self.registration.label)
        self.assertIsNone(plain.status())
        # The label and build digest have no reserved meaning in the normal
        # namespace. This is a separate regular registration.
        regular = plain.begin(gen._FIXTURE_BUILD)
        with plain.enrollment_profile(regular):
            pass
        self.assertEqual(plain.status().registration_id, regular.registration_id)
        self.assertIs(plain.status().phase, reg.Phase.ENROLLING)
        with self.launch():
            pass
        (self.slot / gen._AUTHORITY).unlink()
        (self.slot / gen._STATE).unlink()
        with self.assertRaises(gen.GenerationHeld):
            self.registration.begin(gen._FIXTURE_BUILD)
        enrollment = replace(self.anchor.enrollment, build_digest="b" * 64)
        for phase in (reg.Phase.PENDING, reg.Phase.ENROLLMENT_RETIRED, reg.Phase.COLD_PENDING):
            with self.subTest(phase=phase):
                record = json.loads(self.metadata.read_bytes())
                record["enrollment"]["build_digest"] = enrollment.build_digest
                record.update(phase=phase.value, credential_identity=None, subject_digest=None,
                              enrollment_metadata_spent=0, cold_metadata_spent=0, cold_subject_observed=False,
                              check_nonce=None)
                if phase is not reg.Phase.PENDING:
                    record.update(credential_identity={"device": self.anchor.credential.device,
                                                       "inode": self.anchor.credential.inode})
                if phase is reg.Phase.COLD_PENDING:
                    record.update(check_nonce="a" * 32, subject_digest="b" * 64)
                self.metadata.write_bytes(gen._json(record))
                with self.assertRaises(gen.GenerationHeld):
                    if phase is reg.Phase.PENDING:
                        with self.registration.enrollment_profile(enrollment):
                            self.fail("enrollment writer bypassed sealed fixture authority")
                    elif phase is reg.Phase.ENROLLMENT_RETIRED:
                        self.registration.begin_cold_check(enrollment)
                    else:
                        with self.registration.cold_profile(reg.ColdCheck(enrollment, "a" * 32, self.anchor.credential)):
                            self.fail("cold profile writer bypassed sealed fixture authority")
                with self.assertRaises(gen.GenerationHeld):
                    self.registration.status()
                with self.assertRaises(reg.RegistrationUnavailable), plain.enrollment_profile(enrollment):
                    self.fail("normal registration reached the fixture namespace")
                self.assertEqual(plain.status().registration_id, regular.registration_id)
                self.check_held()

    def test_loss_before_launch_leaves_writer_admissible_and_loss_after_claim_spends(self):
        self.current = None
        with self.assertRaises(gen.GenerationHeld):
            with self.launch():
                self.fail("revoked owner launched")
        self.assertEqual(self.journal.status(), gen.Phase.UNSTARTED)
        self.journal.fixture_writer(1)

        self.current = self.binding
        with self.launch() as run:
            capability = run.issue(gen.Operation.ACP)
            self.current = replace(self.binding, epoch=2)
            with self.assertRaises(gen.GenerationHeld):
                run.consume(capability, lambda _: self.fail("stale epoch reached effect"))
            self.current = self.binding
            with self.assertRaises(gen.GenerationHeld):
                run.consume(capability, lambda _: self.fail("revoked capability became current again"))
        self.assertEqual(self.phase(), gen.Phase.ACP_CLAIMED)
        self.check_held()

    def test_bad_binding_cannot_create_a_generation_hold(self):
        for changes in ({"model": "gemini-2.5-pro"}, {"epoch": True}, {"launch": "b" * 31},
                        {"profile_digest": "wrong"}, {"credential_digest": "wrong"}, {"policy_digest": "wrong"}):
            with self.subTest(changes=changes), self.assertRaises(gen.GenerationHeld):
                with self.journal.launch(replace(self.binding, **changes), fence=self.fence, authorized=lambda _: True):
                    self.fail("unbound generation reached launch")
        self.assertEqual(self.journal.status(), gen.Phase.UNSTARTED)
        self.journal.fixture_writer(1)

    def test_split_write_requires_observed_settlement_in_every_durable_phase(self):
        with self.launch(deadline=monotonic() + 5) as run:
            with self.assertRaises(gen.GenerationHeld):
                run.acp_sent()
            acp_sent = None
            writes = []
            for operation in _STEPS:
                _, claimed, settled = gen._STEPS[operation]
                cap = run.issue(operation)
                if operation is gen.Operation.DELIVERY:
                    with self.assertRaises(gen.GenerationHeld):
                        run.verify_acp_sent(acp_sent)
                elif acp_sent is not None:
                    run.verify_acp_sent(acp_sent)
                with self.assertRaises(gen.GenerationHeld):
                    run.consume(cap, lambda _: self.fail("legacy settlement ran inside a join"))

                def write(data):
                    self.assertEqual(self.phase(), claimed)
                    writes.append(data)
                    return len(data)

                receipt, evidence = self.split_write(run, cap, write=write)
                self.assertEqual((receipt.operation, receipt.byte_count, receipt.packet_sha256),
                                 (operation, len(writes[-1]), gen._digest(writes[-1])))
                self.assertEqual(self.phase(), claimed)
                with self.assertRaises(gen.GenerationHeld):
                    self.split_write(copy(run), cap, write=write)
                run.settle(receipt, evidence)
                self.assertEqual(self.phase(), settled)
                if operation is gen.Operation.ACP:
                    acp_sent = run.acp_sent()
                    self.assertIs(acp_sent.write, receipt)
                    with self.assertRaises(gen.GenerationHeld):
                        run.verify_acp_sent(copy(acp_sent))
            self.assertEqual(writes, [b"synthetic acp", b"synthetic destination", b"synthetic delivery"])
            self.check_unchanged()
        self.check_held()

    def test_local_acp_pin_has_no_owner_callback_and_requires_exact_current_receipt(self):
        owner_calls = []

        def owner(binding):
            owner_calls.append(binding)
            return binding is self.binding

        with self.launch(authorized=owner, deadline=monotonic() + 5) as run:
            write, evidence = self.split_write(run, run.issue(gen.Operation.ACP))
            run.settle(write, evidence)
            sent = run.acp_sent()
            prior = len(owner_calls)

            with self.assertRaises(gen.GenerationHeld):
                run._verify_local_acp_sent(sent, phase=gen.Phase.ACP_SENT)
            with self.fence:
                run._verify_local_acp_sent(sent, phase=gen.Phase.ACP_SENT)
                for receipt, phase in ((copy(sent), gen.Phase.ACP_SENT),
                                       (sent, gen.Phase.DESTINATION_SETTLED)):
                    with self.assertRaises(gen.GenerationHeld):
                        run._verify_local_acp_sent(receipt, phase=phase)
                run._verify_local_acp_sent(sent, phase=gen.Phase.ACP_SENT)
            self.assertEqual(len(owner_calls), prior)

    def test_local_destination_pin_requires_ordinary_proof_in_current_effect(self):
        owner_calls = []

        def owner(binding):
            owner_calls.append(binding)
            return binding is self.binding

        with self.launch(authorized=owner, deadline=monotonic() + 5) as run:
            write, evidence = self.split_write(run, run.issue(gen.Operation.ACP))
            run.settle(write, evidence)
            cap = run.issue(gen.Operation.DESTINATION)
            target, data = object(), b"synthetic destination gate"
            proofs = []

            def effect(proof):
                proofs.append(proof)
                prior = len(owner_calls)
                with self.assertRaises(gen.GenerationHeld):
                    run._verify_local_destination(proof)
                self.assertEqual(len(owner_calls), prior)
                self.assertFalse(run._files._authority.flight_checked)
                run.verify_in_flight(proof, gen.Operation.DESTINATION)
                prior = len(owner_calls)
                with self.assertRaises(gen.GenerationHeld):
                    run._verify_local_destination(copy(proof))
                with patch.object(gen, "get_ident", return_value=proof.thread + 1):
                    with self.assertRaises(gen.GenerationHeld):
                        run._verify_local_destination(proof)
                run._verify_local_destination(proof)
                self.assertEqual(len(owner_calls), prior)
                return gen.WriteEvidence(target, len(data), gen._digest(data))

            run.write_once(cap, effect, target=target, data=data)
            with self.fence, self.assertRaises(gen.GenerationHeld):
                run._verify_local_destination(proofs[0])

    def test_local_acp_durable_drift_stays_revoked_after_restoration(self):
        for replaced in (False, True):
            with self.subTest(replaced=replaced):
                self.create_fixture()
                with self.launch(deadline=monotonic() + 5) as run:
                    write, evidence = self.split_write(run, run.issue(gen.Operation.ACP))
                    run.settle(write, evidence)
                    sent = run.acp_sent()
                    state = self.slot / gen._STATE
                    saved = self.slot / "saved-synthetic-state"
                    original, inode = state.read_bytes(), state.stat().st_ino
                    with self.fence:
                        if replaced:
                            state.rename(saved)
                            state.write_bytes(original)
                            state.chmod(0o600)
                            self.assertNotEqual(state.stat().st_ino, inode)
                        else:
                            state.write_bytes(original + b"\n")
                        try:
                            with self.assertRaises(gen.GenerationHeld):
                                run._verify_local_acp_sent(sent, phase=gen.Phase.ACP_SENT)
                        finally:
                            if replaced:
                                saved.replace(state)
                            else:
                                state.write_bytes(original)
                        self.assertEqual(state.stat().st_ino, inode)
                        run._files.verify()
                        with self.assertRaises(gen.GenerationHeld):
                            run._verify_local_acp_sent(sent, phase=gen.Phase.ACP_SENT)
                    with self.assertRaises(gen.GenerationHeld):
                        run.issue(gen.Operation.DESTINATION)

    def test_local_acp_expiry_stays_revoked_after_clock_is_restored(self):
        for during_verification in (False, True):
            with self.subTest(during_verification=during_verification):
                self.create_fixture()
                deadline = monotonic() + 5
                with self.launch(deadline=deadline) as run:
                    write, evidence = self.split_write(run, run.issue(gen.Operation.ACP))
                    run.settle(write, evidence)
                    sent = run.acp_sent()
                    clock = [deadline - 1, deadline] if during_verification else [deadline]
                    with self.fence:
                        with patch.object(gen, "monotonic", side_effect=clock), self.assertRaises(gen.GenerationHeld):
                            run._verify_local_acp_sent(sent, phase=gen.Phase.ACP_SENT)
                        self.assertLess(monotonic(), deadline)
                        with self.assertRaises(gen.GenerationHeld):
                            run._verify_local_acp_sent(sent, phase=gen.Phase.ACP_SENT)

    def test_local_acp_rechecks_sticky_revocation_after_durable_verification(self):
        with self.launch(deadline=monotonic() + 5) as run:
            write, evidence = self.split_write(run, run.issue(gen.Operation.ACP))
            run.settle(write, evidence)
            sent = run.acp_sent()
            verify = gen._Files.verify

            def verify_and_revoke(files):
                verify(files)
                run.revoke()

            with self.fence, patch.object(gen._Files, "verify", new=verify_and_revoke):
                with self.assertRaises(gen.GenerationHeld):
                    run._verify_local_acp_sent(sent, phase=gen.Phase.ACP_SENT)

    def test_local_destination_durable_drift_stays_revoked_inside_same_write(self):
        with self.launch(deadline=monotonic() + 5) as run:
            write, evidence = self.split_write(run, run.issue(gen.Operation.ACP))
            run.settle(write, evidence)
            cap = run.issue(gen.Operation.DESTINATION)
            target, data = object(), b"synthetic destination gate"

            def effect(proof):
                run.verify_in_flight(proof, gen.Operation.DESTINATION)
                state = self.slot / gen._STATE
                original = state.read_bytes()
                state.write_bytes(original + b"\n")
                try:
                    with self.assertRaises(gen.GenerationHeld):
                        run._verify_local_destination(proof)
                finally:
                    state.write_bytes(original)
                run._files.verify()
                with self.assertRaises(gen.GenerationHeld):
                    run._verify_local_destination(proof)
                return gen.WriteEvidence(target, len(data), gen._digest(data))

            with self.assertRaises(gen.GenerationHeld):
                run.write_once(cap, effect, target=target, data=data)
            self.assertEqual(self.phase(), gen.Phase.DESTINATION_CLAIMED)

    def test_legacy_consume_cannot_mint_acp_sent_or_use_split_write(self):
        with self.launch() as run:
            cap = run.issue(gen.Operation.ACP)
            with self.assertRaises(gen.GenerationHeld):
                self.split_write(run, cap, write=lambda _: self.fail("split write ran inside a legacy lease"))
            run.consume(cap, lambda observe: observe())
            self.assertEqual(self.phase(), gen.Phase.ACP_SENT)
            with self.assertRaises(gen.GenerationHeld):
                run.acp_sent()

    def test_divergent_deadline_view_cannot_use_legacy_consume_on_split_lease(self):
        with self.launch(deadline=monotonic() + 5) as run:
            cap = run.issue(gen.Operation.ACP)
            try:
                forged = replace(run, _deadline=None)
            except TypeError:
                pass
            else:
                with self.assertRaises(gen.GenerationHeld):
                    forged.consume(cap, lambda observe: observe())
            self.assertEqual(self.phase(), gen.Phase.ACP_CLAIMED)
            receipt, evidence = self.split_write(copy(run), cap)
            run.settle(receipt, evidence)
            self.assertEqual(self.phase(), gen.Phase.ACP_SENT)

    def test_divergent_authorizer_view_cannot_write_after_real_owner_loss(self):
        with self.launch(deadline=monotonic() + 5) as run:
            cap = run.issue(gen.Operation.ACP)
            effects = []
            self.current = None
            try:
                forged = replace(run, _authorized=lambda _: True)
            except TypeError:
                pass
            else:
                with self.assertRaises(gen.GenerationHeld):
                    self.split_write(forged, cap, write=lambda data: effects.append(data) or len(data))
            with self.assertRaises(gen.GenerationHeld):
                self.split_write(copy(run), cap, write=lambda data: effects.append(data) or len(data))
            self.assertEqual(effects, [])
            self.assertEqual(self.phase(), gen.Phase.ACP_CLAIMED)

    def test_divergent_fence_view_cannot_write_without_the_shared_fence(self):
        with self.launch(deadline=monotonic() + 5) as run:
            cap = run.issue(gen.Operation.ACP)
            try:
                forged = replace(run, _fence=RLock())
            except TypeError:
                pass
            else:
                with self.assertRaises(gen.GenerationHeld):
                    self.split_write(forged, cap)
            self.assertEqual(self.phase(), gen.Phase.ACP_CLAIMED)
            receipt, evidence = self.split_write(run, cap)
            copy(run).settle(receipt, evidence)
            self.assertEqual(self.phase(), gen.Phase.ACP_SENT)

    def test_reconstructed_control_is_rejected_before_touching_the_exact_lease(self):
        with self.launch(deadline=monotonic() + 5) as run:
            cap = run.issue(gen.Operation.ACP)
            for changes in ({}, {"deadline": None}, {"fence": RLock()}, {"authorized": lambda _: True},
                            {"binding": replace(self.binding, epoch=2)}, {"pid": os.getpid() + 1}):
                with self.subTest(fields=tuple(changes)):
                    forged = replace(run, _control=replace(run._control, **changes))
                    with self.assertRaises(gen.GenerationHeld):
                        forged.revoke()
                    with self.assertRaises(gen.GenerationHeld):
                        forged.consume(cap, lambda _: self.fail("reconstructed control ran legacy consume"))
                    with self.assertRaises(gen.GenerationHeld):
                        self.split_write(forged, cap, write=lambda _: self.fail("reconstructed control wrote"))
            self.assertEqual(self.phase(), gen.Phase.ACP_CLAIMED)
            receipt, evidence = self.split_write(replace(run), cap)
            copy(run).settle(receipt, evidence)
            self.assertIs(run.acp_sent().write, receipt)

    def test_inflight_proof_requires_exact_identity_method_thread_and_current_call(self):
        with self.launch(deadline=monotonic() + 5) as run:
            cap = run.issue(gen.Operation.ACP)
            target, data = object(), b"synthetic"
            captured = []

            def effect(proof):
                captured.append(proof)
                with self.assertRaises(gen.GenerationHeld):
                    run.verify_in_flight(copy(proof), gen.Operation.ACP)
                with self.assertRaises(gen.GenerationHeld):
                    run.verify_in_flight(proof, gen.Operation.DESTINATION)
                response = []

                def cross_thread():
                    try:
                        run.verify_in_flight(proof, gen.Operation.ACP)
                    except gen.GenerationHeld:
                        response.append("rejected")

                outsider = Thread(target=cross_thread, daemon=True)
                outsider.start()
                outsider.join(1)
                self.assertFalse(outsider.is_alive())
                self.assertEqual(response, ["rejected"])
                child = os.fork()
                if child == 0:
                    try:
                        run.verify_in_flight(proof, gen.Operation.ACP)
                    except gen.GenerationHeld:
                        os._exit(0)
                    os._exit(1)
                self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(child, 0)[1]), 0)
                with self.assertRaises(gen.GenerationHeld):
                    run.settle(None, None)
                run.verify_in_flight(proof, gen.Operation.ACP)
                return gen.WriteEvidence(target, len(data), gen._digest(data))

            receipt = run.write_once(cap, effect, target=target, data=data)
            with self.assertRaises(gen.GenerationHeld):
                run.verify_in_flight(captured[0], gen.Operation.ACP)
            run.settle(receipt, gen.SettlementEvidence(receipt, target, len(data), gen._digest(data)))
            self.assertEqual(self.phase(), gen.Phase.ACP_SENT)

    def test_write_failure_no_proof_or_uncertain_evidence_cannot_create_a_receipt(self):
        for kind in ("no-proof", "short", "wrong-target", "wrong-bytes", "boolean", "interrupt", "owner-loss"):
            with self.subTest(kind=kind):
                self.create_fixture()
                with self.launch(deadline=monotonic() + 5) as run:
                    cap = run.issue(gen.Operation.ACP)
                    target, data = object(), b"synthetic"
                    captured = []

                    def effect(proof):
                        captured.append(proof)
                        if kind == "owner-loss":
                            self.current = None
                            with self.assertRaises(gen.GenerationHeld):
                                run.verify_in_flight(proof, gen.Operation.ACP)
                            self.current = self.binding
                        elif kind != "no-proof":
                            run.verify_in_flight(proof, gen.Operation.ACP)
                        if kind == "interrupt":
                            raise InterruptedError
                        if kind == "boolean":
                            return True
                        return gen.WriteEvidence(object() if kind == "wrong-target" else target,
                                                 1 if kind == "short" else len(data),
                                                 gen._digest(b"other" if kind == "wrong-bytes" else data))

                    failure = InterruptedError if kind == "interrupt" else gen.GenerationHeld
                    with self.assertRaises(failure):
                        run.write_once(cap, effect, target=target, data=data)
                    with self.assertRaises(gen.GenerationHeld):
                        run.verify_in_flight(captured[0], gen.Operation.ACP)
                    with self.assertRaises(gen.GenerationHeld):
                        run.write_once(cap, effect, target=target, data=data)
                    self.assertEqual(self.phase(), gen.Phase.ACP_CLAIMED)
                self.check_held()

    def test_forged_foreign_or_replayed_write_receipt_cannot_settle(self):
        with self.launch(deadline=monotonic() + 5) as run:
            previous, previous_evidence = self.split_write(run, run.issue(gen.Operation.ACP))
            run.settle(previous, previous_evidence)
            with self.assertRaises(gen.GenerationHeld):
                run.settle(previous, previous_evidence)
            self.assertEqual(self.phase(), gen.Phase.ACP_SENT)
        for variant in ("copy", "foreign", "wrong-observation"):
            with self.subTest(variant=variant):
                self.create_fixture()
                with self.launch(deadline=monotonic() + 5) as run:
                    receipt, evidence = self.split_write(run, run.issue(gen.Operation.ACP))
                    invalid = copy(receipt) if variant == "copy" else previous if variant == "foreign" else receipt
                    invalid_evidence = replace(evidence, write=invalid, byte_count=1 if variant == "wrong-observation"
                                               else receipt.byte_count)
                    with self.assertRaises(gen.GenerationHeld):
                        run.settle(invalid, invalid_evidence)
                    with self.assertRaises(gen.GenerationHeld):
                        run.settle(receipt, evidence)
                    with self.assertRaises(gen.GenerationHeld):
                        run.acp_sent()
                    self.assertEqual(self.phase(), gen.Phase.ACP_CLAIMED)

    def test_observer_stall_allows_revocation_and_no_other_write(self):
        with self.launch(deadline=monotonic() + 5) as run:
            cap = run.issue(gen.Operation.ACP)
            receipt, evidence = self.split_write(run, cap)
            waiting, resume, revoked = Event(), Event(), Event()
            outcomes = []

            def observe():
                waiting.set()
                if resume.wait(2):
                    try:
                        run.settle(receipt, evidence)
                    except gen.GenerationHeld:
                        outcomes.append("held")

            def revoke():
                run.revoke()
                revoked.set()

            observer = Thread(target=observe, daemon=True)
            revoker = Thread(target=revoke, daemon=True)
            observer.start()
            try:
                self.assertTrue(waiting.wait(1))
                with self.assertRaises(gen.GenerationHeld):
                    self.split_write(run, cap, write=lambda _: self.fail("observer permitted another write"))
                revoker.start()
                self.assertTrue(revoked.wait(1), "observer blocked revocation")
            finally:
                resume.set()
                observer.join(1)
                if revoker.ident is not None:
                    revoker.join(1)
            self.assertEqual(outcomes, ["held"])
            self.assertEqual(self.phase(), gen.Phase.ACP_CLAIMED)
        self.check_held()

    def test_deadline_or_metadata_drift_between_write_and_settlement_withholds_sent_proof(self):
        for expired in (False, True):
            with self.subTest(expired=expired):
                self.create_fixture()
                deadline = monotonic() + 5
                with self.launch(deadline=deadline) as run:
                    receipt, evidence = self.split_write(run, run.issue(gen.Operation.ACP))
                    if expired:
                        with patch.object(gen, "monotonic", return_value=deadline), self.assertRaises(gen.GenerationHeld):
                            run.settle(receipt, evidence)
                    else:
                        self.metadata.write_bytes(self.metadata.read_bytes() + b"\n")
                        with self.assertRaises(gen.GenerationHeld):
                            run.settle(receipt, evidence)
                    with self.assertRaises(gen.GenerationHeld):
                        run.acp_sent()
                    self.assertEqual(self.phase(), gen.Phase.ACP_CLAIMED)

    def test_acp_sent_proof_rechecks_durable_bytes_and_stays_revoked_after_restore(self):
        with self.launch(deadline=monotonic() + 5) as run:
            receipt, evidence = self.split_write(run, run.issue(gen.Operation.ACP))
            run.settle(receipt, evidence)
            sent = run.acp_sent()
            state = self.slot / gen._STATE
            valid = state.read_bytes()
            state.write_bytes(valid + b"\n")
            with self.assertRaises(gen.GenerationHeld):
                run.verify_acp_sent(sent)
            state.write_bytes(valid)
            with self.assertRaises(gen.GenerationHeld):
                run.verify_acp_sent(sent)
            with self.assertRaises(gen.GenerationHeld):
                run.issue(gen.Operation.DESTINATION)
        self.check_held()

    def test_scope_exit_and_explicit_revocation_invalidate_outstanding_capability(self):
        for revoke in (False, True):
            with self.subTest(revoke=revoke):
                self.create_fixture()
                with self.launch() as run:
                    capability = run.issue(gen.Operation.ACP)
                    if revoke:
                        run.revoke()
                        with self.assertRaises(gen.GenerationHeld):
                            run.consume(capability, lambda _: self.fail("revoked capability reached effect"))
                with self.assertRaises(gen.GenerationHeld):
                    run.consume(capability, lambda _: self.fail("closed registration lease reached effect"))
                self.check_held()

    def test_effect_reentry_does_not_spend_another_capability(self):
        with self.launch() as run:
            capability = run.issue(gen.Operation.ACP)

            def effect(observe):
                with self.assertRaises(gen.GenerationHeld):
                    run.consume(capability, lambda _: self.fail("reentry repeated effect"))
                with self.assertRaises(gen.GenerationHeld):
                    run.issue(gen.Operation.DESTINATION)
                receipt = observe()
                with self.assertRaises(gen.GenerationHeld):
                    observe()
                return receipt

            run.consume(capability, effect)
            self.assertEqual(self.phase(), gen.Phase.ACP_SENT)

    def test_copy_before_issue_cannot_rewind_the_durable_phase(self):
        with self.launch() as run:
            stale = copy(run)
            first = run.issue(gen.Operation.ACP)
            run.consume(first, lambda observe: observe())
            run.issue(gen.Operation.DESTINATION)
            with self.assertRaises(gen.GenerationHeld):
                stale.issue(gen.Operation.ACP)
            self.assertEqual(self.phase(), gen.Phase.DESTINATION_CLAIMED)

    def test_copy_after_issue_cannot_repeat_effect_or_outlive_the_lease(self):
        effects = []

        def effect(observe):
            effects.append("ran")
            return observe()

        with self.launch() as run:
            first = run.issue(gen.Operation.ACP)
            stale = copy(run)
            run.consume(first, effect)
            with self.assertRaises(gen.GenerationHeld):
                stale.consume(first, effect)
            self.assertEqual(self.phase(), gen.Phase.ACP_SENT)
            second = run.issue(gen.Operation.DESTINATION)
            closed = copy(run)
        with self.assertRaises(gen.GenerationHeld):
            closed.consume(second, effect)
        self.assertEqual(effects, ["ran"])
        self.assertEqual(self.phase(), gen.Phase.DESTINATION_CLAIMED)

    def test_forged_stale_or_revoked_effect_observation_never_settles(self):
        for mode in ("forged", "stale", "revoked"):
            with self.subTest(mode=mode):
                self.create_fixture()
                with self.launch() as run:
                    first = run.issue(gen.Operation.ACP)
                    observed = []

                    def initial(observe):
                        observed.append(observe())
                        return observed[0]

                    run.consume(first, initial)
                    capability = run.issue(gen.Operation.DESTINATION)

                    def effect(observe):
                        receipt = observe()
                        if mode == "stale":
                            return observed[0]
                        if mode == "forged":
                            return replace(receipt)
                        run.revoke()
                        return receipt

                    with self.assertRaises(gen.GenerationHeld):
                        run.consume(capability, effect)
                    self.assertEqual(self.phase(), gen.Phase.DESTINATION_CLAIMED)
                self.check_held()

    def test_authority_loss_after_claim_sync_does_not_issue(self):
        record_save = gen._Files._latch
        with self.launch() as run:
            def latch(files, value):
                record_save(files, value)
                if value == gen._HELD:
                    self.current = None

            with patch.object(gen._Files, "_latch", latch), self.assertRaises(gen.GenerationHeld):
                run.issue(gen.Operation.ACP)
        self.assertEqual(self.phase(), gen.Phase.ACP_CLAIMED)
        self.assertEqual((self.slot / gen._LATCH).read_bytes(), gen._DIRTY)
        self.check_held()

    def test_authority_callback_cannot_swap_the_verified_profile_bytes(self):
        tamper = False

        def authorized(_binding):
            if tamper:
                self.credential.write_bytes(b"changed synthetic bytes")
            return True

        with self.launch(authorized=authorized) as run:
            tamper = True
            with self.assertRaises(gen.GenerationHeld):
                run.issue(gen.Operation.ACP)
        self.assertEqual(self.phase(), gen.Phase.LAUNCH_HELD)
        self.check_held()

    def test_storage_faults_leave_a_dirty_latch_or_park_only_the_generation_latch(self):
        for mode in ("before-temp-fsync", "before-replace", "after-replace", "commit-latch-fsync", "park-latch"):
            with self.subTest(mode=mode):
                self.create_fixture()
                fsync = os.fsync
                replace_file = os.replace
                replaced = False

                def sync(fd):
                    target = Path(os.readlink(f"/proc/self/fd/{fd}"))
                    if mode == "before-temp-fsync" and target.name.startswith(gen._TEMP):
                        raise OSError(errno.EIO, "fixture temporary sync failure")
                    if mode == "after-replace" and replaced and target == self.slot:
                        raise OSError(errno.EIO, "fixture directory sync failure")
                    if (mode == "commit-latch-fsync" and target.name == gen._LATCH
                            and os.pread(fd, 1, 0) == gen._HELD):
                        raise OSError(errno.EIO, "fixture latch commit sync failure")
                    if mode == "park-latch" and target.name == gen._LATCH:
                        raise OSError(errno.EIO, "fixture latch sync failure")
                    return fsync(fd)

                def replace_state(src, dst, **options):
                    nonlocal replaced
                    if mode == "before-replace" and dst == gen._STATE:
                        raise OSError(errno.EIO, "fixture rename failure")
                    replace_file(src, dst, **options)
                    replaced = True

                with (patch.object(os, "fsync", sync), patch.object(os, "replace", replace_state),
                      self.assertRaises(gen.GenerationHeld)):
                    with self.launch():
                        self.fail("failed launch save granted authority")
                if mode == "park-latch":
                    self.assertFalse((self.slot / gen._LATCH).exists())
                    self.assertEqual(len(list(self.slot.glob(gen._PARKED + "*"))), 1)
                else:
                    self.assertEqual((self.slot / gen._LATCH).read_bytes(), gen._DIRTY)
                self.check_held()
                self.check_unchanged()

    def test_lock_acquire_rechecks_owner_after_contention_and_rejects_other_errors(self):
        for code, attempts in ((errno.EAGAIN, 1), (errno.EINTR, 1)):
            with self.subTest(code=code):
                checks = []
                fd = os.open(self.lock, os.O_RDWR)
                self.addCleanup(os.close, fd)

                def authorized():
                    checks.append(True)
                    return len(checks) == 1

                with patch.object(reg.fcntl, "flock", side_effect=OSError(code, "fixture")) as flock:
                    with self.assertRaises((reg.RegistrationUnavailable, OSError)):
                        reg._acquire(fd, authorized=authorized)
                self.assertEqual(flock.call_count, attempts)
                self.assertEqual(len(checks), 2 if code == errno.EAGAIN else 1)

    def test_lock_acquire_does_not_retry_at_the_deadline(self):
        with (patch.object(reg.time, "monotonic", side_effect=(1.0, 1.0, 1.05, 1.075)),
              patch.object(reg.time, "sleep"),
              patch.object(reg.fcntl, "flock", side_effect=BlockingIOError(errno.EAGAIN, "fixture")) as flock):
            with self.assertRaisesRegex(reg.RegistrationUnavailable, "busy"):
                reg._acquire(0)
        self.assertEqual(flock.call_count, 1)

    def test_killed_holder_blocks_same_writer_after_kernel_lock_is_released(self):
        for target in tuple(gen.Phase)[1:]:
            with self.subTest(phase=target):
                self.create_fixture()
                self.journal.fixture_writer(1)
                with self.assertRaises(gen.GenerationHeld):
                    # The parent owns the immutable receipt independently of both children.
                    gen.GenerationJournal(self.registration, replace(self.anchor, authority=self.anchor.latch)).status()
                live = self._fork_holder(target)
                try:
                    self.assertEqual(self.phase(), target)
                    with self.assertRaises(gen.GenerationHeld):
                        self.journal.fixture_writer(2)
                finally:
                    os.kill(live, signal.SIGKILL)
                    _, status = os.waitpid(live, 0)
                self.assertEqual(os.waitstatus_to_exitcode(status), -signal.SIGKILL)
                reopened = os.fork()
                if reopened == 0:
                    try:
                        self.check_held()
                        self.check_unchanged()
                    except BaseException:
                        os._exit(1)
                    os._exit(0)
                _, status = os.waitpid(reopened, 0)
                self.assertEqual(os.waitstatus_to_exitcode(status), 0)
                self.assertEqual(self.phase(), target)
                self.assertFalse((self.slot / "fixture-writer-2").exists())

    def test_killed_split_holder_blocks_restart_before_or_after_each_actual_write(self):
        for operation in _STEPS:
            target = gen._STEPS[operation][1]
            for boundary in ("claimed", "written"):
                with self.subTest(operation=operation, boundary=boundary):
                    self.create_fixture()
                    self.journal.fixture_writer(1)
                    holder = self._fork_holder(target, split_boundary=boundary)
                    try:
                        self.assertEqual(self.phase(), target)
                    finally:
                        os.kill(holder, signal.SIGKILL)
                        self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(holder, 0)[1]), -signal.SIGKILL)
                    self.check_held()
                    self.check_unchanged()

    def _fork_holder(self, target, *, split_boundary=None):
        source, ready = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(source)
            try:
                deadline = monotonic() + 10 if split_boundary is not None else None
                with self.launch(deadline=deadline) as run:
                    if split_boundary is None:
                        self._advance_to(run, target)
                    else:
                        self._advance_split(run, target, split_boundary)
                    os.write(ready, b"!")
                    signal.pause()
            except BaseException:
                os._exit(1)
            os._exit(0)
        os.close(ready)
        try:
            readable, _, _ = select.select([source], [], [], _DEADLINE)
            self.assertTrue(readable and os.read(source, 1) == b"!")
            return pid
        except BaseException:
            with suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            raise
        finally:
            os.close(source)

    def _advance_to(self, run, target):
        if target is gen.Phase.LAUNCH_HELD:
            return
        for operation in _STEPS:
            capability = run.issue(operation)
            if self.phase() is target:
                return
            run.consume(capability, lambda observe: observe())
            if self.phase() is target:
                return
        self.fail("holder did not reach requested phase")

    def _advance_split(self, run, target, boundary):
        for operation in _STEPS:
            cap = run.issue(operation)
            selected = self.phase() is target
            if selected and boundary == "claimed":
                return
            reader, writer = os.pipe()
            try:
                receipt, evidence = self.split_write(run, cap, write=lambda data: os.write(writer, data))
                actual = os.read(reader, receipt.byte_count)
                self.assertEqual(gen._digest(actual), receipt.packet_sha256)
            finally:
                os.close(writer)
                os.close(reader)
            if selected:
                return
            run.settle(receipt, evidence)
        self.fail("holder did not reach requested split write boundary")
