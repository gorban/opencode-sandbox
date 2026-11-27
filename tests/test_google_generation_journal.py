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
from threading import RLock
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

    def launch(self, *, authorized=None):
        owner = authorized if authorized is not None else lambda binding: self.current is binding
        return self.journal.launch(self.binding, fence=self.fence, authorized=owner)

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

    def _fork_holder(self, target):
        source, ready = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(source)
            try:
                with self.launch() as run:
                    self._advance_to(run, target)
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
