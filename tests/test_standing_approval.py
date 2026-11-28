"""Scratch-filesystem tests for the host-only standing approval writer."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch

from oc_providers import standing_approval as approval
from oc_providers.standing_approval import (
    ApprovalAuthority,
    Foreground,
    Publication,
    StandingApprovalError,
    StandingApprovalStore,
)


ORIGINAL_CONFIG = b"[launch]\nmini = false\n"
NEW_CONFIG = b"[launch]\nmini = true\n"
AUTHORITY = ApprovalAuthority(
    "1" * 64, "2" * 64, (("openai", "harbor", "a" * 32), ("openai", "meridian", "b" * 32)),
)
RELINKED = ApprovalAuthority(
    "1" * 64, "2" * 64, (("openai", "harbor", "c" * 32), ("openai", "meridian", "b" * 32)),
)
CHANGED_PLACEMENT = ApprovalAuthority("1" * 64, "3" * 64, AUTHORITY.lineages)
CHANGED_DELEGATION = ApprovalAuthority("4" * 64, "2" * 64, AUTHORITY.lineages)


def live():
    return Foreground.LIVE


class StandingApprovalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.config_dir = root / "config"
        self.config_dir.mkdir(mode=0o700)
        self.state_dir = root / "state"
        self.state_dir.mkdir(mode=0o700)
        self.config = self.config_dir / "providers.toml"
        self.config.write_bytes(ORIGINAL_CONFIG)
        self.receipt = self.state_dir / "standing-approval.json"
        self.lock = self.state_dir / "standing-approval.lock"
        self.sandbox_dir = root / "sandbox"
        self.sandbox_dir.mkdir(mode=0o700)
        self.store = self.make_store()

    def make_store(self):
        return StandingApprovalStore(
            config_dir=self.config_dir, state_dir=self.state_dir, sandbox_dir=self.sandbox_dir,
        )

    @staticmethod
    def fence(authority):
        @contextmanager
        def resolve(_snapshot):
            yield authority
        return resolve

    def commit(self, expected, authority=AUTHORITY, *, observed=None, checkpoint=live):
        return self.store.commit(
            expected, authority, authority_fence=self.fence(observed or authority), checkpoint=checkpoint,
        )

    def assert_refusal(self, action, code, publication=Publication.UNCHANGED):
        with self.assertRaises(StandingApprovalError) as raised:
            action()
        self.assertEqual(raised.exception.code, code)
        self.assertIs(raised.exception.publication, publication)

    def test_write_then_fresh_reuse_requires_exact_current_authority(self):
        observed = self.store.observe()
        self.assertIsNone(observed.receipt)
        stored = self.commit(observed)
        self.assertTrue(stored.covers(AUTHORITY))
        raw = self.receipt.read_bytes()
        self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(ORIGINAL_CONFIG.strip(), raw)
        reread = self.make_store().observe()
        self.assertEqual(reread, stored)
        self.assertEqual(self.store.verify_admission(
            reread, AUTHORITY, authority_fence=self.fence(AUTHORITY), checkpoint=live,
        ), stored)
        self.assertEqual(self.receipt.read_bytes(), raw)
        for authority in (RELINKED, CHANGED_PLACEMENT, CHANGED_DELEGATION):
            with self.subTest(authority=authority):
                self.assert_refusal(lambda: self.store.verify_admission(
                    stored, AUTHORITY, authority_fence=self.fence(authority), checkpoint=live,
                ), "approval_authority_changed")
        renewed = self.commit(reread, RELINKED)
        self.assertNotEqual(renewed.receipt.revision, stored.receipt.revision)
        self.assertTrue(renewed.covers(RELINKED))

    def test_overlapping_writers_reject_identical_and_different_stale_proposals(self):
        for second_authority in (AUTHORITY, CHANGED_DELEGATION):
            with self.subTest(second_authority=second_authority):
                paused = threading.Barrier(2, timeout=3)
                decided = threading.Event()

                def writer_one():
                    expected = self.make_store().observe()
                    paused.wait()
                    try:
                        return self.commit(expected)
                    finally:
                        decided.set()

                def writer_two():
                    store = self.make_store()
                    expected = store.observe()
                    paused.wait()
                    self.assertTrue(decided.wait(3))
                    self.assert_refusal(
                        lambda: store.commit(expected, second_authority,
                                             authority_fence=self.fence(second_authority), checkpoint=live),
                        "approval_snapshot_changed",
                    )

                with ThreadPoolExecutor(max_workers=2) as threads:
                    winning = threads.submit(writer_one)
                    losing = threads.submit(writer_two)
                    self.assertEqual(winning.result(4), self.store.observe())
                    losing.result(4)

    def test_lock_is_bounded_and_shared_with_managed_config_writer(self):
        expected = self.store.observe()
        with self.lock.open("r+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.object(approval, "_LOCK_WAIT_SECONDS", 0.02):
                self.assert_refusal(lambda: self.commit(expected), "approval_storage_busy")
                self.assert_refusal(
                    lambda: self.store.replace_config(expected, NEW_CONFIG, checkpoint=live),
                    "approval_storage_busy",
                )
        installed = self.store.replace_config(expected, NEW_CONFIG, checkpoint=live)
        self.assertEqual(installed.config_bytes, NEW_CONFIG)
        self.assert_refusal(lambda: self.commit(expected), "approval_snapshot_changed")
        self.assertEqual(self.store.observe(), installed)
        self.assertFalse(self.receipt.exists())
        self.assertEqual(self.commit(installed).config_bytes, NEW_CONFIG)

    def test_managed_initial_config_and_approval_use_same_permanent_lock(self):
        self.config.unlink()
        empty = self.store.observe()
        lock_stat = self.lock.stat()
        self.assertIsNone(empty.config_bytes)
        self.assert_refusal(lambda: self.commit(empty), "approval_config_missing")
        configured = self.store.replace_config(empty, ORIGINAL_CONFIG, checkpoint=live)
        self.assertIsNone(configured.receipt)
        approved = self.commit(configured)
        self.assertTrue(approved.covers(AUTHORITY))
        after = self.store.replace_config(approved, NEW_CONFIG, checkpoint=live)
        self.assertEqual(after.receipt, approved.receipt)
        self.assertFalse(after.covers(AUTHORITY))
        self.assertTrue(os.path.samestat(lock_stat, self.lock.stat()))

    def test_config_change_during_prompt_including_same_bytes_replacement(self):
        for data in (NEW_CONFIG, ORIGINAL_CONFIG):
            with self.subTest(data=data):
                self.config.write_bytes(ORIGINAL_CONFIG)
                expected = self.store.observe()
                replacement = self.config.with_suffix(".replacement")
                replacement.write_bytes(data)
                replacement.replace(self.config)
                self.assert_refusal(lambda: self.commit(expected), "approval_snapshot_changed")
                self.assertFalse(self.receipt.exists())

    def test_out_of_band_config_edit_before_and_after_atomic_publication(self):
        previous = self.commit(self.store.observe())
        raw = self.receipt.read_bytes()

        @contextmanager
        def modifying_fence(_snapshot):
            self.config.write_bytes(NEW_CONFIG)
            yield AUTHORITY

        self.assert_refusal(lambda: self.store.commit(
            previous, AUTHORITY, authority_fence=modifying_fence, checkpoint=live,
        ), "approval_snapshot_changed")
        self.assertEqual(self.receipt.read_bytes(), raw)
        self.config.write_bytes(ORIGINAL_CONFIG)
        fresh = self.store.observe()
        real_replace = os.replace

        def edit_after_replace(source, destination, **kwargs):
            real_replace(source, destination, **kwargs)
            self.config.write_bytes(NEW_CONFIG)

        with patch.object(approval.os, "replace", side_effect=edit_after_replace):
            self.assert_refusal(lambda: self.commit(fresh),
                                "approval_snapshot_changed", Publication.PUBLISHED)
        self.assertFalse(self.store.observe().covers(AUTHORITY))
        self.assertEqual(self.store.observe().receipt.config_digest, fresh.config_digest)

    def config_edit_checkpoint(self, *, on_check, replace_file):
        checks = 0
        edited = []

        def checkpoint():
            nonlocal checks
            checks += 1
            if checks == on_check:
                before = self.config.read_bytes()
                if replace_file:
                    replacement = self.config.with_suffix(".external")
                    replacement.write_bytes(before)
                    replacement.replace(self.config)
                else:
                    self.config.write_bytes(b"[launch]\nmini = false\n# external save\n")
                edited.append((before, self.config.read_bytes(), self.config.stat()))
            return Foreground.LIVE

        return checkpoint, edited

    def assert_external_config_preserved(self, edited, *, before=ORIGINAL_CONFIG):
        self.assertEqual(len(edited), 1)
        original, data, info = edited[0]
        self.assertEqual(original, before)
        self.assertEqual(self.config.read_bytes(), data)
        self.assertTrue(os.path.samestat(self.config.stat(), info))

    def test_commit_preserves_prior_receipt_during_prepublication_checkpoint(self):
        for replace_file in (False, True):
            with self.subTest(replace_file=replace_file):
                self.config.write_bytes(ORIGINAL_CONFIG)
                approved = self.commit(self.store.observe())
                prior = self.receipt.read_bytes()
                prior_info = self.receipt.stat()
                checkpoint, edited = self.config_edit_checkpoint(on_check=1, replace_file=replace_file)
                self.assert_refusal(lambda: self.commit(approved, CHANGED_DELEGATION, checkpoint=checkpoint),
                                    "approval_snapshot_changed", Publication.UNCHANGED)
                self.assert_external_config_preserved(edited)
                self.assertEqual(self.receipt.read_bytes(), prior)
                self.assertTrue(os.path.samestat(self.receipt.stat(), prior_info))
                self.assertEqual(list(self.state_dir.glob(".standing-*")), [])

    def test_commit_refuses_config_drift_during_final_checkpoint(self):
        for replace_file in (False, True):
            with self.subTest(replace_file=replace_file):
                self.config.write_bytes(ORIGINAL_CONFIG)
                current = self.commit(self.store.observe())
                checkpoint, edited = self.config_edit_checkpoint(on_check=2, replace_file=replace_file)
                self.assert_refusal(lambda: self.commit(current, CHANGED_DELEGATION, checkpoint=checkpoint),
                                    "approval_snapshot_changed", Publication.PUBLISHED)
                self.assert_external_config_preserved(edited)
                published = self.store.observe()
                self.assertNotEqual(published.receipt.revision, current.receipt.revision)
                self.assertEqual(published.receipt.config_digest, current.config_digest)
                self.assertEqual(published.receipt.authority, CHANGED_DELEGATION)

    def test_verify_admission_refuses_config_drift_during_final_checkpoint(self):
        for replace_file in (False, True):
            with self.subTest(replace_file=replace_file):
                self.config.write_bytes(ORIGINAL_CONFIG)
                approved = self.commit(self.store.observe())
                prior = self.receipt.read_bytes()
                prior_info = self.receipt.stat()
                checkpoint, edited = self.config_edit_checkpoint(on_check=1, replace_file=replace_file)
                self.assert_refusal(lambda: self.store.verify_admission(
                    approved, AUTHORITY, authority_fence=self.fence(AUTHORITY), checkpoint=checkpoint,
                ), "approval_snapshot_changed")
                self.assert_external_config_preserved(edited)
                self.assertEqual(self.receipt.read_bytes(), prior)
                self.assertTrue(os.path.samestat(self.receipt.stat(), prior_info))

    def test_replace_config_preserves_external_save_during_prepublication_checkpoint(self):
        for replace_file in (False, True):
            with self.subTest(replace_file=replace_file):
                self.config.write_bytes(ORIGINAL_CONFIG)
                approved = self.commit(self.store.observe())
                prior = self.receipt.read_bytes()
                checkpoint, edited = self.config_edit_checkpoint(on_check=1, replace_file=replace_file)
                self.assert_refusal(lambda: self.store.replace_config(approved, NEW_CONFIG, checkpoint=checkpoint),
                                    "approval_snapshot_changed")
                self.assert_external_config_preserved(edited)
                self.assertEqual(self.receipt.read_bytes(), prior)

    def test_replace_config_refuses_config_drift_during_final_checkpoint(self):
        for replace_file in (False, True):
            with self.subTest(replace_file=replace_file):
                self.config.write_bytes(ORIGINAL_CONFIG)
                approved = self.commit(self.store.observe())
                prior = self.receipt.read_bytes()
                checkpoint, edited = self.config_edit_checkpoint(on_check=2, replace_file=replace_file)
                self.assert_refusal(lambda: self.store.replace_config(approved, NEW_CONFIG, checkpoint=checkpoint),
                                    "approval_snapshot_changed", Publication.PUBLISHED)
                self.assert_external_config_preserved(edited, before=NEW_CONFIG)
                self.assertEqual(self.receipt.read_bytes(), prior)

    def test_authority_changes_during_owner_prompt_leave_prior_receipt_untouched(self):
        current = self.commit(self.store.observe())
        for authority in (RELINKED, CHANGED_PLACEMENT, CHANGED_DELEGATION):
            with self.subTest(authority=authority):
                self.assert_refusal(
                    lambda: self.commit(current, observed=authority), "approval_authority_changed",
                )
                self.assertEqual(self.store.observe(), current)

    def test_replaced_identical_receipt_and_replaced_lock_refuse_pending_decision(self):
        current = self.commit(self.store.observe())
        replacement = self.receipt.with_suffix(".replacement")
        replacement.write_bytes(self.receipt.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(self.receipt)
        self.assert_refusal(lambda: self.commit(current), "approval_snapshot_changed")
        current = self.store.observe()
        replacement_lock = self.lock.with_suffix(".replacement")
        replacement_lock.touch(mode=0o600)
        replacement_lock.replace(self.lock)
        self.assert_refusal(lambda: self.commit(current), "approval_snapshot_changed")
        self.lock.unlink()
        self.assert_refusal(self.store.observe, "approval_lock_missing")

    def test_owner_loss_and_cancellation_before_and_after_rename(self):
        current = self.commit(self.store.observe())
        for state, code in ((Foreground.CANCELLED, "approval_cancelled"),
                            (Foreground.OWNER_LOST, "approval_owner_lost")):
            with self.subTest(state=state):
                before = self.receipt.read_bytes()
                self.assert_refusal(lambda: self.commit(current, checkpoint=lambda: state), code)
                self.assertEqual(self.receipt.read_bytes(), before)
                self.assertEqual(list(self.state_dir.glob(".standing-*")), [])
                checkpoints = iter((Foreground.LIVE, state))
                self.assert_refusal(lambda: self.commit(current, CHANGED_DELEGATION,
                                                       checkpoint=lambda: next(checkpoints)),
                                    code, Publication.PUBLISHED)
                current = self.store.observe()
                self.assertTrue(current.covers(CHANGED_DELEGATION))
                self.assertNotEqual(self.receipt.read_bytes(), before)
                self.assert_refusal(
                    lambda: self.store.verify_admission(
                        current, CHANGED_DELEGATION, authority_fence=self.fence(CHANGED_DELEGATION),
                        checkpoint=lambda: state,
                    ), code,
                )

    def test_failed_file_sync_leaves_old_receipt_in_force(self):
        current = self.commit(self.store.observe())
        with patch.object(approval.os, "fsync", side_effect=OSError):
            self.assert_refusal(lambda: self.commit(current, CHANGED_DELEGATION),
                                "approval_storage_unavailable")
        self.assertEqual(self.store.observe(), current)
        self.assertEqual(list(self.state_dir.glob(".standing-*")), [])

    def test_directory_sync_uncertainty_requires_fresh_durable_verification(self):
        current = self.store.observe()
        real_sync = os.fsync

        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("injected directory fsync failure")
            real_sync(fd)

        with patch.object(approval.os, "fsync", side_effect=fail_directory):
            self.assert_refusal(lambda: self.commit(current),
                                "approval_storage_unavailable", Publication.UNCERTAIN)
            observed = self.store.observe()
            self.assertTrue(observed.covers(AUTHORITY))
            self.assert_refusal(
                lambda: self.store.verify_admission(
                    observed, AUTHORITY, authority_fence=self.fence(AUTHORITY), checkpoint=live,
                ), "approval_storage_unavailable",
            )
        self.assertEqual(self.store.verify_admission(
            observed, AUTHORITY, authority_fence=self.fence(AUTHORITY), checkpoint=live,
        ), observed)

    def test_corrupt_or_untrusted_entries_fail_closed(self):
        current = self.commit(self.store.observe())
        encoded = self.receipt.read_bytes()
        invalid_records = (
            b"{}\n",
            encoded.replace(b'"version":1', b'"version":true'),
            encoded.replace(b'"version":1', b'"version":1,"version":1'),
            encoded.replace(b'"harbor"', b'"meridian"'),
            encoded.replace(b'"version":1', b'"version":1,"unexpected":"ignored"'),
        )
        for record in invalid_records:
            with self.subTest(record=record):
                self.receipt.write_bytes(record)
                self.assert_refusal(lambda: self.commit(current), "approval_corrupt_receipt")
        self.receipt.write_bytes(encoded)
        self.receipt.chmod(0o644)
        self.assert_refusal(self.store.observe, "approval_untrusted_file")
        self.receipt.chmod(0o600)
        link = self.receipt.with_suffix(".hardlink")
        os.link(self.receipt, link)
        self.assert_refusal(self.store.observe, "approval_untrusted_file")
        self.receipt.unlink()
        self.receipt.symlink_to(link)
        self.assert_refusal(self.store.observe, "approval_storage_unavailable")
        self.receipt.unlink()
        os.mkfifo(self.receipt, 0o600)
        self.assert_refusal(self.store.observe, "approval_untrusted_file")
        self.receipt.unlink()
        self.receipt.write_bytes(b"x" * (approval._MAX_RECEIPT_BYTES + 1))
        self.receipt.chmod(0o600)
        self.assert_refusal(self.store.observe, "approval_file_too_large")

    def test_directory_replacement_refuses_pending_decision(self):
        observed = self.store.observe()
        self.config_dir.rename(self.config_dir.with_name("old-config"))
        self.config_dir.mkdir(mode=0o700)
        self.config.write_bytes(ORIGINAL_CONFIG)
        self.assert_refusal(lambda: self.commit(observed), "approval_snapshot_changed")
        observed = self.store.observe()
        self.state_dir.rename(self.state_dir.with_name("old-state"))
        self.state_dir.mkdir(mode=0o700)
        self.assert_refusal(lambda: self.commit(observed), "approval_snapshot_changed")
        self.assertFalse(self.receipt.exists())

    def test_reject_untrusted_state_directory_and_config_symlink(self):
        self.state_dir.chmod(0o750)
        self.assert_refusal(self.store.observe, "approval_untrusted_directory")
        self.state_dir.chmod(0o700)
        self.config.unlink()
        self.config.symlink_to(self.sandbox_dir / "providers.toml")
        self.assert_refusal(self.store.observe, "approval_storage_unavailable")


if __name__ == "__main__":
    unittest.main()
