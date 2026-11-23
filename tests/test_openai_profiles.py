"""Isolated tests for the local saved OpenAI registration registry."""

import os
from pathlib import Path
import pwd
from tempfile import TemporaryDirectory
import unittest
from uuid import UUID

from oc_openai.profiles import ProfileError, Profiles, RegistryView


class ProfilesTests(unittest.TestCase):
    def setUp(self):
        home = pwd.getpwuid(os.getuid()).pw_dir
        scratch = self.enterContext(TemporaryDirectory(dir=home))
        self.root = Path(scratch) / "openai"
        self.profiles = Profiles(self.root)

    def save(self, label, client):
        candidate = self.profiles.begin(label)
        with self.profiles.publish(candidate, client):
            pass
        return self.profiles.selected()

    def test_status_is_read_only_and_one_installation_id_survives_opening_again(self):
        self.assertEqual(self.profiles.snapshot(), RegistryView((), None))
        self.assertFalse(self.root.exists())
        personal = self.save("personal", "issued-one")
        self.assertTrue(personal.host_id.startswith("urn:uuid:"))
        self.assertEqual(UUID(personal.host_id).version, 4)
        self.assertFalse(personal.directory.exists())
        self.assertEqual(personal.directory.parent, self.root / "registrations")
        self.assertNotIn("personal", str(personal.directory))

        self.profiles = Profiles(self.root)
        work = self.save("Work_2", "issued-two")
        self.assertNotEqual(personal.directory, work.directory)
        self.assertEqual(personal.host_id, work.host_id)
        self.assertNotEqual(personal.epoch, work.epoch)
        self.assertEqual([profile.label for profile in self.profiles.list()], ["Work_2", "personal"])
        self.assertEqual(self.profiles.selected(), work)
        for name in ("state.lock", "state.json", "foreground.lock"):
            self.assertEqual((self.root / "profiles" / name).stat().st_mode & 0o777, 0o600)

    def test_duplicate_client_and_changed_returning_client_preserve_selection(self):
        personal = self.save("personal", "issued-one")
        for label in ("other", "personal"):
            with self.subTest(label=label):
                candidate = self.profiles.begin(label)
                client = "issued-one" if label == "other" else "issued-two"
                with self.assertRaisesRegex(ProfileError, "^profile_client_conflict$"):
                    with self.profiles.publish(candidate, client):
                        self.fail("conflicting client reached local publication")
                self.assertEqual(self.profiles.selected(), personal)
        candidate = self.profiles.begin("personal")
        self.assertEqual(candidate.profile.client_id, "issued-one")
        self.assertEqual(candidate.profile.directory, personal.directory)
        with self.profiles.publish(candidate, "issued-one"):
            pass

    def test_selection_epoch_rejects_candidate_even_after_target_return(self):
        self.save("personal", "issued-one")
        work = self.save("work", "issued-two")
        candidate = self.profiles.begin("other")
        self.profiles.select("personal", lambda *_: None)
        self.profiles.select("work", lambda *_: None)
        self.assertNotEqual(work.epoch, self.profiles.selected().epoch)
        with self.assertRaisesRegex(ProfileError, "^profile_stale$"):
            with self.profiles.publish(candidate, "issued-three"):
                self.fail("stale epoch reached publication")
        self.assertEqual(self.profiles.selected().label, "work")

    def test_only_current_pending_generation_can_publish_or_be_abandoned(self):
        stale = self.profiles.begin("personal")
        current = self.profiles.begin("personal")
        self.assertEqual(stale.profile, current.profile)
        self.assertNotEqual(stale.pending_generation, current.pending_generation)
        self.profiles.abandon(stale)
        with self.assertRaisesRegex(ProfileError, "^profile_stale$"):
            with self.profiles.publish(stale, "issued-one"):
                self.fail("stale attempt reached publication")
        with self.profiles.publish(current, "issued-one"):
            pass
        self.assertEqual(self.profiles.selected().label, "personal")
        pending = self.profiles.begin("personal")
        self.profiles.abandon(pending)
        with self.assertRaisesRegex(ProfileError, "^profile_stale$"):
            with self.profiles.publish(pending, "issued-one"):
                self.fail("abandoned attempt reached publication")

    def test_abandoned_first_attempt_keeps_opaque_directory_for_local_recovery(self):
        candidate = self.profiles.begin("personal")
        self.profiles.abandon(candidate)
        self.assertEqual(self.profiles.snapshot(), RegistryView((), None))
        retry = self.profiles.begin("personal")
        self.assertEqual(retry.profile.directory, candidate.profile.directory)
        self.assertEqual(retry.profile.host_id, candidate.profile.host_id)
        self.assertNotEqual(retry.pending_generation, candidate.pending_generation)
        with self.profiles.publish(retry, "issued-one"):
            pass
        self.assertEqual(self.profiles.selected().client_id, "issued-one")

    def test_selection_and_publication_are_busy_but_disconnect_fences_immediately(self):
        personal = self.save("personal", "issued-one")
        other = Profiles(self.root)
        pending = other.begin("work")
        with self.profiles.foreground():
            with self.assertRaisesRegex(ProfileError, "^profile_busy$"):
                other.select("personal", lambda *_: self.fail("selection callback while busy"))
            with self.assertRaisesRegex(ProfileError, "^profile_busy$"):
                with other.publish(pending, "issued-two"):
                    self.fail("publication while busy")
            retired = other.begin_disconnect(lambda profile: None)
            self.assertEqual(retired.label, personal.label)
            self.assertNotEqual(retired.epoch, personal.epoch)
            self.assertTrue(other.selected().retiring)
        self.assertTrue(other.begin_disconnect(lambda profile: None).retiring)
        with self.assertRaisesRegex(ProfileError, "^profile_stale$"):
            with other.publish(pending, "issued-two"):
                self.fail("publication with a retired epoch")
        with self.assertRaisesRegex(ProfileError, "^profile_retiring$"):
            other.select("personal", lambda *_: self.fail("selected a retiring registration"))
        reconnected = self.save("personal", "issued-one")
        self.assertFalse(reconnected.retiring)
        self.assertEqual(reconnected.directory, personal.directory)

    def test_disconnect_invalidates_pending_first_connection(self):
        pending = self.profiles.begin("personal")
        self.assertIsNone(self.profiles.begin_disconnect(lambda profile: None))
        with self.assertRaisesRegex(ProfileError, "^profile_stale$"):
            with self.profiles.publish(pending, "issued-one"):
                self.fail("disconnected installation accepted stale connect")
        self.assertEqual(self.profiles.snapshot(), RegistryView((), None))

    def test_failed_local_gates_preserve_previous_selection(self):
        personal = self.save("personal", "issued-one")
        work = self.save("work", "issued-two")
        self.profiles.select("personal", lambda *_: None)
        previous = self.profiles.selected()

        def refuse(old, proposed):
            self.assertEqual((old.directory, proposed.directory), (personal.directory, work.directory))
            raise RuntimeError("local precondition fixture")

        with self.assertRaisesRegex(RuntimeError, "local precondition fixture"):
            self.profiles.select("work", refuse)
        candidate = self.profiles.begin("work")
        with self.assertRaisesRegex(RuntimeError, "local precondition fixture"):
            with self.profiles.publish(candidate, "issued-two", refuse):
                self.fail("publication body reached despite local precondition")
        with self.assertRaisesRegex(RuntimeError, "local write fixture"):
            with self.profiles.publish(candidate, "issued-two"):
                raise RuntimeError("local write fixture")
        self.assertEqual(self.profiles.selected(), previous)

    def test_rejects_untrusted_storage_and_bounds_registration_inventory(self):
        for label in ("", "../escaped", "x" * 33, "newline\n", "ü"):
            with self.assertRaisesRegex(ProfileError, "^profile_invalid_label$"):
                self.profiles.begin(label)
        for index in range(16):
            self.profiles.begin(f"label-{index}")
        with self.assertRaisesRegex(ProfileError, "^profile_limit$"):
            self.profiles.begin("extra")
        lock = self.root / "profiles" / "foreground.lock"
        state = self.root / "profiles" / "state.json"
        lock.symlink_to(state)
        with self.assertRaisesRegex(ProfileError, "^profile_storage_unavailable$"):
            with self.profiles.foreground():
                self.fail("followed an untrusted lock path")
        state.chmod(0o644)
        with self.assertRaisesRegex(ProfileError, "^profile_storage_unavailable$"):
            self.profiles.snapshot()


if __name__ == "__main__":
    unittest.main()
