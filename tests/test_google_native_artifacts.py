"""Check exact native build staging without executing an artifact."""

import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from oc_google import native_artifacts


class NativeBuildStagingTest(unittest.TestCase):
    def setUp(self):
        root = Path(self.enterContext(TemporaryDirectory()))
        self.source = root / "source"
        self.output = root / "destination"
        self.source.mkdir(mode=0o700)
        self.output.mkdir(mode=0o700)
        self.files = {"agy_acp_server.par": b"synthetic native", "localharness_external": b"synthetic companion"}
        for name, data in self.files.items():
            (self.source / name).write_bytes(data)
        pins = {name: (len(data), hashlib.sha256(data).hexdigest()) for name, data in self.files.items()}
        self.enterContext(patch.object(native_artifacts, "_PINNED", pins))

    def test_stages_both_pins_and_returns_stable_build_identity(self):
        result = native_artifacts.stage_standalone(self.source, self.output)
        self.assertEqual(result.entrypoint, self.output / "agy_acp_server.par")
        self.assertRegex(result.digest, r"^[0-9a-f]{64}$")
        for name, data in self.files.items():
            staged = self.output / name
            self.assertEqual(staged.read_bytes(), data)
            self.assertEqual(staged.stat().st_mode & 0o777, 0o500)
        second = self.output.parent / "second"
        second.mkdir(mode=0o700)
        self.assertEqual(native_artifacts.stage_standalone(self.source, second).digest, result.digest)

    def test_wrong_same_length_companion_cannot_qualify_the_build(self):
        (self.source / "localharness_external").write_bytes(b"x" * len(self.files["localharness_external"]))
        with self.assertRaisesRegex(native_artifacts.NativeArtifactError, "did not match"):
            native_artifacts.stage_standalone(self.source, self.output)

    def test_symlink_and_group_writable_members_are_refused(self):
        artifact = self.source / "agy_acp_server.par"
        artifact.chmod(0o620)
        with self.assertRaises(native_artifacts.NativeArtifactError):
            native_artifacts.stage_standalone(self.source, self.output)
        artifact.unlink()
        artifact.symlink_to(self.source / "localharness_external")
        with self.assertRaises(native_artifacts.NativeArtifactError):
            native_artifacts.stage_standalone(self.source, self.output)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_refuses_populated_or_symlink_staging_without_overwrite(self):
        existing = self.output / "agy_acp_server.par"
        existing.write_bytes(b"leave alone")
        with self.assertRaises(native_artifacts.NativeArtifactError):
            native_artifacts.stage_standalone(self.source, self.output)
        linked = self.output.parent / "alias"
        linked.symlink_to(self.output, target_is_directory=True)
        with self.assertRaises(native_artifacts.NativeArtifactError):
            native_artifacts.stage_standalone(self.source, linked)
        self.assertEqual(existing.read_bytes(), b"leave alone")
