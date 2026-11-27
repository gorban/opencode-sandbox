"""Check bridge staging using scratch files and a fake editor."""

import json
import os
from pathlib import Path
import runpy
import shutil
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

BRIDGE = sys.argv[1]


class StagingTests(unittest.TestCase):
    def setUp(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.sandbox = root / "sandbox"
        self.sandbox.mkdir()
        self.stage = root / "stage"
        self.enterContext(patch.dict(os.environ, {
            "HOME": str(root), "OC_SB": str(self.sandbox),
            "OC_BRIDGE_STAGE": str(self.stage), "OC_CODE_BIN": "/fake/code",
            "OC_BCOMPARE_BIN": "/fake/bcompare",
            "OC_BRIDGE_BLOCKING_TOOLS": "code,bcompare",
        }))
        self.bridge = runpy.run_path(BRIDGE)["run_session"].__globals__

    def put(self, relative, content="original"):
        path = self.sandbox / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def select(self, tool, *paths):
        return self.bridge["stage_request"](tool, ["/sandbox/" + path for path in paths])

    def test_same_basename_uses_separate_slots_and_writes_back(self):
        left = self.put("left/item.txt", "left initial")
        right = self.put("right/item.txt", "right initial")
        session = Path(self.select("code", "left/item.txt", "right/item.txt"))

        def edit(argv, **options):
            self.assertEqual(argv, ["/fake/code", "--wait", "--", "./files/1/item.txt", "./files/2/item.txt"])
            workdir = Path(options.get("cwd", "."))
            self.assertEqual(workdir, session)
            first, second = (workdir / operand for operand in argv[-2:])
            self.assertNotEqual(first.parent, second.parent)
            self.assertEqual(first.parent.parent, session / "files")
            self.assertEqual(second.parent.parent, session / "files")
            self.assertEqual({first.parent.name, second.parent.name}, {"1", "2"})
            self.assertEqual(first.name, second.name)
            self.assertEqual(first.read_text(encoding="utf-8"), "left initial")
            self.assertEqual(second.read_text(encoding="utf-8"), "right initial")
            first.write_text("left edited", encoding="utf-8")
            replacement = second.with_suffix(".tmp")
            replacement.write_text("right edited atomically", encoding="utf-8")
            replacement.replace(second)
            proc = MagicMock()
            proc.poll.return_value = 0
            return proc

        with patch("subprocess.Popen", side_effect=edit) as launch:
            self.bridge["run_session"](str(session))
        launch.assert_called_once()
        self.assertEqual(left.read_text(encoding="utf-8"), "left edited")
        self.assertEqual(right.read_text(encoding="utf-8"), "right edited atomically")
        self.assertFalse(session.exists())

    def test_direct_selection_refuses_metadata_and_its_descendants(self):
        for name in ("fixture.Code-Workspace", "fixture.BCPKG", "fixture.bcs", "fixture.bcss",
                     "HEAD", ".git", ".VsCoDe/sub/plain.txt"):
            with self.subTest(name=name):
                self.put(name)
                self.assertIsNone(self.select("bcompare", name))
        self.assertEqual(list(self.stage.iterdir()), [])

    def test_folder_copy_preserves_layout_and_prunes_metadata(self):
        self.put("tree/nested/ordinary.txt")
        self.put("tree/nested/.GiT/note.txt")
        self.put("tree/nested/HEAD")
        self.put("tree/nested/.vscode/ordinary.txt")
        self.put("tree/nested/fixture.bcpkg")
        session = Path(self.select("bcompare", "tree"))

        def inspect(argv, **options):
            self.assertEqual(argv, ["/fake/bcompare", "-solo", "./files/1"])
            snapshot = Path(options["cwd"]) / argv[-1]
            self.assertEqual(
                {str(path.relative_to(snapshot)) for path in snapshot.rglob("*")},
                {"nested", "nested/ordinary.txt"},
            )
            self.assertEqual((snapshot / "nested/ordinary.txt").read_text(encoding="utf-8"), "original")
            proc = MagicMock()
            proc.poll.return_value = 0
            return proc

        with patch("subprocess.Popen", side_effect=inspect) as launch:
            self.bridge["run_session"](str(session))
        launch.assert_called_once()

    def test_editor_operands_use_safe_names_and_write_to_distinct_sources(self):
        first = self.put("left/Quarterly draft.txt")
        second = self.put("right/Résumé.txt")
        session = Path(self.select("bcompare", "left/Quarterly draft.txt", "right/Résumé.txt"))

        def edit(argv, **options):
            self.assertEqual(argv, ["/fake/bcompare", "-solo", "./files/1/selection.txt", "./files/2/selection.txt"])
            workdir = Path(options["cwd"])
            self.assertEqual(workdir, session)
            (workdir / argv[2]).write_text("first saved", encoding="utf-8")
            (workdir / argv[3]).write_text("second saved", encoding="utf-8")
            proc = MagicMock()
            proc.poll.return_value = 0
            return proc

        with patch("subprocess.Popen", side_effect=edit):
            self.bridge["run_session"](str(session))
        self.assertEqual(first.read_text(encoding="utf-8"), "first saved")
        self.assertEqual(second.read_text(encoding="utf-8"), "second saved")

    def test_manifest_refuses_unlisted_slots(self):
        self.put("item.txt")
        session = Path(self.select("code", "item.txt"))
        (session / "files" / "8").mkdir()
        self.assert_refused(session)

    def test_manifest_refuses_extra_files_within_file_slot(self):
        self.put("item.txt")
        session = Path(self.select("code", "item.txt"))
        slot = next((session / "files").rglob("item.txt")).parent
        (slot / "extra.txt").write_text("extra", encoding="utf-8")
        self.assert_refused(session)

    def test_pruned_metadata_counts_toward_traversal_limit(self):
        self.put("tree/.git/note.txt")
        self.put("tree/HEAD")
        with patch.dict(self.bridge, MAX_TREE_FILES=1):
            with self.assertRaises(self.bridge["OverBudget"]):
                self.select("bcompare", "tree")
        self.assertEqual(list(self.stage.iterdir()), [])

    def test_aborts_unpublished_session_if_slot_cannot_be_removed(self):
        self.put("second.txt")
        remove = shutil.rmtree

        def cannot_remove_slot(*args, **kwargs):
            if kwargs.get("dir_fd") is not None:
                raise PermissionError("fixture slot cleanup failed")
            return remove(*args, **kwargs)

        with patch("shutil.rmtree", side_effect=cannot_remove_slot):
            with self.assertRaisesRegex(PermissionError, "fixture slot cleanup failed"):
                self.select("code", "missing.txt", "second.txt")
        self.assertEqual(list(self.stage.iterdir()), [])

    def test_legacy_manifest_keeps_recovery_without_launching(self):
        self.put("item.txt")
        session = Path(self.select("code", "item.txt"))
        manifest = session / "manifest.json"
        data = json.loads(manifest.read_bytes())
        data.pop("version", None)
        manifest.write_text(json.dumps(data), encoding="utf-8")
        self.assert_refused(session)
        staged, = (session / "files").rglob("item.txt")
        self.assertEqual(staged.read_text(encoding="utf-8"), "original")

    def assert_refused(self, session):
        with patch("subprocess.Popen") as launch:
            launch.return_value.poll.return_value = 0
            with self.assertRaises(self.bridge["Refused"]):
                self.bridge["run_session"](str(session))
        launch.assert_not_called()


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
