import contextlib
from dataclasses import asdict, replace
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import select
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from oc_openai.exposure import ExposureError, ExposureLedger, Phase, Slot
from oc_openai.scoped_exposure import ScopedClaim, ScopedExposure, VerifiedUsage, _ANCHOR, _JOURNAL, _USAGE_MAX


COHORT = "f" * 64
ROOT = Path(__file__).resolve().parents[1]
CLAIM = ScopedClaim("a" * 32, "b" * 32, "c" * 32, "d" * 64, "gpt-fixture", "e" * 64, 10, 20)
OTHER = replace(CLAIM, slot="d" * 32, operation="e" * 32, binding="9" * 64)
TERMINAL = VerifiedUsage(CLAIM.operation, "9" * 64, 4, 5)

CHILD = """
import contextlib
import os
from pathlib import Path
import sys
from oc_openai.exposure import ExposureLedger
from oc_openai.scoped_exposure import ScopedClaim, ScopedExposure

scope = ScopedExposure(ExposureLedger(Path(sys.argv[1])), "f" * 64, require_compatible=lambda: None)
claim = ScopedClaim("a" * 32, "b" * 32, "c" * 32, "d" * 64, "gpt-fixture", "e" * 64, 10, 20)

def check():
    if sys.argv[2] == "before-claim":
        os._exit(91)
    if sys.argv[2] == "after-claim" and (Path(sys.argv[1]) / "did-check").exists():
        os._exit(92)
    (Path(sys.argv[1]) / "did-check").touch()

def write():
    print("write", flush=True)
    if sys.argv[2] == "contest":
        sys.stdin.readline()
        return
    os._exit(93)

scope.first_write(claim, slot_fence=contextlib.nullcontext, check=check, write=write)
"""


class ScopedExposureTest(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="oc-exposure-scope-")
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.legacy = ExposureLedger(self.root)
        self.compatible = Mock(return_value=None)
        self.scope = ScopedExposure(self.legacy, COHORT, require_compatible=self.compatible)

    def first(self, claim=CLAIM, *, write=None, check=None, slot_fence=contextlib.nullcontext, **options):
        return self.scope.first_write(
            claim, write=write if write is not None else Mock(return_value=7),
            check=check if check is not None else Mock(return_value=None), slot_fence=slot_fence, **options,
        )

    def child(self, mode):
        return [sys.executable, "-B", "-c", CHILD, str(self.root), mode]

    def journal(self):
        return json.loads((self.root / _JOURNAL).read_bytes())

    def test_primitive_is_unreachable_from_production_call_sites(self):
        for root in (ROOT / "oc_openai", ROOT / "oc_providers", ROOT / "oc_orchestrator"):
            for source in root.rglob("*.py"):
                if source.name != "scoped_exposure.py":
                    self.assertNotIn("scoped_exposure", source.read_text(), source)
        for source in ("oc-sandbox", "oc-openai-session.py", "oc-openai.py", "oc-orchestrate.py"):
            self.assertNotIn("scoped_exposure", (ROOT / source).read_text(), source)

    def test_no_implicit_activation_including_marker_only(self):
        write = Mock()
        with self.assertRaisesRegex(ExposureError, "shared_exposure_not_active"):
            self.first(write=write)
        self.assertFalse((self.root / _JOURNAL).exists())
        self.assertFalse((self.root / _ANCHOR).exists())
        with self.assertRaisesRegex(ExposureError, "incompatible_exposure_writers"):
            ScopedExposure(self.legacy, COHORT, require_compatible=True)
        anchor = self.root / _ANCHOR
        anchor.write_text(json.dumps({"version": 1, "cohort": COHORT}))
        anchor.chmod(0o600)
        with self.assertRaisesRegex(ExposureError, "invalid_shared_exposure"):
            self.scope.activate()
        with self.assertRaisesRegex(ExposureError, "invalid_shared_exposure"):
            self.first(write=write)
        write.assert_not_called()

    def test_writer_incompatibility_refuses_activation_and_existing_journal_use(self):
        self.compatible.side_effect = ExposureError("incompatible_exposure_writers")
        with self.assertRaisesRegex(ExposureError, "incompatible_exposure_writers"):
            self.scope.activate()
        self.assertFalse((self.root / _ANCHOR).exists())
        self.assertFalse((self.root / _JOURNAL).exists())

        self.compatible.side_effect = None
        self.scope.activate()
        self.compatible.return_value = True
        write = Mock()
        with self.assertRaisesRegex(ExposureError, "incompatible_exposure_writers"):
            self.first(write=write)
        write.assert_not_called()
        self.assertEqual(self.journal()["claims"], [])

    def test_same_canonical_lock_through_durable_claim_and_bounded_write(self):
        self.scope.activate()
        seen = []

        @contextlib.contextmanager
        def route_fence():
            seen.append("route-enter")
            yield
            seen.append("route-exit")

        def check():
            seen.append("check")

        def write():
            self.assertIsNone(self.journal()["claims"][0]["usage"])
            anchor = json.loads((self.root / _ANCHOR).read_bytes())
            self.assertEqual(anchor["journal_sha256"], sha256((self.root / _JOURNAL).read_bytes()).hexdigest())
            with (self.root / "exposure.lock").open("r+b") as lock:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            seen.append("write")
            return 11

        self.assertEqual(self.first(write=write, check=check, slot_fence=route_fence), 11)
        self.assertEqual(seen, ["route-enter", "check", "check", "write", "route-exit"])
        self.assertEqual(self.compatible.call_count, 3)

    def test_cancel_before_claim_has_no_effect_after_claim_keeps_scope_blocked(self):
        self.scope.activate()
        write = Mock()
        cancel_before_claim = Mock(side_effect=RuntimeError("cancel"))
        with self.assertRaisesRegex(RuntimeError, "cancel"):
            self.first(check=cancel_before_claim, write=write)
        self.assertEqual(self.journal()["claims"], [])
        cancel_after_claim = Mock(side_effect=[None, RuntimeError("cancel")])
        with self.assertRaisesRegex(RuntimeError, "cancel"):
            self.first(check=cancel_after_claim, write=write)
        self.assertIsNone(self.journal()["claims"][0]["usage"])
        with self.assertRaisesRegex(ExposureError, "unsettled_exposure"):
            self.first(OTHER, write=write)
        write.assert_not_called()

    def test_real_crash_before_or_after_claim_has_expected_restart_effect(self):
        self.scope.activate()
        for mode, status, sent in (("before-claim", 91, b""), ("after-claim", 92, b"")):
            result = subprocess.run(self.child(mode), cwd=ROOT, capture_output=True, timeout=5)
            self.assertEqual((result.returncode, result.stdout), (status, sent), result.stderr)
        self.assertIsNone(self.journal()["claims"][0]["usage"])
        restarted = ScopedExposure(ExposureLedger(self.root), COHORT, require_compatible=self.compatible)
        with self.assertRaisesRegex(ExposureError, "unsettled_exposure"):
            restarted.first_write(OTHER, slot_fence=contextlib.nullcontext, check=lambda: None, write=self.fail)

    def test_crash_during_first_write_keeps_persisted_claim(self):
        self.scope.activate()
        result = subprocess.run(self.child("during-write"), cwd=ROOT, capture_output=True, timeout=5)
        self.assertEqual((result.returncode, result.stdout), (93, b"write\n"), result.stderr)
        self.assertIsNone(self.journal()["claims"][0]["usage"])
        with self.assertRaisesRegex(ExposureError, "unsettled_exposure"):
            self.first(OTHER)

    def test_competing_subprocess_writes_once_and_next_profile_needs_settlement(self):
        self.scope.activate()
        with subprocess.Popen(self.child("contest"), cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE) as competing:
            try:
                self.assertEqual(select.select([competing.stdout], [], [], 5)[0], [competing.stdout])
                self.assertEqual(competing.stdout.readline(), b"write\n")
                attempted = Mock()
                with self.assertRaisesRegex(ExposureError, "exposure_lock_busy"):
                    self.first(OTHER, write=attempted)
                competing.stdin.write(b"done\n")
                competing.stdin.flush()
                self.assertEqual(competing.wait(timeout=5), 0)
            finally:
                if competing.poll() is None:
                    competing.kill()
                    competing.wait(timeout=5)
        with self.assertRaisesRegex(ExposureError, "unsettled_exposure"):
            self.first(OTHER, write=attempted)
        attempted.assert_not_called()
        self.scope.settle(CLAIM, TERMINAL)
        self.assertEqual(self.first(OTHER), 7)

    def test_settlement_exact_idempotent_and_cannot_clear_foreign_pending_slot(self):
        self.scope.activate()
        self.first()
        historical = (self.root / _JOURNAL).read_bytes()
        for claim, usage in ((replace(CLAIM, binding="3" * 64), TERMINAL),
                             (CLAIM, replace(TERMINAL, operation=OTHER.operation)),
                             (CLAIM, replace(TERMINAL, input_tokens=True))):
            with self.assertRaises(ExposureError):
                self.scope.settle(claim, usage)
            self.assertEqual((self.root / _JOURNAL).read_bytes(), historical)
        self.scope.settle(CLAIM, TERMINAL)
        self.first(OTHER)
        settled = (self.root / _JOURNAL).read_bytes()
        self.scope.settle(CLAIM, TERMINAL)
        with self.assertRaisesRegex(ExposureError, "unmatched_exposure_settlement"):
            self.scope.settle(CLAIM, replace(TERMINAL, terminal_digest="8" * 64))
        self.assertEqual((self.root / _JOURNAL).read_bytes(), settled)

    def test_overage_remains_durable_and_settled_slot_cannot_be_replayed(self):
        self.scope.activate()
        self.first()
        self.scope.settle(CLAIM, TERMINAL)
        with self.assertRaisesRegex(ExposureError, "shared_exposure_slot_spent"):
            self.first(replace(CLAIM, operation="0" * 32))
        self.first(OTHER)
        overage = replace(TERMINAL, operation=OTHER.operation, output_tokens=OTHER.max_output + 1)
        with self.assertRaisesRegex(ExposureError, "exposure_bound_exceeded"):
            self.scope.settle(OTHER, overage)
        self.assertEqual(self.journal()["claims"][-1]["usage"]["output_tokens"], OTHER.max_output + 1)
        with self.assertRaisesRegex(ExposureError, "exposure_bound_exceeded"):
            self.first(replace(OTHER, slot="9" * 32, operation="8" * 32))

    def test_existing_receipts_are_scanned_before_activation_claim_and_settlement(self):
        self.legacy.reserve(Slot("0" * 32, "a" * 64, Phase.ORCHESTRATOR))
        with self.assertRaisesRegex(ExposureError, "unsettled_exposure"):
            self.scope.activate()
        self.legacy.settle(Slot("0" * 32, "a" * 64, Phase.ORCHESTRATOR), 1, 1)
        self.scope.activate()
        self.first()
        diagnostic = self.root / "canary-recovery.json"
        diagnostic.write_text("{}")
        diagnostic.chmod(0o600)
        with self.assertRaisesRegex(ExposureError, "invalid_exposure_record"):
            self.scope.settle(CLAIM, TERMINAL)
        self.assertIsNone(self.journal()["claims"][-1]["usage"])
        write = Mock()
        with self.assertRaisesRegex(ExposureError, "invalid_exposure_record"):
            self.first(OTHER, write=write)
        write.assert_not_called()

    def test_missing_or_tampered_journal_fails_after_activation(self):
        self.scope.activate()
        self.first()
        path = self.root / _JOURNAL
        saved = path.read_bytes()
        path.unlink()
        with self.assertRaisesRegex(ExposureError, "invalid_shared_exposure"):
            self.first(OTHER)
        path.write_bytes(saved.replace(b'"version":1', b'"version":true'))
        path.chmod(0o600)
        with self.assertRaisesRegex(ExposureError, "invalid_shared_exposure"):
            self.scope.settle(CLAIM, TERMINAL)

    def test_stale_journal_cannot_clear_a_newer_anchored_claim(self):
        self.scope.activate()
        path = self.root / _JOURNAL
        stale = path.read_bytes()
        self.first()
        current_anchor = (self.root / _ANCHOR).read_bytes()
        path.write_bytes(stale)
        attempted = Mock()
        reopened = ScopedExposure(ExposureLedger(self.root), COHORT, require_compatible=self.compatible)
        with self.assertRaisesRegex(ExposureError, "invalid_shared_exposure"):
            reopened.first_write(OTHER, slot_fence=contextlib.nullcontext, check=lambda: None, write=attempted)
        with self.assertRaisesRegex(ExposureError, "invalid_shared_exposure"):
            reopened.settle(CLAIM, TERMINAL)
        attempted.assert_not_called()
        self.assertEqual(path.read_bytes(), stale)
        self.assertEqual((self.root / _ANCHOR).read_bytes(), current_anchor)

    def test_last_admitted_claim_reserves_room_for_maximum_terminal_overage(self):
        self.scope.activate()
        path = self.root / _JOURNAL
        pending = path.read_bytes()
        anchor = (self.root / _ANCHOR).read_bytes()
        terminal = replace(TERMINAL, input_tokens=_USAGE_MAX, output_tokens=_USAGE_MAX)
        at_capacity = self.journal()
        at_capacity["claims"].append({"claim": asdict(CLAIM), "usage": asdict(terminal)})
        encoded = json.dumps(at_capacity, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        attempted = Mock()

        with patch("oc_openai.scoped_exposure._MAX_BYTES", len(encoded) - 1):
            with self.assertRaisesRegex(ExposureError, "exposure_record_full"):
                self.first(write=attempted)
        attempted.assert_not_called()
        self.assertEqual(path.read_bytes(), pending)
        self.assertEqual((self.root / _ANCHOR).read_bytes(), anchor)

        with patch("oc_openai.scoped_exposure._MAX_BYTES", len(encoded)):
            self.first(write=attempted)
            with self.assertRaisesRegex(ExposureError, "exposure_bound_exceeded"):
                self.scope.settle(CLAIM, terminal)
            self.assertEqual(path.read_bytes(), encoded)
            with self.assertRaisesRegex(ExposureError, "exposure_bound_exceeded"):
                self.first(OTHER)
        attempted.assert_called_once_with()

    def test_interrupted_settlement_never_promotes_an_unmatched_pair(self):
        self.scope.activate()
        self.first()
        real_sync = os.fsync

        def sync_only_file(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("publication durability failed")
            real_sync(fd)

        attempted = Mock()
        with patch("oc_openai.scoped_exposure.os.fsync", side_effect=sync_only_file):
            with self.assertRaisesRegex(ExposureError, "exposure_store_unavailable"):
                self.scope.settle(CLAIM, TERMINAL)
        restarted = ScopedExposure(ExposureLedger(self.root), COHORT, require_compatible=self.compatible)
        journal, anchor = (self.root / _JOURNAL).read_bytes(), (self.root / _ANCHOR).read_bytes()
        self.assertNotEqual(json.loads(anchor)["journal_sha256"], sha256(journal).hexdigest())
        with self.assertRaisesRegex(ExposureError, "invalid_shared_exposure"):
            restarted.first_write(OTHER, slot_fence=contextlib.nullcontext, check=lambda: None, write=attempted)
        with self.assertRaisesRegex(ExposureError, "invalid_shared_exposure"):
            restarted.settle(CLAIM, TERMINAL)
        attempted.assert_not_called()
        self.assertEqual((self.root / _JOURNAL).read_bytes(), journal)
        self.assertEqual((self.root / _ANCHOR).read_bytes(), anchor)

    def test_failed_anchor_write_never_calls_first_writer_or_repairs_the_pair(self):
        self.scope.activate()
        write = Mock()
        old_anchor = (self.root / _ANCHOR).read_bytes()
        actual_write = self.legacy._write

        def refuse_anchor(directory, data, *, name):
            if name == _ANCHOR:
                raise OSError("anchor publication failed")
            actual_write(directory, data, name=name)

        with patch.object(self.legacy, "_write", side_effect=refuse_anchor):
            with self.assertRaisesRegex(ExposureError, "exposure_store_unavailable"):
                self.first(write=write)
        pending = (self.root / _JOURNAL).read_bytes()
        self.assertIsNone(self.journal()["claims"][-1]["usage"])
        self.assertNotEqual(json.loads(old_anchor)["journal_sha256"], sha256(pending).hexdigest())
        with self.assertRaisesRegex(ExposureError, "invalid_shared_exposure"):
            self.first(OTHER, write=write)
        with self.assertRaisesRegex(ExposureError, "invalid_shared_exposure"):
            self.scope.settle(CLAIM, TERMINAL)
        self.assertEqual((self.root / _ANCHOR).read_bytes(), old_anchor)
        self.assertEqual((self.root / _JOURNAL).read_bytes(), pending)
        write.assert_not_called()

    def test_durable_claim_failure_never_calls_the_first_writer(self):
        self.scope.activate()
        write = Mock()
        with patch("oc_openai.scoped_exposure.os.fsync", side_effect=OSError("sync failed")):
            with self.assertRaisesRegex(ExposureError, "exposure_store_unavailable"):
                self.first(write=write)
        write.assert_not_called()
        self.assertEqual(self.journal()["claims"], [])
