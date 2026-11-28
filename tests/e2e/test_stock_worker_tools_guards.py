"""Inert guards for the offline worker-tools proof fixtures."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, nullcontext
from copy import deepcopy
import errno
from io import StringIO
import json
import os
from pathlib import Path
import runpy
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
from threading import Event
import unittest
from unittest.mock import MagicMock, call, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(Path(__file__).resolve().parent)]

from oc_openai.session_broker import SessionBroker
from oc_openai.session_protocol import ReasoningVault, SessionStreamProjector, StreamAborted
import stock_worker_tools_capture as capture_fixture
from stock_worker_tools_capture import AUTHORITY, Observer, Terminal, WireHandler, await_idle, capture, verify_scope
from stock_worker_tools_history import stock_history
from stock_worker_tools_turns import FixtureTurns, PinnedLedger
from stock_worker_tools_guest import (
    HOLD_READER, TCP_CONNECT, WIRE, broker_exchange, confirm_foreground, reap_held_child, run_cleanup,
    verify_direct_broker, verify_loopback_listener, verify_outside_candidates, verify_relay_mcs,
)
from stock_worker_tools_host import firewall_shape
from stock_worker_tools_projection import capsule, describe_source, project_sources
from stock_worker_tools_protocol import (
    LABEL, MODEL, PROMPT, PROVIDER, REFUSED_FILE, TITLE, TITLE_PROMPT, TOOL_NAMES, FixtureMismatch, ToolScript, call_id,
    expected_result, refused_events, response_events,
)


class CaptureGuardTests(unittest.TestCase):
    def test_refuses_non_loopback_namespace_before_workspace_access(self):
        with patch("stock_worker_tools_capture.socket.if_nameindex", return_value=[(1, "lo"), (2, "eth0")]):
            with self.assertRaisesRegex(FixtureMismatch, "loopback-only"):
                verify_scope()

    def test_exposure_parent_sync_failure_precedes_observer_and_terminal_start(self):
        primary = OSError("synthetic evidence-parent sync failed")
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "failure.json"
            with patch("stock_worker_tools_capture.os.fsync", side_effect=primary), \
                    patch("stock_worker_tools_capture.Observer") as observer, \
                    patch("stock_worker_tools_capture.Terminal") as terminal:
                with self.assertRaises(OSError) as raised:
                    capture(("/unused-stock-fixture",), evidence, "tools")
            self.assertIs(raised.exception, primary)
            observer.assert_not_called()
            terminal.assert_not_called()
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_failed_observer_bind_records_empty_exposure_and_removes_owned_scratch(self):
        with tempfile.TemporaryDirectory() as directory, closing(socket.socket()) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            root = Path(directory)
            evidence = root / "failure.json"
            with patch("stock_worker_tools_capture.PORT", listener.getsockname()[1]), \
                    patch("stock_worker_tools_capture.Terminal") as terminal, patch("sys.stderr", StringIO()):
                with self.assertRaises(OSError) as raised:
                    capture(("/unused-stock-fixture",), evidence, "tools")
            self.assertEqual(raised.exception.errno, errno.EADDRINUSE)
            terminal.assert_not_called()
            self.assertEqual(list(root.iterdir()), [evidence])
            self.assertEqual(json.loads(evidence.read_text()), {
                "phase": "failed", "exposure": {"status": "verified", "claims": []}, "requests": [],
            })

    def test_observer_socket_allocation_failure_cleans_empty_owned_scratch(self):
        primary = OSError(errno.EMFILE, "synthetic socket allocation failure")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "failure.json"
            with patch("stock_worker_tools_capture.socket.socket", side_effect=primary), \
                    patch("stock_worker_tools_capture.Terminal") as terminal:
                with self.assertRaises(OSError) as raised:
                    capture(("/unused-stock-fixture",), evidence, "tools")
            self.assertIs(raised.exception, primary)
            terminal.assert_not_called()
            self.assertEqual(list(root.iterdir()), [evidence])
            self.assertEqual(json.loads(evidence.read_text()),
                             {"phase": "failed", "exposure": {"status": "unavailable"}})

    def test_initial_publication_sync_uncertainty_retains_owned_ledger_and_receipt(self):
        primary = OSError("synthetic initial ledger directory sync failed")
        sync = os.fsync
        injected = False
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity = root.stat()
            evidence = root / "failure.json"

            def fail_initial_publication(fd):
                nonlocal injected
                info = os.fstat(fd)
                if not injected and stat.S_ISDIR(info.st_mode) and not os.path.samestat(info, identity):
                    injected = True
                    raise primary
                return sync(fd)

            with patch("stock_worker_tools_turns.os.fsync", side_effect=fail_initial_publication), \
                    patch("stock_worker_tools_capture.Terminal") as terminal:
                with self.assertRaises(OSError) as raised:
                    capture(("/unused-stock-fixture",), evidence, "tools")
            self.assertIs(raised.exception, primary)
            terminal.assert_not_called()
            (ledger,) = root.glob("*/synthetic-exposure.sqlite")
            receipt = json.loads((ledger.parent / "recovery.json").read_text())
            self.assertEqual(receipt["exposure_ledger"], ledger.name)
            self.assertEqual(receipt["terminal_scratch"], {"status": "unavailable"})
            self.assertTrue(any(str(ledger.parent) in note for note in primary.__notes__))
            with closing(sqlite3.connect(ledger)) as db:
                self.assertEqual(db.execute("SELECT sequence FROM exposure").fetchall(), [])
            self.assertEqual(json.loads(evidence.read_text()),
                             {"phase": "failed", "exposure": {"status": "unavailable"}})

    def capture_with_failed_send(self, destination, *, damage=None, after_commit=False,
                                 retain=False, terminal_error=None, exit_error=None):
        primary = RuntimeError("synthetic send dropped after durable claim")
        observed = {}
        history = stock_history([{"type": "message", "role": "user",
                                  "content": [{"type": "input_text", "text": PROMPT}]}])

        def fail_send(request):
            self.assertFalse(after_commit, "Ambiguous commit reached first write")
            observed["dispatch"] = request
            raise primary

        def start_terminal(term, *_args):
            observed["terminal_scratch"] = Path(term.command[4]).parent
            observed["terminal_client_command"] = getattr(term, "client_command", term.command)
            if retain:
                self.addCleanup(shutil.rmtree, observed["terminal_scratch"], ignore_errors=True)

        def run_terminal(*args, check=True, timeout=10):
            if args == ("kill-server",) and terminal_error is not None:
                if check or isinstance(terminal_error, subprocess.TimeoutExpired):
                    raise terminal_error

        def fail_after_claim(_predicate, _description, observer):
            observed["observer"] = observer
            claim = observer.turns._claim

            def claim_then_fail(request):
                claim(request)
                raise primary

            try:
                with patch.object(observer.turns, "_claim", side_effect=claim_then_fail if after_commit else claim):
                    observer.turns.dispatch(AUTHORITY, "ses_capture", history, fail_send)
            finally:
                observed["rows"] = observer.turns.records()
                if damage is not None:
                    damage(observer.turns._path)

        command = ("/unused-stock-fixture",)
        terminal_server = MagicMock()
        terminal_server.poll.return_value = None
        terminal_server.wait.side_effect = exit_error
        observed["terminal_server"] = terminal_server
        with patch("stock_worker_tools_capture.PORT", 0), patch("stock_worker_tools_capture.stock_config", return_value={}), \
                patch.object(Terminal, "launch_server", return_value=terminal_server, create=True), \
                patch.object(Terminal, "await_server", create=True), \
                patch.object(Terminal, "start", start_terminal), patch.object(Terminal, "run", side_effect=run_terminal), \
                patch.object(Terminal, "await_screen", side_effect=fail_after_claim), patch("sys.stderr", StringIO()):
            with self.assertRaisesRegex(RuntimeError, "synthetic send dropped") as raised:
                capture(command, destination, "tools")
        self.assertIs(raised.exception, primary)
        observer = observed["observer"]
        self.assertEqual(observer.socket.fileno(), -1)
        self.assertEqual(observer.turns._path.parent.exists(), retain)
        self.assertEqual(observed["terminal_scratch"].is_dir(), retain)
        return primary, observed

    def test_failed_capture_preserves_exact_unresolved_claim_after_scratch_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "failure.json"
            _, observed = self.capture_with_failed_send(evidence)
            self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o600)
            report = json.loads(evidence.read_text())
            self.assertEqual(report["phase"], "failed")
            self.assertEqual(report["exposure"], {"status": "verified", "claims": observed["rows"]})
            (row,) = report["exposure"]["claims"]
            self.assertEqual(row["sequence"], observed["dispatch"].sequence)
            self.assertIsNone(row["actual_input"])
            self.assertIsNone(row["actual_output"])

    def test_failed_capture_snapshots_exact_claim_when_commit_returns_error(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "failure.json"
            _, observed = self.capture_with_failed_send(evidence, after_commit=True)
            self.assertEqual(json.loads(evidence.read_text())["exposure"],
                             {"status": "verified", "claims": observed["rows"]})
            row, = observed["rows"]
            self.assertEqual((row["sequence"], row["actual_input"], row["actual_output"]), (1, None, None))

    def test_failed_capture_preserves_primary_when_scratch_cleanup_raises(self):
        cleanup = shutil.rmtree

        def fail_cleanup(path, *args, **kwargs):
            cleanup(path, *args, **kwargs)
            raise OSError("synthetic scratch cleanup failure")

        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "failure.json"
            with patch.object(shutil, "rmtree", fail_cleanup):
                primary, observed = self.capture_with_failed_send(evidence)
            self.assertEqual(json.loads(evidence.read_text())["exposure"],
                             {"status": "verified", "claims": observed["rows"]})
            self.assertTrue(any("scratch cleanup" in note for note in primary.__notes__))

    def test_failed_capture_closes_observer_only_once(self):
        close = Observer.server_close
        closed = []

        def fail_second_close(observer):
            closed.append(observer)
            if len(closed) > 1:
                raise OSError("synthetic duplicate observer close")
            close(observer)

        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "failure.json"
            with patch.object(Observer, "server_close", fail_second_close):
                _, observed = self.capture_with_failed_send(evidence)
            self.assertEqual(closed, [observed["observer"]])

    def test_capture_client_never_autostarts_a_replacement_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            _, observed = self.capture_with_failed_send(Path(directory) / "failure.json")
            self.assertIn("-N", observed["terminal_client_command"])

    def test_durable_directory_displacement_preserves_owned_journal_and_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "failure.json"
            moved = Path(directory) / "moved-fixture"
            observed_replacement = []

            def displace(ledger):
                root = ledger.parent
                root.rename(moved)
                root.mkdir(mode=0o700)
                sentinel = root / "sentinel"
                sentinel.write_text("separate synthetic directory")
                observed_replacement.append(sentinel)

            primary, _ = self.capture_with_failed_send(evidence, damage=displace, retain=True)
            sentinel, = observed_replacement
            self.assertEqual(sentinel.read_text(), "separate synthetic directory")
            self.assertEqual(list(sentinel.parent.iterdir()), [sentinel])
            receipt = json.loads((moved / "recovery.json").read_text())
            self.assertEqual(receipt["run_id"], sentinel.parent.name)
            self.assertTrue((moved / receipt["exposure_ledger"]).is_file())
            self.assertTrue(any("visible name changed" in note for note in primary.__notes__))
            self.assertEqual(json.loads(evidence.read_text()),
                             {"phase": "failed", "exposure": {"status": "unavailable"}})

    def test_terminal_cleanup_uncertainty_retains_both_roots_after_observer_stops(self):
        cases = (
            ("kill timed out", subprocess.TimeoutExpired("synthetic tmux", 10), None),
            ("kill failed", subprocess.CalledProcessError(1, "synthetic tmux"), None),
            ("owned server exit unproven", None, subprocess.TimeoutExpired("synthetic foreground child", 10)),
        )
        for label, terminal_error, exit_error in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                evidence = Path(directory) / "failure.json"
                primary, observed = self.capture_with_failed_send(
                    evidence, retain=True, terminal_error=terminal_error, exit_error=exit_error,
                )
                if exit_error is not None:
                    observed["terminal_server"].wait.assert_called_once()
                ledger = observed["observer"].turns._path
                receipt = json.loads((ledger.parent / "recovery.json").read_text())
                self.assertEqual(receipt["exposure_ledger"], ledger.name)
                self.assertEqual(receipt["terminal_scratch"]["path"], str(observed["terminal_scratch"]))
                self.assertTrue(ledger.is_file())
                self.assertTrue(any("terminal cleanup" in note for note in primary.__notes__))
                self.assertEqual(json.loads(evidence.read_text()),
                                 {"phase": "failed", "exposure": {"status": "unavailable"}})

    def test_capture_deadline_retains_journal_while_observer_may_still_write(self):
        for stalled_in in ("serving", "handler"):
            with self.subTest(stalled_in=stalled_in), tempfile.TemporaryDirectory() as directory:
                self.assert_stalled_observer_retains_journal(stalled_in, Path(directory) / "failure.json")

    def test_recovery_receipt_and_revocation_do_not_wait_for_stuck_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "failure.json"
            observed = self.assert_stalled_observer_retains_journal("writer", evidence)
            identity, inheritable = observed["borrowed_after_retirement"]
            expected = observed["ledger"].parent.stat()
            self.assertTrue(os.path.samestat(identity, expected))
            self.assertFalse(inheritable)
            self.assertTrue(observed["new_borrow_refused"])
            self.assertTrue(observed["unfinished_write_refused"])
            with closing(sqlite3.connect(observed["ledger"])) as db:
                self.assertEqual(db.execute("SELECT actual_input FROM exposure").fetchall(), [(None,)])

    def test_revocation_before_final_first_write_authorization_has_zero_sends(self):
        checked = Event()
        resume = Event()
        with tempfile.TemporaryDirectory() as directory, \
                capture_fixture.make_exposure_scratch(Path(directory)) as scratch, ThreadPoolExecutor() as pool:
            ledger = scratch.root / "test-exposure.sqlite"
            turns = FixtureTurns(ledger, AUTHORITY, ledger=PinnedLedger(ledger.name, scratch))
            history = self.first_turn()
            upstream = MagicMock()
            authorize = scratch.authorize_first_write

            def stop_before_authorization(**options):
                checked.set()
                self.assertTrue(resume.wait(2))
                authorize(**options)

            with patch.object(scratch, "authorize_first_write", side_effect=stop_before_authorization):
                result = pool.submit(turns.dispatch, AUTHORITY, "ses_capture", history, upstream)
                try:
                    self.assertTrue(checked.wait(2))
                    scratch.revoke()
                finally:
                    resume.set()
                with self.assertRaisesRegex(FixtureMismatch, "directory retired"):
                    result.result(timeout=2)
            upstream.assert_not_called()
            with closing(sqlite3.connect(ledger)) as db:
                self.assertEqual(db.execute("SELECT sequence, actual_input FROM exposure").fetchall(), [(1, None)])

    def test_grant_expiry_during_final_directory_verification_has_zero_sends(self):
        now = 10
        authorizing = False
        with tempfile.TemporaryDirectory() as directory, capture_fixture.make_exposure_scratch(Path(directory)) as scratch:
            ledger = scratch.root / "test-exposure.sqlite"
            turns = FixtureTurns(ledger, AUTHORITY, ledger=PinnedLedger(ledger.name, scratch), clock=lambda: now)
            authorize = scratch.authorize_first_write
            verify = scratch.verify
            upstream = MagicMock()
            history = self.first_turn()

            def enter_final_authorization(**options):
                nonlocal authorizing
                authorizing = True
                return authorize(**options)

            def slow_verification(*args, **kwargs):
                nonlocal now
                verify(*args, **kwargs)
                if authorizing:
                    now = 310

            with patch.object(scratch, "authorize_first_write", side_effect=enter_final_authorization), \
                    patch.object(scratch, "verify", side_effect=slow_verification):
                with self.assertRaisesRegex(FixtureMismatch, "Stale or expired"):
                    turns.dispatch(AUTHORITY, "ses_capture", history, upstream)
            upstream.assert_not_called()
            with closing(sqlite3.connect(ledger)) as db:
                self.assertEqual(db.execute("SELECT sequence, actual_input FROM exposure").fetchall(), [(1, None)])

    def test_displaced_pinned_ledger_refuses_claim_before_touching_replacement(self):
        with tempfile.TemporaryDirectory() as directory, capture_fixture.make_exposure_scratch(Path(directory)) as scratch:
            ledger_name = "test-exposure.sqlite"
            turns = FixtureTurns(scratch.root / ledger_name, AUTHORITY, ledger=PinnedLedger(ledger_name, scratch))
            moved = Path(directory) / "owned-fixture"
            scratch.root.rename(moved)
            scratch.root.mkdir(mode=0o700)
            replacement = scratch.root / ledger_name
            replacement.write_bytes((moved / ledger_name).read_bytes())
            sentinel = replacement.read_bytes()
            upstream = MagicMock()
            history = self.first_turn()
            with self.assertRaisesRegex(FixtureMismatch, "Capture exposure directory changed"):
                turns.dispatch(AUTHORITY, "ses_capture", history, upstream)
            upstream.assert_not_called()
            self.assertEqual(replacement.read_bytes(), sentinel)
            with closing(sqlite3.connect(moved / ledger_name)) as db:
                self.assertEqual(db.execute("SELECT sequence FROM exposure").fetchall(), [])

    def test_ambiguous_pinned_replace_retains_exact_claim_with_no_send(self):
        primary = OSError("synthetic replace persisted before error")
        replace = os.replace

        def replace_then_raise(*args, **kwargs):
            replace(*args, **kwargs)
            raise primary

        with tempfile.TemporaryDirectory() as directory, capture_fixture.make_exposure_scratch(Path(directory)) as scratch:
            ledger = scratch.root / "test-exposure.sqlite"
            turns = FixtureTurns(ledger, AUTHORITY, ledger=PinnedLedger(ledger.name, scratch))
            upstream = MagicMock()
            history = self.first_turn()
            with patch("stock_worker_tools_turns.os.replace", side_effect=replace_then_raise):
                with self.assertRaises(OSError) as raised:
                    turns.dispatch(AUTHORITY, "ses_capture", history, upstream)
            self.assertIs(raised.exception, primary)
            upstream.assert_not_called()
            claim, = turns.verified_records()
            self.assertEqual((claim["sequence"], claim["parent"], claim["actual_input"], claim["actual_output"]),
                             (1, None, None, None))
            with self.assertRaisesRegex(FixtureMismatch, "Stale or expired"):
                turns.dispatch(AUTHORITY, "ses_capture", history, upstream)

    def test_claim_retirement_checks_the_published_ledger_at_sync_and_final_authorization(self):
        sync = os.fsync
        for phase in ("directory sync", "final authorization"):
            for replacement in (False, True):
                with self.subTest(phase=phase, replacement=replacement), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)

                    def displace(ledger):
                        ledger.rename(ledger.with_name("owned-pending.sqlite"))
                        if replacement:
                            ledger.write_bytes(b"unrelated synthetic file")
                            ledger.chmod(0o600)

                    def fault(observer, ledger):
                        if phase == "directory sync":
                            def move_after_sync(fd):
                                result = sync(fd)
                                if stat.S_ISDIR(os.fstat(fd).st_mode):
                                    displace(ledger)
                                return result

                            return patch("stock_worker_tools_turns.os.fsync", side_effect=move_after_sync)
                        scratch = observer.turns._ledger.scratch
                        authorize = scratch.authorize_first_write

                        def move_before_authorization(**options):
                            displace(ledger)
                            return authorize(**options)

                        return patch.object(scratch, "authorize_first_write", side_effect=move_before_authorization)

                    expected = FixtureMismatch if replacement else FileNotFoundError
                    ledger, receipt, _ = self.assert_claim_fault_preserves_recovery(root, fault, expected)
                    owned = ledger.with_name("owned-pending.sqlite")
                    self.assert_unresolved_claim(owned)
                    info = owned.stat()
                    self.assertEqual(receipt["owned_ledger_identities"], [{"device": info.st_dev, "inode": info.st_ino}])
                    if replacement:
                        self.assertEqual(ledger.read_bytes(), b"unrelated synthetic file")
                    else:
                        self.assertFalse(ledger.exists())

    def test_failed_claim_publication_retains_private_claim_and_redacts_report(self):
        sync = os.fsync
        replace = os.replace
        for failure in ("replace then error", "directory sync"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                primary = OSError(f"synthetic claim publication {failure}")

                def fault(_observer, _ledger):
                    if failure == "replace then error":
                        def replace_then_raise(*args, **kwargs):
                            replace(*args, **kwargs)
                            raise primary

                        return patch("stock_worker_tools_turns.os.replace", side_effect=replace_then_raise)

                    def fail_directory_sync(fd):
                        if stat.S_ISDIR(os.fstat(fd).st_mode):
                            raise primary
                        return sync(fd)

                    return patch("stock_worker_tools_turns.os.fsync", side_effect=fail_directory_sync)

                ledger, receipt, error = self.assert_claim_fault_preserves_recovery(Path(directory), fault, OSError)
                self.assertIs(error, primary)
                self.assert_unresolved_claim(ledger)
                info = ledger.stat()
                self.assertIn({"device": info.st_dev, "inode": info.st_ino}, receipt["owned_ledger_identities"])

    def assert_claim_fault_preserves_recovery(self, root, fault, expected_error):
        upstream = MagicMock()
        observed = {}

        def start_terminal(term, *_args):
            self.addCleanup(shutil.rmtree, Path(term.command[4]).parent, ignore_errors=True)

        def issue_claim(_predicate, _description, observer):
            observed["ledger"] = observer.turns._path
            with fault(observer, observed["ledger"]):
                observer.turns.dispatch(AUTHORITY, "ses_capture", self.first_turn(), upstream)
            self.fail("An ambiguous claim reached the synthetic upstream")

        terminal_server = MagicMock()
        terminal_server.poll.return_value = None
        evidence = root / "failure.json"
        with patch("stock_worker_tools_capture.PORT", 0), \
                patch("stock_worker_tools_capture.stock_config", return_value={}), patch("sys.stderr", StringIO()), \
                patch.object(Terminal, "launch_server", return_value=terminal_server), \
                patch.object(Terminal, "await_server"), patch.object(Terminal, "start", start_terminal), \
                patch.object(Terminal, "await_screen", side_effect=issue_claim), patch.object(Terminal, "run"):
            with self.assertRaises(expected_error) as raised:
                capture(("/unused-stock-fixture",), evidence, "tools")
        upstream.assert_not_called()
        terminal_server.wait.assert_called_once()
        ledger = observed["ledger"]
        receipt = json.loads((ledger.parent / "recovery.json").read_text())
        self.assertEqual(receipt["run_id"], ledger.parent.name)
        self.assertEqual(receipt["exposure_ledger"], ledger.name)
        self.assertTrue(any(str(ledger.parent) in note for note in raised.exception.__notes__))
        self.assertEqual(json.loads(evidence.read_text()), {"phase": "failed", "exposure": {"status": "unavailable"}})
        return ledger, receipt, raised.exception

    def assert_unresolved_claim(self, ledger):
        with closing(sqlite3.connect(ledger)) as db:
            self.assertEqual(db.execute("SELECT sequence, parent, actual_input, actual_output FROM exposure").fetchall(),
                             [(1, None, None, None)])

    def test_exposure_cleanup_enumerates_fresh_without_changing_held_position(self):
        with tempfile.TemporaryDirectory() as directory, capture_fixture.make_exposure_scratch(Path(directory)) as scratch:
            ledger = PinnedLedger("test-exposure.sqlite", scratch)
            FixtureTurns(scratch.root / ledger.name, AUTHORITY, ledger=ledger)
            with os.scandir(scratch.directory) as stale:
                self.assertEqual(next(stale).name, ledger.name)
                offset = os.lseek(scratch.directory, 0, os.SEEK_CUR)
                scratch.discard(ledger)
                self.assertEqual(os.lseek(scratch.directory, 0, os.SEEK_CUR), offset)
            self.assertFalse(scratch.root.exists())

    def test_settlement_sync_uncertainty_retains_exact_usage_and_receipt(self):
        primary = OSError("synthetic settlement directory sync failed")
        sync = os.fsync

        def fail_directory_sync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise primary
            return sync(fd)

        self.assert_settlement_uncertainty_retains_usage(primary, "stock_worker_tools_turns.os.fsync", fail_directory_sync)

    def test_settlement_late_borrow_close_retains_exact_usage_and_receipt(self):
        primary = OSError("synthetic late settlement descriptor close failed")
        close = os.close
        injected = False

        def close_directory_then_fail(fd):
            nonlocal injected
            directory = stat.S_ISDIR(os.fstat(fd).st_mode)
            close(fd)
            if directory and not injected:
                injected = True
                raise primary

        self.assert_settlement_uncertainty_retains_usage(
            primary, "stock_worker_tools_capture.os.close", close_directory_then_fail,
        )

    def assert_settlement_uncertainty_retains_usage(self, primary, fault_target, fault):
        observed = {}

        def start_terminal(term, *_args):
            observed["local_root"] = Path(term.command[4]).parent
            self.addCleanup(shutil.rmtree, observed["local_root"], ignore_errors=True)

        def fail_settlement(_predicate, _description, observer):
            observed["ledger"] = observer.turns._path
            request, _ = observer.turns.dispatch(AUTHORITY, "ses_capture", self.first_turn(), lambda _request: None)
            with patch(fault_target, side_effect=fault):
                observer.turns.settle(AUTHORITY, request, calls=(), completed_message="synthetic", usage=(2, 3, 5))

        terminal_server = MagicMock()
        terminal_server.poll.return_value = None
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "failure.json"
            with patch("stock_worker_tools_capture.PORT", 0), \
                    patch("stock_worker_tools_capture.stock_config", return_value={}), patch("sys.stderr", StringIO()), \
                    patch.object(Terminal, "launch_server", return_value=terminal_server), \
                    patch.object(Terminal, "await_server"), patch.object(Terminal, "start", start_terminal), \
                    patch.object(Terminal, "await_screen", side_effect=fail_settlement), patch.object(Terminal, "run"):
                with self.assertRaises(OSError) as raised:
                    capture(("/unused-stock-fixture",), evidence, "tools")
            self.assertIs(raised.exception, primary)
            terminal_server.wait.assert_called_once()
            ledger = observed["ledger"]
            self.assertTrue(ledger.is_file())
            self.assertTrue(observed["local_root"].is_dir())
            receipt = json.loads((ledger.parent / "recovery.json").read_text())
            self.assertEqual(receipt["exposure_ledger"], ledger.name)
            self.assertTrue(any(str(ledger.parent) in note for note in primary.__notes__))
            with closing(sqlite3.connect(ledger)) as db:
                self.assertEqual(db.execute("SELECT sequence, actual_input, actual_output FROM exposure").fetchall(),
                                 [(1, 2, 3)])
            self.assertEqual(json.loads(evidence.read_text()),
                             {"phase": "failed", "exposure": {"status": "unavailable"}})

    @staticmethod
    def first_turn():
        return stock_history([{"type": "message", "role": "user",
                               "content": [{"type": "input_text", "text": PROMPT}]}])

    def test_observer_joins_serving_and_handlers_with_one_remaining_budget(self):
        with tempfile.TemporaryDirectory() as directory, patch("stock_worker_tools_capture.PORT", 0), \
                patch("stock_worker_tools_capture.time.monotonic", side_effect=[10, 13, 14]):
            observer = Observer("tools", Path(directory) / "exposure.sqlite")
            self.addCleanup(observer.server_close)
            serving, first, second = [MagicMock() for _ in range(3)]
            for thread in (serving, first, second):
                thread.is_alive.side_effect = [True, False]
            observer._handlers = [first, second]
            observer.stop(serving, deadline=15)
        serving.join.assert_called_once_with(5)
        first.join.assert_called_once_with(2)
        second.join.assert_called_once_with(1)

    def test_private_recovery_survives_fixture_scope_and_volatile_scratch_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            durable = Path(directory) / "evidence"
            volatile = Path(directory) / "volatile"
            for folder in (durable, volatile):
                folder.mkdir(mode=0o700)
            evidence = durable / "failure.json"
            result = subprocess.run((sys.executable, "-B", "-c",
                                     "from pathlib import Path\n"
                                     "from sys import argv\n"
                                     "from test_stock_worker_tools_guards import CaptureGuardTests\n"
                                     "CaptureGuardTests().assert_stalled_observer_retains_journal('handler', Path(argv[1]))",
                                     str(evidence)),
                                    cwd=Path(__file__).resolve().parent, env={"TMPDIR": str(volatile)},
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            shutil.rmtree(volatile)
            (journal,) = durable.glob("*/synthetic-exposure.sqlite")
            self.assertEqual(stat.S_IMODE(journal.parent.stat().st_mode), 0o700)
            with closing(sqlite3.connect(journal)) as db:
                self.assertEqual(db.execute("SELECT sequence, actual_input FROM exposure").fetchall(), [(1, None)])
            receipt = journal.parent / "recovery.json"
            self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)
            details = json.loads(receipt.read_text())
            self.assertEqual(details["run_id"], journal.parent.name)
            self.assertEqual(details["exposure_ledger"], journal.name)
            scratch = details["terminal_scratch"]
            self.assertFalse(Path(scratch["path"]).exists())
            self.assertTrue(Path(scratch["path"]).is_relative_to(volatile))
            self.assertTrue(type(scratch["device"]) is int and type(scratch["inode"]) is int)
            socket_identity = details["terminal_socket"]
            self.assertEqual(Path(socket_identity["path"]), Path(scratch["path"]) / "t")
            self.assertTrue(type(socket_identity["device"]) is int and type(socket_identity["inode"]) is int)
            self.assertEqual(json.loads(evidence.read_text()),
                             {"phase": "failed", "exposure": {"status": "unavailable"}})

    def test_private_recovery_receipt_survives_unavailable_socket_probe(self):
        cases = (
            ("scratch mode changed", lambda root: root.chmod(0o750), nullcontext()),
            ("socket probe failed", None, patch("stock_worker_tools_capture.terminal_socket_identity",
                                               side_effect=OSError("synthetic private socket probe failure"))),
        )
        for reason, change_scratch, probe in cases:
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as directory, probe:
                observed = self.assert_stalled_observer_retains_journal(
                    "handler", Path(directory) / "failure.json", change_scratch=change_scratch,
                )
                ledger = observed["ledger"]
                with closing(sqlite3.connect(ledger)) as db:
                    self.assertEqual(db.execute("SELECT sequence, actual_input FROM exposure").fetchall(), [(1, None)])
                scratch = observed["terminal_scratch"]
                identity = scratch.stat()
                receipt = ledger.parent / "recovery.json"
                self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)
                self.assertEqual(json.loads(receipt.read_text()), {
                    "run_id": ledger.parent.name,
                    "exposure_ledger": ledger.name,
                    "terminal_scratch": {"path": str(scratch), "device": identity.st_dev, "inode": identity.st_ino},
                    "terminal_socket": {"status": "unavailable"},
                })

    def assert_stalled_observer_retains_journal(self, stalled_in, evidence, *, change_scratch=None):
        entered = Event()
        released = Event()
        finished = Event()
        writer_done = Event()
        primary = RuntimeError("synthetic terminal failure")
        observed = {}
        accept = Observer.get_request

        def wait_for_release():
            entered.set()
            try:
                self.assertTrue(released.wait(5))
            finally:
                finished.set()

        def stall_serving(observer):
            client, address = accept(observer)
            wait_for_release()
            return client, address

        def stall_handler(handler):
            handler.server.requests.append({"synthetic_private_marker": "unsettled request"})
            if stalled_in != "writer":
                wait_for_release()
                return
            scratch = observed["scratch"]
            try:
                with handler.server.turns._lock, scratch.borrow() as (descriptor, _verify):
                    try:
                        with handler.server.turns._database(write=True) as db, db:
                            db.execute("UPDATE exposure SET actual_input = 7")
                            wait_for_release()
                    except FixtureMismatch as error:
                        observed["unfinished_write_refused"] = str(error) == "Capture exposure directory retired"
                    observed["borrowed_after_retirement"] = os.fstat(descriptor), os.get_inheritable(descriptor)
                    try:
                        with scratch.borrow():
                            observed["new_borrow_refused"] = False
                    except FixtureMismatch as error:
                        observed["new_borrow_refused"] = str(error) == "Capture exposure directory retired"
            finally:
                writer_done.set()

        def observe_scope(command, evidence_name, case, scratch):
            observed["scratch"] = scratch
            return original_scope(command, evidence_name, case, scratch)

        def start_terminal(term, *_args):
            socket_path = Path(term.command[4])
            observed["terminal_scratch"] = socket_path.parent
            with closing(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)) as listener:
                listener.bind(str(socket_path))

        def fail_terminal(_predicate, _description, observer):
            observed["ledger"] = observer.turns._path
            observed["observer"] = observer
            observed["snapshot"] = MagicMock(wraps=observer.turns.verified_records)
            observer.turns.verified_records = observed["snapshot"]
            history = stock_history([{"type": "message", "role": "user",
                                      "content": [{"type": "input_text", "text": PROMPT}]}])
            observer.turns.dispatch(AUTHORITY, "ses_capture", history, lambda _request: None)
            with socket.create_connection(observer.server_address, timeout=2) as client:
                client.sendall(b"GET /fixture HTTP/1.1\r\nHost: localhost\r\n\r\n")
                self.assertTrue(entered.wait(2))
            if change_scratch is not None:
                change_scratch(observed["terminal_scratch"])
            raise primary

        fixture = "stock_worker_tools_capture"
        terminal_server = MagicMock()
        terminal_server.poll.return_value = None
        original_scope = getattr(capture_fixture, "capture_in_scope", None)
        scope_probe = (patch.object(capture_fixture, "capture_in_scope", observe_scope) if stalled_in == "writer"
                       else nullcontext())
        stall = (patch.object(Observer, "get_request", stall_serving) if stalled_in == "serving"
                 else patch.object(WireHandler, "do_GET", stall_handler, create=True))
        with scope_probe, stall, patch(f"{fixture}.PORT", 0), patch(f"{fixture}.OBSERVER_STOP_SECONDS", .2, create=True), \
                patch.object(Terminal, "launch_server", return_value=terminal_server, create=True), \
                patch.object(Terminal, "await_server", create=True), \
                patch(f"{fixture}.stock_config", return_value={}), patch.object(Terminal, "start", start_terminal), \
                patch.object(Terminal, "run"), patch.object(Terminal, "await_screen", side_effect=fail_terminal), \
                patch("sys.stderr", StringIO()) as stderr, ThreadPoolExecutor() as pool:
            result = pool.submit(capture, ("/unused-stock-fixture",), evidence, "tools")
            try:
                with self.assertRaisesRegex(RuntimeError, "synthetic terminal failure") as raised:
                    result.result(timeout=2)
                self.assertIs(raised.exception, primary)
                ledger = observed["ledger"]
                self.assertTrue(ledger.is_file())
                self.assertEqual(stat.S_IMODE(ledger.parent.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(ledger.stat().st_mode), 0o600)
                self.assertEqual(observed["observer"].socket.fileno(), -1)
                self.assertTrue(any(str(ledger.parent) in note for note in primary.__notes__))
                self.assertFalse(finished.is_set())
                observed["snapshot"].assert_not_called()
                if stalled_in == "writer":
                    self.assertTrue((ledger.parent / "recovery.json").is_file())
                self.assertEqual(json.loads(evidence.read_text()),
                                 {"phase": "failed", "exposure": {"status": "unavailable"}})
                self.assertEqual(stderr.getvalue(), "")
            finally:
                released.set()
                self.assertTrue(finished.wait(2))
                for root in {observed["ledger"].parent, observed["terminal_scratch"]}:
                    self.addCleanup(shutil.rmtree, root, ignore_errors=True)
                if stalled_in == "writer":
                    self.assertTrue(writer_done.wait(2))
        return observed

    def test_failed_capture_marks_damaged_journal_without_inventing_claims(self):
        def alter_ledger(path):
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("UPDATE exposure SET actual_input = 12")

        for damage, status in ((alter_ledger, "corrupt"), (Path.unlink, "unavailable")):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                evidence = Path(directory) / "failure.json"
                primary, _ = self.capture_with_failed_send(evidence, damage=damage)
                self.assertEqual(json.loads(evidence.read_text())["exposure"], {"status": status})
                self.assertIn(f"Synthetic exposure evidence {status}", primary.__notes__)

    def test_failed_capture_never_changes_existing_evidence_leaf(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            existing = root / "preserve"
            existing.write_text("sentinel")
            evidence = root / "failure.json"
            evidence.symlink_to(existing)
            primary, _ = self.capture_with_failed_send(evidence)
            self.assertTrue(evidence.is_symlink())
            self.assertEqual(existing.read_text(), "sentinel")
            self.assertTrue(any("Unable to save secondary evidence" in note for note in primary.__notes__))

    def test_capsule_cannot_run_from_checkout(self):
        with self.assertRaisesRegex(RuntimeError, "outside its fixed root-owned"):
            capsule()

    def test_copied_projection_mutates_only_the_exact_tls_function(self):
        source = ROOT / "oc_openai/responses.py"
        with tempfile.TemporaryDirectory() as work:
            location = Path(work) / "oc_openai"
            location.mkdir()
            copied = location / source.name
            before = source.read_text()
            copied.write_text(before)
            project_sources(Path(work))
            after = copied.read_text()
            marker = "def _connect(host, cancellation):\n"
            boundary = "\n\ndef _validate_http(response):"
            self.assertEqual(before.split(marker)[0], after.split(marker)[0])
            self.assertEqual(before.split(boundary)[1], after.split(boundary)[1])
            self.assertIn("stock_worker_tools_projection.py", after)
            compile(after, str(copied), "exec")
            copied.write_text(before.replace(marker, "def different_function():\n"))
            with self.assertRaisesRegex(RuntimeError, "TLS seam changed"):
                project_sources(Path(work))

    def test_source_inventory_covers_driver_and_real_admission(self):
        files = describe_source(ROOT)
        for name in ("oc-sandbox", "oc-openai-session.py", "oc_openai/session_protocol.py",
                     "oc_openai/session_broker.py", "tests/e2e/stock_worker_tools_guest.py",
                     "tests/e2e/stock_worker_tools_peer.py"):
            self.assertIn(name, files)


class DriverGuardTests(unittest.TestCase):
    def test_foreground_wait_returns_the_matching_terminal_capture(self):
        term = Terminal(Path("/tmp/unopened"), {})
        expected = "Start interactive OpenCode session for instance 'default'? [y/N]"
        with patch.object(term, "run", return_value=expected + "\n"):
            self.assertEqual(term.await_screen(lambda line: expected in line, "route approval"), expected + "\n")

    def test_http_status_survives_timeout_after_headers(self):
        request = {"host": "127.0.0.1", "port": 8401, "method": "GET",
                   "path": "/v1/models", "body": None, "token": "test"}
        response = MagicMock(status=200)
        response.read.side_effect = TimeoutError("body did not arrive")
        stdout = StringIO()
        with patch("http.client.HTTPConnection") as connection, patch("sys.stdout", stdout), \
                patch("sys.stdin", StringIO(json.dumps(request))):
            connection.return_value.getresponse.return_value = response
            exec(WIRE, {})
            connection.return_value.close.assert_called_once_with()
        self.assertEqual(json.loads(stdout.getvalue()), {"status": 200, "body": ""})

    def test_egress_probe_performs_only_bounded_socket_connect(self):
        stdout = StringIO()
        with patch("socket.create_connection") as connect, patch("sys.stdout", stdout), \
                patch("sys.stdin", StringIO('["192.0.2.1", 443]')):
            exec(TCP_CONNECT, {})
        connect.assert_called_once_with(("192.0.2.1", 443), timeout=3)
        self.assertTrue(json.loads(stdout.getvalue()))
        self.assertEqual([entry[0] for entry in connect.return_value.mock_calls], ["__enter__", "__exit__"])

    def test_held_reader_reap_escalates_and_bounds_both_waits(self):
        child = MagicMock()
        child.poll.return_value = None
        timeout = subprocess.TimeoutExpired("held-reader", 2)
        child.wait.side_effect = [timeout, timeout]
        with self.assertRaises(subprocess.TimeoutExpired):
            reap_held_child(child)
        self.assertEqual(child.mock_calls, [
            call.poll(), call.terminate(), call.wait(timeout=2), call.kill(), call.wait(timeout=2),
        ])

    def test_outside_tcp_connection_without_http_headers_is_still_reachable(self):
        request = {"host": "192.0.2.1", "port": 8401, "method": "GET",
                   "path": "/v1/models", "body": None, "token": "test"}
        stdout = StringIO()
        with patch("http.client.HTTPConnection") as connection, patch("sys.stdout", stdout), \
                patch("sys.stdin", StringIO(json.dumps(request))):
            connection.return_value.getresponse.side_effect = ConnectionResetError()
            exec(WIRE, {})
        self.assertIsNone(json.loads(stdout.getvalue())["status"])  # The earlier predicate accepted this.
        host, sibling = object(), object()
        with patch("stock_worker_tools_guest.tcp_connect", side_effect=[False, False, False, True]) as connect:
            with self.assertRaisesRegex(FixtureMismatch, "independently networked container connected"):
                verify_outside_candidates(host, sibling, ("192.0.2.1",))
        self.assertEqual(connect.call_args_list, [
            call(host, "127.0.0.1", 8401), call(sibling, "127.0.0.1", 8401),
            call(host, "192.0.2.1", 8401), call(sibling, "192.0.2.1", 8401),
        ])

    def test_direct_broker_control_authenticates_the_exact_private_frame(self):
        support = runpy.run_path(str(ROOT / "tests/test_openai_session_broker.py"))
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        lease, fd = support["_make_lease"](root)
        self.addCleanup(os.close, fd)
        (root / "provider").mkdir()
        (root / "proof").mkdir()
        proof = os.urandom(32)
        (root / "proof/relay").write_bytes(proof)
        upstream = MagicMock(side_effect=AssertionError("Local model catalog must not dispatch upstream"))
        broker = SessionBroker(socket_path=root / "provider/provider.sock", relay_proof=proof,
                               worker_token="test-token", lease=lease, connection=support["_FakeConn"](upstream),
                               binding=object(), models=(MODEL,), profile_label=LABEL)
        broker.start()
        self.addCleanup(broker.close)
        # The earlier unframed probe closes regardless of whether the caller knows the actual proof.
        raw = (b"GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1:8401\r\n"
               b"Authorization: Bearer test-token\r\n\r\n")
        self.assertEqual(broker_exchange(broker.socket_path, raw), b"")
        verify_direct_broker(root, "test-token")
        with patch("stock_worker_tools_guest.broker_exchange", return_value=b""):
            with self.assertRaisesRegex(FixtureMismatch, "framed private relay control"):
                verify_direct_broker(root, "test-token")
        upstream.assert_not_called()

    def test_foreground_checks_complete_disclosure_before_sending_yes(self):
        provider = (f"Provider openai/{LABEL} [{PROVIDER}]: auth=subscription, "
                    f"policy=subscription (no verified spending ceiling) (models: {MODEL})")
        launch = (f"Initial active model: {PROVIDER}/{MODEL} | UI: OpenCode (default) | "
                  "Workspace: /sandbox/construct")
        prompt = "Start interactive OpenCode session for instance 'default'? [y/N]"
        term = MagicMock()
        for altered in (launch.replace(MODEL, MODEL + "-unexpected"), launch + "/unexpected"):
            with self.subTest(altered=altered), patch("stock_worker_tools_guest.assert_no_slot") as no_slot:
                term.await_screen.return_value = "\n".join(
                    (provider, altered, "No API-key fallback will be forwarded.", prompt))
                # Both prefixes matched the earlier launcher predicate.
                self.assertIn(f"Initial active model: {PROVIDER}/{MODEL}", altered)
                self.assertIn("Workspace: /sandbox/construct", altered)
                with self.assertRaisesRegex(FixtureMismatch, "differs from the approved launch"):
                    confirm_foreground(term, approve=True)
                term.type_line.assert_not_called()
                no_slot.assert_not_called()
        term.await_screen.return_value = "\n".join((provider, launch, "No API-key fallback will be forwarded.", prompt))
        with patch("stock_worker_tools_guest.assert_no_slot") as no_slot:
            confirm_foreground(term, approve=True)
        no_slot.assert_called_once_with()
        term.type_line.assert_called_once_with("y")

    def test_idle_requires_the_final_title(self):
        pending = {"messages": [{"type": "idle"}], "info": {"title": "pending"}}
        complete = {"messages": [{"type": "idle"}], "info": {"title": TITLE}}
        observed = iter((pending, complete))
        with patch("stock_worker_tools_capture.time.sleep"):
            self.assertIs(await_idle(lambda: next(observed)), complete)

    def test_listener_accepts_exact_ipv4_loopback_and_rejects_wildcards(self):
        local = "0: 0100007F:20D1 00000000:0000 0A"
        self.assertIsNone(verify_loopback_listener(local))
        for wildcard in ("00000000", "00000000000000000000000000000000"):
            with self.subTest(wildcard=wildcard), self.assertRaisesRegex(FixtureMismatch, "only on IPv4 loopback"):
                verify_loopback_listener(local + f"\n1: {wildcard}:20D1 00000000:0000 0A")

    def test_failed_proof_preserves_primary_and_checks_all_cleanup(self):
        def action(log):
            executed.append(log)
            raise RuntimeError(log)

        executed = []
        primary = RuntimeError("primary fixture error")
        run_cleanup(primary, lambda: action("container"), lambda: action("lease"))
        self.assertEqual(str(primary), "primary fixture error")
        self.assertEqual(executed, ["container", "lease"])
        self.assertEqual(primary.__notes__, ["Fixture cleanup: RuntimeError: container",
                                            "Fixture cleanup: RuntimeError: lease"])

    def test_held_reader_requires_framed_http_and_sse_and_compiles(self):
        compile(HOLD_READER, "held-reader", "exec")
        self.assertIn("response.status != 200", HOLD_READER)
        self.assertIn("event: response.created", HOLD_READER)
        self.assertIn("'event': 'timeout'", HOLD_READER)
        self.assertIn("'event': 'closed'", HOLD_READER)


class PodMcsGuardTests(unittest.TestCase):
    def setUp(self):
        pod_id = "a" * 64
        process_prefix = "system_u:system_r:container_t:"
        mount_prefix = "system_u:object_r:container_file_t:"
        self.infra = {
            "Id": "b" * 64, "Pod": pod_id, "IsInfra": True,
            "ProcessLabel": process_prefix + "s0:c349,c422",
            "Image": "", "ImageName": "", "Path": "/catatonit", "Args": ["-P"],
            "Mounts": [], "HostConfig": {"Privileged": False},
        }
        self.worker = {"Id": "c" * 64, "Pod": pod_id, "IsInfra": False,
                       "ProcessLabel": process_prefix + "s0:c643,c775"}
        self.relay = {"Id": "d" * 64, "Pod": pod_id, "IsInfra": False,
                      "ProcessLabel": process_prefix + "s0:c349,c422",
                      "MountLabel": mount_prefix + "s0:c349,c422"}
        self.browser = {"Id": "e" * 64, "Pod": pod_id, "IsInfra": False,
                        "ProcessLabel": process_prefix + "s0:c17,c332"}
        self.details = [self.infra, self.worker, self.relay, self.browser]
        self.pod = {"Id": pod_id, "InfraContainerID": self.infra["Id"], "InfraConfig": {"PortBindings": {}},
                    "Containers": [{"Id": item["Id"]} for item in self.details]}

    def verify(self, *, details=None):
        verify_relay_mcs(self.pod, self.worker, self.relay, self.details if details is None else details)

    def test_measured_pause_label_was_rejected_by_old_all_sibling_predicate(self):
        level = self.relay["ProcessLabel"].split(":", 3)[-1]
        self.assertFalse(all(other["Id"] == self.relay["Id"] or other["ProcessLabel"].split(":", 3)[-1] != level
                             for other in self.details))
        self.verify()

    def test_rejects_changed_pause_process_image_mounts_or_privilege(self):
        changes = {
            "Image": "f" * 64, "ImageName": "substitute", "Path": "/bin/sh", "Args": ["-c"],
            "Mounts": [{"Destination": "/sandbox"}], "HostConfig": {"Privileged": True}, "IsInfra": False,
        }
        for field, value in changes.items():
            with self.subTest(field=field), self.assertRaisesRegex(FixtureMismatch, "qualified pause"):
                self.verify(details=[{**self.infra, field: value}, *self.details[1:]])

    def test_rejects_duplicate_missing_and_foreign_inspected_membership(self):
        with self.assertRaisesRegex(FixtureMismatch, "inspection changed membership"):
            self.verify(details=[*self.details[:-1], self.infra])
        with self.assertRaisesRegex(FixtureMismatch, "inspection changed membership"):
            self.verify(details=[*self.details[:-1], {**self.browser, "Pod": "f" * 64}])
        with self.assertRaisesRegex(FixtureMismatch, "Duplicate infrastructure"):
            self.verify(details=[*self.details[:-1], {**self.browser, "IsInfra": True}])
        self.pod["Containers"].append({"Id": self.relay["Id"]})
        with self.assertRaisesRegex(FixtureMismatch, "membership is missing or ambiguous"):
            self.verify()

    def test_rejects_real_sibling_collision_with_categories_in_reverse_order(self):
        self.browser["ProcessLabel"] = self.relay["ProcessLabel"].replace("c349,c422", "c422,c349")
        with self.assertRaisesRegex(FixtureMismatch, "shared with an application sibling"):
            self.verify()

    def test_rejects_unqualified_real_sibling_category(self):
        for suffix in ("s0", "s0:c3,c3", "s0:c17,c1024"):
            with self.subTest(suffix=suffix), self.assertRaisesRegex(FixtureMismatch, "category"):
                self.verify(details=[*self.details[:-1], {**self.browser, "ProcessLabel":
                                     "system_u:system_r:container_t:" + suffix}])


def nft_table():
    name = "oc_gemini_fixture"
    base = {"family": "inet", "table": name}
    rules = [
        {**base, "chain": "output", "expr": [
            {"match": {"left": {"meta": {"key": "oifname"}}, "op": "==", "right": "lo"}},
            {"accept": None},
        ]},
        {**base, "chain": "output", "expr": [
            {"match": {"left": {"ct": {"key": "direction"}}, "op": "==", "right": "reply"}},
            {"match": {"left": {"payload": {"protocol": "tcp", "field": "sport"}}, "op": "==", "right": 22}},
            {"match": {"left": {"ct": {"key": "state"}}, "op": "in", "right": "established"}},
            {"accept": None},
        ]},
    ]
    return [{"table": {"family": "inet", "name": name}}, *(
        {"chain": {**base, "name": hook, "type": "filter", "hook": hook, "prio": 0, "policy": "drop"}}
        for hook in ("output", "forward")), *({"rule": rule} for rule in rules)]


class FirewallGuardTests(unittest.TestCase):
    def test_accepts_only_expected_loopback_and_management_reply(self):
        table = nft_table()
        expected = firewall_shape(json.dumps({"nftables": table}))
        self.assertEqual(len(expected), 64)
        table[-1]["rule"]["expr"][0]["match"]["right"] = "original"
        with self.assertRaisesRegex(RuntimeError, "Unexpected exception"):
            firewall_shape(json.dumps({"nftables": table}))


class ProtocolGuardTests(unittest.TestCase):
    workspace = "/sandbox/construct"
    tools = [
        {"type": "function", "name": name, "parameters": {"type": "object", "properties": properties}}
        for name, properties in (
            ("patch", {"patchText": {"type": "string"}}),
            ("read", {"path": {"type": "string"}}),
            ("shell", {"command": {"type": "string"}, "timeout": {"type": "integer"},
                       "workdir": {"type": "string"}}),
        )
    ]

    def setUp(self):
        self.script = ToolScript(self.workspace)
        self.base = {"model": MODEL, "store": False, "stream": True,
                     "input": [{"role": "user", "content": PROMPT}], "tools": self.tools}

    def request(self, count):
        value = deepcopy(self.base)
        for stage in range(count):
            value["input"].extend([
                {"type": "function_call", "name": TOOL_NAMES[stage], "call_id": call_id(stage),
                 "arguments": json.dumps(self.script.arguments[stage])},
                {"type": "function_call_output", "call_id": call_id(stage),
                 "output": expected_result(stage, self.workspace)},
            ])
        return value

    def test_public_fixture_script_requires_exact_results_and_auxiliary_title(self):
        self.script.respond({**self.base, "tools": [], "input": [{"role": "user", "content": TITLE_PROMPT}]})
        for stage in range(4):
            self.script.respond(self.request(stage))
        self.script.verify_done()
        extra_inference = self.request(3)
        with self.assertRaisesRegex(FixtureMismatch, "Unexpected stock inference"):
            self.script.respond(extra_inference)

    def test_rejects_changed_tool_result_before_sending_later_tool(self):
        self.script.respond(self.request(0))
        invalid = self.request(1)
        invalid["input"][-1]["output"] += "changed"
        with self.assertRaisesRegex(FixtureMismatch, "patch result differed"):
            self.script.respond(invalid)
        self.assertEqual(len(self.script.requests), 1)

    def test_negative_hosted_fixture_precedes_rejection_with_a_valid_buffered_worker_call(self):
        events = list(refused_events("hosted", self.base, self.workspace))
        self.assertEqual(events[-2]["item"]["name"], "patch")
        self.assertIn(REFUSED_FILE, events[-2]["item"]["arguments"])
        projector = SessionStreamProjector(model=MODEL, local_response_id="resp_local_probe",
                                           vault=ReasoningVault(), allowed_tools=frozenset({"patch"}))
        observed = [frame for item in events[:-1] for frame in projector.feed(item)]
        self.assertNotIn(b"function_call", b"".join(observed))
        with self.assertRaisesRegex(StreamAborted, "unsupported_event"):
            projector.feed(events[-1])

    def test_hosted_event_cannot_release_earlier_buffered_tool_frames(self):
        for event in ("response.web_search_call.completed", "response.mcp_call.completed",
                      "response.code_interpreter_call.completed"):
            with self.subTest(event=event):
                projector = SessionStreamProjector(model=MODEL, local_response_id="resp_local_probe",
                                                   vault=ReasoningVault(), allowed_tools=frozenset({"patch"}))
                sequence = list(response_events(0, {"patchText": "synthetic"}))
                observed = [frame for item in sequence[:-1] for frame in projector.feed(item)]
                self.assertNotIn(b"function_call", b"".join(observed))
                with self.assertRaises(StreamAborted):
                    projector.feed({"type": event})


if __name__ == "__main__":
    unittest.main()
