"""Proof of the fixed ACP exit sequence with disposable local Python peers."""

from copy import copy, deepcopy
from dataclasses import replace
import json
import os
import pickle
import signal
import subprocess
import sys
from threading import RLock
import time
import unittest
from unittest.mock import patch

from oc_google.native_generation_transcript import (
    GenerationTranscript, NaturalExitReceipt, TranscriptUnavailable, UnitRetirementReceipt,
)
from oc_google.native_service import NativeInvocation


_SESSION = "cdc030fd-3f2d-4eab-8804-17fa3fabfd5e"
_PEER = """
import os
import signal
import sys
import time

mode = sys.argv[2]
if mode == 'trap-zero':
    signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
if sys.stdin.buffer.readline() != b'synthetic prompt\\n':
    os._exit(90)
os.write(1, bytes.fromhex(sys.argv[1]))
if sys.stdin.buffer.read():
    os._exit(91)
if len(sys.argv) == 4:
    os.write(1, bytes.fromhex(sys.argv[3]))
os.close(1)
if mode in ('hang', 'trap-zero'):
    time.sleep(30)
if mode == 'signal':
    os.kill(os.getpid(), signal.SIGTERM)
os._exit(7 if mode == 'fail' else 0)
"""


def frame(value):
    return json.dumps(value, separators=(",", ":")).encode("ascii") + b"\n"


def update(text, *, session=_SESSION, update_type="agent_message_chunk", content_type="text"):
    return frame({"jsonrpc": "2.0", "method": "session/update", "params": {
        "sessionId": session,
        "update": {"sessionUpdate": update_type, "content": {"type": content_type, "text": text}},
    }})


def terminal(*, request_id=4, reason="end_turn", **extra):
    return frame({"jsonrpc": "2.0", "id": request_id, "result": {"stopReason": reason, **extra}})


def cleanup_child(process):
    if process.poll() is None:
        process.kill()
    process.wait(timeout=2)
    process.stdin.close()
    process.stdout.close()


@unittest.skipUnless(hasattr(os, "pidfd_open"), "requires Linux pidfds")
class GenerationTranscriptTests(unittest.TestCase):
    def setUp(self):
        self.authorized = True
        self.fence = RLock()

    def peer(self, wire=None, *, mode="ok", suffix=None, timeout=2):
        wire = update("ok") + terminal() if wire is None else wire
        suffix_arg = [suffix.hex()] if suffix is not None else []
        self.process = subprocess.Popen(
            [sys.executable, "-IBS", "-c", _PEER, wire.hex(), mode, *suffix_arg], bufsize=0,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        self.addCleanup(cleanup_child, self.process)
        self.identity = NativeInvocation("fixture.service", "a" * 32, b"/fixture.service", self.process.pid)
        pidfd = os.pidfd_open(self.process.pid)
        self.addCleanup(os.close, pidfd)
        self.transcript = self.enterContext(GenerationTranscript(
            self.process.stdin, self.process.stdout, invocation=self.identity, pidfd=pidfd,
            session_id=_SESSION, deadline=time.monotonic() + timeout, authorized=lambda: self.authorized,
            fence=self.fence,
        ))
        self.process.stdin.write(b"synthetic prompt\n")
        return self.transcript

    def observe_exit(self, invocation, deadline):
        self.assertIs(invocation, self.identity)
        status = self.process.wait(timeout=max(.001, deadline - time.monotonic()))
        code = os.CLD_EXITED if status >= 0 else os.CLD_KILLED
        # The real subprocess supplies exit status. Cgroup/systemd observations
        # remain explicit test-fixture receipts in this subprocess-only suite.
        return NaturalExitReceipt(invocation, code, abs(status), 0, True)

    def retirement(self):
        return UnitRetirementReceipt(self.identity, True, True)

    def check_denied(self):
        with self.assertRaises(TranscriptUnavailable):
            self.transcript.finish(self.retirement())

    def test_natural_exit_and_independent_retirement_release_one_exact_value(self):
        proof = self.peer(update("o") + update("k") + terminal())
        self.check_denied()
        self.assertIsNone(proof.read_to_eof())
        self.assertTrue(self.process.stdin.closed)
        self.check_denied()
        self.assertIsNone(proof.attest_exit(self.observe_exit))
        result = proof.finish(self.retirement())
        self.assertIs(type(result), bytes)
        self.assertEqual(result, b"ok")
        self.check_denied()

    def test_other_sessions_controls_callbacks_and_wrong_terminals_are_refused(self):
        wrong_update = frame({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": _SESSION,
                              "update": {"sessionUpdate": "usage_update", "size": 10, "used": 2}}})
        cases = (update("ok", session="other") + terminal(), update("", content_type="text") + terminal(),
                 update("ok", update_type="tool_call") + terminal(), update("ok", content_type="image") + terminal(),
                 update("ok") + wrong_update + terminal(),
                 update("ok") + frame({"jsonrpc": "2.0", "id": 6, "method": "fs/read_text_file", "params": {}}),
                 update("ok") + terminal(request_id=5), update("ok") + terminal(request_id=4.0),
                 update("ok") + terminal(reason="max_tokens"), update("ok") + terminal(extra=0),
                 update("o") + terminal(), update("ok!") + terminal())
        for wire in cases:
            with self.subTest(wire=wire[:90]):
                proof = self.peer(wire)
                with self.assertRaises(TranscriptUnavailable):
                    proof.read_to_eof()
                self.check_denied()

    def test_both_already_buffered_and_later_suffix_are_refused(self):
        valid = update("ok") + terminal()
        for wire, later in ((valid + b"{", None), (valid + b"\n", None), (valid + terminal(), None),
                            (valid, b"{"), (valid, update("ok")), (valid, terminal())):
            with self.subTest(initial=len(wire), later=later):
                proof = self.peer(wire, suffix=later)
                with self.assertRaisesRegex(TranscriptUnavailable, "trailing output"):
                    proof.read_to_eof()
                self.check_denied()

    def test_duplicate_keys_invalid_framing_and_frame_limit(self):
        wire = update("ok") + terminal()
        for invalid in (wire.replace(b'"stopReason":', b'"stopReason":"end_turn","stopReason":'),
                        wire.replace(b"\n", b"\r\n"), b"\xef\xbb\xbf" + wire,
                        wire.replace(b'"ok"', b'"\xff"'), update("o" * 4097) + terminal()):
            with self.subTest(invalid=invalid[:70]):
                proof = self.peer(invalid)
                with self.assertRaises(TranscriptUnavailable):
                    proof.read_to_eof()
                self.check_denied()

    def test_clean_eof_from_nonzero_or_signalled_process_is_not_completion(self):
        for mode in ("fail", "signal"):
            with self.subTest(mode=mode):
                proof = self.peer(mode=mode)
                self.assertIsNone(proof.read_to_eof())
                with self.assertRaisesRegex(TranscriptUnavailable, "natural completion"):
                    proof.attest_exit(self.observe_exit)
                self.check_denied()
                self.assertEqual(self.process.returncode, 7 if mode == "fail" else -signal.SIGTERM)

    def test_eof_live_process_times_out_even_if_observer_would_report_success(self):
        proof = self.peer(mode="hang", timeout=.4)
        self.assertIsNone(proof.read_to_eof())
        with self.assertRaises(TranscriptUnavailable):
            proof.attest_exit(lambda *_: self.fail("observer ran while original pidfd was still alive"))
        self.check_denied()
        self.assertIsNone(self.process.poll())

    def test_fallback_termination_vetoes_zero_status_from_signal_trap(self):
        proof = self.peer(mode="trap-zero")
        self.assertIsNone(proof.read_to_eof())
        proof.forced_stop()
        self.process.terminate()
        self.assertEqual(self.process.wait(timeout=2), 0)
        with self.assertRaises(TranscriptUnavailable):
            proof.attest_exit(lambda *_: self.fail("forced shutdown was attested"))
        self.check_denied()

    def test_natural_exit_receipt_must_be_exact_and_strictly_typed(self):
        for bad_fields in ({"exec_main_code": True}, {"exec_main_status": False}, {"main_pid": False},
                           {"main_pid": 44}, {"cgroup_vacant": False}, {"exec_main_code": os.CLD_KILLED},
                           {"exec_main_status": 4}, {"clone": True}, {"missing": True}):
            with self.subTest(bad_fields=bad_fields):
                proof = self.peer()
                proof.read_to_eof()

                def observe(invocation, deadline):
                    receipt = self.observe_exit(invocation, deadline)
                    if "missing" in bad_fields:
                        return None
                    if "clone" in bad_fields:
                        return replace(receipt, invocation=replace(invocation))
                    return replace(receipt, **bad_fields)

                with self.assertRaises(TranscriptUnavailable):
                    proof.attest_exit(observe)
                self.check_denied()

    def test_retirement_proof_is_independent_and_bound_to_original_invocation(self):
        for bad_fields in ({"unit_retired": False}, {"cgroup_vacant": False}, {"clone": True}, {"missing": True}):
            with self.subTest(bad_fields=bad_fields):
                proof = self.peer()
                proof.read_to_eof()
                proof.attest_exit(self.observe_exit)
                if "clone" in bad_fields:
                    receipt = replace(self.retirement(), invocation=replace(self.identity))
                elif "missing" in bad_fields:
                    receipt = None
                else:
                    receipt = replace(self.retirement(), **bad_fields)
                with self.assertRaises(TranscriptUnavailable):
                    proof.finish(receipt)
                self.check_denied()

    def test_cancellation_during_exit_observation_or_between_exit_and_retirement(self):
        for lost_at in ("observation", "retirement"):
            with self.subTest(lost_at=lost_at):
                self.authorized = True
                proof = self.peer()
                proof.read_to_eof()
                if lost_at == "observation":
                    def observe(invocation, deadline):
                        receipt = self.observe_exit(invocation, deadline)
                        self.authorized = False
                        return receipt
                    with self.assertRaises(TranscriptUnavailable):
                        proof.attest_exit(observe)
                else:
                    proof.attest_exit(self.observe_exit)
                    self.authorized = False
                self.check_denied()

    def test_constructor_refuses_pidfd_for_a_different_process(self):
        self.peer()
        other = os.pidfd_open(os.getpid())
        self.addCleanup(os.close, other)
        with self.assertRaisesRegex(TranscriptUnavailable, "pidfd does not pin"):
            GenerationTranscript(self.process.stdin, self.process.stdout, invocation=self.identity, pidfd=other,
                                 session_id=_SESSION, deadline=time.monotonic() + 1,
                                 authorized=lambda: True, fence=self.fence)

    def test_stdout_replacement_or_lost_nonblocking_pin_is_refused(self):
        for replaced in (False, True):
            with self.subTest(replaced=replaced):
                proof = self.peer()
                stdout = self.process.stdout.fileno()
                if replaced:
                    read_end, write_end = os.pipe()
                    self.addCleanup(os.close, write_end)
                    try:
                        os.set_blocking(read_end, False)
                        os.dup2(read_end, stdout, inheritable=False)
                    finally:
                        os.close(read_end)
                    os.write(write_end, b"data from replacement")
                else:
                    os.set_blocking(stdout, True)
                with self.assertRaises(TranscriptUnavailable):
                    proof.read_to_eof()
                self.check_denied()

    def test_stop_during_natural_exit_observer_invalidates_otherwise_valid_receipt(self):
        proof = self.peer()
        proof.read_to_eof()

        def observe(invocation, deadline):
            receipt = self.observe_exit(invocation, deadline)
            proof.forced_stop()
            return receipt

        with self.assertRaises(TranscriptUnavailable):
            proof.attest_exit(observe)
        self.check_denied()

    def test_public_stdout_fd_reuse_after_poll_cannot_hide_original_trailing_byte(self):
        proof = self.peer(suffix=b"{")
        public_stdout = self.process.stdout.fileno()
        other_read, other_write = os.pipe()
        self.addCleanup(os.close, other_read)
        os.close(other_write)
        read = os.read
        replaced = False

        def replace_during_eof_read(fd, count):
            nonlocal replaced
            if count == 1:
                replaced = True
                os.dup2(other_read, public_stdout, inheritable=False)
            return read(fd, count)

        with patch.object(os, "read", replace_during_eof_read):
            with self.assertRaisesRegex(TranscriptUnavailable, "trailing output"):
                proof.read_to_eof()
        self.assertTrue(replaced)
        self.assertEqual(self.process.wait(timeout=2), 0)
        self.check_denied()

    def test_copy_cannot_release_a_second_answer(self):
        proof = self.peer()
        proof.read_to_eof()
        proof.attest_exit(self.observe_exit)
        try:
            duplicate = copy(proof)
        except TypeError:
            self.assertEqual(proof.finish(self.retirement()), b"ok")
            return
        self.assertEqual(proof.finish(self.retirement()), b"ok")
        with self.assertRaises(TranscriptUnavailable):
            duplicate.finish(self.retirement())

    def test_copy_cannot_outlive_forced_stop(self):
        proof = self.peer()
        proof.read_to_eof()
        proof.attest_exit(self.observe_exit)
        try:
            duplicate = copy(proof)
        except TypeError:
            proof.forced_stop()
            self.check_denied()
            return
        proof.forced_stop()
        self.check_denied()
        with self.assertRaises(TranscriptUnavailable):
            duplicate.finish(self.retirement())

    def test_transcript_cannot_be_copied_or_serialized(self):
        proof = self.peer()
        for action in (copy, deepcopy, pickle.dumps):
            with self.subTest(action=action), self.assertRaises(TypeError):
                action(proof)

    def test_stdin_reuse_before_terminal_close_does_not_close_replacement(self):
        proof = self.peer()
        public_stdin = self.process.stdin.fileno()
        read_end, write_end = os.pipe()
        self.addCleanup(os.close, read_end)
        self.addCleanup(os.close, write_end)
        terminal_read = proof._terminal

        def replace_after_terminal(fd, poll):
            terminal_read(fd, poll)
            os.dup2(write_end, public_stdin, inheritable=False)

        with patch.object(proof, "_terminal", replace_after_terminal):
            with self.assertRaisesRegex(TranscriptUnavailable, "stdin changed"):
                proof.read_to_eof()
        self.assertEqual(os.fstat(public_stdin).st_ino, os.fstat(write_end).st_ino)
        self.check_denied()

    def test_close_is_idempotent_after_descriptor_numbers_are_reused(self):
        proof = self.peer()
        owned = (proof._stdout_fd, proof._pidfd)
        replacement = os.open("/dev/null", os.O_RDONLY)
        self.addCleanup(os.close, replacement)
        proof.close()
        for fd in owned:
            os.dup2(replacement, fd, inheritable=False)
            self.addCleanup(os.close, fd)
        proof.close()
        for fd in owned:
            self.assertTrue(os.path.samestat(os.fstat(fd), os.fstat(replacement)))
        self.check_denied()
