"""Synthetic tests of the foreground OpenAI authorization boundary."""

from collections import deque
from dataclasses import replace
import io
import os
import select
import signal
import time
import traceback
import unittest
from unittest.mock import patch

from oc_openai.cli import (
    MODEL, PROPOSAL_MARKER, ConnectionBinding, ConnectionStatus, Reason, RouteUnavailable, SavedProfile,
    Stage, StreamTerminal, WorkerEvidence, run,
)


BINDING = ConnectionBinding("a" * 43, "b" * 43, MODEL, "personal", "e" * 43)
COMPLETE = WorkerEvidence(True, True, True, True)
CANARY = "private-fixture-content"


class FakeTerminal:
    def __init__(self, *approvals, attended=True):
        self.interactive = attended
        self.approvals = deque(approvals)
        self.prompts = []
        self.output = []

    def attended(self):
        return self.interactive

    def write(self, message):
        self.output.append(message)

    error = write

    def confirm(self, message):
        self.prompts.append(message)
        answer = self.approvals.popleft()
        return answer() if callable(answer) else answer


class FakeBackend:
    def __init__(self):
        self.binding = BINDING
        self.response = PROPOSAL_MARKER
        self.evidence = COMPLETE
        self.calls = []
        self.revoked = True
        self.preflight_error = None
        self.local_status = ConnectionStatus((SavedProfile("personal", True),), "personal")

    def connection(self):
        return self.binding

    def propose(self, approval):
        self.calls.append(("inference", approval))
        if isinstance(self.response, BaseException):
            raise self.response
        return self.response

    def prove(self, approval):
        self.calls.append(("proof", approval))
        return self.evidence

    def connect(self, label):
        self.calls.append(("connect", label))

    def active_label(self):
        return self.status().active

    def status(self):
        return self.local_status

    def select(self, label):
        self.calls.append(("select", label))

    def require_acceptance(self):
        if self.preflight_error is not None:
            raise self.preflight_error

    def disconnect(self):
        self.calls.append(("disconnect", None))
        return self.revoked


class OpenAICommandTests(unittest.TestCase):
    def setUp(self):
        self.backend = FakeBackend()

    def call(self, terminal, *args):
        return run(args, terminal=terminal, backend_factory=lambda: self.backend)

    def test_second_confirmation_authorizes_exactly_one_proof_and_pins_both_stages(self):
        def first():
            self.assertEqual(self.backend.calls, [])
            return True

        def second():
            self.assertEqual([kind for kind, _ in self.backend.calls], ["inference"])
            return True

        terminal = FakeTerminal(first, second)
        self.assertEqual(self.call(terminal, "accept"), 0)
        self.assertEqual([kind for kind, _ in self.backend.calls], ["inference", "proof"])
        (_, request), (_, proof) = self.backend.calls
        self.assertEqual((request.stage, proof.stage), (Stage.ORCHESTRATOR, Stage.WORKER))
        self.assertEqual(request.run_id, proof.run_id)
        self.assertEqual(request.connection, BINDING)
        self.assertEqual(proof.connection, BINDING)
        self.assertEqual(len(terminal.prompts), 2)
        output = "\n".join(terminal.output)
        self.assertNotIn(BINDING.registration_id, output)
        self.assertEqual(output.count("Active registration: personal."), 2)
        self.assertIn("922,000 input and 128,000 output", output)
        self.assertIn("1,844,000 input and 256,000 output", output)
        self.assertEqual(output.count("There is no verified hard spending cap."), 2)
        self.assertEqual(output.count("API-key fallback is disabled."), 2)

    def test_declines_at_each_stage(self):
        for approvals, effects in [((False,), []), ((True, False), ["inference"])]:
            with self.subTest(approvals=approvals):
                self.backend.calls.clear()
                terminal = FakeTerminal(*approvals)
                self.assertEqual(self.call(terminal, "accept"), 1)
                self.assertEqual([kind for kind, _ in self.backend.calls], effects)

    def test_connection_change_during_each_approval_voids_it(self):
        changes = (
            replace(BINDING, generation="c" * 43),
            replace(BINDING, registration_id="d" * 43),
            replace(BINDING, model="other-model"),
            replace(BINDING, label="work"),
            replace(BINDING, selection_epoch="f" * 43),
            None,
        )
        for target, effects in [(1, []), (2, ["inference"])]:
            for binding in changes:
                with self.subTest(stage=target, binding=binding):
                    self.backend.binding = BINDING
                    self.backend.calls.clear()

                    def reconnect():
                        self.backend.binding = binding
                        return True

                    approvals = (reconnect,) if target == 1 else (True, reconnect)
                    terminal = FakeTerminal(*approvals)
                    self.assertEqual(self.call(terminal, "accept"), 1)
                    self.assertEqual([kind for kind, _ in self.backend.calls], effects)

    def test_missing_terminal_or_invalid_arguments_never_construct_backend(self):
        def forbidden_factory():
            self.fail("invalid invocation constructed a backend")

        for argv in [
            ("accept",), ("connect", "personal"), ("connect",), ("connect", "../outside"),
            ("select", "personal", "extra"), ("select", "\x1b[31m"), ("status", "--debug"), (),
            ("unsupported",),
        ]:
            with self.subTest(argv=argv):
                terminal = FakeTerminal(attended=False)
                self.assertEqual(run(argv, terminal=terminal, backend_factory=forbidden_factory), 2)

    def test_rejects_wrong_response_and_redacts_route_failures(self):
        for response, result in [
            (PROPOSAL_MARKER + "\n", 1),
            (CANARY, 1),
            (RuntimeError(CANARY), 1),
            (RouteUnavailable(CANARY), 1),
            (KeyboardInterrupt(), 130),
        ]:
            with self.subTest(response=response):
                self.backend.calls.clear()
                self.backend.response = response
                terminal = FakeTerminal(True)
                self.assertEqual(self.call(terminal, "accept"), result)
                self.assertEqual([kind for kind, _ in self.backend.calls], ["inference"])
                self.assertEqual(len(terminal.prompts), 1)
                self.assertNotIn(CANARY, "\n".join(terminal.output))

    def test_all_worker_receipts_required_even_after_a_valid_proposal(self):
        for field in vars(COMPLETE):
            with self.subTest(field=field):
                self.backend.evidence = replace(COMPLETE, **{field: False})
                terminal = FakeTerminal(True, True)
                self.assertEqual(self.call(terminal, "accept"), 1)
                self.assertNotIn("completed the scratch-file proof", "\n".join(terminal.output))

    def test_connect_status_disconnect_have_no_inference(self):
        terminal = FakeTerminal(False)
        self.assertEqual(self.call(terminal, "connect", "work"), 1)
        self.assertEqual(self.backend.calls, [])
        terminal = FakeTerminal(True)
        for args in (("connect", "work"), ("select", "work"), ("status",), ("disconnect",)):
            self.assertEqual(self.call(terminal, *args), 0)
        self.assertEqual(self.backend.calls, [("connect", "work"), ("select", "work"), ("disconnect", None)])
        self.backend.revoked = False
        self.assertEqual(self.call(terminal, "disconnect"), 1)
        self.assertIn("Remote revocation could not be confirmed", "\n".join(terminal.output))
        self.assertNotIn(BINDING.registration_id, "\n".join(terminal.output))
        disclosure = "\n".join(terminal.output)
        for fact in (
            "Active registration: personal.", "Continue with ChatGPT for registration work",
            "installation's identifier", "verified account identity and provider tokens",
            "attempts revocation with OpenAI", "registration labels and IDs", "numeric usage accounting",
            "only after separate authorization",
        ):
            self.assertIn(fact, disclosure)

    def test_status_reports_local_connection_without_model_qualification(self):
        self.backend.binding = replace(BINDING, model="unqualified-model")
        self.backend.local_status = ConnectionStatus(
            (SavedProfile("personal", True), SavedProfile("work", False)), "personal",
        )
        terminal = FakeTerminal()
        self.assertEqual(self.call(terminal, "status"), 0)
        self.assertEqual(terminal.output, ["personal (connected, active)", "work (disconnected)"])
        self.assertEqual(self.backend.calls, [])
        self.backend.local_status = ConnectionStatus((), None)
        self.assertEqual(self.call(terminal, "status"), 0)
        self.assertEqual(terminal.output[-1], "No ChatGPT registrations are saved.")

    def test_status_refuses_untrusted_label_text(self):
        self.backend.local_status = ConnectionStatus((SavedProfile(CANARY + "\x1b[2J", True),), None)
        terminal = FakeTerminal()
        self.assertEqual(self.call(terminal, "status"), 1)
        self.assertNotIn(CANARY, "\n".join(terminal.output))

    def test_placement_failure_precedes_both_prompts_and_all_effects(self):
        self.backend.preflight_error = RouteUnavailable(Reason.PLACEMENT)
        terminal = FakeTerminal()
        self.assertEqual(self.call(terminal, "accept"), 1)
        self.assertEqual(terminal.prompts, [])
        self.assertEqual(self.backend.calls, [])
        self.assertIn("managed worker prerequisites", terminal.output[0])

    def test_unavailable_diagnostics_are_projected_from_fixed_reasons(self):
        terminal = FakeTerminal(True)
        self.backend.response = RouteUnavailable(Reason.EXPOSURE)
        self.assertEqual(self.call(terminal, "accept"), 1)
        self.assertIn("Further inference is suspended.", "\n".join(terminal.output))

    def test_terminal_rejects_eof_partial_approval_and_extra_input(self):
        for source in (b"", b"yes", b"yes please\n", b"yes\n"):
            with self.subTest(source=source):
                read_fd, write_fd = os.pipe()
                os.write(write_fd, source)
                os.close(write_fd)
                with os.fdopen(read_fd) as reader:
                    terminal = StreamTerminal(reader, io.StringIO(), io.StringIO())
                    with patch.object(terminal, "attended", return_value=True), patch("oc_openai.cli.termios.tcflush"):
                        self.assertEqual(terminal.confirm("Approve?"), source == b"yes\n")

    def test_controlling_foreground_tty_is_required_and_typeahead_cannot_approve_stage_two(self):
        other_master, other_slave = os.openpty()
        master, slave = os.openpty()
        child = os.fork()
        if child == 0:
            os.login_tty(slave)
            result = 1
            stdin = os.fdopen(os.dup(0))
            stdout = os.fdopen(os.dup(1), "w")
            stderr = os.fdopen(os.dup(2), "w", buffering=1)
            try:
                terminal = StreamTerminal(stdin, stdout, stderr)
                assert terminal.attended()
                with os.fdopen(master) as master_side:
                    assert not StreamTerminal(master_side, stdout, stderr).attended()
                    assert not StreamTerminal(stdin, master_side, stderr).attended()
                with os.fdopen(other_slave) as other:
                    assert not StreamTerminal(stdin, other, stderr).attended()
                    assert not StreamTerminal(other, other, stderr).attended()
                for detach in (os.setsid, lambda: os.setpgid(0, 0)):
                    subchild = os.fork()
                    if subchild == 0:
                        detach()
                        os._exit(1 if terminal.attended() else 0)
                    assert os.waitpid(subchild, 0)[1] == 0
                first = terminal.confirm("First?")
                second = terminal.confirm("Second?")
                terminal.write(f"Approvals: {first} {second}")
                result = 0
            except BaseException:
                traceback.print_exc(file=stderr)
            finally:
                os._exit(result)

        os.close(slave)
        os.close(other_slave)
        output = bytearray()

        def receive(marker):
            deadline = time.monotonic() + 3
            while marker not in output:
                ready, _, _ = select.select([master], [], [], max(0, deadline - time.monotonic()))
                self.assertTrue(ready, output)
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    chunk = b""
                self.assertTrue(chunk, output)
                output.extend(chunk)

        reaped = False
        try:
            receive(b"First? Type yes to approve.")
            os.write(master, b"yes\nyes\n")
            receive(b"Second? Type yes to approve.")
            os.write(master, b"no\n")
            receive(b"Approvals: True False")
            _, status = os.waitpid(child, 0)
            reaped = True
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        finally:
            os.close(master)
            os.close(other_master)
            if not reaped and not os.waitpid(child, os.WNOHANG)[0]:
                os.kill(child, signal.SIGKILL)
                os.waitpid(child, 0)


if __name__ == "__main__":
    unittest.main()
