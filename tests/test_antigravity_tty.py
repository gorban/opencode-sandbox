"""Exercise native-link validation and a real synthetic foreground terminal."""

from contextlib import contextmanager
import errno
import os
import pty
import selectors
import subprocess
import sys
import time
import traceback
import unittest
from urllib.parse import urlencode

import oc_antigravity_tty as handoff


def good_link():
    google = "https://www.googleapis.com/auth/"
    scopes = " ".join((*(google + name for name in ("cloud-platform", "userinfo.email", "userinfo.profile",
                                                   "cclog", "experimentsandconfigs", "aicode")), "openid"))
    fields = {"access_type": "offline",
              "client_id": "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com",
              "code_challenge": "a" * 43, "code_challenge_method": "S256", "prompt": "consent",
              "redirect_uri": handoff.CALLBACK, "response_type": "code", "scope": scopes,
              "state": "x" * 28}
    return "https://accounts.google.com/o/oauth2/auth?" + urlencode(fields)


CHILD = r"""
import fcntl
import os
import signal
import sys
import termios
import time

import oc_antigravity_tty as handoff

fd = int(sys.argv[1])
signal.signal(signal.SIGHUP, signal.SIG_IGN)
fcntl.ioctl(fd, termios.TIOCSCTTY, 0)
try:
    with handoff.foreground_terminal() as terminal:
        mode = sys.argv[3]
        if mode == 'approve':
            print('READY_TO_QUEUE', flush=True)
            sys.stdin.buffer.read(1)
            approved = handoff.approve(terminal, 'fixture', 'a' * 64, time.monotonic() + 4)
            print('APPROVED' if approved else 'DECLINED', flush=True)
        elif mode == 'partial':
            try:
                handoff.request_code(terminal, sys.argv[2], time.monotonic() + .75)
            except handoff.TerminalUnavailable:
                echo = bool(termios.tcgetattr(terminal)[3] & termios.ECHO)
                os.write(terminal, b'Next reader ready\n')
                fresh = handoff.read_line(terminal, 128, time.monotonic() + 3)
                print('FRESH_AND_RESTORED' if echo and fresh == b'fresh' else 'STALE_INPUT', flush=True)
        else:
            code = handoff.request_code(terminal, sys.argv[2], time.monotonic() + 5)
            if code == b'4/synthetic-terminal-code' and termios.tcgetattr(terminal)[3] & termios.ECHO:
                print('FORWARD_AND_RESTORE', flush=True)
except (handoff.TerminalUnavailable, OSError):
    print('CANCELLED_WITHOUT_CODE', flush=True)
"""


@contextmanager
def operator_test_terminal(mode="code"):
    master, slave = pty.openpty()
    terminal = os.fdopen(master, "rb", buffering=0)
    process = None
    try:
        process = subprocess.Popen([sys.executable, "-B", "-c", CHILD, str(slave), good_link(), mode],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True, pass_fds=(slave,))
        yield terminal, process
    finally:
        terminal.close()
        os.close(slave)
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=2)


def terminal_output(master, *, stop=None, timeout=2):
    result = bytearray()
    deadline = time.monotonic() + timeout
    with selectors.DefaultSelector() as ready:
        ready.register(master, selectors.EVENT_READ)
        while (remaining := deadline - time.monotonic()) > 0 and ready.select(remaining):
            try:
                chunk = os.read(master, 8192)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            result.extend(chunk)
            if not chunk or (stop is not None and stop in result):
                break
    return bytes(result)


class HandoffTest(unittest.TestCase):
    def test_validated_authority_and_fixed_callback(self):
        original = good_link()
        self.assertEqual(handoff.authorization_link(original), original)
        invalid = (original.replace("accounts.google.com", "accounts.google.com.evil.invalid"),
                   original.replace("accounts.google.com", "test@accounts.google.com"),
                   original.replace("antigravity.google", "untrusted.example"),
                   original.replace("S256", "plain"), original + "&extra=1", original + "&state=duplicate",
                   original + "#extra", original + "\n")
        for link in invalid:
            with self.subTest(link=link), self.assertRaises(handoff.TerminalUnavailable):
                handoff.authorization_link(link)

    def test_native_link_requires_the_pinned_client_scopes_and_prompt(self):
        original = good_link()
        variants = (original.replace("1071006060591-", "123456789-"),
                    original.replace("openid&", "openid+email&"), original.replace("prompt=consent", "prompt=none"))
        for link in variants:
            with self.subTest(link=link), self.assertRaises(handoff.TerminalUnavailable):
                handoff.authorization_link(link)

    def test_malformed_query_does_not_include_native_text_in_traceback(self):
        private = "fixture-url-query-private-marker"
        invalid = good_link().replace("prompt=consent", private)
        try:
            handoff.authorization_link(invalid)
        except handoff.TerminalUnavailable as error:
            self.assertNotIn(private, "".join(traceback.format_exception(error)))
        else:
            self.fail("malformed query accepted")

    def test_queued_yes_cannot_approve_a_later_scope(self):
        with operator_test_terminal("approve") as (master, process):
            with selectors.DefaultSelector() as output:
                output.register(process.stdout, selectors.EVENT_READ)
                self.assertTrue(output.select(2))
                self.assertEqual(process.stdout.readline(), b"READY_TO_QUEUE\n")
            os.write(master.fileno(), b"yes\n")
            process.stdin.write(b"x")
            process.stdin.flush()
            displayed = terminal_output(master.fileno(), stop=b"Continue with Google sign-in? [y/N]")
            self.assertIn(b"Allow one temporary HTTPS tunnel", displayed)
            os.write(master.fileno(), b"n\n")
            stdout, stderr = process.communicate(timeout=3)
            self.assertEqual((process.returncode, stdout, stderr), (0, b"DECLINED\n", b""))

    def test_timeout_flushes_partial_code_before_restoring_echo(self):
        with operator_test_terminal("partial") as (master, process):
            shown = terminal_output(master.fileno(), stop=b"Paste the authorization code and press Enter")
            self.assertIn(good_link().encode("ascii"), shown)
            private = b"4/fixture-incomplete-code"
            os.write(master.fileno(), private)
            after = terminal_output(master.fileno(), stop=b"Next reader ready")
            self.assertNotIn(private, after)
            self.assertIn(b"Next reader ready", after)
            os.write(master.fileno(), b"fresh\n")
            stdout, stderr = process.communicate(timeout=3)
            self.assertEqual((process.returncode, stdout, stderr), (0, b"FRESH_AND_RESTORED\n", b""))

    def test_code_is_not_echoed_and_terminal_modes_are_restored(self):
        with operator_test_terminal() as (master, process):
            displayed = terminal_output(master.fileno(), stop=b"Paste the authorization code and press Enter")
            self.assertIn(good_link().encode("ascii"), displayed)
            code = b"4/synthetic-terminal-code"
            os.write(master.fileno(), code + b"\n")
            stdout, stderr = process.communicate(timeout=3)
            self.assertEqual((process.returncode, stdout, stderr), (0, b"FORWARD_AND_RESTORE\n", b""))
            self.assertNotIn(code, terminal_output(master.fileno(), timeout=.1))

    def test_terminal_loss_after_link_cancels_without_code(self):
        with operator_test_terminal() as (master, process):
            displayed = terminal_output(master.fileno(), stop=b"Paste the authorization code and press Enter")
            self.assertIn(good_link().encode("ascii"), displayed)
            master.close()
            stdout, stderr = process.communicate(timeout=3)
            self.assertEqual((process.returncode, stdout, stderr), (0, b"CANCELLED_WITHOUT_CODE\n", b""))


if __name__ == "__main__":
    unittest.main()
