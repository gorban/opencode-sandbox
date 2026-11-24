"""Foreground-only browser handoff for the pinned native Antigravity flow."""

from contextlib import contextmanager
import os
import re
import select
import signal
import termios
import time
from urllib.parse import parse_qsl, urlsplit


AUTHORITY = "accounts.google.com"
CALLBACK = "https://antigravity.google/oauth-callback"
CLIENT_ID = "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com"
SCOPES = frozenset(("openid", "https://www.googleapis.com/auth/cloud-platform",
                    "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile",
                    "https://www.googleapis.com/auth/cclog", "https://www.googleapis.com/auth/experimentsandconfigs",
                    "https://www.googleapis.com/auth/aicode"))
PARAMETERS = frozenset(("access_type", "client_id", "code_challenge", "code_challenge_method", "prompt",
                        "redirect_uri", "response_type", "scope", "state"))
DESTINATIONS = ("oauth2.googleapis.com:443", "www.googleapis.com:443")
LINK_LIMIT = 8192
CODE_LIMIT = 2048


class TerminalUnavailable(RuntimeError):
    """The native handoff could not be completed from the operator terminal."""


def authorization_link(candidate):
    if (type(candidate) is not str or not 1 <= len(candidate) <= LINK_LIMIT
            or any(not 33 <= ord(char) < 127 for char in candidate)):
        raise TerminalUnavailable("invalid native authorization link")
    try:
        link = urlsplit(candidate)
        entries = parse_qsl(link.query, strict_parsing=True, max_num_fields=len(PARAMETERS), keep_blank_values=True)
    except ValueError:
        raise TerminalUnavailable("invalid native authorization link") from None
    fields = dict(entries)
    if (link.scheme != "https" or link.netloc != AUTHORITY or link.path != "/o/oauth2/auth" or link.fragment
            or len(entries) != len(fields) or fields.keys() != PARAMETERS
            or fields["redirect_uri"] != CALLBACK or fields["response_type"] != "code"
            or fields["code_challenge_method"] != "S256" or fields["access_type"] != "offline"):
        raise TerminalUnavailable("unexpected native authorization link")
    scopes = fields["scope"].split(" ")
    if (fields["client_id"] != CLIENT_ID or fields["prompt"] != "consent"
            or len(scopes) != len(SCOPES) or set(scopes) != SCOPES
            or not re.fullmatch(r"[a-zA-Z0-9_-]{43}", fields["code_challenge"])
            or not re.fullmatch(r"[a-zA-Z0-9_-]{16,128}", fields["state"])
            or any(not value or any(not 32 <= ord(char) < 127 for char in value) for value in fields.values())):
        raise TerminalUnavailable("unexpected native authorization parameters")
    return candidate


@contextmanager
def foreground_terminal():
    try:
        terminal = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as error:
        raise TerminalUnavailable("Antigravity sign-in requires a foreground terminal") from error
    try:
        require_foreground(terminal)
        yield terminal
    finally:
        os.close(terminal)


def require_foreground(terminal):
    try:
        if os.isatty(terminal) and os.tcgetpgrp(terminal) == os.getpgrp():
            return
    except OSError:
        pass
    raise TerminalUnavailable("the operator terminal is no longer foreground")


def write_operator(terminal, message, deadline):
    data = memoryview(message.encode("ascii"))
    while data:
        wait_for_terminal(terminal, select.POLLOUT, deadline)
        try:
            count = os.write(terminal, data)
        except BlockingIOError:
            continue
        if not count:
            raise TerminalUnavailable("the operator terminal stopped receiving")
        data = data[count:]


def wait_for_terminal(terminal, event, deadline):
    require_foreground(terminal)
    poll = select.poll()
    poll.register(terminal, event)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TerminalUnavailable("the operator approval expired")
    events = poll.poll(max(1, int(1000 * remaining)))
    if len(events) != 1 or events[0][1] != event:
        raise TerminalUnavailable("the operator terminal closed or expired")
    require_foreground(terminal)


def read_line(terminal, limit, deadline):
    wait_for_terminal(terminal, select.POLLIN, deadline)
    line = os.read(terminal, limit + 2)
    require_foreground(terminal)
    if not line.endswith(b"\n") or len(line) > limit + 1:
        raise TerminalUnavailable("invalid operator terminal input")
    return line[:-1]


def approve(terminal, label, build_digest, deadline):
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", label) or not re.fullmatch(r"[0-9a-f]{64}", build_digest):
        raise TerminalUnavailable("invalid registration or pinned build")
    first, second = DESTINATIONS
    write_operator(terminal, f"Antigravity registration {label}\n"
                   f"Native build SHA-256 {build_digest}\n"
                   f"Allow one temporary HTTPS tunnel to {first}, then one to {second}?\n"
                   "Each tunnel permits any encrypted path at its destination.\n", deadline)
    require_foreground(terminal)
    termios.tcflush(terminal, termios.TCIFLUSH)
    write_operator(terminal, "Continue with Google sign-in? [y/N] ", deadline)
    return read_line(terminal, 8, deadline).lower() in (b"y", b"yes")


@contextmanager
def hidden_input(terminal):
    require_foreground(terminal)
    previous = termios.tcgetattr(terminal)
    current = list(previous)
    current[3] = (current[3] | termios.ICANON) & ~(termios.ECHO | termios.ECHONL)
    termios.tcsetattr(terminal, termios.TCSAFLUSH, current)
    try:
        yield
    finally:
        old = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTTOU})
        try:
            try:
                termios.tcsetattr(terminal, termios.TCSAFLUSH, previous)
            except termios.error as error:
                raise TerminalUnavailable("the operator terminal detached during sign-in") from error
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, old)


def request_code(terminal, candidate, deadline):
    link = authorization_link(candidate)
    with hidden_input(terminal):
        write_operator(terminal, "Open this native Google sign-in link in your browser\n" + link
                       + "\nPaste the authorization code and press Enter\n", deadline)
        code = read_line(terminal, CODE_LIMIT, deadline)
    if not re.fullmatch(rb"[a-zA-Z0-9_./~-]{8,2048}", code):
        raise TerminalUnavailable("invalid authorization code")
    require_foreground(terminal)
    return code
