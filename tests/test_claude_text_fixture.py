from contextlib import ExitStack
import errno
import os
import secrets
import stat
import tempfile
from pathlib import Path
from threading import Event, Thread
from types import SimpleNamespace
import time
import unittest
from unittest.mock import call, patch

from oc_claude.fixture import (
    FixtureAuthority, Unavailable, probe_fixture, run_fixture_text,
)
from oc_claude import fixture_custody
from oc_claude.fixture_custody import ANCHOR, FixtureCustody, _rename_without_replacing, _same_private_dir
from oc_claude.fixture_protocol import FixtureError, decode, encode


_A, _B, _C = (character * 32 for character in "abc")
_ACCOUNT = "d" * 64
_BINARY = "e" * 64
_PROMPT = "  Compris? \N{WAVING HAND SIGN}\n\"\\  "


def _fail(reason):
    raise FixtureError(reason)


class _Child:
    session = "1" * 32
    pipe_buf = 4096

    def __init__(self, pin, mode, configure):
        self.pin = pin
        self.mode = mode
        self.writes, self.frames, self.read_deadlines = [], [], []
        self.quiet_checks = 0
        self.input_closed = mode == "status"
        self.retirement_confirmed = False
        self.on_quiet = lambda count: None
        self.on_write = lambda: None
        self.on_read = lambda: None
        self.on_finish = lambda: None
        self.on_retire = lambda: True
        self.change_status = lambda frame: frame
        self.change_ready = lambda frame: frame
        self.change_delta = lambda frame: frame
        self.change_result = lambda frame: frame
        configure(self)
        if mode == "status":
            frame = {
                "type": "status", "logged_in": True, "auth": "claude.ai", "provider": "firstParty",
                "profile": pin.profile_id, "account": pin.account_tag, "expires_at": pin.expires_at, "model": pin.model,
            }
            self.frames.append(self.change_status(encode(frame)))
        else:
            frame = {
                "type": "ready", "session": self.session, "profile": pin.profile_id, "account": pin.account_tag,
                "auth": "claude.ai", "provider": "firstParty", "model": pin.model, "tools": [], "mcp": [], "hooks": [],
            }
            self.frames.append(self.change_ready(encode(frame)))

    def read_frame(self, deadline, _cancel):
        self.read_deadlines.append(deadline)
        self.on_read()
        if not self.frames:
            _fail("deadline_exceeded")
        return self.frames.pop(0)

    def verify_quiet(self):
        self.quiet_checks += 1
        self.on_quiet(self.quiet_checks)
        if self.frames:
            _fail("integrity_error")

    def is_live(self):
        return True

    def write_once(self, packet):
        self.writes.append(packet)
        amount = self.on_write()
        frame = decode(packet)
        route = {"session": self.session, "challenge": frame["challenge"], "model": self.pin.model}
        self.frames.extend((
            self.change_delta(encode({"type": "delta", **route, "role": "assistant", "text": "fixture-ok"})),
            self.change_result(encode({"type": "result", **route, "stop": "end_turn", "tool_calls": 0})),
        ))
        return len(packet) if amount is None else amount

    def close_input(self):
        self.input_closed = True

    def finish(self, _deadline, _cancel):
        self.on_finish()
        if self.frames:
            _fail("integrity_error")

    def retire(self, _deadline):
        self.input_closed = True
        self.retirement_confirmed = self.on_retire()
        return self.retirement_confirmed


class _Launcher:
    def __init__(self):
        self.children = []
        self.configure = lambda child: None

    def start(self, profile, mode, _deadline, _cancel):
        child = _Child(profile.snapshot(), mode, self.configure)
        self.children.append(child)
        return child


def _updated(**values):
    def update(raw):
        return encode({**decode(raw), **values})
    return update


class PortableScratchTest(unittest.TestCase):
    def setUp(self):
        # Portable state tests own this tmpfs parent. They do not depend on how
        # the devbox maps the host root uid. Production anchor checks are tested
        # independently and used unmocked in the delegated kernel fixture.
        self.portable_anchor = Path(self.enterContext(tempfile.TemporaryDirectory(dir=ANCHOR)))

    def new_custody(self, **kwargs):
        def open_test_anchor():
            fd = os.open(self.portable_anchor, fixture_custody._DIR_FLAGS)
            try:
                info = os.fstat(fd)
                self.assertEqual(info.st_uid, os.geteuid())
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o700)
                return fd, info.st_dev
            except BaseException:
                os.close(fd)
                raise

        with patch.object(fixture_custody, "ANCHOR", self.portable_anchor), \
                patch.object(fixture_custody, "_open_anchor", side_effect=open_test_anchor):
            return FixtureCustody(**kwargs)


class AnchorCustodyTest(unittest.TestCase):
    def test_live_anchor_requires_visible_root(self):
        parent = os.stat(ANCHOR.parent, follow_symlinks=False)
        child = os.stat(ANCHOR, follow_symlinks=False)
        if parent.st_uid == child.st_uid == 0:
            fd, device = fixture_custody._open_anchor()
            self.addCleanup(os.close, fd)
            info = os.fstat(fd)
            self.assertEqual((device, info.st_ino), (child.st_dev, child.st_ino))
        else:
            with self.assertRaisesRegex(FixtureError, "^integrity_error$"):
                fixture_custody._open_anchor()

    def test_anchor_uses_verified_parent_and_closes_on_success(self):
        parent = self._info(1, 0o755)
        child = self._info(2, 0o1777)
        with patch.object(fixture_custody.os, "open", side_effect=(41, 42)) as open_fd, \
                patch.object(fixture_custody.os, "fstat", side_effect=(parent, child)), \
                patch.object(fixture_custody.os, "stat", side_effect=(parent, child)) as stat_name, \
                patch.object(fixture_custody.os, "close") as close, \
                patch.object(fixture_custody, "_verify_anchor_mount") as check_mount:
            self.assertEqual(fixture_custody._open_anchor(), (42, child.st_dev))
        self.assertEqual(open_fd.call_args_list, [
            call(ANCHOR.parent, fixture_custody._DIR_FLAGS),
            call(ANCHOR.name, fixture_custody._DIR_FLAGS, dir_fd=41),
        ])
        self.assertEqual(stat_name.call_args_list, [
            call(ANCHOR.parent, follow_symlinks=False),
            call(ANCHOR.name, dir_fd=41, follow_symlinks=False),
        ])
        self.assertTrue(fixture_custody._DIR_FLAGS & os.O_NOFOLLOW)
        close.assert_called_once_with(41)
        check_mount.assert_called_once_with(42)

    def test_anchor_refusals_close_exact_open_descriptors(self):
        parent = self._info(1, 0o755)
        child = self._info(2, 0o1777)
        parent_cases = (
            (self._info(1, 0o755, uid=1000), parent),
            (self._info(1, 0o775), parent),
            (parent, self._info(3, 0o755)),
            (parent, self._info(1, 0o755, kind=stat.S_IFLNK)),
        )
        child_cases = (
            (self._info(2, 0o1777, uid=1000), child),
            (self._info(2, 0o777), child),
            (child, self._info(3, 0o1777)),
            (child, self._info(2, 0o1777, kind=stat.S_IFLNK)),
        )
        for opened, named in parent_cases:
            with self.subTest(parent=opened, named=named):
                self._assert_anchor_refused((opened,), (named,), [call(41)])
        for opened, named in child_cases:
            with self.subTest(child=opened, named=named):
                self._assert_anchor_refused((parent, opened), (parent, named), [call(42), call(41)])
        self._assert_anchor_refused((parent, child), (parent, child), [call(42), call(41)],
                                    invalid_mount=True)

    def test_anchor_never_follows_a_parent_or_child_symlink(self):
        parent = self._info(1, 0o755)
        error = OSError(errno.ELOOP, "synthetic symlink")
        for opening, expected in (((error,), []), ((41, error), [call(41)])):
            with self.subTest(opening=opening), \
                    patch.object(fixture_custody.os, "open", side_effect=opening), \
                    patch.object(fixture_custody.os, "fstat", return_value=parent), \
                    patch.object(fixture_custody.os, "stat", return_value=parent), \
                    patch.object(fixture_custody.os, "close") as close:
                with self.assertRaises(OSError):
                    fixture_custody._open_anchor()
                self.assertEqual(close.call_args_list, expected)

    def _assert_anchor_refused(self, opened, named, expected, *, invalid_mount=False):
        mount_error = FixtureError("integrity_error") if invalid_mount else None
        with patch.object(fixture_custody.os, "open", side_effect=(41, 42)), \
                patch.object(fixture_custody.os, "fstat", side_effect=opened), \
                patch.object(fixture_custody.os, "stat", side_effect=named), \
                patch.object(fixture_custody.os, "close") as close, \
                patch.object(fixture_custody, "_verify_anchor_mount", side_effect=mount_error):
            with self.assertRaisesRegex(FixtureError, "^integrity_error$"):
                fixture_custody._open_anchor()
        self.assertEqual(close.call_args_list, expected)

    @staticmethod
    def _info(inode, permissions, *, uid=0, kind=stat.S_IFDIR):
        return SimpleNamespace(st_dev=11, st_ino=inode, st_uid=uid, st_mode=kind | permissions)


class ClaudeFixtureTest(PortableScratchTest):
    def setUp(self):
        super().setUp()
        self.stack = self.enterContext(ExitStack())
        self.monotonic = time.monotonic
        self.wall = lambda: 1000
        custody = self.new_custody(now=lambda: self.monotonic(), wall=lambda: self.wall())
        self.root = custody.root
        scratch = self.stack.enter_context(custody.pin_scratch())
        self.stack.callback(scratch.remove)
        self.custody = self.stack.enter_context(custody)
        for profile_id in (_A, _B, _C):
            (self.root / profile_id).mkdir(mode=0o700)
        self.enroll("personal", 1, _A)
        self.enroll("team", 1, _B, "f" * 64)
        self.profile = self.custody.open("personal", 1)
        self.cancel = Event()
        self.launcher = _Launcher()

    def enroll(self, instance, generation, profile_id, account_tag=_ACCOUNT, cancel=None, expires_at=2000):
        self.custody.enroll(instance, generation, profile_id=profile_id, account_tag=account_tag,
                            model="haiku", executable_identity=_BINARY, expires_at=expires_at, cancel=cancel)

    def probe(self):
        return probe_fixture(self.profile, self.launcher, self.cancel)

    def turn(self, binding, *, authority=None, now=None, text=_PROMPT):
        if authority is None:
            authority = FixtureAuthority(binding, "haiku", text)
        old_now = self.monotonic
        if now is not None:
            self.monotonic = now
        try:
            return run_fixture_text(binding, "haiku", text, self.launcher, authority, self.cancel)
        finally:
            self.monotonic = old_now

    def assert_failure(self, reason, invoke, *, sent=False):
        with self.assertRaises(FixtureError) as caught:
            invoke()
        self.assertEqual(caught.exception.reason, reason)
        self.assertIs(caught.exception.possible_send, sent)
        self.assertEqual(str(caught.exception), reason)

    def test_exact_status_and_literal_user_turn(self):
        binding = self.probe()
        status = self.launcher.children[-1]
        self.assertTrue(status.input_closed and status.retirement_confirmed)
        self.assertEqual(status.writes, [])
        answer = self.turn(binding)
        turn = self.launcher.children[-1]
        self.assertEqual(answer, "fixture-ok")
        self.assertIs(turn.pin, status.pin)
        self.assertTrue(turn.input_closed and turn.retirement_confirmed)
        self.assertEqual(turn.quiet_checks, 2)
        self.assertEqual(len(turn.writes), 1)
        frame = decode(turn.writes[0])
        self.assertRegex(frame.pop("challenge"), r"^[a-f0-9]{32}$")
        self.assertEqual(frame, {"type": "user", "session": turn.session, "role": "user", "text": _PROMPT})

    def test_status_and_ready_require_enrolled_custody(self):
        for field, update in (
            ("change_status", _updated(auth="oauth_token")),
            ("change_status", _updated(profile=_B)),
            ("change_status", _updated(account="f" * 64)),
            ("change_status", _updated(expires_at=True)),
            ("change_status", _updated(expires_at=1000)),
        ):
            with self.subTest(field=field, update=update):
                self.launcher.configure = lambda child: setattr(child, field, update)
                self.assert_failure("integrity_error", self.probe)
                self.assertEqual(self.launcher.children[-1].writes, [])
                self.assertTrue(self.launcher.children[-1].retirement_confirmed)

        self.launcher.configure = lambda child: setattr(child, "change_status", _updated(
            logged_in=False, auth="none", provider="none", account=None, expires_at=None, model=None,
        ))
        self.assertIsInstance(self.probe(), Unavailable)
        self.launcher.configure = lambda child: None
        binding = self.probe()
        for changes in ({"profile": _B}, {"account": "f" * 64}, {"provider": "other"}):
            with self.subTest(changes=changes):
                self.launcher.configure = lambda child: setattr(child, "change_ready", _updated(**changes))
                self.assert_failure("integrity_error", lambda: self.turn(binding))
                self.assertTrue(self.launcher.children[-1].retirement_confirmed)
                self.assertEqual(self.launcher.children[-1].writes, [])
        self.assert_failure("integrity_error", lambda: self.enroll("alias", 1, _A))
        self.enroll("same-account", 1, _C)
        self.launcher.configure = lambda child: setattr(child, "change_ready", _updated(profile=_C))
        self.assert_failure("integrity_error", lambda: self.turn(binding))
        self.assertEqual(self.launcher.children[-1].writes, [])

        def swap_profile():
            (self.root / _A).rename(self.root / "original")
            (self.root / _A).mkdir(mode=0o700)

        self.launcher.configure = lambda child: setattr(child, "on_quiet", lambda count: swap_profile())
        self.assert_failure("integrity_error", lambda: self.turn(binding))
        self.assertTrue(self.launcher.children[-1].retirement_confirmed)
        self.assertEqual(self.launcher.children[-1].writes, [])
        count = len(self.launcher.children)
        self.assert_failure("integrity_error", self.probe)
        self.assertEqual(len(self.launcher.children), count)

    def test_contended_fence_revalidates_scratch_and_profile_path(self):
        binding = self.probe()
        leaf = self.root / _A
        saved_leaf = self.root / "saved"
        saved_root = self.root.with_name(self.root.name + "-saved")
        for change in ("leaf", "mode", "parent"):
            with self.subTest(change=change):
                authority = FixtureAuthority(binding, "haiku", _PROMPT)

                def configure(child):
                    def hold(count):
                        if count == 1:
                            self.assertTrue(authority.try_fence())
                    child.on_quiet = hold

                def change_while_waiting(_timeout):
                    if change == "leaf":
                        leaf.rename(saved_leaf)
                        leaf.mkdir(mode=0o700)
                    elif change == "mode":
                        leaf.chmod(0o755)
                    else:
                        self.root.rename(saved_root)
                        self.root.mkdir(mode=0o700)
                        leaf.mkdir(mode=0o700)
                    authority.release_fence()

                self.launcher.configure = configure
                try:
                    with patch.object(self.cancel, "wait", change_while_waiting):
                        self.assert_failure("integrity_error", lambda: self.turn(binding, authority=authority))
                    child = self.launcher.children[-1]
                    self.assertEqual(child.writes, [])
                    self.assertTrue(child.retirement_confirmed)
                    self.assertEqual(child.quiet_checks, 1)
                finally:
                    if saved_leaf.exists():
                        leaf.rmdir()
                        saved_leaf.rename(leaf)
                    elif saved_root.exists():
                        leaf.rmdir()
                        self.root.rmdir()
                        saved_root.rename(self.root)
                    else:
                        leaf.chmod(0o700)

    def test_observed_expiry_cannot_rearm_authority_or_status(self):
        binding = self.probe()
        authority = FixtureAuthority(binding, "haiku", _PROMPT)
        count = len(self.launcher.children)
        self.wall = lambda: 2000
        self.assert_failure("cancelled", lambda: self.turn(binding, authority=authority))
        self.wall = lambda: 1000
        self.assert_failure("cancelled", lambda: self.turn(binding, authority=authority))
        self.assert_failure("cancelled", lambda: self.turn(binding))
        self.assertIsInstance(self.probe(), Unavailable)
        self.assertEqual(len(self.launcher.children), count)
        self.assert_failure("integrity_error", lambda: self.enroll("personal", 1, _C, cancel=self.cancel))

        self.enroll("personal", 2, _C, cancel=self.cancel, expires_at=3000)
        self.cancel.clear()
        self.profile = self.custody.open("personal", 2)
        renewed = self.probe()
        self.assertEqual(self.turn(renewed), "fixture-ok")
        self.assert_failure("cancelled", lambda: self.turn(binding))

    def test_monotonic_enrollment_deadline_survives_wall_rollback(self):
        original_now = self.monotonic()
        binding = self.probe()
        self.wall = lambda: 500
        self.monotonic = lambda: original_now + 1001
        count = len(self.launcher.children)
        self.assertIsInstance(self.probe(), Unavailable)
        self.assert_failure("cancelled", lambda: self.turn(binding))
        self.assertEqual(len(self.launcher.children), count)

        self.enroll("expired-at-enroll", 1, _C, expires_at=500)
        self.wall = lambda: 100
        expired_at_enroll = self.custody.open("expired-at-enroll", 1)
        self.assertIsInstance(probe_fixture(expired_at_enroll, self.launcher, self.cancel), Unavailable)
        self.assertEqual(len(self.launcher.children), count)

    def test_preexisting_and_retired_scratch_cannot_be_adopted(self):
        name = "oc-claude-" + secrets.token_hex(16)
        existing = self.portable_anchor / name
        existing.mkdir(mode=0o700)
        try:
            sentinel = existing / "untouched"
            sentinel.write_text("fixture-sentinel")
            with patch("oc_claude.fixture_custody._new_name", return_value=name):
                self.assert_failure("integrity_error", self.new_custody)
            self.assertEqual(list(existing.iterdir()), [sentinel])
            self.assertEqual(sentinel.read_text(), "fixture-sentinel")
        finally:
            (existing / "untouched").unlink()
            existing.rmdir()

        with self.new_custody() as other:
            retired = other.root
            cleanup = self.enterContext(other.pin_scratch())
        (retired / ".claude-fixture-custody").unlink()
        with patch("oc_claude.fixture_custody._new_name", return_value=retired.name):
            self.assert_failure("integrity_error", self.new_custody)
            self.assertEqual(list(retired.iterdir()), [])
            cleanup.remove()
            self.assert_failure("integrity_error", self.new_custody)
            self.assertFalse(retired.exists())

    def test_revocation_and_claim_are_ordered(self):
        binding = self.probe()
        for event, sent in (("on_quiet", False), ("on_write", True), ("on_retire", True)):
            with self.subTest(event=event):
                self.cancel.clear()

                def cancel(*_args):
                    self.cancel.set()
                    return True if event == "on_retire" else None

                self.launcher.configure = lambda child: setattr(child, event, cancel)
                self.assert_failure("cancelled", lambda: self.turn(binding), sent=sent)
                self.assertTrue(self.launcher.children[-1].retirement_confirmed)
                self.assertEqual(len(self.launcher.children[-1].writes), int(sent))
        self.cancel.clear()
        self.launcher.configure = lambda child: None
        authority = FixtureAuthority(binding, "haiku", _PROMPT)
        claim = authority.try_claim

        def claim_and_cancel(*args):
            claim(*args)
            self.cancel.set()

        with patch.object(authority, "try_claim", claim_and_cancel):
            self.assert_failure("cancelled", lambda: self.turn(binding, authority=authority))
        self.assertEqual(self.launcher.children[-1].writes, [])
        self.cancel.clear()
        self.assert_failure("integrity_error", lambda: self.turn(binding, authority=authority))

        authority = FixtureAuthority(binding, "haiku", _PROMPT)
        ready, release = Event(), Event()
        outcomes = []

        def pause():
            ready.set()
            if not release.wait(2):
                _fail("deadline_exceeded")

        self.launcher.configure = lambda child: setattr(child, "on_read", pause)
        thread = Thread(target=lambda: outcomes.append(self.turn(binding, authority=authority)), daemon=True)
        thread.start()
        try:
            self.assertTrue(ready.wait(2))
            self.assert_failure("integrity_error", lambda: self.turn(binding, authority=authority))
        finally:
            release.set()
            thread.join(2)
        self.assertEqual(outcomes, ["fixture-ok"])
        self.assertEqual(len(self.launcher.children[-1].writes), 1)
        self.assertTrue(self.launcher.children[-1].retirement_confirmed)

        self.launcher.configure = lambda child: setattr(
            child, "on_quiet", lambda _count: self.enroll("personal", 2, _C, cancel=self.cancel),
        )
        self.assert_failure("cancelled", lambda: self.turn(binding))
        self.assertEqual(self.launcher.children[-1].writes, [])
        self.assertTrue(self.launcher.children[-1].retirement_confirmed)

    def test_json_phase_role_and_bounds_are_strict(self):
        binding = self.probe()
        cases = (
            ("change_ready", _updated(mcp=["fake"])),
            ("change_ready", _updated(tools=["read"])),
            ("change_ready", _updated(hooks=["read"])),
            ("change_ready", lambda raw: b'{"type":"ready",' + raw[1:]),
            ("change_ready", lambda raw: raw[:-1] + b"\xff\n"),
            ("change_delta", _updated(role="user")),
            ("change_delta", _updated(type="tool")),
            ("change_delta", _updated(type="control")),
            ("change_delta", _updated(session="2" * 32)),
            ("change_delta", _updated(model="alternate")),
            ("change_delta", _updated(challenge="2" * 32)),
            ("change_delta", _updated(text="x" * 4097)),
            ("change_delta", lambda _raw: b'{"text":"\\ud800"}\n'),
            ("change_result", _updated(tool_calls=False)),
            ("change_result", lambda raw: raw[:-1]),
        )
        for phase, change in cases:
            with self.subTest(phase=phase, change=change):
                self.launcher.configure = lambda child: setattr(child, phase, change)
                sent = phase != "change_ready"
                self.assert_failure("integrity_error", lambda: self.turn(binding), sent=sent)
                self.assertTrue(self.launcher.children[-1].retirement_confirmed)
                self.assertEqual(len(self.launcher.children[-1].writes), int(sent))
        for text in ("", " " * 2, "x" * 513, "a\0b"):
            self.assert_failure("integrity_error", lambda: self.turn(binding, text=text))

    def test_whole_operation_deadline_and_write_faults(self):
        binding = self.probe()
        ticks = [0]

        def drip():
            ticks[0] += 1
            if ticks[0] == 3:
                ticks[0] = 6
                _fail("deadline_exceeded")

        self.launcher.configure = lambda child: setattr(child, "on_read", drip)
        self.assert_failure("deadline_exceeded", lambda: self.turn(binding, now=lambda: ticks[0]), sent=True)
        child = self.launcher.children[-1]
        self.assertEqual(child.read_deadlines, [2, 6, 6])
        self.assertEqual(len(child.writes), 1)
        self.assertTrue(child.retirement_confirmed)

        def fail_write(number):
            raise OSError(number, "not part of the diagnostic")

        for outcome in (lambda: 1, *(lambda number=number: fail_write(number)
                                    for number in (errno.EAGAIN, errno.EPIPE, errno.EINTR))):
            self.launcher.configure = lambda child: setattr(child, "on_write", outcome)
            self.assert_failure("send_uncertain", lambda: self.turn(binding), sent=True)
            self.assertEqual(len(self.launcher.children[-1].writes), 1)
            self.assertTrue(self.launcher.children[-1].retirement_confirmed)

        self.launcher.configure = lambda child: setattr(child, "on_read", lambda: _fail("deadline_exceeded"))
        self.assert_failure("deadline_exceeded", lambda: self.turn(binding))
        self.assertEqual(self.launcher.children[-1].writes, [])
        self.launcher.configure = lambda child: setattr(child, "on_finish", lambda: _fail("deadline_exceeded"))
        self.assert_failure("deadline_exceeded", lambda: self.turn(binding), sent=True)
        self.assertEqual(len(self.launcher.children[-1].writes), 1)
        self.launcher.configure = lambda child: setattr(child, "on_finish", lambda: _fail("provider_failed"))
        self.assert_failure("provider_failed", lambda: self.turn(binding), sent=True)

        for error in ("integrity_error", "cancelled"):
            with self.subTest(blocked_fence=error):
                self.cancel.clear()
                authority = FixtureAuthority(binding, "haiku", _PROMPT)

                def configure(child):
                    def block_fence(count):
                        if count == 1:
                            self.assertTrue(authority.try_fence())
                    child.on_quiet = block_fence

                def release_fence(timeout):
                    self.assertGreater(timeout, 0)
                    self.assertLessEqual(timeout, .01)
                    authority.release_fence()
                    if error == "cancelled":
                        self.cancel.set()
                    else:
                        child = self.launcher.children[-1]
                        child.frames.append(encode({
                            "type": "result", "session": child.session, "model": "haiku",
                            "challenge": "2" * 32, "stop": "end_turn", "tool_calls": 0,
                        }))

                self.launcher.configure = configure
                with patch.object(self.cancel, "wait", release_fence):
                    self.assert_failure(error, lambda: self.turn(binding, authority=authority))
                self.assertEqual(self.launcher.children[-1].writes, [])
                self.assertTrue(self.launcher.children[-1].retirement_confirmed)

    def test_retirement_failure_wins_and_preserves_evidence(self):
        binding = self.probe()
        for event in ("bad_result", "cancelled"):
            with self.subTest(event=event):
                marker = self.root / event
                marker.touch()
                self.cancel.clear()

                def configure(child):
                    child.on_retire = lambda: False
                    if event == "cancelled":
                        child.on_write = self.cancel.set
                    else:
                        child.change_result = _updated(stop="other")

                self.launcher.configure = configure
                self.assert_failure("retirement_unverified", lambda: self.turn(binding), sent=True)
                self.assertFalse(self.launcher.children[-1].retirement_confirmed)
                self.assertEqual(len(self.launcher.children[-1].writes), 1)
                self.assertTrue(marker.is_file())


class ScratchRetirementTest(PortableScratchTest):
    def test_substituted_scratch_is_neither_read_nor_removed(self):
        with self.new_custody() as custody:
            scratch = self.enterContext(custody.pin_scratch())
            root = scratch.path
            (root / "owner-sentinel").write_text("owner")
        saved = root.with_name(root.name + "-original")
        root.rename(saved)
        root.mkdir(mode=0o700)
        foreign = root / "foreign-sentinel"
        foreign.write_text("foreign")
        try:
            with patch("oc_claude.fixture_custody.os.listdir", side_effect=AssertionError("scratch walk")):
                with self.assertRaisesRegex(FixtureError, "^retirement_unverified$"):
                    scratch.remove()
            self.assertEqual(foreign.read_text(), "foreign")
            self.assertEqual((saved / "owner-sentinel").read_text(), "owner")
        finally:
            foreign.unlink()
            root.rmdir()
            saved.rename(root)
            scratch.remove()
        self.assertFalse(root.exists())

    def test_swap_during_quarantine_move_restores_foreign_without_reading_it(self):
        with self.new_custody() as custody:
            scratch = self.enterContext(custody.pin_scratch())
            root = scratch.path
            (root / "owner-sentinel").write_text("owner")
        saved = root.with_name(root.name + "-original")
        foreign = root / "foreign-sentinel"

        original_listdir = os.listdir
        foreign_inode = None

        def swap(source, source_fd, target, target_fd):
            nonlocal foreign_inode
            if source == root.name:
                root.rename(saved)
                root.mkdir(mode=0o700)
                foreign.write_text("foreign")
                foreign_inode = root.stat().st_ino
            return _rename_without_replacing(source, source_fd, target, target_fd)

        def list_without_foreign(directory):
            self.assertIsInstance(directory, int)
            self.assertNotEqual(os.fstat(directory).st_ino, foreign_inode)
            return original_listdir(directory)

        try:
            with patch("oc_claude.fixture_custody._rename_without_replacing", side_effect=swap), \
                    patch("oc_claude.fixture_custody.os.listdir", side_effect=list_without_foreign):
                with self.assertRaisesRegex(FixtureError, "^retirement_unverified$"):
                    scratch.remove()
            self.assertEqual(foreign.read_text(), "foreign")
            self.assertEqual((saved / "owner-sentinel").read_text(), "owner")
        finally:
            foreign.unlink()
            root.rmdir()
            saved.rename(root)
            scratch.remove()

    def test_pending_retirement_refuses_removal_even_without_a_record(self):
        with self.new_custody() as custody:
            scratch = self.enterContext(custody.pin_scratch())
            sentinel = scratch.path / "expected-owner"
            sentinel.write_text("retained")
            receipt = scratch.expect_recovery("occlaude-expected")
            another_pin = self.enterContext(custody.pin_scratch())
        self.assertEqual(scratch.recovery_names(), ())
        try:
            with self.assertRaisesRegex(FixtureError, "^retirement_unverified$"):
                scratch.remove()
            with self.assertRaisesRegex(FixtureError, "^retirement_unverified$"):
                another_pin.remove()
            self.assertEqual(sentinel.read_text(), "retained")
            with self.assertRaisesRegex(FixtureError, "^integrity_error$"):
                scratch.confirm_recovery("occlaude-expected", object())
            with self.assertRaisesRegex(FixtureError, "^retirement_unverified$"):
                scratch.remove()
        finally:
            # This portable test never starts a process or creates a cgroup.
            scratch.confirm_recovery("occlaude-expected", receipt)
            scratch.remove()

    def test_refused_prelaunch_mkdir_releases_reserved_scratch(self):
        from fixtures.claude_kernel import _Cgroup

        with tempfile.TemporaryDirectory() as delegation:
            delegated = Path(delegation)
            with self.new_custody() as custody:
                scratch = self.enterContext(custody.pin_scratch())
            with patch("fixtures.claude_kernel.os.mkdir", side_effect=PermissionError(errno.EACCES, "fixture")):
                with self.assertRaises(PermissionError):
                    _Cgroup(delegated, scratch)
            self.assertEqual(list(delegated.iterdir()), [])
            self.assertEqual(scratch.recovery_names(), ())
            scratch.remove()
            self.assertFalse(scratch.path.exists())

    def test_unowned_or_uncertain_prelaunch_mkdir_preserves_scratch(self):
        from fixtures.claude_kernel import _Cgroup

        for error in (errno.EIO, errno.EEXIST):
            with self.subTest(error=error), tempfile.TemporaryDirectory() as delegation:
                delegated = Path(delegation)
                with self.new_custody() as custody:
                    scratch = self.enterContext(custody.pin_scratch())
                marker = scratch.path / "scratch-sentinel"
                marker.write_text("retained")
                expected = []
                original_expect = scratch.expect_recovery
                original_mkdir = os.mkdir

                def reserve(name):
                    receipt = original_expect(name)
                    expected.append((name, receipt))
                    return receipt

                def refused_mkdir(name, mode, *, dir_fd):
                    if error == errno.EEXIST:
                        original_mkdir(name, mode, dir_fd=dir_fd)
                        (delegated / name / "other-sentinel").write_text("untouched")
                    raise OSError(error, "fixture")

                with patch.object(scratch, "expect_recovery", side_effect=reserve), \
                        patch("fixtures.claude_kernel.os.mkdir", side_effect=refused_mkdir):
                    with self.assertRaisesRegex(FixtureError, "^retirement_unverified$"):
                        _Cgroup(delegated, scratch)
                try:
                    with self.assertRaisesRegex(FixtureError, "^retirement_unverified$"):
                        scratch.remove()
                    self.assertEqual(marker.read_text(), "retained")
                    if error == errno.EEXIST:
                        name, _receipt = expected[0]
                        self.assertEqual((delegated / name / "other-sentinel").read_text(), "untouched")
                    else:
                        self.assertEqual(list(delegated.iterdir()), [])
                finally:
                    # The test injected the failure without creating a kernel unit.
                    # It can settle this synthetic reservation after checking that fact.
                    for name, receipt in expected:
                        scratch.confirm_recovery(name, receipt)
                    scratch.remove()

    def test_prelaunch_parent_provenance_mismatch_preserves_scratch(self):
        from fixtures.claude_kernel import _Cgroup

        with tempfile.TemporaryDirectory() as root:
            delegated = Path(root) / "delegated"
            foreign = Path(root) / "foreign"
            delegated.mkdir()
            foreign.mkdir()
            with self.new_custody() as custody:
                scratch = self.enterContext(custody.pin_scratch())
            expected = []
            original_expect = scratch.expect_recovery
            original_stat = os.stat

            def reserve(name):
                receipt = original_expect(name)
                expected.append((name, receipt))
                return receipt

            def displaced_parent(path, *args, **kwargs):
                return original_stat(foreign if path == delegated else path, *args, **kwargs)

            with patch.object(scratch, "expect_recovery", side_effect=reserve), \
                    patch("fixtures.claude_kernel.os.stat", side_effect=displaced_parent), \
                    patch("fixtures.claude_kernel.os.mkdir") as mkdir:
                with self.assertRaisesRegex(FixtureError, "^retirement_unverified$"):
                    _Cgroup(delegated, scratch)
            try:
                mkdir.assert_not_called()
                with self.assertRaisesRegex(FixtureError, "^retirement_unverified$"):
                    scratch.remove()
                self.assertFalse(list(delegated.iterdir()) or list(foreign.iterdir()))
            finally:
                # Both paths were inert test directories and mkdir was never called.
                for name, receipt in expected:
                    scratch.confirm_recovery(name, receipt)
                scratch.remove()

    def test_held_entry_is_retained_without_reading_its_contents(self):
        with self.new_custody() as custody:
            scratch = self.enterContext(custody.pin_scratch())
            held = scratch.path / "occlaude-held"
            held.mkdir(mode=0o700)
            sentinel = held / "sentinel"
            sentinel.write_text("held")
        try:
            with self.assertRaisesRegex(FixtureError, "^retirement_unverified$"):
                scratch.remove()
            self.assertEqual(sentinel.read_text(), "held")
        finally:
            sentinel.unlink()
            held.rmdir()
            scratch.remove()


class LinuxClaudeFixtureTest(unittest.TestCase):
    def test_linux_owned_unit_retires_descendants(self):
        import json
        import os
        import subprocess

        from fixtures.claude_kernel import BWRAP, KernelLauncher, PollCancellation

        configured = os.environ.get("OC_TEST_CLAUDE_CGROUP")
        if not configured:
            self.skipTest("explicit delegated cgroup v2 fixture subtree was not supplied")
        root = Path(configured)
        self.assertEqual(str(root), str(root.resolve(strict=True)))
        self.assertNotEqual(os.geteuid(), 0)
        own = Path("/proc/self/cgroup").read_text().strip()
        self.assertTrue(own.startswith("0::/"))
        self.assertEqual(root, Path("/sys/fs/cgroup" + own.removeprefix("0::")))
        self.assertTrue(root.is_dir() and root.stat().st_uid == os.geteuid())
        self.assertTrue(BWRAP.is_file() and hasattr(os, "pidfd_open") and hasattr(os, "memfd_create"))

        # An unrelated in-namespace process must never be targeted by fixture retirement.
        unrelated = subprocess.Popen(["/usr/bin/sleep", "30"], stdin=subprocess.DEVNULL)
        self.addCleanup(self._retire_unrelated, unrelated)
        custody = FixtureCustody()
        scratch = custody.root
        scratch_pin = self.enterContext(custody.pin_scratch())
        self.addCleanup(scratch_pin.remove)
        denied = (scratch / "other-credential", scratch / "job-data", scratch / "host-service")
        for path in denied:
            path.write_text("known-present-synthetic")
            self.assertEqual(path.read_text(), "known-present-synthetic")
        launcher = KernelLauncher(root, scratch_pin, (*denied, root / "cgroup.procs"))
        self.addCleanup(launcher.close)
        self._check_owned_prelaunch_errors(root)

        profile = scratch / _A
        profile.mkdir(mode=0o700)
        expiry = int(time.time()) + 60
        (profile / "registration.json").write_text(json.dumps({
            "profile": _A, "account": _ACCOUNT, "expires_at": expiry, "model": "haiku",
        }))
        (profile / "credential").write_text("synthetic-only-" + _A)
        with custody, PollCancellation() as cancellation:
            custody.enroll("personal", 1, profile_id=_A, account_tag=_ACCOUNT, model="haiku",
                           executable_identity=launcher.executable_identity, expires_at=expiry)
            profile_pin = custody.open("personal", 1)
            self._check_sealing_failure(launcher, profile_pin, cancellation)
            binding = probe_fixture(profile_pin, launcher, cancellation)
            self._check_sealing_failure(launcher, profile_pin, cancellation, binding=binding)
            sealed = launcher.profile_images[binding.pin]
            # Original host files remain accessible to the operator but are not the native source.
            (profile / "credential").write_text("operator-replaced-host-sentinel")
            (profile / "registration.json").write_text("{}")
            self.assertEqual((profile / "credential").read_text(), "operator-replaced-host-sentinel")
            reply = run_fixture_text(
                binding, "haiku", _PROMPT, launcher, FixtureAuthority(binding, "haiku", _PROMPT), cancellation,
            )
            self.assertEqual(reply, "fixture:" + _PROMPT)
            self.assertIs(launcher.profile_images[binding.pin], sealed)
            self._check_linux_owner_eof(launcher, binding)
            self._check_linux_scenarios(root, launcher, binding, unrelated)
            self._check_supervisor_disappearance(launcher, binding)
        for child in launcher.children:
            self.assertTrue(child.retired)
            self.assertIsNotNone(child.process.returncode)
            self.assertFalse((root / child.unit.name).exists())
            self.assertFalse(child.unit.record.exists())

    def _check_owned_prelaunch_errors(self, delegated):
        import stat

        from fixtures.claude_kernel import DIR, FILE, _Cgroup

        prepare_record = _Cgroup._prepare_record
        for missing_evidence in (False, True):
            with self.subTest(missing_evidence=missing_evidence):
                with FixtureCustody() as custody:
                    scratch = self.enterContext(custody.pin_scratch())
                marker = scratch.path / "scratch-sentinel"
                marker.write_text("retained")
                units = []

                def fail_after_prepare(unit):
                    prepare_record(unit)
                    units.append(unit)
                    if missing_evidence:
                        os.unlink("recovery.json", dir_fd=unit.record_fd)
                    raise OSError(errno.EIO, "synthetic failure after complete allocation")

                with patch.object(_Cgroup, "_prepare_record", autospec=True, side_effect=fail_after_prepare):
                    if not missing_evidence:
                        with self.assertRaises(OSError) as error:
                            _Cgroup(delegated, scratch)
                        self.assertEqual(error.exception.errno, errno.EIO)
                    else:
                        with self.assertRaisesRegex(FixtureError, "^retirement_unverified$"):
                            _Cgroup(delegated, scratch)

                [unit] = units
                leaf = delegated / unit.name
                if missing_evidence:
                    with self.assertRaisesRegex(FixtureError, "^retirement_unverified$"):
                        scratch.remove()
                    self.assertEqual(marker.read_text(), "retained")
                    self.assertEqual(scratch.recovery_names(), (unit.name,))
                    # Independent test cleanup has the original fixture identities
                    # and knows no launch took place. Never discover a substitute.
                    with ExitStack() as fds:
                        parent = os.open(delegated, DIR)
                        fds.callback(os.close, parent)
                        fd = os.open(unit.name, DIR, dir_fd=parent)
                        fds.callback(os.close, fd)
                        info = os.fstat(fd)
                        self.assertTrue(stat.S_ISDIR(info.st_mode))
                        actual_identity = (info.st_dev, info.st_ino)
                        self.assertEqual(actual_identity, unit.identity)
                        self.assertEqual(info.st_uid, os.geteuid())
                        events = os.open("cgroup.events", os.O_RDONLY | FILE, dir_fd=fd)
                        fds.callback(os.close, events)
                        self.assertIn(b"populated 0", os.read(events, 1024).splitlines())
                        self.assertTrue(_same_private_dir(unit.name, scratch.fd, unit.record_identity))
                        os.rmdir(unit.name, dir_fd=parent)
                        os.rmdir(unit.name, dir_fd=scratch.fd)
                    scratch.confirm_recovery(unit.name, unit.receipt)
                self.assertFalse(leaf.exists())
                self.assertEqual(scratch.recovery_names(), ())
                scratch.remove()
                self.assertFalse(scratch.path.exists())

    def _check_sealing_failure(self, launcher, profile, cancellation, *, binding=None):
        import fcntl

        original = fcntl.fcntl
        children = len(launcher.children)

        def refuse(fd, operation, *args):
            if binding is None and operation == fcntl.F_ADD_SEALS:
                raise OSError(errno.EPERM, "synthetic sealing fault")
            if binding is not None and operation == fcntl.F_GET_SEALS:
                return 0
            return original(fd, operation, *args)

        with patch.object(fcntl, "fcntl", refuse):
            if binding is None:
                with self.assertRaises(FixtureError) as error:
                    probe_fixture(profile, launcher, cancellation)
            else:
                authority = FixtureAuthority(binding, "haiku", _PROMPT)
                with self.assertRaises(FixtureError) as error:
                    run_fixture_text(binding, "haiku", _PROMPT, launcher, authority, cancellation)
        self.assertEqual(error.exception.reason, "integrity_error")
        self.assertFalse(error.exception.possible_send)
        self.assertEqual(len(launcher.children), children)
        self.assertEqual(launcher.scratch.recovery_names(), ())
        self.assertEqual(list(launcher.delegated.glob("occlaude-*")), [])

    def _check_linux_owner_eof(self, launcher, binding):
        import subprocess

        from fixtures.claude_kernel import PYTHON, SYSTEM, PollCancellation

        for scenario, sent in (("stall_ready", False), ("stall_output", True)):
            with self.subTest(owner_eof=scenario), ExitStack() as cleanup:
                launcher.scenario = scenario
                launcher.started.clear()
                launcher.sent.clear()
                read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
                cleanup.callback(os.close, read_fd)
                try:
                    # This independent owner retains the sole write end until process exit.
                    owner = subprocess.Popen([str(PYTHON), "-IB", "-c", "import os; os.read(0, 1)"],
                                             stdin=subprocess.PIPE, env=SYSTEM, cwd="/", pass_fds=(write_fd,))
                finally:
                    os.close(write_fd)
                cleanup.callback(self._retire_unrelated, owner)
                cleanup.callback(owner.stdin.close)
                cancellation = cleanup.enter_context(PollCancellation(owner_fd=read_fd))

                def let_owner_exit():
                    gate = launcher.sent if sent else launcher.started
                    if gate.wait(3):
                        owner.stdin.close()

                controller = Thread(target=let_owner_exit, daemon=True)
                controller.start()
                start = time.monotonic()
                try:
                    with self.assertRaises(FixtureError) as error:
                        run_fixture_text(binding, "haiku", _PROMPT, launcher,
                                         FixtureAuthority(binding, "haiku", _PROMPT), cancellation)
                finally:
                    controller.join(4)
                self.assertEqual(owner.wait(timeout=2), 0)
                self.assertEqual(os.read(read_fd, 1), b"")
                self.assertEqual(error.exception.reason, "cancelled")
                self.assertIs(error.exception.possible_send, sent)
                self.assertLess(time.monotonic() - start, 4)
                child = launcher.children[-1]
                self.assertTrue(child.retired)
                self.assertIsNotNone(child.process.returncode)
                self.assertFalse((launcher.delegated / child.unit.name).exists())
                self.assertFalse(child.unit.record.exists())

    def _check_linux_scenarios(self, root, launcher, binding, unrelated):
        from fixtures.claude_kernel import PollCancellation

        for scenario, sent in (("stall_ready", False), ("stall_output", True), ("leader_exit", True),
                               ("oversize", True)):
            with self.subTest(scenario=scenario), PollCancellation() as cancellation:
                launcher.scenario = scenario
                launcher.started.clear()
                launcher.sent.clear()
                launcher.leader_exited.clear()
                elapsed = time.monotonic()

                def cancel_active():
                    gate = launcher.sent if sent else launcher.started
                    if scenario == "leader_exit":
                        gate = launcher.leader_exited
                    if gate.wait(3):
                        cancellation.set()

                controller = None
                if scenario != "oversize":
                    controller = Thread(target=cancel_active, daemon=True)
                    controller.start()
                try:
                    with self.assertRaises(FixtureError) as error:
                        run_fixture_text(binding, "haiku", _PROMPT, launcher,
                                         FixtureAuthority(binding, "haiku", _PROMPT), cancellation)
                finally:
                    if controller is not None:
                        controller.join(4)
                self.assertEqual(error.exception.reason, "integrity_error" if scenario == "oversize" else "cancelled")
                self.assertIs(error.exception.possible_send, sent)
                self.assertLess(time.monotonic() - elapsed, 4)
                child = launcher.children[-1]
                self.assertTrue(child.retired)
                self.assertIsNotNone(child.process.returncode)
                self.assertFalse((root / child.unit.name).exists())
                self.assertFalse(child.unit.record.exists())
                self.assertIsNone(unrelated.poll())

    def _check_supervisor_disappearance(self, launcher, binding):
        import select
        import signal

        from fixtures.claude_kernel import PollCancellation

        launcher.scenario = "stall_ready"
        # The controller keeps its own cgroup and record descriptors before it
        # forks. The child receives this unit without opening another by name.
        unit = launcher.prepare_unit()
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        supervisor = os.fork()
        if supervisor == 0:
            os.close(read_fd)
            start = launcher.start

            def announce(*args):
                child = start(*args, prepared_unit=unit)
                os.write(write_fd, b"R" + child.unit.name.encode("ascii"))
                return child

            launcher.start = announce
            with PollCancellation() as cancellation:
                try:
                    run_fixture_text(binding, "haiku", _PROMPT, launcher,
                                     FixtureAuthority(binding, "haiku", _PROMPT), cancellation)
                except BaseException:
                    os._exit(1)
                os.write(write_fd, b"A")
            os._exit(0)

        os.close(write_fd)
        pidfd = os.pidfd_open(supervisor)
        try:
            poller = select.poll()
            poller.register(read_fd, select.POLLIN | select.POLLHUP)
            try:
                self.assertTrue(poller.poll(2000))
                notice = os.read(read_fd, 64)
                self.assertEqual(notice, b"R" + unit.name.encode("ascii"))
                # A ready child is not evidence of a dead supervisor.
                deadline = time.monotonic() + 2
                with self.assertRaisesRegex(FixtureError, "^retirement_unverified$"):
                    unit.recover(pidfd, notice, deadline)
            finally:
                poller.unregister(read_fd)
                poller.register(pidfd, select.POLLIN)
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                self.assertTrue(poller.poll(2000))
                _pid, status = os.waitpid(supervisor, os.WNOHANG)
                self.assertEqual(os.waitstatus_to_exitcode(status), -signal.SIGKILL)
            self.assertEqual(os.read(read_fd, 1), b"")
            deadline = time.monotonic() + 2
            with self.assertRaisesRegex(FixtureError, "^retirement_unverified$"):
                unit.recover(pidfd, b"", deadline)
            self._check_missing_or_substituted_recovery(launcher, unit, pidfd, notice)
            unit.recover(pidfd, notice, time.monotonic() + 2)
            self.assertEqual(launcher.scratch.recovery_names(), ())
            self.assertFalse((launcher.delegated / unit.name).exists())
        finally:
            os.close(pidfd)
            os.close(read_fd)

    def _check_missing_or_substituted_recovery(self, launcher, unit, pidfd, notice):
        scratch = launcher.scratch
        record = unit.record
        evidence = record / "recovery.json"
        original_record = scratch.path.with_name(scratch.path.name + "-held")
        original_file = record / "expected.json"
        sentinel = scratch.path / "recovery-sentinel"
        sentinel.write_text("retain expected scratch")

        def must_refuse():
            with self.assertRaisesRegex(FixtureError, "^retirement_unverified$"):
                scratch.remove()
            deadline = time.monotonic() + 2
            with self.assertRaisesRegex(FixtureError, "^retirement_unverified$"):
                unit.recover(pidfd, notice, deadline)
            self.assertEqual(sentinel.read_text(), "retain expected scratch")
            self.assertTrue((launcher.delegated / unit.name).is_dir())

        record.rename(original_record)
        try:
            self.assertEqual(scratch.recovery_names(), ())
            must_refuse()

            record.mkdir(mode=0o700)
            try:
                evidence.write_bytes(unit.evidence)
                evidence.chmod(0o600)
                must_refuse()
                self.assertEqual(evidence.read_bytes(), unit.evidence)
            finally:
                evidence.unlink()
                record.rmdir()
        finally:
            original_record.rename(record)

        evidence.rename(original_file)
        try:
            must_refuse()
            evidence.write_bytes(unit.evidence)
            evidence.chmod(0o600)
            must_refuse()
            self.assertEqual(evidence.read_bytes(), unit.evidence)
        finally:
            evidence.unlink(missing_ok=True)
            original_file.rename(evidence)

    @staticmethod
    def _retire_unrelated(process):
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)
