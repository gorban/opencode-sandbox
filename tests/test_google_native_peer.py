"""Check native connector ownership without depending on a kernel pidfd sockopt."""

import socket
import struct
import unittest
from unittest.mock import Mock, patch

from oc_google import native_peer


GROUP = b"/user.slice/fixture.service"


class NativePeerTest(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(native_peer.os, "geteuid", return_value=1000))
        self.closed = self.enterContext(patch.object(native_peer.os, "close"))
        self.alive = self.enterContext(patch.object(native_peer, "_alive", return_value=True))
        self.connection = Mock()
        self.connection.family = socket.AF_UNIX
        self.connection.getsockopt.side_effect = [struct.pack("=3i", 123, 1000, 1000), struct.pack("=i", 77)]
        self.membership = Mock(return_value=b"0::" + GROUP + b"\n")

    def admit(self):
        return native_peer.admit_native_peer(self.connection, expected_group=GROUP, read_cgroup=self.membership)

    def test_same_uid_and_live_exact_group_required_through_release(self):
        with self.admit() as peer:
            self.assertTrue(peer.active())
            self.membership.return_value = b"0::" + GROUP + b"/other\n"
            self.assertFalse(peer.active())
        self.assertFalse(peer.active())
        self.closed.assert_called_once_with(77)

    def test_rejects_different_uid_before_opening_pidfd_or_reading(self):
        self.connection.getsockopt.side_effect = [struct.pack("=3i", 123, 1001, 1000)]
        with self.assertRaises(native_peer.NativePeerError):
            with self.admit():
                self.fail("unexpected peer")
        self.membership.assert_not_called()
        self.closed.assert_not_called()

    def test_peer_exit_during_membership_read_denies_admission(self):
        self.alive.side_effect = [True, False]
        with self.assertRaises(native_peer.NativePeerError):
            with self.admit():
                self.fail("unexpected peer")
        self.membership.assert_called_once_with(123)
        self.closed.assert_called_once_with(77)

    def test_missing_pidfd_support_fails_closed(self):
        self.connection.getsockopt.side_effect = [struct.pack("=3i", 123, 1000, 1000), OSError()]
        with self.assertRaises(native_peer.NativePeerError):
            with self.admit():
                self.fail("unexpected peer")
        self.membership.assert_not_called()
