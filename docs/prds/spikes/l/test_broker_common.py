"""Unit & adversarial tests for oc_broker_common.py shared host-broker primitives."""

from __future__ import annotations

import base64
import ipaddress
import os
from pathlib import Path
import socket
import ssl
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
from urllib.parse import quote

_SPIKE_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SPIKE_DIR.parents[3]
for _p in (str(_SPIKE_DIR), str(_REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import oc_controller as occ  # noqa: E402
from oc_broker_common import (  # noqa: E402
    BrokerAuthError,
    BrokerLease,
    BrokerPolicyError,
    CanaryLeakError,
    HostVaultMemory,
    OverlapCanaryScanner,
    PgUpstreamCancelTarget,
    bind_loopback_tcp,
    bind_trusted_uds,
    connect_tls_pinned_ip,
    resolve_and_validate_ip,
    validate_allowed_cidrs,
)


def _ip(*octets: int) -> str:
    return ".".join(str(o) for o in octets)


class _DummyLeaseAdapter:
    def target_revision(self, target: str) -> str | None:
        return "rev_0001" if target == "broker_target" else None

    def set_target_revision(self, target: str, revision: str | None) -> None:
        _ = (target, revision)

    def dispatch(self, attempt: occ.Attempt, payload: occ.Payload) -> occ.Outcome:
        _ = (attempt, payload)
        return occ.Outcome.SUCCEEDED

    def reconcile(self, attempt: occ.Attempt, payload: occ.Payload) -> occ.Outcome:
        return self.dispatch(attempt, payload)


class TestBrokerCommon(unittest.TestCase):
    def test_tls_context_is_verified_before_connecting(self) -> None:
        context = Mock(spec=ssl.SSLContext, verify_mode=ssl.CERT_REQUIRED, check_hostname=False)
        with patch("oc_broker_common.connect_tcp_pinned_ip", side_effect=AssertionError("unexpected fixture dial")) as dial:
            with self.assertRaises(BrokerPolicyError):
                connect_tls_pinned_ip("127.0.0.1", 443, server_hostname="fixture.test", ssl_context=context)
            dial.assert_not_called()

    def test_unix_listener_owns_its_entry_and_cleans_up_partial_start(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "broker.sock"
            listener, bound = bind_trusted_uds(path)
            try:
                with self.assertRaises(BrokerPolicyError):
                    bind_trusted_uds(path)
                with socket.socket(socket.AF_UNIX) as client:
                    client.connect(str(path))
                    peer, _ = listener.accept()
                    peer.close()
            finally:
                listener.close()
                bound.cleanup()
            self.assertFalse(path.exists())

            with (
                patch.object(socket.socket, "listen", side_effect=OSError("fixture listen failure")),
                self.assertRaises(OSError),
            ):
                bind_trusted_uds(path)
            self.assertFalse(path.exists())

    def test_cidr_validation_and_dns_ssrf_fail_closed(self) -> None:
        valid = validate_allowed_cidrs([f"{_ip(10, 20, 0, 0)}/16", f"{_ip(100, 64, 0, 0)}/10"])
        self.assertEqual(len(valid), 2)

        for bad_cidr in (
            f"{_ip(0, 0, 0, 0)}/0",
            "::/0",
            f"{_ip(127, 0, 0, 0)}/8",
            f"{_ip(169, 254, 0, 0)}/16",
            f"{_ip(8, 8, 8, 0)}/24",
            f"{_ip(10, 0, 0, 1)}/8",  # host bits set
        ):
            with self.subTest(cidr=bad_cidr), self.assertRaises(BrokerPolicyError):
                validate_allowed_cidrs([bad_cidr])

        # Non-overridably blocked ranges including IPv4-mapped IPv6 and NAT64
        cidrs_10 = [f"{_ip(10, 0, 0, 0)}/8"]
        for bad_ip in (
            "127.0.0.1",
            "::1",
            f"::ffff:{_ip(127, 0, 0, 1)}",
            _ip(169, 254, 169, 254),
            f"::ffff:{_ip(169, 254, 169, 254)}",
            str(ipaddress.IPv6Address((0xFE80 << 112) | 1)),
            str(ipaddress.IPv6Address((0x0064 << 112) | (0xFF9B << 96) | 1)),
            str(ipaddress.IPv6Address((0xFC00 << 112) | 1)),
        ):
            with self.subTest(ip=bad_ip), self.assertRaises(BrokerPolicyError):
                resolve_and_validate_ip(bad_ip, allowed_cidrs=cidrs_10)

        # RFC1918 blocked by default, allowed ONLY when explicitly pinned
        priv = _ip(10, 42, 1, 9)
        with self.assertRaises(BrokerPolicyError):
            resolve_and_validate_ip(priv)
        self.assertEqual(
            resolve_and_validate_ip(priv, allowed_cidrs=[f"{_ip(10, 42, 0, 0)}/16"]),
            priv,
        )

        # Multi-record DNS fails closed if ANY returned record hits metadata/loopback
        def _poisoned_dns(host: str, port: int, **_kw: object) -> list[object]:
            _ = (host, port)
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (_ip(93, 184, 216, 34), 443)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (_ip(169, 254, 169, 254), 443)),
            ]

        with self.assertRaises(BrokerPolicyError):
            resolve_and_validate_ip("rebind.example.com", resolver=_poisoned_dns)

    def test_host_vault_and_overlap_canary_scanner(self) -> None:
        vault = HostVaultMemory()
        with self.assertRaises(BrokerPolicyError):
            vault.set("k:short", "too-short")
        secret_ro = "CANARY_SECRET_VALUE_RO_991122/+=?"
        secret_rw = "CANARY_SECRET_VALUE_RW_884455/+=?"
        vault.set("keeper:ro", secret_ro)
        vault.set("keeper:rw", secret_rw)
        vault.assert_distinct_refs("keeper:ro", "keeper:rw")

        vault.set("keeper:dup", secret_ro)
        with self.assertRaises(BrokerPolicyError):
            vault.assert_distinct_refs("keeper:ro", "keeper:dup")

        with self.assertRaises(BrokerPolicyError):
            HostVaultMemory.assert_distinct_pg_credentials("app_ro", "pw1_long_secret", "app_ro", "pw2_long_secret")

        # Raw split across chunks
        def _feed_chunked(scanner: OverlapCanaryScanner, data: bytes, step: int) -> bytes:
            parts = [scanner.feed(data[idx : idx + step]) for idx in range(0, len(data), step)]
            parts.append(scanner.finish())
            return b"".join(parts)

        sc_raw = OverlapCanaryScanner([secret_ro])
        raw_bytes = b"prefix " + secret_ro.encode("utf-8") + b" suffix"
        with self.assertRaises(CanaryLeakError):
            _feed_chunked(sc_raw, raw_bytes, 5)

        # URL-encoded & unpadded base64 split across chunks
        for variant in (
            quote(secret_ro, safe="").encode("ascii"),
            base64.b64encode(secret_ro.encode("utf-8")).rstrip(b"="),
            base64.urlsafe_b64encode(secret_ro.encode("utf-8")).rstrip(b"="),
        ):
            sc = OverlapCanaryScanner([secret_ro])
            payload = b"ok:" + variant + b":end"
            with self.subTest(variant=variant[:12]), self.assertRaises(CanaryLeakError):
                _feed_chunked(sc, payload, 15)

        # Clean stream passes intact including flushed tail
        sc_ok = OverlapCanaryScanner([secret_ro])
        reconstructed = sc_ok.feed(b"hello ") + sc_ok.feed(b"world!") + sc_ok.finish()
        self.assertEqual(reconstructed, b"hello world!")

    def test_broker_lease_controller_watchdog_and_socket_teardown(self) -> None:
        now = [100]
        op = occ.Principal(occ.Role.OPERATOR, "host_op")
        orch = occ.Principal(occ.Role.ORCHESTRATOR, "orch_1")
        job_p = occ.Principal(occ.Role.JOB, "broker_job")
        subj = occ.Subject("worker_local", "job_inc_01", "broker_job")
        ctrl = occ.Controller(
            incarnation="0123456789abcdef0123456789abcdef",
            clock=lambda: now[0],
            lifetime=600,
            workers=[occ.Worker("worker_local", op)],
            jobs=[occ.Job(subj, orch, 16)],
            capabilities=[occ.Capability("cap_broker", occ.Operation.PROBE, "broker_target")],
            references=[occ.Reference("ref_broker", "cap_broker")],
            adapter=_DummyLeaseAdapter(),
        )
        ctrl._set_alias("broker_alias", "broker_target")
        prop = ctrl.propose(job_p, occ.Proposal(occ.Intent.PROBE_GRANT, "broker_alias", "ref_broker"))
        view = ctrl.view(op, prop.request_id)
        ctrl.decide(op, prop.request_id, view.payload.revision, view.digest, occ.Decision.APPROVE)

        lease = BrokerLease(
            "job_1",
            controller=ctrl,
            controller_actor=job_p,
            controller_request_id=prop.request_id,
        )
        lease.start_watchdog(poll_interval=0.02)
        s_a, s_b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        cancelled = []
        try:
            lease.register_stream(s_a)
            lease.add_revoke_callback(lambda: cancelled.append(True))
            pair = lease.register_pg_cancel(
                PgUpstreamCancelTarget("127.0.0.1", 5432, "db.example.com", 101, 202)
            )
            self.assertIsNotNone(lease.lookup_pg_cancel(*pair))

            # Out-of-band controller revoke tears down stream within <1s
            t0 = time.monotonic()
            ctrl.revoke(op, prop.request_id)
            s_b.settimeout(1.0)
            eof = s_b.recv(16)
            elapsed = time.monotonic() - t0
            self.assertEqual(eof, b"")
            self.assertLess(elapsed, 0.8)
            self.assertTrue(cancelled)
            self.assertIsNone(lease.lookup_pg_cancel(*pair))

            # Post-revocation stream registration fails closed immediately
            s_c, s_d = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                with self.assertRaises(BrokerAuthError):
                    lease.register_stream(s_c)
            finally:
                s_c.close()
                s_d.close()
        finally:
            lease.stop_watchdog()
            s_a.close()
            s_b.close()

    def test_gate2_r1_bind_trusted_uds_ipv6_loopback_and_revoke_no_close(self) -> None:
        # P3-2: BrokerLease.revoke shuts down registered sockets without closing owning FDs
        lease = BrokerLease("job_revoke_fd")
        s1, s2 = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            lease.register_stream(s1)
            lease.revoke()
            self.assertNotEqual(s1.fileno(), -1)
            s2.settimeout(0.5)
            self.assertEqual(s2.recv(16), b"")
        finally:
            s1.close()
            s2.close()

        # P1-2: bind_trusted_uds rejects untrusted parent perms, symlinks, sandbox paths, non-sockets
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            os.chmod(root, 0o700)
            sandbox = root / "sandbox"
            sandbox.mkdir(mode=0o700)

            grp_dir = root / "group_writable"
            grp_dir.mkdir(mode=0o700)
            os.chmod(grp_dir, 0o770)
            with self.assertRaises(BrokerPolicyError):
                bind_trusted_uds(grp_dir / "nested" / "b.sock", sandbox_root=sandbox)
            # Must NOT silently chmod untrusted pre-existing dirs or create nested dirs
            self.assertEqual(stat.S_IMODE(os.lstat(grp_dir).st_mode), 0o770)
            self.assertFalse((grp_dir / "nested").exists())

            link_parent = root / "sym_parent"
            link_parent.symlink_to(root)
            with self.assertRaises(BrokerPolicyError):
                bind_trusted_uds(link_parent / "b.sock", sandbox_root=sandbox)

            with self.assertRaises(BrokerPolicyError):
                bind_trusted_uds(sandbox / "inside.sock", sandbox_root=sandbox)

            reg_file = root / "not_a_socket"
            reg_file.write_text("keep", encoding="utf-8")
            with self.assertRaises(BrokerPolicyError):
                bind_trusted_uds(reg_file, sandbox_root=sandbox)
            self.assertTrue(reg_file.exists())

            sock, bound = bind_trusted_uds(root / "ok_sub" / "broker.sock", sandbox_root=sandbox)
            try:
                self.assertEqual(stat.S_IMODE(os.lstat(bound.path.parent).st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(os.lstat(bound.path).st_mode), 0o600)
            finally:
                sock.close()
                bound.cleanup()
            self.assertFalse(bound.path.exists())

        # P3-1: bind_loopback_tcp supports IPv6 ::1 and rejects non-loopback
        with self.assertRaises(BrokerPolicyError):
            bind_loopback_tcp("2001:db8::1", 0)
        if socket.has_ipv6:
            try:
                s6, port6 = bind_loopback_tcp("::1", 0)
            except OSError:
                return
            try:
                self.assertGreater(port6, 0)
                self.assertEqual(s6.family, socket.AF_INET6)
            finally:
                s6.close()


if __name__ == "__main__":
    unittest.main()
