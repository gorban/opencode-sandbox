"""Unit and adversarial tests for oc_coord_rpc.py and oc_ui_auth.py."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
import socket
import stat
import sys
import tempfile
import threading
from typing import Any
import unittest

_SPIKE_M_DIR = Path(__file__).resolve().parent
if str(_SPIKE_M_DIR) not in sys.path:
    sys.path.insert(0, str(_SPIKE_M_DIR))

from oc_coord_contract import (  # noqa: E402
    MAX_ARTIFACTS_PER_MSG,
    ArtifactRef,
    CoordAuthError,
    CoordBackpressureError,
    CoordPolicyError,
    CoordRole,
    CoordValidationError,
    PrincipalCtx,
    RevocationStatus,
)
from oc_coord_rpc import (  # noqa: E402
    ERR_CODE_AUTH,
    ERR_CODE_INTERNAL,
    ERR_CODE_INVALID_PARAMS,
    ERR_CODE_INVALID_REQUEST,
    ERR_CODE_PARSE,
    ERR_CODE_POLICY,
    ERR_CODE_RATE_LIMIT,
    FORBIDDEN_IDENTITY_KEYS,
    MAX_FRAME_BYTES,
    MAX_HEADER_BYTES,
    MAX_SEQ_INT,
    CoordHubProtocol,
    CoordUdsRpcServer,
    SlidingWindowRateLimiter,
    StrictJsonError,
    encode_content_length_frame,
    parse_strict_json,
    read_content_length_frame,
    uds_rpc_call,
)
from oc_ui_auth import (  # noqa: E402
    MODE_INTERACTIVE,
    MODE_OBSERVE,
    MODE_PIP_WALL,
    SURFACE_BROWSER,
    SURFACE_EVENTS,
    SURFACE_OPENCODE_TUI,
    SURFACE_SHELL,
    UiAuthDeniedError,
    UiAuthManager,
    UiAuthValidationError,
)

_TEST_HOST = "127.0.0.1:47110"
_TEST_ORIGIN = "http://127.0.0.1:47110"
_TEST_TARGET = "feat-a"
_TEST_INCARNATION = "inc_abc123"
_TEST_SHA256 = "a" * 64


class _ManualClock:
    def __init__(self, start: float = 1000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _StubCoordHub:
    """In-memory stub implementing CoordHubProtocol for RPC server tests."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, PrincipalCtx, dict[str, Any]]] = []
        self.next_error: Exception | None = None

    def _maybe_raise(self) -> None:
        if self.next_error is not None:
            exc = self.next_error
            self.next_error = None
            raise exc

    def send(
        self,
        caller: PrincipalCtx,
        *,
        target: str,
        thread_id: str = "main",
        msg_kind: str = "prompt",
        body_text: str,
        in_reply_to: str | None = None,
        artifact_refs: Sequence[ArtifactRef] = (),
    ) -> dict[str, Any]:
        self._maybe_raise()
        self.calls.append(
            (
                "send",
                caller,
                {
                    "target": target,
                    "thread_id": thread_id,
                    "msg_kind": msg_kind,
                    "body_text": body_text,
                    "in_reply_to": in_reply_to,
                    "artifact_refs": tuple(artifact_refs),
                },
            )
        )
        return {"msg_id": "msg_1", "seq": 1, "sender": caller.canonical_sender}

    def status(
        self,
        caller: PrincipalCtx,
        *,
        target: str | None = None,
    ) -> dict[str, Any]:
        self._maybe_raise()
        self.calls.append(("status", caller, {"target": target}))
        return {"target": target, "state": "running"}

    def wait(
        self,
        caller: PrincipalCtx,
        *,
        targets: Sequence[str],
        since_seq: int = 0,
        timeout_s: float = 5.0,
    ) -> dict[str, Any]:
        self._maybe_raise()
        self.calls.append(
            ("wait", caller, {"targets": tuple(targets), "since_seq": since_seq, "timeout_s": timeout_s})
        )
        return {"events": [], "last_seq": since_seq}

    def revoke(
        self,
        caller: PrincipalCtx,
        *,
        target: str,
        reason: str = "operator_revoked",
    ) -> RevocationStatus:
        self._maybe_raise()
        self.calls.append(("revoke", caller, {"target": target, "reason": reason}))
        return RevocationStatus(
            target_addr=target,
            incarnation_id=_TEST_INCARNATION,
            revoked_edges=2,
            aborted_streams=True,
            elapsed_ms=1.5,
        )

    def projection(self, caller: PrincipalCtx) -> dict[str, Any]:
        self._maybe_raise()
        self.calls.append(("projection", caller, {}))
        return {"projects": [], "caller": caller.canonical_sender}


def _extract_session_id(set_cookie_header: str) -> str:
    first_pair = set_cookie_header.split(";", 1)[0]
    return first_pair.split("=", 1)[1]


class TestStrictJsonAndRateLimiter(unittest.TestCase):
    def test_parse_strict_json_rejects_adversarial_inputs(self) -> None:
        bad_payloads = [
            b'{"a":1,"a":2}',
            b'{"v":NaN}',
            b'{"v":Infinity}',
            b'{"v":-Infinity}',
            b'{"v":1e999}',
            b'{"v":-1e999}',
            b'{"s":"\\ud800"}',
            b'{"s":"\\udfff"}',
            b'{"s":"ok\x00bad"}',
            b'{"s":"\\u0000"}',
            b"\xff\xfe",
            b"[1, 2, 3]",
            b'"just a string"',
            b"42",
        ]
        for raw in bad_payloads:
            with self.assertRaises(StrictJsonError):
                parse_strict_json(raw)

    def test_parse_strict_json_enforces_depth_and_max_bytes(self) -> None:
        deep_ok = (b'{"a":' * 31) + b"1" + (b"}" * 31)
        parsed = parse_strict_json(deep_ok, max_depth=32)
        self.assertIsInstance(parsed, dict)

        deep_bad = (b'{"a":' * 33) + b"1" + (b"}" * 33)
        with self.assertRaises(StrictJsonError):
            parse_strict_json(deep_bad, max_depth=32)

        oversized = b'{"x":"' + (b"a" * 200) + b'"}'
        with self.assertRaises(StrictJsonError):
            parse_strict_json(oversized, max_bytes=128)

    def test_sliding_window_rate_limiter_window_and_key_bounds(self) -> None:
        clock = _ManualClock(100.0)
        limiter = SlidingWindowRateLimiter(2, 10.0, max_keys=2, clock=clock)
        self.assertTrue(limiter.allow("k1"))
        self.assertTrue(limiter.allow("k1"))
        self.assertFalse(limiter.allow("k1"))
        self.assertTrue(limiter.allow("k2"))
        self.assertFalse(limiter.allow("k3"))

        clock.advance(11.0)
        self.assertTrue(limiter.allow("k3"))
        self.assertTrue(limiter.allow("k1"))

        for bad_window in (0.0, -1.0, float("nan"), float("inf"), True):
            with self.assertRaises(ValueError):
                SlidingWindowRateLimiter(5, bad_window)


class TestCoordUdsRpcServer(unittest.TestCase):
    def test_stub_satisfies_protocol(self) -> None:
        self.assertIsInstance(_StubCoordHub(), CoordHubProtocol)

    def test_bind_permissions_and_happy_path_methods(self) -> None:
        hub = _StubCoordHub()
        with tempfile.TemporaryDirectory() as tmp:
            sock_dir = Path(tmp) / "rpc_dir"
            sock_path = sock_dir / "operator.sock"
            with CoordUdsRpcServer(hub, sock_path) as srv:
                dir_mode = stat.S_IMODE(sock_dir.stat().st_mode)
                sock_mode = stat.S_IMODE(sock_path.stat().st_mode)
                self.assertEqual(dir_mode, 0o700)
                self.assertEqual(sock_mode, 0o600)
                self.assertEqual(srv.socket_path, sock_path)

                send_resp = uds_rpc_call(
                    sock_path,
                    "coord.send",
                    {
                        "target": _TEST_TARGET,
                        "thread_id": "main",
                        "msg_kind": "prompt",
                        "body_text": "hello",
                        "artifact_refs": [
                            {"blob_sha256": _TEST_SHA256, "size_bytes": 12, "media_type": "text/x-patch"}
                        ],
                    },
                )
                self.assertEqual(send_resp["result"]["msg_id"], "msg_1")
                self.assertEqual(hub.calls[-1][1].role, CoordRole.OPERATOR)

                st_resp = uds_rpc_call(sock_path, "coord.status", {"target": _TEST_TARGET})
                self.assertEqual(st_resp["result"]["state"], "running")

                wait_resp = uds_rpc_call(
                    sock_path,
                    "coord.wait",
                    {"targets": [_TEST_TARGET], "since_seq": 3, "timeout_s": 0.5},
                )
                self.assertEqual(wait_resp["result"]["last_seq"], 3)

                rev_resp = uds_rpc_call(
                    sock_path,
                    "coord.revoke",
                    {"target": _TEST_TARGET, "reason": "done"},
                )
                self.assertTrue(rev_resp["result"]["aborted_streams"])
                self.assertEqual(rev_resp["result"]["revoked_edges"], 2)

                proj_resp = uds_rpc_call(sock_path, "coord.projection", {})
                self.assertEqual(proj_resp["result"]["projects"], [])

    def test_so_peercred_uid_mismatch_closes_without_reading(self) -> None:
        hub = _StubCoordHub()
        with tempfile.TemporaryDirectory() as tmp:
            sock_path = Path(tmp) / "rpc_dir" / "operator.sock"
            with CoordUdsRpcServer(
                hub, sock_path, peer_uid_getter=lambda _c: 999_999
            ):
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    client.settimeout(2.0)
                    client.connect(str(sock_path))
                    try:
                        client.sendall(
                            encode_content_length_frame(
                                {"jsonrpc": "2.0", "id": 1, "method": "coord.projection", "params": {}}
                            )
                        )
                        data = client.recv(1024)
                    except (ConnectionResetError, BrokenPipeError):
                        data = b""
                    self.assertEqual(data, b"")
                finally:
                    client.close()
        self.assertEqual(hub.calls, [])

    def test_pre_parse_rate_limit_denial(self) -> None:
        hub = _StubCoordHub()
        with tempfile.TemporaryDirectory() as tmp:
            sock_path = Path(tmp) / "rpc_dir" / "operator.sock"
            with CoordUdsRpcServer(hub, sock_path, rate_limit_max=1, rate_limit_window=60.0):
                first = uds_rpc_call(sock_path, "coord.projection", {})
                self.assertIn("result", first)

                # Second connection sends malformed/oversized header; must still get rate_limited
                # BEFORE framing/JSON parsing runs.
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    client.settimeout(2.0)
                    client.connect(str(sock_path))
                    raw_resp = read_content_length_frame(client, read_timeout=2.0, total_timeout=2.0)
                    parsed = parse_strict_json(raw_resp)
                    self.assertEqual(parsed["error"]["code"], ERR_CODE_RATE_LIMIT)
                finally:
                    client.close()

    def test_oversized_frame_and_pipelined_bytes_rejected(self) -> None:
        hub = _StubCoordHub()
        with tempfile.TemporaryDirectory() as tmp:
            sock_path = Path(tmp) / "rpc_dir" / "operator.sock"
            with CoordUdsRpcServer(hub, sock_path):
                # Oversized Content-Length header
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    client.settimeout(2.0)
                    client.connect(str(sock_path))
                    hdr = f"Content-Length: {MAX_FRAME_BYTES + 1}\r\n\r\n".encode("ascii")
                    client.sendall(hdr)
                    resp = parse_strict_json(read_content_length_frame(client))
                    self.assertEqual(resp["error"]["code"], ERR_CODE_PARSE)
                finally:
                    client.close()

                # Trailing pipelined bytes
                client2 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    client2.settimeout(2.0)
                    client2.connect(str(sock_path))
                    frame = encode_content_length_frame(
                        {"jsonrpc": "2.0", "id": 1, "method": "coord.projection", "params": {}}
                    )
                    client2.sendall(frame + b"EXTRA")
                    resp2 = parse_strict_json(read_content_length_frame(client2))
                    self.assertEqual(resp2["error"]["code"], ERR_CODE_PARSE)
                finally:
                    client2.close()

    def test_forged_identity_keys_and_unknown_extra_params_rejected(self) -> None:
        hub = _StubCoordHub()
        with tempfile.TemporaryDirectory() as tmp:
            sock_path = Path(tmp) / "rpc_dir" / "operator.sock"
            with CoordUdsRpcServer(hub, sock_path):
                for key in sorted(FORBIDDEN_IDENTITY_KEYS):
                    resp = uds_rpc_call(
                        sock_path,
                        "coord.status",
                        {"target": _TEST_TARGET, key: "forged-operator"},
                    )
                    self.assertEqual(resp["error"]["code"], ERR_CODE_INVALID_PARAMS)
                    self.assertIn("forbidden_identity_params", resp["error"]["message"])

                extra_resp = uds_rpc_call(
                    sock_path,
                    "coord.status",
                    {"target": _TEST_TARGET, "unexpected_key": True},
                )
                self.assertEqual(extra_resp["error"]["code"], ERR_CODE_INVALID_PARAMS)
                self.assertIn("unknown_params", extra_resp["error"]["message"])
        self.assertEqual(hub.calls, [])

    def test_token_principal_binding_and_hub_error_mapping(self) -> None:
        hub = _StubCoordHub()
        job_principal = PrincipalCtx(
            role=CoordRole.JOB,
            actor_id="job_1",
            sandbox_addr=_TEST_TARGET,
            incarnation_id=_TEST_INCARNATION,
        )
        tok = "ocjob_token_value_1234567890"
        with tempfile.TemporaryDirectory() as tmp:
            sock_path = Path(tmp) / "rpc_dir" / "job.sock"
            with CoordUdsRpcServer(hub, sock_path, token_principals={tok: job_principal}):
                unauth = uds_rpc_call(sock_path, "coord.projection", {})
                self.assertEqual(unauth["error"]["code"], ERR_CODE_AUTH)

                wrong = uds_rpc_call(sock_path, "coord.projection", {}, auth_token="wrong")
                self.assertEqual(wrong["error"]["code"], ERR_CODE_AUTH)

                ok = uds_rpc_call(sock_path, "coord.projection", {}, auth_token=tok)
                self.assertEqual(ok["result"]["caller"], _TEST_TARGET)
                self.assertEqual(hub.calls[-1][1], job_principal)

                for exc, code in (
                    (CoordValidationError("bad"), ERR_CODE_INVALID_PARAMS),
                    (CoordAuthError("denied"), ERR_CODE_AUTH),
                    (CoordBackpressureError("full"), ERR_CODE_RATE_LIMIT),
                    (CoordPolicyError("policy"), ERR_CODE_POLICY),
                ):
                    hub.next_error = exc
                    err_resp = uds_rpc_call(sock_path, "coord.projection", {}, auth_token=tok)
                    self.assertEqual(err_resp["error"]["code"], code)

    def test_rpc_dos_bounds_slowloris_concurrency_and_config_validation(self) -> None:
        hub = _StubCoordHub()
        with tempfile.TemporaryDirectory() as tmp:
            sock_path = Path(tmp) / "rpc_dir" / "operator.sock"
            # Reject invalid server configs
            with self.assertRaises(ValueError):
                CoordUdsRpcServer(hub, sock_path, io_timeout=float("nan"))
            with self.assertRaises(ValueError):
                CoordUdsRpcServer(
                    hub,
                    sock_path,
                    required_auth_token="tok_a",
                    token_principals={"tok_b": PrincipalCtx(CoordRole.OPERATOR, "op1")},
                )

            with CoordUdsRpcServer(hub, sock_path, max_concurrent_conns=1, io_timeout=0.15):
                # Top-level forged identity key rejected with -32600
                c_top = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    c_top.settimeout(2.0)
                    c_top.connect(str(sock_path))
                    c_top.sendall(
                        encode_content_length_frame(
                            {
                                "jsonrpc": "2.0",
                                "id": 1,
                                "src": "forged",
                                "method": "coord.projection",
                                "params": {},
                            }
                        )
                    )
                    top_resp = parse_strict_json(read_content_length_frame(c_top))
                    self.assertEqual(top_resp["error"]["code"], ERR_CODE_INVALID_REQUEST)
                finally:
                    c_top.close()

                # Oversized header section > MAX_HEADER_BYTES rejected even on final chunk
                c_hdr = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    c_hdr.settimeout(2.0)
                    c_hdr.connect(str(sock_path))
                    pad = " " * (MAX_HEADER_BYTES + 16)
                    c_hdr.sendall(f"Content-Length:{pad}2\r\n\r\n{{}}".encode("ascii"))
                    hdr_resp = parse_strict_json(read_content_length_frame(c_hdr))
                    self.assertEqual(hdr_resp["error"]["code"], ERR_CODE_PARSE)
                finally:
                    c_hdr.close()

                # Huge wait timeout_s, out-of-range since_seq, and too many artifact_refs rejected
                bad_wait_timeout = uds_rpc_call(
                    sock_path, "coord.wait", {"targets": [_TEST_TARGET], "timeout_s": 10**400}
                )
                self.assertEqual(bad_wait_timeout["error"]["code"], ERR_CODE_INVALID_PARAMS)
                bad_wait_seq = uds_rpc_call(
                    sock_path, "coord.wait", {"targets": [_TEST_TARGET], "since_seq": MAX_SEQ_INT + 1}
                )
                self.assertEqual(bad_wait_seq["error"]["code"], ERR_CODE_INVALID_PARAMS)
                too_many_refs = [
                    {"blob_sha256": _TEST_SHA256, "size_bytes": 1}
                    for _ in range(MAX_ARTIFACTS_PER_MSG + 1)
                ]
                bad_refs = uds_rpc_call(
                    sock_path,
                    "coord.send",
                    {"target": _TEST_TARGET, "body_text": "hi", "artifact_refs": too_many_refs},
                )
                self.assertEqual(bad_refs["error"]["code"], ERR_CODE_INVALID_PARAMS)

                # Slowloris + max_concurrent_conns=1 enforcement: hold 1 slot idle, 2nd conn dropped
                slow = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                second = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    slow.settimeout(2.0)
                    slow.connect(str(sock_path))
                    slow.sendall(b"Content-Length: 20\r\n")
                    second.settimeout(1.0)
                    second.connect(str(sock_path))
                    try:
                        extra_data = second.recv(64)
                    except (ConnectionResetError, BrokenPipeError):
                        extra_data = b""
                    self.assertEqual(extra_data, b"")
                    # Slowloris client times out and receives parse/framing error -32700
                    slow_resp = parse_strict_json(read_content_length_frame(slow, read_timeout=2.0))
                    self.assertEqual(slow_resp["error"]["code"], ERR_CODE_PARSE)
                finally:
                    second.close()
                    slow.close()

    def test_non_serializable_hub_response_returns_internal_error(self) -> None:
        class _BadHub(_StubCoordHub):
            def projection(self, caller: PrincipalCtx) -> dict[str, Any]:
                return {"bad": object()}

        with tempfile.TemporaryDirectory() as tmp:
            sock_path = Path(tmp) / "rpc_dir" / "operator.sock"
            with CoordUdsRpcServer(_BadHub(), sock_path):
                resp = uds_rpc_call(sock_path, "coord.projection", {})
                self.assertEqual(resp["error"]["code"], ERR_CODE_INTERNAL)
                self.assertEqual(resp["error"]["message"], "response_serialization_error")


class TestUiAuthManager(unittest.TestCase):
    def _make_mgr(self, clock: _ManualClock, **kwargs: Any) -> UiAuthManager:
        return UiAuthManager(
            allowed_hosts=[_TEST_HOST],
            allowed_origins=[_TEST_ORIGIN],
            clock=clock,
            **kwargs,
        )

    def _new_session(self, mgr: UiAuthManager, actor_id: str = "operator") -> tuple[str, str, str]:
        code = mgr.mint_bootstrap_code(actor_id=actor_id)
        rec, csrf, cookie = mgr.exchange_bootstrap_code(
            code, host_header=_TEST_HOST, origin_header=_TEST_ORIGIN
        )
        return _extract_session_id(cookie), csrf, rec.session_id_hash

    def test_bootstrap_code_expiry_cookie_flags_and_concurrent_single_use(self) -> None:
        clock = _ManualClock(500.0)
        mgr = self._make_mgr(clock)

        exp_code = mgr.mint_bootstrap_code()
        clock.advance(60.0)
        with self.assertRaises(UiAuthDeniedError):
            mgr.exchange_bootstrap_code(exp_code, host_header=_TEST_HOST)

        race_code = mgr.mint_bootstrap_code()
        barrier = threading.Barrier(8)
        successes: list[tuple[str, str]] = []
        failures: list[Exception] = []
        res_lock = threading.Lock()

        def worker() -> None:
            barrier.wait()
            try:
                rec, csrf, cookie = mgr.exchange_bootstrap_code(
                    race_code, host_header=_TEST_HOST, origin_header=_TEST_ORIGIN
                )
                with res_lock:
                    successes.append((rec.session_id_hash, cookie))
            except UiAuthDeniedError as exc:
                with res_lock:
                    failures.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 7)
        cookie_hdr = successes[0][1]
        self.assertIn("HttpOnly; SameSite=Strict; Path=/", cookie_hdr)
        raw_sid = _extract_session_id(cookie_hdr)
        self.assertNotEqual(raw_sid, successes[0][0])

    def test_session_idle_and_absolute_ttl_expiry(self) -> None:
        clock = _ManualClock(1000.0)
        mgr = self._make_mgr(clock, idle_ttl_s=100.0, absolute_ttl_s=250.0)
        sid_idle, _, _ = self._new_session(mgr)

        clock.advance(99.0)
        mgr.validate_session(sid_idle, host_header=_TEST_HOST, touch=False)
        clock.advance(1.0)
        with self.assertRaises(UiAuthDeniedError):
            mgr.validate_session(sid_idle, host_header=_TEST_HOST)

        sid_abs, _, _ = self._new_session(mgr)
        for _ in range(4):
            clock.advance(60.0)
            mgr.validate_session(sid_abs, host_header=_TEST_HOST, touch=True)
        clock.advance(10.0)
        with self.assertRaises(UiAuthDeniedError):
            mgr.validate_session(sid_abs, host_header=_TEST_HOST)

    def test_cross_session_csrf_host_rebinding_and_origin_enforcement(self) -> None:
        clock = _ManualClock(2000.0)
        mgr = self._make_mgr(clock, idle_ttl_s=100.0)
        sid_a, csrf_a, _ = self._new_session(mgr, actor_id="op_a")
        sid_b, csrf_b, _ = self._new_session(mgr, actor_id="op_b")

        mgr.verify_http_mutation(
            sid_a, host_header=_TEST_HOST, origin_header=_TEST_ORIGIN, csrf_token=csrf_a
        )
        # Cross-session CSRF rejected and must NOT extend Session B's idle clock
        clock.advance(90.0)
        with self.assertRaises(UiAuthDeniedError):
            mgr.verify_http_mutation(
                sid_b, host_header=_TEST_HOST, origin_header=_TEST_ORIGIN, csrf_token=csrf_a
            )
        clock.advance(10.0)
        with self.assertRaises(UiAuthDeniedError):
            mgr.validate_session(sid_b, host_header=_TEST_HOST)

        # DNS rebinding Host rejected
        for bad_host in ("evil.com:47110", "127.0.0.1:9999", "127.0.0.1.evil.com:47110", ""):
            with self.assertRaises(UiAuthDeniedError):
                mgr.verify_http_mutation(
                    sid_a, host_header=bad_host, origin_header=_TEST_ORIGIN, csrf_token=csrf_a
                )

        # Missing, null, and foreign Origin rejected
        for bad_origin in (None, "null", "NULL", "http://evil.example", "http://127.0.0.1:9999"):
            with self.assertRaises(UiAuthDeniedError):
                mgr.verify_http_mutation(
                    sid_a, host_header=_TEST_HOST, origin_header=bad_origin, csrf_token=csrf_a
                )
        _ = csrf_b

    def test_ws_ticket_expiry_concurrent_single_use_and_origin_host_checks(self) -> None:
        clock = _ManualClock(3000.0)
        mgr = self._make_mgr(clock)
        sid, csrf, _ = self._new_session(mgr)

        exp_tk = mgr.mint_ws_ticket(
            sid,
            host_header=_TEST_HOST,
            origin_header=_TEST_ORIGIN,
            csrf_token=csrf,
            target_addr=_TEST_TARGET,
            incarnation_id=_TEST_INCARNATION,
            surface_kind=SURFACE_OPENCODE_TUI,
            mode=MODE_OBSERVE,
        )
        clock.advance(30.0)
        with self.assertRaises(UiAuthDeniedError):
            mgr.consume_ws_ticket(
                exp_tk,
                host_header=_TEST_HOST,
                origin_header=_TEST_ORIGIN,
                expected_target_addr=_TEST_TARGET,
                expected_incarnation_id=_TEST_INCARNATION,
                expected_surface_kind=SURFACE_OPENCODE_TUI,
                expected_mode=MODE_OBSERVE,
            )

        race_tk = mgr.mint_ws_ticket(
            sid,
            host_header=_TEST_HOST,
            origin_header=_TEST_ORIGIN,
            csrf_token=csrf,
            target_addr=_TEST_TARGET,
            incarnation_id=_TEST_INCARNATION,
            surface_kind=SURFACE_SHELL,
            mode=MODE_INTERACTIVE,
        )
        # Reject null/foreign origin before ticket consumption burns nothing or denies
        for bad_origin in (None, "null", "http://evil.example"):
            with self.assertRaises(UiAuthDeniedError):
                mgr.consume_ws_ticket(
                    race_tk,
                    host_header=_TEST_HOST,
                    origin_header=bad_origin,
                    expected_target_addr=_TEST_TARGET,
                    expected_incarnation_id=_TEST_INCARNATION,
                    expected_surface_kind=SURFACE_SHELL,
                    expected_mode=MODE_INTERACTIVE,
                )

        barrier = threading.Barrier(8)
        ok_count = 0
        err_count = 0
        lock = threading.Lock()

        def consumer() -> None:
            nonlocal ok_count, err_count
            barrier.wait()
            try:
                mgr.consume_ws_ticket(
                    race_tk,
                    host_header=_TEST_HOST,
                    origin_header=_TEST_ORIGIN,
                    expected_target_addr=_TEST_TARGET,
                    expected_incarnation_id=_TEST_INCARNATION,
                    expected_surface_kind=SURFACE_SHELL,
                    expected_mode=MODE_INTERACTIVE,
                )
                with lock:
                    ok_count += 1
            except UiAuthDeniedError:
                with lock:
                    err_count += 1

        threads = [threading.Thread(target=consumer) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(ok_count, 1)
        self.assertEqual(err_count, 7)

    def test_ws_ticket_scope_pinning_pip_wall_and_revoked_session(self) -> None:
        clock = _ManualClock(4000.0)
        mgr = self._make_mgr(clock)
        sid, csrf, _ = self._new_session(mgr)

        # pip_wall is forbidden on non-browser surfaces; events forbids interactive
        with self.assertRaises(UiAuthValidationError):
            mgr.mint_ws_ticket(
                sid,
                host_header=_TEST_HOST,
                origin_header=_TEST_ORIGIN,
                csrf_token=csrf,
                target_addr=_TEST_TARGET,
                incarnation_id=_TEST_INCARNATION,
                surface_kind=SURFACE_SHELL,
                mode=MODE_PIP_WALL,
            )
        with self.assertRaises(UiAuthValidationError):
            mgr.mint_ws_ticket(
                sid,
                host_header=_TEST_HOST,
                origin_header=_TEST_ORIGIN,
                csrf_token=csrf,
                target_addr=_TEST_TARGET,
                incarnation_id=_TEST_INCARNATION,
                surface_kind=SURFACE_EVENTS,
                mode=MODE_INTERACTIVE,
            )

        # Cross-target, cross-incarnation, cross-surface, cross-mode (pip_wall -> interactive)
        mismatches = [
            ("feat-b", _TEST_INCARNATION, SURFACE_BROWSER, MODE_PIP_WALL),
            (_TEST_TARGET, "inc_other", SURFACE_BROWSER, MODE_PIP_WALL),
            (_TEST_TARGET, _TEST_INCARNATION, SURFACE_SHELL, MODE_OBSERVE),
            (_TEST_TARGET, _TEST_INCARNATION, SURFACE_BROWSER, MODE_INTERACTIVE),
        ]
        for exp_target, exp_inc, exp_surface, exp_mode in mismatches:
            tk = mgr.mint_ws_ticket(
                sid,
                host_header=_TEST_HOST,
                origin_header=_TEST_ORIGIN,
                csrf_token=csrf,
                target_addr=_TEST_TARGET,
                incarnation_id=_TEST_INCARNATION,
                surface_kind=SURFACE_BROWSER,
                mode=MODE_PIP_WALL,
            )
            with self.assertRaises(UiAuthDeniedError):
                mgr.consume_ws_ticket(
                    tk,
                    host_header=_TEST_HOST,
                    origin_header=_TEST_ORIGIN,
                    expected_target_addr=exp_target,
                    expected_incarnation_id=exp_inc,
                    expected_surface_kind=exp_surface,
                    expected_mode=exp_mode,
                )

        # Revoked session invalidates pending WS tickets
        tk_rev = mgr.mint_ws_ticket(
            sid,
            host_header=_TEST_HOST,
            origin_header=_TEST_ORIGIN,
            csrf_token=csrf,
            target_addr=_TEST_TARGET,
            incarnation_id=_TEST_INCARNATION,
            surface_kind=SURFACE_BROWSER,
            mode=MODE_PIP_WALL,
        )
        self.assertTrue(mgr.revoke_session(sid))
        with self.assertRaises(UiAuthDeniedError):
            mgr.consume_ws_ticket(
                tk_rev,
                host_header=_TEST_HOST,
                origin_header=_TEST_ORIGIN,
                expected_target_addr=_TEST_TARGET,
                expected_incarnation_id=_TEST_INCARNATION,
                expected_surface_kind=SURFACE_BROWSER,
                expected_mode=MODE_PIP_WALL,
            )

    def test_bounded_tables_and_expired_eviction(self) -> None:
        clock = _ManualClock(5000.0)
        mgr = self._make_mgr(
            clock, max_pending_codes=2, max_sessions=2, max_pending_ws_tickets=2
        )
        mgr.mint_bootstrap_code()
        mgr.mint_bootstrap_code()
        with self.assertRaises(UiAuthDeniedError):
            mgr.mint_bootstrap_code()

        # Advancing past 60s evicts expired codes cleanly
        clock.advance(61.0)
        sid1, csrf1, _ = self._new_session(mgr)
        self._new_session(mgr)
        extra_code = mgr.mint_bootstrap_code()
        with self.assertRaises(UiAuthDeniedError):
            mgr.exchange_bootstrap_code(extra_code, host_header=_TEST_HOST)

        mgr.mint_ws_ticket(
            sid1,
            host_header=_TEST_HOST,
            origin_header=_TEST_ORIGIN,
            csrf_token=csrf1,
            target_addr=_TEST_TARGET,
            incarnation_id=_TEST_INCARNATION,
            surface_kind=SURFACE_EVENTS,
            mode=MODE_OBSERVE,
        )
        mgr.mint_ws_ticket(
            sid1,
            host_header=_TEST_HOST,
            origin_header=_TEST_ORIGIN,
            csrf_token=csrf1,
            target_addr=_TEST_TARGET,
            incarnation_id=_TEST_INCARNATION,
            surface_kind=SURFACE_EVENTS,
            mode=MODE_OBSERVE,
        )
        with self.assertRaises(UiAuthDeniedError):
            mgr.mint_ws_ticket(
                sid1,
                host_header=_TEST_HOST,
                origin_header=_TEST_ORIGIN,
                csrf_token=csrf1,
                target_addr=_TEST_TARGET,
                incarnation_id=_TEST_INCARNATION,
                surface_kind=SURFACE_EVENTS,
                mode=MODE_OBSERVE,
            )

        self.assertEqual(mgr.revoke_all_sessions(), 2)
        with self.assertRaises(UiAuthDeniedError):
            mgr.validate_session(sid1, host_header=_TEST_HOST)

    def test_cross_authority_host_origin_mismatch_and_host_port_validation(self) -> None:
        clock = _ManualClock(6000.0)
        alt_host = "localhost:47110"
        alt_origin = "http://localhost:47110"

        # Origin authority not in allowed_hosts rejected at init
        with self.assertRaises(UiAuthValidationError):
            UiAuthManager([_TEST_HOST], [alt_origin], clock=clock)
        # Trailing empty colon and leading-zero ports rejected
        for bad_host in ("127.0.0.1:", "[::1]:", "localhost:", "127.0.0.1:047110", "[::1]:080"):
            with self.assertRaises(UiAuthValidationError):
                UiAuthManager([bad_host], [f"http://{bad_host}"], clock=clock)
        # Huge int TTL rejected cleanly without OverflowError
        with self.assertRaises(UiAuthValidationError):
            UiAuthManager([_TEST_HOST], [_TEST_ORIGIN], idle_ttl_s=10**400, clock=clock)

        mgr = UiAuthManager(
            [_TEST_HOST, alt_host],
            [_TEST_ORIGIN, alt_origin],
            clock=clock,
        )
        code = mgr.mint_bootstrap_code()
        with self.assertRaises(UiAuthDeniedError):
            mgr.exchange_bootstrap_code(code, host_header=_TEST_HOST, origin_header=alt_origin)

        sid, csrf, _ = self._new_session(mgr)
        with self.assertRaises(UiAuthDeniedError):
            mgr.verify_http_mutation(
                sid, host_header=_TEST_HOST, origin_header=alt_origin, csrf_token=csrf
            )
        with self.assertRaises(UiAuthDeniedError):
            mgr.mint_ws_ticket(
                sid,
                host_header=_TEST_HOST,
                origin_header=alt_origin,
                csrf_token=csrf,
                target_addr=_TEST_TARGET,
                incarnation_id=_TEST_INCARNATION,
                surface_kind=SURFACE_EVENTS,
                mode=MODE_OBSERVE,
            )
        tk = mgr.mint_ws_ticket(
            sid,
            host_header=_TEST_HOST,
            origin_header=_TEST_ORIGIN,
            csrf_token=csrf,
            target_addr=_TEST_TARGET,
            incarnation_id=_TEST_INCARNATION,
            surface_kind=SURFACE_EVENTS,
            mode=MODE_OBSERVE,
        )
        with self.assertRaises(UiAuthDeniedError):
            mgr.consume_ws_ticket(
                tk,
                host_header=_TEST_HOST,
                origin_header=alt_origin,
                expected_target_addr=_TEST_TARGET,
                expected_incarnation_id=_TEST_INCARNATION,
                expected_surface_kind=SURFACE_EVENTS,
                expected_mode=MODE_OBSERVE,
            )

    def test_ws_ticket_session_pinning_idle_expiry_and_surrogate_revoke(self) -> None:
        clock = _ManualClock(7000.0)
        mgr = self._make_mgr(clock, idle_ttl_s=20.0, absolute_ttl_s=100.0)
        sid_a, csrf_a, hash_a = self._new_session(mgr, actor_id="op_a")
        sid_b, _, _ = self._new_session(mgr, actor_id="op_b")

        # Session B cannot consume Session A's ticket when expected_session_id is pinned
        tk_a = mgr.mint_ws_ticket(
            sid_a,
            host_header=_TEST_HOST,
            origin_header=_TEST_ORIGIN,
            csrf_token=csrf_a,
            target_addr=_TEST_TARGET,
            incarnation_id=_TEST_INCARNATION,
            surface_kind=SURFACE_SHELL,
            mode=MODE_OBSERVE,
        )
        with self.assertRaises(UiAuthDeniedError):
            mgr.consume_ws_ticket(
                tk_a,
                host_header=_TEST_HOST,
                origin_header=_TEST_ORIGIN,
                expected_target_addr=_TEST_TARGET,
                expected_incarnation_id=_TEST_INCARNATION,
                expected_surface_kind=SURFACE_SHELL,
                expected_mode=MODE_OBSERVE,
                expected_session_id=sid_b,
            )

        # Matching expected_session_id succeeds
        tk_ok = mgr.mint_ws_ticket(
            sid_a,
            host_header=_TEST_HOST,
            origin_header=_TEST_ORIGIN,
            csrf_token=csrf_a,
            target_addr=_TEST_TARGET,
            incarnation_id=_TEST_INCARNATION,
            surface_kind=SURFACE_SHELL,
            mode=MODE_OBSERVE,
        )
        scope = mgr.consume_ws_ticket(
            tk_ok,
            host_header=_TEST_HOST,
            origin_header=_TEST_ORIGIN,
            expected_target_addr=_TEST_TARGET,
            expected_incarnation_id=_TEST_INCARNATION,
            expected_surface_kind=SURFACE_SHELL,
            expected_mode=MODE_OBSERVE,
            expected_session_id=sid_a,
        )
        self.assertEqual(scope.session_id_hash, hash_a)

        # Idle-expired session invalidates a still-unexpired (30s) WS ticket
        tk_idle = mgr.mint_ws_ticket(
            sid_a,
            host_header=_TEST_HOST,
            origin_header=_TEST_ORIGIN,
            csrf_token=csrf_a,
            target_addr=_TEST_TARGET,
            incarnation_id=_TEST_INCARNATION,
            surface_kind=SURFACE_EVENTS,
            mode=MODE_OBSERVE,
            ttl_s=30.0,
        )
        clock.advance(21.0)
        with self.assertRaises(UiAuthDeniedError):
            mgr.consume_ws_ticket(
                tk_idle,
                host_header=_TEST_HOST,
                origin_header=_TEST_ORIGIN,
                expected_target_addr=_TEST_TARGET,
                expected_incarnation_id=_TEST_INCARNATION,
                expected_surface_kind=SURFACE_EVENTS,
                expected_mode=MODE_OBSERVE,
            )

        # Unpaired surrogate in revoke_session returns False cleanly
        self.assertFalse(mgr.revoke_session("\ud800"))


if __name__ == "__main__":
    unittest.main()
