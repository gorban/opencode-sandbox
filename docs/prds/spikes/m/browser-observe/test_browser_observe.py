"""Offline qualification & adversarial red-team test suite for PRD M3.4 browser-observe.

Runs completely offline with pure stdlib, programmatic PNG/JPEG fixtures, and
an injectable monotonic clock (zero Podman, zero live Chromium, zero network,
zero host filesystem writes).
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
from pathlib import Path
import struct
import sys
import unittest
import zlib

_BROWSER_DIR = Path(__file__).resolve().parent
_SPIKE_M_DIR = _BROWSER_DIR.parent
for _p in (str(_BROWSER_DIR), str(_SPIKE_M_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from oc_coord_contract import (  # noqa: E402
    CoordAuthError,
    CoordPolicyError,
    CoordRole,
    CoordValidationError,
    IncarnationMismatchError,
    PrincipalCtx,
    RevokedError,
)

from oc_browser_contract import (  # noqa: E402
    BROWSER_OBSERVE_SCHEMA_VERSION,
    BrowserFrameMeta,
    BrowserNavState,
    FrameFreshness,
    MAX_FRAME_BYTES,
    MAX_JPEG_SEGMENTS,
    MAX_SNAPSHOT_RESPONSE_BYTES,
    MAX_SQLITE_INT64,
    MAX_TITLE_BYTES,
    MIN_RESPONSE_BYTES,
    NavClassification,
    OMIT_BUDGET_EXCEEDED,
    ORIGIN_TRUST_EXTERNAL,
    ORIGIN_TRUST_LOOPBACK_HTTP,
    ORIGIN_TRUST_SANDBOX_HTTPS,
    PairedBrowserFrame,
    STALE_AWAITING_FRAME,
    STALE_AWAITING_NAV,
    STALE_CAPTURE_GENERATION,
    STALE_CLOCK_REGRESSION,
    STALE_DISCONNECTED,
    STALE_NAV_GENERATION,
    STALE_NON_MONOTONIC_SEQ,
    STALE_SUPERSEDED_INCARNATION,
    STALE_TTL_EXPIRED,
    STALE_UNKNOWN_NAV,
    SurfaceKey,
    TLS_EVIDENCE_ERROR,
    TLS_EVIDENCE_EXTERNAL_CA,
    TLS_EVIDENCE_SANDBOX_CA,
    TLS_EVIDENCE_UNKNOWN,
    TLS_STATE_ERROR,
    TLS_STATE_EXTERNAL_VERIFIED,
    TLS_STATE_HTTP_UNENCRYPTED,
    TLS_STATE_SANDBOX_CA,
    TLS_STATE_UNKNOWN,
    compute_wall_scope_hash,
    decode_wall_cursor,
    encode_wall_cursor,
    serialize_json_bytes,
)
from oc_browser_store import BrowserObserveService, BrowserProvenanceStore  # noqa: E402
from oc_browser_validate import (  # noqa: E402
    parse_and_classify_url,
    scrub_page_title,
    validate_frame_bytes,
)

_SB_FEAT_A = "feat-a"
_SB_REMOTE_A = "macmini / feat-a"
_INC_1 = "inc:one-001"
_INC_2 = "inc:two-002"
_INC_3 = "inc:three-003"
_SURF_MAIN = "main:tab-1"
_SURF_TWO = "side:tab-2"
_MEDIA_PNG = "image/png"
_MEDIA_JPEG = "image/jpeg"
_MEDIA_WEBP = "image/webp"
_SCHEME_HTTP = "http" + "://"
_SCHEME_HTTPS = "https" + "://"
_URL_INTERNAL_APP = "https://feat-a.oc-sandbox.internal/app"
_URL_INTERNAL_ORIGIN = "https://feat-a.oc-sandbox.internal"
_URL_EXTERNAL_PHISH = f"{_SCHEME_HTTP}external.example/phish"
_URL_EXTERNAL_HTTPS = "https://example.com/page"
_SYNTH_USERINFO = "alice" + ":" + "TOPSECRET"
_URL_CRED_SECRET = (
    f"{_SCHEME_HTTPS}{_SYNTH_USERINFO}@feat-a.oc-sandbox.internal/callback?token=TOK999&a=1#jwt=FRAG777"
)
_SESS_ID = "sess:op-001"


class _FakeClock:
    """Deterministic injectable monotonic clock for offline TTL & barrier tests."""

    def __init__(self, initial: float = 100.0) -> None:
        self.now: float = initial

    def __call__(self) -> float:
        return self.now

    def advance(self, delta_s: float) -> float:
        self.now += delta_s
        return self.now


def _operator() -> PrincipalCtx:
    return PrincipalCtx(role=CoordRole.OPERATOR, actor_id="op-main")


def _make_png(
    width: int = 16,
    height: int = 16,
    *,
    bit_depth: int = 8,
    color_type: int = 2,
    corrupt_crc: bool = False,
    pad_bytes: int = 0,
) -> bytes:
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", width, height, bit_depth, color_type, 0, 0, 0)
    ihdr_body = b"IHDR" + ihdr_data
    crc = zlib.crc32(ihdr_body) & 0xFFFFFFFF
    if corrupt_crc:
        crc ^= 0x12345678
    ihdr = struct.pack(">I", 13) + ihdr_body + struct.pack(">I", crc)
    iend_crc = zlib.crc32(b"IEND") & 0xFFFFFFFF
    iend = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc)
    if pad_bytes > 0:
        extra_body = b"tEXt" + (b"A" * pad_bytes)
        extra_crc = zlib.crc32(extra_body) & 0xFFFFFFFF
        extra = struct.pack(">I", pad_bytes) + extra_body + struct.pack(">I", extra_crc)
        return sig + ihdr + extra + iend
    return sig + ihdr + iend


def _make_jpeg(
    width: int = 32,
    height: int = 24,
    *,
    sof_marker: int = 0xC0,
    include_exif_fake_sof: bool = False,
    nf: int = 3,
    precision: int = 8,
) -> bytes:
    parts = [b"\xff\xd8"]
    app0_payload = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    parts.append(b"\xff\xe0" + struct.pack(">H", len(app0_payload) + 2) + app0_payload)
    if include_exif_fake_sof:
        fake_sof = (
            b"Exif\x00\x00"
            + b"\xff\xc0"
            + struct.pack(">HBHHB", 11, 8, 9999, 9999, 1)
            + b"\x01\x11\x00"
        )
        parts.append(b"\xff\xe1" + struct.pack(">H", len(fake_sof) + 2) + fake_sof)
    comp_bytes = b"".join(bytes([idx + 1, 0x11, 0x00]) for idx in range(nf))
    sof_len = 8 + 3 * nf
    sof = (
        bytes([0xFF, sof_marker])
        + struct.pack(">HBHHB", sof_len, precision, height, width, nf)
        + comp_bytes
    )
    parts.append(sof)
    parts.append(b"\xff\xd9")
    return b"".join(parts)


def _make_webp_bytes() -> bytes:
    vp8l_payload = bytes([0x2F]) + struct.pack("<I", (15 & 0x3FFF) | ((15 & 0x3FFF) << 14))
    chunk = b"VP8L" + struct.pack("<I", len(vp8l_payload)) + vp8l_payload
    riff_size = 4 + len(chunk)
    return b"RIFF" + struct.pack("<I", riff_size) + b"WEBP" + chunk


def _make_store_with_paired_frame(
    clock: _FakeClock,
    *,
    max_frame_age_ms: int = 5_000,
    on_after_pack_before_release: object = None,
    session_validator: object = None,
    live_authority_checker: object = None,
    png_bytes: bytes | None = None,
) -> tuple[BrowserProvenanceStore, bytes]:
    store = BrowserProvenanceStore(
        clock=clock,
        max_frame_age_ms=max_frame_age_ms,
        on_after_pack_before_release=on_after_pack_before_release,  # type: ignore[arg-type]
        session_validator=session_validator,  # type: ignore[arg-type]
        live_authority_checker=live_authority_checker,  # type: ignore[arg-type]
    )
    frame_data = _make_png(64, 48) if png_bytes is None else png_bytes
    store.register_sandbox(_SB_FEAT_A, incarnation_id=_INC_1)
    store.record_navigation(
        _SB_FEAT_A,
        incarnation_id=_INC_1,
        surface_id=_SURF_MAIN,
        capture_generation=1,
        nav_generation=1,
        raw_url=_URL_INTERNAL_APP,
        tls_verified=True,
        tls_state_evidence=TLS_EVIDENCE_SANDBOX_CA,
        page_title="Dashboard",
    )
    res = store.ingest_frame(
        _SB_FEAT_A,
        incarnation_id=_INC_1,
        surface_id=_SURF_MAIN,
        capture_generation=1,
        nav_generation=1,
        frame_seq=1,
        media_type=_MEDIA_PNG,
        frame_bytes=frame_data,
    )
    assert res.accepted is True
    return store, frame_data


class TestProvenancePairingAndFencing(unittest.TestCase):
    """Sections 9.1 & 9.2: anti-spoofing pairing, capture_generation, & lifecycle fencing."""

    def test_frame_after_navigation_spoofing_blocked(self) -> None:
        clock = _FakeClock(100.0)
        store = BrowserObserveService(clock=clock)
        store.register_sandbox(_SB_FEAT_A, incarnation_id=_INC_1)
        png1 = _make_png(20, 20)
        png2 = _make_png(30, 30)

        store.record_navigation(
            _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
            capture_generation=1, nav_generation=1,
            raw_url=_URL_EXTERNAL_PHISH, tls_verified=False, page_title="Phish",
        )
        r1 = store.ingest_frame(
            _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
            capture_generation=1, nav_generation=1, frame_seq=1,
            media_type=_MEDIA_PNG, frame_bytes=png1,
        )
        self.assertTrue(r1.accepted)

        clock.advance(1.0)
        store.record_navigation(
            _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
            capture_generation=1, nav_generation=2,
            raw_url=_URL_INTERNAL_APP, tls_verified=True,
            tls_state_evidence=TLS_EVIDENCE_SANDBOX_CA, page_title="Trusted",
        )
        snap_wait = store.get_surface_snapshot(
            _operator(), target=_SB_FEAT_A, surface_id=_SURF_MAIN, include_frame_b64=True
        )
        self.assertIsNone(snap_wait.paired_frame)
        self.assertTrue(snap_wait.frame_stale)
        self.assertEqual(snap_wait.stale_reason, STALE_AWAITING_FRAME)
        self.assertIsNone(snap_wait.frame_b64)

        delayed = store.ingest_frame(
            _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
            capture_generation=1, nav_generation=1, frame_seq=2,
            media_type=_MEDIA_PNG, frame_bytes=png1,
        )
        self.assertFalse(delayed.accepted)
        self.assertEqual(delayed.stale_reason, STALE_NAV_GENERATION)

        r2 = store.ingest_frame(
            _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
            capture_generation=1, nav_generation=2, frame_seq=2,
            media_type=_MEDIA_PNG, frame_bytes=png2,
        )
        self.assertTrue(r2.accepted)
        assert r2.paired_frame is not None
        self.assertEqual(r2.paired_frame.nav.origin_trust, ORIGIN_TRUST_SANDBOX_HTTPS)
        self.assertEqual(r2.paired_frame.nav.tls_state, TLS_STATE_SANDBOX_CA)
        self.assertTrue(r2.paired_frame.untrusted_content)

        delayed_after = store.ingest_frame(
            _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
            capture_generation=1, nav_generation=1, frame_seq=3,
            media_type=_MEDIA_PNG, frame_bytes=png1,
        )
        self.assertFalse(delayed_after.accepted)
        self.assertEqual(delayed_after.stale_reason, STALE_NAV_GENERATION)

        pre_commit = store.ingest_frame(
            _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
            capture_generation=1, nav_generation=2, frame_seq=3,
            media_type=_MEDIA_PNG, frame_bytes=png2, captured_at=100.5,
        )
        self.assertFalse(pre_commit.accepted)
        self.assertEqual(pre_commit.stale_reason, STALE_NAV_GENERATION)

        snap_ok = store.get_surface_snapshot(
            _operator(), target=_SB_FEAT_A, surface_id=_SURF_MAIN
        )
        self.assertEqual(snap_ok.schema_version, BROWSER_OBSERVE_SCHEMA_VERSION)
        assert snap_ok.paired_frame is not None
        self.assertEqual(snap_ok.paired_frame.frame.frame_seq, 2)
        self.assertEqual(snap_ok.dropped_frame_counts[STALE_NAV_GENERATION], 3)

    def test_future_nav_non_monotonic_seq_and_int64_bounds(self) -> None:
        clock = _FakeClock(100.0)
        store = BrowserProvenanceStore(clock=clock)
        store.register_sandbox(_SB_FEAT_A, incarnation_id=_INC_1)
        png = _make_png()

        before_nav = store.ingest_frame(
            _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
            capture_generation=1, nav_generation=1, frame_seq=1,
            media_type=_MEDIA_PNG, frame_bytes=png,
        )
        self.assertFalse(before_nav.accepted)
        self.assertEqual(before_nav.stale_reason, STALE_UNKNOWN_NAV)

        store.record_navigation(
            _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
            capture_generation=1, nav_generation=1,
            raw_url=_URL_EXTERNAL_PHISH, tls_verified=False,
        )
        future = store.ingest_frame(
            _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
            capture_generation=1, nav_generation=99, frame_seq=1,
            media_type=_MEDIA_PNG, frame_bytes=png,
        )
        self.assertFalse(future.accepted)
        self.assertEqual(future.stale_reason, STALE_UNKNOWN_NAV)

        store.ingest_frame(
            _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
            capture_generation=1, nav_generation=1, frame_seq=5,
            media_type=_MEDIA_PNG, frame_bytes=png,
        )
        replay_eq = store.ingest_frame(
            _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
            capture_generation=1, nav_generation=1, frame_seq=5,
            media_type=_MEDIA_PNG, frame_bytes=png,
        )
        self.assertFalse(replay_eq.accepted)
        self.assertEqual(replay_eq.stale_reason, STALE_NON_MONOTONIC_SEQ)

        replay_lo = store.ingest_frame(
            _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
            capture_generation=1, nav_generation=1, frame_seq=2,
            media_type=_MEDIA_PNG, frame_bytes=png,
        )
        self.assertFalse(replay_lo.accepted)
        self.assertEqual(replay_lo.stale_reason, STALE_NON_MONOTONIC_SEQ)

        for bad_int in (0, -1, True, MAX_SQLITE_INT64 + 1):
            with self.assertRaises(CoordValidationError):
                store.ingest_frame(
                    _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
                    capture_generation=1, nav_generation=1, frame_seq=bad_int,  # type: ignore[arg-type]
                    media_type=_MEDIA_PNG, frame_bytes=png,
                )
        with self.assertRaises(CoordValidationError):
            store.record_navigation(
                _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
                capture_generation=1, nav_generation=1,
                raw_url=_URL_EXTERNAL_PHISH, tls_verified=False,
            )

    def test_incarnation_rotation_and_terminal_revoked(self) -> None:
        clock = _FakeClock(100.0)
        store, png = _make_store_with_paired_frame(clock)
        store.register_sandbox(_SB_FEAT_A, incarnation_id=_INC_2)

        old_frame = store.ingest_frame(
            _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
            capture_generation=1, nav_generation=1, frame_seq=2,
            media_type=_MEDIA_PNG, frame_bytes=png,
        )
        self.assertFalse(old_frame.accepted)
        self.assertEqual(old_frame.stale_reason, STALE_SUPERSEDED_INCARNATION)

        with self.assertRaises(IncarnationMismatchError):
            store.record_navigation(
                _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
                capture_generation=1, nav_generation=2,
                raw_url=_URL_EXTERNAL_PHISH, tls_verified=False,
            )
        with self.assertRaises(IncarnationMismatchError):
            store.set_sandbox_status(_SB_FEAT_A, incarnation_id=_INC_1, status="stopped")
        with self.assertRaises(IncarnationMismatchError):
            store.register_sandbox(_SB_FEAT_A, incarnation_id=_INC_1)
        op = _operator()
        with self.assertRaises(IncarnationMismatchError):
            store.get_surface_snapshot(
                op, target=_SB_FEAT_A, surface_id=_SURF_MAIN, incarnation_id=_INC_1
            )

        store.set_sandbox_status(_SB_FEAT_A, incarnation_id=_INC_2, status="revoked")
        with self.assertRaises(RevokedError):
            store.set_sandbox_status(_SB_FEAT_A, incarnation_id=_INC_2, status="running")
        with self.assertRaises(RevokedError):
            store.register_sandbox(_SB_FEAT_A, incarnation_id=_INC_2, status="running")

        store.register_sandbox(_SB_FEAT_A, incarnation_id=_INC_3, status="running")
        nav3 = store.record_navigation(
            _SB_FEAT_A, incarnation_id=_INC_3, surface_id=_SURF_MAIN,
            capture_generation=1, nav_generation=1,
            raw_url=_URL_EXTERNAL_PHISH, tls_verified=False,
        )
        self.assertEqual(nav3.incarnation_id, _INC_3)

    def test_capture_generation_retirement_blocks_held_pre_stop_frame(self) -> None:
        clock = _FakeClock(100.0)
        store, png = _make_store_with_paired_frame(clock)

        store.set_sandbox_status(_SB_FEAT_A, incarnation_id=_INC_1, status="stopped")
        snap_disc = store.get_surface_snapshot(
            _operator(), target=_SB_FEAT_A, surface_id=_SURF_MAIN, include_frame_b64=True
        )
        self.assertTrue(snap_disc.frame_stale)
        self.assertEqual(snap_disc.stale_reason, STALE_DISCONNECTED)
        self.assertIsNone(snap_disc.nav)
        self.assertIsNone(snap_disc.paired_frame)
        self.assertIsNone(snap_disc.frame_b64)

        store.set_sandbox_status(_SB_FEAT_A, incarnation_id=_INC_1, status="running")
        with self.assertRaises(CoordPolicyError):
            store.ingest_frame(
                _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
                capture_generation=1, nav_generation=1, frame_seq=2,
                media_type=_MEDIA_PNG, frame_bytes=png,
            )
        with self.assertRaises(CoordPolicyError):
            store.record_navigation(
                _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
                capture_generation=1, nav_generation=2,
                raw_url=_URL_INTERNAL_APP, tls_verified=True,
                tls_state_evidence=TLS_EVIDENCE_SANDBOX_CA,
            )

        snap_resumed = store.get_surface_snapshot(
            _operator(), target=_SB_FEAT_A, surface_id=_SURF_MAIN, include_frame_b64=True
        )
        self.assertEqual(snap_resumed.capture_generation, 2)
        self.assertIsNone(snap_resumed.nav)
        self.assertIsNone(snap_resumed.paired_frame)
        self.assertIsNone(snap_resumed.frame_b64)
        self.assertEqual(snap_resumed.stale_reason, STALE_AWAITING_NAV)

        store.record_navigation(
            _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
            capture_generation=2, nav_generation=2,
            raw_url=_URL_INTERNAL_APP, tls_verified=True,
            tls_state_evidence=TLS_EVIDENCE_SANDBOX_CA,
        )
        res2 = store.ingest_frame(
            _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
            capture_generation=2, nav_generation=2, frame_seq=2,
            media_type=_MEDIA_PNG, frame_bytes=png,
        )
        self.assertTrue(res2.accepted)
        snap_live = store.get_surface_snapshot(
            _operator(), target=_SB_FEAT_A, surface_id=_SURF_MAIN, include_frame_b64=True
        )
        self.assertFalse(snap_live.frame_stale)
        self.assertIsNotNone(snap_live.frame_b64)

    def test_capture_generation_max_int64_exhaustion_never_blocks_revoke_or_disable(
        self,
    ) -> None:
        clock = _FakeClock(100.0)
        store, png = _make_store_with_paired_frame(clock)
        # Seed capture_generation to MAX_SQLITE_INT64 to exercise terminal exhaustion.
        sb_rec = store._sandboxes[_SB_FEAT_A]  # noqa: SLF001
        sb_rec.capture_generation = MAX_SQLITE_INT64

        store.register_sandbox(_SB_FEAT_A, incarnation_id=_INC_1, browser_enabled=False)
        self.assertTrue(sb_rec.capture_generation_exhausted)
        self.assertIsNone(sb_rec.surfaces[_SURF_MAIN].current_nav)
        self.assertIsNone(sb_rec.surfaces[_SURF_MAIN].paired_frame)
        self.assertIsNone(sb_rec.surfaces[_SURF_MAIN].paired_frame_bytes)

        # Revocation still succeeds cleanly on an exhausted incarnation.
        store.set_sandbox_status(_SB_FEAT_A, incarnation_id=_INC_1, status="revoked")

        # Separate non-revoked exhausted incarnation verifies resume/nav/frame fail closed.
        store.register_sandbox("feat-b", incarnation_id=_INC_1)
        store._sandboxes["feat-b"].capture_generation = MAX_SQLITE_INT64  # noqa: SLF001
        store.set_sandbox_status("feat-b", incarnation_id=_INC_1, status="stopped")
        with self.assertRaises(RevokedError):
            store.set_sandbox_status("feat-b", incarnation_id=_INC_1, status="running")
        with self.assertRaises(RevokedError):
            store.register_sandbox("feat-b", incarnation_id=_INC_1, status="running")
        with self.assertRaises(RevokedError):
            store.record_navigation(
                "feat-b", incarnation_id=_INC_1, surface_id=_SURF_MAIN,
                capture_generation=MAX_SQLITE_INT64, nav_generation=1,
                raw_url=_URL_EXTERNAL_PHISH, tls_verified=False,
            )
        with self.assertRaises(RevokedError):
            store.ingest_frame(
                "feat-b", incarnation_id=_INC_1, surface_id=_SURF_MAIN,
                capture_generation=MAX_SQLITE_INT64, nav_generation=1, frame_seq=1,
                media_type=_MEDIA_PNG, frame_bytes=png,
            )

        # Rotating to a fresh incarnation resets exhaustion and resumes cleanly.
        store.register_sandbox("feat-b", incarnation_id=_INC_2, status="running")
        nav = store.record_navigation(
            "feat-b", incarnation_id=_INC_2, surface_id=_SURF_MAIN,
            capture_generation=1, nav_generation=1,
            raw_url=_URL_EXTERNAL_PHISH, tls_verified=False,
        )
        self.assertEqual(nav.capture_generation, 1)

    def test_structural_invariants_and_immutable_audit_mapping(self) -> None:
        clock = _FakeClock(100.0)
        store, png = _make_store_with_paired_frame(clock)
        snap = store.get_surface_snapshot(
            _operator(), target=_SB_FEAT_A, surface_id=_SURF_MAIN
        )
        with self.assertRaises(TypeError):
            snap.audit.dropped_frame_counts[STALE_NAV_GENERATION] = 99  # type: ignore[index]

        k1 = SurfaceKey(_SB_FEAT_A, _INC_1, _SURF_MAIN, 1)
        k2 = SurfaceKey(_SB_FEAT_A, _INC_1, _SURF_MAIN, 2)
        nav = BrowserNavState(
            surface_key=k1, nav_generation=1, origin=_URL_INTERNAL_ORIGIN,
            path_redacted="/app", scheme="https", tls_verified=True,
            page_title_clean="OK", committed_at=100.0,
            classification=NavClassification(ORIGIN_TRUST_SANDBOX_HTTPS, TLS_STATE_SANDBOX_CA),
        )
        digest = hashlib.sha256(png).hexdigest()
        meta_same = BrowserFrameMeta(k1, 1, 1, _MEDIA_PNG, 16, 16, len(png), digest, 100.0)
        meta_diff_cap = BrowserFrameMeta(k2, 1, 1, _MEDIA_PNG, 16, 16, len(png), digest, 100.0)
        meta_diff_nav = BrowserFrameMeta(k1, 2, 1, _MEDIA_PNG, 16, 16, len(png), digest, 100.0)

        with self.assertRaises(CoordValidationError):
            PairedBrowserFrame(nav=nav, frame=meta_same, untrusted_content=False)
        with self.assertRaises(CoordValidationError):
            PairedBrowserFrame(nav=nav, frame=meta_diff_cap, untrusted_content=True)
        with self.assertRaises(CoordValidationError):
            PairedBrowserFrame(nav=nav, frame=meta_diff_nav, untrusted_content=True)
        with self.assertRaises(CoordValidationError):
            FrameFreshness(frame_stale=False, stale_reason=STALE_TTL_EXPIRED, frame_age_ms=0)

        # Direct BrowserNavState rejects whitespace/backslash in origin or path_redacted & 10**400.
        cls_ok = NavClassification(ORIGIN_TRUST_SANDBOX_HTTPS, TLS_STATE_SANDBOX_CA)
        for bad_origin in (f"{_URL_INTERNAL_ORIGIN} bad", f"{_URL_INTERNAL_ORIGIN}\\x"):
            with self.assertRaises(CoordValidationError):
                BrowserNavState(
                    k1, 1, bad_origin, "/app", "https", True, "OK", 100.0, cls_ok
                )
        for bad_path in ("/a b", "/a\\b"):
            with self.assertRaises(CoordValidationError):
                BrowserNavState(
                    k1, 1, _URL_INTERNAL_ORIGIN, bad_path, "https", True, "OK", 100.0, cls_ok
                )
        huge_int = 10**400
        with self.assertRaises(CoordValidationError):
            BrowserNavState(
                k1, 1, _URL_INTERNAL_ORIGIN, "/app", "https", True, "OK", huge_int, cls_ok  # type: ignore[arg-type]
            )


class TestClockTtlAndPostPackBarriers(unittest.TestCase):
    """Section 9.3: unrounded TTL, extreme display age, clock anomalies, & post-pack barriers."""

    def test_fractional_ttl_expiry_and_huge_display_age_saturation(self) -> None:
        clock = _FakeClock(100.0)
        store, png = _make_store_with_paired_frame(clock, max_frame_age_ms=5_000)

        clock.now = 104.999
        snap_ok = store.get_surface_snapshot(
            _operator(), target=_SB_FEAT_A, surface_id=_SURF_MAIN, include_frame_b64=True
        )
        self.assertFalse(snap_ok.frame_stale)
        assert snap_ok.frame_age_ms is not None
        self.assertLessEqual(snap_ok.frame_age_ms, 4999)
        assert snap_ok.frame_b64 is not None
        self.assertEqual(base64.b64decode(snap_ok.frame_b64), png)

        # Fractional-ms-over-TTL (5000.5 ms > 5000 ms) must expire cleanly!
        clock.now = 105.0005
        snap_frac = store.get_surface_snapshot(
            _operator(), target=_SB_FEAT_A, surface_id=_SURF_MAIN, include_frame_b64=True
        )
        self.assertTrue(snap_frac.frame_stale)
        self.assertEqual(snap_frac.stale_reason, STALE_TTL_EXPIRED)
        self.assertEqual(snap_frac.frame_age_ms, 5001)
        self.assertIsNone(snap_frac.frame_b64)
        self.assertEqual(snap_frac.frame_b64_omitted_reason, STALE_TTL_EXPIRED)

        clock.now = 105.001
        snap_exp = store.get_surface_snapshot(
            _operator(), target=_SB_FEAT_A, surface_id=_SURF_MAIN, include_frame_b64=True
        )
        self.assertTrue(snap_exp.frame_stale)
        assert snap_exp.frame_age_ms is not None
        self.assertGreaterEqual(snap_exp.frame_age_ms, 5001)

        # Extreme monotonic delta (1e308 s) saturates display age at MAX_SQLITE_INT64 without OverflowError.
        clock.now = 1e308
        snap_huge = store.get_surface_snapshot(
            _operator(), target=_SB_FEAT_A, surface_id=_SURF_MAIN, include_frame_b64=True
        )
        self.assertTrue(snap_huge.frame_stale)
        self.assertEqual(snap_huge.stale_reason, STALE_TTL_EXPIRED)
        self.assertEqual(snap_huge.frame_age_ms, MAX_SQLITE_INT64)
        self.assertGreater(len(snap_huge.to_json_bytes()), 0)

    def test_exact_ieee754_ttl_boundaries_and_big_int_overflow(self) -> None:
        # max_frame_age_ms=140 at exact t=0.14 must stay fresh with frame_age_ms=140
        # (even though 0.14 * 1000.0 == 140.00000000000003 in IEEE-754).
        clock_140 = _FakeClock(0.0)
        store_140, _ = _make_store_with_paired_frame(clock_140, max_frame_age_ms=140)
        clock_140.now = 0.14
        snap_140 = store_140.get_surface_snapshot(
            _operator(), target=_SB_FEAT_A, surface_id=_SURF_MAIN, include_frame_b64=True
        )
        self.assertFalse(snap_140.frame_stale)
        self.assertEqual(snap_140.frame_age_ms, 140)
        self.assertIsNotNone(snap_140.frame_b64)

        # max_frame_age_ms=290 at math.nextafter(0.29, 1.0) must expire with frame_age_ms=291.
        clock_290 = _FakeClock(0.0)
        store_290, png = _make_store_with_paired_frame(clock_290, max_frame_age_ms=290)
        clock_290.now = math.nextafter(0.29, 1.0)
        snap_290 = store_290.get_surface_snapshot(
            _operator(), target=_SB_FEAT_A, surface_id=_SURF_MAIN, include_frame_b64=True
        )
        self.assertTrue(snap_290.frame_stale)
        self.assertEqual(snap_290.stale_reason, STALE_TTL_EXPIRED)
        self.assertEqual(snap_290.frame_age_ms, 291)
        self.assertIsNone(snap_290.frame_b64)

        # 10**400 OverflowError handled fail-closed in committed_at, captured_at, and clock.
        huge_int = 10**400
        with self.assertRaises(CoordValidationError):
            store_290.record_navigation(
                _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
                capture_generation=1, nav_generation=2,
                raw_url=_URL_EXTERNAL_PHISH, tls_verified=False,
                committed_at=huge_int,  # type: ignore[arg-type]
            )
        with self.assertRaises(CoordValidationError):
            store_290.ingest_frame(
                _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
                capture_generation=1, nav_generation=1, frame_seq=2,
                media_type=_MEDIA_PNG, frame_bytes=png,
                captured_at=huge_int,  # type: ignore[arg-type]
            )
        overflow_store = BrowserProvenanceStore(clock=lambda: huge_int)  # type: ignore[arg-type,return-value]
        overflow_store.register_sandbox(_SB_FEAT_A, incarnation_id=_INC_1)
        with self.assertRaises(CoordPolicyError):
            overflow_store.record_navigation(
                _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
                capture_generation=1, nav_generation=1,
                raw_url=_URL_EXTERNAL_PHISH, tls_verified=False,
            )

        # -0.0 normalizes cleanly to +0.0.
        clock_neg0 = _FakeClock(-0.0)
        store_neg0 = BrowserProvenanceStore(clock=clock_neg0)
        store_neg0.register_sandbox(_SB_FEAT_A, incarnation_id=_INC_1)
        nav_neg0 = store_neg0.record_navigation(
            _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
            capture_generation=1, nav_generation=1,
            raw_url=_URL_EXTERNAL_PHISH, tls_verified=False, committed_at=-0.0,
        )
        self.assertEqual(math.copysign(1.0, nav_neg0.committed_at), 1.0)

    def test_clock_regression_future_timestamps_and_broken_clock(self) -> None:
        clock = _FakeClock(100.0)
        store, png = _make_store_with_paired_frame(clock)

        with self.assertRaises(CoordValidationError):
            store.ingest_frame(
                _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
                capture_generation=1, nav_generation=1, frame_seq=2,
                media_type=_MEDIA_PNG, frame_bytes=png, captured_at=101.0,
            )
        with self.assertRaises(CoordValidationError):
            store.record_navigation(
                _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
                capture_generation=1, nav_generation=2,
                raw_url=_URL_EXTERNAL_PHISH, tls_verified=False, committed_at=105.0,
            )

        clock.now = 99.0
        snap_reg = store.get_surface_snapshot(
            _operator(), target=_SB_FEAT_A, surface_id=_SURF_MAIN, include_frame_b64=True
        )
        self.assertTrue(snap_reg.frame_stale)
        self.assertEqual(snap_reg.stale_reason, STALE_CLOCK_REGRESSION)
        self.assertIsNone(snap_reg.frame_b64)

        for bad_val in (float("nan"), float("inf"), -1.0, True):
            broken = BrowserProvenanceStore(clock=lambda _v=bad_val: _v)  # type: ignore[arg-type,return-value]
            broken.register_sandbox(_SB_FEAT_A, incarnation_id=_INC_1)
            with self.assertRaises(CoordPolicyError):
                broken.record_navigation(
                    _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
                    capture_generation=1, nav_generation=1,
                    raw_url=_URL_EXTERNAL_PHISH, tls_verified=False,
                )

    def test_post_pack_barriers_pixel_metadata_budget_and_already_stale(self) -> None:
        # (a) Pixel-bearing across nav commit & fractional TTL expiry
        clock = _FakeClock(100.0)
        hook_fn: list[object] = [None]
        store, _ = _make_store_with_paired_frame(
            clock, max_frame_age_ms=5_000,
            on_after_pack_before_release=lambda: hook_fn[0]() if callable(hook_fn[0]) else None,
        )

        # Mid-pack fractional TTL expiry on pixel-bearing response
        clock.now = 104.999
        hook_fn[0] = lambda: setattr(clock, "now", 105.0005)
        snap_ttl = store.get_surface_snapshot(
            _operator(), target=_SB_FEAT_A, surface_id=_SURF_MAIN, include_frame_b64=True
        )
        self.assertTrue(snap_ttl.frame_stale)
        self.assertEqual(snap_ttl.stale_reason, STALE_TTL_EXPIRED)
        self.assertIsNone(snap_ttl.frame_b64)

        # Mid-pack TTL expiry on metadata-only (include_frame_b64=False)
        clock.now = 104.999
        hook_fn[0] = lambda: setattr(clock, "now", 105.0005)
        snap_meta_ttl = store.get_surface_snapshot(
            _operator(), target=_SB_FEAT_A, surface_id=_SURF_MAIN, include_frame_b64=False
        )
        self.assertTrue(snap_meta_ttl.frame_stale)
        self.assertEqual(snap_meta_ttl.stale_reason, STALE_TTL_EXPIRED)

        # Mid-pack nav commit on budget-omitted pixel response (include_frame_b64=True, 1024 B)
        clock.now = 101.0
        large_png = _make_png(64, 48, pad_bytes=2048)
        store.ingest_frame(
            _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
            capture_generation=1, nav_generation=1, frame_seq=2,
            media_type=_MEDIA_PNG, frame_bytes=large_png,
        )
        hook_fn[0] = lambda: store.record_navigation(
            _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
            capture_generation=1, nav_generation=2,
            raw_url=_URL_EXTERNAL_PHISH, tls_verified=False,
        )
        snap_budget_nav = store.get_surface_snapshot(
            _operator(), target=_SB_FEAT_A, surface_id=_SURF_MAIN,
            include_frame_b64=True, max_response_bytes=MIN_RESPONSE_BYTES,
        )
        self.assertTrue(snap_budget_nav.frame_stale)
        self.assertEqual(snap_budget_nav.stale_reason, STALE_NAV_GENERATION)
        self.assertIsNone(snap_budget_nav.paired_frame)
        self.assertIsNone(snap_budget_nav.frame_b64)
        self.assertLessEqual(len(snap_budget_nav.to_json_bytes()), MIN_RESPONSE_BYTES)

        # Already-stale snapshot carrying nav/paired_frame across mid-pack disable -> resume!
        hook_fn[0] = None
        store.ingest_frame(
            _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
            capture_generation=1, nav_generation=2, frame_seq=3,
            media_type=_MEDIA_PNG, frame_bytes=_make_png(),
        )
        clock.now = 110.0  # already TTL-expired, but nav + paired_frame metadata present

        def _disable_and_resume() -> None:
            store.register_sandbox(_SB_FEAT_A, incarnation_id=_INC_1, browser_enabled=False)
            store.register_sandbox(_SB_FEAT_A, incarnation_id=_INC_1, browser_enabled=True)

        hook_fn[0] = _disable_and_resume
        snap_stale_rot = store.get_surface_snapshot(
            _operator(), target=_SB_FEAT_A, surface_id=_SURF_MAIN, include_frame_b64=False
        )
        self.assertEqual(snap_stale_rot.capture_generation, 2)
        self.assertTrue(snap_stale_rot.frame_stale)
        self.assertEqual(snap_stale_rot.stale_reason, STALE_CAPTURE_GENERATION)
        self.assertIsNone(snap_stale_rot.nav)
        self.assertIsNone(snap_stale_rot.paired_frame)

        # Mid-pack incarnation rotation fails closed with IncarnationMismatchError
        op = _operator()
        hook_fn[0] = lambda: store.register_sandbox(_SB_FEAT_A, incarnation_id=_INC_2)
        with self.assertRaises(IncarnationMismatchError):
            store.get_surface_snapshot(
                op, target=_SB_FEAT_A, surface_id=_SURF_MAIN
            )


class TestUrlRedactionAndTlsClassification(unittest.TestCase):
    """Section 9.4: URL redaction, browser-canonical ASCII host, bare 0x, & TLS/CA matrix."""

    def test_userinfo_query_fragment_redaction_and_surrogate_no_leak(self) -> None:
        parsed = parse_and_classify_url(
            _URL_CRED_SECRET,
            sandbox_instance_name=_SB_FEAT_A,
            tls_verified=True,
            tls_state_evidence=TLS_EVIDENCE_SANDBOX_CA,
        )
        self.assertEqual(parsed.origin, _URL_INTERNAL_ORIGIN)
        self.assertEqual(parsed.path_redacted, "/callback")
        self.assertTrue(parsed.userinfo_redacted)
        self.assertTrue(parsed.query_redacted)
        self.assertTrue(parsed.fragment_redacted)
        self.assertEqual(parsed.tls_state, TLS_STATE_SANDBOX_CA)
        self.assertEqual(parsed.origin_trust, ORIGIN_TRUST_EXTERNAL)

        clock = _FakeClock(100.0)
        store = BrowserProvenanceStore(clock=clock)
        store.register_sandbox(_SB_FEAT_A, incarnation_id=_INC_1)
        store.record_navigation(
            _SB_FEAT_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
            capture_generation=1, nav_generation=1,
            raw_url=_URL_CRED_SECRET, tls_verified=True,
            tls_state_evidence=TLS_EVIDENCE_SANDBOX_CA,
        )
        snap = store.get_surface_snapshot(
            _operator(), target=_SB_FEAT_A, surface_id=_SURF_MAIN
        )
        raw_json = snap.to_json_bytes().decode("utf-8")
        for leaked in ("alice", "TOPSECRET", "TOK999", "FRAG777"):
            self.assertNotIn(leaked, raw_json)
        assert snap.nav is not None
        self.assertNotIn("@", json.dumps(snap.nav.to_dict()))

        surrogate_url = "https://user:SECRET99@example.com/\ud800"
        with self.assertRaises(CoordValidationError) as ctx:
            parse_and_classify_url(
                surrogate_url, sandbox_instance_name=_SB_FEAT_A, tls_verified=False
            )
        self.assertNotIn("SECRET99", str(ctx.exception))

        with self.assertRaises(CoordValidationError) as ctx_u:
            parse_and_classify_url(
                "https://bob:PASS99@example.com/",
                sandbox_instance_name=_SB_FEAT_A,
                tls_verified=False,
                reject_userinfo=True,
            )
        self.assertNotIn("PASS99", str(ctx_u.exception))

    def test_forbidden_schemes_idna_uts46_bare_0x_and_ports(self) -> None:
        bad_urls = (
            "javascript:alert(1)",
            "data:text/html,<b>x</b>",
            "file:///etc/passwd",
            "chrome://settings",
            "chrome-extension://abc/bg.html",
            "about:srcdoc",
            "about:blank",
            "blob:https://example.com/1",
            "devtools://devtools",
            "ftp://example.com/file",
            "//example.com/path",
            "https://straße.example/",
            "https://bücher.example/",
            "https://\uff4c\uff4f\uff43\uff41\uff4c\uff48\uff4f\uff53\uff54/",
            "https://\uff46\uff45\uff41\uff54-a.oc-sandbox.internal/",
            "https://feat-a\u3002oc-sandbox.internal/",
            "https://feat-a\u200b.oc-sandbox.internal/",
            "https://evil.com\\@feat-a.oc-sandbox.internal/",
            "https://0x/",
            "https://foo.0x/",
            f"{_SCHEME_HTTP}2130706433/",
            f"{_SCHEME_HTTP}0x7f000001/",
            f"{_SCHEME_HTTP}0177.0.0.1/",
            f"{_SCHEME_HTTP}127.1/",
            f"{_SCHEME_HTTP}0x7f.0.0.1/",
            f"{_SCHEME_HTTP}[::1%25lo]/",
            "https://feat-a.oc-sandbox.internal:0443/",
            "https://feat-a.oc-sandbox.internal:00000080/",
            "https://feat-a.oc-sandbox.internal:99999/",
        )
        for bad in bad_urls:
            with self.assertRaises(CoordValidationError):
                parse_and_classify_url(
                    bad, sandbox_instance_name=_SB_FEAT_A, tls_verified=False
                )

        # Browser-canonical punycode ASCII labels preserved verbatim without re-encoding.
        for canonical in ("https://xn--strae-oqa.example/p", "https://xn--bcher-kva.example/p"):
            parsed = parse_and_classify_url(
                canonical,
                sandbox_instance_name=_SB_FEAT_A,
                tls_verified=True,
                tls_state_evidence=TLS_EVIDENCE_EXTERNAL_CA,
            )
            self.assertEqual(parsed.origin, canonical[:-2])
            self.assertEqual(parsed.tls_state, TLS_STATE_EXTERNAL_VERIFIED)
            self.assertEqual(parsed.origin_trust, ORIGIN_TRUST_EXTERNAL)

        # Explicit :443 omitted; non-default :8443 preserved.
        p443 = parse_and_classify_url(
            "https://feat-a.oc-sandbox.internal:443/x",
            sandbox_instance_name=_SB_FEAT_A,
            tls_verified=True,
            tls_state_evidence=TLS_EVIDENCE_SANDBOX_CA,
        )
        self.assertEqual(p443.origin, _URL_INTERNAL_ORIGIN)
        self.assertEqual(p443.origin_trust, ORIGIN_TRUST_SANDBOX_HTTPS)

        p8443 = parse_and_classify_url(
            "https://feat-a.oc-sandbox.internal:8443/x",
            sandbox_instance_name=_SB_FEAT_A,
            tls_verified=True,
            tls_state_evidence=TLS_EVIDENCE_SANDBOX_CA,
        )
        self.assertEqual(p8443.origin, "https://feat-a.oc-sandbox.internal:8443")
        self.assertEqual(p8443.origin_trust, ORIGIN_TRUST_SANDBOX_HTTPS)

    def test_complete_tls_ca_and_origin_trust_matrix(self) -> None:
        # Missing CA evidence on HTTPS never fabricates trust even when tls_verified=True.
        no_ev = parse_and_classify_url(
            _URL_INTERNAL_APP,
            sandbox_instance_name=_SB_FEAT_A,
            tls_verified=True,
            tls_state_evidence=None,
        )
        self.assertEqual(no_ev.tls_state, TLS_STATE_UNKNOWN)
        self.assertFalse(no_ev.effective_tls_verified)
        self.assertEqual(no_ev.origin_trust, ORIGIN_TRUST_EXTERNAL)

        # Mismatched sandbox_internal_ca on non-own hosts downgrades to unknown/False.
        for host_url in (
            "https://feat-b.oc-sandbox.internal/",
            "https://sub.feat-a.oc-sandbox.internal/",
            "https://oc-sandbox.internal/",
            "https://localhost/",
            "https://127.0.0.1/",
            _URL_EXTERNAL_HTTPS,
        ):
            res = parse_and_classify_url(
                host_url,
                sandbox_instance_name=_SB_FEAT_A,
                tls_verified=True,
                tls_state_evidence=TLS_EVIDENCE_SANDBOX_CA,
            )
            self.assertEqual(res.tls_state, TLS_STATE_UNKNOWN)
            self.assertFalse(res.effective_tls_verified)
            self.assertEqual(res.origin_trust, ORIGIN_TRUST_EXTERNAL)

        # Mismatched external_ca on any .oc-sandbox.internal host downgrades to unknown/False.
        for int_url in (
            _URL_INTERNAL_APP,
            "https://feat-b.oc-sandbox.internal/",
            "https://sub.feat-a.oc-sandbox.internal/",
            "https://oc-sandbox.internal/",
        ):
            res = parse_and_classify_url(
                int_url,
                sandbox_instance_name=_SB_FEAT_A,
                tls_verified=True,
                tls_state_evidence=TLS_EVIDENCE_EXTERNAL_CA,
            )
            self.assertEqual(res.tls_state, TLS_STATE_UNKNOWN)
            self.assertFalse(res.effective_tls_verified)
            self.assertEqual(res.origin_trust, ORIGIN_TRUST_EXTERNAL)

        # Explicit tls_error
        err_res = parse_and_classify_url(
            _URL_INTERNAL_APP,
            sandbox_instance_name=_SB_FEAT_A,
            tls_verified=False,
            tls_state_evidence=TLS_EVIDENCE_ERROR,
        )
        self.assertEqual(err_res.tls_state, TLS_STATE_ERROR)
        self.assertFalse(err_res.effective_tls_verified)

        # Loopback HTTP vs IPv4-mapped IPv6
        for lb in ("http://127.0.0.1:3000/", "http://[::1]:8080/", "http://localhost:5173/"):
            lb_res = parse_and_classify_url(
                lb, sandbox_instance_name=_SB_FEAT_A, tls_verified=False
            )
            self.assertEqual(lb_res.origin_trust, ORIGIN_TRUST_LOOPBACK_HTTP)
            self.assertEqual(lb_res.tls_state, TLS_STATE_HTTP_UNENCRYPTED)

        mapped = parse_and_classify_url(
            f"{_SCHEME_HTTP}[::ffff:127.0.0.1]/",
            sandbox_instance_name=_SB_FEAT_A,
            tls_verified=False,
        )
        self.assertEqual(mapped.origin_trust, ORIGIN_TRUST_EXTERNAL)

        # Contradictory TLS flags rejected.
        contradictions = (
            ("http://127.0.0.1/", True, None),
            ("http://127.0.0.1/", False, TLS_EVIDENCE_UNKNOWN),
            (_URL_EXTERNAL_HTTPS, True, TLS_EVIDENCE_ERROR),
            (_URL_EXTERNAL_HTTPS, True, TLS_EVIDENCE_UNKNOWN),
            (_URL_EXTERNAL_HTTPS, False, TLS_EVIDENCE_SANDBOX_CA),
            (_URL_EXTERNAL_HTTPS, False, TLS_EVIDENCE_EXTERNAL_CA),
            (_URL_EXTERNAL_HTTPS, True, "bogus_ca"),
        )
        for u, tv, ev in contradictions:
            with self.assertRaises(CoordValidationError):
                parse_and_classify_url(
                    u, sandbox_instance_name=_SB_FEAT_A, tls_verified=tv, tls_state_evidence=ev
                )

        # Remote target ("macmini / feat-a") matches feat-a.oc-sandbox.internal.
        clock = _FakeClock(100.0)
        store = BrowserProvenanceStore(clock=clock)
        store.register_sandbox(_SB_REMOTE_A, incarnation_id=_INC_1)
        nav = store.record_navigation(
            _SB_REMOTE_A, incarnation_id=_INC_1, surface_id=_SURF_MAIN,
            capture_generation=1, nav_generation=1,
            raw_url=_URL_INTERNAL_APP, tls_verified=True,
            tls_state_evidence=TLS_EVIDENCE_SANDBOX_CA,
        )
        self.assertEqual(nav.origin_trust, ORIGIN_TRUST_SANDBOX_HTTPS)


class TestImageHeaderInspectionAndTitleScrubber(unittest.TestCase):
    """Sections 9.5 & 9.6: PNG/JPEG header inspection & title escape/whitespace scrubbing."""

    def test_valid_png_jpeg_and_exif_fake_sof_skipped(self) -> None:
        for color_type, bit_depth in ((0, 1), (2, 8), (3, 4), (4, 16), (6, 8)):
            png = _make_png(128, 96, bit_depth=bit_depth, color_type=color_type)
            hdr = validate_frame_bytes(_MEDIA_PNG, png)
            self.assertEqual((hdr.width, hdr.height), (128, 96))
            self.assertEqual(hdr.frame_sha256, hashlib.sha256(png).hexdigest())

        jpg = _make_jpeg(320, 240, sof_marker=0xC2, include_exif_fake_sof=True)
        jhdr = validate_frame_bytes(_MEDIA_JPEG, jpg)
        self.assertEqual((jhdr.width, jhdr.height), (320, 240))
        self.assertEqual(jhdr.frame_sha256, hashlib.sha256(jpg).hexdigest())

    def test_webp_svg_mime_mismatch_bombs_and_truncated_jpeg_rejected(self) -> None:
        png = _make_png()
        jpg = _make_jpeg()
        webp = _make_webp_bytes()
        svg = b"<svg xmlns='http://www.w3.org/2000/svg'></svg>"

        bad_cases: tuple[tuple[object, object], ...] = (
            (_MEDIA_WEBP, webp),
            ("image/svg+xml", svg),
            ("image/gif", b"GIF89a" + b"\x00" * 20),
            (_MEDIA_JPEG, png),
            (_MEDIA_PNG, jpg),
            (_MEDIA_PNG, svg),
            (_MEDIA_PNG, bytearray(png)),
            (_MEDIA_PNG, "not-bytes"),
            (_MEDIA_PNG, b"\x89PNG\r\n\x1a\n" + b"\x00" * 4),
            (_MEDIA_PNG, _make_png(pad_bytes=MAX_FRAME_BYTES)),
            (_MEDIA_PNG, _make_png(0, 10)),
            (_MEDIA_PNG, _make_png(65535, 65535)),
            (_MEDIA_PNG, _make_png(4096, 4096)),
            (_MEDIA_PNG, _make_png(16, 16, corrupt_crc=True)),
            (_MEDIA_PNG, _make_png(16, 16, bit_depth=16, color_type=3)),
            # Truncated JPEG markers: trailing 0xFF, <2 bytes for seg_len, mid-SOF
            (_MEDIA_JPEG, b"\xff\xd8" + b"\xff" * 20),
            (_MEDIA_JPEG, b"\xff\xd8\xff\xe0\x00\x04AB\xff\xe1\x00"),
            (_MEDIA_JPEG, b"\xff\xd8\xff\xe0\x00\x04AB\xff\xc0\x00\x11\x08\x00"),
            # Non-0xFF alignment, 0x00 / 0xD8 / 0xD0 before SOF, bad SOF seg_len != 8+3*nf
            (_MEDIA_JPEG, b"\xff\xd8\xff\xe0\x00\x04AB\x12\x34" + b"\x00" * 10),
            (_MEDIA_JPEG, b"\xff\xd8\xff\x00" + b"\x00" * 16),
            (_MEDIA_JPEG, b"\xff\xd8\xff\xd8" + b"\x00" * 16),
            (_MEDIA_JPEG, b"\xff\xd8\xff\xd0" + b"\x00" * 16),
            (_MEDIA_JPEG, b"\xff\xd8\xff\xc0" + struct.pack(">HBHHB", 12, 8, 16, 16, 1) + b"\x01\x11\x00\x00"),
            # Exceeding MAX_JPEG_SEGMENTS
            (_MEDIA_JPEG, b"\xff\xd8" + (b"\xff\xfe\x00\x02" * (MAX_JPEG_SEGMENTS + 2)) + b"\xff\xd9"),
        )
        for mime, payload in bad_cases:
            with self.assertRaises(CoordValidationError):
                validate_frame_bytes(mime, payload)

    def test_title_scrubber_escapes_unicode_whitespace_and_truncation(self) -> None:
        hostile = (
            "\x1b[31mRed\x1b[0m \x1b]52;c;AAAA\x07\x1b]0;spoof\x9c"
            "\x1b(0Box \x1b[31\x1b]52;c;AAAA\x07Safe \x1bP1$r\x1b\\"
            "\x9b2J\x9d0;c1\x07A\x00B\u202eC\ud800D\r\nE\tF\vG\fH\u00a0I\u2028J\u2029K"
        )
        res = scrub_page_title(hostile)
        self.assertTrue(res.scrubbed)
        self.assertEqual(res.text, "Red Box Safe ABCD E F G H I J K")

        long_utf8 = "日本語タイトル" * 100
        res_long = scrub_page_title(long_utf8)
        self.assertTrue(res_long.truncated)
        self.assertLessEqual(len(res_long.text.encode("utf-8")), MAX_TITLE_BYTES)


class _TwoPhaseGate:
    """Test helper allowing pre-read to succeed and post-read to fail cleanly."""

    def __init__(self) -> None:
        self.calls = 0
        self.allow_second = True

    def reset(self, *, allow_second: bool) -> None:
        self.calls = 0
        self.allow_second = allow_second

    def check_session(self, caller: PrincipalCtx, sid: str, gen: int) -> bool:
        self.calls += 1
        if self.calls == 2:
            return self.allow_second
        return sid == _SESS_ID and gen == 1

    def check_live(self, caller: PrincipalCtx) -> bool:
        self.calls += 1
        if self.calls == 2:
            return self.allow_second
        return True


class TestOperatorAuthBudgetAndCursor(unittest.TestCase):
    """Sections 9.7 & 9.8: operator-only auth, pre/post fencing, 1 KiB budget, & cursor codec."""

    def test_operator_only_admission_and_target_wrapping(self) -> None:
        clock = _FakeClock(100.0)
        store, _ = _make_store_with_paired_frame(clock)
        op = _operator()

        bad_callers = (
            PrincipalCtx(CoordRole.JOB, "job-1", _SB_FEAT_A, _INC_1),
            PrincipalCtx(CoordRole.ORCHESTRATOR, "orch-root"),
            PrincipalCtx(CoordRole.ORCHESTRATOR, "orch-sub", _SB_FEAT_A, _INC_1),
            PrincipalCtx(CoordRole.EXTERNAL_PEER, "peer-1"),
            PrincipalCtx(CoordRole.OPERATOR, "op-bound", _SB_FEAT_A, None),
        )
        for bad_c in bad_callers:
            with self.assertRaises(CoordAuthError):
                store.get_surface_snapshot(bad_c, target=_SB_FEAT_A, surface_id=_SURF_MAIN)
        with self.assertRaises(CoordValidationError):
            store.get_surface_snapshot("not-principal", target=_SB_FEAT_A)  # type: ignore[arg-type]

        # @PEER and invalid targets wrap AddressError -> CoordValidationError.
        for bad_target in ("@peer-a", "bad/slash", "feat\x00a"):
            with self.assertRaises(CoordValidationError):
                store.get_surface_snapshot(op, target=bad_target)

        # browser_enabled=False sandbox raises browser_service_not_enabled and omitted from wall.
        plain_store = BrowserProvenanceStore(clock=clock)
        plain_store.register_sandbox("no-browser", incarnation_id=_INC_1, browser_enabled=False)
        with self.assertRaises(CoordPolicyError):
            plain_store.get_surface_snapshot(op, target="no-browser")
        wall_empty = plain_store.list_browser_wall(op)
        self.assertEqual(wall_empty.tiles, ())

    def test_pre_post_session_and_authority_fencing(self) -> None:
        clock = _FakeClock(100.0)
        sess_gate = _TwoPhaseGate()
        live_gate = _TwoPhaseGate()
        op = _operator()
        store, _ = _make_store_with_paired_frame(
            clock,
            session_validator=sess_gate.check_session,
            live_authority_checker=live_gate.check_live,
        )

        # Missing/partial session args & non-bool flags
        with self.assertRaises(CoordAuthError):
            store.get_surface_snapshot(op, target=_SB_FEAT_A, surface_id=_SURF_MAIN)
        with self.assertRaises(CoordValidationError):
            store.get_surface_snapshot(
                op, target=_SB_FEAT_A, surface_id=_SURF_MAIN, read_session_id=_SESS_ID
            )
        with self.assertRaises(CoordValidationError):
            store.get_surface_snapshot(
                op, target=_SB_FEAT_A, surface_id=_SURF_MAIN,
                include_frame_b64=1,  # type: ignore[arg-type]
                read_session_id=_SESS_ID, session_generation=1,
            )

        # Mid-read session revocation raises RevokedError with zero data.
        sess_gate.reset(allow_second=False)
        live_gate.reset(allow_second=True)
        with self.assertRaises(RevokedError):
            store.get_surface_snapshot(
                op, target=_SB_FEAT_A, surface_id=_SURF_MAIN,
                read_session_id=_SESS_ID, session_generation=1,
            )

        # Mid-read live authority revocation raises RevokedError with zero data.
        sess_gate.reset(allow_second=True)
        live_gate.reset(allow_second=False)
        with self.assertRaises(RevokedError):
            store.list_browser_wall(
                op, read_session_id=_SESS_ID, session_generation=1
            )

    def test_1kib_budget_atomic_shrink_pagination_and_cursor_tampering(self) -> None:
        clock = _FakeClock(100.0)
        store = BrowserProvenanceStore(clock=clock)
        big_png = _make_png(64, 48, pad_bytes=2048)
        escape_title = ('"quote\\slash" 日本語 ' * 20).strip()
        long_path = "/seg/" + ("a" * 200)

        for sb in (_SB_FEAT_A, _SB_REMOTE_A):
            store.register_sandbox(sb, incarnation_id=_INC_1)
            for sid in (_SURF_MAIN, _SURF_TWO):
                store.record_navigation(
                    sb, incarnation_id=_INC_1, surface_id=sid,
                    capture_generation=1, nav_generation=1,
                    raw_url=f"{_URL_INTERNAL_ORIGIN}{long_path}",
                    tls_verified=True, tls_state_evidence=TLS_EVIDENCE_SANDBOX_CA,
                    page_title=escape_title,
                )
                store.ingest_frame(
                    sb, incarnation_id=_INC_1, surface_id=sid,
                    capture_generation=1, nav_generation=1, frame_seq=1,
                    media_type=_MEDIA_PNG, frame_bytes=big_png,
                )

        # 1 KiB snapshot omits frame_b64, shrinks nav atomically with paired_frame, preserves '/'.
        snap_1k = store.get_surface_snapshot(
            _operator(), target=_SB_FEAT_A, surface_id=_SURF_MAIN,
            include_frame_b64=True, max_response_bytes=MIN_RESPONSE_BYTES,
        )
        self.assertLessEqual(len(snap_1k.to_json_bytes()), MIN_RESPONSE_BYTES)
        self.assertIsNone(snap_1k.frame_b64)
        self.assertEqual(snap_1k.frame_b64_omitted_reason, OMIT_BUDGET_EXCEEDED)
        self.assertIsNotNone(snap_1k.nav)
        self.assertIsNotNone(snap_1k.paired_frame)
        assert snap_1k.nav is not None
        assert snap_1k.paired_frame is not None
        self.assertEqual(snap_1k.nav, snap_1k.paired_frame.nav)
        self.assertTrue(snap_1k.nav.path_redacted.startswith("/"))

        # 768 KiB snapshot includes exact frame_b64 matching frame_sha256.
        snap_full = store.get_surface_snapshot(
            _operator(), target=_SB_FEAT_A, surface_id=_SURF_MAIN,
            include_frame_b64=True, max_response_bytes=MAX_SNAPSHOT_RESPONSE_BYTES,
        )
        assert snap_full.frame_b64 is not None
        self.assertEqual(base64.b64decode(snap_full.frame_b64), big_png)

        # Paginate all 4 tiles under 1 KiB cap with limit=1 and zero skips/duplicates.
        seen: list[tuple[str, str]] = []
        cursor: str | None = None
        while True:
            page = store.list_browser_wall(
                _operator(), after_cursor=cursor, limit=1,
                max_response_bytes=MIN_RESPONSE_BYTES,
            )
            raw_page = page.to_json_bytes()
            self.assertLessEqual(len(raw_page), MIN_RESPONSE_BYTES)
            self.assertNotIn(b"frame_b64", raw_page)
            for tile in page.tiles:
                seen.append((tile.sandbox_addr, tile.surface_id))
                assert tile.nav is not None
                self.assertTrue(tile.nav.path_redacted.startswith("/"))
            if not page.has_more:
                self.assertIsNone(page.next_cursor)
                break
            cursor = page.next_cursor
        self.assertEqual(
            seen,
            [
                (_SB_FEAT_A, _SURF_MAIN),
                (_SB_FEAT_A, _SURF_TWO),
                (_SB_REMOTE_A, _SURF_MAIN),
                (_SB_REMOTE_A, _SURF_TWO),
            ],
        )

        # Cursor scope mismatch & tampering rejections.
        scope_false = compute_wall_scope_hash(include_disconnected=False)
        scope_true = compute_wall_scope_hash(include_disconnected=True)
        good_cursor = encode_wall_cursor(
            scope_hash=scope_false, sandbox_addr=_SB_FEAT_A, surface_id=_SURF_MAIN
        )
        with self.assertRaises(CoordValidationError):
            decode_wall_cursor(good_cursor, expected_scope_hash=scope_true)

        def _b64(raw: bytes) -> str:
            return "v1." + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

        tampered_cursors = (
            f"{good_cursor}=",
            "v2.abc",
            "v1." + ("A" * 520),
            _b64(b'{"addr":"feat-a","fh":"' + scope_false.encode() + b'","op":"wrong","sid":"main"}'),
            _b64(b'{"addr":"feat-a","extra":1,"fh":"' + scope_false.encode() + b'","op":"browser_wall","sid":"main"}'),
            _b64(b'{"addr":"feat-a","fh":NaN,"op":"browser_wall","sid":"main"}'),
            _b64((b"[" * 120) + (b"]" * 120)),
            _b64(b'{"addr":"@peer","fh":"' + scope_false.encode() + b'","op":"browser_wall","sid":"main"}'),
        )
        for bad_c in tampered_cursors:
            with self.assertRaises(CoordValidationError):
                decode_wall_cursor(bad_c, expected_scope_hash=scope_false)

        # allow_nan=False enforced in serializer.
        nan_obj = {"bad": float("nan")}
        inf_obj = {"bad": float("inf")}
        with self.assertRaises(CoordValidationError):
            serialize_json_bytes(nan_obj)
        with self.assertRaises(CoordValidationError):
            serialize_json_bytes(inf_obj)


if __name__ == "__main__":
    unittest.main()
