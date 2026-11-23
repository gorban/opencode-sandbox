"""Browser URL redaction, TLS/origin classification, image header inspection, and title scrubbing.

Pure Python standard library plus sibling contract imports.
Binary image inspection verifies PNG/JPEG magic bytes, IHDR/SOF dimensions,
pixel ceilings, and SHA-256 provenance digests; full bounded bitstream decoding
before display remains a separate downstream display gate.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import re
import struct
import zlib

from oc_address import has_forbidden_control_or_bidi
from oc_coord_contract import CoordValidationError

from oc_browser_contract import (
    ALLOWED_FRAME_MEDIA_TYPES,
    ALLOWED_URL_SCHEMES,
    MAX_DISPLAY_URL_BYTES,
    MAX_FRAME_BYTES,
    MAX_FRAME_HEIGHT,
    MAX_FRAME_PIXELS,
    MAX_FRAME_WIDTH,
    MAX_JPEG_SEGMENTS,
    MAX_PATH_BYTES,
    MAX_RAW_TITLE_CHARS,
    MAX_RAW_URL_BYTES,
    MAX_TITLE_BYTES,
    MIN_FRAME_BYTES,
    MIN_FRAME_HEIGHT,
    MIN_FRAME_WIDTH,
    ORIGIN_TRUST_EXTERNAL,
    ORIGIN_TRUST_LOOPBACK_HTTP,
    ORIGIN_TRUST_SANDBOX_HTTPS,
    TLS_EVIDENCE_ERROR,
    TLS_EVIDENCE_EXTERNAL_CA,
    TLS_EVIDENCE_SANDBOX_CA,
    TLS_EVIDENCE_UNKNOWN,
    TLS_STATE_ERROR,
    TLS_STATE_EXTERNAL_VERIFIED,
    TLS_STATE_HTTP_UNENCRYPTED,
    TLS_STATE_SANDBOX_CA,
    TLS_STATE_UNKNOWN,
    VALID_TLS_EVIDENCE,
    require_bool,
)

SANDBOX_INTERNAL_DOMAIN = "oc-sandbox.internal"
SANDBOX_INTERNAL_SUFFIX = ".oc-sandbox.internal"
LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "::1", "localhost"})

_NUMERIC_OR_HEX_LABEL_RE = re.compile(r"^(?:0x[\da-f]*|\d+)$", re.ASCII)
_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.ASCII)

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_JPEG_MAGIC = b"\xff\xd8\xff"
_PNG_IHDR_TAG = b"IHDR"
_PNG_LEGAL_COLOR_DEPTHS: dict[int, frozenset[int]] = {
    0: frozenset({1, 2, 4, 8, 16}),
    2: frozenset({8, 16}),
    3: frozenset({1, 2, 4, 8}),
    4: frozenset({8, 16}),
    6: frozenset({8, 16}),
}
_JPEG_SOF_MARKERS: frozenset[int] = frozenset(
    {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
)
_JPEG_VALID_PRECISIONS: frozenset[int] = frozenset({8, 12, 16})

_ESC_STRING_INTROS: frozenset[str] = frozenset({"P", "X", "^", "_"})
_C1_STRING_INTROS: frozenset[int] = frozenset({0x90, 0x98, 0x9E, 0x9F})

_ERR_URL_HOST_INVALID = "url_host_invalid"
_ERR_URL_HOST_NON_CANONICAL = "url_host_non_canonical"
_ERR_URL_PORT_INVALID = "url_port_invalid"
_ERR_URL_SCHEME_REJECTED = "url_scheme_rejected"
_ERR_URL_LENGTH_INVALID = "url_length_invalid"
_ERR_URL_FORBIDDEN_CHARS = "url_forbidden_chars"
_ERR_URL_USERINFO_REJECTED = "url_userinfo_rejected"
_ERR_HTTP_TLS_INVALID = "http_cannot_be_tls_verified"
_ERR_TLS_EVIDENCE_INVALID = "invalid_tls_evidence"
_ERR_FRAME_MIME_UNSUPPORTED = "frame_media_type_unsupported"
_ERR_FRAME_MIME_MISMATCH = "frame_media_type_mismatch"
_ERR_FRAME_SIZE = "frame_size_out_of_bounds"
_ERR_FRAME_DIMS = "frame_dimensions_out_of_bounds"
_ERR_PNG_MALFORMED = "frame_png_malformed"
_ERR_JPEG_MALFORMED = "frame_jpeg_malformed"
_ERR_JPEG_MISSING_SOF = "frame_jpeg_missing_sof"
_UTF8 = "utf-8"
_MEDIA_PNG = "image/png"
_MEDIA_JPEG = "image/jpeg"


@dataclass(frozen=True, slots=True)
class ParsedBrowserUrl:
    """Validated, credential-redacted, and classified browser navigation URL."""

    scheme: str
    origin: str
    path_redacted: str
    path_truncated: bool
    userinfo_redacted: bool
    query_redacted: bool
    fragment_redacted: bool
    tls_state: str
    effective_tls_verified: bool
    origin_trust: str


@dataclass(frozen=True, slots=True)
class InspectedImageHeader:
    """Header-inspected PNG/JPEG dimensions and authoritative SHA-256 digest."""

    media_type: str
    width: int
    height: int
    size_bytes: int
    frame_sha256: str


@dataclass(frozen=True, slots=True)
class ScrubbedTitle:
    """Single-line scrubbed page title result."""

    text: str
    scrubbed: bool
    truncated: bool


def truncate_utf8_clean(text: str, max_bytes: int) -> tuple[str, bool]:
    """Truncate text on a clean UTF-8 character boundary to <= max_bytes."""
    raw = text.encode(_UTF8)
    if len(raw) <= max_bytes:
        return text, False
    lo = 0
    hi = len(text)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if len(text[:mid].encode(_UTF8)) <= max_bytes:
            lo = mid
        else:
            hi = mid - 1
    return text[:lo], True


def _check_raw_url_bytes(raw_url: object) -> str:
    if not isinstance(raw_url, str):
        raise CoordValidationError("url_invalid_type")
    if not raw_url or len(raw_url) > MAX_RAW_URL_BYTES:
        raise CoordValidationError(_ERR_URL_LENGTH_INVALID)
    if has_forbidden_control_or_bidi(raw_url) or any(ch.isspace() for ch in raw_url):
        raise CoordValidationError(_ERR_URL_FORBIDDEN_CHARS)
    try:
        encoded = raw_url.encode(_UTF8)
    except UnicodeEncodeError as exc:
        raise CoordValidationError("url_invalid_utf8") from exc
    if len(encoded) > MAX_RAW_URL_BYTES:
        raise CoordValidationError(_ERR_URL_LENGTH_INVALID)
    return raw_url


def _split_http_https_scheme(raw_url: str) -> tuple[str, str]:
    sep = raw_url.find("://")
    if sep <= 0:
        raise CoordValidationError(_ERR_URL_SCHEME_REJECTED)
    prefix = raw_url[:sep]
    if any(ch in prefix for ch in ("/", "?", "#", ":")):
        raise CoordValidationError(_ERR_URL_SCHEME_REJECTED)
    scheme = prefix.lower()
    if scheme not in ALLOWED_URL_SCHEMES:
        raise CoordValidationError(_ERR_URL_SCHEME_REJECTED)
    return scheme, raw_url[sep + 3 :]


def _strip_after_first(text: str, marker: str) -> tuple[str, bool]:
    idx = text.find(marker)
    if idx < 0:
        return text, False
    return text[:idx], True


def _strip_userinfo(authority: str, *, reject_userinfo: bool) -> tuple[str, bool]:
    if "@" not in authority:
        return authority, False
    if reject_userinfo:
        raise CoordValidationError(_ERR_URL_USERINFO_REJECTED)
    _, hostport = authority.rsplit("@", 1)
    if not hostport:
        raise CoordValidationError(_ERR_URL_HOST_INVALID)
    return hostport, True


def _parse_port(port_str: str, *, scheme: str) -> int | None:
    if (
        not port_str
        or len(port_str) > 5
        or not port_str.isascii()
        or not port_str.isdigit()
        or port_str[0] == "0"
    ):
        raise CoordValidationError(_ERR_URL_PORT_INVALID)
    port = int(port_str)
    if not (1 <= port <= 65535):
        raise CoordValidationError(_ERR_URL_PORT_INVALID)
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return None
    return port


def _parse_ipv6_host_port(hostport: str, *, scheme: str) -> tuple[str, str, int | None]:
    close_idx = hostport.find("]")
    if close_idx <= 1:
        raise CoordValidationError(_ERR_URL_HOST_INVALID)
    inner = hostport[1:close_idx]
    rest = hostport[close_idx + 1 :]
    if not inner.isascii():
        raise CoordValidationError(_ERR_URL_HOST_NON_CANONICAL)
    if "%" in inner:
        raise CoordValidationError(_ERR_URL_HOST_INVALID)
    try:
        ipv6 = ipaddress.IPv6Address(inner)
    except ValueError as exc:
        raise CoordValidationError(_ERR_URL_HOST_INVALID) from exc
    port: int | None = None
    if rest:
        if not rest.startswith(":"):
            raise CoordValidationError(_ERR_URL_HOST_INVALID)
        port = _parse_port(rest[1:], scheme=scheme)
    return ipv6.compressed, "ipv6", port


def _is_ambiguous_numeric_or_hex_host(labels: list[str]) -> bool:
    return _NUMERIC_OR_HEX_LABEL_RE.fullmatch(labels[-1]) is not None or all(
        _NUMERIC_OR_HEX_LABEL_RE.fullmatch(lbl) is not None for lbl in labels
    )


def _is_canonical_ipv4(host: str) -> bool:
    try:
        ipv4 = ipaddress.IPv4Address(host)
    except ValueError:
        return False
    return host == str(ipv4)


def _validate_ascii_dns_or_ipv4(raw_host: str) -> tuple[str, str]:
    if not raw_host:
        raise CoordValidationError(_ERR_URL_HOST_INVALID)
    if not raw_host.isascii():
        raise CoordValidationError(_ERR_URL_HOST_NON_CANONICAL)
    host = raw_host.lower()
    if "%" in host or len(host) > 253:
        raise CoordValidationError(_ERR_URL_HOST_INVALID)
    labels = host.split(".")
    if any(not lbl for lbl in labels):
        raise CoordValidationError(_ERR_URL_HOST_INVALID)
    if _is_canonical_ipv4(host):
        return host, "ipv4"
    if _is_ambiguous_numeric_or_hex_host(labels):
        raise CoordValidationError(_ERR_URL_HOST_INVALID)
    if any(_DNS_LABEL_RE.fullmatch(lbl) is None for lbl in labels):
        raise CoordValidationError(_ERR_URL_HOST_INVALID)
    return host, "dns"


def _parse_strict_host_port(hostport: str, *, scheme: str) -> tuple[str, str, int | None]:
    if hostport.startswith("["):
        return _parse_ipv6_host_port(hostport, scheme=scheme)
    if "]" in hostport:
        raise CoordValidationError(_ERR_URL_HOST_INVALID)
    colon_idx = hostport.find(":")
    if colon_idx >= 0:
        if ":" in hostport[colon_idx + 1 :]:
            raise CoordValidationError(_ERR_URL_HOST_INVALID)
        raw_host = hostport[:colon_idx]
        port = _parse_port(hostport[colon_idx + 1 :], scheme=scheme)
    else:
        raw_host = hostport
        port = None
    ascii_host, host_kind = _validate_ascii_dns_or_ipv4(raw_host)
    return ascii_host, host_kind, port


def _format_origin(scheme: str, ascii_host: str, host_kind: str, port: int | None) -> str:
    host_part = f"[{ascii_host}]" if host_kind == "ipv6" else ascii_host
    port_part = "" if port is None else f":{port}"
    return f"{scheme}://{host_part}{port_part}"


def _validate_https_tls_args(
    *, tls_verified: bool, tls_state_evidence: str | None
) -> None:
    if tls_state_evidence is not None and tls_state_evidence not in VALID_TLS_EVIDENCE:
        raise CoordValidationError(_ERR_TLS_EVIDENCE_INVALID)
    if tls_verified and tls_state_evidence in (TLS_EVIDENCE_ERROR, TLS_EVIDENCE_UNKNOWN):
        raise CoordValidationError(_ERR_TLS_EVIDENCE_INVALID)
    if not tls_verified and tls_state_evidence in (
        TLS_EVIDENCE_SANDBOX_CA,
        TLS_EVIDENCE_EXTERNAL_CA,
    ):
        raise CoordValidationError(_ERR_TLS_EVIDENCE_INVALID)


def _classify_https_tls(
    *,
    ascii_host: str,
    sandbox_instance_name: str,
    tls_verified: bool,
    tls_state_evidence: str | None,
    userinfo_redacted: bool,
) -> tuple[str, bool, str]:
    _validate_https_tls_args(
        tls_verified=tls_verified, tls_state_evidence=tls_state_evidence
    )
    own_host = f"{sandbox_instance_name}{SANDBOX_INTERNAL_SUFFIX}"
    is_own_internal = ascii_host == own_host
    is_internal_ns = ascii_host == SANDBOX_INTERNAL_DOMAIN or ascii_host.endswith(
        SANDBOX_INTERNAL_SUFFIX
    )
    if tls_state_evidence == TLS_EVIDENCE_ERROR:
        return TLS_STATE_ERROR, False, ORIGIN_TRUST_EXTERNAL
    if tls_state_evidence == TLS_EVIDENCE_SANDBOX_CA and is_own_internal:
        trust = ORIGIN_TRUST_EXTERNAL if userinfo_redacted else ORIGIN_TRUST_SANDBOX_HTTPS
        return TLS_STATE_SANDBOX_CA, True, trust
    if tls_state_evidence == TLS_EVIDENCE_EXTERNAL_CA and not is_internal_ns:
        return TLS_STATE_EXTERNAL_VERIFIED, True, ORIGIN_TRUST_EXTERNAL
    return TLS_STATE_UNKNOWN, False, ORIGIN_TRUST_EXTERNAL


def _classify_origin_and_tls(
    *,
    scheme: str,
    ascii_host: str,
    sandbox_instance_name: str,
    tls_verified: bool,
    tls_state_evidence: str | None,
    userinfo_redacted: bool,
) -> tuple[str, bool, str]:
    if scheme == "http":
        if tls_verified or tls_state_evidence is not None:
            raise CoordValidationError(_ERR_HTTP_TLS_INVALID)
        is_loopback = ascii_host in LOOPBACK_HOSTS and not userinfo_redacted
        trust = ORIGIN_TRUST_LOOPBACK_HTTP if is_loopback else ORIGIN_TRUST_EXTERNAL
        return TLS_STATE_HTTP_UNENCRYPTED, False, trust
    return _classify_https_tls(
        ascii_host=ascii_host,
        sandbox_instance_name=sandbox_instance_name,
        tls_verified=tls_verified,
        tls_state_evidence=tls_state_evidence,
        userinfo_redacted=userinfo_redacted,
    )


def parse_and_classify_url(
    raw_url: object,
    *,
    sandbox_instance_name: str,
    tls_verified: bool,
    tls_state_evidence: str | None = None,
    reject_userinfo: bool = False,
) -> ParsedBrowserUrl:
    """Parse, redact, and classify a browser-canonical ASCII HTTP(S) URL."""
    require_bool(tls_verified, "tls_verified")
    require_bool(reject_userinfo, "reject_userinfo")
    clean_raw = _check_raw_url_bytes(raw_url)
    scheme, after_scheme = _split_http_https_scheme(clean_raw)
    before_frag, fragment_redacted = _strip_after_first(after_scheme, "#")
    before_query, query_redacted = _strip_after_first(before_frag, "?")
    if "\\" in before_query:
        raise CoordValidationError("url_backslash_rejected")
    slash_idx = before_query.find("/")
    if slash_idx < 0:
        authority, raw_path = before_query, "/"
    else:
        authority, raw_path = before_query[:slash_idx], before_query[slash_idx:]
    if not authority:
        raise CoordValidationError(_ERR_URL_HOST_INVALID)
    hostport, userinfo_redacted = _strip_userinfo(
        authority, reject_userinfo=reject_userinfo
    )
    ascii_host, host_kind, port = _parse_strict_host_port(hostport, scheme=scheme)
    path_redacted, path_truncated = truncate_utf8_clean(raw_path or "/", MAX_PATH_BYTES)
    origin = _format_origin(scheme, ascii_host, host_kind, port)
    if len(f"{origin}{path_redacted}".encode(_UTF8)) > MAX_DISPLAY_URL_BYTES:
        raise CoordValidationError("display_url_exceeds_limit")
    tls_state, eff_verified, origin_trust = _classify_origin_and_tls(
        scheme=scheme,
        ascii_host=ascii_host,
        sandbox_instance_name=sandbox_instance_name,
        tls_verified=tls_verified,
        tls_state_evidence=tls_state_evidence,
        userinfo_redacted=userinfo_redacted,
    )
    return ParsedBrowserUrl(
        scheme=scheme,
        origin=origin,
        path_redacted=path_redacted,
        path_truncated=path_truncated,
        userinfo_redacted=userinfo_redacted,
        query_redacted=query_redacted,
        fragment_redacted=fragment_redacted,
        tls_state=tls_state,
        effective_tls_verified=eff_verified,
        origin_trust=origin_trust,
    )


def _check_dimensions(width: int, height: int) -> None:
    if not (
        MIN_FRAME_WIDTH <= width <= MAX_FRAME_WIDTH
        and MIN_FRAME_HEIGHT <= height <= MAX_FRAME_HEIGHT
        and width * height <= MAX_FRAME_PIXELS
    ):
        raise CoordValidationError(_ERR_FRAME_DIMS)


def _detect_image_format(raw: bytes) -> str | None:
    if raw.startswith(_PNG_MAGIC):
        return _MEDIA_PNG
    if raw.startswith(_JPEG_MAGIC):
        return _MEDIA_JPEG
    return None


def _validate_png_header(raw: bytes) -> tuple[int, int]:
    if len(raw) < 33:
        raise CoordValidationError(_ERR_PNG_MALFORMED)
    ihdr_len = struct.unpack(">I", raw[8:12])[0]
    if ihdr_len != 13 or raw[12:16] != _PNG_IHDR_TAG:
        raise CoordValidationError(_ERR_PNG_MALFORMED)
    expected_crc = struct.unpack(">I", raw[29:33])[0]
    actual_crc = zlib.crc32(raw[12:29]) & 0xFFFFFFFF
    if actual_crc != expected_crc:
        raise CoordValidationError(_ERR_PNG_MALFORMED)
    width, height = struct.unpack(">II", raw[16:24])
    bit_depth, color_type, compression, filter_method, interlace = raw[24:29]
    allowed_depths = _PNG_LEGAL_COLOR_DEPTHS.get(color_type)
    if (
        allowed_depths is None
        or bit_depth not in allowed_depths
        or compression != 0
        or filter_method != 0
        or interlace not in (0, 1)
    ):
        raise CoordValidationError(_ERR_PNG_MALFORMED)
    _check_dimensions(width, height)
    return width, height


def _parse_jpeg_sof(raw: bytes, pos: int, seg_len: int) -> tuple[int, int]:
    if seg_len < 11:
        raise CoordValidationError(_ERR_JPEG_MALFORMED)
    precision = raw[pos + 2]
    if precision not in _JPEG_VALID_PRECISIONS:
        raise CoordValidationError(_ERR_JPEG_MALFORMED)
    height, width = struct.unpack(">HH", raw[pos + 3 : pos + 7])
    nf = raw[pos + 7]
    if nf < 1 or seg_len != 8 + 3 * nf:
        raise CoordValidationError(_ERR_JPEG_MALFORMED)
    _check_dimensions(width, height)
    return width, height


def _read_next_jpeg_marker(raw: bytes, pos: int) -> tuple[int, int]:
    length = len(raw)
    if pos >= length or raw[pos] != 0xFF:
        raise CoordValidationError(_ERR_JPEG_MALFORMED)
    while pos < length and raw[pos] == 0xFF:
        pos += 1
    if pos >= length:
        raise CoordValidationError(_ERR_JPEG_MALFORMED)
    marker = raw[pos]
    pos += 1
    if marker == 0x00 or marker == 0xD8 or 0xD0 <= marker <= 0xD7:
        raise CoordValidationError(_ERR_JPEG_MALFORMED)
    return marker, pos


def _validate_jpeg_header(raw: bytes) -> tuple[int, int]:
    pos = 2
    length = len(raw)
    for _ in range(MAX_JPEG_SEGMENTS):
        marker, pos = _read_next_jpeg_marker(raw, pos)
        if marker == 0x01:
            continue
        if marker in (0xD9, 0xDA):
            raise CoordValidationError(_ERR_JPEG_MISSING_SOF)
        if pos + 2 > length:
            raise CoordValidationError(_ERR_JPEG_MALFORMED)
        seg_len = struct.unpack(">H", raw[pos : pos + 2])[0]
        if seg_len < 2 or pos + seg_len > length:
            raise CoordValidationError(_ERR_JPEG_MALFORMED)
        if marker in _JPEG_SOF_MARKERS:
            return _parse_jpeg_sof(raw, pos, seg_len)
        pos += seg_len
    raise CoordValidationError(_ERR_JPEG_MISSING_SOF)


def validate_frame_bytes(media_type: object, frame_bytes: object) -> InspectedImageHeader:
    """Inspect PNG/JPEG magic bytes, IHDR/SOF dimensions, and compute authoritative SHA-256."""
    if type(frame_bytes) is not bytes:
        raise CoordValidationError("frame_bytes_must_be_bytes")
    if not (MIN_FRAME_BYTES <= len(frame_bytes) <= MAX_FRAME_BYTES):
        raise CoordValidationError(_ERR_FRAME_SIZE)
    if not isinstance(media_type, str) or media_type not in ALLOWED_FRAME_MEDIA_TYPES:
        raise CoordValidationError(_ERR_FRAME_MIME_UNSUPPORTED)
    detected = _detect_image_format(frame_bytes)
    if detected != media_type:
        raise CoordValidationError(_ERR_FRAME_MIME_MISMATCH)
    if media_type == _MEDIA_PNG:
        width, height = _validate_png_header(frame_bytes)
    else:
        width, height = _validate_jpeg_header(frame_bytes)
    digest = hashlib.sha256(frame_bytes).hexdigest()
    return InspectedImageHeader(
        media_type=media_type,
        width=width,
        height=height,
        size_bytes=len(frame_bytes),
        frame_sha256=digest,
    )


def _consume_csi(text: str, idx: int, end: int) -> int:
    while idx < end:
        code = ord(text[idx])
        if code == 0x1B or 0x80 <= code <= 0x9F:
            return idx
        if 0x40 <= code <= 0x7E:
            return idx + 1
        if 0x20 <= code <= 0x3F:
            idx += 1
            continue
        return idx + 1
    return end


def _consume_string_seq(text: str, idx: int, end: int, *, allow_bel: bool) -> int:
    while idx < end:
        ch = text[idx]
        code = ord(ch)
        if allow_bel and code == 0x07:
            return idx + 1
        if code == 0x9C:
            return idx + 1
        if code == 0x1B and idx + 1 < end and text[idx + 1] == "\\":
            return idx + 2
        idx += 1
    return end


def _consume_esc_seq(text: str, idx: int, end: int) -> int:
    pos = idx + 1
    if pos >= end:
        return end
    nxt = text[pos]
    if nxt == "[":
        return _consume_csi(text, pos + 1, end)
    if nxt == "]":
        return _consume_string_seq(text, pos + 1, end, allow_bel=True)
    if nxt in _ESC_STRING_INTROS:
        return _consume_string_seq(text, pos + 1, end, allow_bel=False)
    code = ord(nxt)
    if 0x20 <= code <= 0x2F:
        while pos < end and 0x20 <= ord(text[pos]) <= 0x2F:
            pos += 1
        if pos < end and 0x30 <= ord(text[pos]) <= 0x7E:
            return pos + 1
        return pos
    if 0x30 <= code <= 0x7E:
        return pos + 1
    return pos


def _consume_c1_seq(text: str, idx: int, end: int) -> int:
    code = ord(text[idx])
    if code == 0x9B:
        return _consume_csi(text, idx + 1, end)
    if code == 0x9D:
        return _consume_string_seq(text, idx + 1, end, allow_bel=True)
    if code in _C1_STRING_INTROS:
        return _consume_string_seq(text, idx + 1, end, allow_bel=False)
    return idx + 1


def _strip_terminal_escapes(text: str) -> tuple[str, bool]:
    out: list[str] = []
    scrubbed = False
    idx = 0
    end = len(text)
    while idx < end:
        code = ord(text[idx])
        if code == 0x1B:
            scrubbed = True
            idx = _consume_esc_seq(text, idx, end)
        elif 0x80 <= code <= 0x9F:
            scrubbed = True
            idx = _consume_c1_seq(text, idx, end)
        else:
            out.append(text[idx])
            idx += 1
    return "".join(out), scrubbed


def _filter_single_line_chars(text: str) -> tuple[str, bool]:
    chars: list[str] = []
    scrubbed = False
    for ch in text:
        if ch.isspace():
            if ch != " ":
                scrubbed = True
            chars.append(" ")
            continue
        if has_forbidden_control_or_bidi(ch):
            scrubbed = True
            continue
        chars.append(ch)
    collapsed = " ".join("".join(chars).split())
    return collapsed, scrubbed


def scrub_page_title(raw_title: object, *, max_bytes: int = MAX_TITLE_BYTES) -> ScrubbedTitle:
    """Scrub untrusted document.title into a safe single-line UTF-8 string <= max_bytes."""
    if not isinstance(raw_title, str):
        raise CoordValidationError("page_title_must_be_string")
    truncated = len(raw_title) > MAX_RAW_TITLE_CHARS
    prefix = raw_title[:MAX_RAW_TITLE_CHARS] if truncated else raw_title
    no_esc, esc_scrubbed = _strip_terminal_escapes(prefix)
    cleaned, char_scrubbed = _filter_single_line_chars(no_esc)
    capped, cap_truncated = truncate_utf8_clean(cleaned, max_bytes)
    return ScrubbedTitle(
        text=capped,
        scrubbed=esc_scrubbed or char_scrubbed or truncated,
        truncated=truncated or cap_truncated,
    )
