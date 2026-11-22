"""Unified Host L7 HTTP Policy Reverse Proxy for PRD L1 (Path A).

Pure Python standard library only. Enforces:
- Bounded TCP loopback or 0o700 UDS listener (semaphore, read/write/total timeouts)
- Strict HTTP/1.1 framing (rejects CL+TE, duplicate CL, inbound TE, obs-fold,
  pipelining, and HTTP Upgrade / 101 Switching Protocols)
- Per-job BrokerLease verification and <1s stream revocation
- Per-route inbound_auth (bearer, basic-token, header, aws-sigv4-job-key)
- Strict path/query splitting, canonicalization, and segment-bounded glob matching
- Pluggable body policies: mcp-jsonrpc (with JSON+SSE tools/list filtering),
  graphql-query-only (pure-stdlib lexer & AST parser), and aws-sigv4
- Connect-time DNS-pinned IP validation & TLS SNI dialing
- Hard follow_redirects=False (502 on 3xx), Accept-Encoding: identity,
  safe response header allowlist, 4xx/5xx scrubbing, and OverlapCanaryScanner
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from fnmatch import fnmatchcase
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import struct
import threading
import time
from typing import Any
from urllib.parse import parse_qsl, quote, unquote, urlsplit

from oc_broker_common import (
    BrokerAuthError,
    BrokerLease,
    BrokerPolicyError,
    CanaryLeakError,
    HostVaultMemory,
    OverlapCanaryScanner,
    connect_tls_pinned_ip,
    resolve_and_validate_ip,
    validate_allowed_cidrs,
)

MAX_CONCURRENT_CONNS = 16
READ_TIMEOUT_SECONDS = 5.0
WRITE_TIMEOUT_SECONDS = 5.0
TOTAL_REQUEST_TIMEOUT_SECONDS = 15.0
MAX_HEADER_BYTES = 16_384
MAX_BODY_BYTES = 1_048_576
MAX_JSON_DEPTH = 32
MAX_GQL_TOKENS = 8_192
MAX_GQL_DEPTH = 64
MAX_SIGV4_CLOCK_SKEW_SECONDS = 300
MAX_CHUNK_LINE_BYTES = 1_024

_UMASK_LOCK = threading.Lock()

CLOSED_MCP_WIRE_METHODS = frozenset(
    {
        "initialize",
        "notifications/initialized",
        "ping",
        "tools/list",
        "tools/call",
    }
)
ALLOWED_MCP_KEYS = frozenset({"jsonrpc", "id", "method", "params"})
ALLOWED_GQL_KEYS = frozenset({"query", "variables", "operationName"})

DEFAULT_DENIED_AWS_ACTIONS = frozenset(
    {
        "secretsmanager:*",
        "ssm:GetParameter*",
        "iam:*",
        "sts:AssumeRole",
    }
)

HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)

IGNORED_INBOUND_HEADERS = frozenset(
    {
        "host",
        "forwarded",
        "x-original-url",
        "x-rewrite-url",
        "x-http-method-override",
        "x-http-method",
        "x-method-override",
        "accept-encoding",
        "content-length",
        "expect",
        "authorization",
        "proxy-authorization",
        "cookie",
        "x-auth-token",
        "x-access-token",
    }
)

_AWS_PRESIGN_QUERY_KEYS = frozenset(
    {"x-amz-signature", "x-amz-credential", "x-amz-security-token"}
)
_AWS_AUTH_HEADERS = frozenset(
    {"x-amz-date", "x-amz-security-token", "x-amz-content-sha256"}
)

SAFE_RESPONSE_HEADERS = frozenset(
    {
        "content-type",
        "content-length",
        "cache-control",
        "etag",
        "x-request-id",
        "mcp-session-id",
    }
)

VALID_INBOUND_AUTH = frozenset({"bearer", "basic-token", "header", "aws-sigv4-job-key"})
VALID_UPSTREAM_AUTH = frozenset({"bearer", "basic-token", "header", "aws-sigv4", "none"})
VALID_BODY_POLICIES = frozenset({"none", "mcp-jsonrpc", "graphql-query-only", "aws-sigv4"})

_HTTP_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_HTTP_METHOD_RE = re.compile(r"^[A-Z]+$")
_CHUNK_SIZE_RE = re.compile(rb"^[0-9A-Fa-f]{1,8}$")
_GQL_NUM_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_GQL_NAME_RE = re.compile(r"[_A-Za-z][_0-9A-Za-z]*")
_AMZ_TARGET_PART_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_GQL_SIMPLE_ESCAPES = frozenset('"\\/bfnrt')
_FORBIDDEN_PCT_BYTES = frozenset({0x2E, 0x2F, 0x5C, 0x3B, 0x3F, 0x23, 0x25, 0x7F})

_HTTP_REASONS: dict[int, str] = {
    200: "OK",
    201: "Created",
    202: "Accepted",
    204: "No Content",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    413: "Payload Too Large",
    415: "Unsupported Media Type",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}


class HttpFramingError(ValueError):
    """Strict HTTP/1.1 framing violation."""


class StrictJsonError(ValueError):
    """Strict JSON decode violation."""


class GraphQLParseError(ValueError):
    """Strict GraphQL syntax or policy violation."""


class HttpErrorResponse(Exception):
    """Structured HTTP error to serialize directly back to the sandbox client."""

    def __init__(self, status: int, code: str, message: str = ""):
        super().__init__(code)
        self.status = status
        self.code = code
        self.message = message or code


@dataclass(frozen=True, slots=True)
class AllowRule:
    methods: tuple[str, ...]
    path_patterns: tuple[str, ...]
    body_policy: str = "none"


@dataclass(frozen=True, slots=True)
class WirePolicy:
    denied_paths: tuple[str, ...] = ()
    allow_rules: tuple[AllowRule, ...] = ()
    allowed_tools: frozenset[str] = frozenset()
    allowed_aws_actions: frozenset[str] = frozenset()
    denied_aws_actions: frozenset[str] = DEFAULT_DENIED_AWS_ACTIONS


@dataclass(frozen=True, slots=True)
class HttpBrokerRoute:
    route_id: str
    route_prefix: str
    upstream_url: str
    secret_ref: str
    wire_policy: WirePolicy
    inbound_auth: str = "bearer"
    inbound_auth_header: str | None = None
    upstream_auth_mode: str = "bearer"
    upstream_auth_header: str = "Authorization"
    allow_streaming: bool = False
    allowed_cidrs: tuple[str, ...] = ()
    credential_delivery: str = "host-brokered"
    aws_region: str = "us-east-1"
    aws_service: str = "sts"
    aws_access_key_ref: str | None = None
    aws_secret_key_ref: str | None = None
    aws_session_token_ref: str | None = None
    pair_distinct_secret_ref: str | None = None


@dataclass(slots=True)
class ParsedHttpRequest:
    method: str
    target: str
    headers: list[tuple[str, str, str]]  # (lower_name, orig_name, value)
    body: bytes
    connection_tokens: frozenset[str]


@dataclass(slots=True)
class ParsedUpstreamHead:
    status: int
    reason: str
    headers: list[tuple[str, str, str]]
    connection_tokens: frozenset[str]
    rest: bytes


@dataclass(frozen=True, slots=True)
class _ParsedUpstreamUrl:
    host: str
    port: int
    base_path: str


# ---------------------------------------------------------------------------
# Preset Route-Policy Builders
# ---------------------------------------------------------------------------


def build_concourse_ro_route(
    name: str,
    upstream_url: str,
    secret_ref: str,
    *,
    allowed_cidrs: tuple[str, ...] = (),
    pair_distinct_secret_ref: str | None = None,
) -> HttpBrokerRoute:
    """Default read-only Concourse CI (fly) route with /hijack denied and /events SSE."""
    policy = WirePolicy(
        denied_paths=("/api/v1/teams/*/containers/*/hijack*",),
        allow_rules=(
            AllowRule(
                methods=("GET", "HEAD"),
                path_patterns=(
                    "/api/v1/info",
                    "/api/v1/teams/*/pipelines*",
                    "/api/v1/teams/*/pipelines/*/jobs*",
                    "/api/v1/builds*",
                    "/api/v1/builds/*/events",
                    "/api/v1/teams/*/builds*",
                    "/api/v1/teams/*/builds/*/events",
                ),
                body_policy="none",
            ),
        ),
    )
    return HttpBrokerRoute(
        route_id=f"http:{name}",
        route_prefix=f"/http/{name}",
        upstream_url=upstream_url,
        secret_ref=secret_ref,
        wire_policy=policy,
        inbound_auth="bearer",
        upstream_auth_mode="bearer",
        allow_streaming=True,
        allowed_cidrs=allowed_cidrs,
        pair_distinct_secret_ref=pair_distinct_secret_ref,
    )


def build_k8s_ro_route(
    name: str,
    upstream_url: str,
    secret_ref: str,
    *,
    allowed_cidrs: tuple[str, ...] = (),
    pair_distinct_secret_ref: str | None = None,
) -> HttpBrokerRoute:
    """Default read-only Kubernetes (kubectl) route with secrets/exec/attach/proxy denied."""
    policy = WirePolicy(
        denied_paths=(
            "/api/v1/secrets*",
            "/api/v1/namespaces/*/secrets*",
            "/api/v1/namespaces/*/pods/*/exec*",
            "/api/v1/namespaces/*/pods/*/attach*",
            "/api/v1/namespaces/*/pods/*/portforward*",
            "/api/v1/namespaces/*/pods/*/proxy*",
            "/api/v1/namespaces/*/services/*/proxy*",
        ),
        allow_rules=(
            AllowRule(
                methods=("GET", "HEAD"),
                path_patterns=(
                    "/version",
                    "/api",
                    "/apis",
                    "/api/v1/namespaces/*/pods*",
                    "/api/v1/namespaces/*/pods/*",
                    "/api/v1/namespaces/*/pods/*/log",
                    "/api/v1/namespaces/*/events*",
                    "/api/v1/namespaces/*/services*",
                    "/api/v1/namespaces/*/services/*",
                    "/apis/apps/v1/namespaces/*/deployments*",
                    "/apis/apps/v1/namespaces/*/deployments/*",
                ),
                body_policy="none",
            ),
        ),
    )
    return HttpBrokerRoute(
        route_id=f"http:{name}",
        route_prefix=f"/http/{name}",
        upstream_url=upstream_url,
        secret_ref=secret_ref,
        wire_policy=policy,
        inbound_auth="bearer",
        upstream_auth_mode="bearer",
        allow_streaming=False,
        allowed_cidrs=allowed_cidrs,
        pair_distinct_secret_ref=pair_distinct_secret_ref,
    )


def build_sonarqube_ro_route(
    name: str,
    upstream_url: str,
    secret_ref: str,
    *,
    allowed_cidrs: tuple[str, ...] = (),
    pair_distinct_secret_ref: str | None = None,
) -> HttpBrokerRoute:
    """Default read-only SonarQube route using basic-token auth."""
    policy = WirePolicy(
        allow_rules=(
            AllowRule(
                methods=("GET", "HEAD"),
                path_patterns=(
                    "/api/qualitygates/*",
                    "/api/issues/search",
                    "/api/measures/component*",
                    "/api/hotspots/search",
                ),
                body_policy="none",
            ),
        ),
    )
    return HttpBrokerRoute(
        route_id=f"http:{name}",
        route_prefix=f"/http/{name}",
        upstream_url=upstream_url,
        secret_ref=secret_ref,
        wire_policy=policy,
        inbound_auth="basic-token",
        upstream_auth_mode="basic-token",
        allow_streaming=False,
        allowed_cidrs=allowed_cidrs,
        pair_distinct_secret_ref=pair_distinct_secret_ref,
    )


def build_github_ro_route(
    name: str,
    upstream_url: str,
    secret_ref: str,
    *,
    allowed_cidrs: tuple[str, ...] = (),
    pair_distinct_secret_ref: str | None = None,
) -> HttpBrokerRoute:
    """Default read-only GitHub route: GET REST + POST /graphql query-only AST."""
    policy = WirePolicy(
        allow_rules=(
            AllowRule(
                methods=("GET", "HEAD"),
                path_patterns=(
                    "/repos/*/*",
                    "/repos/*/*/pulls*",
                    "/repos/*/*/pulls/*",
                    "/repos/*/*/issues*",
                    "/repos/*/*/issues/*",
                    "/repos/*/*/commits*",
                    "/repos/*/*/commits/*",
                ),
                body_policy="none",
            ),
            AllowRule(
                methods=("POST",),
                path_patterns=("/graphql",),
                body_policy="graphql-query-only",
            ),
        ),
    )
    return HttpBrokerRoute(
        route_id=f"http:{name}",
        route_prefix=f"/http/{name}",
        upstream_url=upstream_url,
        secret_ref=secret_ref,
        wire_policy=policy,
        inbound_auth="bearer",
        upstream_auth_mode="bearer",
        allow_streaming=False,
        allowed_cidrs=allowed_cidrs,
        pair_distinct_secret_ref=pair_distinct_secret_ref,
    )


def build_remote_mcp_route(
    name: str,
    upstream_url: str,
    secret_ref: str,
    allowed_tools: Sequence[str] | frozenset[str],
    *,
    allow_streaming: bool = False,
    allowed_cidrs: tuple[str, ...] = (),
    pair_distinct_secret_ref: str | None = None,
) -> HttpBrokerRoute:
    """Default Remote MCP route enforcing closed JSON-RPC 2.0 methods & tool allowlist."""
    rules: list[AllowRule] = [
        AllowRule(methods=("POST",), path_patterns=("/",), body_policy="mcp-jsonrpc")
    ]
    if allow_streaming:
        rules.append(AllowRule(methods=("GET",), path_patterns=("/",), body_policy="none"))
    policy = WirePolicy(
        allow_rules=tuple(rules),
        allowed_tools=frozenset(allowed_tools),
    )
    return HttpBrokerRoute(
        route_id=f"mcp:{name}",
        route_prefix=f"/mcp/{name}",
        upstream_url=upstream_url,
        secret_ref=secret_ref,
        wire_policy=policy,
        inbound_auth="bearer",
        upstream_auth_mode="bearer",
        allow_streaming=allow_streaming,
        allowed_cidrs=allowed_cidrs,
        pair_distinct_secret_ref=pair_distinct_secret_ref,
    )


def build_aws_ro_route(
    service: str,
    upstream_url: str,
    aws_access_key_ref: str,
    aws_secret_key_ref: str,
    allowed_aws_actions: Sequence[str] | frozenset[str],
    *,
    aws_region: str = "us-east-1",
    aws_session_token_ref: str | None = None,
    denied_aws_actions: frozenset[str] = DEFAULT_DENIED_AWS_ACTIONS,
    allowed_cidrs: tuple[str, ...] = (),
    pair_distinct_secret_ref: str | None = None,
) -> HttpBrokerRoute:
    """Default read-only AWS SigV4 route verifying job-key auth and re-signing on host."""
    policy = WirePolicy(
        allow_rules=(
            AllowRule(
                methods=("GET", "HEAD", "POST"),
                path_patterns=("/", "/*", "/*/*", "/*/*/*"),
                body_policy="aws-sigv4",
            ),
        ),
        allowed_aws_actions=frozenset(allowed_aws_actions),
        denied_aws_actions=denied_aws_actions,
    )
    return HttpBrokerRoute(
        route_id=f"aws:{service}",
        route_prefix=f"/aws/{service}",
        upstream_url=upstream_url,
        secret_ref=aws_secret_key_ref,
        wire_policy=policy,
        inbound_auth="aws-sigv4-job-key",
        upstream_auth_mode="aws-sigv4",
        allow_streaming=False,
        allowed_cidrs=allowed_cidrs,
        aws_region=aws_region,
        aws_service=service,
        aws_access_key_ref=aws_access_key_ref,
        aws_secret_key_ref=aws_secret_key_ref,
        aws_session_token_ref=aws_session_token_ref,
        pair_distinct_secret_ref=pair_distinct_secret_ref,
    )


# ---------------------------------------------------------------------------
# Route Validation & Upstream URL Parsing
# ---------------------------------------------------------------------------


def _parse_upstream_url(url: str) -> _ParsedUpstreamUrl:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise BrokerPolicyError(f"Upstream URL must use https with a valid host: {url!r}")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise BrokerPolicyError(f"Upstream URL must not contain userinfo, query, or fragment: {url!r}")
    port = parts.port or 443
    if not (1 <= port <= 65535):
        raise BrokerPolicyError(f"Invalid upstream port in URL: {url!r}")
    return _ParsedUpstreamUrl(host=parts.hostname.lower(), port=port, base_path=parts.path or "")


def _validate_route_auth_fields(route: HttpBrokerRoute) -> None:
    if route.inbound_auth not in VALID_INBOUND_AUTH:
        raise BrokerPolicyError(f"Unsupported inbound_auth: {route.inbound_auth!r}")
    if route.inbound_auth == "header":
        if not route.inbound_auth_header or not _HTTP_TOKEN_RE.match(route.inbound_auth_header):
            raise BrokerPolicyError(f"Route {route.route_id!r} requires valid inbound_auth_header")
    if route.upstream_auth_mode not in VALID_UPSTREAM_AUTH:
        raise BrokerPolicyError(f"Unsupported upstream_auth_mode: {route.upstream_auth_mode!r}")
    if route.upstream_auth_header and not _HTTP_TOKEN_RE.match(route.upstream_auth_header):
        raise BrokerPolicyError(f"Invalid upstream_auth_header: {route.upstream_auth_header!r}")
    if route.upstream_auth_mode == "aws-sigv4":
        if not route.aws_access_key_ref or not route.aws_secret_key_ref:
            raise BrokerPolicyError(f"AWS SigV4 route {route.route_id!r} requires access/secret refs")


def _validate_route_policy_patterns(route: HttpBrokerRoute) -> None:
    for pat in route.wire_policy.denied_paths:
        if not pat.startswith("/"):
            raise BrokerPolicyError(f"denied_paths pattern must start with '/': {pat!r}")
    for rule in route.wire_policy.allow_rules:
        if rule.body_policy not in VALID_BODY_POLICIES:
            raise BrokerPolicyError(f"Unsupported body_policy: {rule.body_policy!r}")
        for pat in rule.path_patterns:
            if not pat.startswith("/"):
                raise BrokerPolicyError(f"allow_rules pattern must start with '/': {pat!r}")


def _validate_single_route(route: HttpBrokerRoute, vault: HostVaultMemory) -> None:
    if not route.route_prefix.startswith("/") or "//" in route.route_prefix:
        raise BrokerPolicyError(f"Invalid route_prefix: {route.route_prefix!r}")
    if route.route_prefix != "/" and route.route_prefix.endswith("/"):
        raise BrokerPolicyError(f"route_prefix must not end with '/': {route.route_prefix!r}")
    _validate_route_auth_fields(route)
    _parse_upstream_url(route.upstream_url)
    if route.allowed_cidrs:
        validate_allowed_cidrs(route.allowed_cidrs, context=f"route:{route.route_id}")
    _validate_route_policy_patterns(route)
    if route.pair_distinct_secret_ref is not None:
        vault.assert_distinct_refs(
            route.secret_ref,
            route.pair_distinct_secret_ref,
            label=f"route:{route.route_id}",
        )


def validate_route_table(
    routes: Sequence[HttpBrokerRoute], vault: HostVaultMemory
) -> dict[str, HttpBrokerRoute]:
    """Validate routes and enforce startup RO/RW secret distinctness checks."""
    by_prefix: dict[str, HttpBrokerRoute] = {}
    seen_ids: set[str] = set()
    for route in routes:
        if route.route_id in seen_ids:
            raise BrokerPolicyError(f"Duplicate route_id: {route.route_id!r}")
        if route.route_prefix in by_prefix:
            raise BrokerPolicyError(f"Duplicate route_prefix: {route.route_prefix!r}")
        _validate_single_route(route, vault)
        seen_ids.add(route.route_id)
        by_prefix[route.route_prefix] = route
    return by_prefix


# ---------------------------------------------------------------------------
# Strict JSON Helpers
# ---------------------------------------------------------------------------


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise StrictJsonError(f"Duplicate JSON key: {k!r}")
        out[k] = v
    return out


def _reject_constants(val: str) -> Any:
    raise StrictJsonError(f"Non-standard JSON constant rejected: {val}")


def _check_depth_and_surrogates(obj: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise StrictJsonError(f"JSON nesting depth exceeds {MAX_JSON_DEPTH}")
    if isinstance(obj, str):
        try:
            obj.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise StrictJsonError("Unpaired UTF-16 surrogate rejected") from exc
    elif isinstance(obj, list):
        for item in obj:
            _check_depth_and_surrogates(item, depth + 1)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            _check_depth_and_surrogates(k, depth + 1)
            _check_depth_and_surrogates(v, depth + 1)


def parse_strict_json_object(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise StrictJsonError("Invalid UTF-8 payload") from exc
    try:
        data = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constants,
        )
    except StrictJsonError:
        raise
    except Exception as exc:
        raise StrictJsonError(f"Invalid JSON: {exc}") from exc
    _check_depth_and_surrogates(data, 0)
    if not isinstance(data, dict):
        raise StrictJsonError("JSON payload must be a JSON object")
    return data


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------------------
# Path Canonicalization, Route Matching & Segment-Bounded Glob
# ---------------------------------------------------------------------------


def _validate_percent_escapes(raw_path: str) -> None:
    idx = raw_path.find("%")
    while idx != -1:
        if idx + 2 >= len(raw_path):
            raise HttpErrorResponse(400, "malformed_percent_encoding")
        hex_part = raw_path[idx + 1 : idx + 3]
        if hex_part[0] not in _HEX_DIGITS or hex_part[1] not in _HEX_DIGITS:
            raise HttpErrorResponse(400, "malformed_percent_encoding")
        val = int(hex_part, 16)
        if val <= 0x1F or val in _FORBIDDEN_PCT_BYTES:
            raise HttpErrorResponse(400, "forbidden_encoded_path_char")
        idx = raw_path.find("%", idx + 3)


def _validate_raw_query(raw_query: str) -> None:
    for ch in raw_query:
        code = ord(ch)
        if code <= 0x20 or code >= 0x7F or ch in ("#", "\\"):
            raise HttpErrorResponse(400, "invalid_query_char")


def _canonicalize_path(raw_path: str) -> str:
    if ";" in raw_path:
        raise HttpErrorResponse(400, "semicolon_in_path_rejected")
    _validate_percent_escapes(raw_path)
    try:
        decoded = unquote(raw_path, errors="strict")
    except UnicodeDecodeError as exc:
        raise HttpErrorResponse(400, "invalid_utf8_path") from exc
    for ch in decoded:
        code = ord(ch)
        if code <= 0x20 or code == 0x7F or ch in ("#", "\\", ";", "%"):
            raise HttpErrorResponse(400, "forbidden_decoded_path_char")
    if "//" in decoded or (decoded != "/" and decoded.endswith("/")):
        raise HttpErrorResponse(400, "empty_path_segment_rejected")
    for seg in decoded.split("/")[1:]:
        if seg in (".", ".."):
            raise HttpErrorResponse(400, "dot_segment_rejected")
    return decoded


def split_and_canonicalize_target(raw_target: str) -> tuple[str, str]:
    """Split target into (canonical_path, raw_query) FIRST and reject unsafe encodings/segments."""
    if not raw_target.startswith("/"):
        raise HttpErrorResponse(400, "target_must_be_origin_form")
    for ch in raw_target:
        code = ord(ch)
        if code <= 0x20 or code >= 0x7F or ch in ("#", "\\"):
            raise HttpErrorResponse(400, "invalid_target_char")
    raw_path, has_q, raw_query = raw_target.partition("?")
    if has_q:
        _validate_raw_query(raw_query)
    canon_path = _canonicalize_path(raw_path)
    return canon_path, raw_query


def match_route_prefix(
    raw_path: str, routes_by_prefix: dict[str, HttpBrokerRoute]
) -> tuple[HttpBrokerRoute | None, str]:
    """Match longest route prefix and compute normalized rel_path starting with '/'."""
    best: HttpBrokerRoute | None = None
    best_len = -1
    for prefix, route in routes_by_prefix.items():
        matched = (prefix == "/" and raw_path.startswith("/")) or raw_path == prefix or raw_path.startswith(prefix + "/")
        if matched and len(prefix) > best_len:
            best = route
            best_len = len(prefix)
    if best is None:
        return None, ""
    if best.route_prefix == "/":
        return best, raw_path
    rel_path = "/" if raw_path == best.route_prefix else raw_path[len(best.route_prefix) :]
    return best, rel_path


def _segment_matches(segment: str, pattern_segment: str) -> bool:
    if "*" not in pattern_segment:
        return segment == pattern_segment
    parts = [re.escape(p) for p in pattern_segment.split("*")]
    regex = "^" + "[^/]*".join(parts) + "$"
    return re.match(regex, segment) is not None


def match_segment_glob(path: str, pattern: str) -> bool:
    """Segment-bounded glob match where '*' matches within a single segment only."""
    if path == "/" and pattern == "/":
        return True
    if path == "/" or pattern == "/":
        return False
    path_segs = path[1:].split("/")
    pat_segs = pattern[1:].split("/")
    if "" in path_segs or len(path_segs) != len(pat_segs):
        return False
    return all(_segment_matches(s, p) for s, p in zip(path_segs, pat_segs))


def matches_segment_glob_any(path: str, patterns: Sequence[str]) -> bool:
    return any(match_segment_glob(path, pat) for pat in patterns)


def first_matching_allow_rule(
    method: str, rel_path: str, allow_rules: Sequence[AllowRule]
) -> AllowRule | None:
    for rule in allow_rules:
        if method in rule.methods and matches_segment_glob_any(rel_path, rule.path_patterns):
            return rule
    return None


def join_upstream_path(base_path: str, rel_path: str) -> str:
    """Join upstream base_path and rel_path cleanly without mangling exact base paths."""
    base = base_path or ""
    if rel_path == "/":
        return base if base else "/"
    return base.rstrip("/") + rel_path


# ---------------------------------------------------------------------------
# Strict HTTP/1.1 Framing Parser (Request & Upstream Response)
# ---------------------------------------------------------------------------


def _recv_with_deadline(
    conn: socket.socket, limit: int, deadline: float, read_timeout: float
) -> bytes:
    rem = deadline - time.monotonic()
    if rem <= 0:
        raise HttpFramingError("request_deadline_exceeded")
    conn.settimeout(min(read_timeout, rem))
    try:
        return conn.recv(limit)
    except TimeoutError as exc:
        raise HttpFramingError("socket_read_timeout") from exc
    except OSError as exc:
        raise HttpFramingError("socket_read_error") from exc


def _read_header_block(
    conn: socket.socket, deadline: float, read_timeout: float, max_headers: int
) -> tuple[bytes, bytes]:
    buf = bytearray()
    while True:
        idx = buf.find(b"\r\n\r\n")
        if idx != -1:
            if idx > max_headers:
                raise HttpFramingError("headers_too_large")
            return bytes(buf[:idx]), bytes(buf[idx + 4 :])
        if len(buf) > max_headers:
            raise HttpFramingError("headers_too_large")
        chunk = _recv_with_deadline(conn, 4096, deadline, read_timeout)
        if not chunk:
            raise HttpFramingError("unexpected_eof_in_headers")
        buf.extend(chunk)


def _parse_single_header(line: str) -> tuple[str, str, str]:
    if not line or line[0] in (" ", "\t"):
        raise HttpFramingError("obs_fold_rejected")
    if ":" not in line:
        raise HttpFramingError("malformed_header_line")
    name, value = line.split(":", 1)
    if not _HTTP_TOKEN_RE.match(name):
        raise HttpFramingError("invalid_header_name")
    val_clean = value.strip(" \t")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in val_clean):
        raise HttpFramingError("control_char_in_header_value")
    return name.lower(), name, val_clean


def _extract_connection_tokens(headers: list[tuple[str, str, str]]) -> frozenset[str]:
    tokens: set[str] = set()
    for lname, _oname, val in headers:
        if lname == "connection":
            for part in val.split(","):
                tok = part.strip().lower()
                if tok:
                    tokens.add(tok)
    return frozenset(tokens)


def _validate_request_headers(
    header_lines: list[str], max_body: int
) -> tuple[list[tuple[str, str, str]], int, frozenset[str]]:
    headers: list[tuple[str, str, str]] = []
    cl_values: list[str] = []
    for line in header_lines:
        lname, oname, val = _parse_single_header(line)
        if lname == "transfer-encoding":
            raise HttpFramingError("transfer_encoding_rejected")
        if lname == "upgrade":
            raise HttpFramingError("upgrade_rejected")
        if lname == "content-length":
            cl_values.append(val)
        headers.append((lname, oname, val))

    conn_tokens = _extract_connection_tokens(headers)
    if "upgrade" in conn_tokens:
        raise HttpFramingError("upgrade_rejected")
    if len(cl_values) > 1:
        raise HttpFramingError("duplicate_content_length")
    content_length = _parse_cl_value(cl_values[0], max_body) if cl_values else 0
    return headers, content_length, conn_tokens


def _parse_cl_value(raw_cl: str, max_body: int) -> int:
    if not (raw_cl.isascii() and raw_cl.isdigit()):
        raise HttpFramingError("invalid_content_length")
    cl = int(raw_cl)
    if cl > max_body:
        raise HttpErrorResponse(413, "body_too_large")
    return cl


def _reject_pipelined_bytes(conn: socket.socket, read_timeout: float) -> None:
    conn.setblocking(False)
    try:
        extra = conn.recv(1, socket.MSG_PEEK)
        if extra:
            raise HttpFramingError("pipelined_bytes_rejected")
    except OSError:
        pass
    finally:
        conn.settimeout(read_timeout)


def _read_exact_body(
    conn: socket.socket,
    rest: bytes,
    content_length: int,
    deadline: float,
    read_timeout: float,
) -> bytes:
    if len(rest) > content_length:
        raise HttpFramingError("pipelined_bytes_rejected")
    body = bytearray(rest)
    while len(body) < content_length:
        need = min(16_384, content_length - len(body) + 1)
        chunk = _recv_with_deadline(conn, need, deadline, read_timeout)
        if not chunk:
            raise HttpFramingError("unexpected_eof_in_body")
        body.extend(chunk)
        if len(body) > content_length:
            raise HttpFramingError("pipelined_bytes_rejected")
    _reject_pipelined_bytes(conn, read_timeout)
    return bytes(body)


def parse_strict_http11_request(
    conn: socket.socket,
    *,
    max_headers: int = MAX_HEADER_BYTES,
    max_body: int = MAX_BODY_BYTES,
    read_timeout: float = READ_TIMEOUT_SECONDS,
    total_timeout: float = TOTAL_REQUEST_TIMEOUT_SECONDS,
) -> ParsedHttpRequest:
    """Parse one strict HTTP/1.1 request; reject smuggling, obs-fold, Upgrade, pipelining."""
    deadline = time.monotonic() + total_timeout
    header_bytes, rest = _read_header_block(conn, deadline, read_timeout, max_headers)
    try:
        header_text = header_bytes.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise HttpFramingError("non_ascii_headers") from exc
    lines = header_text.split("\r\n")
    if any("\n" in ln or "\r" in ln for ln in lines):
        raise HttpFramingError("bare_cr_or_lf_rejected")
    req_parts = lines[0].split(" ")
    if len(req_parts) != 3 or req_parts[2] != "HTTP/1.1" or not _HTTP_METHOD_RE.match(req_parts[0]):
        raise HttpFramingError("malformed_request_line")
    headers, content_length, conn_tokens = _validate_request_headers(lines[1:], max_body)
    body = _read_exact_body(conn, rest, content_length, deadline, read_timeout)
    return ParsedHttpRequest(
        method=req_parts[0],
        target=req_parts[1],
        headers=headers,
        body=body,
        connection_tokens=conn_tokens,
    )


# ---------------------------------------------------------------------------
# AWS SigV4 Helpers (Job-Key Derivation, Inbound Verification & Host Signing)
# ---------------------------------------------------------------------------


def derive_job_aws_credentials(ocjob_token: str) -> tuple[str, str]:
    """Derive deterministic disposable AWS access/secret keys from ocjob_token."""
    access_key = "OCJOB" + hashlib.sha256(ocjob_token.encode("utf-8")).hexdigest()[:16].upper()
    secret_key = hashlib.sha256(f"sigv4:{ocjob_token}".encode("utf-8")).hexdigest()
    return access_key, secret_key


def _sigv4_hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _sigv4_signing_key(secret_key: str, date_stamp: str, region: str, service: str) -> bytes:
    k_date = _sigv4_hmac(f"AWS4{secret_key}".encode("utf-8"), date_stamp)
    k_region = _sigv4_hmac(k_date, region)
    k_service = _sigv4_hmac(k_region, service)
    return _sigv4_hmac(k_service, "aws4_request")


def _sigv4_canonical_query(raw_query: str) -> str:
    if not raw_query:
        return ""
    pairs = parse_qsl(raw_query, keep_blank_values=True)
    encoded = [(quote(k, safe="-_.~"), quote(v, safe="-_.~")) for k, v in pairs]
    encoded.sort()
    return "&".join(f"{k}={v}" for k, v in encoded)


def _sigv4_canonical_uri(raw_path: str) -> str:
    if not raw_path:
        return "/"
    return "/".join(quote(seg, safe="-_.~") for seg in raw_path.split("/"))


def _compute_sigv4_signature(
    *,
    method: str,
    raw_path: str,
    raw_query: str,
    headers_map: dict[str, str],
    signed_headers: Sequence[str],
    payload_hash: str,
    amz_date: str,
    region: str,
    service: str,
    secret_key: str,
) -> str:
    canon_headers = "".join(f"{h}:{headers_map[h].strip()}\n" for h in signed_headers)
    signed_str = ";".join(signed_headers)
    canon_req = "\n".join(
        [
            method,
            _sigv4_canonical_uri(raw_path),
            _sigv4_canonical_query(raw_query),
            canon_headers,
            signed_str,
            payload_hash,
        ]
    )
    date_stamp = amz_date[:8]
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            scope,
            hashlib.sha256(canon_req.encode("utf-8")).hexdigest(),
        ]
    )
    signing_key = _sigv4_signing_key(secret_key, date_stamp, region, service)
    return hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()


def sign_aws_sigv4(
    *,
    method: str,
    raw_path: str,
    raw_query: str,
    host_header: str,
    body: bytes,
    access_key: str,
    secret_key: str,
    region: str,
    service: str,
    session_token: str | None = None,
    extra_headers: dict[str, str] | None = None,
    now_ts: float | None = None,
) -> dict[str, str]:
    """Sign an HTTP request with AWS SigV4 HMAC-SHA256 and return auth headers to attach."""
    dt = datetime.fromtimestamp(time.time() if now_ts is None else now_ts, tz=timezone.utc)
    amz_date = dt.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = amz_date[:8]
    payload_hash = hashlib.sha256(body).hexdigest()

    sign_map: dict[str, str] = {
        "host": host_header,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_date,
    }
    if session_token:
        sign_map["x-amz-security-token"] = session_token
    if extra_headers:
        for k, v in extra_headers.items():
            sign_map[k.lower()] = v.strip()

    signed_headers = sorted(sign_map.keys())
    signature = _compute_sigv4_signature(
        method=method,
        raw_path=raw_path,
        raw_query=raw_query,
        headers_map=sign_map,
        signed_headers=signed_headers,
        payload_hash=payload_hash,
        amz_date=amz_date,
        region=region,
        service=service,
        secret_key=secret_key,
    )
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    auth_val = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
        f"SignedHeaders={';'.join(signed_headers)}, Signature={signature}"
    )
    out = {
        "X-Amz-Date": amz_date,
        "X-Amz-Content-Sha256": payload_hash,
        "Authorization": auth_val,
    }
    if session_token:
        out["X-Amz-Security-Token"] = session_token
    return out


def _parse_sigv4_auth_header(auth_header: str) -> tuple[list[str], list[str], str] | None:
    if not auth_header.startswith("AWS4-HMAC-SHA256 "):
        return None
    fields: dict[str, str] = {}
    for part in auth_header[len("AWS4-HMAC-SHA256 ") :].split(","):
        if "=" not in part:
            return None
        k, v = part.strip().split("=", 1)
        fields[k] = v
    cred = fields.get("Credential", "").split("/")
    signed = fields.get("SignedHeaders", "").split(";")
    sig = fields.get("Signature", "")
    if len(cred) != 5 or cred[4] != "aws4_request" or not sig:
        return None
    return cred, signed, sig


def _check_sigv4_clock_skew(amz_date: str, expected_date: str, now_ts: float) -> bool:
    if len(amz_date) != 16 or amz_date[:8] != expected_date:
        return False
    try:
        req_dt = datetime.strptime(amz_date, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return abs(now_ts - req_dt.timestamp()) <= MAX_SIGV4_CLOCK_SKEW_SECONDS


def _header_values(headers: list[tuple[str, str, str]], target_lower: str) -> list[str]:
    return [v for ln, _on, v in headers if ln == target_lower]


def _single_header(headers: list[tuple[str, str, str]], target_lower: str) -> str | None:
    vals = _header_values(headers, target_lower)
    return vals[0] if len(vals) == 1 else None


def _has_aws_presign_query_params(raw_query: str) -> bool:
    if not raw_query:
        return False
    return any(k.lower() in _AWS_PRESIGN_QUERY_KEYS for k, _v in parse_qsl(raw_query, keep_blank_values=True))


def _verify_sigv4_payload_hash(req: ParsedHttpRequest) -> str | None:
    payload_hash = hashlib.sha256(req.body).hexdigest()
    hdr_hashes = _header_values(req.headers, "x-amz-content-sha256")
    if len(hdr_hashes) > 1:
        return None
    if len(hdr_hashes) == 1 and not hmac.compare_digest(hdr_hashes[0].lower(), payload_hash):
        return None
    return payload_hash


def _collect_signed_headers(
    req: ParsedHttpRequest, signed_headers: list[str]
) -> dict[str, str] | None:
    if "host" not in signed_headers or "x-amz-date" not in signed_headers:
        return None
    headers_map: dict[str, str] = {}
    for h in signed_headers:
        val = _single_header(req.headers, h)
        if val is None:
            return None
        headers_map[h] = val
    return headers_map


def _verify_inbound_sigv4(
    req: ParsedHttpRequest,
    route: HttpBrokerRoute,
    raw_path: str,
    raw_query: str,
    ocjob_token: str,
    now_ts: float,
) -> bool:
    if _has_aws_presign_query_params(raw_query):
        return False
    auth_val = _single_header(req.headers, "authorization")
    amz_date = _single_header(req.headers, "x-amz-date")
    if not auth_val or not amz_date:
        return False
    parsed = _parse_sigv4_auth_header(auth_val)
    if parsed is None:
        return False
    cred, signed_headers, provided_sig = parsed
    job_ak, job_sk = derive_job_aws_credentials(ocjob_token)
    if not hmac.compare_digest(cred[0], job_ak):
        return False
    if cred[2] != route.aws_region or cred[3] != route.aws_service:
        return False
    if not _check_sigv4_clock_skew(amz_date, cred[1], now_ts):
        return False
    headers_map = _collect_signed_headers(req, signed_headers)
    payload_hash = _verify_sigv4_payload_hash(req)
    if headers_map is None or payload_hash is None:
        return False
    expected_sig = _compute_sigv4_signature(
        method=req.method,
        raw_path=raw_path,
        raw_query=raw_query,
        headers_map=headers_map,
        signed_headers=signed_headers,
        payload_hash=payload_hash,
        amz_date=amz_date,
        region=route.aws_region,
        service=route.aws_service,
        secret_key=job_sk,
    )
    return hmac.compare_digest(provided_sig.lower(), expected_sig.lower())


def _verify_bearer_auth(req: ParsedHttpRequest, lease: BrokerLease) -> frozenset[str] | None:
    auth = _single_header(req.headers, "authorization")
    if not auth or not auth.startswith("Bearer ") or not lease.verify_token(auth[7:]):
        return None
    return frozenset({"authorization"})


def _verify_basic_token_auth(req: ParsedHttpRequest, lease: BrokerLease) -> frozenset[str] | None:
    auth = _single_header(req.headers, "authorization")
    expected = base64.b64encode(f"{lease.ocjob_token}:".encode("ascii")).decode("ascii")
    if not auth or not auth.startswith("Basic ") or not hmac.compare_digest(auth[6:], expected):
        return None
    return frozenset({"authorization"})


def _verify_header_auth(
    req: ParsedHttpRequest, route: HttpBrokerRoute, lease: BrokerLease
) -> frozenset[str] | None:
    hname = (route.inbound_auth_header or "").lower()
    val = _single_header(req.headers, hname)
    if not val or not lease.verify_token(val):
        return None
    return frozenset({hname})


def verify_and_strip_inbound_auth(
    req: ParsedHttpRequest,
    route: HttpBrokerRoute,
    lease: BrokerLease,
    *,
    raw_path: str,
    raw_query: str,
    now_ts: float | None = None,
) -> bool:
    """Verify per-route inbound_auth using hmac.compare_digest and strip job auth headers."""
    mode = route.inbound_auth
    strip: frozenset[str] | None = None
    if mode == "bearer":
        strip = _verify_bearer_auth(req, lease)
    elif mode == "basic-token":
        strip = _verify_basic_token_auth(req, lease)
    elif mode == "header":
        strip = _verify_header_auth(req, route, lease)
    elif mode == "aws-sigv4-job-key":
        ts = time.time() if now_ts is None else now_ts
        if _verify_inbound_sigv4(req, route, raw_path, raw_query, lease.ocjob_token, ts):
            strip = frozenset(
                {"authorization", "x-amz-date", "x-amz-security-token", "x-amz-content-sha256"}
            )
    if strip is None:
        return False
    req.headers = [(ln, on, v) for ln, on, v in req.headers if ln not in strip]
    return True


# ---------------------------------------------------------------------------
# Pure-Stdlib GraphQL Lexer & Recursive-Descent AST Parser
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _GqlToken:
    kind: str  # NAME, INT, FLOAT, STRING, PUNCT
    value: str


_GQL_SINGLE_PUNCT = frozenset("!$&():=@[]{|}")


def _lex_gql_block_string(src: str, pos: int) -> tuple[_GqlToken, int]:
    i = pos + 3
    n = len(src)
    out: list[str] = []
    while i < n:
        if src.startswith('\\"""', i):
            out.append('"""')
            i += 4
            continue
        if src.startswith('"""', i):
            return _GqlToken("STRING", "".join(out)), i + 3
        out.append(src[i])
        i += 1
    raise GraphQLParseError("Unterminated GraphQL block string")


def _lex_gql_escape(src: str, pos: int) -> tuple[str, int]:
    n = len(src)
    if pos + 1 >= n:
        raise GraphQLParseError("Unterminated escape in GraphQL string")
    esc = src[pos + 1]
    if esc in _GQL_SIMPLE_ESCAPES:
        return esc, pos + 2
    if esc == "u":
        if pos + 5 >= n or any(c not in _HEX_DIGITS for c in src[pos + 2 : pos + 6]):
            raise GraphQLParseError("Invalid unicode escape in GraphQL string")
        return chr(int(src[pos + 2 : pos + 6], 16)), pos + 6
    raise GraphQLParseError(f"Invalid escape char in GraphQL string: {esc!r}")


def _lex_gql_string(src: str, pos: int) -> tuple[_GqlToken, int]:
    i = pos + 1
    n = len(src)
    out: list[str] = []
    while i < n:
        ch = src[i]
        if ch in ("\n", "\r"):
            raise GraphQLParseError("Unescaped newline in GraphQL string")
        if ch == "\\":
            decoded, i = _lex_gql_escape(src, i)
            out.append(decoded)
            continue
        if ch == '"':
            return _GqlToken("STRING", "".join(out)), i + 1
        out.append(ch)
        i += 1
    raise GraphQLParseError("Unterminated GraphQL string")


def _lex_gql_number(src: str, pos: int) -> tuple[_GqlToken, int]:
    m = _GQL_NUM_RE.match(src, pos)
    if m is None:
        raise GraphQLParseError("Invalid GraphQL number")
    raw = m.group(0)
    kind = "FLOAT" if ("." in raw or "e" in raw or "E" in raw) else "INT"
    return _GqlToken(kind, raw), m.end()


def _skip_gql_comment(src: str, pos: int) -> int:
    n = len(src)
    while pos < n and src[pos] not in ("\n", "\r"):
        pos += 1
    return pos


def _skip_gql_trivia(src: str, pos: int) -> int:
    n = len(src)
    while pos < n:
        ch = src[pos]
        if ch in (" ", "\t", "\r", "\n", ",", "\ufeff"):
            pos += 1
        elif ch == "#":
            pos = _skip_gql_comment(src, pos + 1)
        else:
            break
    return pos


def _lex_gql_one(src: str, pos: int) -> tuple[_GqlToken, int]:
    ch = src[pos]
    if src.startswith("...", pos):
        return _GqlToken("PUNCT", "..."), pos + 3
    if ch in _GQL_SINGLE_PUNCT:
        return _GqlToken("PUNCT", ch), pos + 1
    if src.startswith('"""', pos):
        return _lex_gql_block_string(src, pos)
    if ch == '"':
        return _lex_gql_string(src, pos)
    if ch == "-" or ("0" <= ch <= "9"):
        return _lex_gql_number(src, pos)
    if ch == "_" or ("a" <= ch <= "z") or ("A" <= ch <= "Z"):
        m = _GQL_NAME_RE.match(src, pos)
        if m is None:
            raise GraphQLParseError(f"Invalid GraphQL name at {pos}")
        return _GqlToken("NAME", m.group(0)), m.end()
    raise GraphQLParseError(f"Unexpected GraphQL character: {ch!r}")


def _validate_gql_control_chars(src: str) -> None:
    for ch in src:
        code = ord(ch)
        if code == 0x7F or (code < 0x20 and ch not in ("\t", "\n", "\r")):
            raise GraphQLParseError("Illegal control character in GraphQL source")


def tokenize_graphql(src: str) -> list[_GqlToken]:
    _validate_gql_control_chars(src)
    tokens: list[_GqlToken] = []
    pos = 0
    n = len(src)
    while True:
        pos = _skip_gql_trivia(src, pos)
        if pos >= n:
            break
        tok, pos = _lex_gql_one(src, pos)
        tokens.append(tok)
        if len(tokens) > MAX_GQL_TOKENS:
            raise GraphQLParseError("GraphQL token limit exceeded")
    return tokens


class _GraphQLParser:
    def __init__(self, tokens: list[_GqlToken]):
        self._tokens = tokens
        self._pos = 0
        self.operation_types: list[str] = []

    def _peek(self, offset: int = 0) -> _GqlToken | None:
        idx = self._pos + offset
        return self._tokens[idx] if idx < len(self._tokens) else None

    def _next(self) -> _GqlToken:
        tok = self._peek()
        if tok is None:
            raise GraphQLParseError("Unexpected end of GraphQL document")
        self._pos += 1
        return tok

    def _expect_punct(self, val: str) -> None:
        tok = self._next()
        if tok.kind != "PUNCT" or tok.value != val:
            raise GraphQLParseError(f"Expected {val!r}, got {tok.value!r}")

    def _expect_name(self) -> str:
        tok = self._next()
        if tok.kind != "NAME":
            raise GraphQLParseError(f"Expected NAME, got {tok.kind}")
        return tok.value

    def _is_punct(self, val: str) -> bool:
        tok = self._peek()
        return tok is not None and tok.kind == "PUNCT" and tok.value == val

    def parse_document(self) -> None:
        if not self._tokens:
            raise GraphQLParseError("Empty GraphQL document")
        while self._peek() is not None:
            self._parse_definition()

    def _parse_definition(self) -> None:
        tok = self._peek()
        if tok is None:
            raise GraphQLParseError("Unexpected end of GraphQL document")
        if tok.kind == "PUNCT" and tok.value == "{":
            self.operation_types.append("query")
            self._parse_selection_set(1)
            return
        if tok.kind != "NAME":
            raise GraphQLParseError("Expected operation or fragment definition")
        if tok.value == "fragment":
            self._parse_fragment_definition()
            return
        if tok.value in ("query", "mutation", "subscription"):
            self._parse_operation_definition()
            return
        raise GraphQLParseError(f"Disallowed GraphQL definition: {tok.value!r}")

    def _parse_operation_definition(self) -> None:
        op_type = self._expect_name()
        self.operation_types.append(op_type)
        tok = self._peek()
        if tok is not None and tok.kind == "NAME":
            self._next()
        if self._is_punct("("):
            self._parse_variable_definitions(1)
        self._parse_directives(1)
        self._parse_selection_set(1)

    def _parse_fragment_definition(self) -> None:
        self._expect_name()  # "fragment"
        frag_name = self._expect_name()
        if frag_name == "on":
            raise GraphQLParseError("Fragment name cannot be 'on'")
        if self._expect_name() != "on":
            raise GraphQLParseError("Expected 'on' in fragment definition")
        self._expect_name()  # type condition
        self._parse_directives(1)
        self._parse_selection_set(1)

    def _parse_variable_definitions(self, depth: int) -> None:
        self._expect_punct("(")
        if self._is_punct(")"):
            raise GraphQLParseError("Empty variable definitions")
        while not self._is_punct(")"):
            self._expect_punct("$")
            self._expect_name()
            self._expect_punct(":")
            self._parse_type(depth + 1)
            if self._is_punct("="):
                self._next()
                self._parse_value(depth + 1)
            self._parse_directives(depth + 1)
        self._expect_punct(")")

    def _parse_type(self, depth: int) -> None:
        if depth > MAX_GQL_DEPTH:
            raise GraphQLParseError("GraphQL nesting depth exceeded")
        if self._is_punct("["):
            self._next()
            self._parse_type(depth + 1)
            self._expect_punct("]")
        else:
            self._expect_name()
        if self._is_punct("!"):
            self._next()

    def _parse_directives(self, depth: int) -> None:
        while self._is_punct("@"):
            self._next()
            self._expect_name()
            if self._is_punct("("):
                self._parse_arguments(depth + 1)

    def _parse_arguments(self, depth: int) -> None:
        if depth > MAX_GQL_DEPTH:
            raise GraphQLParseError("GraphQL nesting depth exceeded")
        self._expect_punct("(")
        if self._is_punct(")"):
            raise GraphQLParseError("Empty argument list")
        while not self._is_punct(")"):
            self._expect_name()
            self._expect_punct(":")
            self._parse_value(depth + 1)
        self._expect_punct(")")

    def _parse_value(self, depth: int) -> None:
        if depth > MAX_GQL_DEPTH:
            raise GraphQLParseError("GraphQL nesting depth exceeded")
        tok = self._peek()
        if tok is None:
            raise GraphQLParseError("Unexpected EOF in GraphQL value")
        if tok.kind == "PUNCT" and tok.value == "$":
            self._next()
            self._expect_name()
            return
        if tok.kind == "PUNCT" and tok.value == "[":
            self._parse_list_value(depth + 1)
            return
        if tok.kind == "PUNCT" and tok.value == "{":
            self._parse_object_value(depth + 1)
            return
        if tok.kind in ("INT", "FLOAT", "STRING", "NAME"):
            self._next()
            return
        raise GraphQLParseError(f"Unexpected token in GraphQL value: {tok.value!r}")

    def _parse_list_value(self, depth: int) -> None:
        self._expect_punct("[")
        while not self._is_punct("]"):
            self._parse_value(depth + 1)
        self._expect_punct("]")

    def _parse_object_value(self, depth: int) -> None:
        self._expect_punct("{")
        while not self._is_punct("}"):
            self._expect_name()
            self._expect_punct(":")
            self._parse_value(depth + 1)
        self._expect_punct("}")

    def _parse_selection_set(self, depth: int) -> None:
        if depth > MAX_GQL_DEPTH:
            raise GraphQLParseError("GraphQL nesting depth exceeded")
        self._expect_punct("{")
        if self._is_punct("}"):
            raise GraphQLParseError("Empty selection set")
        while not self._is_punct("}"):
            self._parse_selection(depth + 1)
        self._expect_punct("}")

    def _parse_selection(self, depth: int) -> None:
        if self._is_punct("..."):
            self._parse_fragment_selection(depth)
            return
        self._expect_name()
        if self._is_punct(":"):
            self._next()
            self._expect_name()
        if self._is_punct("("):
            self._parse_arguments(depth + 1)
        self._parse_directives(depth + 1)
        if self._is_punct("{"):
            self._parse_selection_set(depth + 1)

    def _parse_fragment_selection(self, depth: int) -> None:
        self._expect_punct("...")
        tok = self._peek()
        if tok is not None and tok.kind == "NAME" and tok.value != "on":
            self._next()
            self._parse_directives(depth + 1)
            return
        if tok is not None and tok.kind == "NAME" and tok.value == "on":
            self._next()
            self._expect_name()
        self._parse_directives(depth + 1)
        self._parse_selection_set(depth + 1)


def all_graphql_operations_are_query(query: Any) -> bool:
    """Strictly parse GraphQL document and confirm >=1 operation and ALL are query."""
    if type(query) is not str or not query.strip():
        return False
    try:
        tokens = tokenize_graphql(query)
        parser = _GraphQLParser(tokens)
        parser.parse_document()
    except GraphQLParseError:
        return False
    return bool(parser.operation_types) and all(op == "query" for op in parser.operation_types)


# ---------------------------------------------------------------------------
# Pluggable Body Policy Enforcement
# ---------------------------------------------------------------------------


def _media_type_strict(
    headers: list[tuple[str, str, str]], *, dup_status: int = 400, dup_code: str = "duplicate_content_type"
) -> str:
    vals = _header_values(headers, "content-type")
    if len(vals) > 1:
        raise HttpErrorResponse(dup_status, dup_code)
    if not vals:
        return ""
    return vals[0].split(";", 1)[0].strip().lower()


def _enforce_mcp_jsonrpc(req: ParsedHttpRequest, policy: WirePolicy) -> tuple[bytes, str]:
    if req.method != "POST":
        raise HttpErrorResponse(403, "mcp_requires_post")
    if _media_type_strict(req.headers) != "application/json":
        raise HttpErrorResponse(415, "mcp_requires_json_content_type")
    try:
        obj = parse_strict_json_object(req.body)
    except StrictJsonError as exc:
        raise HttpErrorResponse(400, "invalid_mcp_json", str(exc)) from exc
    if set(obj.keys()) - ALLOWED_MCP_KEYS:
        raise HttpErrorResponse(400, "unknown_mcp_keys")
    method = obj.get("method")
    if obj.get("jsonrpc") != "2.0" or type(method) is not str or method not in CLOSED_MCP_WIRE_METHODS:
        raise HttpErrorResponse(403, "mcp_method_not_allowed")
    if method == "tools/call":
        params = obj.get("params")
        if not isinstance(params, dict) or type(params.get("name")) is not str:
            raise HttpErrorResponse(400, "invalid_mcp_params")
        if params["name"] not in policy.allowed_tools:
            raise HttpErrorResponse(403, "mcp_tool_not_allowed")
    return canonical_json_bytes(obj), method


def _enforce_graphql_query_only(req: ParsedHttpRequest) -> bytes:
    if req.method != "POST":
        raise HttpErrorResponse(403, "graphql_requires_post")
    if _media_type_strict(req.headers) != "application/json":
        raise HttpErrorResponse(415, "graphql_requires_json_content_type")
    try:
        obj = parse_strict_json_object(req.body)
    except StrictJsonError as exc:
        raise HttpErrorResponse(400, "invalid_graphql_json", str(exc)) from exc
    if set(obj.keys()) - ALLOWED_GQL_KEYS:
        raise HttpErrorResponse(403, "graphql_unknown_keys_denied")
    op_name = obj.get("operationName")
    if op_name is not None and type(op_name) is not str:
        raise HttpErrorResponse(400, "invalid_graphql_operation_name")
    variables = obj.get("variables")
    if variables is not None and not isinstance(variables, dict):
        raise HttpErrorResponse(400, "invalid_graphql_variables")
    if not all_graphql_operations_are_query(obj.get("query")):
        raise HttpErrorResponse(403, "graphql_non_query_denied")
    return canonical_json_bytes(obj)


def _extract_action_params(raw_encoded: str) -> list[str]:
    if not raw_encoded:
        return []
    return [v for k, v in parse_qsl(raw_encoded, keep_blank_values=True) if k.lower() == "action"]


def _extract_body_action_params(req: ParsedHttpRequest) -> list[str]:
    media = _media_type_strict(req.headers)
    if not req.body:
        return []
    if media == "application/x-www-form-urlencoded":
        try:
            body_text = req.body.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise HttpErrorResponse(400, "invalid_form_encoding") from exc
        return _extract_action_params(body_text)
    body_text = req.body.decode("utf-8", errors="replace")
    if _extract_action_params(body_text) or "action=" in unquote(body_text).lower():
        raise HttpErrorResponse(403, "aws_ambiguous_action_denied")
    return []


def _parse_amz_target(req: ParsedHttpRequest, route: HttpBrokerRoute) -> tuple[str, str] | None:
    targets = _header_values(req.headers, "x-amz-target")
    if len(targets) > 1:
        raise HttpErrorResponse(400, "duplicate_amz_target")
    if not targets:
        return None
    raw_target = targets[0]
    parts = raw_target.split(".")
    if len(parts) != 2 or not _AMZ_TARGET_PART_RE.match(parts[0]) or not _AMZ_TARGET_PART_RE.match(parts[1]):
        raise HttpErrorResponse(400, "invalid_amz_target")
    svc_prefix, op = parts[0], parts[1]
    return f"{route.aws_service}:{op}", f"{svc_prefix}:{op}"


def _resolve_aws_actions(
    req: ParsedHttpRequest, route: HttpBrokerRoute, rel_path: str, raw_query: str
) -> tuple[str, tuple[str, ...]]:
    query_actions = _extract_action_params(raw_query)
    body_actions = _extract_body_action_params(req)
    if len(query_actions) > 1 or len(body_actions) > 1:
        raise HttpErrorResponse(403, "aws_duplicate_action_denied")
    if query_actions and body_actions:
        raise HttpErrorResponse(403, "aws_ambiguous_action_denied")

    amz_pair = _parse_amz_target(req, route)
    action_list = query_actions or body_actions
    if amz_pair is not None and action_list:
        raise HttpErrorResponse(403, "aws_ambiguous_action_denied")
    if amz_pair is not None:
        return amz_pair[0], amz_pair
    if action_list:
        if not action_list[0]:
            raise HttpErrorResponse(400, "empty_aws_action")
        act = f"{route.aws_service}:{action_list[0]}"
        return act, (act,)
    rest_act = f"{route.aws_service}:{req.method}:{rel_path}"
    return rest_act, (rest_act,)


def _aws_action_matches(action: str, patterns: frozenset[str]) -> bool:
    low_action = action.lower()
    return any(fnmatchcase(low_action, pat.lower()) for pat in patterns)


def _enforce_aws_sigv4_policy(
    req: ParsedHttpRequest, route: HttpBrokerRoute, rel_path: str, raw_query: str
) -> bytes:
    primary_action, deny_candidates = _resolve_aws_actions(req, route, rel_path, raw_query)
    for cand in deny_candidates:
        if _aws_action_matches(cand, route.wire_policy.denied_aws_actions):
            raise HttpErrorResponse(403, "aws_action_denied")
    if not _aws_action_matches(primary_action, route.wire_policy.allowed_aws_actions):
        raise HttpErrorResponse(403, "aws_action_not_allowed")
    return req.body


def apply_body_policy(
    req: ParsedHttpRequest,
    route: HttpBrokerRoute,
    rule: AllowRule,
    rel_path: str,
    raw_query: str,
) -> tuple[bytes, str | None]:
    if rule.body_policy == "mcp-jsonrpc":
        out_body, mcp_method = _enforce_mcp_jsonrpc(req, route.wire_policy)
        return out_body, mcp_method
    if rule.body_policy == "graphql-query-only":
        return _enforce_graphql_query_only(req), None
    if rule.body_policy == "aws-sigv4":
        return _enforce_aws_sigv4_policy(req, route, rel_path, raw_query), None
    return req.body, None


# ---------------------------------------------------------------------------
# MCP tools/list Response Filtering (JSON & SSE)
# ---------------------------------------------------------------------------


def _filter_mcp_tools_payload(raw_json: bytes, allowed_tools: frozenset[str]) -> bytes:
    try:
        obj = parse_strict_json_object(raw_json)
    except StrictJsonError as exc:
        raise HttpErrorResponse(502, "invalid_mcp_upstream_json") from exc
    if "result" not in obj:
        return canonical_json_bytes(obj)
    res = obj["result"]
    if not isinstance(res, dict):
        raise HttpErrorResponse(502, "invalid_mcp_upstream_result")
    if "tools" in res:
        tools = res["tools"]
        if not isinstance(tools, list):
            raise HttpErrorResponse(502, "invalid_mcp_upstream_tools")
        filtered = [
            t
            for t in tools
            if isinstance(t, dict) and type(t.get("name")) is str and t["name"] in allowed_tools
        ]
        res["tools"] = filtered
    return canonical_json_bytes(obj)


def _filter_single_sse_event(block: str, allowed_tools: frozenset[str]) -> str:
    kept_lines: list[str] = []
    data_lines: list[str] = []
    for raw_line in block.splitlines():
        if raw_line.startswith("data:"):
            val = raw_line[5:]
            data_lines.append(val[1:] if val.startswith(" ") else val)
        elif raw_line.startswith(("event:", "id:", "retry:", ":")):
            kept_lines.append(raw_line)
        elif raw_line.strip():
            raise HttpErrorResponse(502, "invalid_mcp_sse_frame")
    if data_lines:
        joined = "\n".join(data_lines).encode("utf-8")
        filtered = _filter_mcp_tools_payload(joined, allowed_tools).decode("utf-8")
        kept_lines.append(f"data: {filtered}")
    return "\n".join(kept_lines)


def filter_mcp_tools_list_response(
    media_type: str, body: bytes, allowed_tools: frozenset[str]
) -> bytes:
    """Filter MCP tools/list response for application/json or text/event-stream; fail closed 502."""
    if media_type == "application/json":
        return _filter_mcp_tools_payload(body, allowed_tools)
    if media_type == "text/event-stream":
        try:
            text = body.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise HttpErrorResponse(502, "invalid_mcp_sse_utf8") from exc
        norm = text.replace("\r\n", "\n").replace("\r", "\n")
        blocks = [b for b in norm.split("\n\n") if b.strip()]
        if not blocks:
            raise HttpErrorResponse(502, "empty_mcp_sse_response")
        out_blocks = [_filter_single_sse_event(b, allowed_tools) for b in blocks]
        return ("\n\n".join(out_blocks) + "\n\n").encode("utf-8")
    raise HttpErrorResponse(502, "unexpected_mcp_content_type")


# ---------------------------------------------------------------------------
# Upstream HTTP/1.1 Wire Helpers
# ---------------------------------------------------------------------------


def _build_upstream_auth_headers(
    route: HttpBrokerRoute,
    vault: HostVaultMemory,
    *,
    method: str,
    upstream_path: str,
    raw_query: str,
    host_header: str,
    body: bytes,
    extra_sigv4_headers: dict[str, str],
) -> tuple[list[tuple[str, str]], list[str]]:
    mode = route.upstream_auth_mode
    if mode == "none":
        return [], []
    if mode == "aws-sigv4":
        ak = vault.get(route.aws_access_key_ref or "")
        sk = vault.get(route.aws_secret_key_ref or "")
        st = vault.get(route.aws_session_token_ref) if route.aws_session_token_ref else None
        signed = sign_aws_sigv4(
            method=method,
            raw_path=upstream_path,
            raw_query=raw_query,
            host_header=host_header,
            body=body,
            access_key=ak,
            secret_key=sk,
            region=route.aws_region,
            service=route.aws_service,
            session_token=st,
            extra_headers=extra_sigv4_headers,
        )
        secrets_list = [s for s in (ak, sk, st) if s]
        return list(signed.items()), secrets_list

    secret_val = vault.get(route.secret_ref)
    if mode == "bearer":
        return [("Authorization", f"Bearer {secret_val}")], [secret_val]
    if mode == "basic-token":
        tok = base64.b64encode(f"{secret_val}:".encode("ascii")).decode("ascii")
        return [("Authorization", f"Basic {tok}")], [secret_val, tok]
    if mode == "header":
        return [(route.upstream_auth_header, secret_val)], [secret_val]
    raise BrokerPolicyError(f"Unsupported upstream_auth_mode: {mode!r}")


def _build_upstream_request_bytes(
    req: ParsedHttpRequest,
    route: HttpBrokerRoute,
    vault: HostVaultMemory,
    upstream: _ParsedUpstreamUrl,
    rel_path: str,
    raw_query: str,
    out_body: bytes,
) -> tuple[bytes, list[str]]:
    upstream_path = join_upstream_path(upstream.base_path, rel_path)
    wire_path = "/".join(quote(seg, safe="-_.~:@!$&'()*+,=") for seg in upstream_path.split("/"))
    target = f"{wire_path}?{raw_query}" if raw_query else wire_path
    host_header = upstream.host if upstream.port == 443 else f"{upstream.host}:{upstream.port}"

    strip_names = HOP_BY_HOP_HEADERS | req.connection_tokens | IGNORED_INBOUND_HEADERS
    if route.upstream_auth_header:
        strip_names = strip_names | frozenset({route.upstream_auth_header.lower()})
    if route.upstream_auth_mode == "aws-sigv4":
        strip_names = strip_names | _AWS_AUTH_HEADERS
    fwd_headers: list[tuple[str, str]] = [
        ("Host", host_header),
        ("Accept-Encoding", "identity"),
        ("Connection", "close"),
    ]
    sigv4_extra: dict[str, str] = {}
    for lname, oname, val in req.headers:
        if lname in strip_names or lname.startswith("x-forwarded-"):
            continue
        fwd_headers.append((oname, val))
        if lname in ("content-type", "x-amz-target"):
            sigv4_extra[lname] = val

    if out_body or req.method in ("POST", "PUT", "PATCH"):
        fwd_headers.append(("Content-Length", str(len(out_body))))

    auth_headers, secrets_list = _build_upstream_auth_headers(
        route,
        vault,
        method=req.method,
        upstream_path=upstream_path,
        raw_query=raw_query,
        host_header=host_header,
        body=out_body,
        extra_sigv4_headers=sigv4_extra,
    )
    fwd_headers.extend(auth_headers)

    lines = [f"{req.method} {target} HTTP/1.1"]
    lines.extend(f"{k}: {v}" for k, v in fwd_headers)
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
    return head + out_body, secrets_list


def _parse_upstream_response_head(
    sock: socket.socket, deadline: float, read_timeout: float, max_headers: int
) -> ParsedUpstreamHead:
    header_bytes, rest = _read_header_block(sock, deadline, read_timeout, max_headers)
    try:
        text = header_bytes.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise HttpErrorResponse(502, "upstream_invalid_headers") from exc
    lines = text.split("\r\n")
    if any("\n" in ln or "\r" in ln for ln in lines):
        raise HttpErrorResponse(502, "upstream_invalid_headers")
    parts = lines[0].split(" ", 2)
    if (
        len(parts) < 2
        or parts[0] not in ("HTTP/1.0", "HTTP/1.1")
        or len(parts[1]) != 3
        or not (parts[1].isascii() and parts[1].isdigit())
    ):
        raise HttpErrorResponse(502, "upstream_invalid_status_line")
    status = int(parts[1])
    reason = parts[2] if len(parts) == 3 else _HTTP_REASONS.get(status, "OK")
    headers: list[tuple[str, str, str]] = []
    for line in lines[1:]:
        try:
            headers.append(_parse_single_header(line))
        except HttpFramingError as exc:
            raise HttpErrorResponse(502, "upstream_invalid_headers") from exc
    conn_tokens = _extract_connection_tokens(headers)
    return ParsedUpstreamHead(
        status=status,
        reason=reason,
        headers=headers,
        connection_tokens=conn_tokens,
        rest=rest,
    )


def _fill_until(
    sock: socket.socket,
    buf: bytearray,
    needed: int,
    deadline: float,
    read_timeout: float,
    err_code: str,
) -> None:
    while len(buf) < needed:
        chunk = _recv_with_deadline(sock, 8192, deadline, read_timeout)
        if not chunk:
            raise HttpErrorResponse(502, err_code)
        buf.extend(chunk)


def _read_chunk_size_line(
    sock: socket.socket, buf: bytearray, deadline: float, read_timeout: float
) -> int:
    while b"\r\n" not in buf:
        if len(buf) > MAX_CHUNK_LINE_BYTES:
            raise HttpErrorResponse(502, "upstream_chunk_line_too_large")
        chunk = _recv_with_deadline(sock, 8192, deadline, read_timeout)
        if not chunk:
            raise HttpErrorResponse(502, "upstream_truncated_chunked")
        buf.extend(chunk)
    line_end = buf.find(b"\r\n")
    if line_end > MAX_CHUNK_LINE_BYTES:
        raise HttpErrorResponse(502, "upstream_chunk_line_too_large")
    size_token = bytes(buf[:line_end]).split(b";", 1)[0].strip()
    del buf[: line_end + 2]
    if not _CHUNK_SIZE_RE.fullmatch(size_token):
        raise HttpErrorResponse(502, "upstream_invalid_chunk_size")
    return int(size_token, 16)


def _consume_chunk_trailers(
    sock: socket.socket, buf: bytearray, deadline: float, read_timeout: float
) -> None:
    while True:
        while b"\r\n" not in buf:
            if len(buf) > MAX_CHUNK_LINE_BYTES:
                raise HttpErrorResponse(502, "upstream_chunk_trailer_too_large")
            chunk = _recv_with_deadline(sock, 4096, deadline, read_timeout)
            if not chunk:
                raise HttpErrorResponse(502, "upstream_truncated_chunked")
            buf.extend(chunk)
        line_end = buf.find(b"\r\n")
        del buf[: line_end + 2]
        if line_end == 0:
            return


def _read_chunked_body_bounded(
    sock: socket.socket,
    initial: bytes,
    max_body: int,
    deadline: float,
    read_timeout: float,
) -> bytes:
    buf = bytearray(initial)
    out = bytearray()
    while True:
        size = _read_chunk_size_line(sock, buf, deadline, read_timeout)
        if size == 0:
            _consume_chunk_trailers(sock, buf, deadline, read_timeout)
            return bytes(out)
        if len(out) + size > max_body:
            raise HttpErrorResponse(502, "upstream_body_too_large")
        _fill_until(sock, buf, size + 2, deadline, read_timeout, "upstream_truncated_chunked")
        if buf[size : size + 2] != b"\r\n":
            raise HttpErrorResponse(502, "upstream_invalid_chunk_terminator")
        out.extend(buf[:size])
        del buf[: size + 2]


def _is_upstream_chunked(head: ParsedUpstreamHead) -> bool:
    te_vals = _header_values(head.headers, "transfer-encoding")
    cl_vals = _header_values(head.headers, "content-length")
    if not te_vals:
        return False
    if cl_vals:
        raise HttpErrorResponse(502, "upstream_cl_te_rejected")
    tokens = [p.strip().lower() for v in te_vals for p in v.split(",") if p.strip()]
    if tokens != ["chunked"]:
        raise HttpErrorResponse(502, "upstream_unsupported_te")
    return True


def _read_cl_body_bounded(
    sock: socket.socket,
    initial: bytes,
    raw_cl: str,
    max_body: int,
    deadline: float,
    read_timeout: float,
) -> bytes:
    if not (raw_cl.isascii() and raw_cl.isdigit()):
        raise HttpErrorResponse(502, "upstream_invalid_content_length")
    cl = int(raw_cl)
    if cl > max_body:
        raise HttpErrorResponse(502, "upstream_body_too_large")
    buf = bytearray(initial[:cl])
    _fill_until(sock, buf, cl, deadline, read_timeout, "upstream_truncated_body")
    return bytes(buf[:cl])


def _read_eof_body_bounded(
    sock: socket.socket,
    initial: bytes,
    max_body: int,
    deadline: float,
    read_timeout: float,
) -> bytes:
    buf = bytearray(initial)
    while len(buf) <= max_body:
        chunk = _recv_with_deadline(sock, 8192, deadline, read_timeout)
        if not chunk:
            return bytes(buf)
        buf.extend(chunk)
    raise HttpErrorResponse(502, "upstream_body_too_large")


def _read_upstream_body_bounded(
    sock: socket.socket,
    head: ParsedUpstreamHead,
    req_method: str,
    max_body: int,
    deadline: float,
    read_timeout: float,
) -> bytes:
    if req_method == "HEAD" or head.status in (204, 304):
        return b""
    if _is_upstream_chunked(head):
        return _read_chunked_body_bounded(sock, head.rest, max_body, deadline, read_timeout)
    cl_vals = _header_values(head.headers, "content-length")
    if len(cl_vals) > 1:
        raise HttpErrorResponse(502, "upstream_duplicate_content_length")
    if cl_vals:
        return _read_cl_body_bounded(sock, head.rest, cl_vals[0], max_body, deadline, read_timeout)
    return _read_eof_body_bounded(sock, head.rest, max_body, deadline, read_timeout)


def _filter_safe_response_headers(
    headers: list[tuple[str, str, str]], conn_tokens: frozenset[str], secrets_list: Sequence[str]
) -> list[tuple[str, str]]:
    drop = HOP_BY_HOP_HEADERS | conn_tokens
    out: list[tuple[str, str]] = []
    for lname, oname, val in headers:
        if lname in drop or lname == "content-length":
            continue
        if lname in SAFE_RESPONSE_HEADERS:
            OverlapCanaryScanner(secrets_list).scan_bytes(val.encode("utf-8", errors="replace"))
            out.append((oname, val))
    return out


def _get_peer_uid(conn: socket.socket) -> int:
    so_peercred = getattr(socket, "SO_PEERCRED", 17)
    raw = conn.getsockopt(socket.SOL_SOCKET, so_peercred, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", raw)
    return uid


def _format_http_response(
    status: int, headers: list[tuple[str, str]], body: bytes, *, include_cl: bool = True
) -> bytes:
    reason = _HTTP_REASONS.get(status, "OK")
    lines = [f"HTTP/1.1 {status} {reason}"]
    for k, v in headers:
        lines.append(f"{k}: {v}")
    if include_cl:
        lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body


def _send_error_response(conn: socket.socket, err: HttpErrorResponse, write_timeout: float) -> None:
    body = canonical_json_bytes({"error": err.code})
    raw = _format_http_response(
        err.status,
        [("Content-Type", "application/json")],
        body,
    )
    try:
        conn.setblocking(False)
        try:
            conn.recv(4096)
        except OSError:
            pass
        conn.settimeout(write_timeout)
        conn.sendall(raw)
        conn.shutdown(socket.SHUT_WR)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# HostHttpBrokerServer
# ---------------------------------------------------------------------------


class HostHttpBrokerServer:
    """Unified host L7 HTTP policy reverse proxy over loopback TCP or 0o700 UDS."""

    def __init__(
        self,
        routes: Sequence[HttpBrokerRoute],
        vault: HostVaultMemory,
        lease: BrokerLease,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        socket_path: Path | None = None,
        expected_uid: int | None = None,
        max_concurrent_conns: int = MAX_CONCURRENT_CONNS,
        read_timeout: float = READ_TIMEOUT_SECONDS,
        write_timeout: float = WRITE_TIMEOUT_SECONDS,
        total_timeout: float = TOTAL_REQUEST_TIMEOUT_SECONDS,
        max_headers: int = MAX_HEADER_BYTES,
        max_body: int = MAX_BODY_BYTES,
        ssl_context: ssl.SSLContext | None = None,
        resolver: Callable[..., list[Any]] | None = None,
        allow_test_loopback: bool = False,
        clock: Callable[[], float] | None = None,
    ):
        self.vault = vault
        self.lease = lease
        self.routes_by_prefix = validate_route_table(routes, vault)
        self._socket_path = Path(socket_path) if socket_path is not None else None
        if self._socket_path is None:
            try:
                if not ipaddress.ip_address(host).is_loopback:
                    raise BrokerPolicyError("HTTP broker TCP listener must bind to loopback only")
            except ValueError as exc:
                raise BrokerPolicyError("HTTP broker TCP host must be a loopback IP address") from exc
        self._host = host
        self._port = port
        self._expected_uid = os.geteuid() if expected_uid is None else expected_uid
        self._conn_sem = threading.BoundedSemaphore(max_concurrent_conns)
        self._read_timeout = read_timeout
        self._write_timeout = write_timeout
        self._total_timeout = total_timeout
        self._max_headers = max_headers
        self._max_body = max_body
        self._ssl_context = ssl_context
        self._resolver = resolver
        self._allow_test_loopback = allow_test_loopback
        self._clock = clock or time.time

        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.bound_address: tuple[str, int] | Path | None = None

    def _bind_uds(self, sock_path: Path) -> socket.socket:
        parent = sock_path.parent
        if parent.is_symlink():
            raise BrokerPolicyError(f"Refusing symlink socket directory: {parent}")
        parent.mkdir(parents=True, exist_ok=True)
        os.chmod(parent, 0o700)
        try:
            st = os.lstat(sock_path)
        except FileNotFoundError:
            st = None
        if st is not None:
            if not stat.S_ISSOCK(st.st_mode):
                raise BrokerPolicyError(f"Refusing to unlink non-socket path: {sock_path}")
            sock_path.unlink()
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        with _UMASK_LOCK:
            old_umask = os.umask(0o177)
            try:
                srv.bind(str(sock_path))
            finally:
                os.umask(old_umask)
        os.chmod(sock_path, 0o600)
        return srv

    def start(self) -> tuple[str, int] | Path:
        if self._socket_path is not None:
            srv = self._bind_uds(self._socket_path)
            self.bound_address = self._socket_path
        else:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self._host, self._port))
            self.bound_address = srv.getsockname()[:2]
        srv.listen(32)
        srv.settimeout(0.2)
        self._sock = srv
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return self.bound_address

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        if self._socket_path is not None:
            try:
                st = os.lstat(self._socket_path)
                if stat.S_ISSOCK(st.st_mode):
                    self._socket_path.unlink()
            except OSError:
                pass

    def _accept_loop(self) -> None:
        srv = self._sock
        if srv is None:
            return
        while not self._stop.is_set():
            try:
                conn, _ = srv.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            if not self._conn_sem.acquire(blocking=False):
                conn.close()
                continue
            t = threading.Thread(target=self._handle_conn, args=(conn,), daemon=True)
            t.start()

    def _handle_conn(self, conn: socket.socket) -> None:
        try:
            if self._socket_path is not None and _get_peer_uid(conn) != self._expected_uid:
                return
            try:
                self._process_request(conn)
            except HttpFramingError as exc:
                _send_error_response(conn, HttpErrorResponse(400, str(exc)), self._write_timeout)
            except HttpErrorResponse as exc:
                _send_error_response(conn, exc, self._write_timeout)
            except BrokerAuthError:
                _send_error_response(
                    conn, HttpErrorResponse(403, "lease_revoked_or_expired"), self._write_timeout
                )
            except BrokerPolicyError:
                _send_error_response(
                    conn, HttpErrorResponse(502, "broker_policy_blocked"), self._write_timeout
                )
            except CanaryLeakError:
                _send_error_response(
                    conn, HttpErrorResponse(502, "upstream_canary_blocked"), self._write_timeout
                )
            except OSError:
                pass
        finally:
            self.lease.unregister_stream(conn)
            try:
                conn.close()
            finally:
                self._conn_sem.release()

    def _process_request(self, conn: socket.socket) -> None:
        if not self.lease.is_active():
            raise HttpErrorResponse(403, "lease_revoked_or_expired")
        self.lease.register_stream(conn)
        req = parse_strict_http11_request(
            conn,
            max_headers=self._max_headers,
            max_body=self._max_body,
            read_timeout=self._read_timeout,
            total_timeout=self._total_timeout,
        )
        if not self.lease.is_active():
            raise HttpErrorResponse(403, "lease_revoked_or_expired")

        raw_path, raw_query = split_and_canonicalize_target(req.target)
        route, rel_path = match_route_prefix(raw_path, self.routes_by_prefix)
        if route is None or route.credential_delivery != "host-brokered":
            raise HttpErrorResponse(404, "unknown_route")

        if not verify_and_strip_inbound_auth(
            req,
            route,
            self.lease,
            raw_path=raw_path,
            raw_query=raw_query,
            now_ts=self._clock(),
        ):
            raise HttpErrorResponse(401, "invalid_job_auth")

        if matches_segment_glob_any(rel_path, route.wire_policy.denied_paths):
            raise HttpErrorResponse(403, "path_denied")
        rule = first_matching_allow_rule(req.method, rel_path, route.wire_policy.allow_rules)
        if rule is None:
            raise HttpErrorResponse(403, "method_or_path_not_allowed")

        out_body, mcp_method = apply_body_policy(req, route, rule, rel_path, raw_query)
        self._proxy_to_upstream(conn, req, route, rule, rel_path, raw_query, out_body, mcp_method)

    def _proxy_to_upstream(
        self,
        client_sock: socket.socket,
        req: ParsedHttpRequest,
        route: HttpBrokerRoute,
        rule: AllowRule,
        rel_path: str,
        raw_query: str,
        out_body: bytes,
        mcp_method: str | None,
    ) -> None:
        upstream = _parse_upstream_url(route.upstream_url)
        ip = resolve_and_validate_ip(
            upstream.host,
            route.allowed_cidrs,
            port=upstream.port,
            resolver=self._resolver,
            allow_test_loopback=self._allow_test_loopback,
        )
        raw_req, secrets_list = _build_upstream_request_bytes(
            req, route, self.vault, upstream, rel_path, raw_query, out_body
        )
        try:
            up_sock = connect_tls_pinned_ip(
                ip,
                upstream.port,
                server_hostname=upstream.host,
                ssl_context=self._ssl_context,
                timeout=self._read_timeout,
            )
        except Exception as exc:
            raise HttpErrorResponse(502, "upstream_connect_failed") from exc

        try:
            self.lease.register_stream(up_sock)
            up_sock.settimeout(self._write_timeout)
            up_sock.sendall(raw_req)
            deadline = time.monotonic() + self._total_timeout
            head = _parse_upstream_response_head(
                up_sock, deadline, self._read_timeout, self._max_headers
            )
            self._handle_upstream_response(
                client_sock, up_sock, head, req, route, rule, mcp_method, secrets_list, deadline
            )
        finally:
            self.lease.unregister_stream(up_sock)
            try:
                up_sock.close()
            except OSError:
                pass

    def _validate_upstream_head(
        self,
        head: ParsedUpstreamHead,
        route: HttpBrokerRoute,
    ) -> tuple[str, bool, bool]:
        if head.status == 101 or _header_values(head.headers, "upgrade") or "upgrade" in head.connection_tokens:
            raise HttpErrorResponse(502, "upstream_upgrade_blocked")
        if head.status < 200 or head.status > 599:
            raise HttpErrorResponse(502, "upstream_invalid_status")
        if 300 <= head.status <= 399:
            raise HttpErrorResponse(502, "upstream_redirect_blocked")
        media = _media_type_strict(
            head.headers, dup_status=502, dup_code="upstream_duplicate_content_type"
        )
        is_sse = media == "text/event-stream"
        if is_sse and not route.allow_streaming:
            raise HttpErrorResponse(502, "streaming_not_allowed")
        ce_vals = _header_values(head.headers, "content-encoding")
        if any(v.strip().lower() not in ("", "identity") for v in ce_vals):
            raise HttpErrorResponse(502, "upstream_compressed_response")
        is_chunked = _is_upstream_chunked(head)
        return media, is_sse, is_chunked

    def _handle_upstream_response(
        self,
        client_sock: socket.socket,
        up_sock: socket.socket,
        head: ParsedUpstreamHead,
        req: ParsedHttpRequest,
        route: HttpBrokerRoute,
        rule: AllowRule,
        mcp_method: str | None,
        secrets_list: list[str],
        deadline: float,
    ) -> None:
        media, is_sse, is_chunked = self._validate_upstream_head(head, route)
        if 400 <= head.status <= 599:
            scrubbed = b"" if req.method == "HEAD" else canonical_json_bytes({"error": "upstream_error", "status": head.status})
            raw = _format_http_response(
                head.status,
                [("Content-Type", "application/json")],
                scrubbed,
                include_cl=(req.method != "HEAD"),
            )
            client_sock.settimeout(self._write_timeout)
            client_sock.sendall(raw)
            return

        if rule.body_policy == "mcp-jsonrpc" and mcp_method == "tools/list":
            raw_body = _read_upstream_body_bounded(
                up_sock, head, req.method, self._max_body, deadline, self._read_timeout
            )
            scanned = OverlapCanaryScanner(secrets_list).scan_bytes(raw_body)
            filtered = filter_mcp_tools_list_response(media, scanned, route.wire_policy.allowed_tools)
            safe_hdrs = _filter_safe_response_headers(head.headers, head.connection_tokens, secrets_list)
            client_sock.settimeout(self._write_timeout)
            client_sock.sendall(_format_http_response(head.status, safe_hdrs, filtered))
            return

        if is_sse:
            self._stream_sse_response(client_sock, up_sock, head, secrets_list, is_chunked=is_chunked)
            return

        raw_body = _read_upstream_body_bounded(
            up_sock, head, req.method, self._max_body, deadline, self._read_timeout
        )
        scanned = OverlapCanaryScanner(secrets_list).scan_bytes(raw_body)
        safe_hdrs = _filter_safe_response_headers(head.headers, head.connection_tokens, secrets_list)
        client_sock.settimeout(self._write_timeout)
        client_sock.sendall(
            _format_http_response(head.status, safe_hdrs, scanned, include_cl=(req.method != "HEAD"))
        )

    def _stream_sse_response(
        self,
        client_sock: socket.socket,
        up_sock: socket.socket,
        head: ParsedUpstreamHead,
        secrets_list: list[str],
        *,
        is_chunked: bool = False,
    ) -> None:
        safe_hdrs = _filter_safe_response_headers(head.headers, head.connection_tokens, secrets_list)
        scanner = OverlapCanaryScanner(secrets_list)
        client_sock.settimeout(self._write_timeout)
        client_sock.sendall(_format_http_response(head.status, safe_hdrs, b"", include_cl=False))
        up_sock.settimeout(self._read_timeout)
        try:
            if is_chunked:
                self._relay_chunked_sse_chunks(client_sock, up_sock, head.rest, scanner)
            else:
                self._relay_sse_chunks(client_sock, up_sock, head.rest, scanner)
        except (CanaryLeakError, HttpErrorResponse):
            try:
                client_sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _recv_sse_more(self, up_sock: socket.socket, buf: bytearray) -> bool:
        while self.lease.is_active():
            try:
                chunk = up_sock.recv(4096)
            except TimeoutError:
                continue
            except OSError:
                return False
            if not chunk:
                return False
            buf.extend(chunk)
            return True
        return False

    def _read_sse_chunk_size(self, up_sock: socket.socket, buf: bytearray) -> int | None:
        while b"\r\n" not in buf:
            if len(buf) > MAX_CHUNK_LINE_BYTES:
                raise HttpErrorResponse(502, "upstream_chunk_line_too_large")
            if not self._recv_sse_more(up_sock, buf):
                return None
        line_end = buf.find(b"\r\n")
        if line_end > MAX_CHUNK_LINE_BYTES:
            raise HttpErrorResponse(502, "upstream_chunk_line_too_large")
        token = bytes(buf[:line_end]).split(b";", 1)[0].strip()
        del buf[: line_end + 2]
        if not _CHUNK_SIZE_RE.fullmatch(token):
            raise HttpErrorResponse(502, "upstream_invalid_chunk_size")
        return int(token, 16)

    def _relay_one_sse_chunk(
        self,
        client_sock: socket.socket,
        up_sock: socket.socket,
        buf: bytearray,
        size: int,
        scanner: OverlapCanaryScanner,
    ) -> None:
        rem = size
        while rem > 0:
            if not buf and not self._recv_sse_more(up_sock, buf):
                raise HttpErrorResponse(502, "upstream_truncated_chunked")
            take = min(rem, len(buf))
            emit = scanner.feed(bytes(buf[:take]))
            del buf[:take]
            rem -= take
            if emit:
                client_sock.sendall(emit)

    def _consume_sse_chunk_crlf(self, up_sock: socket.socket, buf: bytearray) -> None:
        while len(buf) < 2:
            if not self._recv_sse_more(up_sock, buf):
                raise HttpErrorResponse(502, "upstream_truncated_chunked")
        if buf[:2] != b"\r\n":
            raise HttpErrorResponse(502, "upstream_invalid_chunk_terminator")
        del buf[:2]

    def _relay_chunked_sse_chunks(
        self,
        client_sock: socket.socket,
        up_sock: socket.socket,
        initial: bytes,
        scanner: OverlapCanaryScanner,
    ) -> None:
        buf = bytearray(initial)
        while self.lease.is_active():
            size = self._read_sse_chunk_size(up_sock, buf)
            if size is None or size == 0:
                tail = scanner.finish()
                if tail:
                    client_sock.sendall(tail)
                return
            self._relay_one_sse_chunk(client_sock, up_sock, buf, size, scanner)
            self._consume_sse_chunk_crlf(up_sock, buf)

    def _relay_sse_chunks(
        self,
        client_sock: socket.socket,
        up_sock: socket.socket,
        initial: bytes,
        scanner: OverlapCanaryScanner,
    ) -> None:
        if initial:
            emit = scanner.feed(initial)
            if emit:
                client_sock.sendall(emit)
        while self.lease.is_active():
            try:
                chunk = up_sock.recv(4096)
            except TimeoutError:
                continue
            except OSError:
                break
            if not chunk:
                tail = scanner.finish()
                if tail:
                    client_sock.sendall(tail)
                break
            emit = scanner.feed(chunk)
            if emit:
                client_sock.sendall(emit)
