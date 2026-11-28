"""Bind a verified Google OAuth v2 subject to metadata access in one phase."""

from enum import Enum
import hmac
import json
import re


_DOMAIN = b"oc-sandbox/google/account-subject/v1\x00"
# This identifies the verified v2 endpoint in the digest domain.
_ISSUER = b"https://www.googleapis.com/oauth2/v2/userinfo"
_MAX_SUBJECT_BODY = 1024
_MAX_BEARER = 8192
_SUBJECT = re.compile(r"[0-9]{1,64}")
_BEARER = re.compile(rb"[A-Za-z0-9._~+/\-]+=*")


class AccountBindingError(ValueError):
    """A redacted denial of Google account continuity or metadata access."""


class MetadataOperation(Enum):
    """Account and model metadata operations covered by this proof."""

    LOAD_CODE_ASSIST = "loadCodeAssist"
    FETCH_AVAILABLE_MODELS = "fetchAvailableModels"


def _unique_fields(pairs):
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError
    return fields


def _subject(body):
    if type(body) is bytes and 0 < len(body) <= _MAX_SUBJECT_BODY:
        try:
            fields = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_fields)
        except (ValueError, RecursionError):
            fields = None
        if isinstance(fields, dict) and fields.keys() == {"id"}:
            subject = fields["id"]
            if type(subject) is str and _SUBJECT.fullmatch(subject):
                return subject.encode("ascii")
    raise AccountBindingError("Invalid Google account subject response")


def _subject_digest(key, body):
    if type(key) is not bytes or len(key) != 32:
        raise AccountBindingError("Invalid Google account binding key")
    subject = _subject(body)
    message = _DOMAIN + len(_ISSUER).to_bytes(4, "big") + _ISSUER + len(subject).to_bytes(4, "big") + subject
    return hmac.digest(key, message, "sha256")


def _valid_bearer(bearer):
    return type(bearer) is bytes and 0 < len(bearer) <= _MAX_BEARER and _BEARER.fullmatch(bearer) is not None


class SubjectProof:
    """An in-memory same-bearer proof. Only its keyed digest is for storage."""

    __slots__ = ("_digest", "_bearer", "_operations")

    def __init__(self, digest, bearer, *, operations: frozenset[MetadataOperation]):
        if not _valid_bearer(bearer):
            raise AccountBindingError("Invalid Google metadata bearer")
        self._digest = digest
        self._bearer = bearer
        self._operations = operations

    @property
    def digest(self) -> bytes:
        return self._digest

    def require_metadata_bearer(self, operation: MetadataOperation, bearer: bytes) -> None:
        if type(operation) is not MetadataOperation:
            raise AccountBindingError("Google account proof permits metadata only")
        if operation not in self._operations:
            raise AccountBindingError("Google metadata operation is unavailable in this phase")
        if not _valid_bearer(bearer) or not hmac.compare_digest(self._bearer, bearer):
            raise AccountBindingError("Google metadata bearer does not match the verified bearer")

    def __reduce_ex__(self, _protocol):
        raise TypeError("Google account proof must remain in memory")


def bind_subject(key: bytes, bearer: bytes, body: bytes) -> SubjectProof:
    """Bind a verified enrollment subject for the loadCodeAssist check.

    The caller owns HTTP verification and the registration dispatch fence.
    """
    return SubjectProof(_subject_digest(key, body), bearer,
                        operations=frozenset({MetadataOperation.LOAD_CODE_ASSIST}))


def rebind_subject(key: bytes, bearer: bytes, body: bytes, expected_digest: bytes) -> SubjectProof:
    """Require the enrolled subject on a fresh bearer for account and catalog checks."""
    if type(expected_digest) is not bytes or len(expected_digest) != 32:
        raise AccountBindingError("Invalid enrolled Google account digest")
    digest = _subject_digest(key, body)
    if not hmac.compare_digest(digest, expected_digest):
        raise AccountBindingError("Google account subject does not match enrollment")
    return SubjectProof(digest, bearer, operations=frozenset({
        MetadataOperation.LOAD_CODE_ASSIST,
        MetadataOperation.FETCH_AVAILABLE_MODELS,
    }))
