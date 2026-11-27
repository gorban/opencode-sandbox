"""In-memory categories for one attended initial token exchange."""

from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable


class TokenStage(Enum):
    HTTP_400 = auto()
    HTTP_401_403 = auto()
    HTTP_429 = auto()
    HTTP_5XX = auto()
    HTTP_OTHER = auto()
    CHUNKED = auto()
    HEADER = auto()
    DUPLICATE_HEADER = auto()
    FRAMING = auto()
    TRAILING = auto()
    TLS_EOF = auto()
    TRANSPORT = auto()
    GRANT_SHAPE = auto()
    GRANT_SCOPE_LIST = auto()
    GRANT_SCOPE_UNKNOWN = auto()
    GRANT_SCOPE_RESOURCE = auto()
    GRANT_SCOPE_EMAIL = auto()
    GRANT_BEARER = auto()
    GRANT_IDENTITY = auto()
    GRANT_REFRESH = auto()
    USERINFO_PRE_WRITE = auto()


@dataclass(frozen=True, slots=True, eq=False)
class TokenDiagnostic:
    """The exact attended enrollment that can report a matched refusal."""

    def mark(self, error):
        if type(getattr(error, "token_stage", None)) is TokenStage:
            error.attended_token_diagnostic = self

    def stage(self, error):
        if getattr(error, "attended_token_diagnostic", None) is self:
            stage = getattr(error, "token_stage", None)
            if type(stage) is TokenStage:
                return stage
        return None


class PostTokenStage(Enum):
    LOAD_ADMISSION = auto()
    LOAD_HTTP_REPLY = auto()
    LOAD_BODY = auto()
    LOAD_NATIVE_REPLY = auto()
    AUTH_COMPLETE = auto()
    ENROLLMENT_DRAIN = auto()
    ENROLLMENT_COMMIT = auto()
    COLD_REFRESH = auto()
    COLD_SUBJECT = auto()
    COLD_CATALOG = auto()
    COLD_ACP_COMPLETE = auto()
    COLD_DRAIN = auto()
    COLD_COMMIT = auto()


class LoadBodyReason(Enum):
    SIZE = auto()
    JSON_OBJECT = auto()
    STRUCTURE_LIMITS = auto()
    TOP_LEVEL_FIELDS = auto()
    CURRENT_TIER = auto()
    ORIGINAL_PROJECT = auto()
    PAID_TIER = auto()
    CONSUMER_PROJECT_POLICY = auto()
    OPTIONAL_METADATA = auto()
    ALTERNATIVE_TIER_POLICY = auto()


class CurrentTierDetail(Enum):
    ABSENT = auto()
    NULL = auto()
    NON_OBJECT = auto()
    EMPTY_OBJECT = auto()
    UNSUPPORTED_FIELDS = auto()
    IDENTIFIER = auto()
    DISPLAY_NAME = auto()
    OTHER_SHAPE = auto()


class OriginalProjectDetail(Enum):
    ABSENT = auto()
    NULL = auto()
    EMPTY_STRING = auto()
    WRONG_TYPE = auto()
    IDENTIFIER_SHAPE = auto()


def _load_reasons(error):
    try:
        reasons = getattr(error, "load_body_reasons", None)
    except Exception:
        return ()
    if (type(reasons) is not tuple or not 0 < len(reasons) <= len(LoadBodyReason)
            or any(type(reason) is not LoadBodyReason for reason in reasons)):
        return ()
    return tuple(reason for reason in LoadBodyReason if reason in reasons)


def _load_account_details(error, reasons):
    if LoadBodyReason.CURRENT_TIER not in reasons or LoadBodyReason.ORIGINAL_PROJECT not in reasons:
        return None
    try:
        pair = getattr(error, "load_account_details", None)
    except Exception:
        return None
    if (type(pair) is tuple and len(pair) == 2
            and type(pair[0]) is CurrentTierDetail and type(pair[1]) is OriginalProjectDetail):
        return pair
    return None


@dataclass(slots=True, eq=False)
class PostTokenDiagnostic:
    """The first exact failure recorded by this attended enrollment."""

    _failure: tuple[
        Exception, PostTokenStage, BaseException | None, tuple[LoadBodyReason, ...],
        tuple[CurrentTierDetail, OriginalProjectDetail] | None,
    ] | None = field(default=None, init=False, repr=False)

    def __reduce_ex__(self, _protocol):
        raise TypeError("Google enrollment diagnostics must remain with the exact attempt")

    def mark(self, error, stage):
        if self._failure is None and isinstance(error, Exception) and type(stage) is PostTokenStage:
            reasons = _load_reasons(error) if stage is PostTokenStage.LOAD_BODY else ()
            self._failure = error, stage, error.__context__, reasons, _load_account_details(error, reasons)

    def stage(self, error):
        failure = self._failure
        if failure is not None and error is failure[0] and error.__context__ is failure[2]:
            return failure[1]
        return None

    def clear(self):
        self._failure = None

    def load_body_reasons(self, error):
        failure = self._failure
        if failure is not None and self.stage(error) is PostTokenStage.LOAD_BODY:
            return failure[3]
        return ()

    def load_account_details(self, error):
        failure = self._failure
        if failure is not None and self.stage(error) is PostTokenStage.LOAD_BODY:
            return failure[4]
        return None


@dataclass(frozen=True, slots=True, eq=False)
class ScopedPostTokenDiagnostic:
    """Record the failure only under the exact operation's authority fence."""

    _attempt: PostTokenDiagnostic = field(repr=False)
    _fence: object = field(repr=False)
    _active: Callable[[], bool] = field(repr=False)

    def mark(self, error, stage):
        # Authority checks here can only suppress a detail, never replace the failure.
        with suppress(Exception), self._fence:
            if self._active() is True:
                self._attempt.mark(error, stage)


def scoped_post_token(diagnostic, fence, active):
    if type(diagnostic) is PostTokenDiagnostic:
        return ScopedPostTokenDiagnostic(diagnostic, fence, active)
    return None


@contextmanager
def observe_post_token(diagnostic, stage, *exceptions):
    try:
        yield
    except exceptions as error:
        if type(diagnostic) is ScopedPostTokenDiagnostic:
            diagnostic.mark(error, stage)
        raise
