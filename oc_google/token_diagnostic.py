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


@dataclass(slots=True, eq=False)
class PostTokenDiagnostic:
    """The first exact failure recorded by this attended enrollment."""

    _failure: tuple[Exception, PostTokenStage, BaseException | None] | None = field(
        default=None, init=False, repr=False,
    )

    def __reduce_ex__(self, _protocol):
        raise TypeError("Google enrollment diagnostics must remain with the exact attempt")

    def mark(self, error, stage):
        if self._failure is None and isinstance(error, Exception) and type(stage) is PostTokenStage:
            self._failure = error, stage, error.__context__

    def stage(self, error):
        failure = self._failure
        if failure is not None and error is failure[0] and error.__context__ is failure[2]:
            return failure[1]
        return None

    def clear(self):
        self._failure = None


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
