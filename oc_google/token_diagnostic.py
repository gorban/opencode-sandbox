"""In-memory categories for one attended initial token exchange."""

from dataclasses import dataclass
from enum import Enum, auto


class TokenStage(Enum):
    HTTP_400 = auto()
    HTTP_401_403 = auto()
    HTTP_429 = auto()
    HTTP_5XX = auto()
    HTTP_OTHER = auto()
    CHUNKED = auto()
    HEADER = auto()
    FRAMING = auto()
    TRAILING = auto()
    TLS_EOF = auto()
    TRANSPORT = auto()
    GRANT_SHAPE = auto()
    GRANT_SCOPE = auto()
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
