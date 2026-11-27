"""Closed, in-process transport for one offline Gemini generation fixture."""

from dataclasses import dataclass, field
from enum import Enum, auto
from hashlib import sha256
import json
import re
from threading import RLock, get_ident
from time import monotonic


MODEL_ALIAS = "gemini-2.5-flash"
WIRE_MODEL = "gemini-2.5-flash"
RESPONSE_VERSION = "fixture-gemini-2.5-flash-v1"
PROMPT = "Reply with exactly: ok"
DEADLINE_SECONDS = 2.5
_HEAD_LIMIT = 8192
_REQUEST_LIMIT = 24576
_REPLY_LIMIT = 8192
_REQUEST_LINE = b"POST /v1internal:streamGenerateContent?alt=sse HTTP/1.1"
_RESPONSE_LINE = b"HTTP/1.1 200 OK"
_REQUEST_HEADERS = {b"host": b"gemini-fixture.invalid", b"content-type": b"application/json",
                    b"connection": b"close", b"authorization": b"Bearer fixture-generation"}
_REPLY_HEADERS = {b"content-type": b"text/event-stream", b"connection": b"close"}
_HEADER = re.compile(rb"([A-Za-z-]+): ([\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?)")
_USAGE_FIELDS = {"promptTokenCount", "candidatesTokenCount", "thoughtsTokenCount", "totalTokenCount"}
_TOOL_TOKENS = "toolUsePromptTokenCount"


class GenerationRefused(ValueError):
    """The synthetic generation could not be admitted or settled."""


def _unique(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError("duplicate field")
    return value


def _constant(_value):
    raise ValueError("invalid numeric constant")


def _json(body):
    return json.loads(body.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_constant)


def _body(packet, *, end_of_input, first_line, expected, limit):
    if (type(packet) is not bytes or end_of_input is not True
            or len(packet) > _HEAD_LIMIT + limit):
        raise GenerationRefused("Incomplete or oversized Gemini fixture packet")
    head, separator, body = packet.partition(b"\r\n\r\n")
    first, *lines = head.split(b"\r\n")
    if not separator or len(head) + len(separator) > _HEAD_LIMIT or first != first_line:
        raise GenerationRefused("Unexpected Gemini fixture framing")
    fields = {}
    for line in lines:
        match = _HEADER.fullmatch(line)
        if match is None or (name := match[1].lower()) in fields:
            raise GenerationRefused("Unexpected Gemini fixture header")
        fields[name] = match[2]
    if (not 0 < len(body) <= limit or fields.pop(b"content-length", None) != str(len(body)).encode("ascii")
            or fields != expected):
        raise GenerationRefused("Unexpected Gemini fixture body framing")
    return body


def _text(value):
    return {"role": "user", "parts": [{"text": value}]}


def _request(*, mode, limits):
    return {"model": WIRE_MODEL, "project": "oc-synthetic-stage-a", "request": {
        "contents": [_text(PROMPT)],
        "systemInstruction": _text("Fixture system instruction."),
        "sessionId": "0",
        "toolConfig": {"functionCallingConfig": {"mode": mode}},
        "generationConfig": limits,
    }}


def _projected_packet():
    request = _request(mode="NONE", limits={"maxOutputTokens": 64, "thinkingConfig": {"thinkingBudget": 0}})
    body = json.dumps(request, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    fields = _REQUEST_HEADERS | {b"content-length": str(len(body)).encode("ascii")}
    return b"\r\n".join([_REQUEST_LINE, *(name + b": " + value for name, value in fields.items()), b"", body])


_PROJECTED_PACKET = _projected_packet()


def project_generation(packet, *, end_of_input):
    """Check the exact Flash fixture wire envelope and replace it with canonical bytes."""
    body = _body(packet, end_of_input=end_of_input, first_line=_REQUEST_LINE,
                 expected=_REQUEST_HEADERS, limit=_REQUEST_LIMIT)
    try:
        request = _json(body)
        # The measured native input configured generationConfig.maxOutputTokens = 65535.
        if (request != _request(mode="AUTO", limits={"maxOutputTokens": 65535})
                or type(request["request"]["generationConfig"]["maxOutputTokens"]) is not int):
            raise ValueError()
    except (ValueError, RecursionError):
        raise GenerationRefused("Unexpected Gemini fixture request") from None
    return _PROJECTED_PACKET


def _check_usage(usage):
    if (type(usage) is not dict or not (_USAGE_FIELDS <= usage.keys() <= _USAGE_FIELDS | {_TOOL_TOKENS})
            or any(type(value) is not int for value in usage.values())):
        raise ValueError()
    prompt, candidates, thoughts, total = (usage[key] for key in (
        "promptTokenCount", "candidatesTokenCount", "thoughtsTokenCount", "totalTokenCount",
    ))
    tool = usage.get(_TOOL_TOKENS, 0)
    if not (1 <= prompt <= 128 and 1 <= candidates and candidates + thoughts <= 64
            and thoughts == tool == 0 and total == prompt + candidates + thoughts + tool <= 192):
        raise ValueError()


def validate_generation_reply(packet, *, end_of_input):
    """Buffer one complete, exact Flash fixture event and reject any suffix."""
    body = _body(packet, end_of_input=end_of_input, first_line=_RESPONSE_LINE,
                 expected=_REPLY_HEADERS, limit=_REPLY_LIMIT)
    if (not body.startswith(b"data: {") or not body.endswith(b"}\n\n")
            or b"\r" in body or b"\n" in body[:-2]):
        raise GenerationRefused("Unexpected Gemini fixture event framing")
    try:
        event = _json(body[6:-2])
        if type(event) is not dict or event.keys() != {"response"}:
            raise ValueError()
        response = event["response"]
        if (type(response) is not dict or response.keys() != {"modelVersion", "candidates", "usageMetadata"}
                or response["modelVersion"] != RESPONSE_VERSION):
            raise ValueError()
        expected = [{"content": {"role": "model", "parts": [{"text": "ok"}]}, "finishReason": "STOP", "index": 0}]
        if response["candidates"] != expected or type(response["candidates"][0]["index"]) is not int:
            raise ValueError()
        _check_usage(response["usageMetadata"])
    except (ValueError, RecursionError):
        raise GenerationRefused("Unexpected Gemini fixture event or token usage") from None
    return body


@dataclass(frozen=True, slots=True, eq=False)
class GenerationBinding:
    """One exact owner, worker incarnation, and host selection in the fixture."""

    owner: object
    job: object
    epoch: int
    alias: str

    def __post_init__(self):
        if (self.owner is None or self.job is None or type(self.epoch) is not int or self.epoch < 1
                or type(self.alias) is not str or self.alias != MODEL_ALIAS):
            raise GenerationRefused("Invalid Gemini fixture selection")


@dataclass(frozen=True, slots=True, eq=False)
class _SinkReceipt:
    """The recorder's exact visit permit for the accepted packet."""

    attempt: object
    packet_digest: bytes


@dataclass(frozen=True, slots=True, eq=False)
class _Retirement:
    receipt: _SinkReceipt


def _deny_copy(self, *_):
    raise TypeError(f"{type(self).__name__} has exclusive fixture ownership")


class FakeDestination:
    """Record one complete canonical request without any network or credential access."""

    __copy__ = __deepcopy__ = __reduce_ex__ = _deny_copy

    def __init__(self, reply: bytes, *, end_of_input: bool):
        if type(reply) is not bytes or type(end_of_input) is not bool:
            raise TypeError("Expected a synthetic Gemini response")
        self._reply = reply
        self._eof = end_of_input
        self._lock = RLock()
        self._attempt = None
        self._receipt = None
        self._read = False
        self._retirement = None

    def _attach(self, attempt):
        with self._lock:
            if self._attempt is not None:
                raise GenerationRefused("Gemini fixture sink already has an attempt")
            self._attempt = attempt

    def write(self, packet, *, attempt, deadline, check):
        """Accept the complete packet at the independent fake sink boundary."""
        with self._lock:
            if (self._attempt is None or attempt is not self._attempt or self._receipt is not None
                    or type(packet) is not bytes or packet != _PROJECTED_PACKET):
                raise GenerationRefused("Gemini fixture sink refused the projected packet")
            digest = sha256(packet).digest()
            check(deadline)
            if self._receipt is not None:
                raise GenerationRefused("Gemini fixture sink was already spent")
            self._receipt = _SinkReceipt(attempt, digest)
        return len(packet)

    def receipt(self):
        with self._lock:
            return self._receipt

    def confirms_write(self, receipt):
        with self._lock:
            return receipt is not None and receipt is self._receipt

    def read(self, receipt, *, deadline, check):
        check(deadline)
        with self._lock:
            if receipt is not self._receipt or receipt is None or self._read:
                raise GenerationRefused("Gemini fixture reply is unavailable")
            self._read = True
            return self._reply, self._eof

    def retire(self, receipt, *, deadline, check):
        check(deadline)
        with self._lock:
            if (receipt is not self._receipt or receipt is None or not self._read or not self._eof
                    or self._retirement is not None):
                raise GenerationRefused("Gemini fixture retirement is unconfirmed")
            self._retirement = _Retirement(receipt)
            return self._retirement

    def confirms_retirement(self, receipt, proof):
        with self._lock:
            return (proof is not None and proof is self._retirement and proof.receipt is receipt
                    and receipt is self._receipt)


@dataclass(frozen=True, slots=True, eq=False)
class PreparedGeneration:
    """An exact, immutable request reserved for one attempt."""

    byte_count: int
    packet_digest: bytes
    _packet: bytes = field(repr=False)


@dataclass(frozen=True, slots=True, eq=False)
class GenerationWrite:
    """Evidence of one complete fake write, before reply verification."""

    byte_count: int
    packet_digest: bytes
    sink_receipt: _SinkReceipt


@dataclass(frozen=True, slots=True, eq=False)
class GenerationCompletion:
    """Exact sink evidence prepared for settlement, with no reply bytes."""

    write: GenerationWrite
    reply_digest: bytes
    retirement: _Retirement


class GenerationState(Enum):
    UNSPENT = auto()
    CLAIMED = auto()
    SENT = auto()
    UNCERTAIN = auto()


@dataclass(frozen=True, slots=True)
class GenerationReceipt:
    """Count one immutable reply at successful settlement under the fence."""

    state: GenerationState
    native_requests: int
    destination_attempts: int
    complete_requests: int
    releases: int


class GenerationAttempt:
    """Share one sticky authority and one non-retrying write across all call sites."""

    __copy__ = __deepcopy__ = __reduce_ex__ = _deny_copy

    def __init__(self, binding: GenerationBinding, destination: FakeDestination, *, authorized, now=monotonic):
        if type(binding) is not GenerationBinding or type(destination) is not FakeDestination:
            raise TypeError("Expected a bound Gemini fixture destination")
        self._binding = binding
        self._destination = destination
        self._authorized = authorized
        self._now = now
        self._fence = RLock()
        self._attempt = object()
        destination._attach(self._attempt)
        self._state = GenerationState.UNSPENT
        self._active = False
        self._revoked = False
        self._deadline = None
        self._native_requests = 0
        self._destination_attempts = 0
        self._releases = 0
        self._prepared = self._write = self._completion = self._validated = None
        self._observing = False

    def _clear_evidence(self):
        self._prepared = self._write = self._completion = self._validated = None

    def revoke(self):
        with self._fence:
            if self._active and self._state in (GenerationState.CLAIMED, GenerationState.SENT):
                self._hold()
            else:
                self._revoked = True
                self._clear_evidence()

    def _hold(self):
        self._state = GenerationState.UNCERTAIN
        self._revoked = True
        self._active = False
        self._clear_evidence()

    def receipt(self):
        with self._fence:
            received = self._destination.receipt()
            complete = int(type(received) is _SinkReceipt and received.attempt is self._attempt)
            return GenerationReceipt(self._state, self._native_requests, self._destination_attempts,
                                     complete, self._releases)

    def _check_local(self, deadline):
        if not self._revoked and deadline == self._deadline:
            observed = self._now()
            if observed < deadline and not self._revoked:
                return observed
        self._revoked = True
        raise GenerationRefused("Gemini fixture owner or deadline changed")

    def _check(self, deadline):
        try:
            if self._revoked or deadline != self._deadline or self._authorized(self._binding) is not True:
                raise GenerationRefused("Gemini fixture owner or deadline changed")
            return self._check_local(deadline)
        except BaseException:
            self._revoked = True
            raise

    def prepare(self, binding, packet, *, end_of_input, deadline=None):
        """Project one exact input before the caller charges a durable claim."""
        with self._fence:
            self._native_requests += 1
            if (self._active or self._state is not GenerationState.UNSPENT or self._revoked
                    or binding is not self._binding):
                raise GenerationRefused("Gemini fixture attempt is unavailable")
            # Reserve the attempt before invoking the clock or authority.
            self._active = True
            try:
                if deadline is not None and (type(deadline) not in (int, float)
                                             or not float("-inf") < deadline < float("inf")):
                    raise GenerationRefused("Invalid Gemini fixture deadline")
                if self._deadline is None:
                    self._deadline = self._now() + DEADLINE_SECONDS
                if deadline is not None:
                    self._deadline = min(self._deadline, deadline)
                self._check(self._deadline)
                projected = project_generation(packet, end_of_input=end_of_input)
                self._prepared = PreparedGeneration(len(projected), sha256(projected).digest(), projected)
                return self._prepared
            except BaseException:
                self._active = False
                raise

    def run(self, binding, packet, *, end_of_input) -> bytes:
        """Return one immutable reply only after exact fake retirement and settlement."""
        prepared = self.prepare(binding, packet, end_of_input=end_of_input)
        write = self._write_prepared(prepared, admit=None)
        return self.settle(write, self._observe(write, check_authority=True))

    def write_prepared(self, prepared, *, admit):
        """Accept one prepared request inside the caller's live synthetic effect.

        Admit is the private synchronous D1 proof check. It must perform no I/O
        or wait and is neither stored nor passed to the observer.
        """
        if not callable(admit):
            raise TypeError("Expected the private Gemini fixture admission check")
        return self._write_prepared(prepared, admit=admit)

    def _write_prepared(self, prepared, *, admit):
        with self._fence:
            if (prepared is None or prepared is not self._prepared or not self._active
                    or self._state is not GenerationState.UNSPENT):
                raise GenerationRefused("Gemini fixture preparation is unavailable")
            self._prepared = None
            self._state = GenerationState.CLAIMED
            try:
                self._write = self._dispatch(prepared, admit=admit)
                self._state = GenerationState.SENT
                return self._write
            except BaseException:
                self._hold()
                raise

    def _dispatch(self, prepared, *, admit):
        deadline = self._deadline
        self._check(deadline)
        owner_thread = get_ident()
        split = admit is not None
        open_check = True
        used_check = False
        admitted_until = None

        def check_final():
            if not split:
                self._check(deadline)
            elif (self._revoked or not self._active or self._state is not GenerationState.CLAIMED
                  or deadline is not self._deadline or admitted_until is None or not monotonic() < admitted_until):
                raise GenerationRefused("Gemini fixture owner or deadline changed")

        def check(checked_deadline):
            nonlocal used_check, admitted_until
            if not open_check or used_check or get_ident() != owner_thread:
                raise GenerationRefused("Gemini fixture write check is unavailable")
            used_check = True
            self._check(checked_deadline)
            if split:
                # Sample the injectable clock and external owner before the
                # journal check. Only the local monotonic clock may run after it.
                started = monotonic()
                observed = self._check(checked_deadline)
                cutoff = started + float(checked_deadline - observed)
                if admit() is not True:
                    raise GenerationRefused("Gemini fixture journal admission is unavailable")
                admitted_until = cutoff
                check_final()

        self._destination_attempts += 1
        try:
            written = self._destination.write(prepared._packet, attempt=self._attempt, deadline=deadline, check=check)
        finally:
            open_check = False
            admit = None
        check_final()
        receipt = self._destination.receipt()
        if (not used_check or type(written) is not int or written != prepared.byte_count
                or type(receipt) is not _SinkReceipt or receipt.attempt is not self._attempt
                or receipt.packet_digest != prepared.packet_digest or not self._destination.confirms_write(receipt)):
            raise GenerationRefused("Gemini fixture dispatch is unconfirmed")
        check_final()
        return GenerationWrite(written, prepared.packet_digest, receipt)

    def observe(self, write):
        """Observe the exact fake reply and retirement outside the shared owner fence."""
        return self._observe(write, check_authority=False)

    def _observe(self, write, *, check_authority):
        with self._fence:
            if (write is None or write is not self._write or not self._active
                    or self._state is not GenerationState.SENT or self._observing or self._completion is not None):
                raise GenerationRefused("Gemini fixture visit changed")
            self._observing = True

        def check(deadline):
            with self._fence:
                if not self._observing or write is not self._write:
                    raise GenerationRefused("Gemini fixture visit changed")
                if check_authority:
                    self._check(deadline)
                else:
                    self._check_local(deadline)

        deadline = self._deadline
        sink_receipt = write.sink_receipt
        try:
            check(deadline)
            reply, eof = self._destination.read(sink_receipt, deadline=deadline, check=check)
            check(deadline)
            validated = validate_generation_reply(reply, end_of_input=eof)
            check(deadline)
            retired = self._destination.retire(sink_receipt, deadline=deadline, check=check)
            check(deadline)
            if not self._destination.confirms_retirement(sink_receipt, retired):
                raise GenerationRefused("Gemini fixture retirement is unconfirmed")
            with self._fence:
                check(deadline)
                self._completion = GenerationCompletion(write, sha256(validated).digest(), retired)
                self._validated = validated
                return self._completion
        except BaseException:
            with self._fence:
                self._hold()
            raise
        finally:
            with self._fence:
                self._observing = False

    def settle(self, write, completion):
        """Release verified bytes to the trusted caller for post-commit delivery."""
        with self._fence:
            if (write is None or write is not self._write or not self._active
                    or self._state is not GenerationState.SENT or self._observing):
                raise GenerationRefused("Gemini fixture settlement is unavailable")
            try:
                if completion is None or completion is not self._completion or completion.write is not write:
                    raise GenerationRefused("Gemini fixture completion changed")
                validated = self._validated
                self._clear_evidence()
                self._check(self._deadline)
                if (completion.reply_digest != sha256(validated).digest()
                        or not self._destination.confirms_write(write.sink_receipt)
                        or not self._destination.confirms_retirement(write.sink_receipt, completion.retirement)):
                    raise GenerationRefused("Gemini fixture retirement is unconfirmed")
                self._check(self._deadline)
                self._releases = 1
                self._active = False
                return validated
            except BaseException:
                self._hold()
                raise
