"""Durable request accounting for the single attended OpenAI acceptance."""

from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
import fcntl
from hashlib import sha256
import hmac
import json
import os
import re
import secrets
import stat


_INPUT_LIMIT = 922_000
_OUTPUT_LIMIT = 128_000
_MAX_SLOTS = 256
_MAX_BYTES = 128 * 1024
_LEDGER = "exposure.json"
_DIAGNOSTIC = "diagnostic.json"
_STREAM_DIAGNOSTIC = "diagnostic-stream.json"
_RECOVERY_PROOF = "recovery-proof.json"
_RECOVERY_WORKER = "recovery-worker.json"
_RECOVERY_WORKER_PROGRESS = "recovery-worker-progress.json"
_RECOVERY_TRACE = "recovery-worker-trace.json"
_RECOVERY_METADATA = "recovery-worker-metadata.json"
_RECOVERY_MODERATION = "recovery-worker-moderation.json"
_RECOVERY_NAMES = (
    _RECOVERY_PROOF, _RECOVERY_WORKER, _RECOVERY_WORKER_PROGRESS,
    _RECOVERY_TRACE, _RECOVERY_METADATA, _RECOVERY_MODERATION,
)
_CANARY = "canary.json"
_CANARY_RECOVERY = "canary-recovery.json"
_CANARY_E2E = "canary-e2e.json"
_CANARY_NAMES = (_CANARY, _CANARY_RECOVERY, _CANARY_E2E)
_LOCK = "exposure.lock"
_RUN = re.compile(r"[0-9a-f]{32}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_MODEL_SLUG = re.compile(r"[A-Za-z0-9._-]{1,64}\Z", re.ASCII)
_LOCAL_ID = re.compile(r"[A-Za-z0-9_-]{43}")
_DIAG_KEYS = frozenset({"original_run", "binding", "run", "phase", "max_input", "max_output", "actual"})
_STREAM_DIAG_KEYS = _DIAG_KEYS | {"previous_diagnostic_run"}
_RECOVERY_KEYS = frozenset({"version", "prior", "source", "phases"})
_CANARY_REQ_KEYS = frozenset({
    "run_id", "binding", "model", "history_digest", "max_input", "max_output", "actual", "outcome",
})
_CANARY_RECOVERY_EXTRA = frozenset({"prior_canary_run_id", "prior_canary_digest"})
_ERR_INVALID_RECORD = "invalid_exposure_record"


class ExposureError(RuntimeError):
    """An account-bound request slot could not be recorded or settled."""


class Phase(str, Enum):
    ORCHESTRATOR = "orchestrator"
    INITIAL = "initial"
    CONTINUATION = "continuation"


class RecoveryMode(Enum):
    FIRST = "first"
    STREAM = "stream"


_PRECEDING = {
    Phase.INITIAL: Phase.ORCHESTRATOR,
    Phase.CONTINUATION: Phase.INITIAL,
}


def binding_digest(registration: str, generation: str, selection: str | None = None) -> str:
    if (type(registration) is not str or not _LOCAL_ID.fullmatch(registration)
            or type(generation) is not str or not _LOCAL_ID.fullmatch(generation)
            or (selection is not None and (type(selection) is not str or not _LOCAL_ID.fullmatch(selection)))):
        raise ExposureError("invalid_connection_binding")
    return sha256(json.dumps([registration, generation, selection], ensure_ascii=True).encode("ascii")).hexdigest()


@dataclass(frozen=True)
class Slot:
    run_id: str
    binding: str
    phase: Phase


@dataclass(frozen=True)
class ExposureHold:
    blocked: bool
    file_count: int
    unsettled_count: int
    digest: str


@dataclass(frozen=True)
class Diagnostic:
    original: Slot
    request: Slot
    previous: Slot | None = None

    @property
    def stream(self):
        return self.previous is not None


def _private_file(info):
    return (
        stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_uid == os.geteuid() and info.st_nlink == 1
    )


def _valid_slot(slot):
    return (
        type(slot) is Slot and type(slot.run_id) is str and _RUN.fullmatch(slot.run_id)
        and type(slot.binding) is str and _DIGEST.fullmatch(slot.binding) and type(slot.phase) is Phase
    )


def _unique(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError
    return obj


def _bad_constant(_value):
    raise ValueError("non-finite JSON constant")


def _validate_diagnostic_record(name: str, payload) -> tuple[bool, int]:
    expected_keys = _STREAM_DIAG_KEYS if name == _STREAM_DIAGNOSTIC else _DIAG_KEYS
    if type(payload) is not dict or set(payload) != expected_keys:
        raise ExposureError(_ERR_INVALID_RECORD)
    try:
        phase = Phase(payload["phase"])
    except ValueError:
        raise ExposureError(_ERR_INVALID_RECORD) from None
    slot = Slot(payload["run"], payload["binding"], phase)
    valid_orig = type(payload["original_run"]) is str and bool(_RUN.fullmatch(payload["original_run"]))
    valid_prev = (
        name != _STREAM_DIAGNOSTIC
        or (type(payload["previous_diagnostic_run"]) is str
            and bool(_RUN.fullmatch(payload["previous_diagnostic_run"])))
    )
    if (not _valid_slot(slot) or not valid_orig or not valid_prev
            or type(payload["max_input"]) is not int or payload["max_input"] != _INPUT_LIMIT
            or type(payload["max_output"]) is not int or payload["max_output"] != _OUTPUT_LIMIT
            or not _use(payload)):
        raise ExposureError(_ERR_INVALID_RECORD)
    return True, int(payload["actual"] is None)


def _validate_recovery_record(name: str, payload) -> tuple[bool, int]:
    if (type(payload) is not dict or set(payload) != _RECOVERY_KEYS
            or type(payload["version"]) is not int or payload["version"] != 1
            or type(payload["prior"]) is not list
            or any(type(p) is not str or not (_RUN.fullmatch(p) or _DIGEST.fullmatch(p)) for p in payload["prior"])
            or type(payload["source"]) is not str or not _DIGEST.fullmatch(payload["source"])):
        raise ExposureError(_ERR_INVALID_RECORD)
    first = Phase.ORCHESTRATOR if name == _RECOVERY_PROOF else Phase.INITIAL
    try:
        entries = _validate(payload["phases"], first=first)
    except ValueError:
        raise ExposureError(_ERR_INVALID_RECORD) from None
    if not entries:
        raise ExposureError(_ERR_INVALID_RECORD)
    unsettled = sum(1 for entry in entries if entry["actual"] is None)
    return True, unsettled


def _valid_canary_links(record: dict) -> bool:
    prior_run = record.get("prior_canary_run_id")
    prior_digest = record.get("prior_canary_digest")
    return (
        type(prior_run) is str and bool(_RUN.fullmatch(prior_run))
        and prior_run != record["run_id"]
        and type(prior_digest) is str and bool(_DIGEST.fullmatch(prior_digest))
    )


def _valid_canary_strings(record: dict) -> bool:
    return (
        type(record["run_id"]) is str and bool(_RUN.fullmatch(record["run_id"]))
        and type(record["binding"]) is str and bool(_DIGEST.fullmatch(record["binding"]))
        and type(record["model"]) is str and bool(_MODEL_SLUG.fullmatch(record["model"]))
        and type(record["history_digest"]) is str and bool(_DIGEST.fullmatch(record["history_digest"]))
    )


def _validate_canary_fields(record: dict, *, recovery: bool) -> None:
    required = _CANARY_REQ_KEYS | (_CANARY_RECOVERY_EXTRA if recovery else frozenset())
    if not required <= set(record) <= (required | {"delivered"}):
        raise ExposureError(_ERR_INVALID_RECORD)
    delivered = record.get("delivered", False)
    if (type(delivered) is not bool or not _valid_canary_strings(record)
            or record["max_input"] != _INPUT_LIMIT or record["max_output"] != _OUTPUT_LIMIT
            or not _is_usage(record["max_input"]) or not _is_usage(record["max_output"])):
        raise ExposureError(_ERR_INVALID_RECORD)
    if recovery and not _valid_canary_links(record):
        raise ExposureError(_ERR_INVALID_RECORD)


def _validate_settled_canary(record: dict) -> tuple[bool, int]:
    outcome = record["outcome"]
    actual = record["actual"]
    delivered = record.get("delivered", False)
    if (outcome not in ("ok_settled", "refused_settled", "overage_settled")
            or (delivered and outcome != "ok_settled")
            or type(actual) is not list or len(actual) != 2 or not all(_is_usage(v) for v in actual)):
        raise ExposureError(_ERR_INVALID_RECORD)
    is_over = actual[0] > record["max_input"] or actual[1] > record["max_output"]
    if (outcome == "overage_settled") != is_over:
        raise ExposureError(_ERR_INVALID_RECORD)
    return is_over, 0


def _validate_canary_record(name: str, record) -> tuple[bool, int]:
    if type(record) is not dict:
        raise ExposureError(_ERR_INVALID_RECORD)
    _validate_canary_fields(record, recovery=(name == _CANARY_RECOVERY))
    if record["outcome"] == "unsettled":
        if record["actual"] is not None or record.get("delivered", False) is not False:
            raise ExposureError(_ERR_INVALID_RECORD)
        return True, 1
    return _validate_settled_canary(record)


def _is_usage(value):
    return type(value) is int and value >= 0


def _overage(actual):
    return actual is not None and (actual[0] > _INPUT_LIMIT or actual[1] > _OUTPUT_LIMIT)


def _use(record):
    actual = record["actual"]
    return actual is None or (type(actual) is list and len(actual) == 2 and all(map(_is_usage, actual)))


def _validate_record(record, seen, previous, *, first):
    if type(record) is not dict or set(record) != {
        "run", "binding", "phase", "max_input", "max_output", "actual",
    }:
        raise ValueError
    phase = Phase(record["phase"])
    slot = Slot(record["run"], record["binding"], phase)
    if (not _valid_slot(slot) or type(record["max_input"]) is not int
            or type(record["max_output"]) is not int or record["max_input"] != _INPUT_LIMIT
            or record["max_output"] != _OUTPUT_LIMIT or not _use(record)):
        raise ValueError
    if previous is not None and (previous["actual"] is None or _overage(previous["actual"])):
        raise ValueError
    if phase is Phase.ORCHESTRATOR:
        if first is not Phase.ORCHESTRATOR or slot.run_id in seen:
            raise ValueError
        seen.add(slot.run_id)
    elif previous is None:
        if phase is not first:
            raise ValueError
    elif (previous["run"], previous["binding"], previous["phase"]) != (
        slot.run_id, slot.binding, _PRECEDING[phase].value,
    ):
        raise ValueError


def _validate(records, *, first=Phase.ORCHESTRATOR):
    if type(records) is not list or len(records) > _MAX_SLOTS:
        raise ValueError
    seen = set()
    previous = None
    for record in records:
        _validate_record(record, seen, previous, first=first)
        previous = record
    return records


def _diagnostic_receipt(ticket):
    receipt = {
        "original_run": ticket.original.run_id,
        "binding": ticket.request.binding,
        "run": ticket.request.run_id,
        "phase": ticket.request.phase.value,
        "max_input": _INPUT_LIMIT,
        "max_output": _OUTPUT_LIMIT,
        "actual": None,
    }
    if ticket.stream:
        receipt["previous_diagnostic_run"] = ticket.previous.run_id
    return receipt


def _matches_receipt(stored, expected):
    return (
        type(stored) is dict and stored == expected
        and all(type(stored[key]) is type(value) for key, value in expected.items())
    )


class ExposureLedger:
    """The caller provides an owner-only directory verified by the connection store.

    An unsettled send blocks ordinary sends even after restart or account retirement.
    """

    def __init__(self, state_dir):
        self._state_dir = state_dir

    @contextmanager
    def _locked(self):
        directory = lock = None
        try:
            directory = os.open(self._state_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            info = os.fstat(directory)
            if stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.geteuid():
                raise ExposureError("untrusted_exposure_store")
            lock = os.open(
                _LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory
            )
            if not _private_file(os.fstat(lock)):
                raise ExposureError("untrusted_exposure_store")
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield directory
        except OSError:
            raise ExposureError("exposure_store_unavailable") from None
        finally:
            if lock is not None:
                os.close(lock)
            if directory is not None:
                os.close(directory)

    def _load(self, directory, name, *, missing):
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            return missing
        with os.fdopen(fd, "rb") as stream:
            if not _private_file(os.fstat(fd)):
                raise ExposureError("untrusted_exposure_store")
            raw = stream.read(_MAX_BYTES + 1)
        try:
            if len(raw) > _MAX_BYTES:
                raise ValueError
            return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
        except (TypeError, ValueError, RecursionError):
            raise ExposureError("invalid_exposure_record") from None

    def _read(self, directory):
        try:
            return _validate(self._load(directory, _LEDGER, missing=[]))
        except (TypeError, ValueError):
            raise ExposureError("invalid_exposure_record") from None

    def _write(self, directory, data, *, name=_LEDGER):
        temporary = ".exposure-" + secrets.token_hex(16)
        fd = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory
        )
        try:
            with os.fdopen(fd, "w", encoding="ascii") as stream:
                json.dump(data, stream, separators=(",", ":"), ensure_ascii=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass

    @staticmethod
    def _admit(records, slot, *, first=Phase.ORCHESTRATOR):
        if len(records) >= _MAX_SLOTS:
            raise ExposureError("exposure_record_full")
        if records:
            actual = records[-1]["actual"]
            if actual is None:
                raise ExposureError("unsettled_exposure")
            if _overage(actual):
                raise ExposureError("exposure_bound_exceeded")
        record = {
            "run": slot.run_id, "binding": slot.binding, "phase": slot.phase.value,
            "max_input": _INPUT_LIMIT, "max_output": _OUTPUT_LIMIT, "actual": None,
        }
        updated = [*records, record]
        try:
            return _validate(updated, first=first)
        except ValueError:
            raise ExposureError("unapproved_or_replayed_phase") from None

    def _read_verified_hold_file(self, directory, name: str) -> tuple[bytes, object] | None:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        except FileNotFoundError:
            return None
        except OSError:
            raise ExposureError("untrusted_exposure_store") from None
        with os.fdopen(fd, "rb") as stream:
            if not _private_file(os.fstat(fd)):
                raise ExposureError("untrusted_exposure_store")
            raw = stream.read(_MAX_BYTES + 1)
        if len(raw) > _MAX_BYTES:
            raise ExposureError(_ERR_INVALID_RECORD)
        try:
            parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_bad_constant)
        except (TypeError, ValueError, RecursionError):
            raise ExposureError(_ERR_INVALID_RECORD) from None
        return raw, parsed

    def _validate_hold_entry(self, name: str, parsed) -> tuple[bool, int]:
        if name == _LEDGER:
            try:
                records = _validate(parsed)
            except (TypeError, ValueError):
                raise ExposureError(_ERR_INVALID_RECORD) from None
            if not records:
                return False, 0
            actual = records[-1]["actual"]
            if actual is None:
                return True, 1
            return _overage(actual), 0
        if name in _CANARY_NAMES:
            return _validate_canary_record(name, parsed)
        if name in (_DIAGNOSTIC, _STREAM_DIAGNOSTIC):
            return _validate_diagnostic_record(name, parsed)
        return _validate_recovery_record(name, parsed)

    @staticmethod
    def _validate_canary_recovery_link(loaded_files: dict[str, tuple[bytes, object]]) -> None:
        if _CANARY_RECOVERY not in loaded_files:
            return
        canary = loaded_files.get(_CANARY)
        if canary is None:
            raise ExposureError(_ERR_INVALID_RECORD)
        canary_raw, canary_parsed = canary
        _rec_raw, rec_parsed = loaded_files[_CANARY_RECOVERY]
        if (canary_parsed["outcome"] != "unsettled"
                or rec_parsed["prior_canary_run_id"] != canary_parsed["run_id"]
                or rec_parsed["binding"] != canary_parsed["binding"]
                or rec_parsed["model"] != canary_parsed["model"]
                or rec_parsed["history_digest"] != canary_parsed["history_digest"]
                or not hmac.compare_digest(rec_parsed["prior_canary_digest"], sha256(canary_raw).hexdigest())):
            raise ExposureError(_ERR_INVALID_RECORD)

    @staticmethod
    def _validate_diagnostic_links(loaded_files: dict[str, tuple[bytes, object]]) -> None:
        exp = loaded_files.get(_LEDGER)
        if _DIAGNOSTIC in loaded_files:
            if exp is None or not exp[1]:
                raise ExposureError(_ERR_INVALID_RECORD)
            first_entry = exp[1][0]
            diag = loaded_files[_DIAGNOSTIC][1]
            if (diag["original_run"] != first_entry["run"] or diag["run"] == first_entry["run"]
                    or diag["binding"] != first_entry["binding"]):
                raise ExposureError(_ERR_INVALID_RECORD)
        if _STREAM_DIAGNOSTIC in loaded_files:
            diag = loaded_files.get(_DIAGNOSTIC)
            if exp is None or not exp[1] or diag is None:
                raise ExposureError(_ERR_INVALID_RECORD)
            first_entry = exp[1][0]
            prev_run = diag[1]["run"]
            stream = loaded_files[_STREAM_DIAGNOSTIC][1]
            if (stream["original_run"] != first_entry["run"]
                    or stream["previous_diagnostic_run"] != prev_run
                    or stream["binding"] != first_entry["binding"]
                    or stream["run"] in (first_entry["run"], prev_run)):
                raise ExposureError(_ERR_INVALID_RECORD)

    @classmethod
    def _validate_hold_links(cls, loaded_files: dict[str, tuple[bytes, object]]) -> None:
        cls._validate_canary_recovery_link(loaded_files)
        cls._validate_diagnostic_links(loaded_files)

    def _inspect_locked(self, directory) -> ExposureHold:
        names = (_LEDGER, _DIAGNOSTIC, _STREAM_DIAGNOSTIC, *_RECOVERY_NAMES, *_CANARY_NAMES)
        hasher = sha256()
        present = 0
        unsettled = 0
        blocked = False
        loaded_files: dict[str, tuple[bytes, object]] = {}
        for name in names:
            loaded = self._read_verified_hold_file(directory, name)
            if loaded is None:
                hasher.update(name.encode("ascii") + b"\0missing\0")
                continue
            raw, parsed = loaded
            loaded_files[name] = (raw, parsed)
            file_blocked, file_unsettled = self._validate_hold_entry(name, parsed)
            present += 1
            unsettled += file_unsettled
            blocked = blocked or file_blocked
            hasher.update(name.encode("ascii") + b"\0" + sha256(raw).digest())
        self._validate_hold_links(loaded_files)
        if not blocked:
            return ExposureHold(blocked=False, file_count=0, unsettled_count=0, digest="")
        return ExposureHold(blocked=True, file_count=present, unsettled_count=unsettled, digest=hasher.hexdigest())

    def inspect_hold(self) -> ExposureHold:
        """Read-only inspection of whether an I4a/canary exposure hold blocks ordinary sends."""
        with self._locked() as directory:
            return self._inspect_locked(directory)

    @contextmanager
    def dispatch_fence(self, *, acknowledged_digest: str | None = None):
        """Hold non-blocking exposure.lock across hold validation and the bounded first write."""
        with self._locked() as directory:
            hold = self._inspect_locked(directory)
            if hold.blocked:
                if acknowledged_digest is None or type(acknowledged_digest) is not str:
                    raise ExposureError("exposure_hold_active")
                if not hmac.compare_digest(hold.digest, acknowledged_digest):
                    raise ExposureError("exposure_hold_changed")
            yield hold

    def require_dispatch_allowed(self, *, acknowledged_digest: str | None = None) -> None:
        """Atomically enforce the shared exposure hold under non-blocking exposure.lock."""
        with self.dispatch_fence(acknowledged_digest=acknowledged_digest):
            return None

    def require_quiescent(self):
        """Keep a pending possible send from becoming a different account's run."""
        with self._locked() as directory:
            self._require_no_diagnostic(directory)
            records = self._read(directory)
            if records and records[-1]["actual"] is None:
                raise ExposureError("unsettled_exposure")

    def require_next(self, slot: Slot):
        """Check the expected phase without consuming an inference slot."""
        if not _valid_slot(slot):
            raise ExposureError("invalid_exposure_slot")
        with self._locked() as directory:
            self._require_no_diagnostic(directory)
            self._admit(self._read(directory), slot)

    def reserve(self, slot: Slot):
        if not _valid_slot(slot):
            raise ExposureError("invalid_exposure_slot")
        with self._locked() as directory:
            self._require_no_diagnostic(directory)
            self._write(directory, self._admit(self._read(directory), slot))

    def settle(self, slot: Slot, input_tokens: int, output_tokens: int):
        if (not _valid_slot(slot) or not _is_usage(input_tokens)
                or not _is_usage(output_tokens)):
            raise ExposureError("invalid_terminal_usage")
        with self._locked() as directory:
            self._require_no_diagnostic(directory)
            records = self._read(directory)
            if not records:
                raise ExposureError("unmatched_exposure_settlement")
            record = records[-1]
            if (record["run"], record["binding"], record["phase"], record["actual"]) != (
                slot.run_id, slot.binding, slot.phase.value, None
            ):
                raise ExposureError("unmatched_exposure_settlement")
            record["actual"] = [input_tokens, output_tokens]
            self._write(directory, records)
        if _overage(record["actual"]):
            raise ExposureError("exposure_bound_exceeded")

    @staticmethod
    def _require_no_diagnostic(directory, *, stream=False):
        names = (_STREAM_DIAGNOSTIC, *_RECOVERY_NAMES)
        if not stream:
            names = (_DIAGNOSTIC, *names)
        for name in names:
            try:
                os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            # Presence alone spends the exception, including a corrupt receipt.
            raise ExposureError("diagnostic_already_reserved")

    def _diagnostic(self, directory, slot, *, stream=False):
        if not _valid_slot(slot) or slot.phase is not Phase.ORCHESTRATOR:
            raise ExposureError("diagnostic_unavailable")
        records = self._read(directory)
        if len(records) != 1:
            raise ExposureError("diagnostic_unavailable")
        held = records[0]
        if (held["phase"] != Phase.ORCHESTRATOR.value or held["actual"] is not None
                or held["run"] == slot.run_id or held["binding"] != slot.binding):
            raise ExposureError("diagnostic_unavailable")
        original = Slot(held["run"], held["binding"], Phase.ORCHESTRATOR)
        if not stream:
            return Diagnostic(original, slot)

        stored = self._load(directory, _DIAGNOSTIC, missing=None)
        if type(stored) is not dict:
            raise ExposureError("diagnostic_unavailable")
        previous = Slot(stored.get("run"), slot.binding, Phase.ORCHESTRATOR)
        if (not _valid_slot(previous) or previous in (original, slot)
                or not _matches_receipt(stored, _diagnostic_receipt(Diagnostic(original, previous)))):
            raise ExposureError("diagnostic_unavailable")
        return Diagnostic(original, slot, previous)

    def prepare_diagnostic(self, slot, *, stream=False):
        with self._locked() as directory:
            self._require_no_diagnostic(directory, stream=stream)
            return self._diagnostic(directory, slot, stream=stream)

    def _check_diagnostic(self, directory, ticket):
        if (type(ticket) is not Diagnostic
                or self._diagnostic(directory, ticket.request, stream=ticket.stream) != ticket):
            raise ExposureError("diagnostic_unavailable")

    def reserve_diagnostic(self, ticket):
        with self._locked() as directory:
            self._check_diagnostic(directory, ticket)
            self._require_no_diagnostic(directory, stream=ticket.stream)
            name = _STREAM_DIAGNOSTIC if ticket.stream else _DIAGNOSTIC
            self._write(directory, _diagnostic_receipt(ticket), name=name)

    def settle_diagnostic(self, ticket, input_tokens, output_tokens):
        if not _is_usage(input_tokens) or not _is_usage(output_tokens):
            raise ExposureError("invalid_terminal_usage")
        with self._locked() as directory:
            self._check_diagnostic(directory, ticket)
            if ticket.stream:
                # After a recovery proof starts, these receipts are its immutable history.
                for name in _RECOVERY_NAMES:
                    try:
                        os.stat(name, dir_fd=directory, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    raise ExposureError("diagnostic_already_reserved")
            if not ticket.stream:
                self._require_no_diagnostic(directory, stream=True)
            expected = _diagnostic_receipt(ticket)
            name = _STREAM_DIAGNOSTIC if ticket.stream else _DIAGNOSTIC
            if not _matches_receipt(self._load(directory, name, missing=None), expected):
                raise ExposureError("unmatched_exposure_settlement")
            actual = [input_tokens, output_tokens]
            self._write(directory, {**expected, "actual": actual}, name=name)
        if _overage(actual):
            raise ExposureError("exposure_bound_exceeded")
