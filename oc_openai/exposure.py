"""Durable request accounting for the single attended OpenAI acceptance."""

from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
import fcntl
from hashlib import sha256
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
_LOCK = "exposure.lock"
_RUN = re.compile(r"[0-9a-f]{32}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_LOCAL_ID = re.compile(r"[A-Za-z0-9_-]{43}")


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
