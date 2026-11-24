"""Shared single-use durable ledger and read-only I4a history inspection for the canary."""

from contextlib import contextmanager
from dataclasses import dataclass
import errno
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import stat

from .exposure import (
    _DIAGNOSTIC,
    _INPUT_LIMIT,
    _LEDGER,
    _LOCK,
    _MAX_BYTES,
    _OUTPUT_LIMIT,
    _RECOVERY_NAMES,
    _STREAM_DIAGNOSTIC,
    _is_usage,
    _private_file,
    _unique,
)


CANARY_FILE = "canary.json"
CANARY_LOCK = "canary.lock"
I4A_HOLD_FILES = (_LEDGER, _DIAGNOSTIC, _STREAM_DIAGNOSTIC, *_RECOVERY_NAMES)
_RUN_RE = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MODEL_RE = re.compile(r"[A-Za-z0-9._-]{1,64}\Z", re.ASCII)
_OUTCOME_UNSETTLED = "unsettled"
_OUTCOME_OK = "ok_settled"
_OUTCOME_REFUSED = "refused_settled"
_OUTCOME_OVERAGE = "overage_settled"
_SETTLED_OUTCOMES = frozenset({_OUTCOME_OK, _OUTCOME_REFUSED, _OUTCOME_OVERAGE})
_ERR_STORAGE = "canary_storage_unavailable"


class CanaryLedgerError(RuntimeError):
    """Raised when canary accounting, history, or single-use state fails closed."""


@dataclass(frozen=True)
class HistorySnapshot:
    digest: str
    present_files: tuple[str, ...]
    record_count: int
    unsettled_count: int
    reserved_input: int
    reserved_output: int


def _open_state_dir(root: Path) -> int:
    try:
        os.makedirs(root, mode=0o700, exist_ok=True)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        dir_fd = os.open(root, flags)
    except OSError:
        raise CanaryLedgerError(_ERR_STORAGE) from None
    try:
        info = os.fstat(dir_fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise CanaryLedgerError(_ERR_STORAGE)
        return dir_fd
    except BaseException:
        os.close(dir_fd)
        raise


def _read_private_bytes(dir_fd: int, name: str) -> bytes | None:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
    except FileNotFoundError:
        return None
    except OSError:
        raise CanaryLedgerError(_ERR_STORAGE) from None
    try:
        info = os.fstat(fd)
        if not _private_file(info) or info.st_size > _MAX_BYTES:
            raise CanaryLedgerError(_ERR_STORAGE)
        chunks = []
        total = 0
        while True:
            block = os.read(fd, 8192)
            if not block:
                return b"".join(chunks)
            total += len(block)
            if total > _MAX_BYTES:
                raise CanaryLedgerError(_ERR_STORAGE)
            chunks.append(block)
    except OSError:
        raise CanaryLedgerError(_ERR_STORAGE) from None
    finally:
        os.close(fd)


def _decode_json_bytes(raw: bytes):
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeDecodeError, ValueError):
        raise CanaryLedgerError("canary_history_corrupt") from None


def _tally_entry(entry: dict) -> tuple[int, int, int, int]:
    if type(entry) is not dict:
        raise CanaryLedgerError("canary_history_corrupt")
    max_in = entry.get("max_input", _INPUT_LIMIT)
    max_out = entry.get("max_output", _OUTPUT_LIMIT)
    if not _is_usage(max_in) or not _is_usage(max_out):
        raise CanaryLedgerError("canary_history_corrupt")
    actual = entry.get("actual")
    if actual is None:
        return 1, 1, max_in, max_out
    if type(actual) is list and len(actual) == 2 and all(_is_usage(v) for v in actual):
        return 1, 0, actual[0], actual[1]
    raise CanaryLedgerError("canary_history_corrupt")


def _tally_i4a_payload(name: str, payload) -> tuple[int, int, int, int]:
    if name == _LEDGER:
        if type(payload) is not list:
            raise CanaryLedgerError("canary_history_corrupt")
        entries = payload
    elif name in (_DIAGNOSTIC, _STREAM_DIAGNOSTIC):
        entries = [payload]
    else:
        if type(payload) is not dict or type(payload.get("phases")) is not list:
            raise CanaryLedgerError("canary_history_corrupt")
        entries = payload["phases"]
    records = unsettled = res_in = res_out = 0
    for entry in entries:
        r, u, i_tok, o_tok = _tally_entry(entry)
        records += r
        unsettled += u
        res_in += i_tok
        res_out += o_tok
    return records, unsettled, res_in, res_out


def _inspect_history_fd(dir_fd: int) -> HistorySnapshot:
    hasher = sha256()
    present = []
    records = unsettled = res_in = res_out = 0
    for name in I4A_HOLD_FILES:
        raw = _read_private_bytes(dir_fd, name)
        if raw is None:
            continue
        payload = _decode_json_bytes(raw)
        r, u, i_tok, o_tok = _tally_i4a_payload(name, payload)
        present.append(name)
        records += r
        unsettled += u
        res_in += i_tok
        res_out += o_tok
        hasher.update(name.encode("ascii") + b"\0" + str(len(raw)).encode("ascii") + b"\0" + raw + b"\0")
    return HistorySnapshot(
        digest=hasher.hexdigest(),
        present_files=tuple(present),
        record_count=records,
        unsettled_count=unsettled,
        reserved_input=res_in,
        reserved_output=res_out,
    )


def inspect_i4a_history(root: Path) -> HistorySnapshot:
    """Strictly read-only inspection of all 9 I4a hold files in shared state."""
    dir_fd = _open_state_dir(Path(root))
    try:
        return _inspect_history_fd(dir_fd)
    finally:
        os.close(dir_fd)


def _valid_canary_record(record) -> bool:
    if type(record) is not dict:
        return False
    required = {"run_id", "binding", "model", "history_digest", "max_input", "max_output", "actual", "outcome"}
    if not required <= set(record) <= (required | {"delivered"}):
        return False
    if (type(record["run_id"]) is not str or not _RUN_RE.fullmatch(record["run_id"])
            or type(record["binding"]) is not str or not _DIGEST_RE.fullmatch(record["binding"])
            or type(record["model"]) is not str or not _MODEL_RE.fullmatch(record["model"])
            or type(record["history_digest"]) is not str or not _DIGEST_RE.fullmatch(record["history_digest"])
            or not _is_usage(record["max_input"]) or not _is_usage(record["max_output"])):
        return False
    outcome = record["outcome"]
    actual = record["actual"]
    if outcome == _OUTCOME_UNSETTLED:
        return actual is None
    return (
        outcome in _SETTLED_OUTCOMES
        and type(actual) is list and len(actual) == 2
        and all(_is_usage(v) for v in actual)
    )


def _atomic_write_json(dir_fd: int, name: str, payload: dict) -> None:
    encoded = (json.dumps(payload, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")
    tmp_name = f".{name}.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(tmp_name, flags, 0o600, dir_fd=dir_fd)
    except OSError:
        raise CanaryLedgerError(_ERR_STORAGE) from None
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(encoded)
        written = 0
        while written < len(encoded):
            written += os.write(fd, view[written:])
        os.fsync(fd)
    except OSError:
        os.close(fd)
        try:
            os.unlink(tmp_name, dir_fd=dir_fd)
        except OSError:
            pass
        raise CanaryLedgerError(_ERR_STORAGE) from None
    os.close(fd)
    try:
        os.replace(tmp_name, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        os.fsync(dir_fd)
    except OSError:
        try:
            os.unlink(tmp_name, dir_fd=dir_fd)
        except OSError:
            pass
        raise CanaryLedgerError(_ERR_STORAGE) from None


def _refuse_existing_canary(raw: bytes) -> None:
    try:
        record = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeDecodeError, ValueError):
        raise CanaryLedgerError(_ERR_STORAGE) from None
    if not _valid_canary_record(record):
        raise CanaryLedgerError(_ERR_STORAGE)
    if record["outcome"] == _OUTCOME_UNSETTLED:
        raise CanaryLedgerError("canary_unsettled_hold")
    raise CanaryLedgerError("canary_already_spent")


class CanaryLedger:
    """Shared single-use durable canary ledger serialized under exposure.lock."""

    def __init__(self, root: Path, *, max_input: int = _INPUT_LIMIT, max_output: int = _OUTPUT_LIMIT):
        self.root = Path(root)
        self.max_input = max_input
        self.max_output = max_output

    @contextmanager
    def _locked(self, *, lock_name: str = _LOCK, blocking: bool = True):
        dir_fd = _open_state_dir(self.root)
        lock_fd = None
        try:
            flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
            lock_fd = os.open(lock_name, flags, 0o600, dir_fd=dir_fd)
            info = os.fstat(lock_fd)
            if not _private_file(info):
                raise CanaryLedgerError(_ERR_STORAGE)
            mode = fcntl.LOCK_EX if blocking else (fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                fcntl.flock(lock_fd, mode)
            except OSError as error:
                if error.errno in (errno.EAGAIN, errno.EACCES):
                    raise CanaryLedgerError("canary_busy") from None
                raise CanaryLedgerError(_ERR_STORAGE) from None
            yield dir_fd
        except OSError:
            raise CanaryLedgerError(_ERR_STORAGE) from None
        finally:
            if lock_fd is not None:
                os.close(lock_fd)
            os.close(dir_fd)

    @contextmanager
    def exclusive_run(self):
        """Serialize whole canary invocations via non-blocking canary.lock."""
        with self._locked(lock_name=CANARY_LOCK, blocking=False):
            yield

    def preflight(self) -> HistorySnapshot:
        """Verify no prior canary slot exists and snapshot all 9 I4a hold files."""
        with self._locked(blocking=False) as dir_fd:
            existing = _read_private_bytes(dir_fd, CANARY_FILE)
            if existing is not None:
                _refuse_existing_canary(existing)
            return _inspect_history_fd(dir_fd)

    def reserve(self, run_id: str, binding: str, model: str, history_digest: str) -> None:
        """Durably reserve the single canary slot before any upstream write."""
        if (type(run_id) is not str or not _RUN_RE.fullmatch(run_id)
                or type(binding) is not str or not _DIGEST_RE.fullmatch(binding)
                or type(model) is not str or not _MODEL_RE.fullmatch(model)
                or type(history_digest) is not str or not _DIGEST_RE.fullmatch(history_digest)):
            raise CanaryLedgerError("canary_invalid_reservation")
        with self._locked(blocking=True) as dir_fd:
            existing = _read_private_bytes(dir_fd, CANARY_FILE)
            if existing is not None:
                _refuse_existing_canary(existing)
            current = _inspect_history_fd(dir_fd)
            if current.digest != history_digest:
                raise CanaryLedgerError("canary_history_changed")
            record = {
                "run_id": run_id,
                "binding": binding,
                "model": model,
                "history_digest": history_digest,
                "max_input": self.max_input,
                "max_output": self.max_output,
                "actual": None,
                "outcome": _OUTCOME_UNSETTLED,
                "delivered": False,
            }
            _atomic_write_json(dir_fd, CANARY_FILE, record)

    def _load_matching_unsettled(self, dir_fd: int, run_id: str) -> dict:
        raw = _read_private_bytes(dir_fd, CANARY_FILE)
        if raw is None:
            raise CanaryLedgerError("canary_missing_reservation")
        record = _decode_json_bytes(raw)
        if not _valid_canary_record(record) or record["run_id"] != run_id:
            raise CanaryLedgerError("canary_unmatched_settlement")
        if record["outcome"] != _OUTCOME_UNSETTLED:
            raise CanaryLedgerError("canary_already_settled")
        return record

    def settle(self, run_id: str, *, allow_delivery: bool, input_tokens: int, output_tokens: int) -> str:
        """Durably settle verified usage independently of delivery permission."""
        if not _is_usage(input_tokens) or not _is_usage(output_tokens):
            raise CanaryLedgerError("canary_invalid_usage")
        with self._locked(blocking=True) as dir_fd:
            record = self._load_matching_unsettled(dir_fd, run_id)
            over = input_tokens > record["max_input"] or output_tokens > record["max_output"]
            if over:
                outcome = _OUTCOME_OVERAGE
            elif allow_delivery:
                outcome = _OUTCOME_OK
            else:
                outcome = _OUTCOME_REFUSED
            record["actual"] = [input_tokens, output_tokens]
            record["outcome"] = outcome
            _atomic_write_json(dir_fd, CANARY_FILE, record)
            return outcome

    def mark_delivered(self, run_id: str) -> None:
        """Record milestone delivery only after OpenCode exits 0 with one visible ok."""
        with self._locked(blocking=True) as dir_fd:
            raw = _read_private_bytes(dir_fd, CANARY_FILE)
            if raw is None:
                raise CanaryLedgerError("canary_missing_reservation")
            record = _decode_json_bytes(raw)
            if not _valid_canary_record(record) or record["run_id"] != run_id or record["outcome"] != _OUTCOME_OK:
                raise CanaryLedgerError("canary_unmatched_settlement")
            record["delivered"] = True
            _atomic_write_json(dir_fd, CANARY_FILE, record)
