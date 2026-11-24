"""Shared single-use durable ledger and read-only I4a history inspection for the canary."""

from contextlib import contextmanager
from dataclasses import dataclass
import errno
import fcntl
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import time

from .connection_state import ConnectionError as StateError, _directory
from .exposure import (
    Phase,
    Slot,
    _DIAGNOSTIC,
    _DIGEST,
    _INPUT_LIMIT,
    _LEDGER,
    _LOCK,
    _MAX_BYTES,
    _OUTPUT_LIMIT,
    _RECOVERY_NAMES,
    _RECOVERY_PROOF,
    _RUN,
    _STREAM_DIAGNOSTIC,
    _is_usage,
    _private_file,
    _unique,
    _use,
    _valid_slot,
    _validate,
)


CANARY_FILE = "canary.json"
CANARY_RECOVERY_FILE = "canary-recovery.json"
CANARY_E2E_FILE = "canary-e2e.json"
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
_ERR_CORRUPT = "canary_history_corrupt"
_ERR_UNSETTLED_HOLD = "canary_unsettled_hold"
_ERR_OVERAGE_HOLD = "canary_overage_hold"
_ERR_INVALID_RES = "canary_invalid_reservation"
_ERR_HISTORY_CHANGED = "canary_history_changed"
_ERR_MISSING = "canary_missing_reservation"
_ERR_UNMATCHED = "canary_unmatched_settlement"
_ERR_ALREADY_SETTLED = "canary_already_settled"
_ERR_INVALID_USAGE = "canary_invalid_usage"
_DIAG_KEYS = frozenset({"original_run", "binding", "run", "phase", "max_input", "max_output", "actual"})
_STREAM_DIAG_KEYS = _DIAG_KEYS | {"previous_diagnostic_run"}
_RECOVERY_KEYS = frozenset({"version", "prior", "source", "phases"})
_EMPTY_HISTORY_DIGEST = sha256(b"").hexdigest()


class CanaryLedgerError(RuntimeError):
    """Raised when canary accounting, history, or single-use state fails closed."""


@dataclass(frozen=True)
class HistorySnapshot:
    digest: str
    present_files: tuple[str, ...]
    record_count: int
    unsettled_count: int
    settled_input: int
    settled_output: int
    unsettled_input: int
    unsettled_output: int
    reserved_input: int
    reserved_output: int


@dataclass(frozen=True)
class RecoverySnapshot:
    history: HistorySnapshot
    prior_run_id: str
    prior_digest: str
    prior_max_input: int
    prior_max_output: int


def _bad_constant(_value):
    raise ValueError("non-finite JSON constant")


def _open_state_dir(root: Path, *, create: bool) -> int | None:
    try:
        return _directory(Path(root), create=create)
    except FileNotFoundError:
        if not create:
            return None
        raise CanaryLedgerError(_ERR_STORAGE) from None
    except (OSError, StateError):
        raise CanaryLedgerError(_ERR_STORAGE) from None


def _read_private_bytes(dir_fd: int, name: str) -> bytes | None:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
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


def _decode_json_bytes(raw: bytes, *, err_code: str = _ERR_CORRUPT):
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_bad_constant)
    except ValueError:
        raise CanaryLedgerError(err_code) from None


def _validate_diagnostic_entry(name: str, payload) -> list[dict]:
    expected_keys = _STREAM_DIAG_KEYS if name == _STREAM_DIAGNOSTIC else _DIAG_KEYS
    if type(payload) is not dict or set(payload) != expected_keys:
        raise CanaryLedgerError(_ERR_CORRUPT)
    try:
        phase = Phase(payload["phase"])
    except ValueError:
        raise CanaryLedgerError(_ERR_CORRUPT) from None
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
        raise CanaryLedgerError(_ERR_CORRUPT)
    return [payload]


def _validate_recovery_payload(name: str, payload) -> list[dict]:
    if (type(payload) is not dict or set(payload) != _RECOVERY_KEYS
            or type(payload["version"]) is not int or payload["version"] != 1
            or type(payload["prior"]) is not list
            or any(type(p) is not str or not (_RUN.fullmatch(p) or _DIGEST.fullmatch(p)) for p in payload["prior"])
            or type(payload["source"]) is not str or not _DIGEST.fullmatch(payload["source"])):
        raise CanaryLedgerError(_ERR_CORRUPT)
    first = Phase.ORCHESTRATOR if name == _RECOVERY_PROOF else Phase.INITIAL
    try:
        entries = _validate(payload["phases"], first=first)
    except ValueError:
        raise CanaryLedgerError(_ERR_CORRUPT) from None
    if not entries:
        raise CanaryLedgerError(_ERR_CORRUPT)
    return entries


def _validate_i4a_entries(name: str, payload) -> list[dict]:
    if name == _LEDGER:
        try:
            return _validate(payload)
        except ValueError:
            raise CanaryLedgerError(_ERR_CORRUPT) from None
    if name in (_DIAGNOSTIC, _STREAM_DIAGNOSTIC):
        return _validate_diagnostic_entry(name, payload)
    return _validate_recovery_payload(name, payload)


def _tally_entries(entries: list[dict]) -> tuple[int, int, int, int, int, int, int, int]:
    records = unsettled = s_in = s_out = u_in = u_out = r_in = r_out = 0
    for entry in entries:
        records += 1
        max_in, max_out = entry["max_input"], entry["max_output"]
        r_in += max_in
        r_out += max_out
        actual = entry["actual"]
        if actual is None:
            unsettled += 1
            u_in += max_in
            u_out += max_out
        else:
            s_in += actual[0]
            s_out += actual[1]
    return records, unsettled, s_in, s_out, u_in, u_out, r_in, r_out


def _inspect_history_fd(dir_fd: int) -> HistorySnapshot:
    hasher = sha256()
    present = []
    totals = [0, 0, 0, 0, 0, 0, 0, 0]
    for name in I4A_HOLD_FILES:
        raw = _read_private_bytes(dir_fd, name)
        if raw is None:
            continue
        payload = _decode_json_bytes(raw)
        entries = _validate_i4a_entries(name, payload)
        counts = _tally_entries(entries)
        present.append(name)
        for idx, value in enumerate(counts):
            totals[idx] += value
        hasher.update(name.encode("ascii") + b"\0" + str(len(raw)).encode("ascii") + b"\0" + raw + b"\0")
    return HistorySnapshot(
        digest=hasher.hexdigest(),
        present_files=tuple(present),
        record_count=totals[0],
        unsettled_count=totals[1],
        settled_input=totals[2],
        settled_output=totals[3],
        unsettled_input=totals[4],
        unsettled_output=totals[5],
        reserved_input=totals[6],
        reserved_output=totals[7],
    )


def inspect_i4a_history(root: Path) -> HistorySnapshot:
    """Strictly read-only inspection of all 9 I4a hold files without creating directories."""
    dir_fd = _open_state_dir(Path(root), create=False)
    if dir_fd is None:
        return HistorySnapshot(_EMPTY_HISTORY_DIGEST, (), 0, 0, 0, 0, 0, 0, 0, 0)
    try:
        return _inspect_history_fd(dir_fd)
    finally:
        os.close(dir_fd)


def _valid_recovery_links(record: dict) -> bool:
    prior_run = record.get("prior_canary_run_id")
    prior_digest = record.get("prior_canary_digest")
    return (
        type(prior_run) is str and bool(_RUN_RE.fullmatch(prior_run))
        and prior_run != record["run_id"]
        and type(prior_digest) is str and bool(_DIGEST_RE.fullmatch(prior_digest))
    )


def _valid_canary_settled(record: dict, *, delivered: bool, max_input: int, max_output: int) -> bool:
    outcome = record["outcome"]
    actual = record["actual"]
    if outcome == _OUTCOME_UNSETTLED:
        return actual is None and delivered is False
    if (outcome not in _SETTLED_OUTCOMES
            or (delivered and outcome != _OUTCOME_OK)
            or type(actual) is not list or len(actual) != 2
            or not all(_is_usage(v) for v in actual)):
        return False
    return (outcome == _OUTCOME_OVERAGE) == (actual[0] > max_input or actual[1] > max_output)


def _valid_canary_record(
    record,
    *,
    recovery: bool = False,
    max_input: int = _INPUT_LIMIT,
    max_output: int = _OUTPUT_LIMIT,
) -> bool:
    if type(record) is not dict:
        return False
    required = {"run_id", "binding", "model", "history_digest", "max_input", "max_output", "actual", "outcome"}
    if recovery:
        required |= {"prior_canary_run_id", "prior_canary_digest"}
    if not required <= set(record) <= (required | {"delivered"}):
        return False
    delivered = record.get("delivered", False)
    if type(delivered) is not bool:
        return False
    if (type(record["run_id"]) is not str or not _RUN_RE.fullmatch(record["run_id"])
            or type(record["binding"]) is not str or not _DIGEST_RE.fullmatch(record["binding"])
            or type(record["model"]) is not str or not _MODEL_RE.fullmatch(record["model"])
            or type(record["history_digest"]) is not str or not _DIGEST_RE.fullmatch(record["history_digest"])
            or not _is_usage(record["max_input"]) or not _is_usage(record["max_output"])
            or record["max_input"] != max_input or record["max_output"] != max_output):
        return False
    if recovery and not _valid_recovery_links(record):
        return False
    return _valid_canary_settled(record, delivered=delivered, max_input=max_input, max_output=max_output)


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


def _refuse_existing_canary(
    raw: bytes, *, recovery: bool = False, max_input: int = _INPUT_LIMIT, max_output: int = _OUTPUT_LIMIT,
) -> None:
    record = _decode_json_bytes(raw, err_code=_ERR_STORAGE)
    if not _valid_canary_record(record, recovery=recovery, max_input=max_input, max_output=max_output):
        raise CanaryLedgerError(_ERR_STORAGE)
    if recovery:
        raise CanaryLedgerError("canary_recovery_already_used")
    if record["outcome"] == _OUTCOME_UNSETTLED:
        raise CanaryLedgerError(_ERR_UNSETTLED_HOLD)
    raise CanaryLedgerError("canary_already_spent")


def _require_settled_in_bounds(
    record: dict, *, max_input: int = _INPUT_LIMIT, max_output: int = _OUTPUT_LIMIT,
) -> None:
    if record["max_input"] != max_input or record["max_output"] != max_output:
        raise CanaryLedgerError(_ERR_STORAGE)
    if record["outcome"] == _OUTCOME_UNSETTLED:
        raise CanaryLedgerError(_ERR_UNSETTLED_HOLD)
    if record["outcome"] == _OUTCOME_OVERAGE:
        raise CanaryLedgerError(_ERR_OVERAGE_HOLD)
    actual = record["actual"]
    if actual[0] > max_input or actual[1] > max_output:
        raise CanaryLedgerError(_ERR_OVERAGE_HOLD)


def _check_e2e_record(
    dir_fd: int, *, run_id: str | None = None, max_input: int = _INPUT_LIMIT, max_output: int = _OUTPUT_LIMIT,
) -> None:
    raw = _read_private_bytes(dir_fd, CANARY_E2E_FILE)
    if raw is None:
        return
    record = _decode_json_bytes(raw, err_code=_ERR_STORAGE)
    if not _valid_canary_record(record, recovery=False, max_input=max_input, max_output=max_output):
        raise CanaryLedgerError(_ERR_STORAGE)
    _require_settled_in_bounds(record, max_input=max_input, max_output=max_output)
    if run_id is not None and record["run_id"] == run_id:
        raise CanaryLedgerError(_ERR_INVALID_RES)


def _load_optional_canary(
    dir_fd: int, name: str, *, recovery: bool, max_input: int = _INPUT_LIMIT, max_output: int = _OUTPUT_LIMIT,
) -> tuple[bytes, dict] | None:
    raw = _read_private_bytes(dir_fd, name)
    if raw is None:
        return None
    record = _decode_json_bytes(raw, err_code=_ERR_STORAGE)
    if not _valid_canary_record(record, recovery=recovery, max_input=max_input, max_output=max_output):
        raise CanaryLedgerError(_ERR_STORAGE)
    return raw, record


def _check_readonly_canary_files(
    dir_fd: int, *, max_input: int = _INPUT_LIMIT, max_output: int = _OUTPUT_LIMIT,
) -> None:
    primary = _load_optional_canary(dir_fd, CANARY_FILE, recovery=False, max_input=max_input, max_output=max_output)
    recovery = _load_optional_canary(
        dir_fd, CANARY_RECOVERY_FILE, recovery=True, max_input=max_input, max_output=max_output,
    )
    if recovery is not None:
        if primary is None:
            raise CanaryLedgerError(_ERR_STORAGE)
        canary_raw, canary = primary
        _rec_raw, rec = recovery
        if (canary["outcome"] != _OUTCOME_UNSETTLED
                or rec["prior_canary_run_id"] != canary["run_id"]
                or rec["binding"] != canary["binding"]
                or rec["model"] != canary["model"]
                or rec["history_digest"] != canary["history_digest"]
                or not hmac.compare_digest(rec["prior_canary_digest"], sha256(canary_raw).hexdigest())):
            raise CanaryLedgerError(_ERR_STORAGE)
        _require_settled_in_bounds(rec, max_input=max_input, max_output=max_output)
        return
    if primary is not None:
        _require_settled_in_bounds(primary[1], max_input=max_input, max_output=max_output)


def _load_eligible_prior_canary(
    dir_fd: int,
    *,
    binding: str,
    model: str,
    history_digest: str,
    max_input: int,
    max_output: int,
    expected_prior: tuple[str, str],
) -> tuple[dict, str]:
    raw = _read_private_bytes(dir_fd, CANARY_FILE)
    if raw is None:
        raise CanaryLedgerError("canary_recovery_no_prior")
    prior_digest = sha256(raw).hexdigest()
    record = _decode_json_bytes(raw, err_code=_ERR_STORAGE)
    expected_run_id, expected_digest = expected_prior
    if (not _valid_canary_record(record, max_input=max_input, max_output=max_output)
            or record["outcome"] != _OUTCOME_UNSETTLED
            or record["actual"] is not None
            or record.get("delivered") is not False
            or record["run_id"] != expected_run_id
            or prior_digest != expected_digest
            or record["binding"] != binding
            or record["model"] != model
            or record["max_input"] != max_input
            or record["max_output"] != max_output
            or record["history_digest"] != history_digest):
        raise CanaryLedgerError("canary_recovery_ineligible")
    return record, prior_digest


def _try_flock_nb(lock_fd: int) -> bool:
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError as error:
        if error.errno in (errno.EAGAIN, errno.EACCES):
            return False
        raise CanaryLedgerError(_ERR_STORAGE) from None


def _acquire_flock(lock_fd: int, *, blocking: bool, deadline: float | None, check_alive) -> None:
    if not blocking:
        if not _try_flock_nb(lock_fd):
            raise CanaryLedgerError("canary_busy")
        return
    while True:
        if check_alive is not None:
            check_alive()
        if _try_flock_nb(lock_fd):
            return
        pause = 0.05
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CanaryLedgerError("canary_lock_timeout")
            pause = min(pause, remaining)
        time.sleep(pause)


class CanaryLedger:
    """Shared single-use durable canary ledger serialized under exposure.lock."""

    def __init__(self, root: Path, *, max_input: int = _INPUT_LIMIT, max_output: int = _OUTPUT_LIMIT):
        self.root = Path(root)
        self.max_input = max_input
        self.max_output = max_output

    @contextmanager
    def _locked(self, *, lock_name: str = _LOCK, blocking: bool = True,
                deadline: float | None = None, check_alive=None):
        dir_fd = _open_state_dir(self.root, create=True)
        lock_fd = None
        try:
            try:
                flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
                lock_fd = os.open(lock_name, flags, 0o600, dir_fd=dir_fd)
                info = os.fstat(lock_fd)
                if not _private_file(info):
                    raise CanaryLedgerError(_ERR_STORAGE)
                _acquire_flock(lock_fd, blocking=blocking, deadline=deadline, check_alive=check_alive)
            except OSError:
                raise CanaryLedgerError(_ERR_STORAGE) from None
            yield dir_fd
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
        """Verify no prior canary or recovery slot exists and snapshot all 9 I4a hold files."""
        with self._locked(blocking=False) as dir_fd:
            _check_e2e_record(dir_fd, max_input=self.max_input, max_output=self.max_output)
            existing = _read_private_bytes(dir_fd, CANARY_FILE)
            if existing is not None:
                _refuse_existing_canary(existing, max_input=self.max_input, max_output=self.max_output)
            existing_rec = _read_private_bytes(dir_fd, CANARY_RECOVERY_FILE)
            if existing_rec is not None:
                _refuse_existing_canary(existing_rec, recovery=True, max_input=self.max_input, max_output=self.max_output)
            return _inspect_history_fd(dir_fd)

    def preflight_recovery(
        self,
        binding: str,
        model: str,
        *,
        expected_prior: tuple[str, str] | None = None,
    ) -> RecoverySnapshot:
        """Verify exact reviewed unsettled canary.json predecessor and absent canary-recovery.json."""
        if (type(binding) is not str or not _DIGEST_RE.fullmatch(binding)
                or type(model) is not str or not _MODEL_RE.fullmatch(model)):
            raise CanaryLedgerError("canary_recovery_ineligible")
        if expected_prior is None:
            raise CanaryLedgerError("canary_recovery_ineligible")
        pinned = expected_prior
        with self._locked(blocking=False) as dir_fd:
            _check_e2e_record(dir_fd, max_input=self.max_input, max_output=self.max_output)
            existing_rec = _read_private_bytes(dir_fd, CANARY_RECOVERY_FILE)
            if existing_rec is not None:
                _refuse_existing_canary(existing_rec, recovery=True, max_input=self.max_input, max_output=self.max_output)
            history = _inspect_history_fd(dir_fd)
            prior, prior_digest = _load_eligible_prior_canary(
                dir_fd, binding=binding, model=model, history_digest=history.digest,
                max_input=self.max_input, max_output=self.max_output, expected_prior=pinned,
            )
            return RecoverySnapshot(
                history=history,
                prior_run_id=prior["run_id"],
                prior_digest=prior_digest,
                prior_max_input=prior["max_input"],
                prior_max_output=prior["max_output"],
            )

    def reserve(self, run_id: str, binding: str, model: str, history_digest: str, *,
                deadline: float | None = None, check_alive=None) -> None:
        """Durably reserve the single canary slot before any upstream write."""
        if (type(run_id) is not str or not _RUN_RE.fullmatch(run_id)
                or type(binding) is not str or not _DIGEST_RE.fullmatch(binding)
                or type(model) is not str or not _MODEL_RE.fullmatch(model)
                or type(history_digest) is not str or not _DIGEST_RE.fullmatch(history_digest)):
            raise CanaryLedgerError(_ERR_INVALID_RES)
        with self._locked(blocking=True, deadline=deadline, check_alive=check_alive) as dir_fd:
            _check_e2e_record(dir_fd, run_id=run_id, max_input=self.max_input, max_output=self.max_output)
            existing = _read_private_bytes(dir_fd, CANARY_FILE)
            if existing is not None:
                _refuse_existing_canary(existing, max_input=self.max_input, max_output=self.max_output)
            existing_rec = _read_private_bytes(dir_fd, CANARY_RECOVERY_FILE)
            if existing_rec is not None:
                _refuse_existing_canary(existing_rec, recovery=True, max_input=self.max_input, max_output=self.max_output)
            current = _inspect_history_fd(dir_fd)
            if current.digest != history_digest:
                raise CanaryLedgerError(_ERR_HISTORY_CHANGED)
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

    def reserve_recovery(
        self,
        run_id: str,
        binding: str,
        model: str,
        history_digest: str,
        *,
        prior_run_id: str,
        prior_digest: str,
        expected_prior: tuple[str, str] | None = None,
        deadline: float | None = None,
        check_alive=None,
    ) -> None:
        """Durably reserve the single one-shot recovery slot without touching canary.json."""
        if expected_prior is None:
            raise CanaryLedgerError("canary_recovery_ineligible")
        pinned = expected_prior
        if (type(run_id) is not str or not _RUN_RE.fullmatch(run_id)
                or type(binding) is not str or not _DIGEST_RE.fullmatch(binding)
                or type(model) is not str or not _MODEL_RE.fullmatch(model)
                or type(history_digest) is not str or not _DIGEST_RE.fullmatch(history_digest)
                or (prior_run_id, prior_digest) != pinned
                or run_id == prior_run_id):
            raise CanaryLedgerError(_ERR_INVALID_RES)
        with self._locked(blocking=True, deadline=deadline, check_alive=check_alive) as dir_fd:
            _check_e2e_record(dir_fd, run_id=run_id, max_input=self.max_input, max_output=self.max_output)
            existing_rec = _read_private_bytes(dir_fd, CANARY_RECOVERY_FILE)
            if existing_rec is not None:
                _refuse_existing_canary(existing_rec, recovery=True, max_input=self.max_input, max_output=self.max_output)
            current = _inspect_history_fd(dir_fd)
            if current.digest != history_digest:
                raise CanaryLedgerError(_ERR_HISTORY_CHANGED)
            _load_eligible_prior_canary(
                dir_fd, binding=binding, model=model, history_digest=history_digest,
                max_input=self.max_input, max_output=self.max_output, expected_prior=pinned,
            )
            record = {
                "run_id": run_id,
                "binding": binding,
                "model": model,
                "history_digest": history_digest,
                "prior_canary_run_id": prior_run_id,
                "prior_canary_digest": prior_digest,
                "max_input": self.max_input,
                "max_output": self.max_output,
                "actual": None,
                "outcome": _OUTCOME_UNSETTLED,
                "delivered": False,
            }
            _atomic_write_json(dir_fd, CANARY_RECOVERY_FILE, record)

    def _load_matching_unsettled(self, dir_fd: int, run_id: str, *, recovery: bool = False) -> dict:
        target = CANARY_RECOVERY_FILE if recovery else CANARY_FILE
        raw = _read_private_bytes(dir_fd, target)
        if raw is None:
            raise CanaryLedgerError(_ERR_MISSING)
        record = _decode_json_bytes(raw, err_code=_ERR_STORAGE)
        if (not _valid_canary_record(record, recovery=recovery, max_input=self.max_input, max_output=self.max_output)
                or record["run_id"] != run_id):
            raise CanaryLedgerError(_ERR_UNMATCHED)
        if record["outcome"] != _OUTCOME_UNSETTLED:
            raise CanaryLedgerError(_ERR_ALREADY_SETTLED)
        return record

    def settle(self, run_id: str, *, allow_delivery: bool, input_tokens: int, output_tokens: int,
               recovery: bool = False) -> str:
        """Durably settle verified usage independently of delivery permission."""
        if not _is_usage(input_tokens) or not _is_usage(output_tokens):
            raise CanaryLedgerError(_ERR_INVALID_USAGE)
        target = CANARY_RECOVERY_FILE if recovery else CANARY_FILE
        with self._locked(blocking=True) as dir_fd:
            record = self._load_matching_unsettled(dir_fd, run_id, recovery=recovery)
            over = input_tokens > self.max_input or output_tokens > self.max_output
            if over:
                outcome = _OUTCOME_OVERAGE
            elif allow_delivery:
                outcome = _OUTCOME_OK
            else:
                outcome = _OUTCOME_REFUSED
            record["actual"] = [input_tokens, output_tokens]
            record["outcome"] = outcome
            _atomic_write_json(dir_fd, target, record)
            return outcome

    def mark_delivered(self, run_id: str, *, recovery: bool = False) -> None:
        """Record milestone delivery only after OpenCode exits 0 with one visible ok and verified cleanup."""
        target = CANARY_RECOVERY_FILE if recovery else CANARY_FILE
        with self._locked(blocking=True) as dir_fd:
            raw = _read_private_bytes(dir_fd, target)
            if raw is None:
                raise CanaryLedgerError(_ERR_MISSING)
            record = _decode_json_bytes(raw, err_code=_ERR_STORAGE)
            if (not _valid_canary_record(record, recovery=recovery, max_input=self.max_input, max_output=self.max_output)
                    or record["run_id"] != run_id or record["outcome"] != _OUTCOME_OK):
                raise CanaryLedgerError(_ERR_UNMATCHED)
            record["delivered"] = True
            _atomic_write_json(dir_fd, target, record)


class E2ECanaryLedger(CanaryLedger):
    """Durable repeatable live-e2e ledger sharing exposure.lock without mutating historical receipts.

    Historical I4a files, canary.json, and canary-recovery.json are read-only. Each live e2e
    invocation serializes via canary.lock and exposure.lock and writes its own durable record in
    canary-e2e.json. Any unsettled or overage canary/e2e record durably blocks subsequent runs;
    cleanly settled in-bounds records (or a valid linked settled recovery) permit explicit re-runs.
    """

    def _validate_readonly_history(self, dir_fd: int) -> HistorySnapshot:
        history = _inspect_history_fd(dir_fd)
        _check_readonly_canary_files(dir_fd, max_input=self.max_input, max_output=self.max_output)
        return history

    def preflight(self) -> HistorySnapshot:
        with self._locked(blocking=False) as dir_fd:
            _check_e2e_record(dir_fd, max_input=self.max_input, max_output=self.max_output)
            return self._validate_readonly_history(dir_fd)

    def reserve(self, run_id: str, binding: str, model: str, history_digest: str, *,
                deadline: float | None = None, check_alive=None) -> None:
        if (type(run_id) is not str or not _RUN_RE.fullmatch(run_id)
                or type(binding) is not str or not _DIGEST_RE.fullmatch(binding)
                or type(model) is not str or not _MODEL_RE.fullmatch(model)
                or type(history_digest) is not str or not _DIGEST_RE.fullmatch(history_digest)):
            raise CanaryLedgerError(_ERR_INVALID_RES)
        with self._locked(blocking=True, deadline=deadline, check_alive=check_alive) as dir_fd:
            _check_e2e_record(dir_fd, run_id=run_id, max_input=self.max_input, max_output=self.max_output)
            current = self._validate_readonly_history(dir_fd)
            if current.digest != history_digest:
                raise CanaryLedgerError(_ERR_HISTORY_CHANGED)
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
            _atomic_write_json(dir_fd, CANARY_E2E_FILE, record)

    def settle(self, run_id: str, *, allow_delivery: bool, input_tokens: int, output_tokens: int,
               recovery: bool = False) -> str:
        if recovery or not _is_usage(input_tokens) or not _is_usage(output_tokens):
            raise CanaryLedgerError(_ERR_INVALID_USAGE)
        with self._locked(blocking=True) as dir_fd:
            raw = _read_private_bytes(dir_fd, CANARY_E2E_FILE)
            if raw is None:
                raise CanaryLedgerError(_ERR_MISSING)
            record = _decode_json_bytes(raw, err_code=_ERR_STORAGE)
            if (not _valid_canary_record(record, recovery=False, max_input=self.max_input, max_output=self.max_output)
                    or record["run_id"] != run_id):
                raise CanaryLedgerError(_ERR_UNMATCHED)
            if record["outcome"] != _OUTCOME_UNSETTLED:
                raise CanaryLedgerError(_ERR_ALREADY_SETTLED)
            over = input_tokens > self.max_input or output_tokens > self.max_output
            if over:
                outcome = _OUTCOME_OVERAGE
            elif allow_delivery:
                outcome = _OUTCOME_OK
            else:
                outcome = _OUTCOME_REFUSED
            record["actual"] = [input_tokens, output_tokens]
            record["outcome"] = outcome
            _atomic_write_json(dir_fd, CANARY_E2E_FILE, record)
            return outcome

    def mark_delivered(self, run_id: str, *, recovery: bool = False) -> None:
        if recovery:
            raise CanaryLedgerError(_ERR_UNMATCHED)
        with self._locked(blocking=True) as dir_fd:
            raw = _read_private_bytes(dir_fd, CANARY_E2E_FILE)
            if raw is None:
                raise CanaryLedgerError(_ERR_MISSING)
            record = _decode_json_bytes(raw, err_code=_ERR_STORAGE)
            if (not _valid_canary_record(record, recovery=False, max_input=self.max_input, max_output=self.max_output)
                    or record["run_id"] != run_id or record["outcome"] != _OUTCOME_OK):
                raise CanaryLedgerError(_ERR_UNMATCHED)
            record["delivered"] = True
            _atomic_write_json(dir_fd, CANARY_E2E_FILE, record)
