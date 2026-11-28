"""Inactive shared first-write journal on the canonical OpenAI exposure lock.

The trusted host must supply the independently qualified writer fence before
activation or use. A scope capability or files on disk cannot exclude older
writers or detect loss or rollback of both files. The deployment fence must
verify compatibility and continuity from independent trusted deployment state,
including whether activation would recreate a previously used scope. No
production caller constructs this journal or supplies that fence.
"""

from collections.abc import Callable
from dataclasses import asdict, dataclass
from hashlib import sha256
import hmac
import json
import os

from .exposure import (
    ExposureError, ExposureLedger, _DIGEST, _INPUT_LIMIT, _MAX_BYTES, _MAX_SLOTS,
    _MODEL_SLUG, _OUTPUT_LIMIT, _RUN, _is_usage,
)


_ANCHOR = "shared-exposure-v1.anchor.json"
_JOURNAL = "shared-exposure-v1.json"
_VERSION = 1
_USAGE_MAX = (1 << 63) - 1


@dataclass(frozen=True)
class ScopedClaim:
    launch: str
    slot: str
    operation: str
    binding: str
    model: str
    request_digest: str
    max_input: int
    max_output: int


@dataclass(frozen=True)
class VerifiedUsage:
    """Usage already verified against the exact provider stream by the caller."""

    operation: str
    terminal_digest: str
    input_tokens: int
    output_tokens: int


def _matches(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def _bounded(value, maximum, *, minimum=0):
    return _is_usage(value) and minimum <= value <= maximum


def _valid_claim(claim):
    return (
        type(claim) is ScopedClaim and _matches(_RUN, claim.launch) and _matches(_RUN, claim.slot)
        and _matches(_RUN, claim.operation) and _matches(_DIGEST, claim.binding)
        and _matches(_MODEL_SLUG, claim.model) and _matches(_DIGEST, claim.request_digest)
        and _bounded(claim.max_input, _INPUT_LIMIT, minimum=1)
        and _bounded(claim.max_output, _OUTPUT_LIMIT, minimum=1)
    )


def _valid_usage(usage):
    return (
        type(usage) is VerifiedUsage and _matches(_RUN, usage.operation)
        and _matches(_DIGEST, usage.terminal_digest)
        and _bounded(usage.input_tokens, _USAGE_MAX) and _bounded(usage.output_tokens, _USAGE_MAX)
    )


def _over_budget(claim, usage):
    return usage.input_tokens > claim.max_input or usage.output_tokens > claim.max_output


class ScopedExposure:
    """Offline primitive for one scope and a host-attested compatible writer cohort."""

    def __init__(self, ledger: ExposureLedger, cohort: str, *, require_compatible: Callable[[], None]):
        if not _matches(_DIGEST, cohort) or not callable(require_compatible):
            raise ExposureError("incompatible_exposure_writers")
        self._ledger = ledger
        self._cohort = cohort
        self._require_compatible = require_compatible

    def _check_writers(self):
        # The future host implementation is responsible for exclusion and
        # continuity through this operation. Do not reacquire the ledger lock.
        if self._require_compatible() is not None:
            raise ExposureError("incompatible_exposure_writers")

    def _read_locked(self, directory, *, initial=False):
        anchor = self._ledger._read_verified_hold_file(directory, _ANCHOR)
        journal = self._ledger._read_verified_hold_file(directory, _JOURNAL)
        if anchor is None and journal is None:
            if initial:
                return []
            raise ExposureError("shared_exposure_not_active")
        if anchor is None or journal is None:
            raise ExposureError("invalid_shared_exposure")
        record = anchor[1]
        if (type(record) is not dict or set(record) != {"version", "cohort", "journal_sha256"}
                or type(record["version"]) is not int or record["version"] != _VERSION
                or record["cohort"] != self._cohort or not _matches(_DIGEST, record["journal_sha256"])
                or not hmac.compare_digest(record["journal_sha256"], sha256(journal[0]).hexdigest())):
            raise ExposureError("invalid_shared_exposure")
        payload = journal[1]
        if (type(payload) is not dict or set(payload) != {"version", "cohort", "claims"}
                or type(payload["version"]) is not int or payload["version"] != _VERSION
                or payload["cohort"] != self._cohort):
            raise ExposureError("invalid_shared_exposure")
        entries = payload["claims"]
        if type(entries) is not list or len(entries) > _MAX_SLOTS:
            raise ExposureError("invalid_shared_exposure")
        self._validate_entries(entries)
        if initial:
            raise ExposureError("shared_exposure_already_active")
        return entries

    @staticmethod
    def _validate_entries(entries):
        slots = set()
        operations = set()
        try:
            for index, entry in enumerate(entries):
                if type(entry) is not dict or set(entry) != {"claim", "usage"}:
                    raise ValueError
                claim = ScopedClaim(**entry["claim"])
                if not _valid_claim(claim):
                    raise ValueError
                slot = (claim.launch, claim.slot)
                if slot in slots or claim.operation in operations:
                    raise ValueError
                slots.add(slot)
                operations.add(claim.operation)
                is_last = index == len(entries) - 1
                if entry["usage"] is None:
                    if not is_last:
                        raise ValueError
                    continue
                usage = VerifiedUsage(**entry["usage"])
                if (not _valid_usage(usage) or usage.operation != claim.operation
                        or (_over_budget(claim, usage) and not is_last)):
                    raise ValueError
        except (TypeError, ValueError):
            raise ExposureError("invalid_shared_exposure") from None

    def _journal_content(self, entries):
        payload = {"version": _VERSION, "cohort": self._cohort, "claims": entries}
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        if len(encoded) > _MAX_BYTES:
            raise ExposureError("exposure_record_full")
        return payload, encoded

    def _write_locked(self, directory, entries):
        payload, encoded = self._journal_content(entries)
        self._ledger._write(directory, payload, name=_JOURNAL)
        written = self._ledger._read_verified_hold_file(directory, _JOURNAL)
        if written is None or written[0] != encoded:
            raise ExposureError("invalid_shared_exposure")
        anchor = {"version": _VERSION, "cohort": self._cohort, "journal_sha256": sha256(encoded).hexdigest()}
        self._ledger._write(directory, anchor, name=_ANCHOR)
        if self._read_locked(directory) != entries:
            raise ExposureError("invalid_shared_exposure")

    def activate(self):
        with self._ledger._locked() as directory:
            self._check_writers()
            self._read_locked(directory, initial=True)
            hold = self._ledger._inspect_locked(directory)
            if hold.unsettled_count:
                raise ExposureError("unsettled_exposure")
            self._write_locked(directory, [])

    @staticmethod
    def _require_hold(hold, acknowledged_digest):
        if hold.unsettled_count:
            raise ExposureError("unsettled_exposure")
        if hold.blocked:
            if not _matches(_DIGEST, acknowledged_digest):
                raise ExposureError("exposure_hold_active")
            if not hmac.compare_digest(hold.digest, acknowledged_digest):
                raise ExposureError("exposure_hold_changed")
        elif acknowledged_digest is not None:
            raise ExposureError("exposure_hold_changed")

    def first_write(self, claim: ScopedClaim, *, slot_fence: Callable, check: Callable[[], None], write: Callable,
                    acknowledged_digest=None, wait=0.0):
        """Claim one slot and invoke the existing bounded first writer under the lock.

        The caller retains its outer ownership, connection and lease fences.
        Acquire the route-local slot fence after the canonical exposure lock.
        Rejection or cancellation before claim persistence has no send effect.
        After persistence every outcome stays unresolved until exact settlement.
        """
        if not _valid_claim(claim):
            raise ExposureError("invalid_shared_exposure_claim")
        with self._ledger._locked(wait=wait) as directory:
            self._check_writers()
            entries = self._read_locked(directory)
            hold = self._ledger._inspect_locked(directory)
            self._require_hold(hold, acknowledged_digest)
            # A previous replace can be visible after an interrupted directory
            # sync. Confirm the verified publication before trusting headroom.
            os.fsync(directory)
            if entries:
                last = entries[-1]
                if last["usage"] is None:
                    raise ExposureError("unsettled_exposure")
                if _over_budget(ScopedClaim(**last["claim"]), VerifiedUsage(**last["usage"])):
                    raise ExposureError("exposure_bound_exceeded")
            proposed = asdict(claim)
            if any(entry["claim"]["operation"] == claim.operation or (
                entry["claim"]["launch"], entry["claim"]["slot"],
            ) == (claim.launch, claim.slot) for entry in entries):
                raise ExposureError("shared_exposure_slot_spent")
            if len(entries) == _MAX_SLOTS:
                raise ExposureError("exposure_record_full")
            # Maximum accepted usage can exceed the claim's budget. Reserve
            # space to retain that terminal evidence before claiming a write.
            largest_usage = VerifiedUsage(claim.operation, "f" * 64, _USAGE_MAX, _USAGE_MAX)
            self._journal_content([*entries, {"claim": proposed, "usage": asdict(largest_usage)}])
            with slot_fence():
                if check() is not None:
                    raise ExposureError("shared_exposure_write_unverified")
                self._write_locked(directory, [*entries, {"claim": proposed, "usage": None}])
                self._check_writers()
                if check() is not None:
                    raise ExposureError("shared_exposure_write_unverified")
                return write()

    def settle(self, claim: ScopedClaim, usage: VerifiedUsage):
        if not _valid_claim(claim) or not _valid_usage(usage) or usage.operation != claim.operation:
            raise ExposureError("invalid_terminal_usage")
        with self._ledger._locked() as directory:
            self._check_writers()
            entries = self._read_locked(directory)
            self._ledger._inspect_locked(directory)
            expected_claim, expected_usage = asdict(claim), asdict(usage)
            for entry in entries:
                if entry["claim"] != expected_claim:
                    continue
                if entry["usage"] is None:
                    entry["usage"] = expected_usage
                    self._write_locked(directory, entries)
                elif entry["usage"] != expected_usage:
                    raise ExposureError("unmatched_exposure_settlement")
                else:
                    # Reaffirm the directory sync if a previous caller observed
                    # uncertainty after rename. The exact settled record is required.
                    os.fsync(directory)
                break
            else:
                raise ExposureError("unmatched_exposure_settlement")
            if _over_budget(claim, usage):
                raise ExposureError("exposure_bound_exceeded")
