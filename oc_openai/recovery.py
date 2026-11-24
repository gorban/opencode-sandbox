"""Separate accounting for one foreground recovery proof after a spent diagnostic."""

from dataclasses import replace
from hashlib import sha256
import json
import os
import time

from .exposure import (
    Diagnostic, ExposureError, Phase, Slot, _DIGEST, _RECOVERY_PROOF, _RECOVERY_WORKER,
    _RECOVERY_METADATA, _RECOVERY_MODERATION, _RECOVERY_TRACE, _RECOVERY_WORKER_PROGRESS, _STREAM_DIAGNOSTIC,
    _diagnostic_receipt, _is_usage, _matches_receipt, _overage, _validate, _valid_slot,
)

_PHASES = (Phase.ORCHESTRATOR, Phase.INITIAL, Phase.CONTINUATION)
_CONSENT_SECONDS = 300
_ABSENT = object()
_REVIEWED_PREVIOUS = "4cbcf31fc1e5c740c2fe5e2ea27b4a1f71c542c0b4f63ac09477af8370570118"
_REVIEWED_WORKER = "b35322c0a40f3204db7264a973cd0642cc7f5f1361ad3b6c421f3c4690b0e4d3"
_REVIEWED_PROGRESS = "dc6663ff792b073a2d7cbe3128a3632807864e160d5f969a403523a496b1d3fd"
_REVIEWED_TRACE = "dccaa92e285656a74f5293224bd64c7b3604b3330d98b8aa71151de54adf4bd8"
_REVIEWED_METADATA = "999b1a0a04b9e50477ab2df9f3100b1249bde1dc706cb49b23d4481839b11409"


def _recovery_phases(*, trace_only, worker_only):
    if trace_only:
        return (Phase.INITIAL,)
    if worker_only:
        return _PHASES[1:]
    return _PHASES


def _recovery_name(*, moderation_trace, after_trace, trace_only, after_retry, worker_only):
    if moderation_trace:
        return _RECOVERY_MODERATION
    if after_trace:
        return _RECOVERY_METADATA
    if trace_only:
        return _RECOVERY_TRACE
    if after_retry:
        return _RECOVERY_WORKER_PROGRESS
    return _RECOVERY_WORKER if worker_only else _RECOVERY_PROOF


class RecoveryLedger:
    """Process-local permit backed by a one-shot durable phase record."""

    def __init__(self, ledger, first, source, *, worker_only=False, after_retry=False,
                 trace_only=False, after_trace=False, moderation_trace=False):
        trace_only = trace_only or moderation_trace
        phases = _recovery_phases(trace_only=trace_only, worker_only=worker_only)
        invalid_flags = (
            (after_retry and not worker_only)
            or ((trace_only or after_trace) and not after_retry)
            or (trace_only and after_trace and not moderation_trace)
            or (moderation_trace and not after_trace)
        )
        if (not _valid_slot(first) or first.phase is not phases[0]
                or invalid_flags or type(source) is not str or not _DIGEST.fullmatch(source)):
            raise ExposureError("diagnostic_unavailable")
        self._ledger = ledger
        self._first = first
        self._source = source
        self._phases = phases
        self._name = _recovery_name(
            moderation_trace=moderation_trace, after_trace=after_trace,
            trace_only=trace_only, after_retry=after_retry, worker_only=worker_only,
        )
        self._worker_only = worker_only
        self._after_retry = after_retry
        self._trace_only = trace_only
        self._after_trace = after_trace
        self._moderation_trace = moderation_trace
        self._until = None
        self._attended = None
        self._closed = False
        self._started = False
        with ledger._locked() as directory:
            self._require_absent(directory, self._name)
            self._prior = self._history(directory)

    @staticmethod
    def _require_absent(directory, name):
        try:
            os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise ExposureError("diagnostic_already_reserved")

    def _history(self, directory):
        ledger = self._ledger
        candidate = replace(self._first, phase=Phase.ORCHESTRATOR)
        ticket = ledger._diagnostic(directory, candidate, stream=True)
        stored = ledger._load(directory, _STREAM_DIAGNOSTIC, missing=None)
        if type(stored) is not dict:
            raise ExposureError("diagnostic_unavailable")
        last = Slot(stored.get("run"), ticket.request.binding, Phase.ORCHESTRATOR)
        if (not _valid_slot(last) or last in (ticket.original, ticket.previous, ticket.request)
                or not _matches_receipt(stored, _diagnostic_receipt(Diagnostic(
                    ticket.original, last, ticket.previous,
                )))):
            raise ExposureError("diagnostic_unavailable")
        earlier = (ticket.original.run_id, ticket.previous.run_id, last.run_id)
        if not self._moderation_trace:
            self._require_absent(directory, _RECOVERY_MODERATION)
        if not self._after_trace:
            self._require_absent(directory, _RECOVERY_METADATA)
        if not (self._trace_only or self._after_trace):
            self._require_absent(directory, _RECOVERY_TRACE)
        if not self._after_retry:
            self._require_absent(directory, _RECOVERY_WORKER_PROGRESS)
        if not self._worker_only:
            self._require_absent(directory, _RECOVERY_WORKER)
            return earlier
        excluded = (*earlier, self._first.run_id)
        proof, proof_hash = self._settled_predecessor(
            directory, _RECOVERY_PROOF, earlier, _REVIEWED_PREVIOUS, _PHASES[:2], excluded,
        )
        parent = (*earlier, proof_hash)
        if not self._after_retry:
            return parent
        worker, worker_hash = self._settled_predecessor(
            directory, _RECOVERY_WORKER, parent, _REVIEWED_WORKER, (Phase.INITIAL,), (*excluded, proof),
        )
        chain = (*parent, worker_hash)
        if not (self._trace_only or self._after_trace):
            return chain
        progress, progress_hash = self._settled_predecessor(
            directory, _RECOVERY_WORKER_PROGRESS, chain, _REVIEWED_PROGRESS,
            (Phase.INITIAL,), (*excluded, proof, worker),
        )
        chain = (*chain, progress_hash)
        if not self._after_trace:
            return chain
        trace, trace_hash = self._settled_predecessor(
            directory, _RECOVERY_TRACE, chain, _REVIEWED_TRACE, (Phase.INITIAL,),
            (*excluded, proof, worker, progress),
        )
        chain = (*chain, trace_hash)
        if not self._moderation_trace:
            return chain
        _, metadata_hash = self._settled_predecessor(
            directory, _RECOVERY_METADATA, chain, _REVIEWED_METADATA, (Phase.INITIAL,),
            (*excluded, proof, worker, progress, trace),
        )
        return (*chain, metadata_hash)

    def _settled_predecessor(self, directory, name, prior, source, expected, excluded):
        old = self._ledger._load(directory, name, missing=None)
        if (type(old) is not dict or set(old) != {"version", "prior", "source", "phases"}
                or type(old["version"]) is not int or old["version"] != 1
                or old["prior"] != list(prior) or old["source"] != source):
            raise ExposureError("diagnostic_unavailable")
        phases = old["phases"]
        try:
            _validate(phases, first=expected[0])
        except ValueError:
            raise ExposureError("diagnostic_unavailable") from None
        if ([row["phase"] for row in phases] != [phase.value for phase in expected]
                or any(row["binding"] != self._first.binding or row["actual"] is None
                       or _overage(row["actual"]) for row in phases)
                or phases[0]["run"] in excluded):
            raise ExposureError("diagnostic_unavailable")
        return phases[0]["run"], sha256(json.dumps(old, sort_keys=True, ensure_ascii=True).encode("ascii")).hexdigest()

    def approve(self, confirmed_at, attended):
        if self._until is not None or self._closed:
            raise ExposureError("diagnostic_unavailable")
        self._until = confirmed_at + _CONSENT_SECONDS
        self._attended = attended

    def close(self):
        self._closed = True

    def require_dispatch(self):
        if (self._closed or self._until is None or not self._attended()
                or time.monotonic() >= self._until):
            raise ExposureError("diagnostic_unavailable")

    def _receipt(self):
        return {"version": 1, "prior": list(self._prior), "source": self._source, "phases": []}

    def _read(self, directory, *, allow_absent=False):
        if self._closed or self._until is None or self._history(directory) != self._prior:
            raise ExposureError("diagnostic_unavailable")
        row = self._ledger._load(directory, self._name, missing=_ABSENT)
        expected = self._receipt()
        if row is _ABSENT and allow_absent and not self._started:
            return expected
        if (not self._started or type(row) is not dict or set(row) != set(expected)
                or type(row["version"]) is not int or row["version"] != expected["version"]
                or row["prior"] != expected["prior"] or row["source"] != self._source):
            raise ExposureError("diagnostic_unavailable")
        phases = row["phases"]
        if (type(phases) is not list or not 0 < len(phases) <= len(self._phases)):
            raise ExposureError("diagnostic_unavailable")
        try:
            _validate(phases, first=self._first.phase)
        except ValueError:
            raise ExposureError("diagnostic_unavailable") from None
        if any((phase["run"], phase["binding"], phase["phase"]) != (
            self._first.run_id, self._first.binding, expected_phase.value,
        ) for phase, expected_phase in zip(phases, self._phases)):
            raise ExposureError("diagnostic_unavailable")
        return row

    def _next(self, directory, slot):
        self.require_dispatch()
        row = self._read(directory, allow_absent=slot == self._first)
        index = len(row["phases"])
        if index == len(self._phases) or slot != replace(self._first, phase=self._phases[index]):
            raise ExposureError("diagnostic_unavailable")
        row["phases"] = self._ledger._admit(row["phases"], slot, first=self._first.phase)
        return row

    def require_next(self, slot):
        with self._ledger._locked() as directory:
            self._next(directory, slot)

    def reserve(self, slot):
        with self._ledger._locked() as directory:
            row = self._next(directory, slot)
            self._started = True
            self._ledger._write(directory, row, name=self._name)

    def settle(self, slot, input_tokens, output_tokens):
        if not _is_usage(input_tokens) or not _is_usage(output_tokens):
            raise ExposureError("invalid_terminal_usage")
        with self._ledger._locked() as directory:
            row = self._read(directory)
            record = row["phases"][-1]
            if (not _valid_slot(slot) or record["actual"] is not None
                    or slot != replace(self._first, phase=Phase(record["phase"]))):
                raise ExposureError("unmatched_exposure_settlement")
            actual = [input_tokens, output_tokens]
            record["actual"] = actual
            self._ledger._write(directory, row, name=self._name)
        if _overage(actual):
            raise ExposureError("exposure_bound_exceeded")
