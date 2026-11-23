"""In-process quota accounting proof for host-owned synthetic evidence."""

import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from threading import Lock
from typing import TypeGuard, cast


CLOCK_MAX = 2_147_483_647
RECEIPT_LIMIT = 8
WINDOWS = (
    ("5h_rolling", 18_000, 300),
    ("7d_weekly", 604_800, 900),
)


@dataclass(frozen=True)
class Window:
    remaining_bps: int
    resets_at: int


@dataclass(frozen=True)
class Admission:
    allowed: bool
    reason: str
    blocking_window: str | None = None
    resets_at: int | None = None
    headroom_bps: int | None = None
    low_headroom: bool = False


@dataclass(frozen=True)
class FixtureGrant:
    route: str
    model: str
    budget: int
    hard_bound: int | None


@dataclass(frozen=True)
class Reservation:
    request_id: str
    bound: int
    may_have_sent: bool = False


@dataclass(frozen=True)
class Settlement:
    request_id: str
    route: str
    model: str
    charge: int
    authoritative_final: bool


@dataclass(frozen=True)
class Accounting:
    spent: int
    active: Reservation | None
    suspended: bool
    admitted_ids: int


def valid_second(value: object) -> TypeGuard[int]:
    return type(value) is int and 0 <= value <= CLOCK_MAX


def valid_identifier(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value) is not None


def validate_windows(snapshot: object, observed_at: int) -> tuple[Window, ...] | None:
    if type(snapshot) is not dict:
        return None
    snapshot_fields = cast(dict[object, object], snapshot)
    if snapshot_fields.keys() != {name for name, _, _ in WINDOWS}:
        return None

    windows = []
    for name, duration, _ in WINDOWS:
        raw = snapshot_fields[name]
        if type(raw) is not dict:
            return None
        fields = cast(dict[object, object], raw)
        if fields.keys() != {"remaining_bps", "resets_at"}:
            return None
        remaining = fields["remaining_bps"]
        resets_at = fields["resets_at"]
        if type(remaining) is not int or not 0 <= remaining <= 10_000:
            return None
        if not valid_second(resets_at) or not 0 < resets_at - observed_at <= duration:
            return None
        windows.append(Window(remaining, resets_at))
    return tuple(windows)


class QuotaCore:
    def __init__(self, clock: Callable[[], object], grant: FixtureGrant):
        self._clock = clock
        self._grant = grant
        self._lock = Lock()
        self._last_clock: int | None = None
        self._observed_at: int | None = None
        self._windows: tuple[Window, ...] | None = None
        self._active: Reservation | None = None
        # A receipt with a None charge records a release before the send boundary.
        self._receipts: dict[str, int | None] = {}
        self._spent = 0
        self._suspended = False

    def _read_clock(self) -> int | None:
        now = self._clock()
        if not valid_second(now) or (self._last_clock is not None and now < self._last_clock):
            return None
        self._last_clock = now
        return now

    def observe(self, snapshot: object, observed_at: int) -> bool:
        with self._lock:
            now = self._read_clock()
            if now is None or not valid_second(observed_at) or observed_at > now:
                return False
            if self._observed_at is not None and observed_at < self._observed_at:
                return False

            windows = validate_windows(snapshot, observed_at)
            if observed_at == self._observed_at:
                if windows != self._windows:
                    self._windows = None
            else:
                self._observed_at = observed_at
                self._windows = windows
            return self._windows is not None

    def ordinary_admission(self) -> Admission:
        with self._lock:
            now = self._read_clock()
            if now is None or self._windows is None or self._observed_at is None:
                return Admission(False, "quota_unverified")

            fresh_remaining = []
            for (name, _, ttl), window in zip(WINDOWS, self._windows, strict=True):
                if now >= window.resets_at or now - self._observed_at >= ttl:
                    continue
                if window.remaining_bps == 0:
                    return Admission(False, "quota_exhausted", name, window.resets_at)
                fresh_remaining.append(window.remaining_bps)

            if len(fresh_remaining) != len(WINDOWS):
                return Admission(False, "quota_unverified")
            headroom = min(fresh_remaining)
            return Admission(True, "allowed", headroom_bps=headroom, low_headroom=headroom < 1_000)

    def _grant_matches(self, route: str, model: str) -> bool:
        return (
            type(route) is str
            and type(model) is str
            and (route, model) == (self._grant.route, self._grant.model)
        )

    def reserve(self, request_id: str, route: str, model: str) -> bool:
        with self._lock:
            if self._read_clock() is None or not self._grant_matches(route, model):
                return False
            if not valid_identifier(request_id) or request_id in self._receipts:
                return False
            bound = self._grant.hard_bound
            budget = self._grant.budget
            if type(bound) is not int or bound <= 0 or type(budget) is not int or budget < 0:
                return False
            if self._suspended or self._active is not None or len(self._receipts) >= RECEIPT_LIMIT:
                return False
            if self._spent + bound > budget:
                return False
            self._active = Reservation(request_id, bound)
            return True

    def mark_may_have_sent(self, request_id: str) -> bool:
        with self._lock:
            active = self._active
            if self._read_clock() is None or self._suspended or active is None:
                return False
            if not valid_identifier(request_id) or active.request_id != request_id or active.may_have_sent:
                return False
            self._active = replace(active, may_have_sent=True)
            return True

    def release_pre_send(self, request_id: str) -> bool:
        with self._lock:
            active = self._active
            if active is None or not valid_identifier(request_id):
                return False
            if active.request_id != request_id or active.may_have_sent:
                return False
            self._receipts[request_id] = None
            self._active = None
            return True

    def settle(self, evidence: Settlement | None) -> bool:
        with self._lock:
            if type(evidence) is not Settlement or evidence.authoritative_final is not True:
                return False
            identifiers = (evidence.request_id, evidence.route, evidence.model)
            if not all(valid_identifier(value) for value in identifiers):
                return False
            request_id, charge = evidence.request_id, evidence.charge
            if type(charge) is not int or charge < 0:
                return False

            binding_matches = self._grant_matches(evidence.route, evidence.model)
            # Final evidence and receipts share the selected grant's fixture ID namespace.
            if request_id in self._receipts:
                if binding_matches and self._receipts[request_id] == charge:
                    return True
                self._suspended = True
                return False

            active = self._active
            if not binding_matches or active is None:
                return False
            if active.request_id != request_id or not active.may_have_sent:
                return False
            self._spent += charge
            self._receipts[request_id] = charge
            self._active = None
            if charge > active.bound:
                self._suspended = True
            return True

    def accounting(self) -> Accounting:
        with self._lock:
            admitted_ids = len(self._receipts) + int(self._active is not None)
            return Accounting(self._spent, self._active, self._suspended, admitted_ids)
