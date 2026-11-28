"""Fixture-only cumulative turn state and durable synthetic exposure records."""

from contextlib import closing
from dataclasses import dataclass
import json
import os
import sqlite3
from threading import Lock
import time

from stock_worker_tools_history import (
    MAX_BATCH, MAX_CONTINUATIONS, MAX_INPUT, MAX_OUTPUT, MAX_TURNS, digest,
)
from stock_worker_tools_protocol import require

DEADLINE_SECONDS = 300
MAX_WRITES = 8
TOTAL_INPUT = 262_144
TOTAL_OUTPUT = 32_768
_EXPOSURE_FIELDS = ("sequence", "authority", "turn", "parent", "suffix", "reserved_input", "reserved_output",
                    "actual_input", "actual_output")
_MAX_EXPOSURE_ROW_BYTES = 4096
HANDOFF_END = b"0\r\n\r\n"


@dataclass(frozen=True)
class Authority:
    job: str
    slot: str
    generation: str
    route: str
    model: str


@dataclass(frozen=True)
class Dispatch:
    sequence: int
    turn: int
    parent: str | None
    suffix: tuple[str, ...]


@dataclass(frozen=True)
class Pending:
    identity: str
    calls: tuple
    completed_message: str | None


class FixtureTurns:
    """One thread-safe synthetic grant. Opening an existing ledger cannot resume it."""

    def __init__(self, path, authority, *, clock=time.monotonic):
        with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb"):
            pass
        self._path = path
        self._authority = authority
        self._clock = clock
        self._lock = Lock()
        self._binding = digest([authority.job, authority.slot, authority.generation, authority.route, authority.model])
        self._owner_current = True
        self._request = None
        self._pending = None
        self._eligible = None
        self._closed = ()
        self._call_ids = set()
        self._anchor = digest([])
        self._prefix = ()
        self._user = None
        self._session = None
        self._turn = self._continuations = self._writes = 0
        with closing(self._connect()) as db, db:
            db.execute("""CREATE TABLE exposure (
                sequence INTEGER PRIMARY KEY,
                authority TEXT NOT NULL,
                turn INTEGER NOT NULL,
                parent TEXT UNIQUE,
                suffix TEXT NOT NULL,
                reserved_input INTEGER NOT NULL,
                reserved_output INTEGER NOT NULL,
                actual_input INTEGER,
                actual_output INTEGER)""")
        self._deadline = clock() + DEADLINE_SECONDS

    def _connect(self):
        # mode=rw prevents a removed ledger from being silently recreated.
        return sqlite3.connect(self._path.resolve().as_uri() + "?mode=rw", uri=True)

    def _require_current(self, authority):
        require(self._owner_current and authority == self._authority and self._clock() < self._deadline,
                "Stale or expired stock fixture authority")

    def retire(self):
        with self._lock:
            self._owner_current = False

    def fail(self, request):
        with self._lock:
            if request is not None and self._request is request:
                self._owner_current = False

    def records(self):
        with self._lock, closing(self._connect()) as db:
            db.row_factory = sqlite3.Row
            return [dict(row) for row in db.execute("SELECT * FROM exposure ORDER BY sequence")]

    def verified_records(self):
        """Snapshot bounded durable records after the fixture observer has stopped."""
        with self._lock, closing(self._connect()) as db:
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, _MAX_EXPOSURE_ROW_BYTES)
            columns = db.execute("SELECT * FROM exposure LIMIT 0").description
            require(tuple(column[0] for column in columns) == _EXPOSURE_FIELDS, "Wrong stock exposure schema")
            rows = self._rows(db)
            unresolved = self._request if rows and rows[-1][-2:] == (None, None) else None
            self._verify_journal(rows, request=unresolved)
            return [dict(zip(_EXPOSURE_FIELDS, row, strict=True)) for row in rows]

    def _validate_history(self, history):
        require(history.closed == self._closed, "Unverified completed stock history")
        if self._user is None:
            require(self._turn < MAX_TURNS and not history.pairs, "Stock user turn limit or unverified restore")
            return ()
        require(history.user == self._user and self._eligible is not None
                and self._continuations < MAX_CONTINUATIONS, "No continuation is eligible")
        prefix_length = len(self._prefix)
        require(tuple(pair.identity for pair in history.pairs[:prefix_length]) == self._prefix,
                "Earlier stock tool history differs")
        suffix = history.pairs[prefix_length:]
        require(tuple(pair.call for pair in suffix) == self._eligible.calls, "New stock tool batch differs")
        return tuple(pair.identity for pair in suffix)

    def _rows(self, db):
        return db.execute("SELECT * FROM exposure ORDER BY sequence LIMIT ?", (MAX_WRITES + 1,)).fetchall()

    def _claimed_row(self, request):
        return (request.sequence, self._binding, request.turn, request.parent,
                json.dumps(request.suffix), MAX_INPUT, MAX_OUTPUT, None, None)

    def _verify_journal(self, rows, *, request=None):
        try:
            matched = (digest(rows) == self._anchor if request is None
                       else bool(rows) and digest(rows[:-1]) == self._anchor and rows[-1] == self._claimed_row(request))
        except (TypeError, ValueError):
            matched = False
        if not matched:
            self._owner_current = False
        require(matched, "Stock fixture exposure needs reconciliation")

    def _claim(self, request):
        with closing(self._connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            self._require_current(self._authority)
            rows = self._rows(db)
            self._verify_journal(rows)
            used_input = sum(row[-2] for row in rows)
            used_output = sum(row[-1] for row in rows)
            require(len(rows) < MAX_WRITES and used_input + MAX_INPUT <= TOTAL_INPUT
                    and used_output + MAX_OUTPUT <= TOTAL_OUTPUT, "Stock fixture write budget exceeded")
            db.execute("INSERT INTO exposure VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", self._claimed_row(request))

    def dispatch(self, authority, session, history, start):
        """Claim and consume one batch under the same fence as the synthetic first write."""
        with self._lock:
            self._require_current(authority)
            require(self._request is None and self._session in (None, session), "Stock route busy or foreign session")
            suffix = self._validate_history(history)
            request = Dispatch(self._writes + 1, self._turn + (self._user is None),
                               self._eligible.identity if suffix else None, suffix)
            try:
                # A commit can persist even when its caller sees an error. Keep
                # the exact candidate for evidence before touching the ledger.
                self._request = request
                self._claim(request)
                if self._user is None:
                    self._turn = request.turn
                    self._user = history.user
                    self._continuations = 0
                else:
                    self._continuations += 1
                self._prefix += suffix
                if suffix:
                    self._call_ids.update(call.call_id for call in self._eligible.calls)
                self._writes = request.sequence
                self._session = session
                self._eligible = None
                self._require_current(authority)
                return request, start(request)
            except BaseException:
                self._owner_current = False
                raise

    def _settle_usage(self, request, input_tokens, output_tokens):
        with closing(self._connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            rows = self._rows(db)
            self._verify_journal(rows, request=request)
            db.execute("UPDATE exposure SET actual_input = ?, actual_output = ? WHERE sequence = ?",
                       (input_tokens, output_tokens, request.sequence))
            anchor = digest(self._rows(db))
        self._anchor = anchor

    def settle(self, authority, request, *, calls, completed_message, usage):
        """Stage only verified terminal data. No continuation is eligible during settlement."""
        with self._lock:
            self._require_current(authority)
            require(request is self._request and self._pending is None, "Wrong stock fixture settlement")
            try:
                require(usage is not None and len(usage) == 3 and all(type(value) is int and 0 <= value <= 2**31
                                                                     for value in usage)
                        and usage[0] + usage[1] == usage[2], "Invalid stock fixture terminal usage")
                require(bool(calls) != bool(completed_message) and len(calls) <= MAX_BATCH
                        and len({call.call_id for call in calls}) == len(calls)
                        and not self._call_ids.intersection(call.call_id for call in calls),
                        "Invalid stock fixture terminal output")
                self._pending = Pending(digest([self._binding, request.turn, request.sequence,
                                                [call.call_id for call in calls]]), calls, completed_message)
                self._settle_usage(request, *usage[:2])
                require(usage[0] <= MAX_INPUT and usage[1] <= MAX_OUTPUT, "Stock fixture terminal usage exceeded reservation")
                require(not calls or self._continuations < MAX_CONTINUATIONS, "Stock fixture continuation limit reached")
            except Exception:
                self._owner_current = False
                raise
            return self._pending

    def deliver(self, authority, request, pending, send, frames):
        """Open only after every broker-observed socket write and the final owner check."""
        try:
            sent_payload = False
            chunks = iter(frames)
            exhausted = object()
            for frame in chunks:
                require(type(frame) is bytes and frame, "Invalid stock fixture handoff framing")
                final = frame == HANDOFF_END
                if final:
                    require(sent_payload and next(chunks, exhausted) is exhausted,
                            "Invalid stock fixture handoff framing")
                with self._lock:
                    self._require_current(authority)
                    require(request is self._request and pending is self._pending, "Wrong stock fixture handoff")
                    if not final:
                        send(frame)
                        sent_payload = True
                        continue
                    # A worker can dispatch as soon as the final write reaches it.
                    # Keep the authority lock through the write and publication.
                    with closing(self._connect()) as db, db:
                        db.execute("BEGIN IMMEDIATE")
                        self._verify_journal(self._rows(db))
                        self._require_current(authority)
                        send(frame)
                    self._require_current(authority)
                    if pending.calls:
                        self._eligible = pending
                    else:
                        self._closed += (self._user, *self._prefix, pending.completed_message)
                        self._prefix = ()
                        self._user = None
                    self._pending = self._request = None
                    return
            require(False, "Incomplete stock fixture handoff")
        except Exception:
            self.fail(request)
            raise
