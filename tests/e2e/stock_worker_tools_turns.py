"""Fixture-only cumulative turn state and durable synthetic exposure records."""

from contextlib import closing, contextmanager
from dataclasses import dataclass
import json
import os
from secrets import token_hex
import sqlite3
import stat
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
_MAX_LEDGER_BYTES = 256 * 1024
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


class PinnedLedger:
    """Keep SQLite's filesystem VFS out of the descriptor-bound capture journal."""

    def __init__(self, name, scratch):
        self.name = name
        self.scratch = scratch
        self._identity = self._candidate = None
        self.publication_uncertain = False

    def owns(self, info):
        return (
            stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_uid == os.geteuid() and info.st_nlink == 1
            and any(identity is not None and os.path.samestat(info, identity)
                    for identity in (self._identity, self._candidate))
        )

    def read(self, directory):
        fd = os.open(self.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(fd)
            require(self.owns(before), "Capture exposure ledger identity changed")
            require(0 < before.st_size <= _MAX_LEDGER_BYTES, "Wrong capture exposure ledger size")
            payload = stream.read(_MAX_LEDGER_BYTES + 1)
            after = os.stat(self.name, dir_fd=directory, follow_symlinks=False)
            require(self.owns(after) and os.path.samestat(before, after)
                    and (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    == (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    and len(payload) == before.st_size,
                    "Capture exposure ledger changed during read")
        return payload, before

    def publish(self, db, directory, verify, previous):
        self.scratch.require_active()
        verify()
        pages = db.execute("PRAGMA page_count").fetchone()[0]
        page_size = db.execute("PRAGMA page_size").fetchone()[0]
        require(0 < pages * page_size <= _MAX_LEDGER_BYTES, "Wrong capture exposure ledger size")
        payload = db.serialize()
        require(len(payload) == pages * page_size, "Wrong serialized capture ledger size")
        staged = f".ledger-{token_hex(12)}"
        fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        staged_identity = None
        try:
            with os.fdopen(fd, "wb") as stream:
                staged_identity = os.fstat(fd)
                stream.write(payload)
                stream.flush()
                os.fsync(fd)
            verify()
            self._install_snapshot(directory, staged, staged_identity, previous)
            os.fsync(directory)
            verify()
            self.scratch.require_active()
        except BaseException as primary:
            self._remove_staging(directory, staged, staged_identity, primary)
            raise

    def _install_snapshot(self, directory, staged, staged_identity, previous):
        named = os.stat(staged, dir_fd=directory, follow_symlinks=False)
        require(os.path.samestat(staged_identity, named), "Capture exposure staging identity changed")
        if previous is None:
            self.scratch.require_active()
            self._candidate = staged_identity
            self.publication_uncertain = True
            os.link(staged, self.name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
            self._identity, self._candidate = staged_identity, None
            os.unlink(staged, dir_fd=directory)
            return
        named = os.stat(self.name, dir_fd=directory, follow_symlinks=False)
        require(self.owns(named) and os.path.samestat(named, previous)
                and (named.st_size, named.st_mtime_ns, named.st_ctime_ns)
                == (previous.st_size, previous.st_mtime_ns, previous.st_ctime_ns),
                "Capture exposure ledger changed before replacement")
        self.scratch.require_active()
        # Either known inode may be present if replacement persists before raising.
        self._candidate = staged_identity
        self.publication_uncertain = True
        os.replace(staged, self.name, src_dir_fd=directory, dst_dir_fd=directory)
        self._identity, self._candidate = staged_identity, None

    @staticmethod
    def _remove_staging(directory, name, identity, primary):
        try:
            if identity is not None and os.path.samestat(identity, os.stat(name, dir_fd=directory, follow_symlinks=False)):
                os.unlink(name, dir_fd=directory)
        except FileNotFoundError:
            pass
        except BaseException as secondary:
            primary.add_note(f"Unable to remove exposure staging file: {type(secondary).__name__}")

    @contextmanager
    def database(self, *, write, initialize):
        with self.scratch.borrow() as (directory, verify), closing(sqlite3.connect(":memory:")) as db:
            previous = None
            if not initialize:
                payload, previous = self.read(directory)
                db.deserialize(payload)
            yield db
            if write:
                self.publish(db, directory, verify, previous)
            else:
                verify()
                self.scratch.require_active()


class FixtureTurns:
    """One thread-safe synthetic grant. Opening an existing ledger cannot resume it."""

    def __init__(self, path, authority, *, clock=time.monotonic, ledger=None):
        self._ledger = ledger
        if self._ledger is None:
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
        self.settlement_uncertain = False
        self._turn = self._continuations = self._writes = 0
        with self._database(write=True, initialize=True) as db, db:
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
        self._confirm_publication()
        self._deadline = clock() + DEADLINE_SECONDS

    def _connect(self):
        # mode=rw prevents a removed ledger from being silently recreated.
        return sqlite3.connect(self._path.resolve().as_uri() + "?mode=rw", uri=True)

    def _database(self, *, write=False, initialize=False):
        if self._ledger is None:
            return closing(self._connect())
        return self._ledger.database(write=write, initialize=initialize)

    def _confirm_publication(self):
        if self._ledger is not None:
            self._ledger.publication_uncertain = False

    def _require_current(self, authority):
        require(self._owner_current and authority == self._authority and self._clock() < self._deadline,
                "Stale or expired stock fixture authority")
        if self._ledger is not None:
            self._ledger.scratch.require_active()

    def retire(self):
        with self._lock:
            self._owner_current = False

    def fail(self, request):
        with self._lock:
            if request is not None and self._request is request:
                self._owner_current = False

    def records(self):
        with self._lock, self._database() as db:
            db.row_factory = sqlite3.Row
            return [dict(row) for row in db.execute("SELECT * FROM exposure ORDER BY sequence")]

    def verified_records(self):
        """Snapshot bounded durable records after the fixture observer has stopped."""
        with self._lock, self._database() as db:
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
            if request is None:
                matched = digest(rows) == self._anchor
            else:
                matched = bool(rows) and digest(rows[:-1]) == self._anchor and all(
                    type(value) is type(expected) and value == expected
                    for value, expected in zip(rows[-1], self._claimed_row(request), strict=True)
                )
        except (TypeError, ValueError):
            matched = False
        if not matched:
            self._owner_current = False
        require(matched, "Stock fixture exposure needs reconciliation")

    def _claim(self, request):
        with self._database(write=True) as db, db:
            db.execute("BEGIN IMMEDIATE")
            self._require_current(self._authority)
            rows = self._rows(db)
            self._verify_journal(rows)
            used_input = sum(row[-2] for row in rows)
            used_output = sum(row[-1] for row in rows)
            require(len(rows) < MAX_WRITES and used_input + MAX_INPUT <= TOTAL_INPUT
                    and used_output + MAX_OUTPUT <= TOTAL_OUTPUT, "Stock fixture write budget exceeded")
            db.execute("INSERT INTO exposure VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", self._claimed_row(request))
        self._confirm_publication()

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
                if self._ledger is not None:
                    self._ledger.scratch.authorize_first_write(deadline=self._deadline, clock=self._clock)
                return request, start(request)
            except BaseException:
                self._owner_current = False
                raise

    def _settle_usage(self, request, input_tokens, output_tokens):
        with self._database(write=True) as db, db:
            db.execute("BEGIN IMMEDIATE")
            rows = self._rows(db)
            self._verify_journal(rows, request=request)
            db.execute("UPDATE exposure SET actual_input = ?, actual_output = ? WHERE sequence = ?",
                       (input_tokens, output_tokens, request.sequence))
            anchor = digest(self._rows(db))
        self._anchor = anchor
        self._confirm_publication()

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
            except BaseException:
                if self._ledger is not None and self._ledger.publication_uncertain:
                    self.settlement_uncertain = True
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
                    with self._database() as db, db:
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
