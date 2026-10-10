"""Audit rows older than ``audit_hot_days`` kept as compressed daily blocks (the format is
app/core/audit_archive_format.py, the table ``audit_archive_blocks``).

Archiving deletes nothing: every row moves, whole, into a block, and comes back with ``audit unarchive``. So
shrinking the row window is not a reduction, and it applies at once.

The pruner's ``audit_archive`` job, after the audit job, each pass:

1. waits out the grace period: archiving starts ``audit_archive_start_after_days`` (AUDIT_ARCHIVE_START_AFTER_DAYS,
   14 by default) after the chain's genesis, which the first start of this release writes on its first pass and
   which the chain authenticates (a database writer cannot move it). Until then a rollback needs no unarchive. A
   day ``audit unarchive`` put back stays rows for the same grace (at least a day) after that, so a rollback right
   after an unarchive finds no new block;
2. takes the oldest UTC day older than ``audit_hot_days`` (90 by default, 31 to 3650, so the 30-day summary
   band never reaches the archive) whose every hour is sealed, and cuts it into parts of whole hours, at most
   PART_ROWS rows each (an hour with more rows gets a part of its own); at most DAYS_PER_PASS days and
   ROW_BUDGET rows a pass;
3. archives one part per transaction, under the chain lock: it writes the block while reading the part's rows
   once, in order, inserts it, reads it back from the table and checks it there: its length and digest, every
   column of every row against the rows it read (the format's identity digest), each hour's count, both roots
   and ids digest against the hour's root seal as the verified view names it (read again, its link checked), and
   the aggregates. Only then does it delete the rows, which must be exactly the ones it wrote, clear
   the hours' working data (the block keeps their salt), keep the data marker (data_requirements) that stops a
   release that cannot read blocks from starting, and write the ``archive`` seal of the day, listing every part
   the day has so far. Anything that does not check out rolls the whole transaction back: the rows stay, and a
   mismatch with the seals is reported as a failure.

An hour is left as rows (not a finding) while an erase seal follows its root seal (an erase over blocks comes
with per-person erase), and while its root seal, or an erase after it, is a seal another writer appended after
the head record that the host has not acknowledged.

A day archived over several transactions gets one ``archive`` seal per transaction; the one whose parts cover
all the day's hours the chain covers says ``complete``.

Changing archived rows (the audit job's deletions now; the erase and the address rewrite later) goes through
rewrite_day(), the block-rewrite primitive: every block of the day is checked against the day's ``archive``
seal (length, digest) and its hours against their seals, and a part the change touches is written again and
checked the same way, all in one transaction, so a check that fails anywhere leaves every block as it was; the
change's own seal (a ``prune``) and then an ``archive`` seal of cause ``rewrite`` naming it commit with them. A
day whose rows are all gone loses its blocks. No part's rows are held: a part is read as a stream, checked as it
goes (PartReader), once to pick the rows the change touches and once to write it anew, and unarchive puts rows
back a chunk at a time.

The size cap counts each archived part as the smaller of its bound length (the ``archive`` seal's) and the lagged
bytes of the hours it holds (app/core/audit_chain_size.py).

The host's ``audit unarchive`` restores a range of days as rows (identical rows, so the seals still hold), writes
back each hour's working data (row_ids, checked against the seal, and the salt the block kept), removes the
blocks and writes an ``archive`` seal with no parts, in two phases like every host command that writes a seal.
``audit compact`` is a VACUUM FULL of the audit tables: Postgres gives freed space back to the system only that
way, and it blocks audit writes while it runs.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Tuple

import sqlalchemy as sa
from sqlalchemy import Text, cast, func, text

from app.core import audit_archive_format as af
from app.core import audit_chain_format as fmt
from app.core import settings_registry as registry
from app.core.audit_chain_view import ArchivePart

HOT_DAYS_KEY = "audit_hot_days"
START_AFTER_KEY = "audit_archive_start_after_days"

registry.register(registry.SettingSpec(
    key=HOT_DAYS_KEY, kind="int", default=90, env="audit_hot_days", minimum=31, maximum=3650,
    group="audit_retention", unit="days", label="Keep audit rows uncompressed for",
    help="Older days are compressed into daily blocks, each checked against the log's seals before its rows "
         "are removed. Nothing is deleted: the rows can be restored with dockvault.py audit unarchive."))
registry.register(registry.SettingSpec(
    key=START_AFTER_KEY, kind="int", default=14, env="audit_archive_start_after_days", minimum=0, maximum=90,
    editable=registry.ENV_ONLY, group="audit_retention", unit="days",
    label="Days after this release first ran before archiving begins",
    help="Until then nothing is compressed, so going back to an earlier release needs no unarchive."))

PART_ROWS = 50000
DAYS_PER_PASS = 7
DAY = timedelta(days=1)
HOUR = timedelta(hours=1)
# The restored size of a block, from the measured 85-92 % reduction: 7 to 12 times its compressed size.
RESTORE_LOW, RESTORE_HIGH = 7, 12

# The data marker (data_requirements) kept while any block exists.
MARKER_KEY = "archived-audit-history"
MARKER_REASON = ("Archived audit history: part of the audit log is kept in compressed daily blocks, which "
                 "releases before {introduced} cannot read. They would neither show nor export those days, and "
                 "would not keep them.")
MARKER_UNDO = ("Restore the archived days as rows with `python dockvault.py audit unarchive` (it checks the free "
               "space first); the marker goes with the last block.")

UNARCHIVED_ACTION = "audit_archive_restored"


def _ai():
    from app.core import audit_integrity
    return audit_integrity


def _say(message: str) -> None:
    registry._say(message)


def day_start(d: date) -> datetime:
    return datetime.combine(d, time())


def hours_between(first: datetime, last: datetime) -> List[datetime]:
    """The hours from ``first`` to ``last``, both included."""
    out, h = [], first
    while h <= last:
        out.append(h)
        h += HOUR
    return out


def hot_days() -> int:
    try:
        return int(registry.resolve(HOT_DAYS_KEY))
    except Exception:  # noqa: BLE001 -- the default until the registry answers
        return 90


def start_after_days() -> int:
    try:
        return int(registry.resolve(START_AFTER_KEY))
    except Exception:  # noqa: BLE001
        return 14


def _is_pg(db) -> bool:
    bind = db.get_bind()
    return bind is not None and bind.dialect.name == "postgresql"


def _length(column, db):
    return func.octet_length(column) if _is_pg(db) else func.length(column)


class NotVerified(Exception):
    """Rows or a block that do not give the seals: nothing is changed, and the kind is reported."""

    def __init__(self, kind: str, message: str, hour: Optional[str] = None):
        super().__init__(message)
        self.kind = kind
        self.hour = hour


# A block of a later block format (audit_archive_format.LaterFormat): reported as a warning by a check, and the day
# left as it is by every change (a change of rows, the size cap's, unarchive).
LATER_FORMAT = "block-later-format"


class NotArchivable(Exception):
    """A day, part or hour that is left as it is this time (not a finding)."""


# --------------------------------------------------------------------------- when archiving may run

def first_start(view) -> Optional[datetime]:
    """When this release first ran on this database: its genesis seal's time, as the verified view holds it."""
    return view.at(1) if view.position else None


def starts_at(view) -> Optional[datetime]:
    """When archiving may begin: the chain's genesis plus the grace. None before genesis."""
    first = first_start(view)
    return first + timedelta(days=start_after_days()) if first is not None else None


def unarchived_until(view, day: date) -> Optional[datetime]:
    """Until when a day ``audit unarchive`` put back stays rows: its unarchive seal's time plus the grace (at
    least a day). None for any other day."""
    entry = view.archives.get(day)
    if entry is None or entry.cause != "unarchive":
        return None
    return view.at(entry.seq) + timedelta(days=max(1, start_after_days()))


def day_hours(view, day: date) -> List[datetime]:
    """The hours of ``day`` the chain covers: from its first hour (the chain's first hour on the day it starts)
    to the day's last."""
    start = day_start(day)
    first = view.first_hour()
    if first is not None and first > start:
        start = first
    return hours_between(start, day_start(day) + DAY - HOUR) if start < day_start(day) + DAY else []


def covers_day(view, parts, day: date) -> bool:
    """Whether the parts' hour ranges cover every hour of ``day`` the chain covers, none twice."""
    seen = set()
    for p in parts:
        for h in hours_between(p.first_hour, p.last_hour):
            if h in seen or h.date() != day:
                return False
            seen.add(h)
    wanted = day_hours(view, day)
    return bool(wanted) and seen == set(wanted)


# --------------------------------------------------------------------------- reading rows and hours

def _full_columns(db):
    from app.core.audit_retention import _row_bytes
    from app.core.models import AuditLog as A
    cols = [cast(getattr(A, n), Text) if n in af.JSON_NAMES else getattr(A, n) for n in af.NAMES]
    cols.append(_row_bytes(A, db.get_bind().dialect.name))
    return cols


def iter_full_rows(db, start: datetime, end: datetime) -> Iterator[dict]:
    """Every column of the rows of [start, end) (JSON columns as their stored text), and each row's stored
    size, in (timestamp, id) order, streamed."""
    from app.core.models import AuditLog as A
    q = db.query(*_full_columns(db)).filter(A.timestamp >= start, A.timestamp < end)
    width = len(af.NAMES)
    for r in q.order_by(A.timestamp, A.id).yield_per(2000):
        row = dict(zip(af.NAMES, r[:width]))
        row["id"] = fmt.as_uuid(row["id"])
        if row.get("seal_nonce") is not None:
            row["seal_nonce"] = bytes(row["seal_nonce"])
        row["_bytes"] = int(r[width] or 0)
        yield row


def hour_counts(db, start: datetime, end: datetime) -> Dict[datetime, int]:
    from app.core.audit_retention import _as_time, _hour
    from app.core.models import AuditLog as A
    hour = _hour(A, db.get_bind().dialect.name)
    rows = db.query(hour, func.count()).filter(A.timestamp >= start, A.timestamp < end).group_by(hour).all()
    return {_as_time(h): int(n) for h, n in rows}


def _root(db, view, hour: datetime):
    """``hour``'s root entry with its roots, read again through the link table; None for an hour the chain does
    not cover. Raises NotVerified (link-broken) for a seal changed after the view accepted it."""
    ai = _ai()
    try:
        return ai.hour_root(db, view, hour)
    except ai.ChainStopped as stop:
        raise NotVerified("link-broken", str(stop), fmt.hour_text(hour)) from None


def _c_prev(db, view, hour: datetime) -> Dict:
    """The earlier commitments of the rows an erase seal after ``hour``'s root seal changed."""
    ai = _ai()
    own = view.own_entry(hour)
    if own is None or not own.erases:
        return {}
    try:
        return ai.erase_c_prev(db, view, own)
    except ai.ChainStopped as stop:
        raise NotVerified("link-broken", str(stop), fmt.hour_text(hour)) from None


def held_hour(view, record: Optional[dict], hour: datetime) -> Optional[int]:
    """The seal that keeps ``hour`` as it is (app/core/audit_integrity.py hour_held), or None."""
    return _ai().hour_held(view, record, hour)


EMPTY = (0, fmt.EMPTY_ROOT, fmt.EMPTY_ROOT, fmt.ids_digest([]))


def check_hours(db, view, hours: List[datetime], figs: Dict[datetime, object],
                expected: Optional[Dict[datetime, tuple]] = None) -> None:
    """Each hour of ``hours`` must give its root seal (or ``expected``'s figures); no row may lie outside them.
    Raises NotVerified."""
    wanted = set(hours)
    for h in figs:
        if h not in wanted:
            raise NotVerified("rows-added", f"rows in {fmt.hour_text(h)}, outside the part that holds them",
                              fmt.hour_text(h))
    for h in hours:
        fig = figs.get(h)
        label = fmt.hour_text(h)
        if fig is not None and fig.missing_nonce:
            raise NotVerified("nonce-missing", f"{len(fig.missing_nonce)} rows in {label} have no nonce and the "
                                               "hour no salt", label)
        got = (fig.count, fig.root_s, fig.root_c, fig.ids_digest) if fig is not None else EMPTY
        if expected is not None and h in expected:
            want = expected[h]
        else:
            root = _root(db, view, h)
            if root is None:
                if got[0]:
                    raise NotVerified("rows-added", f"{got[0]} rows in {label}, an hour the chain does not cover",
                                      label)
                continue
            want = (root.count, root.root_s, root.root_c, root.ids_digest)
        if got == want:
            continue
        kind = "rows-missing" if got[0] < want[0] else "rows-added" if got[0] > want[0] else "rows-altered"
        raise NotVerified(kind, f"the rows of {label} do not give its seal", label)


# --------------------------------------------------------------------------- blocks and their seal

def stored_blocks(db, day: Optional[date] = None) -> Dict[tuple, int]:
    """{(day, part): octet_length(payload)} of the blocks (of ``day``, or all): no payload is read (stored without
    compression, a block's length is in its pointer)."""
    from app.core.models import AuditArchiveBlock as B
    q = db.query(B.day, B.part, _length(B.payload, db))
    if day is not None:
        q = q.filter(B.day == day)
    return {(_as_date(d), int(p)): int(n or 0) for d, p, n in q.all()}


def _as_date(d) -> date:
    if isinstance(d, datetime):
        return d.date()
    if isinstance(d, date):
        return d
    return date.fromisoformat(str(d)[:10])


def read_payload(db, day: date, number: int) -> Optional[bytes]:
    from app.core.models import AuditArchiveBlock as B
    r = db.query(B.payload).filter(B.day == day, B.part == number).first()
    return bytes(r[0]) if r is not None and r[0] is not None else None


def _stored_aggregates(db, day: date, number: int):
    from app.core.models import AuditArchiveBlock as B
    r = db.query(B.aggregates).filter(B.day == day, B.part == number).first()
    return r[0] if r is not None else None


def _label(day: date, part) -> str:
    return f"{day.isoformat()} part {part.part}"


def open_part(db, day: date, part, payload: Optional[bytes] = None) -> af.Block:
    """The block of ``part`` once its length and digest are the ones its archive seal binds. Raises NotVerified
    (block-missing, block-altered)."""
    if payload is None:
        payload = read_payload(db, day, part.part)
    if payload is None:
        raise NotVerified("block-missing", f"the block of {_label(day, part)} is gone")
    if len(payload) != part.length or af.digest(payload) != part.sha256:
        raise NotVerified("block-altered", f"the block of {_label(day, part)} is not the one its archive seal names")
    try:
        return af.open_block(payload)
    except af.LaterFormat as exc:
        # Its archive seal binds it, so a sealer wrote it: a later release's, which this one leaves as it is.
        raise NotVerified(LATER_FORMAT, f"the block of {_label(day, part)} is of {exc}: this release neither "
                                        "checks nor changes it") from None
    except af.BlockError as exc:
        raise NotVerified("block-altered", f"the block of {_label(day, part)} cannot be read: {exc}") from None


class PartReader:
    """The rows of a part, read from its block one at a time and checked: the block against its archive seal before
    anything is read (length, digest, the part it says it is, the hours of its salts), each hour's figures built
    as its rows go by, and, once the last row has been read, the row count, each hour against its root seal (or
    ``expected``), and the block's aggregates. Nothing holds the rows, so a part of any size is read in fixed
    memory (only each hour's ids grow with it). A caller that stops early calls finish(), which reads the rest and
    runs the checks; a check that fails raises NotVerified, and the caller's transaction then rolls back whatever
    it did with the rows."""

    def __init__(self, db, view, day: date, part, *, expected: Optional[Dict[datetime, tuple]] = None):
        self.db, self.view, self.day, self.part, self.expected = db, view, day, part, expected
        self.block = open_part(db, day, part)
        if self.block.header.get("day") != day.isoformat() or self.block.header.get("part") != part.part:
            raise NotVerified("block-altered", f"the block of {_label(day, part)} says it is another part")
        self.hours = hours_between(part.first_hour, part.last_hour)
        try:
            self.salts = self.block.salts
        except (TypeError, ValueError, AttributeError):
            raise NotVerified("block-altered", f"the block of {_label(day, part)} has salts it cannot read") from None
        if any(h not in set(self.hours) for h in self.salts):
            raise NotVerified("block-altered", f"the block of {_label(day, part)} keeps a salt of an hour it does "
                                               "not hold")
        self.c_prev = {h: _c_prev(db, view, h) for h in self.hours} if expected is None else {}
        self.figs: Dict[datetime, object] = {}
        self.checked = False
        self._iter = None

    def rows(self) -> Iterator[dict]:
        if self._iter is None:
            self._iter = self._rows()
        return self._iter

    def _rows(self) -> Iterator[dict]:
        ai = _ai()
        current, builder = None, None
        try:
            for row in self.block.rows():
                if not isinstance(row.get("timestamp"), datetime):
                    raise NotVerified("block-altered", f"a row of {_label(self.day, self.part)} has no time")
                hour = ai.hour_floor(row["timestamp"])
                if hour != current:
                    if builder is not None:
                        self.figs[current] = builder.result()
                    if hour in self.figs:
                        raise NotVerified("rows-altered", f"the rows of {fmt.hour_text(hour)} are out of order",
                                          fmt.hour_text(hour))
                    current = hour
                    builder = ai.FiguresBuilder(self.salts.get(hour), self.c_prev.get(hour) or None)
                builder.add(row)
                yield row
        except af.BlockError as exc:
            raise NotVerified("block-altered", f"the block of {_label(self.day, self.part)} cannot be read: "
                                               f"{exc}") from None
        if builder is not None:
            self.figs[current] = builder.result()
        self._check()

    def _check(self) -> None:
        label = _label(self.day, self.part)
        if self.block.count != self.part.rows:
            raise NotVerified("block-altered", f"the block of {label} holds {self.block.count} rows; its seal "
                                               f"{self.part.rows}")
        check_hours(self.db, self.view, self.hours, self.figs, self.expected)
        if _stored_aggregates(self.db, self.day, self.part.part) != self.block.aggregates:
            raise NotVerified("block-altered", f"the aggregates of {label} are not its rows'")
        self.checked = True

    def finish(self) -> "PartReader":
        """Read whatever is left and run the checks (NotVerified). Returns itself."""
        for _row in self.rows():
            pass
        if not self.checked:
            raise NotVerified("block-altered", f"the block of {_label(self.day, self.part)} was not read to its end")
        return self


def sync_marker(db, now: datetime, present: Optional[bool] = None) -> bool:
    """Keep the data marker while any block exists, in the caller's transaction. Returns whether it is there."""
    from app.core import recording_marker as rm
    from app.core.models import AuditArchiveBlock as B
    if present is None:
        present = db.query(B.day).first() is not None
    rm._ensure_table(db)
    if not present:
        db.execute(text(f"DELETE FROM {rm.TABLE} WHERE key = :key"), {"key": MARKER_KEY})
        return False
    params = {"key": MARKER_KEY, "version": rm.required_version(),
              "reason": MARKER_REASON.format(introduced=rm.INTRODUCED), "undo": MARKER_UNDO, "since": now}
    updated = db.execute(text(f"UPDATE {rm.TABLE} SET requires_at_least = :version, reason = :reason, "
                              "undo = :undo WHERE key = :key"), params).rowcount
    if not updated:
        db.execute(text(f"INSERT INTO {rm.TABLE} (key, requires_at_least, reason, undo, since) "
                        "VALUES (:key, :version, :reason, :undo, :since)"), params)
    return True


def _write_archive_seal(w, day: date, cause: str, parts, *, after_seq: Optional[int] = None):
    parts = sorted(parts, key=lambda p: p.first_hour)
    detail = {"day": day.isoformat(), "cause": cause, "after_seq": after_seq,
              "complete": bool(parts) and covers_day(w.st.view, parts, day), "parts": [p.as_list() for p in parts]}
    return w.append("archive", period_start=day_start(day), period_end=day_start(day) + DAY,
                    row_count=sum(p.rows for p in parts), row_bytes=sum(p.length for p in parts), detail=detail)


def _insert_block(db, day: date, number: int, first: datetime, last: datetime, bw: af.BlockWriter,
                  payload: bytes, now: datetime) -> None:
    from sqlalchemy.exc import IntegrityError
    from app.core.models import AuditArchiveBlock as B
    db.add(B(day=day, part=number, first_hour=first, last_hour=last, row_count=bw.rows, codec=af.CODEC,
             format=af.FORMAT, payload=payload, raw_bytes=bw.raw_bytes, aggregates=bw.aggregates,
             created_at=now))
    try:
        db.flush()
    except IntegrityError:
        # A block of that number written since the day's blocks were checked: the caller rolls back.
        raise NotVerified("block-unsealed", f"a block of {day.isoformat()} (part {number}) is in no archive "
                                            "seal") from None


def _check_stored(db, view, day: date, part, bw: af.BlockWriter,
                  expected: Optional[Dict[datetime, tuple]] = None) -> None:
    """The block as the table now holds it: its length, digest, rows (every column), hours and aggregates.
    Raises NotVerified."""
    lengths = stored_blocks(db, day)
    if lengths.get((day, part.part)) != part.length:
        raise NotVerified("block-altered", f"the block of {_label(day, part)} was not stored whole")
    block = PartReader(db, view, day, part, expected=expected).finish().block
    if block.identity.digest() != bw.identity.digest():
        raise NotVerified("block-altered", f"the block of {_label(day, part)} does not give back the rows written "
                                           "into it")


# --------------------------------------------------------------------------- archiving

def next_day(db, view, now: datetime, skipped: set) -> Optional[date]:
    """The oldest day archiving may take now: with rows in audit_logs at or after the chain's first hour, older
    than the row window, sealed whole, and not one ``audit unarchive`` put back within its grace."""
    from app.core.models import AuditLog as A
    first = view.first_hour()
    if first is None or view.newest_hour_end is None:
        return None
    limit = min(day_start((now - timedelta(days=hot_days())).date()), day_start(view.newest_hour_end.date()))
    after = first
    while after < limit:
        t = db.query(func.min(A.timestamp)).filter(A.timestamp >= after, A.timestamp < limit).scalar()
        if t is None:
            return None
        d = t.date()
        until = unarchived_until(view, d)
        if d not in skipped and (until is None or now >= until):
            return d
        after = day_start(d) + DAY
    return None


def plan_part(counts: Dict[datetime, int], start: datetime, end: datetime) -> Tuple[datetime, datetime]:
    """The next part from ``start``: whole hours, up to PART_ROWS rows, the last part of the day reaching its
    last hour. An hour with more rows than PART_ROWS is a part of its own."""
    total = 0
    h = start
    while h < end:
        n = counts.get(h, 0)
        if n and total and total + n > PART_ROWS:
            return start, h - HOUR
        total += n
        h += HOUR
    return start, end - HOUR


def archive_next_part(w, day: date, now: datetime):
    """Archive the next part of ``day`` in ``w``'s transaction. Returns the archive seal, or None when the
    day has no rows left after its parts. Raises NotVerified (a finding) or NotArchivable."""
    from app.core.models import AuditLog as A
    ai = _ai()
    db, view = w.db, w.st.view
    entry = view.archives.get(day)
    if entry is not None and entry.complete:
        raise NotArchivable(f"{day.isoformat()} is archived whole, and has rows in audit_logs")
    prev = sorted(entry.parts, key=lambda p: p.first_hour) if entry is not None else []
    # A block the day's archive seal does not name (or one it names gone, or of another length) is a finding: the
    # day is left as it is, and the pass goes on with the next day.
    _check_day_blocks(db, entry, day)
    covered = day_hours(view, day)
    if not covered:
        return None
    start = max(prev[-1].last_hour + HOUR, covered[0]) if prev else covered[0]
    end = day_start(day) + DAY
    if view.newest_hour_end is None or view.newest_hour_end < end:
        raise NotArchivable(f"{day.isoformat()} is not sealed whole")
    counts = hour_counts(db, start, end)
    if not counts:
        return None
    first, last = plan_part(counts, start, end)
    hours = hours_between(first, last)
    for h in hours:
        if view.entry_for(h) is None:
            if counts.get(h):
                raise NotArchivable(f"{fmt.hour_text(h)} has rows and no seal")
            continue
        own = view.own_entry(h)
        if own is not None and own.erases:
            raise NotArchivable(f"{fmt.hour_text(h)} has an erase after its seal")
        held = held_hour(view, w.record, h)
        if held is not None:
            raise NotArchivable(f"{fmt.hour_text(h)}'s seal {held} was appended by another writer and waits for "
                                "the host")
    salts = {}
    for h in hours:
        if counts.get(h):
            wr = ai.working_row(db, h)
            if wr is not None and wr.legacy_salt is not None:
                salts[h] = bytes(wr.legacy_salt)
    number = max((p.part for p in prev), default=0) + 1
    bw = af.BlockWriter(day, number, salts)
    for row in iter_full_rows(db, first, last + HOUR):
        bw.add(row)
    payload = bw.finish()
    part = ArchivePart(number, first, last, bw.rows, len(payload), af.digest(payload))
    _insert_block(db, day, number, first, last, bw, payload, now)
    _check_stored(db, view, day, part, bw)
    gone = db.query(A).filter(A.timestamp >= first, A.timestamp < last + HOUR).delete(synchronize_session=False)
    if gone != bw.rows:
        raise NotArchivable(f"{gone} rows were in {fmt.hour_text(first)}..{fmt.hour_text(last)}, not the "
                            f"{bw.rows} archived: left for the checks")
    _clear_working_data(db, hours)
    sync_marker(db, now, True)
    return _write_archive_seal(w, day, "archive", prev + [part])


def _clear_working_data(db, hours: List[datetime]) -> None:
    ai = _ai()
    for h in hours:
        wr = ai.working_row(db, h)
        if wr is not None:
            wr.row_ids = None
            wr.legacy_salt = None


def archive_job(p):
    """The pruner's audit_archive job (see the module's docstring). Never deletes a row it has not archived."""
    from app.core import retention
    ai = _ai()
    st = ai.state()
    result = retention.JobResult()
    with p.transaction() as db:
        _daily_marker(db, p.now)
    if st.stopped is not None or st.view.newest_policy() is None:
        return result
    begins = starts_at(st.view)
    if begins is None or p.now < begins:
        return result
    engine = ai._engine_of(p.session_factory)
    failures: Dict[str, str] = {}
    try:
        _archive_days(p, engine, st, failures)
    except (ai.ChainStopped, ai.ChainBusy) as exc:
        _say(f"The audit archive waits for the audit chain ({type(exc).__name__})")
    if failures:
        ai.report_failures(st, p.session_factory, failures)
    return result


def _archive_days(p, engine, st, failures: Dict[str, str]) -> None:
    ai = _ai()
    skipped: set = set()
    days: set = set()
    rows = 0
    while p.time_left() and len(days) < DAYS_PER_PASS and rows < ai.ROW_BUDGET:
        seal = None
        day = None
        with ai.ChainWriter(engine, st) as w:
            day = next_day(w.db, w.st.view, p.now, skipped)
            if day is None:
                break
            try:
                seal = archive_next_part(w, day, p.now)
            except NotVerified as nv:
                failures[nv.kind] = f"{nv}; the day was not archived"
                seal = None
            except NotArchivable as why:
                _say(f"The audit archive leaves {day.isoformat()} as rows for now: {why}")
                seal = None
            if seal is None:
                w.db.rollback()
                skipped.add(day)
        if seal is not None:
            days.add(day)
            rows += int(seal.detail["parts"][-1][3]) if seal.detail["parts"] else 0


_marker_checked: Dict[str, date] = {}


def _daily_marker(db, now: datetime) -> None:
    """The marker again, once a day (and at a process's first pass): there exactly while a block is."""
    if _marker_checked.get("on") == now.date():
        return
    sync_marker(db, now)
    _marker_checked["on"] = now.date()


# --------------------------------------------------------------------------- the block-rewrite primitive

@dataclass
class Rewritten:
    entries: List[list] = field(default_factory=list)   # the change seal's hours, as a prune seal lists them
    changed: int = 0
    oldest: Optional[datetime] = None
    newest: Optional[datetime] = None
    parts: list = field(default_factory=list)


def _check_day_blocks(db, entry, day: date) -> None:
    """Every block of ``day`` must be a part of its archive seal (``entry``, None when the day has none), and every
    part's block there at the length the seal binds; no payload is read. Raises NotVerified (block-unsealed,
    block-missing, block-altered)."""
    parts = {p.part: p for p in entry.parts} if entry is not None else {}
    stored = stored_blocks(db, day)
    for key in sorted(stored):
        if key[1] not in parts:
            raise NotVerified("block-unsealed", f"a block of {day.isoformat()} (part {key[1]}) is in no archive seal")
    for number, part in sorted(parts.items()):
        length = stored.get((day, number))
        if length is None:
            raise NotVerified("block-missing", f"the block of {_label(day, part)} is gone")
        if length != part.length:
            raise NotVerified("block-altered", f"the block of {_label(day, part)} is not the one its archive seal "
                                               "names")


def rewrite_day(w, day: date, pick: Callable[[Iterator[dict]], Dict], transform: Callable[[dict], Optional[dict]],
                now: datetime) -> Optional[Rewritten]:
    """Change rows of ``day``'s parts in ``w``'s transaction, a part at a time and holding none of its rows.
    ``pick(rows)`` reads a part's rows (all of them) and returns {id: timestamp} of those the change touches;
    ``transform(row)`` returns such a row as it is to be kept (rewritten where it rewrites it), or None to remove
    it. Every block is checked first (each part read once to pick, and checked to its end); a part with rows
    picked is read again and written anew, the nonces of its changed hours' rows materialised and those hours'
    salts dropped, and checked as stored. Returns what changed, or None when nothing did. The caller then writes
    its change's seal with ``entries`` and calls seal_rewrite(). Raises NotVerified, or NotArchivable when an hour
    it would change waits (another writer's seal the host has not acknowledged, or an erase after its seal)."""
    from app.core.models import AuditArchiveBlock as B
    ai = _ai()
    db, view = w.db, w.st.view
    entry = view.archives.get(day)
    if entry is None or not entry.parts:
        return None
    _check_day_blocks(db, entry, day)
    out = Rewritten()
    new_parts = []
    for part in sorted(entry.parts, key=lambda p: p.first_hour):
        try:
            reader = PartReader(db, view, day, part)
        except NotVerified as nv:
            if nv.kind == LATER_FORMAT:
                raise NotArchivable(str(nv)) from None
            raise
        touched = pick(reader.rows())
        reader.finish()
        if not touched:
            new_parts.append(part)
            continue
        changed_hours = sorted({ai.hour_floor(t) for t in touched.values()})
        for h in changed_hours:
            held = held_hour(view, w.record, h)
            if held is not None:
                raise NotArchivable(f"{fmt.hour_text(h)}'s seal {held} was appended by another writer and waits "
                                    "for the host")
            own = view.own_entry(h)
            if own is not None and own.erases:
                raise NotArchivable(f"{fmt.hour_text(h)} has an erase after its seal")
        salts = reader.salts
        new_salts = {h: salt for h, salt in salts.items() if h not in changed_hours}
        builders = {h: ai.FiguresBuilder() for h in changed_hours}
        bw = af.BlockWriter(day, part.part, new_salts)
        again = PartReader(db, view, day, part)
        for row in again.rows():
            h = ai.hour_floor(row["timestamp"])
            if row["id"] in touched:
                row = transform(dict(row))
                if row is None:
                    continue
            if h in builders:
                # The hour changes: each row's derived nonce is written into it, and the salt goes.
                if row.get("seal_nonce") is None and h in salts:
                    row["seal_nonce"] = fmt.legacy_nonce(salts[h], row["id"])
                builders[h].add(row)
            bw.add(row)
        again.finish()
        expected = {}
        for h in changed_hours:
            root = _root(db, view, h)
            f = builders[h].result()
            expected[h] = (f.count, f.root_s, f.root_c, f.ids_digest)
            out.entries.append(ai.hour_entry(h, root.seq, f))
        times = list(touched.values())
        out.changed += len(touched)
        out.oldest = min([t for t in (out.oldest,) if t is not None] + times)
        out.newest = max([t for t in (out.newest,) if t is not None] + times)
        payload = bw.finish()
        new = ArchivePart(part.part, part.first_hour, part.last_hour, bw.rows, len(payload), af.digest(payload))
        db.query(B).filter(B.day == day, B.part == part.part).update(
            {B.payload: payload, B.row_count: bw.rows, B.raw_bytes: bw.raw_bytes, B.aggregates: bw.aggregates,
             B.rewritten_at: now}, synchronize_session=False)
        db.flush()
        _check_stored(db, view, day, new, bw, expected)
        new_parts.append(new)
    if not out.entries:
        return None
    out.entries.sort(key=lambda e: e[0])
    if all(p.rows == 0 for p in new_parts):
        db.query(B).filter(B.day == day).delete(synchronize_session=False)
        new_parts = []
    out.parts = new_parts
    return out


def seal_rewrite(w, day: date, after_seq: int, rewritten: Rewritten, now: datetime):
    """The archive seal (cause rewrite) after a change's seal, in the same transaction, and the marker."""
    sync_marker(w.db, now)
    return _write_archive_seal(w, day, "rewrite", rewritten.parts, after_seq=after_seq)


# --------------------------------------------------------------------------- selecting archived rows

_probe = None


def probe_model():
    """A class mapped to a temporary table shaped like audit_logs, so the audit job's conditions, written over
    a model, select archived rows the way they select rows."""
    global _probe
    if _probe is None:
        from sqlalchemy.orm import registry as orm_registry
        from app.core.models import AuditLog
        table = sa.Table("audit_archive_probe", sa.MetaData(),
                         *[sa.Column(c.name, c.type, primary_key=c.primary_key) for c in AuditLog.__table__.columns],
                         prefixes=["TEMPORARY"], postgresql_on_commit="DROP")

        class ArchivedRow:
            __tablename__ = "audit_archive_probe"
            # The row-keep rules of audit_logs apply to these rows too (app/core/retention.py keep_clauses).
            __keep_rules_of__ = "audit_logs"

        orm_registry().map_imperatively(ArchivedRow, table)
        ArchivedRow.__table__ = table
        _probe = ArchivedRow
    return _probe


def _probe_table_name(db) -> str:
    return "pg_temp.audit_archive_probe" if _is_pg(db) else "temp.audit_archive_probe"


def probe_create(db) -> None:
    db.execute(text(f"DROP TABLE IF EXISTS {_probe_table_name(db)}"))
    probe_model().__table__.create(db.connection())


def probe_drop(db) -> None:
    try:
        db.execute(text(f"DROP TABLE IF EXISTS {_probe_table_name(db)}"))
    except Exception:  # noqa: BLE001 -- the transaction is being rolled back
        pass


def _probe_values(row: dict) -> dict:
    out = {}
    for name, kind in af.COLUMNS:
        v = row.get(name)
        out[name] = json.loads(v) if kind == "json" and v is not None else v
    return out


def matching(db, rows: Iterable[dict], conditions_for: Callable) -> Dict:
    """{id: timestamp} of the ``rows`` that ``conditions_for(model)`` selects: the rows go, PROBE_CHUNK at a time,
    into the temporary table, and the conditions run there; nothing is held but a chunk."""
    model = probe_model()
    table = model.__table__
    db.execute(table.delete())
    chunk: List[dict] = []
    for row in rows:
        chunk.append(_probe_values(row))
        if len(chunk) >= PROBE_CHUNK:
            db.execute(sa.insert(table), chunk)
            chunk = []
    if chunk:
        db.execute(sa.insert(table), chunk)
    found = {fmt.as_uuid(i): t for i, t in db.query(model.id, model.timestamp).filter(*conditions_for(model)).all()}
    db.execute(table.delete())
    return found


PROBE_CHUNK = 2000


def prune_day(w, day: date, conditions_for: Callable, now: datetime) -> Optional[Rewritten]:
    """The archived rows of ``day`` that ``conditions_for(model)`` selects, removed through rewrite_day in ``w``'s
    transaction. Raises NotVerified, NotArchivable."""
    probe_create(w.db)
    try:
        return rewrite_day(w, day, lambda rows: matching(w.db, rows, conditions_for), lambda row: None, now)
    finally:
        probe_drop(w.db)


# --------------------------------------------------------------------------- the host's commands

def _parse_day(value: Optional[str]) -> Optional[date]:
    if not value:
        return None
    return date.fromisoformat(value[:10])


def estimate(db, first: Optional[date], last: Optional[date]) -> dict:
    """What restoring the archived days from ``first`` to ``last`` would add to the database: 7 to 12 times the
    blocks' compressed size."""
    from app.core.models import AuditArchiveBlock as B
    q = db.query(func.count(), func.count(sa.distinct(B.day)), func.coalesce(func.sum(_length(B.payload, db)), 0),
                 func.coalesce(func.sum(B.row_count), 0), func.coalesce(func.sum(B.raw_bytes), 0))
    if first is not None:
        q = q.filter(B.day >= first)
    if last is not None:
        q = q.filter(B.day <= last)
    blocks, days, compressed, rows, raw = q.one()
    compressed = int(compressed or 0)
    return {"days": int(days or 0), "blocks": int(blocks or 0), "rows": int(rows or 0), "compressed_bytes": compressed,
            "raw_bytes": int(raw or 0), "restored_low_bytes": compressed * RESTORE_LOW,
            "restored_high_bytes": compressed * RESTORE_HIGH}


def _insert_rows(db, rows: List[dict]) -> None:
    """Insert ``rows`` into audit_logs exactly as archived (JSON columns from their stored text)."""
    from app.core.models import AuditLog
    table = AuditLog.__table__
    pg = _is_pg(db)
    values = {}
    for name, kind in af.COLUMNS:
        column = table.c[name]
        if kind == "json":
            bound = sa.type_coerce(sa.bindparam("v_" + name), Text)
            values[name] = sa.cast(bound, column.type) if pg else bound
        else:
            values[name] = sa.bindparam("v_" + name, type_=column.type)
    stmt = sa.insert(table).values(values)
    db.execute(stmt, [{"v_" + name: row.get(name) for name in af.NAMES} for row in rows])


def _restore_rows(db, rows: List[dict]) -> None:
    """Insert a chunk of archived rows back; a row whose account was deleted since it was archived has its link
    cleared, as the foreign key would have done (the link is outside the chain)."""
    from app.core.models import User
    users = {fmt.as_uuid(row["user_id"]) for row in rows if row.get("user_id") is not None}
    present = {fmt.as_uuid(u) for (u,) in db.query(User.id).filter(User.id.in_(list(users))).all()} if users else set()
    for row in rows:
        if row.get("user_id") is not None and fmt.as_uuid(row["user_id"]) not in present:
            row["user_id"] = None
    _insert_rows(db, rows)


def restore_day(w, day: date, now: datetime) -> int:
    """Put ``day``'s archived rows back into audit_logs, in ``w``'s transaction (see the module's docstring).
    Returns the rows restored. Raises NotVerified."""
    from app.core.models import AuditArchiveBlock as B, AuditLog as A
    ai = _ai()
    db, view = w.db, w.st.view
    entry = view.archives.get(day)
    if entry is None or not entry.parts:
        return 0
    _check_day_blocks(db, entry, day)
    restored = 0
    for part in sorted(entry.parts, key=lambda p: p.first_hour):
        hours = hours_between(part.first_hour, part.last_hour)
        if db.query(func.count()).select_from(A).filter(A.timestamp >= part.first_hour,
                                                        A.timestamp < part.last_hour + HOUR).scalar():
            raise NotVerified("row-in-archived-day", f"audit_logs has rows in {_label(day, part)}, which is "
                                                     "archived")
        reader = PartReader(db, view, day, part)
        by_hour: Dict[datetime, bytearray] = {}
        chunk: List[dict] = []
        for row in reader.rows():
            by_hour.setdefault(ai.hour_floor(row["timestamp"]), bytearray()).extend(row["id"].bytes)
            chunk.append(row)
            if len(chunk) >= PROBE_CHUNK:
                _restore_rows(db, chunk)
                chunk = []
        if chunk:
            _restore_rows(db, chunk)
        reader.finish()
        salts = reader.salts
        for h in hours:
            ids = bytes(by_hour.get(h, b""))
            root = _root(db, view, h)
            if root is not None and fmt.ids_digest_of_blob(ids) != root.ids_digest:
                raise NotVerified("rows-altered", f"the ids of {fmt.hour_text(h)} do not give its seal",
                                  fmt.hour_text(h))
            wr = ai.working_row(db, h)
            if wr is None:
                if ids:
                    raise NotVerified("rows-added", f"rows in {fmt.hour_text(h)}, an hour sealed empty",
                                      fmt.hour_text(h))
                continue
            wr.row_ids = ids
            wr.legacy_salt = salts.get(h)
        restored += reader.block.count
    db.query(B).filter(B.day == day).delete(synchronize_session=False)
    db.flush()
    sync_marker(db, now)
    _write_archive_seal(w, day, "unarchive", [])
    return restored


def _days_in(view, first: Optional[date], last: Optional[date]) -> List[date]:
    return sorted(d for d, e in view.archives.items() if e.parts and (first is None or d >= first)
                  and (last is None or d <= last))


def unarchive_plan(db, view, record: Optional[dict], first: Optional[date], last: Optional[date]) -> dict:
    """The read phase of ``audit unarchive``: the days it would restore, with each day's archive seal, the
    estimate, and the state. Raises Refused when there is none."""
    from app.core import audit_chain_host as host
    days = _days_in(view, first, last)
    if not days:
        raise host.Refused("no archived day in that range")
    est = estimate(db, first, last)
    lines = [f"{len(days)} archived days, {days[0].isoformat()} to {days[-1].isoformat()}: {est['rows']} rows in "
             f"{est['blocks']} blocks, {est['compressed_bytes']} bytes compressed.",
             f"Restored as rows they take about {est['restored_low_bytes']} to {est['restored_high_bytes']} bytes "
             "in the database (7 to 12 times the compressed size).",
             f"They stay rows for {max(1, start_after_days())} days; archiving takes them again after that unless "
             "the row window (audit_hot_days) is raised."]
    each = [[d.isoformat(), view.archives[d].seq, view.link_at(view.archives[d].seq).hex()] for d in days]
    state = {"chain": host.chain_state(view, record), "command": "unarchive", "days": each}
    return {"state": state, "lines": lines, "days": days, "each": each, "estimate": est}


def unarchive(engine, st, first: Optional[date], last: Optional[date], *, expect: Optional[str] = None,
              read: bool = False) -> dict:
    """``audit unarchive`` in either phase: the read phase returns the days, the estimate and the state; the write
    phase restores every archived day from ``first`` to ``last``, oldest first, one day per transaction, once the
    state is the one ``expect`` names, and each later day only while its archive seal is still the one the read
    phase saw. Returns the days and rows restored. Raises Refused, NotVerified (on a day that does not check out:
    the days before it stay restored)."""
    from app.core import audit_chain_host as host
    ai = _ai()
    done: List[str] = []
    rows = 0
    planned: Optional[List[list]] = None
    while True:
        with ai.ChainWriter(engine, st, wait=30, writer="host", snapshot=True) as w:
            view = w.st.view
            if planned is None:
                plan = unarchive_plan(w.db, view, w.record, first, last)
                if read:
                    return {"state": host.token(plan["state"]), "lines": plan["lines"], "estimate": plan["estimate"]}
                host.check_expected(plan["state"], expect)
                planned = list(plan["each"])
            if not planned:
                break
            day_text, seq, link = planned[0]
            day = date.fromisoformat(day_text)
            entry = view.archives.get(day)
            if entry is None or entry.seq != seq or view.link_at(seq).hex() != link:
                raise host.Refused(f"the archive of {day_text} changed after the read; restored so far: "
                                   f"{', '.join(done) or 'nothing'}")
            n = restore_day(w, day, w.st.clock())
            host.host_audit_row(w.db, UNARCHIVED_ACTION, {"day": day_text, "rows": n})
        planned.pop(0)
        done.append(day_text)
        rows += n
    return {"days": done, "rows": rows}


def compact(engine) -> dict:
    """VACUUM FULL of audit_logs and audit_archive_blocks: their freed space goes back to the system. Both
    tables are locked while it runs, so audit writes wait (and fail after their lock timeout)."""
    out = []
    conn = engine.connect().execution_options(isolation_level="AUTOCOMMIT")
    try:
        pg = engine.dialect.name == "postgresql"
        if pg:
            conn.execute(text("SET statement_timeout = 0"))
            conn.execute(text("SET lock_timeout = 10000"))
        for table in ("audit_logs", "audit_archive_blocks"):
            def size():
                return conn.execute(text("SELECT pg_total_relation_size(:t)"), {"t": table}).scalar() if pg else None
            before = size()
            conn.execute(text(f"VACUUM (FULL, ANALYZE) {table}" if pg else "VACUUM"))
            out.append({"table": table, "before_bytes": before, "after_bytes": size()})
    finally:
        conn.close()
    return {"tables": out}


# --------------------------------------------------------------------------- checks (audit verify)

def check_block_set(db, view, report) -> None:
    """Every block is a part of its day's latest archive seal, with its length, and every part has its block:
    no payload is read. Also: no row of audit_logs in an archived hour."""
    from app.core.audit_chain_verify import FAILURE
    from app.core.audit_retention import _as_time, _hour
    from app.core.models import AuditLog as A
    stored = stored_blocks(db)
    expected = {(d, p.part): p for d, p in view.archived_parts()}
    for key, length in sorted(stored.items()):
        part = expected.get(key)
        label = f"{key[0].isoformat()} part {key[1]}"
        if part is None:
            report.add(FAILURE, "block-unsealed", f"the block of {label} is in no archive seal")
        elif length != part.length:
            report.add(FAILURE, "block-altered", f"the block of {label} is {length} bytes; its seal {part.length}",
                       view.archives[key[0]].seq)
    for key in sorted(expected):
        if key not in stored:
            report.add(FAILURE, "block-missing", f"the block of {key[0].isoformat()} part {key[1]} is gone",
                       view.archives[key[0]].seq)
    if not expected:
        return
    newest_end = max(p.last_hour for p in expected.values()) + HOUR
    hour = _hour(A, db.get_bind().dialect.name)
    found = db.query(hour, func.count()).filter(A.timestamp < newest_end).group_by(hour).all()
    for h, n in found:
        h = _as_time(h)
        part = view.archived_part(h)
        if part is not None and n:
            report.add(FAILURE, "row-in-archived-day", f"{n} rows of audit_logs are in {fmt.hour_text(h)}, which "
                                                       f"is archived ({h.date().isoformat()} part {part.part})",
                       view.archives[h.date()].seq, fmt.hour_text(h))


def check_parts(db, view, report, parts: List[tuple]) -> None:
    """Steps 5-7 for archived hours: each (day, part) read once, checked against its seal and its hours'. A block of
    a later block format is a warning: this release does not check it."""
    from app.core.audit_chain_verify import FAILURE, WARNING
    for day, part in parts:
        try:
            block = PartReader(db, view, day, part).finish().block
        except NotVerified as nv:
            if nv.kind == LATER_FORMAT:
                report.add(WARNING, nv.kind, str(nv), view.archives[day].seq)
            elif nv.kind != "block-missing":     # check_block_set names a missing block
                report.add(FAILURE, nv.kind, str(nv), view.archives[day].seq, nv.hour)
            continue
        report.rows_checked += block.count
        report.hours_checked += len(hours_between(part.first_hour, part.last_hour))


def block_problems(db, view) -> List[str]:
    """What is wrong with the archive, every block read: the set, each length, each block against its seal and
    its hours', and rows put back into archived hours. [] when every block verifies intact."""
    from app.core.audit_chain_verify import Report
    report = Report()
    check_block_set(db, view, report)
    check_parts(db, view, report, list(view.archived_parts()))
    return [f"{f.kind}: {f.message}" for f in report.findings]


def archived_parts_in(view, from_hour: Optional[datetime], to_hour: Optional[datetime]) -> List[tuple]:
    out = []
    for d, part in view.archived_parts():
        if from_hour is not None and part.last_hour < from_hour:
            continue
        if to_hour is not None and part.first_hour >= to_hour:
            continue
        out.append((d, part))
    return out


def archive_problem(view, seal) -> Optional[str]:
    """Step 4 for an archive seal, judged by the chain up to it."""
    from app.core.audit_chain_view import archive_day, archive_parts
    d = seal.detail if isinstance(seal.detail, dict) else {}
    try:
        day = archive_day(d)
    except (TypeError, ValueError):
        return "an archive seal with no day"
    if seal.period_start != day_start(day) or seal.period_end != day_start(day) + DAY:
        return "an archive seal whose period is not its day"
    try:
        parts = archive_parts(d)
    except (TypeError, ValueError) as exc:
        return f"an archive seal with a bad part ({exc})"
    numbers = [p.part for p in parts]
    if len(set(numbers)) != len(numbers):
        return "an archive seal listing a part twice"
    first = view.first_hour()
    last_end = None
    for p in sorted(parts, key=lambda p: p.first_hour):
        if p.first_hour > p.last_hour or p.first_hour.date() != day or p.last_hour.date() != day:
            return "an archive part whose hours are not in its day"
        if last_end is not None and p.first_hour <= last_end:
            return "archive parts whose hours overlap"
        last_end = p.last_hour
        if first is None or p.first_hour < first or view.newest_hour_end is None or \
                p.last_hour + HOUR > view.newest_hour_end:
            return "an archive part of hours not sealed"
    if d.get("complete") is not (bool(parts) and covers_day(view, parts, day)):
        return "an archive seal whose complete flag is not what its parts cover"
    if seal.row_count != sum(p.rows for p in parts) or seal.row_bytes != sum(p.length for p in parts):
        return "an archive seal whose totals are not its parts'"
    prev = view.archives.get(day)
    before = sorted(prev.parts, key=lambda p: p.first_hour) if prev is not None else []
    cause = d.get("cause")
    after = d.get("after_seq")
    if cause == "archive":
        if after is not None or not parts:
            return "an archive seal of cause archive with a change or no part"
        if prev is not None and prev.complete:
            return "an archive seal of a day already archived whole"
        ordered = sorted(parts, key=lambda p: p.first_hour)
        if len(ordered) <= len(before) or [p.as_list() for p in ordered[:len(before)]] != [p.as_list() for p in before]:
            return "an archive seal that changes the day's parts without a change"
    elif cause == "rewrite":
        if not isinstance(after, int) or isinstance(after, bool) or after != seal.seq - 1:
            return "an archive seal of cause rewrite that does not follow its change"
        change = view.last_change
        if change is None or change[0] != after or day not in change[1]:
            return "an archive seal of cause rewrite whose change is not one of its day"
        if not before:
            return "an archive seal of cause rewrite for a day with no block"
        if parts and {(p.part, p.first_hour, p.last_hour) for p in parts} != \
                {(p.part, p.first_hour, p.last_hour) for p in before}:
            return "an archive seal of cause rewrite that moves a part's hours"
    elif cause == "unarchive":
        if parts or after is not None:
            return "an archive seal of cause unarchive that keeps a part"
        if not before:
            return "an archive seal of cause unarchive for a day with no block"
    else:
        return f"an archive seal of cause {cause!r}"
    return None


# --------------------------------------------------------------------------- what the size cap and the preview read

@dataclass(frozen=True)
class PartFigures:
    """What a part's aggregates say, aligned to its hours: rows and stored bytes by hour, and the rows and stored
    bytes of the actions the size cap never deletes (administration and security)."""
    rows: Tuple[int, ...]
    stored: Tuple[int, ...]
    protected_rows: int
    protected_stored: int


_figures: Dict[tuple, PartFigures] = {}


def part_figures(db, view) -> Dict[tuple, PartFigures]:
    """{(day, part): PartFigures} of every archived part, from the aggregates its block keeps beside the payload
    (checked against its rows whenever the payload is read: archiving, a change, the rolling check), read once per
    payload (keyed by its digest). They decide what the preview says, and can only lower the share of a part's count
    the size cap may never delete (which the chain bounds, part_units), never what the cap counts; a part whose
    aggregates cannot be read has none."""
    from app.core.audit_retention import protected_actions
    from app.core.models import AuditArchiveBlock as B
    parts = {(d, p.part): p for d, p in view.archived_parts()}
    keys = {k: (k[0], k[1], p.sha256) for k, p in parts.items()}
    missing = [k for k, ck in keys.items() if ck not in _figures]
    if missing:
        wanted = set(missing)
        protected = set(protected_actions())
        days = sorted({k[0] for k in missing})
        for d, number, agg in db.query(B.day, B.part, B.aggregates).filter(B.day.in_(days)).all():
            k = (_as_date(d), int(number))
            if k not in wanted:
                continue
            figures = _figures_of(parts[k], agg, protected)
            if figures is not None:
                _figures[keys[k]] = figures
    known = set(keys.values())
    for ck in [ck for ck in _figures if ck not in known]:
        del _figures[ck]
    return {k: _figures[ck] for k, ck in keys.items() if ck in _figures}


def _figures_of(part, agg, protected: set) -> Optional[PartFigures]:
    try:
        hours = {fmt.parse_time_text(h): (int(n), int(b)) for h, n, b in agg["hours"]}
        p_rows = p_stored = 0
        for action, _status, _channel, n, _line, b in agg["by"]:
            if action in protected:
                p_rows += int(n)
                p_stored += int(b)
    except (KeyError, TypeError, ValueError):
        return None
    span = part.hours()
    return PartFigures(tuple(hours.get(h, (0, 0))[0] for h in span), tuple(hours.get(h, (0, 0))[1] for h in span),
                       p_rows, p_stored)


def protected_share(part, counted: int, figures: Optional[PartFigures], now: datetime, min_days: int) -> int:
    """What a part's aggregates say of its count the size cap may never delete, never more than the count: its
    administration and security rows, or its rows younger than the minimum for every row (whole hours), whichever is
    larger, as a share of its stored bytes; 0 when it has no aggregates that can be read. The aggregates are not
    checked when the cap plans, so this only lowers what the chain binds (part_units), never raises it. Rows another
    module's row-keep rule keeps are not known here: they count as deletable, so the cap keeps more, never less (the
    deletion itself never takes them)."""
    if figures is None or counted <= 0:
        return 0
    total = sum(figures.stored)
    if total <= 0:
        return 0
    young = 0
    if min_days > 0:
        since = now - timedelta(days=min_days)
        young = sum(b for h, b in zip(part.hours(), figures.stored) if h >= since)
    return min(counted, counted * min(total, max(figures.protected_stored, young)) // total)


def part_units(part, counted: int, lagged: Dict[datetime, int], bound: Dict[datetime, int],
               figures: Optional[PartFigures], now: datetime, min_days: int) -> List[tuple]:
    """(hour, counted, protected) of each hour of a part, for the size cap's walk from the newest: the part's count
    spread over its hours by their lagged bytes, each hour's protected share the same part of its spread as the
    chain binds of its lagged bytes (``bound``: the hour's lagged protected bytes, audit_chain_size.protected_hours;
    the whole hour when every row of it is younger than the minimum for every row). The part's aggregates
    (protected_share), which are not checked when the cap plans, only lower the shares, from the oldest hour on: an
    understated share keeps more, an overstated one would delete newer rows sooner. The shares add up to the part's
    count exactly, and each protected share is never more than its hour's."""
    total = sum(lagged.values())
    if counted <= 0 or total <= 0:
        return []
    hours = sorted(lagged)
    shares = [counted * lagged[h] // total for h in hours]
    shares[-1] += counted - sum(shares)
    since = now - timedelta(days=min_days) if min_days > 0 else None
    kept = []
    for h, share in zip(hours, shares):
        most = lagged[h] if since is not None and h >= since else min(lagged[h], bound.get(h, 0))
        kept.append(share * most // lagged[h])
    over = sum(kept) - protected_share(part, counted, figures, now, min_days)
    for i in range(len(hours)):
        if over <= 0:
            break
        cut = min(over, kept[i])
        kept[i] -= cut
        over -= cut
    return list(zip(hours, shares, kept))


def preview(db, view, *, age_cut: Optional[datetime], admin_cut: Optional[datetime], size_cut: Optional[datetime],
            young_cut: Optional[datetime]) -> dict:
    """What the audit job would delete of the archived rows, from the parts' aggregates: {"by_age": {rows, bytes},
    "by_size": {rows, bytes}}, bytes as the rows were stored. An estimate, in whole hours, with a part's
    administration and security rows spread evenly over its hours and rows another module's row-keep rule keeps
    counted as deleted. ``age_cut``: the maximum deletes rows older than it (None: kept for ever); ``admin_cut``:
    administration and security rows younger than it are kept from the maximum; ``size_cut``: the size cap deletes
    rows older than it (None: nothing); ``young_cut``: rows younger than it are kept from both. A row both would
    delete counts under the maximum only."""
    figures = part_figures(db, view)
    out = {"by_age": {"rows": 0, "bytes": 0}, "by_size": {"rows": 0, "bytes": 0}}
    for (d, number), f in figures.items():
        part = next(p for p in view.archives[d].parts if p.part == number)
        all_rows, all_stored = sum(f.rows), sum(f.stored)
        if not all_rows:
            continue
        aged = sized = (0, 0)
        for h, n, b in zip(part.hours(), f.rows, f.stored):
            if young_cut is not None and h + HOUR > young_cut:
                continue
            if age_cut is not None and h + HOUR <= age_cut:
                aged = (aged[0] + n, aged[1] + b)
            elif size_cut is not None and h + HOUR <= size_cut:
                sized = (sized[0] + n, sized[1] + b)
        # Administration and security rows: never deleted by the size cap; by the maximum only once older than
        # their own minimum.
        if aged[0] and admin_cut is not None and part.last_hour + HOUR > admin_cut:
            aged = (aged[0] - f.protected_rows * aged[0] // all_rows,
                    aged[1] - (f.protected_stored * aged[1] // all_stored if all_stored else 0))
        if sized[0]:
            sized = (sized[0] - f.protected_rows * sized[0] // all_rows,
                     sized[1] - (f.protected_stored * sized[1] // all_stored if all_stored else 0))
        for key, (rows, stored) in (("by_age", aged), ("by_size", sized)):
            out[key]["rows"] += max(0, rows)
            out[key]["bytes"] += max(0, stored)
    return out


# --------------------------------------------------------------------------- what the pages show

def summary(st=None) -> dict:
    """The archive as the verified view knows it: when archiving starts, the row window, and what is archived."""
    ai = _ai()
    st = st or ai.state()
    view = st.view
    first = first_start(view)
    days = sorted(d for d, e in view.archives.items() if e.parts)
    parts = [p for _d, p in view.archived_parts()]
    begins = starts_at(view)
    return {"hot_days": hot_days(), "start_after_days": start_after_days(),
            "first_start": fmt.time_text(first) if first is not None else None,
            "starts_on": fmt.time_text(begins) if begins is not None else None,
            "days": len(days), "oldest_day": days[0].isoformat() if days else None,
            "newest_day": days[-1].isoformat() if days else None,
            "blocks": len(parts), "bytes": sum(p.length for p in parts), "rows": sum(p.rows for p in parts)}
