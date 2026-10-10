"""Reading archived days: the Events list, its export and the summary band over the days the archive keeps as
compressed blocks (app/core/audit_archive.py), and what the other readers of the audit log say about them.

**The Events list and the export.** A request whose time range has a start and reaches an archived day becomes an
archive search. In one transaction that sees one state of the database (REPEATABLE READ on Postgres), the archived
parts of the range, as the chain's verified view names them, are read from their blocks into a temporary table
shaped like ``audit_logs`` (dropped when the transaction ends), and the Events list's own build_events_query runs
over the rows of both: the same filters, paging and cursors, over rows and archive alike. Each block's length and
digest are checked against its ``archive`` seal before it is decompressed, and its row count after; a block that
does not check out is left out, and the response names its day (``unreadable``). Rows whose account was deleted
since they were archived lose their link, as the deletion did to the rows still in the table. At most MAX_DAYS
archived days, MAX_ROWS archived rows and MAX_BYTES of blocks a search: a range that needs more is refused with
the numbers (TooBroad), and narrowed by its dates.

A range with no start reads rows only, and says where the archive is (``archive`` in the response): the page then
offers a range to search it. The live list's reads of newer rows start where they continue from, so they reach
the archive only when that point is in it.

The view and the transaction's snapshot are taken in that order: the snapshot first, then the view. A part the
view names that the snapshot holds no block of was archived after the snapshot (its rows are then still rows in
it) or put back by an unarchive (its rows too): it is skipped, and reported only when the snapshot holds none of
its rows either. A block the snapshot holds that the view does not name is the archive's own write, committed and
not yet in the view: the search is taken again once, and a day that still does not check out is reported.

**The summary band.** Over archived hours the band counts from each part's aggregates (rows by hour, action, status
and channel), which answer the category, event, status and channel filters exactly; under any other filter
(a person, an address, text, a vault, a credential) a block of the band counts rows only. The most active people and
addresses, and the rows under no account, always count rows only. Each hour counts in the bucket that holds its
start: in a time zone whose offset is not whole hours, the rows of the hour holding a bucket's start count in the
bucket before it. The aggregates are checked against the rows whenever a block is read, not here: a database writer
who edits them changes the band's counts until the daily check reads that block, and nothing else.

**The other readers** (``/audit/log``, ``/users/{id}/activity``, the dashboard's feed) read rows only and say where
the archive is in two response headers (ARCHIVE_HEADERS) when their range reaches it.
"""
from __future__ import annotations

import contextlib
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Tuple

import sqlalchemy as sa
from sqlalchemy import func, text

HOUR = timedelta(hours=1)
# The most archived days, archived rows and bytes of blocks (as their archive seals bind them) one search reads.
MAX_DAYS = 31
MAX_ROWS = 100_000
MAX_BYTES = 16 * 1024 * 1024
# The temporary table a search reads the archived rows into, for its own transaction only.
SEARCH_TABLE = "audit_archive_search"
# How long any statement of a search may run.
STATEMENT_TIMEOUT_MS = 60_000
# Rows inserted into the search's table at a time.
INSERT_CHUNK = 2000
# The headers the readers of rows only say where the archive is in: its oldest and newest archived UTC days.
ARCHIVE_HEADERS = ("X-Audit-Archive-Oldest-Day", "X-Audit-Archive-Newest-Day")
# How long a search waits before it is taken again, when the view has not yet caught up with a block.
RETRY_PAUSE = 0.2


class TooBroad(ValueError):
    """A range whose archived part needs more than one search reads."""


def _ai():
    from app.core import audit_integrity
    return audit_integrity


def _arc():
    from app.core import audit_archive
    return audit_archive


def archives(st=None) -> dict:
    """{day: ArchiveEntry} of the chain's verified view, copied in one step (a dict copy, which the process's
    sealer cannot change midway: its entries are replaced, never changed)."""
    st = st or _ai().state()
    return dict(st.view.archives)


def parts_between(entries: dict, start: Optional[datetime], end: Optional[datetime]) -> List[tuple]:
    """(day, part) of each archived part with an hour in [start, end) (None: unbounded), oldest first."""
    out = []
    for day in sorted(entries):
        for part in sorted(entries[day].parts, key=lambda p: p.first_hour):
            if end is not None and part.first_hour >= end:
                continue
            if start is not None and part.last_hour + HOUR <= start:
                continue
            out.append((day, part))
    return out


def span(entries: dict, start: Optional[datetime] = None, end: Optional[datetime] = None) -> Optional[dict]:
    """The archive as a reader of rows is told of it: its oldest and newest archived day and how many days it
    holds, when any archived part has an hour in [start, end); else None."""
    if not parts_between(entries, start, end):
        return None
    days = sorted(d for d, e in entries.items() if e.parts)
    return {"oldest_day": days[0].isoformat(), "newest_day": days[-1].isoformat(), "days": len(days)}


def headers_for(start: Optional[datetime] = None, end: Optional[datetime] = None, st=None) -> Dict[str, str]:
    """The ARCHIVE_HEADERS a reader of rows only sends for a range [start, end): {} when it reaches no archived
    day. Never raises: a reader is never refused for this."""
    try:
        where = span(archives(st), start, end)
    except Exception:  # noqa: BLE001 -- a chain not started yet has no view to read
        return {}
    if where is None:
        return {}
    return {ARCHIVE_HEADERS[0]: where["oldest_day"], ARCHIVE_HEADERS[1]: where["newest_day"]}


@dataclass(frozen=True)
class Plan:
    """The archived parts a search reads, for a range [start, end)."""
    start: datetime
    end: Optional[datetime]
    parts: Tuple[tuple, ...]

    @property
    def days(self) -> List[date]:
        return sorted({d for d, _p in self.parts})

    @property
    def rows(self) -> int:
        return sum(p.rows for _d, p in self.parts)

    @property
    def length(self) -> int:
        return sum(p.length for _d, p in self.parts)


def check_budget(parts: Sequence[tuple]) -> None:
    """TooBroad when ``parts`` are more than one search reads."""
    days = len({d for d, _p in parts})
    rows = sum(p.rows for _d, p in parts)
    length = sum(p.length for _d, p in parts)
    if days > MAX_DAYS:
        raise TooBroad(f"This range reaches {days} archived days; a search reads at most {MAX_DAYS} at a time. "
                       "Choose a shorter range.")
    if rows > MAX_ROWS or length > MAX_BYTES:
        raise TooBroad(f"The archived days of this range hold {rows} events ({length} bytes compressed); a search "
                       f"reads at most {MAX_ROWS} events and {MAX_BYTES} bytes at a time. Choose a shorter range.")


def plan(start: Optional[datetime], end: Optional[datetime], st=None) -> Optional[Plan]:
    """The search a range [start, end) needs: None when it has no start or reaches no archived part (it then
    reads rows only). Raises TooBroad."""
    if start is None:
        return None
    parts = parts_between(archives(st), start, end)
    if not parts:
        return None
    check_budget(parts)
    return Plan(start, end, tuple(parts))


# --------------------------------------------------------------------------- the search's transaction

def _is_pg(db) -> bool:
    return db.get_bind().dialect.name == "postgresql"


def _search_table():
    """The temporary table, with every column of the model."""
    from app.core.models import AuditLog
    md = sa.MetaData()
    cols = [sa.Column(c.name, c.type, primary_key=c.primary_key) for c in AuditLog.__table__.columns]
    return sa.Table(SEARCH_TABLE, md, *cols, prefixes=["TEMPORARY"], postgresql_on_commit="DROP")


def _entity(table):
    """AuditLog over the rows of audit_logs and the search's table together: build_events_query, the cursors and the
    pages run over it as over AuditLog."""
    from sqlalchemy.orm import aliased
    from app.core import audit_archive_format as af
    from app.core.models import AuditLog
    rows = sa.union_all(sa.select(*[AuditLog.__table__.c[n] for n in af.NAMES]),
                        sa.select(*[table.c[n] for n in af.NAMES])).subquery("audit_rows")
    return aliased(AuditLog, rows, adapt_on_names=True)


def _insert(db, table, rows: List[dict]) -> None:
    """Insert archived rows into the search's table as they were stored (JSON columns from their stored text); a row
    whose account was deleted since it was archived has its link cleared, as the deletion cleared the rows still in
    audit_logs."""
    from app.core import audit_archive_format as af
    from app.core import audit_chain_format as fmt
    from app.core.models import User
    users = {fmt.as_uuid(r["user_id"]) for r in rows if r.get("user_id") is not None}
    present = {fmt.as_uuid(u) for (u,) in db.query(User.id).filter(User.id.in_(list(users))).all()} if users else set()
    pg = _is_pg(db)
    values = {}
    for name, kind in af.COLUMNS:
        column = table.c[name]
        if kind == "json":
            bound = sa.type_coerce(sa.bindparam("v_" + name), sa.Text)
            values[name] = sa.cast(bound, column.type) if pg else bound
        else:
            values[name] = sa.bindparam("v_" + name, type_=column.type)
    batch = []
    for row in rows:
        v = {"v_" + name: row.get(name) for name in af.NAMES}
        if row.get("user_id") is not None and fmt.as_uuid(row["user_id"]) not in present:
            v["v_user_id"] = None
        batch.append(v)
    db.execute(sa.insert(table).values(values), batch)


def _hot_rows_between(db, start: datetime, end: datetime) -> int:
    from app.core.models import AuditLog
    return db.query(func.count()).select_from(AuditLog).filter(
        AuditLog.timestamp >= start, AuditLog.timestamp < end).scalar() or 0


def _stored(db, start: datetime, end: Optional[datetime]) -> Dict[tuple, int]:
    """{(day, part): length} of the blocks the snapshot holds with an hour in [start, end) (no payload read)."""
    from app.core.models import AuditArchiveBlock as B
    arc = _arc()
    q = db.query(B.day, B.part, arc._length(B.payload, db)).filter(B.last_hour > start - HOUR)
    if end is not None:
        q = q.filter(B.first_hour < end)
    return {(arc._as_date(d), int(p)): int(n or 0) for d, p, n in q.all()}


def _drop_rows(db, table, part) -> None:
    """Take a part's rows out of the search's table again (parts never share an hour)."""
    db.execute(sa.delete(table).where(table.c.timestamp >= part.first_hour,
                                      table.c.timestamp < part.last_hour + HOUR))


def _load(db, table, start: datetime, end: Optional[datetime], st) -> Dict[str, str]:
    """Read the range's archived rows into ``table``. The snapshot is taken first, then the view (see the module's
    docstring). Returns {day: why it could not be read} for the days left out. Raises TooBroad."""
    arc = _arc()
    from app.core import audit_archive_format as af
    from app.core.models import AuditArchiveBlock as B
    db.query(func.count()).select_from(B).scalar()          # the snapshot: the transaction's first read
    entries = archives(st)
    parts = parts_between(entries, start, end)
    check_budget(parts)
    problems: Dict[str, str] = {}
    stored = _stored(db, start, end)
    named = {(d, p.part) for d, e in entries.items() for p in e.parts}
    for key in sorted(stored):
        if key not in named:
            problems[key[0].isoformat()] = "block-unsealed"
    for day, part in parts:
        label = day.isoformat()
        if (day, part.part) not in stored:
            if part.rows and not _hot_rows_between(db, part.first_hour, part.last_hour + HOUR):
                problems[label] = "block-missing"
            continue
        try:
            block = arc.open_part(db, day, part)
            if block.header.get("day") != label or block.header.get("part") != part.part:
                raise arc.NotVerified("block-altered", f"the block of {label} part {part.part} says it is another")
            chunk = []
            for row in block.rows():
                ts = row.get("timestamp")
                if not isinstance(ts, datetime) or not part.holds(ts.replace(minute=0, second=0, microsecond=0)):
                    raise arc.NotVerified("block-altered", f"a row of {label} part {part.part} is not of its hours")
                if ts < start or (end is not None and ts >= end):
                    continue
                chunk.append(row)
                if len(chunk) >= INSERT_CHUNK:
                    _insert(db, table, chunk)
                    chunk = []
            if chunk:
                _insert(db, table, chunk)
            if block.count != part.rows:
                raise arc.NotVerified("block-altered", f"the block of {label} part {part.part} holds {block.count} "
                                                       f"rows; its seal {part.rows}")
        except (arc.NotVerified, af.BlockError) as exc:
            _drop_rows(db, table, part)
            problems[label] = getattr(exc, "kind", None) or "block-altered"
    return problems


@dataclass
class Search:
    """An open search: ``db`` (its own session, in its one-state transaction), ``entity`` (AuditLog over rows and
    archive), the days left out and why (``unreadable``), and the plan."""
    db: object
    entity: object
    unreadable: Dict[str, str] = field(default_factory=dict)
    plan: Optional[Plan] = None


def _begin(db) -> None:
    from app.core import audit_chain_verify as v
    v.one_state(db)
    if _is_pg(db):
        db.execute(text(f"SET LOCAL statement_timeout = {int(STATEMENT_TIMEOUT_MS)}"))


def _drop(db, table) -> None:
    """The search's table goes with its transaction on Postgres; elsewhere it is dropped here."""
    if _is_pg(db):
        return
    try:
        db.rollback()
        table.drop(db.connection(), checkfirst=True)
        db.commit()
    except Exception:  # noqa: BLE001 -- the connection goes back to the pool without it all the same
        db.rollback()


@contextlib.contextmanager
def search(engine, p: Plan, st=None) -> Iterator[Search]:
    """Open the archive search ``p`` (see the module's docstring): yields a Search whose session holds the rows of
    both. Everything read from it must be read inside the ``with``: the transaction, its table and the rows loaded
    from it end with it. Raises TooBroad."""
    from sqlalchemy.orm import Session
    st = st or _ai().state()
    db = Session(bind=engine)
    table = _search_table()
    try:
        problems: Dict[str, str] = {}
        for attempt in (1, 2):
            _begin(db)
            if not _is_pg(db):
                table.drop(db.connection(), checkfirst=True)
            table.create(db.connection())
            problems = _load(db, table, p.start, p.end, st)
            if not problems or attempt == 2:
                break
            db.rollback()
            _drop(db, table)
            time.sleep(RETRY_PAUSE)
        if _is_pg(db):
            db.execute(text(f"CREATE INDEX ON {SEARCH_TABLE} (timestamp, id)"))
        yield Search(db, _entity(table), problems, p)
    finally:
        try:
            db.rollback()
            _drop(db, table)
        finally:
            db.close()


@dataclass
class Source:
    """Where a reader of the Events list reads: ``db`` and ``entity`` (the request's session and AuditLog, or an
    archive search's), and what to tell the page of the archive (``note``: None when the range reaches none)."""
    db: object
    entity: object
    note: Optional[dict] = None


@contextlib.contextmanager
def source(db, start: Optional[datetime], end: Optional[datetime], st=None) -> Iterator[Source]:
    """Where to read the Events list's rows for a range [start, end): the request's session and AuditLog when the
    range reaches no archived day or has no start, else an archive search. ``note`` (for the response's
    ``archive``): where the archive is, whether this read searched it, the days it could not read, and the most
    days a search reads. Raises TooBroad."""
    from app.core.models import AuditLog
    st = st or _ai().state()
    try:
        entries = archives(st)
    except Exception:  # noqa: BLE001 -- no view yet: no archive to read
        entries = {}
    where = span(entries, start, end)
    if where is None:
        yield Source(db, AuditLog, None)
        return
    p = plan(start, end, st)
    note = dict(where, searched=p is not None, unreadable=[], max_days=MAX_DAYS)
    if p is None:
        yield Source(db, AuditLog, note)
        return
    with search(db.get_bind(), p, st) as s:
        note["unreadable"] = [{"day": d, "reason": why} for d, why in sorted(s.unreadable.items())]
        note["searched_days"] = len(p.days)
        yield Source(s.db, s.entity, note)


# --------------------------------------------------------------------------- the summary band

# The band's blocks that may count archived hours from aggregates; people and addresses never do.
BAND_BLOCKS = ("events", "categories", "sign_ins")


def _hour_of(text_value) -> Optional[datetime]:
    from app.core import audit_chain_format as fmt
    try:
        return fmt.parse_time_text(text_value)
    except (TypeError, ValueError):
        return None


def band_archive(db, win, per_block: Dict[str, dict], since: Optional[datetime], until: Optional[datetime],
                 now: datetime, st=None) -> Tuple[Dict[str, list], Optional[dict]]:
    """What the archived hours add to the band over ``win`` (activity_summary.summarize's arguments; ``per_block``
    each block's filters): {block: [(bucket or None, action, rows, failed rows, 0, 0)]} for each block of
    BAND_BLOCKS whose filters aggregates answer, and the note for the page (None when the range reaches no archived
    hour): where the archive is, the blocks counted from it, those counting rows only, and the days whose
    aggregates could not be read. The events block's rows carry their bucket (the one holding the hour's start);
    the other blocks' carry none, and count the hours inside their own time filter."""
    from app.core.models import AuditArchiveBlock as B
    from app.services import activity_events as ev
    from app.services import activity_summary as summary
    arc = _arc()
    lo = since if since is not None else win.start
    hi = min(until, now) if until is not None else max(now, win.end)
    try:
        entries = archives(st)
    except Exception:  # noqa: BLE001 -- no view yet
        entries = {}
    parts = parts_between(entries, lo, hi)
    if not parts:
        return {}, None
    where = span(entries, lo, hi)
    counted = [b for b in BAND_BLOCKS if ev.aggregate_countable(per_block[b])]
    note = dict(where, counted=counted, rows_only=[b for b in summary.OWN_FILTERS if b not in counted],
                unreadable=[])
    if not counted:
        return {}, note
    days = sorted({d for d, _p in parts})
    stored = {(arc._as_date(d), int(n)): agg for d, n, agg in
              db.query(B.day, B.part, B.aggregates).filter(B.day.in_(days)).all()}
    matches = {b: ev.aggregate_match(**per_block[b]) for b in counted}
    out: Dict[str, list] = {b: [] for b in counted}
    unreadable = set()
    for day, part in parts:
        agg = stored.get((day, part.part))
        if agg is None:
            continue                     # archived after, or put back before, this read: its rows are rows
        rows = _part_hours(agg, part)
        if rows is None:
            unreadable.add(day.isoformat())
            continue
        for hour, action, status, channel, n in rows:
            if hour < lo or hour >= hi:
                continue
            failed = n if status in summary.FAILED_STATUSES else 0
            for block in counted:
                if not matches[block](action, status, channel):
                    continue
                if block == "events":
                    bucket = win.bucket_of(hour)
                    if bucket is not None:
                        out[block].append((bucket, action, n, failed, 0, 0))
                    continue
                f = per_block[block]
                if f.get("start") is not None and hour < f["start"]:
                    continue
                if f.get("end") is not None and hour >= f["end"]:
                    continue
                out[block].append((None, action, n, failed, 0, 0))
    note["unreadable"] = sorted(unreadable)
    return out, note


def _part_hours(agg, part) -> Optional[List[tuple]]:
    """(hour, action, status, channel, rows) of a part's aggregates, or None when they cannot be read as its own
    (no ``by_hour``, a malformed entry, an hour outside the part, a count that is not a whole number above 0)."""
    try:
        entries = list(agg["by_hour"])
    except (KeyError, TypeError):
        return None
    out = []
    for entry in entries:
        try:
            hour_text, action, status, channel, n = entry
        except (TypeError, ValueError):
            return None
        hour = _hour_of(hour_text)
        if hour is None or not part.holds(hour) or not isinstance(n, int) or isinstance(n, bool) or n < 1:
            return None
        out.append((hour, action, status, channel, n))
    return out


def oldest_archived(per_block_events: dict, until: Optional[datetime], st=None) -> Optional[datetime]:
    """The first hour of the oldest archived part the band's events block counts (its filters answered by
    aggregates), before ``until``: all time is charted from it when it is older than the oldest row. None when the
    filters need rows, or nothing archived is before ``until``. An estimate in whole parts: the part's first hour,
    whatever its aggregates say of its rows."""
    from app.services import activity_events as ev
    if not ev.aggregate_countable(per_block_events):
        return None
    try:
        parts = parts_between(archives(st), None, until)
    except Exception:  # noqa: BLE001
        return None
    return parts[0][1].first_hour if parts else None


def snapshot_session(engine):
    """A session whose transaction sees one state of the database (the band over archived hours reads rows and
    aggregates in it): close it when done."""
    from sqlalchemy.orm import Session
    db = Session(bind=engine)
    _begin(db)
    return db


def reaches_archive(start: Optional[datetime], end: Optional[datetime], st=None) -> bool:
    try:
        return bool(parts_between(archives(st), start, end))
    except Exception:  # noqa: BLE001
        return False


__all__ = ["ARCHIVE_HEADERS", "MAX_BYTES", "MAX_DAYS", "MAX_ROWS", "Plan", "Search", "Source", "TooBroad",
           "archives", "band_archive", "check_budget", "headers_for", "oldest_archived", "parts_between", "plan",
           "reaches_archive", "search", "snapshot_session", "source", "span"]
