"""What the audit log and its archive take, for Settings -> Activity and records (GET /settings/managed/storage,
app/api/managed_settings_router.py; shown by static/js/settings-retention.js).

- the rows: how many (on Postgres the planner's estimate, which reading every row to count would cost far more than
  it is worth on a large log; elsewhere counted), what the table takes with its indexes, and the oldest row's time
  (how far the archive has come: the oldest day still kept as rows);
- the archive: its blocks, the rows they hold and their bytes, and what its table takes;
- the size cap when one is set: the bytes it counts (the chain's figure, app/core/audit_chain_size.py: hot hours'
  lagged bytes and archived parts' bound lengths, read from the verified view), the bytes the log takes now as the
  cap will count them once growth has waited its delay (the hours' figures now and the rows not sealed yet), the
  cap, and a warning once the bytes now reach WARN_AT of it, with the earliest day the cap would start deleting;
- the free space of the volume the vault's files are stored in. The database's volume is in another container: the
  app cannot see its free space (``dockvault.py audit unarchive`` checks it on the host before it restores rows);
- whether the install was running before this release: its audit log has rows older than the release's first
  start, which then says what the release changed (the banner on the page).
"""
from __future__ import annotations

import shutil
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import func, text

# The share of the size cap at which the page warns.
WARN_AT = 0.8


def _is_pg(db) -> bool:
    return db.get_bind().dialect.name == "postgresql"


def _rows(db) -> dict:
    """How many audit rows there are, what they take, and the time of the oldest (the archive's progress: the oldest
    day still kept as rows; the timestamp's index answers it without reading the table)."""
    from app.core.models import AuditLog
    oldest = db.query(func.min(AuditLog.timestamp)).scalar()
    out = {"oldest": oldest.isoformat() + "Z" if oldest is not None else None}
    if _is_pg(db):
        estimate = db.execute(text("SELECT reltuples::bigint FROM pg_class WHERE oid = to_regclass('audit_logs')"))\
            .scalar()
        size = db.execute(text("SELECT pg_total_relation_size(to_regclass('audit_logs'))")).scalar()
        if estimate is not None and estimate >= 0:
            return dict(out, count=int(estimate), exact=False, bytes=int(size or 0))
        return dict(out, count=int(db.query(func.count()).select_from(AuditLog).scalar() or 0), exact=True,
                    bytes=int(size or 0))
    return dict(out, count=int(db.query(func.count()).select_from(AuditLog).scalar() or 0), exact=True, bytes=None)


def _archive(db) -> dict:
    from app.core import audit_archive as arc
    from app.core.models import AuditArchiveBlock as B
    blocks, rows, payload = db.query(func.count(), func.coalesce(func.sum(B.row_count), 0),
                                     func.coalesce(func.sum(arc._length(B.payload, db)), 0)).one()
    table = db.execute(text("SELECT pg_total_relation_size(to_regclass('audit_archive_blocks'))")).scalar() \
        if _is_pg(db) else None
    return {"blocks": int(blocks or 0), "rows": int(rows or 0), "bytes": int(payload or 0),
            "table_bytes": int(table) if table is not None else None}


def _sealed_through(view) -> Optional[datetime]:
    """The end of the newest hour the chain has sealed, or None before the first."""
    end = None
    for _start, unit_end, _last in view.units():
        end = unit_end if end is None or unit_end > end else end
    return end


def unsealed_bytes(db, view) -> int:
    """What the audit rows not sealed yet take (those after the newest sealed hour), as the size cap counts a row's
    bytes; the timestamp's index finds them."""
    from app.core import audit_retention as ar
    from app.core.models import AuditLog
    through = _sealed_through(view)
    if through is None:
        return 0
    size = ar._row_bytes(AuditLog, db.get_bind().dialect.name)
    return int(db.query(func.coalesce(func.sum(size), 0)).filter(AuditLog.timestamp >= through).scalar() or 0)


def cap_counted(now: datetime, st=None, db=None) -> Optional[dict]:
    """The size cap, when one is set: {cap_bytes, counted_bytes, now_bytes, fraction, warn, over_from}. None without
    a cap. ``counted_bytes`` is what the cap counts (the chain's, which takes growth in only a delay of sealing after
    it); ``now_bytes`` what the log takes now as the cap would count it once that delay has run: every hour's figure
    now (app/core/audit_chain_size.now_count), and, given ``db``, the rows not sealed yet. The warning is on the
    bytes now, from WARN_AT of the cap, so a sudden growth is warned of before the cap counts it; ``over_from`` is
    the earliest the cap's count passes the cap on what is sealed now (None when it does not), the day it would
    start deleting unless the cap is raised or the hold turned on. ``counted_bytes`` is None while the chain has
    nothing verified to count, or this process has not read it through (audit_integrity.ChainState.view_read)."""
    from app.core import audit_chain_size as chain_size
    from app.core import audit_integrity as ai
    from app.core import audit_retention as ar
    numbers = ar.current()
    if not numbers.max_mb:
        return None
    cap = numbers.max_mb * ar.MB
    st = st or ai.state()
    unknown = {"cap_bytes": cap, "counted_bytes": None, "now_bytes": None, "fraction": None, "warn": False,
               "over_from": None}
    record = st.known_record()

    def counts(view):
        if not view.position:
            return None
        counted_ = chain_size.cap_count(view, record, now, ar._delay())[4]
        now_ = max(counted_, chain_size.now_count(view, record, now)
                   + (unsealed_bytes(db, view) if db is not None else 0))
        return counted_, now_, chain_size.first_over(view, record, now, ar._delay(), cap) if now_ > cap else None
    try:
        found = st.trusted(counts)
    except ai.ViewUnread:
        found = None
    if found is None:
        return unknown
    counted, now_bytes, over = found
    fraction = now_bytes / cap
    return {"cap_bytes": cap, "counted_bytes": counted, "now_bytes": now_bytes, "fraction": round(fraction, 4),
            "warn": fraction >= WARN_AT, "over_from": over.isoformat() + "Z" if over is not None else None}


def volume(path: str) -> Optional[dict]:
    """{total, used, free} bytes of the volume ``path`` is on, or None when it cannot be read."""
    try:
        usage = shutil.disk_usage(path)
    except OSError:
        return None
    return {"total": int(usage.total), "used": int(usage.used), "free": int(usage.free)}


def existing_install(db, st=None) -> Optional[bool]:
    """Whether the audit log holds rows from before this release first ran here (its genesis seal's time): the
    install was running before, and the page tells its administrators what changed. None while this process has not
    read the chain through (audit_integrity.ChainState.view_read): not known yet."""
    from app.core import audit_archive as arc
    from app.core import audit_integrity as ai
    st = st or ai.state()

    def told(view) -> bool:
        first = arc.first_start(view)
        oldest = view.first_hour() if view.position else None
        return first is not None and oldest is not None and oldest < first - timedelta(hours=1)
    try:
        return st.trusted(told)
    except ai.ViewUnread:
        return None


def summary(db, now: datetime, storage_path: str, st=None) -> dict:
    """Everything the page's Storage card shows (see the module's docstring)."""
    return {"rows": _rows(db), "archive": _archive(db), "cap": cap_counted(now, st, db), "storage_volume":
            volume(storage_path), "database_volume": None, "existing_install": existing_install(db, st)}
