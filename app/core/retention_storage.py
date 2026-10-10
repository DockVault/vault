"""What the audit log and its archive take, for Settings -> Activity and records (GET /settings/managed/storage,
app/api/managed_settings_router.py; shown by static/js/settings-retention.js).

- the rows: how many (on Postgres the planner's estimate, which reading every row to count would cost far more than
  it is worth on a large log; elsewhere counted), what the table takes with its indexes, and the oldest row's time
  (how far the archive has come: the oldest day still kept as rows);
- the archive: its blocks, the rows they hold and their bytes, and what its table takes;
- the size cap when one is set: the bytes it counts (the chain's figure, app/core/audit_chain_size.py: hot hours'
  lagged bytes and archived parts' bound lengths, read from the verified view, no row read), the cap, and a
  warning once they reach WARN_AT of it;
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


def cap_counted(now: datetime, st=None) -> Optional[dict]:
    """The size cap and what it counts, when a cap is set: {cap_bytes, counted_bytes, fraction, warn}. None
    without a cap, or while the chain has nothing verified to count. The count is the pruner's own
    (app/core/audit_chain_size.cap_count, on the server: another writer's seals held back)."""
    from app.core import audit_chain_size as chain_size
    from app.core import audit_integrity as ai
    from app.core import audit_retention as ar
    numbers = ar.current()
    if not numbers.max_mb:
        return None
    cap = numbers.max_mb * ar.MB
    st = st or ai.state()
    if not st.view.position:
        return {"cap_bytes": cap, "counted_bytes": None, "fraction": None, "warn": False}
    counted = chain_size.cap_count(st.view, st.known_record(), now, ar._delay())[4]
    fraction = counted / cap
    return {"cap_bytes": cap, "counted_bytes": counted, "fraction": round(fraction, 4), "warn": fraction >= WARN_AT}


def volume(path: str) -> Optional[dict]:
    """{total, used, free} bytes of the volume ``path`` is on, or None when it cannot be read."""
    try:
        usage = shutil.disk_usage(path)
    except OSError:
        return None
    return {"total": int(usage.total), "used": int(usage.used), "free": int(usage.free)}


def existing_install(db, st=None) -> bool:
    """Whether the audit log holds rows from before this release first ran here (its genesis seal's time): the
    install was running before, and the page tells its administrators what changed."""
    from app.core import audit_archive as arc
    from app.core import audit_integrity as ai
    st = st or ai.state()
    first = arc.first_start(st.view)
    oldest = st.view.first_hour() if st.view.position else None
    return first is not None and oldest is not None and oldest < first - timedelta(hours=1)


def summary(db, now: datetime, storage_path: str, st=None) -> dict:
    """Everything the page's Storage card shows (see the module's docstring)."""
    return {"rows": _rows(db), "archive": _archive(db), "cap": cap_counted(now, st), "storage_volume":
            volume(storage_path), "database_volume": None, "existing_install": existing_install(db, st)}
