"""The Activity page's summary band: what happened over the last 24 hours, 7 days or 30 days, and what is
happening now.

Everything here counts rows the Events list would show for the same filters, and names nothing the
Events list does not: event categories, usernames and addresses, never a vault, file or folder name.
The window is split into buckets aligned to the viewer's clock (whole hours for 24 hours, quarter days
for 7 days, whole days for 30 days), the last bucket being the one in progress; the band's figures all
cover exactly that window.

Cost on a large log: three aggregate queries over the window, each an index range scan on the
timestamp, and one over the sessions table. The window is at most 30 days, whatever the log holds.
Measured on 520,000 rows (about 260,000 in 30 days): 24 hours 50 ms, 7 days 320 ms, 30 days 900 ms.
The page refreshes the band as events arrive, so the counts are kept for a few seconds (CACHE_SECONDS)
and shared by everyone who asks for the same range and filters: they are the same for every
administrator, since they name nothing that depends on who is looking. The "now" figures are never kept.
"""
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from app.core import audit_catalog

# range -> (buckets, bucket size in seconds)
RANGES = {
    "24h": (24, 3600),
    "7d": (28, 6 * 3600),
    "30d": (30, 86400),
}
DEFAULT_RANGE = "24h"
TOP = 5
LEGACY = "legacy"

# Sign-in outcomes, by catalog name (a stored alias counts as its entry).
SIGN_IN_OUTCOMES = {
    "login_success": "succeeded",
    "login_failure": "failed",
    "second_factor_failed": "failed",
    "account_auto_locked": "locked",
}

# How long the band's counts for a range are reused, in seconds, and how many sets are kept.
CACHE_SECONDS = {"24h": 5, "7d": 15, "30d": 30}
CACHE_ENTRIES = 64
_cache: "OrderedDict[tuple, tuple]" = OrderedDict()
_cache_lock = threading.Lock()

# How long a session counts as signed in after its last request: the grace a temporary credential's
# session gets (TEMP_CRED_SESSION_GRACE_MINUTES), the figure the rest of the vault uses for "active".
SESSION_GRACE_MINUTES = 65


@dataclass(frozen=True)
class Window:
    start: datetime          # naive UTC, as the log stores time
    end: datetime            # naive UTC: now
    size: int                # bucket size, seconds
    buckets: int
    offset: int              # the viewer's clock, seconds east of UTC

    def bucket_of(self, ts: datetime) -> Optional[int]:
        i = int((ts - self.start).total_seconds() // self.size)
        return i if 0 <= i < self.buckets else None

    def bucket_start(self, i: int) -> datetime:
        return self.start + timedelta(seconds=i * self.size)


def window(range_key: str, now: datetime, tz_offset_minutes: int = 0) -> Window:
    """The window for a range ending at `now` (naive UTC). Buckets start on the viewer's hour or day
    boundaries (`tz_offset_minutes` east of UTC, as a browser reports it negated), and the last one
    holds `now`."""
    buckets, size = RANGES.get(range_key, RANGES[DEFAULT_RANGE])
    offset = max(-14 * 60, min(14 * 60, int(tz_offset_minutes or 0))) * 60
    epoch = datetime(1970, 1, 1)
    local = (now - epoch).total_seconds() + offset
    current = epoch + timedelta(seconds=(local // size) * size - offset)
    start = current - timedelta(seconds=(buckets - 1) * size)
    return Window(start=start, end=now, size=size, buckets=buckets, offset=offset)


def _iso(ts: datetime) -> str:
    return ts.replace(tzinfo=timezone.utc).isoformat()


def category_of(action: Optional[str]) -> str:
    entry = audit_catalog.lookup(action or "")
    return entry.category if entry else LEGACY


def shape(win: Window, grouped, top_users, top_addresses) -> dict:
    """The band from the grouped counts: `grouped` is (bucket number, stored action, count) rows,
    the tops are (value, count) rows, already ordered."""
    buckets: List[Dict[str, int]] = [{} for _ in range(win.buckets)]
    mix: Dict[str, int] = {}
    outcomes = {"succeeded": 0, "failed": 0, "locked": 0}
    for bucket, action, count in grouped:
        if bucket is None or not 0 <= int(bucket) < win.buckets:
            continue
        cat = category_of(action)
        slot = buckets[int(bucket)]
        slot[cat] = slot.get(cat, 0) + int(count)
        mix[cat] = mix.get(cat, 0) + int(count)
        entry = audit_catalog.lookup(action or "")
        outcome = SIGN_IN_OUTCOMES.get(entry.name if entry else "")
        if outcome:
            outcomes[outcome] += int(count)
    labels = dict(audit_catalog.CATEGORIES)
    order = [k for k, _ in audit_catalog.CATEGORIES] + [LEGACY]
    return {
        "from": _iso(win.start),
        "to": _iso(win.end),
        "bucket_seconds": win.size,
        "buckets": [{"start": _iso(win.bucket_start(i)), "total": sum(c.values()), "counts": c}
                    for i, c in enumerate(buckets)],
        "total": sum(mix.values()),
        "categories": [{"key": k, "label": labels.get(k, audit_catalog.LEGACY_LABEL), "count": mix[k]}
                       for k in order if mix.get(k)],
        "sign_ins": outcomes,
        "top_users": [{"username": u, "count": int(n)} for u, n in top_users],
        "top_addresses": [{"ip_address": a, "count": int(n)} for a, n in top_addresses],
    }


def summarize(db, base, AuditLog, win: Window) -> dict:
    """The band for the rows of `base` (the Events filters, already applied) inside the window."""
    from sqlalchemy import func, literal_column
    q = base.filter(AuditLog.timestamp >= win.start, AuditLog.timestamp <= win.end).order_by(None)
    # The start of a row's bucket (date_bin, PostgreSQL 14 and later). Written out rather than built
    # from bound parameters, so the SELECT and the GROUP BY are the same expression to the database; the
    # size and the origin are the server's own values, never the request's.
    bucket = literal_column(
        f"date_bin('{int(win.size):d} seconds'::interval, audit_logs.timestamp, "
        f"timestamp '{win.start:%Y-%m-%d %H:%M:%S}')")
    grouped = [(win.bucket_of(b), action, n) for b, action, n in
               q.with_entities(bucket, AuditLog.action, func.count()).group_by(bucket, AuditLog.action).all()
               if b is not None]
    count = func.count()

    def top(col):
        return (q.filter(col.isnot(None)).with_entities(col, count).group_by(col)
                .order_by(count.desc(), col).limit(TOP).all())

    return shape(win, grouped, top(AuditLog.username), top(AuditLog.ip_address))


def cached(key: tuple, range_key: str, compute):
    """compute(), or its result from under CACHE_SECONDS[range_key] ago for the same key. The key must
    hold everything the result depends on (the range, the viewer's clock, the filters, the window's
    start). Returns (result, seconds since it was computed)."""
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(key)
        if hit is not None and now - hit[0] < CACHE_SECONDS.get(range_key, 0):
            _cache.move_to_end(key)
            return hit[1], now - hit[0]
    value = compute()
    with _cache_lock:
        _cache[key] = (time.monotonic(), value)
        _cache.move_to_end(key)
        while len(_cache) > CACHE_ENTRIES:
            _cache.popitem(last=False)
    return value, 0.0


def now_panel(db, now: datetime, transfers: dict) -> dict:
    """What is happening now: signed-in sessions (web and SFTP, from the sessions the vault keeps),
    the people and temporary credentials behind them, and the web transfers in progress (`transfers`,
    from the web process's own count; SFTP transfers are not counted)."""
    from sqlalchemy import distinct, func
    from app.core.models import ActiveSession
    cutoff = now - timedelta(minutes=SESSION_GRACE_MINUTES)
    live = db.query(ActiveSession).filter(
        ActiveSession.is_active == True,  # noqa: E712
        ActiveSession.revoked == False,  # noqa: E712
        ActiveSession.last_activity >= cutoff,
    ).order_by(None)
    sessions, people, temps = live.with_entities(
        func.count(ActiveSession.id),
        func.count(distinct(ActiveSession.user_id)).filter(ActiveSession.temp_credential_id.is_(None)),
        func.count(distinct(ActiveSession.temp_credential_id)),
    ).one()
    return {
        "as_of": _iso(now),
        "sessions": int(sessions or 0),
        "people": int(people or 0),
        "temporary_credentials": int(temps or 0),
        "transfers_in_progress": int(transfers.get("in_progress", 0)),
        "transfers_waiting": int(transfers.get("waiting", 0)),
    }
