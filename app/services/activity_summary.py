"""The Activity page's summary band: what happened over the last 24 hours, 7 days or 30 days, and what is
happening now.

Everything here counts rows the Events list would show for the same filters, and names nothing the
Events list does not: event categories, usernames and addresses, never a vault, file or folder name.
The window is split into buckets aligned to the viewer's clock (whole hours for 24 hours, quarter days
for 7 days, whole days for 30 days), the last bucket being the one in progress; the band's figures all
cover exactly that window. "Failed" is a status in the Events list's Failed group (failure, failed,
error, refused). The most active people are accounts: a name typed at a failed sign-in, which can be
anything a person typed into the username box, is counted in `no_account` and never listed by name.

Cost on a large log: three aggregate queries over the window, each an index range scan on the
timestamp, and one over the sessions table. The window is at most 30 days, whatever the log holds.
Measured on 520,000 rows (about 255,000 in 30 days) from a few hundred addresses: 24 hours about 90 ms,
7 and 30 days about 300 to 400 ms. When nearly every row comes from its own address (an attack spread
over many), ranking the addresses dominates and 30 days takes about 1.5 s.
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
TOP = 6
LEGACY = "legacy"
FAILED_STATUSES = ("failure", "failed", "error", "refused")

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
# The most people, and temporary credentials, the "now" lists name.
NOW_LIST = 50


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
    """The band from the grouped counts. `grouped` is (bucket number, stored action, rows, failed rows,
    rows under no account, failed rows under no account) rows; the tops are (value, count, failed)
    rows, already ordered."""
    buckets: List[Dict] = [{"counts": {}, "failed": 0} for _ in range(win.buckets)]
    mix: Dict[str, List[int]] = {}
    outcomes = {"succeeded": 0, "failed": 0, "locked": 0}
    no_account = {"total": 0, "failed": 0}
    for bucket, action, count, failed, unowned, unowned_failed in grouped:
        if bucket is None or not 0 <= int(bucket) < win.buckets:
            continue
        n, f = int(count), int(failed or 0)
        cat = category_of(action)
        slot = buckets[int(bucket)]
        slot["counts"][cat] = slot["counts"].get(cat, 0) + n
        slot["failed"] += f
        tally = mix.setdefault(cat, [0, 0])
        tally[0] += n
        tally[1] += f
        no_account["total"] += int(unowned or 0)
        no_account["failed"] += int(unowned_failed or 0)
        entry = audit_catalog.lookup(action or "")
        outcome = SIGN_IN_OUTCOMES.get(entry.name if entry else "")
        if outcome:
            outcomes[outcome] += n
    labels = dict(audit_catalog.CATEGORIES)
    order = [k for k, _ in audit_catalog.CATEGORIES] + [LEGACY]
    return {
        "from": _iso(win.start),
        "to": _iso(win.end),
        "bucket_seconds": win.size,
        "buckets": [{"start": _iso(win.bucket_start(i)), "total": sum(b["counts"].values()),
                     "failed": b["failed"], "counts": b["counts"]} for i, b in enumerate(buckets)],
        "total": sum(t[0] for t in mix.values()),
        "failed": sum(t[1] for t in mix.values()),
        "categories": [{"key": k, "label": labels.get(k, audit_catalog.LEGACY_LABEL),
                        "count": mix[k][0], "failed": mix[k][1]} for k in order if k in mix],
        "sign_ins": outcomes,
        "top_users": [{"username": u, "count": int(n), "failed": int(f or 0)} for u, n, f in top_users],
        "no_account": no_account,
        "top_addresses": [{"ip_address": a, "count": int(n), "failed": int(f or 0)} for a, n, f in top_addresses],
    }


def summarize(db, base, AuditLog, win: Window) -> dict:
    """The band for the rows of `base` (the Events filters, already applied) inside the window."""
    from sqlalchemy import and_, case, func, literal_column, text
    q = base.filter(AuditLog.timestamp >= win.start, AuditLog.timestamp <= win.end).order_by(None)
    # The start of a row's bucket (date_bin, PostgreSQL 14 and later). Written out, and grouped by
    # position, so the SELECT and the GROUP BY are the same to the database; both values in it are the
    # server's own, never the request's. Failed and no-account rows are counted in the same pass.
    bucket = literal_column(
        f"date_bin('{int(win.size):d} seconds'::interval, audit_logs.timestamp, "
        f"timestamp '{win.start:%Y-%m-%d %H:%M:%S}')")
    is_failed = AuditLog.status.in_(FAILED_STATUSES)
    unowned = and_(AuditLog.user_id.is_(None), AuditLog.username.isnot(None))
    grouped = [(win.bucket_of(b), action, n, f, u, uf) for b, action, n, f, u, uf in
               q.with_entities(bucket, AuditLog.action, func.count(),
                               func.count().filter(is_failed), func.count().filter(unowned),
                               func.count().filter(and_(unowned, is_failed)))
               .group_by(text("1"), text("2")).all()
               if b is not None]
    count = func.count()
    failures = func.count().filter(is_failed)

    def top(col, *conds):
        return (q.filter(col.isnot(None), *conds).with_entities(col, count, failures).group_by(col)
                .order_by(count.desc(), col).limit(TOP).all())

    return shape(win, grouped, top(AuditLog.username, AuditLog.user_id.isnot(None)),
                 top(AuditLog.ip_address))


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


def _live_sessions(db, now: datetime):
    from app.core.models import ActiveSession
    cutoff = now - timedelta(minutes=SESSION_GRACE_MINUTES)
    return db.query(ActiveSession).filter(
        ActiveSession.is_active == True,  # noqa: E712
        ActiveSession.revoked == False,  # noqa: E712
        ActiveSession.last_activity >= cutoff,
    ).order_by(None)


def now_panel(db, now: datetime, transfers: dict) -> dict:
    """What is happening now: signed-in sessions (web and SFTP, from the sessions the vault keeps),
    the people and temporary credentials behind them, and the web transfers in progress (`transfers`,
    from the web process's own count; SFTP transfers are not counted)."""
    from sqlalchemy import distinct, func
    from app.core.models import ActiveSession
    sessions, people, temps = _live_sessions(db, now).with_entities(
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
        "transfers_in_flight": int(transfers.get("in_flight", 0)),
        "transfers_waiting": int(transfers.get("waiting", 0)),
        "transfer_limit": transfers.get("limit"),
    }


def who_is_online(db, now: datetime) -> dict:
    """The people and temporary credentials behind the signed-in sessions, most recently active first,
    at most NOW_LIST of each: a person's username, their sessions, when the latest was last used and
    from which address; a credential's name, its owner and when it was last used."""
    from sqlalchemy import func
    from app.core.models import ActiveSession, TemporaryCredential, User as _User
    live = _live_sessions(db, now)
    people_q = (live.filter(ActiveSession.temp_credential_id.is_(None))
                .join(_User, _User.id == ActiveSession.user_id)
                .with_entities(_User.username, func.count(ActiveSession.id),
                               func.max(ActiveSession.last_activity))
                .group_by(_User.username))
    people_total = people_q.count()
    people = people_q.order_by(func.max(ActiveSession.last_activity).desc(), _User.username).limit(NOW_LIST).all()
    latest_ip = {}
    if people:
        names = [p[0] for p in people]
        for username, ip, _last in (live.filter(ActiveSession.temp_credential_id.is_(None))
                                    .join(_User, _User.id == ActiveSession.user_id)
                                    .filter(_User.username.in_(names))
                                    .with_entities(_User.username, ActiveSession.ip_address,
                                                   ActiveSession.last_activity)
                                    .order_by(ActiveSession.last_activity.asc()).all()):
            latest_ip[username] = ip          # ascending, so the last one written is the latest
    owner = _User
    temps = (live.filter(ActiveSession.temp_credential_id.isnot(None))
             .join(TemporaryCredential, TemporaryCredential.id == ActiveSession.temp_credential_id)
             .join(owner, owner.id == TemporaryCredential.user_id)
             .with_entities(TemporaryCredential.temp_username, owner.username,
                            func.max(ActiveSession.last_activity))
             .group_by(TemporaryCredential.temp_username, owner.username)
             .order_by(func.max(ActiveSession.last_activity).desc()).limit(NOW_LIST).all())
    return {
        "as_of": _iso(now),
        "online_total": int(people_total),
        "online_people": [{"username": u, "sessions": int(n), "last_active": _iso(last) if last else None,
                           "ip_address": latest_ip.get(u)} for u, n, last in people],
        "temp_in_use": [{"name": name, "owner": who, "last_active": _iso(last) if last else None}
                        for name, who, last in temps],
    }
