"""The Activity page's summary band: what happened over the last 24 hours, 7 days or 30 days, over a range
the viewer chose or over all time, and what is happening now.

Everything here counts rows the Events list would show for the same filters, and names nothing the
Events list does not: event categories, usernames and addresses, never a vault, file or folder name.

The range is split into buckets on the viewer's clock: whole hours for 24 hours, six-hour blocks for 7
days, whole days for 30 days, and for a chosen range or all time the smallest of AUTO_SIZES that needs no
more than MAX_BUCKETS. The last bucket of a range that ends now is the one in progress. The viewer's
clock is their time zone when the server knows it (an IANA name, from the browser): six-hour blocks and
days then follow it across a daylight-saving change, so the block or day holding the change is an hour
longer or shorter and the next still starts at 00:00, 06:00... Without one it is a fixed offset from UTC.

The band has five blocks, and each counts under every filter but its own (OWN_FILTERS), so each panel of
the page keeps offering the values that could be picked next: the Events block (the buckets and the
total) leaves out the time picked on the chart, the category mix the category and event filters, the
sign-in outcomes the event filter, the most active people the person filters, and the most active
addresses the address filter. Blocks under the same filters share one query.

"Failed" is a status in the Events list's Failed group (failure, failed, error, refused). The most active
people are accounts: a name typed at a failed sign-in, which can be anything a person typed into the
username box, is counted in `no_account` and never listed by name.

Cost on a large log: three aggregate queries over the range, each an index range scan on the
timestamp, and one over the sessions table; a filter on a block's own dimension adds a query for that
block. Measured on 520,000 rows (about 255,000 in 30 days) from a few hundred addresses: 24 hours about
90 ms, 7 and 30 days about 300 to 400 ms. When nearly every row comes from its own address (an attack
spread over many), ranking the addresses dominates and 30 days takes about 1.5 s. All time reads every
row the filters match, so on a large log with no filter it takes seconds.
The page refreshes the band as events arrive, so the counts are kept for a few seconds (CACHE_SECONDS)
and shared by everyone who asks for the same range and filters: they are the same for every
administrator, since they name nothing that depends on who is looking. The "now" figures are never kept.
"""
import bisect
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Dict, List, Optional, Tuple

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

# Sign-in outcomes, by catalog name (a stored alias counts as its entry). A sign-in with a recovery code
# writes login_success as well, so second_factor_recovery_used is not counted a second time.
SIGN_IN_OUTCOMES = {
    "login_success": "succeeded",
    "login_failure": "failed",
    "second_factor_failed": "failed",
    "account_auto_locked": "locked",
}

# A chosen range, or all time, is split into buckets of the smallest of these sizes that needs no more
# than MAX_BUCKETS of them: an hour, six hours, a day, a week, then 30, 91 and 365 days.
AUTO_SIZES = (3600, 6 * 3600, 86400, 7 * 86400, 30 * 86400, 91 * 86400, 365 * 86400)
MAX_BUCKETS = 48
# The longest range that can be charted, and the longest all time is charted over (two days less, for
# its first bucket starting at the viewer's midnight before the oldest row).
LONGEST = timedelta(days=AUTO_SIZES[-1] // 86400 * MAX_BUCKETS)
ALL_TIME_LONGEST = LONGEST - timedelta(days=2)

# The Events filters (build_events_query's keyword arguments) each block of the band leaves out: its own
# dimension, so the page's panel for it keeps offering what could be picked next. `start` and `end` are
# the time picked on the chart, inside the range.
OWN_FILTERS = {
    "events": ("start", "end"),
    "categories": ("categories", "actions"),
    "sign_ins": ("actions",),
    "people": ("username", "user_exact", "no_account"),
    "addresses": ("ip",),
}

# How long the band's counts for a range are reused, in seconds, and how many sets are kept.
CACHE_SECONDS = {"24h": 5, "7d": 15, "30d": 30, "custom": 30, "all": 30}
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
    start: datetime          # the first bucket's start, naive UTC as the log stores time
    end: datetime            # where the range ends: now, or the end the viewer chose (naive UTC)
    size: int                # the buckets' size in seconds
    buckets: int
    offset: int              # the viewer's clock at `end`, seconds east of UTC
    bounds: Tuple[datetime, ...]    # each bucket's start, then the last one's end: buckets + 1 of them

    def bucket_of(self, ts: datetime) -> Optional[int]:
        i = bisect.bisect_right(self.bounds, ts) - 1
        return i if 0 <= i < self.buckets else None

    def bucket_start(self, i: int) -> datetime:
        return self.bounds[i]

    def bucket_end(self, i: int) -> datetime:
        return self.bounds[i + 1]


def time_zone(name: Optional[str]) -> Optional[tzinfo]:
    """The IANA time zone called `name`, or None when this server has none by that name (its time zone
    database can be older than the browser's): the band then keeps to the viewer's offset from UTC."""
    if not name:
        return None
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(name)
    except Exception:  # noqa: BLE001 - unknown, not a zone's name, or unreadable: use the offset
        return None


def _clock(tz_offset_minutes: int, zone: Optional[tzinfo] = None):
    """The viewer's clock: their time zone, else a fixed offset from UTC (at most the 14 hours zones use)."""
    return zone or timezone(timedelta(minutes=max(-14 * 60, min(14 * 60, int(tz_offset_minutes or 0)))))


def _local(utc: datetime, clock) -> datetime:
    """A naive UTC time as the viewer's wall clock shows it (naive, `fold` set in an hour shown twice)."""
    return utc.replace(tzinfo=timezone.utc).astimezone(clock).replace(tzinfo=None)


def _utc(local: datetime, clock) -> datetime:
    """A time on the viewer's wall clock, in naive UTC. An hour the clock shows twice is taken the first
    time; a time a clock change skips is read with the offset before the change, so it lands just after."""
    return local.replace(tzinfo=clock, fold=0).astimezone(timezone.utc).replace(tzinfo=None)


def _offset(t: datetime, clock) -> int:
    return int((_local(t, clock) - t).total_seconds())


def _bounds(size: int, t: datetime, clock, back: int, count: int) -> Tuple[datetime, ...]:
    """count + 1 bucket bounds in naive UTC: the viewer's boundary for `size` at or before `t`, moved
    `back` buckets earlier, then the `count` after it. Hours are real hours from the viewer's hour at
    `t`. Six-hour blocks and longer follow the viewer's wall clock (00:00, 06:00, 12:00 and 18:00, and
    midnights), so a clock change makes the block or day holding it an hour longer or shorter and the next
    one still starts on time."""
    local = _local(t, clock)
    if size < 6 * 3600:
        shift = local - t                                       # the viewer's offset at t
        first = local.replace(minute=0, second=0, microsecond=0) - shift - timedelta(seconds=back * size)
        return tuple(first + timedelta(seconds=i * size) for i in range(count + 1))
    step = timedelta(hours=6) if size < 86400 else timedelta(days=size // 86400)
    hour = local.hour // 6 * 6 if size < 86400 else 0
    first = local.replace(hour=hour, minute=0, second=0, microsecond=0, fold=0) - back * step
    return tuple(_utc(first + i * step, clock) for i in range(count + 1))


def window(range_key: str, now: datetime, tz_offset_minutes: int = 0, zone: Optional[tzinfo] = None) -> Window:
    """The window for a range ending at `now` (naive UTC). Buckets start on the viewer's hour, six-hour
    or day boundaries (in `zone`, else `tz_offset_minutes` east of UTC, as a browser reports it negated),
    and the last one holds `now`."""
    buckets, size = RANGES.get(range_key, RANGES[DEFAULT_RANGE])
    clock = _clock(tz_offset_minutes, zone)
    bounds = _bounds(size, now, clock, back=buckets - 1, count=buckets)
    return Window(start=bounds[0], end=now, size=size, buckets=buckets, offset=_offset(now, clock),
                  bounds=bounds)


def custom_window(start: datetime, end: datetime, tz_offset_minutes: int = 0,
                  zone: Optional[tzinfo] = None) -> Optional[Window]:
    """The window for a range the viewer chose, from `start` to `end` (naive UTC), in buckets of the
    smallest size in AUTO_SIZES that needs no more than MAX_BUCKETS. Buckets shorter than a day start on
    the viewer's hour or six-hour boundaries; a day or longer starts at the viewer's midnight on the
    range's first day. The first bucket may start before `start` and the last may end after `end`: the
    caller counts only the rows between them, so both can be partial. None when `end` is not after
    `start`, or the range is longer than LONGEST."""
    if end <= start or end - start > LONGEST:
        return None
    clock = _clock(tz_offset_minutes, zone)
    for size in AUTO_SIZES:
        bounds = _bounds(size, start, clock, back=0, count=MAX_BUCKETS)
        n = next((i for i in range(1, MAX_BUCKETS + 1) if bounds[i] >= end), None)
        if n is not None:
            return Window(start=bounds[0], end=end, size=size, buckets=n, offset=_offset(end, clock),
                          bounds=bounds[:n + 1])
    return None


def all_time(first: Optional[datetime], end: datetime, tz_offset_minutes: int = 0,
             zone: Optional[tzinfo] = None) -> Window:
    """The window for all time up to `end`: from `first`, the oldest row the Events block counts, in the
    smallest buckets that fit; the hour before `end` when there is no such row; and at most
    ALL_TIME_LONGEST before `end`, so a row with an absurd date cannot make the range unchartable."""
    start = first if first is not None and first < end else end - timedelta(hours=1)
    return custom_window(max(start, end - ALL_TIME_LONGEST), end, tz_offset_minutes, zone)


def block_filters(filters: dict) -> Dict[str, dict]:
    """The Events filters each block of the band counts under: all of `filters` but its own."""
    return {block: {k: v for k, v in filters.items() if k not in own} for block, own in OWN_FILTERS.items()}


def signature(filters: dict) -> tuple:
    """Events filters in a hashable form, the same however they were spelled out: empty values left out,
    lists sorted. It tells which blocks can share a query, and keys the cache."""
    out = []
    for key, value in sorted(filters.items()):
        if value is None or value is False or value == "" or value == [] or value == ():
            continue
        if isinstance(value, (list, tuple)):
            value = tuple(sorted(str(v) for v in value))
        out.append((key, value))
    return tuple(out)


def _iso(ts: datetime) -> str:
    return ts.replace(tzinfo=timezone.utc).isoformat()


def category_of(action: Optional[str]) -> str:
    entry = audit_catalog.lookup(action or "")
    return entry.category if entry else LEGACY


def shape(win: Window, grouped, top_users, top_addresses, apart: Optional[dict] = None,
          since: Optional[datetime] = None) -> dict:
    """The band from the grouped counts. `grouped` is (bucket number, stored action, rows, failed rows,
    rows under no account, failed rows under no account) rows under the Events block's filters; a row
    outside the window's buckets is left out. The tops are (value, count, failed) rows, already ordered.
    `apart` holds rows of the same form for "categories", "sign_ins" or "people" when that block counts
    under other filters than the Events block (see OWN_FILTERS); their bucket is not used. `since` is
    where the counting starts, when that is not the first bucket's start (a chosen range, all time)."""
    apart = apart or {}
    inside = [r for r in grouped if r[0] is not None and 0 <= int(r[0]) < win.buckets]
    buckets: List[Dict] = [{"counts": {}, "failed": 0} for _ in range(win.buckets)]
    for bucket, action, count, failed, _unowned, _unowned_failed in inside:
        slot = buckets[int(bucket)]
        cat = category_of(action)
        slot["counts"][cat] = slot["counts"].get(cat, 0) + int(count)
        slot["failed"] += int(failed or 0)
    mix: Dict[str, List[int]] = {}
    for _bucket, action, count, failed, _unowned, _unowned_failed in apart.get("categories", inside):
        tally = mix.setdefault(category_of(action), [0, 0])
        tally[0] += int(count)
        tally[1] += int(failed or 0)
    outcomes = {"succeeded": 0, "failed": 0, "locked": 0}
    for _bucket, action, count, _failed, _unowned, _unowned_failed in apart.get("sign_ins", inside):
        entry = audit_catalog.lookup(action or "")
        outcome = SIGN_IN_OUTCOMES.get(entry.name if entry else "")
        if outcome:
            outcomes[outcome] += int(count)
    no_account = {"total": 0, "failed": 0}
    for _bucket, _action, _count, _failed, unowned, unowned_failed in apart.get("people", inside):
        no_account["total"] += int(unowned or 0)
        no_account["failed"] += int(unowned_failed or 0)
    labels = dict(audit_catalog.CATEGORIES)
    order = [k for k, _ in audit_catalog.CATEGORIES] + [LEGACY]
    totals = [sum(b["counts"].values()) for b in buckets]
    return {
        "from": _iso(since or win.start),
        "to": _iso(win.end),
        "bucket_seconds": win.size,
        "buckets": [{"start": _iso(win.bucket_start(i)), "end": _iso(win.bucket_end(i)), "total": totals[i],
                     "failed": b["failed"], "counts": b["counts"]} for i, b in enumerate(buckets)],
        "total": sum(totals),
        "failed": sum(b["failed"] for b in buckets),
        "categories": [{"key": k, "label": labels.get(k, audit_catalog.LEGACY_LABEL),
                        "count": mix[k][0], "failed": mix[k][1]} for k in order if k in mix],
        "sign_ins": outcomes,
        "top_users": [{"username": u, "count": int(n), "failed": int(f or 0)} for u, n, f in top_users],
        "no_account": no_account,
        "top_addresses": [{"ip_address": a, "count": int(n), "failed": int(f or 0)} for a, n, f in top_addresses],
    }


def oldest(db, AuditLog, filters: dict, until: Optional[datetime] = None) -> Optional[datetime]:
    """The time of the oldest row the Events block counts (`filters` but the time picked on the chart),
    before `until` when given: all time is charted from it."""
    from sqlalchemy import func
    from app.services.activity_events import build_events_query
    q = build_events_query(db.query(func.min(AuditLog.timestamp)), AuditLog, **block_filters(filters)["events"])
    if until is not None:
        q = q.filter(AuditLog.timestamp < until)
    return q.scalar()


def summarize(db, AuditLog, win: Window, filters: dict, since: Optional[datetime] = None,
              until: Optional[datetime] = None, from_: Optional[datetime] = None) -> dict:
    """The band over the window for the Events filters `filters` (build_events_query's keyword arguments,
    with `start` and `end` the time picked on the chart). Rows count from `since` (None: from the oldest
    the log holds) up to `until` (exclusive; None: up to now, and anything written since). Each block
    counts under every filter but its own (OWN_FILTERS); blocks under the same filters share one query.
    `from_` is the start the band states when it is not `since` (all time: the oldest row)."""
    from sqlalchemy import and_, func, literal_column, text
    from app.services.activity_events import build_events_query, stored_action_names
    per_block = block_filters(filters)
    keys = {block: signature(f) for block, f in per_block.items()}

    def rows(block):
        q = build_events_query(db.query(AuditLog), AuditLog, **per_block[block]).order_by(None)
        if since is not None:
            q = q.filter(AuditLog.timestamp >= since)
        if until is not None:
            q = q.filter(AuditLog.timestamp < until)
        return q

    is_failed = AuditLog.status.in_(FAILED_STATUSES)
    unowned = and_(AuditLog.user_id.is_(None), AuditLog.username.isnot(None))
    counts = (func.count(), func.count().filter(is_failed), func.count().filter(unowned),
              func.count().filter(and_(unowned, is_failed)))
    # The bucket a row falls in, counted from 1 (width_bucket over the window's bounds; 0 is before the
    # first). Written out, and grouped by position, so the SELECT and the GROUP BY are the same to the
    # database; every time in it is the server's own, never the request's.
    bucket = literal_column("width_bucket(audit_logs.timestamp, ARRAY[" + ", ".join(
        f"timestamp '{b:%Y-%m-%d %H:%M:%S.%f}'" for b in win.bounds) + "])")
    grouped = [(int(b) - 1, action, n, f, u, uf) for b, action, n, f, u, uf in
               rows("events").with_entities(bucket, AuditLog.action, *counts)
               .group_by(text("1"), text("2")).all() if b is not None]
    passes: Dict[tuple, list] = {}
    apart = {}
    for block in ("categories", "people", "sign_ins"):
        if keys[block] == keys["events"]:
            continue
        if keys[block] not in passes:
            q = rows(block)
            if block == "sign_ins":                 # nothing else counts under these filters
                q = q.filter(AuditLog.action.in_(stored_action_names(SIGN_IN_OUTCOMES)))
            passes[keys[block]] = [(None, action, n, f, u, uf) for action, n, f, u, uf in
                                   q.with_entities(AuditLog.action, *counts).group_by(AuditLog.action).all()]
        apart[block] = passes[keys[block]]
    count = func.count()
    failures = func.count().filter(is_failed)

    def top(block, col, *conds):
        return (rows(block).filter(col.isnot(None), *conds).with_entities(col, count, failures)
                .group_by(col).order_by(count.desc(), col).limit(TOP).all())

    return shape(win, grouped, top("people", AuditLog.username, AuditLog.user_id.isnot(None)),
                 top("addresses", AuditLog.ip_address), apart, from_ or since)


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
