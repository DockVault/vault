"""The Activity page's Events tab: the audit log, filtered and paged.

Everything a filter needs to decide lives here and is testable without a database: which stored action
names a category means (from app.core.audit_catalog), which stored statuses a status choice means, how an
IP or CIDR filter is read, and the keyset cursor. `build_events_query` applies them to a SQLAlchemy query.
"""
import base64
import binascii
import ipaddress
import uuid
from datetime import datetime, timezone
from typing import Iterable, List, Optional, Sequence, Tuple

from app.core import audit_catalog

# A status choice, and the stored values it matches. "Failed" covers every spelling the code has used.
STATUS_GROUPS = {
    "success": ("success",),
    "authorized": ("authorized",),
    "failed": ("failure", "failed", "error", "refused"),
}

# The channels a filter can pick, plus "unknown" for rows with none (older rows, background work).
CHANNEL_CHOICES = ("web", "sftp", "public_link", "upload_link", "device_sync", "unknown")

# Rows whose action the catalog does not know, written by an older release.
LEGACY_CATEGORY = "legacy"

MAX_PAGE = 200
MAX_TEXT = 128
# The page sizes the Activity page offers. The API takes any size up to MAX_PAGE.
PAGE_SIZES = (25, 50, 100)
# The furthest a numbered page may start (page x size). A page past it is reached by walking the pages
# before it, each continuing from the last one's cursor, so the database never skips this many rows.
MAX_OFFSET = 100_000
# The most row ids one request for specific rows (the live list's `ids`) may name.
MAX_IDS = 200
# The most seconds a read of newer rows may reach back before its starting point, to catch rows that
# committed late (a safety poll).
MAX_OVERLAP = 300
# The most event names one filter may list.
MAX_ACTIONS = 50
# A username typeahead's longest prefix and most suggestions.
MAX_PREFIX = 64
MAX_SUGGESTIONS = 20


def statuses_for(choices: Iterable[str]) -> List[str]:
    out: List[str] = []
    for c in choices:
        out.extend(STATUS_GROUPS.get(c, ()))
    return out


def parse_ip_filter(text: Optional[str]):
    """An exact address or a CIDR block, as an ipaddress network; None for an empty or invalid filter.
    A bare address becomes a single-address network, so one code path serves both."""
    text = (text or "").strip()
    if not text or len(text) > 64 or "%" in text:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def encode_cursor(timestamp: datetime, row_id) -> str:
    raw = f"{timestamp.isoformat()}|{row_id}".encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: Optional[str]) -> Optional[Tuple[datetime, uuid.UUID]]:
    """The (timestamp, id) a page continues after; None for a missing or malformed cursor, which reads
    as the first page rather than an error."""
    if not cursor or len(cursor) > 200:
        return None
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
        ts_text, id_text = raw.split("|", 1)
        return datetime.fromisoformat(ts_text), uuid.UUID(id_text)
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None


def like_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def build_events_query(q, AuditLog, *, categories: Sequence[str] = (), channels: Sequence[str] = (),
                       statuses: Sequence[str] = (), username: Optional[str] = None,
                       ip: Optional[str] = None, text: Optional[str] = None,
                       temp_credential_id: Optional[str] = None, temp_credential: Optional[str] = None,
                       ids: Sequence[str] = (), actions: Sequence[str] = (), user_exact: bool = False,
                       no_account: bool = False, vault_id: Optional[str] = None,
                       start: Optional[datetime] = None, end: Optional[datetime] = None):
    """Apply the Events filters to a query over AuditLog. Unknown choices are ignored, never errors."""
    from sqlalchemy import String, and_, case, cast, false, literal, or_, select

    if categories:
        known = [c for c in categories if audit_catalog.category_label(c)]
        conds = []
        if known:
            conds.append(AuditLog.action.in_(audit_catalog.stored_names(known)))
        if LEGACY_CATEGORY in categories:
            every = [n for a in audit_catalog.ACTIONS for n in (a.name,) + a.aliases]
            conds.append(~AuditLog.action.in_(every))
        q = q.filter(or_(*conds) if conds else false())

    if channels:
        picked = [c for c in channels if c in CHANNEL_CHOICES and c != "unknown"]
        conds = []
        if picked:
            conds.append(AuditLog.channel.in_(picked))
        if "unknown" in channels:
            conds.append(AuditLog.channel.is_(None))
        q = q.filter(or_(*conds) if conds else false())

    if statuses:
        wanted = statuses_for(statuses)
        q = q.filter(AuditLog.status.in_(wanted) if wanted else false())

    if username and user_exact:
        from sqlalchemy import func
        q = q.filter(func.lower(AuditLog.username) == username[:MAX_TEXT].lower())
    elif username:
        q = q.filter(AuditLog.username.ilike(f"%{like_escape(username[:MAX_TEXT])}%", escape="\\"))

    if no_account:
        # A name no account had: typed at a failed sign-in, an account deleted since, or the server's
        # operator acting from the host (credential_changes.HOST_OPERATOR, which no account may take).
        q = q.filter(AuditLog.user_id.is_(None), AuditLog.username.isnot(None))

    if actions:
        wanted = stored_action_names(actions)
        q = q.filter(AuditLog.action.in_(wanted) if wanted else false())

    if vault_id:
        try:
            vid = str(uuid.UUID(str(vault_id)))
        except (ValueError, TypeError):
            q = q.filter(false())
        else:
            # The vault itself, or anything in it: the rows name it in `details` (see activity_names).
            q = q.filter(or_(and_(AuditLog.resource_type == "vault", AuditLog.resource_id == vid),
                             AuditLog.details["vault_id"].as_string() == vid))

    net = parse_ip_filter(ip)
    if ip and net is None:
        q = q.filter(false())                      # an unreadable IP filter matches nothing
    elif net is not None:
        if net.num_addresses == 1:
            q = q.filter(AuditLog.ip_address == str(net.network_address))
        else:
            # Only rows whose stored value is a plain address are cast; anything else never matches.
            # CASE keeps the cast from being evaluated on the rest.
            pattern = r"^[0-9.]+$" if net.version == 4 else r"^[0-9a-fA-F:]+$"
            q = q.filter(case(
                (AuditLog.ip_address.op("~")(pattern),
                 cast(AuditLog.ip_address, _inet()).op("<<=")(cast(literal(str(net)), _inet()))),
                else_=False))

    if text:
        like = f"%{like_escape(text[:MAX_TEXT])}%"
        labelled = actions_labelled(text[:MAX_TEXT])
        q = q.filter(or_(
            AuditLog.action.in_(labelled) if labelled else false(),
            AuditLog.action.ilike(like, escape="\\"),
            AuditLog.username.ilike(like, escape="\\"),
            AuditLog.resource_id.ilike(like, escape="\\"),
            AuditLog.error_message.ilike(like, escape="\\"),
            cast(AuditLog.details, String).ilike(like, escape="\\"),
        ))

    if temp_credential_id:
        try:
            q = q.filter(AuditLog.temp_credential_id == uuid.UUID(str(temp_credential_id)))
        except (ValueError, TypeError):
            q = q.filter(false())

    if temp_credential:
        # By name: the name the row stored (0.33.0 on), or for an older row the name of the credential
        # it records, while that credential still exists.
        from app.core.models import TemporaryCredential
        like = f"%{like_escape(temp_credential[:MAX_TEXT])}%"
        q = q.filter(or_(
            AuditLog.temp_credential_name.ilike(like, escape="\\"),
            and_(AuditLog.temp_credential_name.is_(None),
                 AuditLog.temp_credential_id.in_(
                     select(TemporaryCredential.id).where(TemporaryCredential.temp_username.ilike(like, escape="\\")))),
        ))

    if ids:
        wanted = parse_ids(ids)
        q = q.filter(AuditLog.id.in_(wanted) if wanted else false())

    if start is not None:
        q = q.filter(AuditLog.timestamp >= start)
    if end is not None:
        q = q.filter(AuditLog.timestamp < end)
    return q


def _inet():
    from sqlalchemy.dialects.postgresql import INET
    return INET()


def stored_action_names(names: Iterable[str]) -> List[str]:
    """The stored names an event filter matches: a catalog name brings its older spellings with it,
    and a name the catalog does not know (an older release's) matches itself. At most MAX_ACTIONS."""
    out: List[str] = []
    for name in list(names)[:MAX_ACTIONS]:
        if not isinstance(name, str) or not name or len(name) > 100:
            continue
        entry = audit_catalog.lookup(name)
        for stored in ((entry.name,) + entry.aliases) if entry else (name,):
            if stored not in out:
                out.append(stored)
    return out


def actions_labelled(text: str) -> List[str]:
    """The stored names of the events whose label contains `text` (any case), so a search for what
    the page shows ("Sign-in failed") finds those rows."""
    t = (text or "").strip().lower()
    if not t:
        return []
    return [n for a in audit_catalog.ACTIONS if any(t in label.lower() for label in audit_catalog.labels_of(a))
            for n in (a.name,) + a.aliases]


def split_ids(values: Iterable[str]) -> List[str]:
    """Row ids given as repeated values, comma-separated values, or both."""
    return [p.strip() for v in values for p in str(v).split(",") if p.strip()]


def parse_ids(values: Iterable[str]) -> List[uuid.UUID]:
    """The row ids that read as UUIDs, at most MAX_IDS, each once; the rest are ignored."""
    out: List[uuid.UUID] = []
    for v in values:
        try:
            u = uuid.UUID(str(v))
        except (ValueError, TypeError, AttributeError):
            continue
        if u not in out:
            out.append(u)
        if len(out) >= MAX_IDS:
            break
    return out


def newer_than(q, AuditLog, anchor: Tuple[datetime, uuid.UUID]):
    """Rows after the anchor in time (the live list's `after`), the id breaking a tie as the page
    order does."""
    from sqlalchemy import and_, or_
    ts, row_id = anchor
    return q.filter(or_(AuditLog.timestamp > ts, and_(AuditLog.timestamp == ts, AuditLog.id > row_id)))


def read_anchor(value: Optional[str]):
    """What `after` names: ("id", UUID) for a row id, ("cursor", (timestamp, id)) for a row's cursor,
    or None when it is neither."""
    if not value:
        return None
    try:
        return ("id", uuid.UUID(value))
    except ValueError:
        pass
    cur = decode_cursor(value)
    return ("cursor", cur) if cur else None


def page_count(total: int, size: int) -> int:
    """How many numbered pages `total` rows fill, at least one (an empty result is page 1 of 1)."""
    return max(1, -(-max(0, total) // max(1, size)))


def page_offset(page: int, size: int) -> Optional[int]:
    """The rows before a numbered page, or None when that is more than MAX_OFFSET (the page is then
    reached through the cursors of the pages before it)."""
    offset = (max(1, page) - 1) * max(1, size)
    return offset if offset <= MAX_OFFSET else None


def page_window(page: int, size: int, total: int):
    """How to read a numbered page without skipping more than MAX_OFFSET rows: ("newest", offset,
    count) counts from the newest row; ("oldest", offset, count) counts from the oldest row, for a page
    near the end (the rows then come oldest first and are turned round). None when the page is more
    than MAX_OFFSET rows from both ends. A page past the end reads nothing."""
    size = max(1, size)
    first = (max(1, page) - 1) * size             # rows before the page, counted from the newest
    if first >= total:
        return ("newest", first, 0)               # past the end: nothing to read
    count = min(size, total - first)
    if first <= MAX_OFFSET:
        return ("newest", first, count)
    from_oldest = total - first - count           # rows after the page, counted from the oldest
    if from_oldest <= MAX_OFFSET:
        return ("oldest", from_oldest, count)
    return None


class PageTooFar(ValueError):
    """A numbered page more than MAX_OFFSET rows from both ends of the list."""


def numbered_page(base, AuditLog, page: int, size: int, total: int):
    """(rows newest first, whether older rows follow) for a numbered page of `base`, read without
    skipping more than MAX_OFFSET rows: from the newest row for a page near the start, from the oldest
    for a page near the end. Raises PageTooFar for a page far from both."""
    window = page_window(page, size, total)
    if window is None:
        raise PageTooFar(page)
    side, skip, count = window
    if not count:
        return [], False
    if side == "newest":
        rows = (base.order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
                .offset(skip).limit(count).all())
        return rows, skip + count < total
    rows = base.order_by(AuditLog.timestamp.asc(), AuditLog.id.asc()).offset(skip).limit(count).all()
    return list(reversed(rows)), skip > 0


def after_cursor(q, AuditLog, cursor: Optional[Tuple[datetime, uuid.UUID]]):
    """Rows older than the cursor, in the page order (newest first, id as the tie-break)."""
    if cursor is None:
        return q
    from sqlalchemy import and_, or_
    ts, row_id = cursor
    return q.filter(or_(AuditLog.timestamp < ts, and_(AuditLog.timestamp == ts, AuditLog.id < row_id)))


# The rows the host tool (dockvault.py accounts) writes under credential_changes.HOST_OPERATOR, with no
# account behind them. A name typed at a failed sign-in can be the same text, so the action decides.
HOST_OPERATOR_ACTIONS = frozenset({"user_updated", "password_reset_link_minted", "second_factor_admin_reset",
                                   "credential_change_approved"})


def is_host_operator(r) -> bool:
    """Whether a row is the server's operator acting from the host, not a person with an account."""
    from app.core.credential_changes import HOST_OPERATOR
    return (getattr(r, "user_id", None) is None and r.username == HOST_OPERATOR
            and r.action in HOST_OPERATOR_ACTIONS)


def row_view(r) -> dict:
    entry = audit_catalog.lookup(r.action or "")
    ts = r.timestamp
    if ts is not None and ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)       # stored naive in UTC
    return {
        "id": str(r.id),
        # Where this row sits in the list: `cursor` continues after it (older rows), `after` reads the
        # rows next to it on the newer side. Opaque to the client.
        "cursor": encode_cursor(r.timestamp, r.id) if r.timestamp is not None else None,
        "timestamp": ts.isoformat() if ts else None,
        "username": r.username,
        # Shown as "Server operator", not as its internal name.
        "host_operator": is_host_operator(r),
        "temp_credential_id": str(r.temp_credential_id) if r.temp_credential_id else None,
        "temp_credential_name": getattr(r, "temp_credential_name", None),
        "action": r.action,
        "label": audit_catalog.row_label(r.action or "", r.details),
        "category": entry.category if entry else LEGACY_CATEGORY,
        "severity": entry.severity if entry else "info",
        # Written by the server on its own (the file-expiry sweep): no person acted.
        "automatic": bool(entry and entry.automatic),
        "status": r.status,
        "channel": r.channel,
        "ip_address": r.ip_address,
        "method": r.method,
        "endpoint": r.endpoint,
        "user_agent": r.user_agent,
        "resource_type": r.resource_type,
        "resource_id": r.resource_id,
        "details": r.details,
        "error_message": r.error_message,
    }


# --- Username typeahead ---------------------------------------------------------------------------
# Suggestions come from the accounts table only. The log also holds every name typed at a failed
# sign-in, which can be a password typed into the username box, and a typeahead over it would list them
# to anyone walking the prefixes. Those names stay findable through the Person filter, never suggested.

def typeahead_prefix(text: Optional[str]) -> Optional[str]:
    """The prefix a typeahead searches for: trimmed and lower-cased, None when empty or too long."""
    text = (text or "").strip().lower()
    if not text or len(text) > MAX_PREFIX:
        return None
    return text


def username_suggestions(db, text: Optional[str], limit: int = 10) -> List[dict]:
    """Accounts whose username starts with `text`, in name order, at most `limit` (MAX_SUGGESTIONS), each
    saying whether it is active. Never a name from the log alone: a name typed at a failed sign-in or a
    deleted account's (see above)."""
    from sqlalchemy import func
    from app.core.models import User
    prefix = typeahead_prefix(text)
    limit = max(1, min(int(limit or 10), MAX_SUGGESTIONS))
    if prefix is None:
        return []
    like = like_escape(prefix) + "%"
    accounts = db.query(User.username, User.is_active).filter(
        func.lower(User.username).like(like, escape="\\")).order_by(
        func.lower(User.username).collate("C")).limit(limit).all()
    return [{"username": u, "account": True, "active": bool(a)} for u, a in accounts if u]


def temp_credential_suggestions(db, text: Optional[str], limit: int = 8) -> List[dict]:
    """Temporary credentials whose name starts with `text` (two characters or more), newest first, at
    most `limit` (MAX_SUGGESTIONS): id, name, state and expiry. Never the note, which is free text."""
    from sqlalchemy import func
    from app.core.models import TemporaryCredential as TC
    prefix = typeahead_prefix(text)
    if prefix is None or len(prefix) < 2:
        return []
    limit = max(1, min(int(limit or 8), MAX_SUGGESTIONS))
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    rows = (db.query(TC.id, TC.temp_username, TC.is_active, TC.expires_at)
            .filter(func.lower(TC.temp_username).like(like_escape(prefix) + "%", escape="\\"))
            .order_by(TC.created_at.desc()).limit(limit).all())
    out = []
    for cid, name, active, expires in rows:
        exp = expires.replace(tzinfo=None) if expires is not None and expires.tzinfo else expires
        state = "turned_off" if not active else ("expired" if exp is not None and exp <= now else "active")
        out.append({"id": str(cid), "name": name, "state": state,
                    "expires_at": exp.replace(tzinfo=timezone.utc).isoformat() if exp else None})
    return out


# --- Export ----------------------------------------------------------------------------------------

# The most rows one export holds. A larger result stops here and says so in its last line.
EXPORT_CAP = 100_000
EXPORT_BATCH = 1000
EXPORT_FORMATS = ("csv", "ndjson")

# (column heading, row_view key), in the order a CSV export lists them.
EXPORT_COLUMNS = (
    ("Time (UTC)", "timestamp"), ("Event", "label"), ("Action", "action"), ("Category", "category"),
    ("Status", "status"), ("User", "username"), ("Temporary credential", "temp_credential_name"),
    ("Channel", "channel"), ("IP address", "ip_address"), ("Method", "method"), ("Route", "endpoint"),
    ("User agent", "user_agent"), ("Resource type", "resource_type"), ("Resource ID", "resource_id"),
    ("Details", "details"), ("Error", "error_message"), ("Temporary credential ID", "temp_credential_id"),
)


def export_filters(*, started: datetime, end: Optional[datetime] = None, **filters) -> dict:
    """The Events filters for an export, its end clamped to the moment the export started: the export
    then holds exactly the rows it counted, and not its own audit row or anything written while it
    streams."""
    filters["end"] = min(end, started) if end else started
    return filters


def export_page(q, AuditLog, filters: dict, after, batch: int = EXPORT_BATCH):
    """One batch of an export: the rows after the cursor, newest first, at most `batch`."""
    return (after_cursor(build_events_query(q, AuditLog, **filters), AuditLog, after)
            .order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
            .limit(batch))


def formula_safe(value):
    """A CSV cell a spreadsheet would run as a formula (=, +, -, @, tab, carriage return first) gets a
    leading quote. Audit cells hold text anyone can influence, such as a username typed at sign-in."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def _cell(value):
    import json
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, default=str)
    return formula_safe(str(value))


def export_lines(fetch_batch, fmt: str, total: int, cap: int = EXPORT_CAP):
    """The export, a line at a time. `fetch_batch(after)` returns (row_views, next_cursor) for the rows
    after the cursor (None: from the newest). Stops at `cap` rows; when more matched, the last line says
    how many were left out."""
    import csv
    import io
    import json

    def csv_line(cells):
        buf = io.StringIO()
        csv.writer(buf).writerow(cells)
        return buf.getvalue()

    if fmt == "csv":
        yield csv_line([h for h, _ in EXPORT_COLUMNS])
    sent, after = 0, None
    while sent < cap:
        rows, after = fetch_batch(after)
        for row in rows[:cap - sent]:
            if fmt == "csv":
                yield csv_line([_cell(row.get(k)) for _, k in EXPORT_COLUMNS])
            else:
                yield json.dumps(row, default=str) + "\n"
            sent += 1
        if not rows or after is None:
            break
    if total > sent and sent >= cap:           # the cap cut it short (not rows deleted meanwhile)
        note = (f"Export stopped at {sent} of {total} events. Narrow the filters to export the rest.")
        if fmt == "csv":
            yield csv_line(["# " + note])
        else:
            yield json.dumps({"truncated": True, "exported": sent, "total": total, "message": note}) + "\n"
