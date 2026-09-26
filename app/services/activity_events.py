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
                       temp_credential_id: Optional[str] = None,
                       start: Optional[datetime] = None, end: Optional[datetime] = None):
    """Apply the Events filters to a query over AuditLog. Unknown choices are ignored, never errors."""
    from sqlalchemy import String, and_, case, cast, false, literal, or_

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

    if username:
        q = q.filter(AuditLog.username.ilike(f"%{like_escape(username[:MAX_TEXT])}%", escape="\\"))

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
        q = q.filter(or_(
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

    if start is not None:
        q = q.filter(AuditLog.timestamp >= start)
    if end is not None:
        q = q.filter(AuditLog.timestamp < end)
    return q


def _inet():
    from sqlalchemy.dialects.postgresql import INET
    return INET()


def after_cursor(q, AuditLog, cursor: Optional[Tuple[datetime, uuid.UUID]]):
    """Rows older than the cursor, in the page order (newest first, id as the tie-break)."""
    if cursor is None:
        return q
    from sqlalchemy import and_, or_
    ts, row_id = cursor
    return q.filter(or_(AuditLog.timestamp < ts, and_(AuditLog.timestamp == ts, AuditLog.id < row_id)))


def row_view(r) -> dict:
    entry = audit_catalog.lookup(r.action or "")
    ts = r.timestamp
    if ts is not None and ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)       # stored naive in UTC
    return {
        "id": str(r.id),
        "timestamp": ts.isoformat() if ts else None,
        "username": r.username,
        "temp_credential_id": str(r.temp_credential_id) if r.temp_credential_id else None,
        "action": r.action,
        "label": entry.label if entry else audit_catalog.LEGACY_LABEL,
        "category": entry.category if entry else LEGACY_CATEGORY,
        "severity": entry.severity if entry else "info",
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
