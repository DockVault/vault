"""Saved searches on the Activity page: what a saved filter set may hold, and its name.

A saved search stores the Events filters as JSON, and only the keys and values listed here: anything
else is refused with a message naming it, so a stored search can never carry a value the Events API
would not take. Everything a person can do with their saved searches is in app/api/api_server.py
(/activity/saved-searches); this module holds the rules and is testable without a database.
"""
import unicodedata
import uuid
from typing import Any, Dict, Optional

from app.core import audit_catalog
from app.services import activity_events as ev

# The most saved searches one person keeps.
MAX_PER_USER = 50
MAX_NAME = 80

RANGES = ("24h", "7d", "30d", "all")

# key -> (kind, bound): "choices" is a list of known values, "text" a string of at most `bound`
# characters. `range` is a time range relative to when the search is loaded; from_date and to_date are
# fixed instants.
FIELDS = {
    "category": ("choices", None),
    "channel": ("choices", None),
    "status": ("choices", None),
    "action": ("choices", None),
    "user": ("text", 128),       # a name; one typed at a failed sign-in is kept as typed_as_recorded says
    "user_match": ("choice", None),
    "no_account": ("flag", None),
    "ip": ("text", 64),
    "q": ("text", 128),
    "temp_credential": ("text", 128),
    "temp_credential_id": ("id", None),
    "vault_id": ("id", None),
    "range": ("choice", None),
    "from_date": ("text", 64),
    "to_date": ("text", 64),
}


class InvalidSearch(ValueError):
    """A saved search that cannot be stored, with a message for the person who tried."""


def _known(key: str):
    if key == "category":
        return [k for k, _ in audit_catalog.CATEGORIES] + [ev.LEGACY_CATEGORY]
    if key == "channel":
        return list(ev.CHANNEL_CHOICES)
    if key == "status":
        return list(ev.STATUS_GROUPS)
    if key == "range":
        return list(RANGES)
    if key == "user_match":
        return ["contains", "exact"]
    if key == "action":
        return [n for a in audit_catalog.ACTIONS for n in (a.name,) + a.aliases]
    return []


def clean_name(name: Any) -> str:
    """A saved search's name: trimmed, 1 to MAX_NAME characters, no control characters."""
    if not isinstance(name, str):
        raise InvalidSearch("Give the search a name.")
    name = " ".join(name.split())
    if not name:
        raise InvalidSearch("Give the search a name.")
    if len(name) > MAX_NAME:
        raise InvalidSearch(f"A name can be at most {MAX_NAME} characters.")
    if any(unicodedata.category(c).startswith("C") for c in name):
        raise InvalidSearch("A name cannot contain control characters.")
    return name


def clean_filters(raw: Any, held_in_full=None) -> Dict[str, Any]:
    """The filters to store: only the listed keys, each checked; empty values left out. A typed name is kept
    as typed_as_recorded says (``held_in_full``: see there)."""
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise InvalidSearch("The filters must be an object.")
    unknown = sorted(k for k in raw if k not in FIELDS)
    if unknown:
        raise InvalidSearch(f"A saved search cannot hold {', '.join(map(str, unknown[:5]))}.")
    out: Dict[str, Any] = {}
    for key, (kind, bound) in FIELDS.items():
        value = raw.get(key)
        if value in (None, "", []):
            continue
        if kind == "choices":
            if isinstance(value, str):
                value = [value]
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise InvalidSearch(f"{key} must be a list of names.")
            known = _known(key)
            bad = [v for v in value if v not in known]
            if bad:
                raise InvalidSearch(f"{key} has a value the Activity page does not offer: {bad[0][:40]}.")
            out[key] = list(dict.fromkeys(value))
        elif kind == "choice":
            if value not in _known(key):
                raise InvalidSearch(f"{key} must be one of {', '.join(_known(key))}.")
            out[key] = value
        elif kind == "flag":
            if not isinstance(value, bool):
                raise InvalidSearch(f"{key} must be true or false.")
            if value:
                out[key] = True
        elif kind == "id":
            # An id, never a name: a saved vault filter must not keep the vault's name.
            try:
                out[key] = str(uuid.UUID(str(value)))
            except (ValueError, TypeError, AttributeError):
                raise InvalidSearch(f"{key} must be an id.")
        else:
            if not isinstance(value, str):
                raise InvalidSearch(f"{key} must be text.")
            value = value.strip()
            if len(value) > bound:
                raise InvalidSearch(f"{key} can be at most {bound} characters.")
            if value:
                out[key] = value
    if "range" in out and ("from_date" in out or "to_date" in out):
        raise InvalidSearch("A search has either a range or dates, not both.")
    return typed_as_recorded(out, held_in_full)


# The filter whose value is a name someone typed, which the recording levels may keep only as a fingerprint.
# The free-text search (q) is kept as typed: it mostly names an event, and its fingerprint would match no label.
TYPED = ("user",)

# Why a saved search cannot hold a typed name while the levels record none of them.
NOT_RECORDED = ("Names typed at a failed sign-in are not recorded at the current recording levels, so a saved "
                "search cannot keep one. Save the search without the person, or with the name of an account.")


def typed_as_recorded(filters: Dict[str, Any], held_in_full=None) -> Dict[str, Any]:
    """``filters`` with each typed name kept the way the audit log keeps it.

    A name the audit log holds in full (an account's username, which every level records, or a name recorded in
    full under earlier levels) is kept as typed: the saved search then finds what the plain search finds.
    ``held_in_full(value, exact)`` says whether the log holds one, for an exact or a contains match; without it
    no name counts as held. Any other name is one typed at a failed sign-in, and is kept as the levels keep those
    (app/core/audit_privacy.py): in full, as its fingerprint, which matches the same rows, or, while none are
    recorded, not at all, and the search is refused. A value that is already a fingerprint is kept as it is."""
    from app.core import audit_privacy as ap
    from app.core.audit_fingerprints import SIGNIN, fingerprint, is_fingerprint
    try:
        level = ap.effective(ap.current().levels)[ap.SIGNIN_NAMES]
    except Exception:  # noqa: BLE001 -- unknown: keep no typed text
        level = ap.FINGERPRINT
    if level == ap.FULL:
        return filters
    out = dict(filters)
    exact = out.get("user_match") == "exact"
    for key in TYPED:
        value = out.get(key)
        if not isinstance(value, str) or not value or is_fingerprint(value):
            continue
        if held_in_full is not None and held_in_full(value, exact):
            continue
        kept = None
        if level == ap.FINGERPRINT:
            try:
                kept = fingerprint(SIGNIN, value)
            except Exception:  # noqa: BLE001 -- no key: nothing to keep in its place
                kept = None
        if kept is None:
            raise InvalidSearch(NOT_RECORDED)
        out[key] = kept
    return out


def held_in_full(db):
    """For typed_as_recorded: whether a name is an account's username or is held in full by an audit row's
    username, matched as the Events search matches it (exactly, ignoring case, or as a part)."""
    def check(value: str, exact: bool) -> bool:
        from sqlalchemy import exists, func
        from app.core.models import AuditLog, User
        value = value[:ev.MAX_TEXT]
        found = []
        for column in (User.username, AuditLog.username):
            if exact:
                found.append(func.lower(column) == value.lower())
            else:
                found.append(column.ilike(f"%{ev.like_escape(value)}%", escape="\\"))
        return any(db.query(exists().where(cond)).scalar() for cond in found)
    return check


def view(row) -> dict:
    """A saved search as the API returns it."""
    def iso(ts: Optional[Any]):
        return ts.isoformat() + "+00:00" if ts is not None and ts.tzinfo is None else (ts.isoformat() if ts else None)
    return {
        "id": str(row.id),
        "name": row.name,
        "filters": row.filters or {},
        "is_default": bool(row.is_default),
        "created_at": iso(row.created_at),
        "updated_at": iso(row.updated_at),
    }
