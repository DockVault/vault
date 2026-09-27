"""Saved searches on the Activity page: what a saved filter set may hold, and its name.

A saved search stores the Events filters as JSON, and only the keys and values listed here: anything
else is refused with a message naming it, so a stored search can never carry a value the Events API
would not take. Everything a person can do with their saved searches is in app/api/api_server.py
(/activity/saved-searches); this module holds the rules and is testable without a database.
"""
import unicodedata
from typing import Any, Dict, Optional

from app.core import audit_catalog
from app.services import activity_events as ev

# The most saved searches one person keeps.
MAX_PER_USER = 50
MAX_NAME = 80

RANGES = ("24h", "7d", "30d")

# key -> (kind, bound): "choices" is a list of known values, "text" a string of at most `bound`
# characters. `range` is a time range relative to when the search is loaded; from_date and to_date are
# fixed instants.
FIELDS = {
    "category": ("choices", None),
    "channel": ("choices", None),
    "status": ("choices", None),
    "user": ("text", 128),
    "ip": ("text", 64),
    "q": ("text", 128),
    "temp_credential": ("text", 128),
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


def clean_filters(raw: Any) -> Dict[str, Any]:
    """The filters to store: only the listed keys, each checked; empty values left out."""
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
    return out


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
