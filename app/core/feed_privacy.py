"""What an administrator watching the live activity feed sees of someone else's activity.

Administrators are not members of every vault, and vault and file names are encrypted at rest for
that reason. The live feed used to carry them in every upload and download event to every signed-in
administrator. An event someone else performed now reaches a watching administrator with only the
fields listed in SAFE_KEYS: who, from where, when, what kind of event, which vault by id, and progress.
Its description, which can name a file, becomes its title ("Upload completed"). Keeping a list of what
may pass, rather than of what to remove, means a field added to an event later stays out until it is
added here. The person's own events are unchanged.
"""
from typing import Optional

# The fields another person's event keeps. Nothing here names a file, folder, vault, note or link.
SAFE_KEYS = frozenset({
    "type", "title", "timestamp", "user", "username", "user_id", "owner_user_id", "ip",
    "is_temporary", "temp_username", "temp_credential_id", "severity",
    "operation_id", "operation_type", "completed", "cancelled", "worker_stopped",
    "bytes_uploaded", "total_size", "vault_id", "vault_type",
})


def _inner(event_data):
    if not isinstance(event_data, dict):
        return {}
    inner = event_data.get("event")
    return inner if isinstance(inner, dict) else event_data


def is_own(event_data, viewer_id, viewer_username: Optional[str]) -> bool:
    """Whether the viewer performed or owns the event."""
    inner = _inner(event_data)
    for key in ("owner_user_id", "user_id"):
        if inner.get(key) is not None and str(inner.get(key)) == str(viewer_id):
            return True
    actor = inner.get("user") or inner.get("username")
    return bool(viewer_username) and actor == viewer_username


def for_viewer(event_data, viewer_id, viewer_username: Optional[str]):
    """The event as this viewer may see it: whole if it is theirs, otherwise with only SAFE_KEYS and
    its title as its description. A frame's own wrapper fields (metrics, traffic) are counts and stay."""
    inner = _inner(event_data)
    if not inner or is_own(event_data, viewer_id, viewer_username):
        return event_data
    kept = {k: v for k, v in inner.items() if k in SAFE_KEYS}
    if "description" in inner:
        kept["description"] = inner.get("title") or ""
    if kept == inner:
        return event_data
    if inner is event_data:
        return kept
    out = dict(event_data)
    out["event"] = kept
    return out
