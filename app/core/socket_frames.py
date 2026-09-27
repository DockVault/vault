"""Which frames the app-wide web socket (/ws/monitor) passes to which connection.

The socket carries three things, and nothing else:

- the Activity signal (app/core/audit_signal.py): the id and category of each new audit row, only to a
  signed-in administrator's own session (not a temporary credential), who can open the Activity page;
- a notification nudge, to the person it is for, carrying no title or text: the page fetches the
  notification itself;
- "your temporary credential signed in", to the account that created it, carrying the credential's name
  and address.

A temporary credential's own socket receives none of them: the nudges and sign-in frames belong to the
account behind it, and one credential must not learn another's name and address.

Until 0.33.0 an administrator's socket also received every upload, download, sign-in and sign-out in the
deployment, for the Live Monitor page. The page is gone and so is that feed. Frames are passed by listing
what may pass rather than what to hold back, so a frame type added later stays off the socket until it
is added here.
"""
from typing import NamedTuple, Optional

from app.core import audit_signal

EVENTS_CHANNEL = "activity_events"
SIGNAL_CHANNEL = audit_signal.CHANNEL
CHANNELS = (EVENTS_CHANNEL, SIGNAL_CHANNEL)


class Viewer(NamedTuple):
    user_id: str
    is_temporary: bool
    # An administrator's own interactive session: may open the Activity page.
    sees_activity: bool


def _inner(data):
    if not isinstance(data, dict):
        return {}
    inner = data.get("event")
    return inner if isinstance(inner, dict) else data


def _forwardable_kind(inner) -> Optional[str]:
    """The kind of an EVENTS_CHANNEL frame that its owner's socket may receive, or None."""
    if inner.get("owner_user_id") is None:
        return None
    kind = inner.get("type")
    if kind == "notification" or (kind == "login" and inner.get("is_temporary")):
        return kind
    return None


def worth_publishing(event_data) -> bool:
    """Whether any connection could receive this frame, so whether it is worth publishing at all."""
    return _forwardable_kind(_inner(event_data)) is not None


def frame_for(viewer: Viewer, channel: str, data) -> Optional[dict]:
    """The frame this connection receives for a published message, or None. A frame is rebuilt from
    the fields its reader uses, so nothing else a publisher put in it reaches the socket."""
    if channel == SIGNAL_CHANNEL:
        if not viewer.sees_activity:
            return None
        events = audit_signal.parse_message(data)
        return {"type": "activity", "events": events} if events else None
    if channel != EVENTS_CHANNEL or viewer.is_temporary:
        return None
    inner = _inner(data)
    kind = _forwardable_kind(inner)
    if kind is None or str(inner["owner_user_id"]) != str(viewer.user_id):
        return None
    keys = (("type", "notification_type", "target", "owner_user_id") if kind == "notification" else
            ("type", "is_temporary", "temp_username", "ip", "owner_user_id", "timestamp"))
    return {"event": {k: inner[k] for k in keys if k in inner}}
