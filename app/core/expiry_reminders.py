"""Reminders before a share, a public link, a note link or an upload link expires.

Every ``INTERVAL_SECONDS`` the web process looks for the account-made things that expire within
``WINDOW_HOURS`` and still work, and tells each one's maker once per thing and expiry date (so an
extension, which moves the date, earns one more reminder). The telling itself (an in-app notice, and the
optional email) is the caller's: this module only decides what is due, so it can be read and tested
without the web app.

Nothing here reads a file's name: a share is named by its vault, a link by its tag, a note link by the
note's title as frozen into the link, an upload link by its label.
"""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Callable, Optional

WINDOW_HOURS = 48
INTERVAL_SECONDS = 600

_executor: Optional[ThreadPoolExecutor] = None


def due(db, now: Optional[datetime] = None, within_hours: int = WINDOW_HOURS) -> list:
    """Everything that expires within ``within_hours`` and still works, as dicts the caller tells about:
    kind (share | public_link | note_link | receiver), id, owner_id, title, expires_at, target (the page
    in the web app that manages it)."""
    from app.core.models import Share, PublicLink, NoteLink, Receiver, Vault, NoteLinkTag

    now = now or datetime.utcnow()
    until = now + timedelta(hours=within_hours)
    items = []

    shares = (db.query(Share).filter(Share.status == "active", Share.expires_at > now, Share.expires_at <= until)
              .order_by(Share.expires_at).all())
    vault_ids = {s.vault_id for s in shares}
    # Whole rows: a vault's name is sealed at rest and read through the loaded object.
    names = {v.id: v.name for v in db.query(Vault).filter(Vault.id.in_(vault_ids)).all()} if vault_ids else {}
    for s in shares:
        what = {"vault": "the vault", "folder": "a folder in", "file": "a file in"}.get(s.target_type, "an item in")
        items.append({"kind": "share", "id": str(s.id), "owner_id": str(s.creator_id),
                      "title": f"Your share of {what} {names.get(s.vault_id) or 'a vault'}",
                      "expires_at": s.expires_at, "target": "#shared"})

    links = (db.query(PublicLink).filter(PublicLink.revoked.is_(False), PublicLink.expires_at.isnot(None),
                                         PublicLink.expires_at > now, PublicLink.expires_at <= until)
             .order_by(PublicLink.expires_at).all())
    tag_ids = {l.tag_id for l in links if l.tag_id}
    tags = dict(db.query(NoteLinkTag.id, NoteLinkTag.name).filter(NoteLinkTag.id.in_(tag_ids)).all()) if tag_ids else {}
    for l in links:
        items.append({"kind": "public_link", "id": str(l.id), "owner_id": str(l.owner_id),
                      "title": f"Your public link ({tags.get(l.tag_id) or 'a ' + (l.target_type or 'file')} link)",
                      "expires_at": l.expires_at, "target": "#vaults"})

    notes = (db.query(NoteLink).filter(NoteLink.revoked.is_(False), NoteLink.expires_at.isnot(None),
                                       NoteLink.expires_at > now, NoteLink.expires_at <= until)
             .order_by(NoteLink.expires_at).all())
    for n in notes:
        items.append({"kind": "note_link", "id": str(n.id), "owner_id": str(n.owner_id),
                      "title": f"Your note link “{(n.title_snapshot or 'Untitled note')[:60]}”",
                      "expires_at": n.expires_at, "target": "#notes"})

    receivers = (db.query(Receiver).filter(Receiver.revoked.is_(False), Receiver.expires_at.isnot(None),
                                           Receiver.expires_at > now, Receiver.expires_at <= until)
                 .order_by(Receiver.expires_at).all())
    for r in receivers:
        items.append({"kind": "receiver", "id": str(r.id), "owner_id": str(r.owner_id),
                      "title": f"Your upload link {r.label}" if r.label else "Your upload link",
                      "expires_at": r.expires_at, "target": "#uploadlinks"})
    return items


def dedup_key(item: dict) -> str:
    """One reminder per thing and expiry date: a thing extended to another day is reminded again."""
    return f"expiry_reminder:{item['kind']}:{item['id']}:{item['expires_at'].date().isoformat()}"


def in_words(expires_at: datetime, now: Optional[datetime] = None) -> str:
    now = now or datetime.utcnow()
    hours = max(0, int((expires_at - now).total_seconds() // 3600))
    if hours < 1:
        return "within the hour"
    if hours < 24:
        return f"in about {hours} hour{'s' if hours != 1 else ''}"
    days = hours // 24
    return f"in about {days} day{'s' if days != 1 else ''}"


def sweep_once(tell: Callable[[dict], bool], now: Optional[datetime] = None) -> int:
    """Tell each maker about what is due; ``tell(item)`` returns True when a notice was written (a second
    call for the same thing and date is its own no-op). Returns how many notices were written. Never
    raises past one failed item."""
    from app.core.database import get_db_context
    from app.core.safe_log import safe_event

    written = 0
    try:
        with get_db_context() as db:
            items = due(db, now=now)
    except Exception as e:  # noqa: BLE001
        safe_event("expiry-reminders.read.failed", e)
        return 0
    for item in items:
        try:
            if tell(item):
                written += 1
        except Exception as e:  # noqa: BLE001
            safe_event("expiry-reminders.tell.failed", e, kind=item.get("kind"))
    if written:
        safe_event("expiry-reminders.sent", count=written)
    return written


def _pool() -> ThreadPoolExecutor:
    global _executor
    if _executor is None:
        _executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="expiry-reminders")
    return _executor


async def run_forever(tell: Callable[[dict], bool], interval_seconds: float = INTERVAL_SECONDS) -> None:
    """The web process's reminder loop: :func:`sweep_once` every ``interval_seconds`` on a thread of its
    own. Survives any error; ends only when cancelled."""
    from app.core.safe_log import safe_event
    loop = asyncio.get_running_loop()
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            await loop.run_in_executor(_pool(), sweep_once, tell)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001
            safe_event("expiry-reminders.loop.failed", e)
