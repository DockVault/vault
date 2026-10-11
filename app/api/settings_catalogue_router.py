"""What the Settings pages need to sort, mark and search every setting (app/core/settings_catalogue.py).

    GET  /settings/catalogue       every setting of every Settings page: its page, its level (essential or
                                   advanced), the release it arrived in and whether it is new to this
                                   administrator, and, for one the deployment has locked, its value and why.
    POST /settings/catalogue/seen  this administrator has opened the Settings pages at the running release.

"New" counts from the release at which this administrator last opened the Settings pages, which is kept
with their preferences (user_preferences, ``settings_seen``): the page reads the catalogue, then says it has
been seen. Saying so is a preference like the skin, not a change to the vault, so it is not audited.

Both routes are plain ``def`` (the thread pool runs them), every statement is bounded by a statement timeout,
and only an interactive administrator reaches them: the Settings pages are theirs alone.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.managed_settings_router import limit_statements
from app.api.user_management_api import require_interactive_admin
from app.core import settings_catalogue as catalogue
from app.core import settings_registry as registry
from app.core.data_requirements import running_version
from app.core.database import get_db
from app.core.models import User, UserPreference

router = APIRouter(tags=["Managed settings"])


def last_seen(db: Session, user: User) -> Optional[str]:
    """The release at which ``user`` last opened the Settings pages, or None (never, or not readable)."""
    row = db.query(UserPreference).filter(UserPreference.user_id == user.id).first()
    value = row.preferences.get(catalogue.SEEN_PREFERENCE) if row and isinstance(row.preferences, dict) else None
    return value if registry.parse_version(value) is not None else None


@router.get("/settings/catalogue")
def get_settings_catalogue(current_user: User = Depends(require_interactive_admin),
                           db: Session = Depends(get_db)):
    """Every setting of the Settings pages, for this administrator."""
    limit_statements(db)
    current = running_version()
    seen = last_seen(db, current_user)
    return {"version": current, "seen": seen, "levels": list(registry.LEVELS), "pages": list(registry.PAGES),
            "entries": catalogue.entries(current=current, seen=seen)}


def _store_seen(db: Session, user: User, version: str) -> None:
    row = db.query(UserPreference).filter(UserPreference.user_id == user.id).with_for_update().first()
    if row is None:
        db.add(UserPreference(user_id=user.id, preferences={catalogue.SEEN_PREFERENCE: version}))
    else:
        merged = dict(row.preferences) if isinstance(row.preferences, dict) else {}
        merged[catalogue.SEEN_PREFERENCE] = version
        row.preferences = merged          # a new dict, so the change is tracked


@router.post("/settings/catalogue/seen")
def mark_settings_seen(current_user: User = Depends(require_interactive_admin),
                       db: Session = Depends(get_db)):
    """Keep the running release as the one this administrator last opened the Settings pages at. A release
    that cannot be read is not kept (nothing would count from it)."""
    current = running_version()
    if registry.parse_version(current) is None:
        return {"seen": last_seen(db, current_user)}
    limit_statements(db)
    _store_seen(db, current_user, current)
    try:
        db.commit()
    except IntegrityError:
        # Another request created the row first: store onto it.
        db.rollback()
        limit_statements(db)
        _store_seen(db, current_user, current)
        db.commit()
    return {"seen": current}
