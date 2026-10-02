"""The notice of what this vault records (app/core/recording_notice.py).

    GET  /recording                      the page (static/recording.html), public: it reads the notice below.
    GET  /privacy/recording              the notice, public: the levels in force, how long records are kept, who
                                         can see them, the legal basis and contact the operator states, and
                                         every other place personal data is kept. Never a past version.
    GET  /privacy/recording/history      the versions of the levels, newest first (signed in).
    GET  /privacy/recording/status       whether the levels changed since the signed-in account last read the
                                         notice (the banner after sign-in).
    POST /privacy/recording/seen         the account has read the notice of a version: the banner goes, and an
                                         audit row records it. Reading is recorded, not consent.

The public notice is computed at most once a minute per process, so a flood of requests does not reach the
database, and the general request limit applies to it like any other route. Every route is a plain ``def`` with
a statement timeout. A temporary credential has no banner and cannot mark the notice read: it is not the account
holder.
"""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.user_management_api import get_current_user
from app.core import audit_privacy as ap
from app.core import recording_notice as rn
from app.core.database import get_db
from app.core.models import AuditPrivacyPolicy, User
from app.core.paths import PROJECT_ROOT

router = APIRouter(tags=["Recording notice"])

STATEMENT_TIMEOUT_MS = 5000
HISTORY_LIMIT = 50
PAGE = os.path.join(str(PROJECT_ROOT / "static"), "recording.html")


def limit_statements(db: Session) -> None:
    bind = db.get_bind()
    if bind is not None and bind.dialect.name == "postgresql":
        db.execute(text(f"SET LOCAL statement_timeout = {STATEMENT_TIMEOUT_MS}"))


@router.get("/recording", include_in_schema=False)
def recording_page():
    """The notice's page. Its script and style are files of their own, so the page runs under the app's
    content security policy with nothing inline."""
    if not os.path.exists(PAGE):
        raise HTTPException(status_code=404, detail="Not found")
    resp = FileResponse(PAGE)
    resp.headers["Cache-Control"] = "no-cache"
    return resp


@router.get("/privacy/recording")
def recording_notice(db: Session = Depends(get_db)):
    """What this vault records, as configured now (public)."""
    limit_statements(db)
    return rn.notice(db)


def _account(user: User) -> User:
    if getattr(user, "_is_temp_session", False):
        raise HTTPException(status_code=403, detail="A temporary credential has no notice of its own to read.")
    return user


@router.get("/privacy/recording/history")
def recording_history(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """The versions of the levels, newest first: when each began and why (signed in)."""
    limit_statements(db)
    rows = (db.query(AuditPrivacyPolicy).order_by(AuditPrivacyPolicy.version.desc()).limit(HISTORY_LIMIT).all())
    reasons = {"initial": "What the vault recorded before the levels existed",
               "admin": "Changed by an administrator",
               "limit": "Brought within a lowered limit of the server's configuration",
               "locked": "Set by the server's configuration"}
    return {"versions": [{"version": r.version, "since": r.created_at.isoformat() + "Z" if r.created_at else None,
                          "why": reasons.get(r.reason, r.reason),
                          "levels": [{"key": key, "label": ap.LABELS[key], "level": getattr(r, key),
                                      "words": rn.LEVEL_WORDS.get(getattr(r, key), getattr(r, key))}
                                     for key in ap.POLICY_KEYS]} for r in rows]}


@router.get("/privacy/recording/status")
def recording_status(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Whether to show the banner: the levels changed since this account last read the notice."""
    limit_statements(db)
    if getattr(current_user, "_is_temp_session", False):
        return {"version": None, "seen": None, "show": False, "text": None}
    latest = ap.read_latest(db) or ap.DEFAULT_POLICY
    return rn.banner(current_user, latest.version)


class Seen(BaseModel):
    version: int


@router.post("/privacy/recording/seen")
def recording_seen(body: Seen, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """The account has read the notice of ``version``: recorded with its audit row, in one transaction."""
    limit_statements(db)
    user = _account(current_user)
    latest = ap.read_latest(db) or ap.DEFAULT_POLICY
    if body.version < 1 or body.version > latest.version:
        raise HTTPException(status_code=400, detail="There is no such version of the recording levels.")
    account = db.get(User, user.id)
    if (account.privacy_seen_version or 1) >= body.version:
        return rn.banner(account, latest.version)
    from app.services.audit_logger import AuditLogger
    try:
        account.privacy_seen_version = body.version
        db.add(AuditLogger(db).build_row(action="privacy_notice_seen", status="success", user=account,
                                         resource_type="user", resource_id=str(account.id),
                                         details={"version": body.version}))
        db.commit()
    except Exception:  # noqa: BLE001 -- not recorded as read without its audit row
        db.rollback()
        raise HTTPException(status_code=503, detail="It could not be recorded; try again shortly.")
    return rn.banner(account, latest.version)
