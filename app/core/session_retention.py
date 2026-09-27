"""How long the working record of a finished sign-in is kept.

Every sign-in leaves a row in ``active_sessions``, and one that stops at the second factor leaves a
row in ``pending_logins``. Both hold the address the sign-in came from. A session row is marked
inactive when it ends and a pending login is marked consumed when it completes, but neither was ever
deleted, so the address of every sign-in stayed in the database for as long as the deployment ran.

The periodic cleanup in the web process now deletes both once they are finished and older than
:data:`SESSION_DATA_RETENTION_DAYS`:

* a session row that is inactive, revoked or past its expiry, and has seen no activity for that long;
* a pending login that was consumed or has expired, and was created that long ago.

The audit log keeps its own record of each sign-in under its own retention setting; this covers only
these working rows.

Deleting a session row can end a session but never revive one: a token whose row is missing is
refused. And a row is only deleted once no token it backs can still be valid. A token is minted when
its row is written and lives at most the configured session timeout, which the settings page caps at
30 days, so a row idle for the retention period backs no live token. A deployment that raised
``JWT_ACCESS_TOKEN_EXPIRE_MINUTES`` beyond that keeps its rows for as long as its tokens live. A
pending login's pre-authentication token lives five minutes.
"""
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, func, or_

from app.core.config import settings
from app.core.models import ActiveSession, PendingLogin

# Finished session and pending-login rows older than this are deleted.
SESSION_DATA_RETENTION_DAYS = 30


def utc_now() -> datetime:
    """Now as these tables store it: UTC with no time zone attached."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def session_window(token_lifetime_minutes: int) -> timedelta:
    """How long a finished session row is kept: the retention period, or the longest a token can
    live if that is longer."""
    return max(timedelta(days=SESSION_DATA_RETENTION_DAYS),
               timedelta(minutes=max(0, int(token_lifetime_minutes or 0))))


def finished_session_conditions(model, now: datetime, window: timedelta):
    """Filter conditions for the session rows :func:`purge_old_session_data` deletes."""
    return (
        or_(model.is_active == False,  # noqa: E712
            model.revoked == True,  # noqa: E712
            and_(model.expires_at.isnot(None), model.expires_at < now)),
        func.coalesce(model.last_activity, model.started_at) < now - window,
    )


def finished_pending_login_conditions(model, now: datetime):
    """Filter conditions for the pending-login rows :func:`purge_old_session_data` deletes."""
    return (
        or_(model.consumed_at.isnot(None),
            and_(model.expires_at.isnot(None), model.expires_at < now)),
        model.created_at < now - timedelta(days=SESSION_DATA_RETENTION_DAYS),
    )


def purge_old_session_data(db, *, now=None, token_lifetime_minutes=None,
                           session_model=ActiveSession, pending_model=PendingLogin):
    """Delete finished session and pending-login rows past retention.

    Returns ``(sessions_deleted, pending_logins_deleted)``. The caller commits. The models are
    parameters so the real conditions can be exercised against a throwaway schema."""
    now = now or utc_now()
    if token_lifetime_minutes is None:
        token_lifetime_minutes = settings.jwt_access_token_expire_minutes
    sessions = db.query(session_model).filter(
        *finished_session_conditions(session_model, now, session_window(token_lifetime_minutes))
    ).delete(synchronize_session=False)
    pending = db.query(pending_model).filter(
        *finished_pending_login_conditions(pending_model, now)
    ).delete(synchronize_session=False)
    return sessions, pending
