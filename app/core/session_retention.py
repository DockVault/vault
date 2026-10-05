"""How long the working record of a finished sign-in is kept.

Every sign-in leaves a row in ``active_sessions``, and one that stops at the second factor leaves a
row in ``pending_logins``. Both hold the address the sign-in came from. A session row is marked
inactive when it ends and a pending login is marked consumed when it completes, but neither was ever
deleted, so the address of every sign-in stayed in the database for as long as the deployment ran.

The pruner (app/core/retention.py) deletes both once they are finished and older than
:data:`SESSION_DATA_RETENTION_DAYS`, in batches, off the event loop:

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
from datetime import datetime, timedelta

from sqlalchemy import and_, func, or_


# Finished session and pending-login rows older than this are deleted.
SESSION_DATA_RETENTION_DAYS = 30


def session_window(token_lifetime_minutes: int) -> timedelta:
    """How long a finished session row is kept: the retention period, or the longest a token can
    live if that is longer."""
    return max(timedelta(days=SESSION_DATA_RETENTION_DAYS),
               timedelta(minutes=max(0, int(token_lifetime_minutes or 0))))


def finished_session_conditions(model, now: datetime, window: timedelta):
    """Filter conditions for the session rows the pruner deletes."""
    return (
        or_(model.is_active == False,  # noqa: E712
            model.revoked == True,  # noqa: E712
            and_(model.expires_at.isnot(None), model.expires_at < now)),
        func.coalesce(model.last_activity, model.started_at) < now - window,
    )


def finished_pending_login_conditions(model, now: datetime):
    """Filter conditions for the pending-login rows the pruner deletes."""
    return (
        or_(model.consumed_at.isnot(None),
            and_(model.expires_at.isnot(None), model.expires_at < now)),
        model.created_at < now - timedelta(days=SESSION_DATA_RETENTION_DAYS),
    )


def expired_key_proof_challenge_conditions(model, now: datetime):
    """Filter conditions for the zero-knowledge key-proof challenges the pruner deletes: those past their
    lifetime.

    Issuing a challenge already deletes the caller's own expired ones; this sweeps the rest, so a challenge
    nobody came back for does not stay in the database with its sealed one-time key. A row past its lifetime
    can no longer be answered, so deleting it changes no outcome: the request it was issued for is refused
    either way."""
    from app.services.zk_key_proof import CHALLENGE_TTL_SECONDS
    return (model.created_at < now - timedelta(seconds=CHALLENGE_TTL_SECONDS),)
