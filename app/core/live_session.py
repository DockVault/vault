"""Whether a request's bearer token belongs to a session that is signed in right now.

The request-body limit (app/core/body_limit.py) gives a body larger than the anonymous limit only to
such a session, because the framework reads a body before the route authenticates anyone. A token's
signature and expiry alone are not enough for that: they also pass a logged-out or revoked session, a
deactivated or administrator-locked account, and a temporary credential that was switched off, has
finished or has run out. So this makes the checks get_current_user makes, and no others:

- the token is signed by this server, has not expired, and names an account and a session;
- the session has not been logged out (the denylist); a regular session's row exists and is not
  revoked; a temporary credential's session row is active and inside the inactivity grace, and the
  credential exists, is active, has not finished (its connection closed) and is inside its
  deactivate_at and expires_at;
- the account exists, is active and is not locked by an administrator (an automatic lock after wrong
  passwords never ends a session, so it does not end this either).

An answer from the database is kept for CACHE_SECONDS per session, so a burst of uploads pays for one
lookup. A session ended during that time keeps the larger limit for at most that long; its request is
still refused by the route's own authentication, which this never replaces.

caller_state() gives one of four answers: NO_CREDENTIAL (no bearer token), LIVE, ENDED (a bearer token
that is not a live session, for whatever reason) or UNKNOWN (the database could not be asked; never
cached).
"""
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

NO_CREDENTIAL = "no-credential"
LIVE = "live"
ENDED = "ended"
UNKNOWN = "unknown"

CACHE_SECONDS = 5.0
CACHE_MAX_ENTRIES = 4096


def session_claims(authorization: Optional[bytes]) -> Optional[dict]:
    """The claims of a bearer session token this server signed and that has not expired, or None.
    A token without a session is none (a second-factor pending token carries none), as for
    get_current_user."""
    token = bearer_token(authorization)
    if not token:
        return None
    try:
        from app.core.security import verify_access_token
        payload = verify_access_token(token)
    except Exception:  # noqa: BLE001 -- a broken token is no session, never a 500
        return None
    if isinstance(payload, dict) and payload.get("sub") and payload.get("session_token"):
        return payload
    return None


def bearer_token(authorization: Optional[bytes]) -> Optional[str]:
    """The token of a `Bearer` Authorization header, or None for anything else."""
    if not authorization:
        return None
    try:
        scheme, _, token = authorization.decode("latin-1").strip().partition(" ")
    except Exception:  # noqa: BLE001 -- an undecodable header carries no token
        return None
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        return None
    return token


def _aware(value):
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def session_is_live(db, claims: dict) -> bool:
    """The checks get_current_user makes, as one answer. `claims` come from session_claims."""
    from app.core.models import ActiveSession, TemporaryCredential, User
    from app.core.session_hash_utils import hash_session_token
    from app.services.auth_service import admin_locked, is_token_denylisted

    session_token = claims.get("session_token")
    try:
        user_id = uuid.UUID(str(claims.get("sub")))
    except ValueError:
        return False
    if not session_token or is_token_denylisted(session_token):
        return False
    now = datetime.now(timezone.utc)

    if not claims.get("is_temporary", False):
        row = db.query(ActiveSession.revoked).filter(
            ActiveSession.session_token == hash_session_token(session_token)).first()
        if row is None or row[0]:
            return False
    else:
        row = db.query(ActiveSession.last_activity, ActiveSession.temp_credential_id).filter(
            ActiveSession.session_token == hash_session_token(session_token),
            ActiveSession.is_active == True,  # noqa: E712
        ).first()
        if row is None:
            return False
        grace = int(os.getenv("TEMP_CRED_SESSION_GRACE_MINUTES", "65"))
        last_activity = _aware(row[0])
        if last_activity is not None and last_activity < now - timedelta(minutes=grace):
            return False
        cred = db.query(TemporaryCredential.is_active, TemporaryCredential.slot_released_at,
                        TemporaryCredential.deactivate_at, TemporaryCredential.expires_at).filter(
            TemporaryCredential.id == row[1]).first()
        if cred is None or not cred[0] or cred[1] is not None:
            return False
        for limit in (cred[2], cred[3]):
            if limit is not None and now > _aware(limit):
                return False

    user = db.query(User.is_active, User.is_locked, User.locked_until).filter(User.id == user_id).first()
    if user is None or not user.is_active or admin_locked(user):
        return False
    return True


def _ask_database(claims: dict) -> bool:
    from app.core.database import SessionLocal
    db = SessionLocal()
    try:
        return session_is_live(db, claims)
    finally:
        db.close()


class _Answers:
    """Recent answers per session, for CACHE_SECONDS. Touched only on the event loop."""

    def __init__(self, seconds=CACHE_SECONDS, max_entries=CACHE_MAX_ENTRIES, clock=time.monotonic):
        self.seconds, self.max_entries, self.clock = seconds, max_entries, clock
        self._entries = {}

    def get(self, key):
        entry = self._entries.get(key)
        if entry is None:
            return None
        answer, until = entry
        if self.clock() >= until:
            del self._entries[key]
            return None
        return answer

    def put(self, key, answer):
        if len(self._entries) >= self.max_entries:
            now = self.clock()
            for k in [k for k, (_a, until) in self._entries.items() if until <= now]:
                del self._entries[k]
            while len(self._entries) >= self.max_entries:
                del self._entries[next(iter(self._entries))]   # the oldest first
        self._entries[key] = (answer, self.clock() + self.seconds)

    def clear(self):
        self._entries.clear()

    def __len__(self):
        return len(self._entries)


answers = _Answers()


async def caller_state(authorization: Optional[bytes], ask=None) -> str:
    """NO_CREDENTIAL, LIVE, ENDED or UNKNOWN for a request's Authorization header (see the module
    docstring). `ask(claims) -> bool` runs in a worker thread; it defaults to the database."""
    if bearer_token(authorization) is None:
        return NO_CREDENTIAL
    claims = session_claims(authorization)
    if claims is None:
        return ENDED
    key = (str(claims.get("sub")), str(claims.get("session_token")), bool(claims.get("is_temporary", False)))
    cached = answers.get(key)
    if cached is not None:
        return cached
    from starlette.concurrency import run_in_threadpool
    try:
        live = await run_in_threadpool(ask or _ask_database, claims)
    except Exception:  # noqa: BLE001 -- the database could not say; never cached
        return UNKNOWN
    state = LIVE if live else ENDED
    answers.put(key, state)
    return state
