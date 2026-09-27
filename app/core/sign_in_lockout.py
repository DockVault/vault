"""Smart lockout: wrong passwords lock an account against new sign-ins from the address they came from,
and past a higher count across every address, from anywhere.

Counting, on every wrong password for an account:
  * one against the account from its source address. When that count reaches the login limit
    (max_login_attempts), new sign-ins to the account FROM THAT ADDRESS are refused for the lockout
    duration. The count ends at a successful sign-in from the address, or when the lock it armed runs
    out;
  * one against the account as a whole. When that count reaches the limit times the backstop multiple
    (lockout_backstop_multiplier) within the login window, new sign-ins to the account from EVERY
    address are refused for the lockout duration: the answer to many addresses guessing at once.

What a lock does, and does not do:
  * it refuses new sign-ins (a web password, an SFTP password, an SFTP key) BEFORE the password is
    checked, so while it lasts nobody can go on guessing from where it applies;
  * it never ends a session already signed in, never stops a device syncing or a temporary
    credential, and never takes the account's links down. All of those follow only an
    administrator's lock (users.is_locked with no end time), which nothing here sets;
  * it ends by itself: at the first sign-in attempt after its time runs out, or at the periodic
    release. Arming and releasing are audited as account_auto_locked and account_auto_unlocked, each
    with its scope (the address, or account-wide). An administrator's unlock clears it at once.

Names that are no account are counted the same way in the cache (the "phantom" functions), so being
refused tells nobody whether an account by that name exists. That mimicry fails open: while the cache
is down, an unknown name is simply never refused by it.

Nothing here commits: the caller's transaction carries each count, lock and audit row.
"""
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, NamedTuple, Optional

from sqlalchemy import and_, case, update

from app.core.models import SignInLockout, User

ACCOUNT_WIDE = "*"
SCOPE_ADDRESS = "address"
SCOPE_ACCOUNT = "account"

AUTO_LOCKED_ACTION = "account_auto_locked"
AUTO_UNLOCKED_ACTION = "account_auto_unlocked"

# An address's count holds no lock and is not time-limited, but one untouched for this long is
# dropped by the periodic prune: a few mistakes last week should not count against someone today.
STALE_ADDRESS_COUNT = timedelta(days=1)


class Lock(NamedTuple):
    scope: str                          # SCOPE_ADDRESS or SCOPE_ACCOUNT
    locked_until: Optional[datetime]    # naive UTC; None: until an administrator clears it
    source: str


def utcnow() -> datetime:
    """Now as these columns store it: UTC with no time zone attached."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def source_of(address) -> str:
    """The address a count is kept under (the column is bounded)."""
    return (str(address) if address else "unknown")[:64]


def limits():
    """(address limit, account-wide limit, window in seconds, lock minutes), as configured now."""
    from app.core import rate_limit_settings as rl
    threshold = int(rl.effective("max_login_attempts"))
    return (threshold, threshold * int(rl.effective("lockout_backstop_multiplier")),
            int(rl.effective("rate_limit_login_window_seconds")), int(rl.effective("lockout_duration")))


def _insert(db):
    if db.get_bind().dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:
        from sqlalchemy.dialects.sqlite import insert
    return insert


def _count(db, user_id, source, now, window_seconds=None):
    """Add one failure to (user_id, source) in one statement and return the row as it now stands.
    With a window, a count that holds no lock and whose window has passed starts again at 1."""
    tbl = SignInLockout.__table__
    stmt = _insert(db)(tbl).values(id=uuid.uuid4(), user_id=user_id, source=source, failed_attempts=1,
                                   window_start=now, last_failure_at=now)
    if window_seconds:
        stale = and_(tbl.c.window_start < now - timedelta(seconds=window_seconds), tbl.c.locked_at.is_(None))
        set_ = {"failed_attempts": case((stale, 1), else_=tbl.c.failed_attempts + 1),
                "window_start": case((stale, now), else_=tbl.c.window_start),
                "last_failure_at": now}
    else:
        set_ = {"failed_attempts": tbl.c.failed_attempts + 1, "last_failure_at": now}
    stmt = stmt.on_conflict_do_update(index_elements=[tbl.c.user_id, tbl.c.source], set_=set_).returning(
        tbl.c.id, tbl.c.failed_attempts, tbl.c.locked_at, tbl.c.locked_until)
    return db.execute(stmt).first()


def _in_force(locked_at, locked_until, now) -> bool:
    return locked_at is not None and (locked_until is None or locked_until > now)


def _audit_row(db, action, user, ip_address, details):
    from app.services.audit_logger import AuditLogger
    return AuditLogger(db).build_row(
        action=action, status="success", user_id=user.id, username=user.username,
        resource_type="user", resource_id=str(user.id), ip_address=ip_address, details=details)


def record_failure(db, user, address, *, now=None) -> list:
    """Count one wrong password for ``user`` from ``address``, against the address and the account.
    A count that reaches its limit arms that lock and records account_auto_locked, in the caller's
    transaction. Returns the locks this failure armed."""
    threshold, backstop, window, minutes = limits()
    now = now or utcnow()
    until = now + timedelta(minutes=minutes) if minutes > 0 else None
    armed = []
    for source, limit, count_window, scope in ((source_of(address), threshold, None, SCOPE_ADDRESS),
                                               (ACCOUNT_WIDE, backstop, window, SCOPE_ACCOUNT)):
        row = _count(db, user.id, source, now, count_window)
        if row is None or row.failed_attempts < limit or _in_force(row.locked_at, row.locked_until, now):
            continue
        tbl = SignInLockout.__table__
        db.execute(update(tbl).where(tbl.c.id == row.id).values(locked_at=now, locked_until=until))
        details = {"scope": scope, "failed_attempts": row.failed_attempts,
                   "locked_until": until.isoformat() if until else None}
        if scope == SCOPE_ADDRESS:
            details["address"] = source
        db.add(_audit_row(db, AUTO_LOCKED_ACTION, user, address, details))
        armed.append(Lock(scope, until, source))
    return armed


def lock_in_force(db, user_id, address, *, now=None) -> Optional[Lock]:
    """The automatic lock refusing a new sign-in to this account from this address right now: the
    account-wide one if it is in force, else the address's own; None when neither is."""
    now = now or utcnow()
    rows = (db.query(SignInLockout)
            .filter(SignInLockout.user_id == user_id,
                    SignInLockout.source.in_([ACCOUNT_WIDE, source_of(address)]),
                    SignInLockout.locked_at.isnot(None))
            .all())
    live = [r for r in rows if _in_force(r.locked_at, r.locked_until, now)]
    if not live:
        return None
    r = next((r for r in live if r.source == ACCOUNT_WIDE), live[0])
    return Lock(SCOPE_ACCOUNT if r.source == ACCOUNT_WIDE else SCOPE_ADDRESS, r.locked_until, r.source)


def clear_after_success(db, user_id, address) -> None:
    """A successful sign-in from an address ends that address's count. The account-wide count is
    left to run out: the owner signing in does not cancel failures from elsewhere."""
    db.query(SignInLockout).filter(SignInLockout.user_id == user_id,
                                   SignInLockout.source == source_of(address),
                                   SignInLockout.locked_at.is_(None)).delete(synchronize_session=False)


def release_expired(db, *, user_id=None, ip_address=None, now=None) -> int:
    """Clear the automatic locks whose time has run out, recording each as account_auto_unlocked with
    its scope, in the caller's transaction. The periodic release passes no ``user_id``; a sign-in
    passes the account and its address, which the row carries. Rows are claimed FOR UPDATE SKIP
    LOCKED, so the two never both record one release. A lock with no end is never touched. Returns
    how many were cleared."""
    now = now or utcnow()
    q = db.query(SignInLockout).filter(SignInLockout.locked_at.isnot(None),
                                       SignInLockout.locked_until.isnot(None),
                                       SignInLockout.locked_until <= now)
    if user_id is not None:
        q = q.filter(SignInLockout.user_id == user_id)
    expired = q.with_for_update(skip_locked=True).all()
    if not expired:
        return 0
    users = {u.id: u for u in db.query(User).filter(User.id.in_({r.user_id for r in expired})).all()}
    for r in expired:
        user = users.get(r.user_id)
        if user is not None:
            details = {"scope": SCOPE_ACCOUNT if r.source == ACCOUNT_WIDE else SCOPE_ADDRESS,
                       "locked_until": r.locked_until.isoformat(), "failed_attempts": r.failed_attempts,
                       "cleared_by": "timer" if user_id is None else "sign_in"}
            if r.source != ACCOUNT_WIDE:
                details["address"] = r.source
            db.add(_audit_row(db, AUTO_UNLOCKED_ACTION, user, ip_address, details))
        db.delete(r)
    return len(expired)


def prune_stale(db, *, now=None) -> int:
    """Drop counts that hold no lock and have nothing left to count: an account-wide count whose
    window has passed, and an address count untouched for a day. Keeps the table small."""
    now = now or utcnow()
    _t, _b, window, _m = limits()
    tbl = SignInLockout
    removed = db.query(tbl).filter(tbl.locked_at.is_(None), tbl.source == ACCOUNT_WIDE,
                                   tbl.window_start < now - timedelta(seconds=window)).delete(synchronize_session=False)
    removed += db.query(tbl).filter(tbl.locked_at.is_(None), tbl.source != ACCOUNT_WIDE,
                                    tbl.last_failure_at < now - STALE_ADDRESS_COUNT).delete(synchronize_session=False)
    return removed


def clear_for_user(db, user_id) -> int:
    """An administrator's unlock: every count and automatic lock on the account goes. Returns how many
    automatic locks were in force."""
    now = utcnow()
    rows = db.query(SignInLockout).filter(SignInLockout.user_id == user_id).all()
    in_force = sum(1 for r in rows if _in_force(r.locked_at, r.locked_until, now))
    for r in rows:
        db.delete(r)
    return in_force


def blocks_by_user(db, user_ids: Iterable, *, now=None) -> Dict:
    """{account id: {scope, addresses, until}} for the accounts with an automatic lock in force, in
    one query: what the Users page shows. ``until`` is the latest end (None: no end)."""
    ids = list(user_ids)
    if not ids:
        return {}
    now = now or utcnow()
    out: Dict = {}
    for r in db.query(SignInLockout).filter(SignInLockout.user_id.in_(ids),
                                            SignInLockout.locked_at.isnot(None)).all():
        if not _in_force(r.locked_at, r.locked_until, now):
            continue
        b = out.setdefault(r.user_id, {"scope": SCOPE_ADDRESS, "addresses": 0, "until": r.locked_until,
                                       "_no_end": False})
        if r.source == ACCOUNT_WIDE:
            b["scope"] = SCOPE_ACCOUNT
        else:
            b["addresses"] += 1
        if r.locked_until is None:
            b["_no_end"] = True
        elif b["until"] is not None and r.locked_until > b["until"]:
            b["until"] = r.locked_until
    for b in out.values():
        if b.pop("_no_end"):
            b["until"] = None
    return out


# --- Names that are no account ------------------------------------------------------------------

def _phantom_keys(identifier, address):
    return (f"login_phantom:{source_of(address)}|{identifier}", f"login_phantom:{ACCOUNT_WIDE}|{identifier}")


def phantom_failure(identifier, address) -> None:
    """Count a wrong sign-in for a name that is no account, the way record_failure counts one for an
    account, so that such a name is refused at the same point. Best-effort: never raises."""
    try:
        from app.core.rate_limiter import rate_limiter
        threshold, backstop, _window, minutes = limits()
        lock_seconds = minutes * 60 if minutes > 0 else 86400
        by_address, account_wide = _phantom_keys(identifier, address)
        # Both kept over the lock's length rather than the login window, so a name's refusal lasts
        # about as long as an account's lock would after a burst of failures.
        rate_limiter.check_rate_limit(by_address, threshold, lock_seconds, fail_open=True)
        rate_limiter.check_rate_limit(account_wide, backstop, lock_seconds, fail_open=True)
    except Exception:  # noqa: BLE001 - the mimicry is best-effort
        pass


def phantom_lock(identifier, address, *, now=None) -> Optional[Lock]:
    """The lock a name that is no account is refused with, when its failures from this address (or
    from everywhere) have reached the limit an account's would. None when not, or when the cache
    cannot be read."""
    try:
        from app.core.rate_limiter import rate_limiter
        threshold, backstop, _window, minutes = limits()
        lock_seconds = minutes * 60 if minutes > 0 else 86400
        by_address, account_wide = _phantom_keys(identifier, address)
        now = now or utcnow()
        over, retry = rate_limiter.peek_rate_limit(account_wide, backstop, lock_seconds)
        if over:
            return Lock(SCOPE_ACCOUNT, now + timedelta(seconds=max(retry, 1)) if minutes > 0 else None,
                        ACCOUNT_WIDE)
        over, retry = rate_limiter.peek_rate_limit(by_address, threshold, lock_seconds)
        if over:
            return Lock(SCOPE_ADDRESS, now + timedelta(seconds=max(retry, 1)) if minutes > 0 else None,
                        source_of(address))
    except Exception:  # noqa: BLE001 - fail open: never refused by the mimicry while the cache is down
        return None
    return None
