"""Smart lockout: wrong passwords lock an account against new sign-ins from the address they came from,
and past a higher count across every address, from anywhere.

Counting, on every wrong password for an account:
  * one against the account from its source address (an IPv6 address counts as its /64, one site's
    network, since whoever holds one can use billions of addresses in it). When that count reaches the
    login limit (max_login_attempts), new sign-ins to the account FROM THAT ADDRESS are refused for the
    lockout duration. The count ends at a successful sign-in from the address, or when the lock it
    armed runs out;
  * one against the account as a whole, from every address together. That count holds about the last
    24 hours: it loses one failure every 24 h / backstop, where the backstop is the limit times the
    backstop multiple (lockout_backstop_multiplier; 5 x 4 = 20 by default, so one every 72 minutes).
    When it reaches the backstop, new sign-ins to the account from EVERY address are refused for the
    lockout duration, or until the count has lost a failure if that is later: the answer to many
    addresses guessing at once. The count does not end with that lock, so while it is still full each
    further failure refuses them again. An account therefore gets at most the backstop number of failed
    sign-ins from all addresses together per 24 hours before new sign-ins pause for everyone, and one
    more per 24 h / backstop after that. (Counted within the
    5-minute login window instead, guessers using four or more addresses could go on for ever without
    arming it: some 5,500 guesses a day.)

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
import ipaddress
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, NamedTuple, Optional

from sqlalchemy import update

from app.core.models import SignInLockout, User

ACCOUNT_WIDE = "*"
SCOPE_ADDRESS = "address"
SCOPE_ACCOUNT = "account"

AUTO_LOCKED_ACTION = "account_auto_locked"
AUTO_UNLOCKED_ACTION = "account_auto_unlocked"

# An address's count holds no lock and is not time-limited, but one untouched for this long is
# dropped by the periodic prune: a few mistakes last week should not count against someone today.
STALE_ADDRESS_COUNT = timedelta(days=1)

# The account-wide count holds the failures of about this long: it loses one every ACCOUNT_PERIOD /
# backstop (see the module docstring).
ACCOUNT_PERIOD = timedelta(hours=24)


class Lock(NamedTuple):
    scope: str                          # SCOPE_ADDRESS or SCOPE_ACCOUNT
    locked_until: Optional[datetime]    # naive UTC; None: until an administrator clears it
    source: str


def utcnow() -> datetime:
    """Now as these columns store it: UTC with no time zone attached."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def source_of(address) -> str:
    """The source a count is kept under: the client address, with an IPv6 address grouped to its /64
    (an IPv4 address written as IPv6 counts as the IPv4 one). Anything that is not an address is kept as
    given, bounded to the column."""
    if not address:
        return "unknown"
    text = str(address).strip()
    try:
        ip = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return text[:64]
    if ip.version == 6:
        if ip.ipv4_mapped is not None:
            return str(ip.ipv4_mapped)
        return str(ipaddress.IPv6Network((int(ip) >> 64 << 64, 64)))
    return str(ip)


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


def _count(db, user_id, source, now):
    """Add one failure to an address's count in one statement and return the row as it now stands."""
    tbl = SignInLockout.__table__
    stmt = _insert(db)(tbl).values(id=uuid.uuid4(), user_id=user_id, source=source, failed_attempts=1,
                                   window_start=now, last_failure_at=now)
    set_ = {"failed_attempts": tbl.c.failed_attempts + 1, "last_failure_at": now}
    stmt = stmt.on_conflict_do_update(index_elements=[tbl.c.user_id, tbl.c.source], set_=set_).returning(
        tbl.c.id, tbl.c.failed_attempts, tbl.c.locked_at, tbl.c.locked_until)
    return db.execute(stmt).first()


def account_interval(limit) -> timedelta:
    """How often the account-wide count loses one failure: ACCOUNT_PERIOD / the backstop."""
    return ACCOUNT_PERIOD / max(1, int(limit))


def decayed(count, since, limit, now):
    """(count, since) after the account-wide count has lost one failure every account_interval(limit)
    since ``since``: the moment it last lost one, or started. A count that is all gone starts again
    now."""
    interval = account_interval(limit).total_seconds()
    elapsed = (now - since).total_seconds() if since is not None else 0.0
    lost = int(elapsed // interval) if elapsed > 0 else 0
    if lost >= (count or 0):
        return 0, now
    return count - lost, since + timedelta(seconds=lost * interval)


def _count_account_wide(db, user_id, limit, now) -> SignInLockout:
    """Add one failure to the account-wide count, after what it lost since the last one (decayed), and
    return its row. The count never goes past ``limit``, so once a lock it armed has ended it falls
    below the limit again one interval later. The row is taken FOR UPDATE, so failures from many
    addresses at once are counted one after another. window_start is the moment the count last lost a
    failure, or started."""
    tbl = SignInLockout.__table__
    db.execute(_insert(db)(tbl).values(id=uuid.uuid4(), user_id=user_id, source=ACCOUNT_WIDE, failed_attempts=0,
                                       window_start=now, last_failure_at=now)
               .on_conflict_do_nothing(index_elements=[tbl.c.user_id, tbl.c.source]))
    row = (db.query(SignInLockout)
           .filter(SignInLockout.user_id == user_id, SignInLockout.source == ACCOUNT_WIDE)
           .with_for_update().populate_existing().one())
    count, since = decayed(row.failed_attempts, row.window_start, limit, now)
    row.failed_attempts = min(int(limit), count + 1)
    row.window_start = since
    row.last_failure_at = now
    db.flush()
    return row


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
    threshold, backstop, _window, minutes = limits()
    now = now or utcnow()
    until = now + timedelta(minutes=minutes) if minutes > 0 else None
    armed = []
    source = source_of(address)
    # Both counts first, the audit rows after: the rows are added to the caller's transaction and
    # written by its commit, with nothing flushed ahead of it.
    row = _count(db, user.id, source, now)
    account = _count_account_wide(db, user.id, backstop, now)

    if row is not None and row.failed_attempts >= threshold and not _in_force(row.locked_at, row.locked_until, now):
        tbl = SignInLockout.__table__
        db.execute(update(tbl).where(tbl.c.id == row.id).values(locked_at=now, locked_until=until))
        db.add(_audit_row(db, AUTO_LOCKED_ACTION, user, address, {
            "scope": SCOPE_ADDRESS, "failed_attempts": row.failed_attempts,
            "locked_until": until.isoformat() if until else None, "address": source}))
        armed.append(Lock(SCOPE_ADDRESS, until, source))

    if account.failed_attempts >= backstop and not _in_force(account.locked_at, account.locked_until, now):
        # The pause lasts the lockout duration, or until the count has lost a failure if that is later:
        # a pause that ended while the count was still full would let one more guess through every
        # lockout duration (96 a day with the defaults) instead of one every 24 h / backstop.
        account_until = None if until is None else max(until, account.window_start + account_interval(backstop))
        account.locked_at, account.locked_until = now, account_until
        db.add(_audit_row(db, AUTO_LOCKED_ACTION, user, address, {
            "scope": SCOPE_ACCOUNT, "failed_attempts": account.failed_attempts,
            "locked_until": account_until.isoformat() if account_until else None}))
        armed.append(Lock(SCOPE_ACCOUNT, account_until, ACCOUNT_WIDE))
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
    LOCKED, so the two never both record one release. A lock with no end is never touched. An
    address's count ends with its lock; the account-wide count stays, so that until it has lost a
    failure (decayed) the next failure refuses new sign-ins again. Returns how many were cleared."""
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
        if r.source == ACCOUNT_WIDE:
            r.locked_at = None
            r.locked_until = None
        else:
            db.delete(r)
    return len(expired)


def prune_stale(db, *, now=None) -> int:
    """Drop counts that hold no lock and have nothing left to count: an account-wide count that has
    lost every failure (it holds at most the backstop, and loses all of them within ACCOUNT_PERIOD of
    window_start), and an address count untouched for a day. Keeps the table small."""
    now = now or utcnow()
    tbl = SignInLockout
    removed = db.query(tbl).filter(tbl.locked_at.is_(None), tbl.source == ACCOUNT_WIDE,
                                   tbl.window_start < now - ACCOUNT_PERIOD).delete(synchronize_session=False)
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
