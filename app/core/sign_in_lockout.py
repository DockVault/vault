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

Each attempt is counted BEFORE its password is checked (reserve): it takes one failure on both counts,
under the account-wide row's lock, and gives it back if the password was right (give_back). An attempt
that finds a count already at its limit, attempts still being checked included, is refused without its
password being checked. So however many attempts arrive at once, from however many addresses, through
the web and SFTP together, no more than the backstop number of passwords are checked for an account in
about 24 hours, nor more than the login limit from one address before its lock. (Counted after the
check, every attempt in flight while the count was below the backstop had its password checked: SFTP's
parallel connections alone came to about 2,000 guesses a day.) The locks themselves are armed after a
wrong password (arm_after_failure), so a right one never records a lock it did not cause.

The cost of the budget, accepted: one failed sign-in about every 24 h / backstop (72 minutes by
default) is enough to keep new sign-ins to an account paused for everyone, its owner included. Sessions
already signed in, devices and temporary credentials keep working throughout, and an administrator's
unlock clears the pause.

What a lock does, and does not do:
  * it refuses new sign-ins (a web password, an SFTP password, an SFTP key) BEFORE the password is
    checked, so while it lasts nobody can go on guessing from where it applies;
  * it never ends a session already signed in, never stops a device syncing or a temporary
    credential, and never takes the account's links down. All of those follow only an
    administrator's lock (users.is_locked with no end time), which nothing here sets;
  * it ends by itself: at the first sign-in attempt after its time runs out, or at the periodic
    release. Arming and releasing are audited as account_auto_locked and account_auto_unlocked, each
    with its scope (the address, or account-wide). An administrator's unlock clears it at once.

Names that are no account are counted the same way in the cache (the "phantom" functions), with the
same counts and the same lock timing, before the stand-in password check and one attempt after another
(phantom_reserve), so being refused, and for how long, tells nobody whether an account by that name
exists, however many attempts arrive at once. That mimicry fails open: while the cache is down, an
unknown name is simply never refused by it.

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


def _account_row(db, user_id, now) -> SignInLockout:
    """The account-wide count's row, made at nought if there is none, taken FOR UPDATE: every attempt on
    one account, from any address, queues on it, so they are counted one after another."""
    tbl = SignInLockout.__table__
    db.execute(_insert(db)(tbl).values(id=uuid.uuid4(), user_id=user_id, source=ACCOUNT_WIDE, failed_attempts=0,
                                       window_start=now, last_failure_at=now)
               .on_conflict_do_nothing(index_elements=[tbl.c.user_id, tbl.c.source]))
    return (db.query(SignInLockout)
            .filter(SignInLockout.user_id == user_id, SignInLockout.source == ACCOUNT_WIDE)
            .with_for_update().populate_existing().one())


def _count_account_wide(db, user_id, limit, now) -> SignInLockout:
    """Add one failure to the account-wide count, after what it lost since the last one (decayed), and
    return its row. The count never goes past ``limit``, so once a lock it armed has ended it falls
    below the limit again one interval later. The row is taken FOR UPDATE, so failures from many
    addresses at once are counted one after another. window_start is the moment the count last lost a
    failure, or started."""
    row = _account_row(db, user_id, now)
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


def _pause_until(until, since, backstop):
    """When an account-wide pause armed now ends: the lockout duration, or until the count has lost a
    failure if that is later. A pause that ended while the count was still full would let one more guess
    through every lockout duration (96 a day with the defaults) instead of one every 24 h / backstop.
    None: no end (a lockout duration of 0)."""
    return None if until is None else max(until, since + account_interval(backstop))


def _arm(db, user, address, source, row, account, *, threshold, backstop, until, now) -> list:
    """Arm the locks whose counts have reached their limit and are not already in force, recording
    account_auto_locked for each. ``row`` is the address's count (None: none), ``account`` the
    account-wide row with its count already decayed. Returns the locks armed."""
    armed = []
    if row is not None and row.failed_attempts >= threshold and not _in_force(row.locked_at, row.locked_until, now):
        tbl = SignInLockout.__table__
        db.execute(update(tbl).where(tbl.c.id == row.id).values(locked_at=now, locked_until=until))
        db.add(_audit_row(db, AUTO_LOCKED_ACTION, user, address, {
            "scope": SCOPE_ADDRESS, "failed_attempts": row.failed_attempts,
            "locked_until": until.isoformat() if until else None, "address": source}))
        armed.append(Lock(SCOPE_ADDRESS, until, source))

    if account.failed_attempts >= backstop and not _in_force(account.locked_at, account.locked_until, now):
        account_until = _pause_until(until, account.window_start, backstop)
        account.locked_at, account.locked_until = now, account_until
        db.add(_audit_row(db, AUTO_LOCKED_ACTION, user, address, {
            "scope": SCOPE_ACCOUNT, "failed_attempts": account.failed_attempts,
            "locked_until": account_until.isoformat() if account_until else None}))
        armed.append(Lock(SCOPE_ACCOUNT, account_until, ACCOUNT_WIDE))
    return armed


def record_failure(db, user, address, *, now=None) -> list:
    """Count one wrong password for ``user`` from ``address``, against the address and the account.
    A count that reaches its limit arms that lock and records account_auto_locked, in the caller's
    transaction. Returns the locks this failure armed.

    For a failure nothing reserved. A sign-in counts its attempt before the check (reserve) and, when
    the password was wrong, arms with arm_after_failure instead."""
    threshold, backstop, _window, minutes = limits()
    now = now or utcnow()
    until = now + timedelta(minutes=minutes) if minutes > 0 else None
    source = source_of(address)
    # Both counts first, the audit rows after: the rows are added to the caller's transaction and
    # written by its commit, with nothing flushed ahead of it. The account-wide row is taken first, as
    # reserve takes it, so the two never wait on each other in opposite orders.
    account = _count_account_wide(db, user.id, backstop, now)
    row = _count(db, user.id, source, now)
    return _arm(db, user, address, source, row, account, threshold=threshold, backstop=backstop,
                until=until, now=now)


def _address_row(db, user_id, source):
    return (db.query(SignInLockout)
            .filter(SignInLockout.user_id == user_id, SignInLockout.source == source)
            .populate_existing().first())


def reserve(db, user, address, *, now=None) -> Optional[Lock]:
    """Count one failure for a sign-in attempt BEFORE its password is checked, on the address's count and
    the account-wide one, in the caller's transaction. The caller commits at once, so the next attempt
    sees it and the account-wide row's lock is let go before the (slow) password check; then it gives
    the failure back if the password was right (give_back), or arms the locks if it was wrong
    (arm_after_failure).

    Returns the lock refusing the attempt, counting nothing, when there is no room: a lock in force, or a
    count already at its limit with attempts still being checked (refused as the lock the next failure
    would arm). None when the attempt may have its password checked. Taken under the account-wide row's
    lock, so of any number of attempts at once no more than the room left get through."""
    threshold, backstop, _window, minutes = limits()
    now = now or utcnow()
    until = now + timedelta(minutes=minutes) if minutes > 0 else None
    source = source_of(address)
    account = _account_row(db, user.id, now)
    if _in_force(account.locked_at, account.locked_until, now):
        return Lock(SCOPE_ACCOUNT, account.locked_until, ACCOUNT_WIDE)
    count, since = decayed(account.failed_attempts, account.window_start, backstop, now)
    if count >= backstop:
        return Lock(SCOPE_ACCOUNT, _pause_until(until, since, backstop), ACCOUNT_WIDE)
    row = _address_row(db, user.id, source)
    if row is not None and _in_force(row.locked_at, row.locked_until, now):
        return Lock(SCOPE_ADDRESS, row.locked_until, source)
    if row is not None and row.locked_at is None and row.failed_attempts >= threshold:
        return Lock(SCOPE_ADDRESS, until, source)
    account.failed_attempts, account.window_start, account.last_failure_at = count + 1, since, now
    db.flush()
    _count(db, user.id, source, now)
    return None


def arm_after_failure(db, user, address, *, now=None) -> list:
    """The password of an attempt reserve() counted was wrong: its failure is counted already. Arm the
    locks its counts have reached, recording account_auto_locked, in the caller's transaction. Returns
    the locks armed."""
    threshold, backstop, _window, minutes = limits()
    now = now or utcnow()
    until = now + timedelta(minutes=minutes) if minutes > 0 else None
    source = source_of(address)
    account = _account_row(db, user.id, now)
    count, since = decayed(account.failed_attempts, account.window_start, backstop, now)
    account.failed_attempts, account.window_start, account.last_failure_at = count, since, now
    db.flush()
    return _arm(db, user, address, source, _address_row(db, user.id, source), account,
                threshold=threshold, backstop=backstop, until=until, now=now)


def give_back(db, user_id, address, *, now=None) -> None:
    """The password of an attempt reserve() counted was right: give back the failure it counted, on the
    account-wide count and the address's, in the caller's transaction. A lock that other attempts'
    failures armed meanwhile stays, and so does the address count such a lock holds."""
    _threshold, backstop, _window, _minutes = limits()
    now = now or utcnow()
    account = (db.query(SignInLockout)
               .filter(SignInLockout.user_id == user_id, SignInLockout.source == ACCOUNT_WIDE)
               .with_for_update().populate_existing().first())
    if account is not None:
        count, since = decayed(account.failed_attempts, account.window_start, backstop, now)
        account.failed_attempts, account.window_start = max(0, count - 1), since
        db.flush()
    tbl = SignInLockout.__table__
    db.execute(update(tbl)
               .where(tbl.c.user_id == user_id, tbl.c.source == source_of(address),
                      tbl.c.locked_at.is_(None), tbl.c.failed_attempts > 0)
               .values(failed_attempts=tbl.c.failed_attempts - 1))


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
#
# A name that is no account is counted in the cache exactly as record_failure counts an account in
# sign_in_lockouts, and refused exactly as lock_in_force refuses it, so nothing an attempt can observe
# (being refused, the scope, when the refusal ends) tells whether an account by that name exists:
#   * per address: one more per failure, never expiring while it is used; at the limit a lock from
#     that failure for the lockout duration; the count ends with its lock, or a day after its last
#     failure (the periodic prune of an untouched address count);
#   * account-wide: the same decaying count, capped at the backstop, and the same pause, which lasts
#     the lockout duration or until the count has lost a failure;
#   * a lock whose time ran out is released at the next attempt (address: the count goes with it;
#     account-wide: the count stays), as release_expired does for an account.
# Each state is one small JSON value in the cache, kept as long as the database row would be. The
# mimicry fails open: while the cache cannot be read or written, a name that is no account is never
# refused by it.

PHANTOM_PREFIX = "login_phantom"
# How long a phantom lock with no end (a lockout duration of 0) is kept. An account's lasts until an
# administrator clears it, which nobody can do for a name that is no account.
PHANTOM_NO_END = timedelta(days=30)

_UNAVAILABLE = object()


def _to_ts(dt) -> float:
    return dt.replace(tzinfo=timezone.utc).timestamp()


def _from_ts(ts):
    return datetime.fromtimestamp(float(ts), timezone.utc).replace(tzinfo=None) if ts is not None else None


class _CacheStore:
    """The mimicry's state in Redis, behind the guard: get() returns the stored dict, None when there
    is none, or _UNAVAILABLE when the cache cannot be read."""

    def get(self, key):
        import json
        from app.core import redis_guard
        from app.core.database import redis_client
        raw = redis_guard.best_effort("sign_in_lockout.phantom_get", lambda: redis_client.get(key),
                                      default=_UNAVAILABLE)
        if raw is _UNAVAILABLE or raw is None:
            return raw
        try:
            value = json.loads(raw)
        except (TypeError, ValueError):
            return None
        return value if isinstance(value, dict) else None

    def set(self, key, value: dict, ttl_seconds: int) -> None:
        import json
        from app.core import redis_guard
        from app.core.database import redis_client
        redis_guard.best_effort("sign_in_lockout.phantom_set",
                                lambda: redis_client.set(key, json.dumps(value), ex=max(1, int(ttl_seconds))))

    # How long one attempt may hold a name while it is counted (a holder that dies lets go by then), and
    # how long another attempt waits for it.
    HOLD_MS = 2000
    WAIT_SECONDS = 2.0

    def hold(self, key):
        """Take ``key`` for one attempt, waiting up to WAIT_SECONDS while another attempt holds it: what
        the account-wide row's lock is to an account. Returns the token to let it go with, or None when
        it was not taken (the cache cannot be reached, or the wait ran out), and the attempt is counted
        without it: the mimicry fails open."""
        import secrets
        import time
        from app.core import redis_guard
        from app.core.database import redis_client
        token = secrets.token_hex(8)
        deadline = time.monotonic() + self.WAIT_SECONDS
        while True:
            taken = redis_guard.best_effort(
                "sign_in_lockout.phantom_hold",
                lambda: redis_client.set(key, token, nx=True, px=self.HOLD_MS), default=_UNAVAILABLE)
            if taken is _UNAVAILABLE:
                return None
            if taken:
                return token
            if time.monotonic() >= deadline:
                return None
            time.sleep(0.01)

    def release(self, key, token) -> None:
        """Let go of a hold taken with ``token``, and only that one. (Read, then deleted: a hold is kept
        for milliseconds and lapses after HOLD_MS, so another attempt's hold is never in between.)"""
        from app.core import redis_guard
        from app.core.database import redis_client

        def _release():
            held = redis_client.get(key)
            if held is not None and (held.decode() if isinstance(held, bytes) else held) == token:
                redis_client.delete(key)

        redis_guard.best_effort("sign_in_lockout.phantom_release", _release)


def _phantom_store():
    return _CacheStore()


def _phantom_keys(identifier, address):
    """The cache keys for a name from an address, and from everywhere. The name is kept as its keyed
    stand-in, never as typed (app/core/name_keys.py)."""
    from app.core.name_keys import name_key
    name = name_key(identifier)
    return (f"{PHANTOM_PREFIX}:{source_of(address)}|{name}", f"{PHANTOM_PREFIX}:{ACCOUNT_WIDE}|{name}")


def _phantom_in_force(state, now) -> bool:
    if not state or not state.get("locked"):
        return False
    until = _from_ts(state.get("until"))
    return until is None or until > now


def _phantom_ended(state, now) -> bool:
    """A lock that ran out, which release_expired would clear at this attempt."""
    return bool(state) and bool(state.get("locked")) and not _phantom_in_force(state, now)


def phantom_failure(identifier, address, *, now=None) -> None:
    """Count a wrong sign-in for a name that is no account, the way record_failure counts one for an
    account (see the section comment above). Best-effort: never raises."""
    try:
        threshold, backstop, _window, minutes = limits()
        now = now or utcnow()
        until = now + timedelta(minutes=minutes) if minutes > 0 else None
        store = _phantom_store()
        by_address, account_wide = _phantom_keys(identifier, address)

        state = store.get(by_address)
        if state is _UNAVAILABLE:
            return
        if _phantom_ended(state, now):
            state = None                          # the count ended with its lock
        if _phantom_in_force(state, now):
            new = dict(state)                     # refused before counting, as an account is
        else:
            new = {"n": int((state or {}).get("n", 0)) + 1}
            if new["n"] >= threshold:
                new.update(locked=True, until=_to_ts(until) if until else None)
        if new.get("locked") and new.get("until") is None:
            ttl = PHANTOM_NO_END
        elif new.get("locked"):
            ttl = (_from_ts(new["until"]) - now) + STALE_ADDRESS_COUNT
        else:
            ttl = STALE_ADDRESS_COUNT
        store.set(by_address, new, ttl.total_seconds())

        state = store.get(account_wide)
        if state is _UNAVAILABLE:
            return
        state = dict(state or {})
        if _phantom_ended(state, now):
            state.update(locked=False, until=None)  # the pause ends; the count stays
        if _phantom_in_force(state, now):
            new = state
            since = _from_ts(state.get("since")) or now
        else:
            count, since = decayed(int(state.get("n", 0)), _from_ts(state.get("since")), backstop, now)
            new = {"n": min(int(backstop), count + 1), "since": _to_ts(since)}
            if new["n"] >= backstop:
                account_until = None if until is None else max(until, since + account_interval(backstop))
                new.update(locked=True, until=_to_ts(account_until) if account_until else None)
        if new.get("locked") and new.get("until") is None:
            ttl = PHANTOM_NO_END
        else:
            ends = since + ACCOUNT_PERIOD
            if new.get("locked"):
                ends = max(ends, _from_ts(new["until"]))
            ttl = ends - now
        store.set(account_wide, new, max(ttl.total_seconds(), 1))
    except Exception:  # noqa: BLE001 - the mimicry is best-effort
        pass


def phantom_lock(identifier, address, *, now=None) -> Optional[Lock]:
    """The lock a name that is no account is refused with: the account-wide one if in force, else the
    address's, as lock_in_force answers for an account. None when neither is, or when the cache cannot
    be read."""
    try:
        now = now or utcnow()
        store = _phantom_store()
        by_address, account_wide = _phantom_keys(identifier, address)
        for key, scope, source in ((account_wide, SCOPE_ACCOUNT, ACCOUNT_WIDE),
                                   (by_address, SCOPE_ADDRESS, source_of(address))):
            state = store.get(key)
            if state is _UNAVAILABLE:
                return None
            if _phantom_in_force(state, now):
                return Lock(scope, _from_ts(state.get("until")), source)
    except Exception:  # noqa: BLE001 - fail open: never refused by the mimicry while the cache is down
        return None
    return None


def phantom_reserve(identifier, address, *, now=None) -> Optional[Lock]:
    """What reserve() is for an account, for a name that is no account: refused as phantom_lock refuses
    it, or else counted as phantom_failure counts a failure, BEFORE the stand-in password check. Both
    happen under one hold on the name in the cache (the account-wide row's lock, for an account), so
    attempts arriving at once are counted one after another and meet the refusal at the same count as
    an account's would. Returns the refusing lock, or None. Best-effort: never raises, and fails open."""
    store = _phantom_store()
    key = token = None
    try:
        from app.core.name_keys import name_key
        hold = getattr(store, "hold", None)
        if hold is not None:
            key = f"{PHANTOM_PREFIX}:hold|{name_key(identifier)}"
            token = hold(key)
        lock = phantom_lock(identifier, address, now=now)
        if lock is None:
            phantom_failure(identifier, address, now=now)
        return lock
    except Exception:  # noqa: BLE001 - the mimicry is best-effort
        return None
    finally:
        if token is not None:
            try:
                store.release(key, token)
            except Exception:  # noqa: BLE001
                pass
