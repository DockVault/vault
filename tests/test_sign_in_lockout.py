"""Smart lockout, offline, on a real database.

Wrong passwords count per account and source address, and across all addresses. At the login limit
new sign-ins to the account from THAT address are refused for the lockout duration; at the limit times
the backstop multiple, counted over about the last 24 hours, they are refused from EVERY address. A refusal happens
before the password is checked, so guessing stops. A lock never ends a session: only an
administrator's lock (users.is_locked with no end) does. Locks end by themselves and are audited
with their scope. Names that are no account are refused the same way, from the cache.

These run app/core/sign_in_lockout.py and AuthService.authenticate_user against the real users,
sign_in_lockouts and audit_logs tables in a throwaway SQLite database. test_smart_lockout_live.py
drives the same over the web and SFTP on a running stack.
"""
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import sign_in_lockout as L  # noqa: E402
from app.core.models import AuditLog, RoleEnum, SignInLockout, User  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.services import auth_service as A  # noqa: E402

pytestmark = pytest.mark.unit

THRESHOLD, MULTIPLE, WINDOW, MINUTES = 3, 2, 300, 15
HOME, CAFE, ATTACKER = "198.51.100.10", "198.51.100.20", "203.0.113.66"
PASSWORD = "right-password-123"


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


@pytest.fixture
def limits(monkeypatch):
    values = {"max_login_attempts": THRESHOLD, "lockout_backstop_multiplier": MULTIPLE,
              "rate_limit_login_window_seconds": WINDOW, "lockout_duration": MINUTES}
    monkeypatch.setattr(A.rate_limit_settings, "effective", lambda key: values[key])
    return values


@pytest.fixture
def Session():
    with tempfile.TemporaryDirectory() as tmp:
        # Attempts on one account take turns (sign_in_lockout.take_turn), here the database's write lock:
        # a long enough wait for it that a burst of slow checks queues rather than gives up.
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'lockout.db'}", connect_args={"timeout": 120})
        for model in (User, AuditLog, SignInLockout):
            model.__table__.create(engine)
        yield sessionmaker(bind=engine, autocommit=False, autoflush=False)
        engine.dispose()


def _add_user(Session, **kw):
    s = Session()
    u = User(username=kw.pop("username", f"u_{uuid.uuid4().hex[:8]}"), password_hash=hash_password(PASSWORD),
             role=RoleEnum.USER, **kw)
    s.add(u)
    s.commit()
    uid = u.id
    s.close()
    return uid


def _user(s, uid):
    return s.query(User).filter(User.id == uid).first()


def _fail(Session, uid, address):
    s = Session()
    try:
        A.AuthService(s)._record_failed_login("x", address, _user(s, uid))
    finally:
        s.close()


def _lock(Session, uid, address):
    s = Session()
    try:
        return L.lock_in_force(s, uid, address)
    finally:
        s.close()


def _audit(Session, action):
    s = Session()
    try:
        return s.query(AuditLog).filter(AuditLog.action == action).order_by(AuditLog.timestamp).all()
    finally:
        s.close()


def _sign_in(Session, uid, address, password=None):
    """authenticate_user with the throttle and the session machinery stubbed. The account's right
    password unless another is given."""
    password = password or PASSWORD
    s = Session()
    svc = A.AuthService(s)
    svc._check_rate_limit = lambda *a, **k: None
    svc._terminate_existing_sessions = lambda *a, **k: None
    svc._create_session = lambda *a, **k: "session-token"
    try:
        return svc.authenticate_user(_user(s, uid).username, password, address)
    finally:
        s.close()


# --------------------------------------------------------------------------- counting and arming

def test_failures_from_one_address_lock_only_that_address(Session, limits):
    uid = _add_user(Session)
    for _ in range(THRESHOLD - 1):
        _fail(Session, uid, ATTACKER)
    assert _lock(Session, uid, ATTACKER) is None, "below the limit nothing is locked"
    _fail(Session, uid, ATTACKER)

    lock = _lock(Session, uid, ATTACKER)
    assert (lock.scope, lock.source) == (L.SCOPE_ADDRESS, ATTACKER)
    assert _now() + timedelta(minutes=MINUTES - 1) < lock.locked_until < _now() + timedelta(minutes=MINUTES + 1)
    assert _lock(Session, uid, HOME) is None, "another address is not affected"

    (row,) = _audit(Session, L.AUTO_LOCKED_ACTION)
    assert row.user_id == uid and row.ip_address == ATTACKER
    assert row.details["scope"] == "address" and row.details["address"] == ATTACKER
    assert row.details["failed_attempts"] == THRESHOLD


def test_failures_from_many_addresses_lock_the_whole_account(Session, limits):
    uid = _add_user(Session)
    addresses = [f"203.0.113.{i}" for i in range(1, THRESHOLD * MULTIPLE + 1)]
    for addr in addresses[:-1]:
        _fail(Session, uid, addr)          # one each: no address reaches its own limit
    assert _lock(Session, uid, HOME) is None
    _fail(Session, uid, addresses[-1])

    lock = _lock(Session, uid, HOME)
    assert lock.scope == L.SCOPE_ACCOUNT, "the owner's own address is refused too"
    rows = [r for r in _audit(Session, L.AUTO_LOCKED_ACTION) if r.details["scope"] == "account"]
    assert len(rows) == 1 and "address" not in rows[0].details
    assert rows[0].details["failed_attempts"] == THRESHOLD * MULTIPLE


def _account_row(Session, uid):
    s = Session()
    try:
        row = s.query(SignInLockout).filter(SignInLockout.user_id == uid,
                                            SignInLockout.source == L.ACCOUNT_WIDE).one()
        return row.failed_attempts, row.window_start, row.locked_at
    finally:
        s.close()


def _age_account_count(Session, uid, by):
    s = Session()
    row = s.query(SignInLockout).filter(SignInLockout.user_id == uid, SignInLockout.source == L.ACCOUNT_WIDE).one()
    row.window_start = row.window_start - by
    s.commit()
    s.close()


INTERVAL = L.ACCOUNT_PERIOD / (THRESHOLD * MULTIPLE)     # the account-wide count loses one this often


def test_the_account_wide_count_outlasts_the_login_window(Session, limits):
    # The count used to start again once the 5-minute login window passed, so guessers using a few
    # addresses at a time never armed it. It now holds about a day.
    uid = _add_user(Session)
    for i in range(THRESHOLD * MULTIPLE - 1):
        _fail(Session, uid, f"203.0.113.{i}")
    _age_account_count(Session, uid, timedelta(seconds=WINDOW + 1))
    _fail(Session, uid, "203.0.113.200")
    assert _lock(Session, uid, HOME).scope == L.SCOPE_ACCOUNT


def test_the_account_wide_count_loses_one_failure_per_interval_and_is_gone_after_a_day(Session, limits):
    uid = _add_user(Session)
    for i in range(THRESHOLD * MULTIPLE - 1):
        _fail(Session, uid, f"203.0.113.{i}")
    _age_account_count(Session, uid, 2 * INTERVAL + timedelta(seconds=1))
    _fail(Session, uid, "203.0.113.200")                 # two lost, one added
    assert _lock(Session, uid, HOME) is None
    assert _account_row(Session, uid)[0] == THRESHOLD * MULTIPLE - 2
    _age_account_count(Session, uid, L.ACCOUNT_PERIOD)
    _fail(Session, uid, "203.0.113.201")
    assert _account_row(Session, uid)[0] == 1, "a day later every earlier failure is gone"


def test_while_the_account_wide_count_is_full_each_further_failure_pauses_sign_ins_again(Session, limits):
    uid = _add_user(Session)
    for i in range(THRESHOLD * MULTIPLE):
        _fail(Session, uid, f"203.0.113.{i}")
    s = Session()
    s.query(SignInLockout).update({"locked_until": _now() - timedelta(seconds=1)})
    s.commit()
    assert L.release_expired(s) == 1
    s.commit()
    s.close()
    count, _start, locked_at = _account_row(Session, uid)
    assert (count, locked_at) == (THRESHOLD * MULTIPLE, None), "the lock ends; the count does not"
    # (Ended early here: it lasts until the count has room again, see the next test.)
    assert _lock(Session, uid, HOME) is None, "the owner can sign in again"
    _fail(Session, uid, "203.0.113.100")
    assert _lock(Session, uid, HOME).scope == L.SCOPE_ACCOUNT, "one more failure pauses them again"
    assert _account_row(Session, uid)[0] == THRESHOLD * MULTIPLE, "the count never passes the backstop"


def test_the_account_wide_pause_lasts_until_the_count_has_room_again(Session, limits):
    uid = _add_user(Session)
    for i in range(THRESHOLD * MULTIPLE):
        _fail(Session, uid, f"203.0.113.{i}")
    _count, start, _locked = _account_row(Session, uid)
    lock = _lock(Session, uid, HOME)
    assert lock.locked_until == start + INTERVAL, "not the 15 minutes: the count is still full then"
    limits["lockout_duration"] = 10 * 24 * 60            # a longer lockout duration still wins
    uid2 = _add_user(Session)
    for i in range(THRESHOLD * MULTIPLE):
        _fail(Session, uid2, f"203.0.113.{i}")
    assert _lock(Session, uid2, HOME).locked_until > _now() + timedelta(days=9)


def test_guessers_from_many_addresses_get_at_most_the_backstop_a_day_before_the_pause(Session, limits,
                                                                                    monkeypatch):
    # The review's arithmetic: fresh addresses, never enough from one to lock it, a guess every five
    # minutes for a day. Counted in the login window, every one of the 288 guesses was answered. Now the
    # backstop's worth are, then a pause, then about one per interval as the count loses a failure.
    clock = {"t": _now()}
    monkeypatch.setattr(L, "utcnow", lambda: clock["t"])
    uid = _add_user(Session)
    answered = refused = 0
    for i in range(24 * 12):
        s = Session()
        svc = A.AuthService(s)
        svc._check_rate_limit = lambda *a, **k: None
        try:
            svc.authenticate_user(_user(s, uid).username, "a-guess", f"2001:db8:{i}::1")
        except A.AccountLockedError:
            refused += 1
        except A.InvalidCredentialsError:
            answered += 1
        finally:
            s.close()
        clock["t"] += timedelta(minutes=5)
    backstop = THRESHOLD * MULTIPLE
    assert answered <= backstop + int(L.ACCOUNT_PERIOD / INTERVAL), (answered, refused)
    assert answered >= backstop and refused > 0


def test_an_ipv6_address_counts_as_its_slash_64():
    assert L.source_of("2001:db8:1:2:aaaa::1") == L.source_of("2001:db8:1:2:ffff:ffff:ffff:ffff") == "2001:db8:1:2::/64"
    assert L.source_of("2001:db8:1:3::1") != L.source_of("2001:db8:1:2::1")
    assert L.source_of("::ffff:198.51.100.7") == "198.51.100.7", "an IPv4 address written as IPv6"
    assert L.source_of("198.51.100.7") == "198.51.100.7"
    assert L.source_of("fe80::1%eth0") == "fe80::/64"
    assert L.source_of(None) == "unknown" and L.source_of("not-an-address") == "not-an-address"


def test_guessing_from_across_one_ipv6_network_locks_that_network(Session, limits):
    uid = _add_user(Session)
    for i in range(THRESHOLD):
        _fail(Session, uid, f"2001:db8:5:6::{i + 1:x}")       # a fresh address each time, one /64
    lock = _lock(Session, uid, "2001:db8:5:6::ffff")
    assert (lock.scope, lock.source) == (L.SCOPE_ADDRESS, "2001:db8:5:6::/64")
    assert _lock(Session, uid, "2001:db8:5:7::1") is None, "the next network is not affected"


def test_an_address_count_is_not_time_limited(Session, limits):
    uid = _add_user(Session)
    _fail(Session, uid, ATTACKER)
    _fail(Session, uid, ATTACKER)
    s = Session()
    s.query(SignInLockout).filter(SignInLockout.source == ATTACKER).update(
        {"window_start": _now() - timedelta(days=2)})
    s.commit()
    s.close()
    _fail(Session, uid, ATTACKER)         # counts on top of the old ones: guessing slowly is no way round
    assert _lock(Session, uid, ATTACKER).scope == L.SCOPE_ADDRESS


def test_a_success_there_ends_an_address_count_but_not_the_account_wide_one(Session, limits):
    uid = _add_user(Session)
    _fail(Session, uid, HOME)
    _fail(Session, uid, HOME)
    _sign_in(Session, uid, HOME)          # the right password from HOME clears HOME's count
    _fail(Session, uid, HOME)
    _fail(Session, uid, HOME)
    assert _lock(Session, uid, HOME) is None
    s = Session()
    rows = {r.source: r.failed_attempts for r in s.query(SignInLockout).all()}
    s.close()
    assert rows[HOME] == 2
    assert rows[L.ACCOUNT_WIDE] == 4, "the owner signing in does not cancel failures counted elsewhere"


def test_the_total_on_the_account_row_is_kept_and_never_locks_it(Session, limits):
    uid = _add_user(Session)
    for _ in range(THRESHOLD * MULTIPLE):
        _fail(Session, uid, ATTACKER)
    s = Session()
    user = _user(s, uid)
    assert (user.failed_login_attempts, user.is_locked, user.locked_until) == (THRESHOLD * MULTIPLE, False, None)
    s.close()


def test_a_lockout_duration_of_zero_locks_until_an_administrator_clears_it(Session, limits):
    limits["lockout_duration"] = 0
    uid = _add_user(Session)
    for _ in range(THRESHOLD):
        _fail(Session, uid, ATTACKER)
    lock = _lock(Session, uid, ATTACKER)
    assert lock.scope == L.SCOPE_ADDRESS and lock.locked_until is None
    s = Session()
    assert L.release_expired(s) == 0, "a lock with no end is never released by the timer"
    assert L.clear_for_user(s, uid) == 1
    s.commit()
    s.close()
    assert _lock(Session, uid, ATTACKER) is None


# --------------------------------------------------------------------------- refusing sign-ins

def test_a_lock_refuses_before_the_password_is_checked(Session, limits, monkeypatch):
    uid = _add_user(Session)
    for _ in range(THRESHOLD):
        _fail(Session, uid, ATTACKER)
    checked = []
    real = A.verify_password
    monkeypatch.setattr(A, "verify_password", lambda pw, h: checked.append(pw) or real(pw, h))
    for password in (PASSWORD, "a-guess"):
        with pytest.raises(A.AccountLockedError) as refused:
            _sign_in(Session, uid, ATTACKER, password=password)
        assert refused.value.scope == "address"
    assert checked == [], "no password is checked while the lock holds: guessing stops"
    s = Session()
    assert _user(s, uid).failed_login_attempts == THRESHOLD, "a refused attempt is not counted"
    s.close()


def test_the_owner_signs_in_from_elsewhere_while_an_address_is_locked(Session, limits):
    uid = _add_user(Session)
    for _ in range(THRESHOLD):
        _fail(Session, uid, ATTACKER)
    user, token = _sign_in(Session, uid, HOME)
    assert token == "session-token"


def test_the_account_wide_lock_refuses_everyone_with_its_scope(Session, limits):
    uid = _add_user(Session)
    for i in range(THRESHOLD * MULTIPLE):
        _fail(Session, uid, f"203.0.113.{i}")
    for address in (HOME, CAFE):
        with pytest.raises(A.AccountLockedError) as refused:
            _sign_in(Session, uid, address)
        assert refused.value.scope == "account" and refused.value.locked_until is not None


def test_an_administrators_lock_still_reports_after_the_password(Session, limits):
    uid = _add_user(Session, is_locked=True, locked_until=None)
    with pytest.raises(A.InvalidCredentialsError):
        _sign_in(Session, uid, HOME, password="a-guess")
    with pytest.raises(A.AccountLockedError) as refused:
        _sign_in(Session, uid, HOME)
    assert refused.value.scope == "administrator"


# --------------------------------------------------------------------------- sessions carry on

def test_only_an_administrators_lock_ends_a_session():
    admin_lock = User(is_locked=True, locked_until=None)
    timed = User(is_locked=True, locked_until=_now() + timedelta(minutes=10))
    assert A.admin_locked(admin_lock) is True
    assert A.admin_locked(timed) is False, "a lock with an end was armed by wrong passwords"
    assert A.admin_locked(User(is_locked=False, locked_until=None)) is False


def test_an_automatic_lock_does_not_stop_a_temporary_credential(Session, limits, monkeypatch):
    # A temporary credential is its own sign-in, handed out by the account's owner. Wrong passwords for
    # the account's password pause new password sign-ins only; an administrator's lock stops it too.
    from app.core import temp_scope
    from app.core.models import ActiveSession, TemporaryCredential
    engine = Session.kw["bind"]
    for model in (TemporaryCredential, ActiveSession):
        model.__table__.create(engine)
    monkeypatch.setattr(temp_scope, "attach_scope", lambda *a, **k: None)
    uid = _add_user(Session)
    for i in range(THRESHOLD * MULTIPLE):              # account-wide, and ATTACKER's own address
        _fail(Session, uid, ATTACKER if i < THRESHOLD else f"203.0.113.{i}")
    assert _lock(Session, uid, ATTACKER).scope == L.SCOPE_ACCOUNT
    s = Session()
    user = _user(s, uid)
    user.is_locked, user.locked_until = True, _now() + timedelta(minutes=10)   # the older timed kind
    s.commit()
    s.close()

    def credential(name):
        s = Session()
        s.add(TemporaryCredential(user_id=uid, temp_username=name, credential_hash=hash_password("one-time"),
                                  expires_at=_now() + timedelta(hours=1),
                                  deactivate_at=_now() + timedelta(hours=1)))
        s.commit()
        s.close()

    def sign_in(name):
        s = Session()
        svc = A.AuthService(s)
        svc._check_rate_limit = lambda *a, **k: None
        svc._create_session = lambda *a, **k: "session-token"
        try:
            user, token = svc.authenticate_temporary_credential(name, "one-time", ATTACKER,
                                                                allow_device_credential=False)
            return user.id, token
        finally:
            s.close()

    credential("temp_during_auto_lock")
    assert sign_in("temp_during_auto_lock") == (uid, "session-token")

    s = Session()
    _user(s, uid).locked_until = None                    # now an administrator's lock
    s.commit()
    s.close()
    credential("temp_during_admin_lock")
    with pytest.raises(A.InvalidCredentialsError):
        sign_in("temp_during_admin_lock")


# --------------------------------------------------------------------------- ending a lock

def test_an_expired_lock_is_released_with_its_scope_by_the_timer(Session, limits):
    uid = _add_user(Session)
    for _ in range(THRESHOLD):
        _fail(Session, uid, ATTACKER)
    s = Session()
    s.query(SignInLockout).filter(SignInLockout.source == ATTACKER).update(
        {"locked_until": _now() - timedelta(minutes=1)})
    s.commit()
    assert L.release_expired(s) == 1
    s.commit()
    assert L.release_expired(s) == 0, "a second pass finds nothing"
    s.close()
    (row,) = _audit(Session, L.AUTO_UNLOCKED_ACTION)
    assert row.details["scope"] == "address" and row.details["address"] == ATTACKER
    assert row.details["cleared_by"] == "timer" and row.ip_address is None
    assert _lock(Session, uid, ATTACKER) is None


def test_a_sign_in_after_the_lock_ran_out_releases_it_and_succeeds(Session, limits):
    uid = _add_user(Session)
    for i in range(THRESHOLD * MULTIPLE):
        _fail(Session, uid, f"203.0.113.{i}")
    s = Session()
    s.query(SignInLockout).update({"locked_until": _now() - timedelta(seconds=1)})
    s.commit()
    s.close()
    # A pause ends only once its count has lost a failure (_pause_until), so the count has room again.
    _age_account_count(Session, uid, INTERVAL)
    user, token = _sign_in(Session, uid, HOME)
    assert token == "session-token"
    released = _audit(Session, L.AUTO_UNLOCKED_ACTION)
    assert {r.details["scope"] for r in released} == {"account"}
    assert all(r.details["cleared_by"] == "sign_in" and r.ip_address == HOME for r in released)


def test_prune_drops_counts_with_nothing_left_to_count(Session, limits):
    uid = _add_user(Session)
    _fail(Session, uid, HOME)
    _fail(Session, uid, CAFE)
    for _ in range(THRESHOLD):
        _fail(Session, uid, ATTACKER)
    s = Session()
    s.query(SignInLockout).update({"window_start": _now() - timedelta(days=2),
                                   "last_failure_at": _now() - timedelta(days=2)})
    s.query(SignInLockout).filter(SignInLockout.source == CAFE).update({"last_failure_at": _now()})
    s.commit()
    assert L.prune_stale(s) == 2          # the account-wide count and HOME's; CAFE is recent
    s.commit()
    left = sorted(r.source for r in s.query(SignInLockout).all())
    s.close()
    assert left == sorted([CAFE, ATTACKER]), "a count holding a lock is never pruned"


def test_blocks_by_user_says_where_and_until_when(Session, limits):
    address_only, account_wide, clear = _add_user(Session), _add_user(Session), _add_user(Session)
    for _ in range(THRESHOLD):
        _fail(Session, address_only, ATTACKER)
    for i in range(THRESHOLD * MULTIPLE):
        _fail(Session, account_wide, f"203.0.113.{i}")
    s = Session()
    blocks = L.blocks_by_user(s, [address_only, account_wide, clear])
    s.close()
    assert set(blocks) == {address_only, account_wide}
    assert (blocks[address_only]["scope"], blocks[address_only]["addresses"]) == ("address", 1)
    assert blocks[account_wide]["scope"] == "account" and blocks[account_wide]["until"] is not None


# --------------------------------------------------------------------------- names that are no account

class _Clock:
    def __init__(self):
        self.t = _now()


class _FakeStore:
    """The cache, in memory, with each value's lifetime kept on the test's clock."""

    def __init__(self, clock):
        self.clock, self.values = clock, {}

    def get(self, key):
        value = self.values.get(key)
        if value is None or value[1] <= self.clock.t:
            self.values.pop(key, None)
            return None
        return dict(value[0])

    def set(self, key, value, ttl_seconds):
        self.values[key] = (dict(value), self.clock.t + timedelta(seconds=ttl_seconds))


@pytest.fixture
def clocked(Session, limits, monkeypatch):
    """A clock the lockout reads, the cache the mimicry uses, and one attempt at a time by a name from
    an address: what the caller sees ("wrong", or the refusal's scope and minutes left)."""
    clock = _Clock()
    monkeypatch.setattr(L, "utcnow", lambda: clock.t)
    store = _FakeStore(clock)
    monkeypatch.setattr(L, "_phantom_store", lambda: store)
    _add_user(Session, username="real-person")

    def attempt(name, address=ATTACKER):
        s = Session()
        svc = A.AuthService(s)
        svc._check_rate_limit = lambda *a, **k: None
        try:
            svc.authenticate_user(name, "a-guess", address)
        except A.AccountLockedError as e:
            left = None if e.locked_until is None else round((e.locked_until - clock.t).total_seconds())
            return (e.scope, left)
        except A.InvalidCredentialsError:
            return "wrong"
        finally:
            s.close()
        return "signed in"

    def prune():
        s = Session()
        L.release_expired(s)
        L.prune_stale(s)
        s.commit()
        s.close()

    clock.attempt, clock.prune, clock.store = attempt, prune, store
    return clock


def _both(clock, steps):
    """Run the same attempts, with the same pauses, as the account and as a name that is no account.
    ``steps`` is a list of (address, minutes to wait afterwards)."""
    seen = {}
    start = clock.t
    for name in ("real-person", "nobody-here"):
        clock.t = start
        out = []
        for address, wait in steps:
            out.append(clock.attempt(name, address))
            clock.t += timedelta(minutes=wait)
            clock.prune()                      # the periodic cleanup, which only an account has
        seen[name] = out
    return seen


def test_slow_guessing_is_refused_at_the_same_point(clocked):
    # The review's first scratch test: guesses further apart than the lock's length, then one a minute
    # later. An address's count does not run out by itself, for an account or for a name.
    steps = [(ATTACKER, MINUTES + 5)] * (THRESHOLD - 1) + [(ATTACKER, 1), (ATTACKER, 1)]
    seen = _both(clocked, steps)
    assert seen["real-person"] == seen["nobody-here"], seen
    assert seen["real-person"][THRESHOLD][0] == "address"


def test_a_burst_spread_over_minutes_is_refused_for_as_long(clocked):
    # The review's second: the lock runs from the failure that armed it, for both, so the minutes left
    # (and so Retry-After) are the same.
    seen = _both(clocked, [(ATTACKER, 2)] * (THRESHOLD + 2))
    assert seen["real-person"] == seen["nobody-here"], seen
    assert seen["real-person"][THRESHOLD] == ("address", (MINUTES - 2) * 60)


def test_guessing_from_many_addresses_pauses_both_the_same_way(clocked):
    steps = [(f"203.0.113.{i}", 5) for i in range(THRESHOLD * MULTIPLE + 2)]
    seen = _both(clocked, steps)
    assert seen["real-person"] == seen["nobody-here"], seen
    assert seen["real-person"][THRESHOLD * MULTIPLE][0] == "account"


def test_after_a_pause_ends_the_next_failure_pauses_both_again(clocked):
    steps = ([(f"203.0.113.{i}", 1) for i in range(THRESHOLD * MULTIPLE)]
             + [(HOME, INTERVAL.total_seconds() / 60 + 1), ("203.0.113.90", 1), (CAFE, 1)])
    seen = _both(clocked, steps)
    assert seen["real-person"] == seen["nobody-here"], seen
    assert seen["real-person"][-1][0] == "account"


def test_an_address_count_left_for_a_day_is_gone_for_both(clocked):
    steps = [(ATTACKER, 1)] * (THRESHOLD - 1) + [(ATTACKER, 24 * 60 + 10), (ATTACKER, 1), (ATTACKER, 1)]
    seen = _both(clocked, steps)
    assert seen["real-person"] == seen["nobody-here"], seen
    assert "address" not in [x[0] for x in seen["real-person"] if isinstance(x, tuple)]


def test_the_name_mimicry_fails_open_when_the_cache_is_down(monkeypatch, limits):
    class _Down:
        def get(self, key):
            return L._UNAVAILABLE

        def set(self, *a, **k):
            raise RuntimeError("down")

    monkeypatch.setattr(L, "_phantom_store", lambda: _Down())
    L.phantom_failure("nobody", ATTACKER)       # never raises
    assert L.phantom_lock("nobody", ATTACKER) is None


def test_the_cache_store_reads_back_what_it_wrote_and_fails_open(monkeypatch):
    from app.core import database, redis_guard

    class _Redis:
        def __init__(self):
            self.values = {}

        def get(self, key):
            return self.values.get(key)

        def set(self, key, value, ex=None):
            self.values[key] = value

    fake = _Redis()
    monkeypatch.setattr(database, "redis_client", fake)
    monkeypatch.setattr(redis_guard, "_guard_open_until", 0.0)
    store = L._CacheStore()
    assert store.get("k") is None
    store.set("k", {"n": 2}, 60)
    assert store.get("k") == {"n": 2}
    fake.values["k"] = "not json"
    assert store.get("k") is None

    class _Broken:
        def get(self, key):
            raise ConnectionError("down")

    monkeypatch.setattr(database, "redis_client", _Broken())
    try:
        assert store.get("k") is L._UNAVAILABLE
    finally:
        redis_guard.guard_record_success()      # leave the shared guard as it was found


def test_an_account_wide_count_is_pruned_only_once_all_of_it_is_gone(Session, limits):
    # It holds at most the backstop and loses all of it within a day of window_start, and not before.
    uid = _add_user(Session)
    _fail(Session, uid, HOME)
    _age_account_count(Session, uid, L.ACCOUNT_PERIOD - timedelta(minutes=5))
    s = Session()
    assert L.prune_stale(s) == 0
    s.commit()
    s.close()
    _age_account_count(Session, uid, timedelta(minutes=5, seconds=1))
    s = Session()
    s.query(SignInLockout).filter(SignInLockout.source == HOME).update({"last_failure_at": _now()})
    assert L.prune_stale(s) == 1
    s.commit()
    assert [r.source for r in s.query(SignInLockout).all()] == [HOME]
    s.close()


def test_after_an_address_lock_runs_out_its_count_starts_again_for_both(clocked):
    steps = ([(ATTACKER, 1)] * THRESHOLD + [(ATTACKER, MINUTES + 1)]
             + [(ATTACKER, 1)] * THRESHOLD)
    seen = _both(clocked, steps)
    assert seen["real-person"] == seen["nobody-here"], seen
    assert seen["real-person"][THRESHOLD + 1:THRESHOLD * 2 + 1] == ["wrong"] * THRESHOLD


def test_with_both_locks_in_force_both_answer_with_the_account_wide_one(clocked):
    steps = ([(ATTACKER, 1)] * THRESHOLD
             + [(f"203.0.113.{i}", 1) for i in range(THRESHOLD * MULTIPLE - THRESHOLD)]
             + [(ATTACKER, 1)])
    seen = _both(clocked, steps)
    assert seen["real-person"] == seen["nobody-here"], seen
    assert seen["real-person"][-1][0] == "account"


# --------------------------------------------------------------------------- one attempt at a time
#
# Attempts on one account take turns: each keeps the account's turn through the lock check, the password
# check and the counting, so each sees what the one before it counted. Counted after the check without
# turns, every attempt in flight while the count was below the backstop had its password checked: through
# SFTP's parallel connections, about 2,000 guesses a day instead of the backstop's 20. Counted before the
# check and given back after, right passwords beyond the room left were refused, and an attempt that died
# in between left a failure counted that no lock recorded.

def _counts(Session, uid):
    s = Session()
    try:
        return {r.source: r.failed_attempts for r in s.query(SignInLockout).filter(SignInLockout.user_id == uid)}
    finally:
        s.close()


class _Checks(list):
    """The hashes checked, and ``running``: how many checks ran at once, now and at the most."""
    running = None


def _slow_checks(monkeypatch, seconds=0.6, right=False):
    """verify_password, slow enough that every attempt of a burst is in flight at once, recording each
    hash it was asked to check, and how many checks ran at the same moment. A guess unless ``right``, when
    it answers as the real check does."""
    import threading
    import time
    real = A.verify_password
    checked, lock = _Checks(), threading.Lock()
    running = {"now": 0, "most": 0}

    def verify(password, password_hash):
        with lock:
            checked.append(password_hash)
            running["now"] += 1
            running["most"] = max(running["most"], running["now"])
        try:
            time.sleep(seconds)
            return real(password, password_hash) if right else False
        finally:
            with lock:
                running["now"] -= 1

    monkeypatch.setattr(A, "verify_password", verify)
    checked.running = running
    return checked


def _burst(Session, name, addresses, password="a-guess"):
    """Sign-in attempts by ``name``, one from each address, all at once, each on its own session and
    thread as the web and SFTP servers run them. Returns how each ended, sorted: "signed in", "wrong" (its
    password was checked and was wrong), or the refusal's scope (refused unchecked), and how long the last
    one took."""
    import threading
    import time
    start, outcomes, lock = threading.Barrier(len(addresses)), [], threading.Lock()
    took = []

    def attempt(address):
        s = Session()
        svc = A.AuthService(s)
        svc._check_rate_limit = lambda *a, **k: None
        svc._terminate_existing_sessions = lambda *a, **k: None
        svc._create_session = lambda *a, **k: "session-token"
        start.wait()
        began = time.monotonic()
        try:
            svc.authenticate_user(name, password, address)
            seen = "signed in"
        except A.AccountLockedError as e:
            seen = e.scope
        except A.InvalidCredentialsError:
            seen = "wrong"
        finally:
            s.close()
        with lock:
            outcomes.append(seen)
            took.append(time.monotonic() - began)

    threads = [threading.Thread(target=attempt, args=(a,)) for a in addresses]
    for t in threads:
        t.start()
    for t in threads:
        t.join(120)
    assert len(outcomes) == len(addresses), "an attempt did not finish"
    _burst.longest = max(took)
    return sorted(outcomes)


BURST = [f"203.0.113.{i}" for i in range(1, 17)]        # 16 addresses, one attempt each, all at once


def test_a_burst_from_many_addresses_gets_no_more_checks_than_the_backstop(Session, limits, monkeypatch):
    # The review's concurrency finding: every attempt already past the lock check when the count was
    # below the backstop had its password checked, however many there were.
    uid = _add_user(Session, username="real-person")
    checked = _slow_checks(monkeypatch)
    seen = _burst(Session, "real-person", BURST)
    backstop = THRESHOLD * MULTIPLE
    assert len(checked) == backstop, f"{len(checked)} passwords checked, the backstop is {backstop}"
    assert seen == ["account"] * (len(BURST) - backstop) + ["wrong"] * backstop, seen
    assert _counts(Session, uid)[L.ACCOUNT_WIDE] == backstop
    assert _lock(Session, uid, HOME).scope == L.SCOPE_ACCOUNT, "the failures armed the pause"
    s = Session()
    assert _user(s, uid).failed_login_attempts == backstop, "only a checked password is a failure"
    s.close()


def test_a_burst_from_one_address_gets_no_more_checks_than_the_login_limit(Session, limits, monkeypatch):
    uid = _add_user(Session, username="real-person")
    checked = _slow_checks(monkeypatch)
    seen = _burst(Session, "real-person", [ATTACKER] * 8)
    assert len(checked) == THRESHOLD, checked
    assert seen == ["address"] * (8 - THRESHOLD) + ["wrong"] * THRESHOLD, seen
    assert _counts(Session, uid) == {ATTACKER: THRESHOLD, L.ACCOUNT_WIDE: THRESHOLD}


def test_a_name_that_is_no_account_meets_the_same_budget_in_a_burst(Session, limits, monkeypatch):
    # Being refused must not tell an account from a name that is none, at once as one by one; nor may how
    # long a burst takes: both are checked one at a time, under the account's turn and the name's hold.
    import threading
    import time

    class _HeldStore(_FakeStore):
        """The fake cache, with the hold the real one takes on a name: a lock per key. A read takes a
        little while, as a round trip to the cache does, so attempts at once interleave unless held."""

        def __init__(self, clock):
            super().__init__(clock)
            self.locks, self.guard = {}, threading.Lock()

        def get(self, key):
            time.sleep(0.005)
            return super().get(key)

        def hold(self, key):
            with self.guard:
                lock = self.locks.setdefault(key, threading.Lock())
            lock.acquire()
            return "token"

        def release(self, key, token):
            self.locks[key].release()

    clock = _Clock()
    store = _HeldStore(clock)
    monkeypatch.setattr(L, "_phantom_store", lambda: store)
    _add_user(Session, username="real-person")
    checked = _slow_checks(monkeypatch, seconds=0.4)
    real = _burst(Session, "real-person", BURST)
    real_took = _burst.longest
    nobody = _burst(Session, "nobody-here", BURST)
    nobody_took = _burst.longest
    assert real == nobody, (real, nobody)
    assert nobody.count("wrong") == THRESHOLD * MULTIPLE
    backstop_checks = THRESHOLD * MULTIPLE * 0.4
    assert real_took >= backstop_checks and nobody_took >= backstop_checks, (real_took, nobody_took)
    assert checked.running["most"] == 1, "neither ran two checks at once"


def test_attempts_on_one_account_are_checked_one_at_a_time(Session, limits, monkeypatch):
    # Each keeps the account's turn through its check: two checks never run at once, however many
    # attempts arrive together.
    _add_user(Session, username="real-person")
    _add_user(Session, username="someone-else")
    checked = _slow_checks(monkeypatch, seconds=0.3, right=True)
    assert _burst(Session, "real-person", [HOME] * 4, password=PASSWORD) == ["signed in"] * 4
    assert checked.running["most"] == 1, checked.running


def test_a_count_at_its_limit_always_has_its_lock(Session, limits, monkeypatch):
    # The count and the lock it arms are committed together, in the failure's turn: whenever a count is
    # at its limit its lock is in force, so an SFTP key sign-in (which checks no password) is refused
    # exactly when a password would be.
    uid = _add_user(Session, username="real-person")
    _slow_checks(monkeypatch, seconds=0.2)
    _burst(Session, "real-person", [ATTACKER] * 5 + [HOME, CAFE] + [f"203.0.113.{i}" for i in range(1, 6)])
    s = Session()
    rows = s.query(SignInLockout).filter(SignInLockout.user_id == uid).all()
    s.close()
    full = [r for r in rows if r.failed_attempts >= (THRESHOLD * MULTIPLE if r.source == L.ACCOUNT_WIDE
                                                     else THRESHOLD)]
    assert full and all(r.locked_at is not None for r in full), [(r.source, r.failed_attempts, r.locked_at)
                                                                 for r in rows]
    assert _lock(Session, uid, ATTACKER) is not None and _lock(Session, uid, HOME).scope == L.SCOPE_ACCOUNT


def test_right_passwords_arriving_at_once_from_one_address_all_sign_in(Session, limits, monkeypatch):
    # The review's first finding here: with a limit of 3, six right passwords at once from one address (an SFTP
    # client opening several connections) gave 3 signed in and 3 refused as locked. They wait their turn.
    uid = _add_user(Session, username="owner")
    _slow_checks(monkeypatch, seconds=0.3, right=True)
    seen = _burst(Session, "owner", [HOME] * (THRESHOLD + 3), password=PASSWORD)
    assert seen == ["signed in"] * (THRESHOLD + 3), seen
    assert _counts(Session, uid) == {}, "a right password is never counted"


def test_right_passwords_arriving_at_once_past_the_backstop_all_sign_in(Session, limits, monkeypatch):
    uid = _add_user(Session, username="owner")
    _slow_checks(monkeypatch, seconds=0.3, right=True)
    addresses = [f"198.51.100.{i}" for i in range(1, THRESHOLD * MULTIPLE + 3)]
    assert _burst(Session, "owner", addresses, password=PASSWORD) == ["signed in"] * len(addresses)
    assert _counts(Session, uid) == {}


def test_twelve_connections_at_once_with_the_right_password_all_sign_in(Session, limits, monkeypatch):
    # What the desktop app and SFTP clients do: several connections at once, one account, one password.
    # Each waits for the ones before it; the last waits about eleven checks.
    _add_user(Session, username="owner")
    _slow_checks(monkeypatch, seconds=0.2, right=True)
    assert _burst(Session, "owner", [HOME] * 12, password=PASSWORD) == ["signed in"] * 12
    assert _burst.longest >= 11 * 0.2, "one at a time: the last one waited for the eleven before it"


def test_an_attempt_that_dies_during_its_check_leaves_nothing_counted(Session, limits, monkeypatch):
    # The review's third finding here: counted before the check, an attempt that died in between (a process
    # killed, a commit that failed) left its failure counted, and a login limit's worth of them left a
    # full count no lock recorded, refusing the address with an end that kept moving. Now nothing is
    # counted before a password is known to be wrong, and a death ends the attempt's transaction.
    uid = _add_user(Session, username="owner")
    real = A.verify_password

    def dies(*_a, **_k):
        raise RuntimeError("the process died")

    monkeypatch.setattr(A, "verify_password", dies)
    for _ in range(THRESHOLD + 1):
        with pytest.raises(RuntimeError):
            _sign_in(Session, uid, HOME)
    assert _counts(Session, uid) == {} and _lock(Session, uid, HOME) is None
    monkeypatch.setattr(A, "verify_password", real)
    assert _sign_in(Session, uid, HOME)[1] == "session-token"


def test_an_attempt_that_dies_after_a_right_password_leaves_nothing_counted(Session, limits, monkeypatch):
    # The review's fourth finding here: a right password whose attempt died before its failure was given back
    # stayed counted.
    uid = _add_user(Session, username="owner")
    s = Session()
    svc = A.AuthService(s)
    svc._check_rate_limit = lambda *a, **k: None
    svc._terminate_existing_sessions = lambda *a, **k: None

    def dies(*_a, **_k):
        raise RuntimeError("the process died")

    svc._create_session = dies
    try:
        for _ in range(THRESHOLD + 1):
            with pytest.raises(RuntimeError):
                svc.authenticate_user("owner", PASSWORD, HOME)
    finally:
        s.close()
    assert _counts(Session, uid) == {} and _lock(Session, uid, HOME) is None
    assert _sign_in(Session, uid, HOME)[1] == "session-token"


def test_a_wrong_password_whose_count_fails_to_commit_leaves_nothing_counted(Session, limits, monkeypatch):
    # Rolled back where it failed: the web's sign-in route goes on to commit its own audit row in the
    # same session, which would otherwise write the half-made count.
    uid = _add_user(Session, username="owner")
    real = L.record_failure

    def fails(*a, **k):
        real(*a, **k)
        raise RuntimeError("the commit failed")

    monkeypatch.setattr(L, "record_failure", fails)
    s = Session()
    svc = A.AuthService(s)
    svc._check_rate_limit = lambda *a, **k: None
    try:
        for _ in range(THRESHOLD + 1):
            with pytest.raises(RuntimeError):
                svc.authenticate_user("owner", "a-guess", HOME)
            s.commit()
    finally:
        s.close()
    assert _counts(Session, uid) == {}
    s = Session()
    assert _user(s, uid).failed_login_attempts == 0, "the total rolls back with its count"
    s.close()


def test_a_right_password_counts_nothing(Session, limits):
    uid = _add_user(Session)
    _fail(Session, uid, ATTACKER)
    _fail(Session, uid, ATTACKER)
    before = _counts(Session, uid)
    _sign_in(Session, uid, HOME)
    after = _counts(Session, uid)
    assert after == before == {ATTACKER: 2, L.ACCOUNT_WIDE: 2}, (before, after)
    # A right password for an account that may not sign in is not a guess either.
    s = Session()
    _user(s, uid).is_active = False
    s.commit()
    s.close()
    with pytest.raises(A.InvalidCredentialsError):
        _sign_in(Session, uid, CAFE)
    assert _counts(Session, uid) == before


@pytest.mark.parametrize("name", ["owner", "nobody-here"])
def test_a_turn_not_come_in_time_is_refused_as_busy_and_counts_nothing(Session, limits, monkeypatch, name):
    # The same refusal for an account whose turn did not come and a name whose hold did not.
    uid = _add_user(Session, username="owner")
    checked = []
    monkeypatch.setattr(A, "verify_password", lambda pw, h: checked.append(pw) or False)

    def busy(*_a, **_k):
        raise L.Busy()

    class _Busy(_FakeStore):
        hold = staticmethod(busy)

    store = _Busy(_Clock())
    monkeypatch.setattr(L, "take_turn", busy)
    monkeypatch.setattr(L, "_phantom_store", lambda: store)
    s = Session()
    svc = A.AuthService(s)
    svc._check_rate_limit = lambda *a, **k: None
    try:
        with pytest.raises(A.RateLimitExceededError) as refused:
            svc.authenticate_user(name, "a-guess", HOME)
    finally:
        s.close()
    assert refused.value.retry_after == L.BUSY_RETRY_SECONDS and "at once" in str(refused.value)
    assert checked == [] and _counts(Session, uid) == {} and store.values == {}


def test_an_administrators_locked_account_is_counted_too(Session, limits, monkeypatch):
    # It arms no lock of its own, but its attempts are still bounded: a right password there answers
    # differently from a wrong one, so unlimited checks would be unlimited guessing.
    uid = _add_user(Session, is_locked=True, locked_until=None)
    checked = _slow_checks(monkeypatch, seconds=0)
    seen = []
    for i in range(THRESHOLD * MULTIPLE + 2):
        try:
            _sign_in(Session, uid, f"203.0.113.{i}", password="a-guess")
        except A.AccountLockedError as e:
            seen.append(e.scope)
        except A.InvalidCredentialsError:
            seen.append("wrong")
    assert len(checked) == THRESHOLD * MULTIPLE
    assert seen == ["wrong"] * (THRESHOLD * MULTIPLE) + ["account"] * 2, seen
    assert _audit(Session, L.AUTO_LOCKED_ACTION) == [], "no automatic lock on top of an administrator's"


def test_the_cache_hold_lets_one_attempt_at_a_time_and_fails_open(monkeypatch):
    import threading
    from app.core import database, redis_guard

    class _Redis:
        def __init__(self):
            self.values, self.guard = {}, threading.Lock()

        def set(self, key, value, nx=False, px=None, ex=None):
            with self.guard:
                if nx and key in self.values:
                    return None
                self.values[key] = value
                return True

        def get(self, key):
            return self.values.get(key)

        def delete(self, key):
            self.values.pop(key, None)

    fake = _Redis()
    monkeypatch.setattr(database, "redis_client", fake)
    monkeypatch.setattr(redis_guard, "_guard_open_until", 0.0)
    store = L._CacheStore()
    monkeypatch.setattr(L._CacheStore, "WAIT_SECONDS", 0.05)
    token = store.hold("k")
    assert token and fake.values["k"] == token
    with pytest.raises(L.Busy):
        store.hold("k")                                   # a second attempt waits, then is refused as busy
    store.release("k", "not-the-token")
    assert fake.values["k"] == token, "only the holder lets go"
    store.release("k", token)
    assert "k" not in fake.values
    assert store.hold("k") is not None

    class _Broken:
        def set(self, *a, **k):
            raise ConnectionError("down")

    monkeypatch.setattr(database, "redis_client", _Broken())
    try:
        assert store.hold("k") is None, "the cache down: no hold, and the attempt goes ahead"
    finally:
        redis_guard.guard_record_success()      # leave the shared guard as it was found


def test_an_administrators_locked_account_guessed_from_one_address_gets_only_the_login_limit(Session, limits,
                                                                                              monkeypatch):
    # The address half of count_at_limit: from ONE address, an account an administrator locked is checked
    # the login limit's number of times, then refused unchecked with the address's scope. The account-wide
    # count alone would have let that address check the whole backstop.
    uid = _add_user(Session, is_locked=True, locked_until=None)
    checked = _slow_checks(monkeypatch, seconds=0)
    seen = []
    for _ in range(THRESHOLD + 2):
        try:
            _sign_in(Session, uid, ATTACKER, password="a-guess")
        except A.AccountLockedError as e:
            seen.append(e.scope)
        except A.InvalidCredentialsError:
            seen.append("wrong")
    assert len(checked) == THRESHOLD, (len(checked), seen)
    assert seen == ["wrong"] * THRESHOLD + ["address"] * 2, seen
    assert _audit(Session, L.AUTO_LOCKED_ACTION) == [], "no automatic lock on top of an administrator's"


class _SharedRedis:
    """Redis, in memory and safe across threads: the calls the name mimicry's cache makes."""

    def __init__(self):
        import threading
        self.values, self.guard = {}, threading.Lock()

    def set(self, key, value, nx=False, px=None, ex=None):
        with self.guard:
            if nx and key in self.values:
                return None
            self.values[key] = value
            return True

    def get(self, key):
        with self.guard:
            return self.values.get(key)

    def delete(self, key):
        with self.guard:
            self.values.pop(key, None)


def test_a_burst_on_a_name_that_is_no_account_waits_its_turn_like_one_on_an_account(Session, limits, monkeypatch):
    # Through the real cache hold, waited for as long as an account's turn. With no wait, every attempt but
    # the first of a burst on a name that is no account was refused as busy, while the same burst on an
    # account waited and was checked: which told a guesser whether the account existed.
    from app.core import database, redis_guard
    monkeypatch.setattr(database, "redis_client", _SharedRedis())
    monkeypatch.setattr(redis_guard, "_guard_open_until", 0.0)
    _add_user(Session, username="real-person")
    checked = _slow_checks(monkeypatch, seconds=0.2)
    real = _burst(Session, "real-person", [ATTACKER] * 6)
    nobody = _burst(Session, "nobody-here", [ATTACKER] * 6)
    assert real == nobody == ["address"] * 3 + ["wrong"] * THRESHOLD, (real, nobody)
    assert checked.running["most"] == 1, "two checks ran at once"
    assert L._CacheStore.WAIT_SECONDS == L.TURN_WAIT_SECONDS, "waited for as long as an account's turn"
