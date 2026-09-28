"""Smart lockout, offline, on a real database.

Wrong passwords count per account and source address, and across all addresses. At the login limit
new sign-ins to the account from THAT address are refused for the lockout duration; at the limit times
the backstop multiple within the login window they are refused from EVERY address. A refusal happens
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
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'lockout.db'}")
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


def test_the_account_wide_count_is_within_the_login_window(Session, limits):
    uid = _add_user(Session)
    for i in range(THRESHOLD * MULTIPLE - 1):
        _fail(Session, uid, f"203.0.113.{i}")
    s = Session()
    s.query(SignInLockout).filter(SignInLockout.source == L.ACCOUNT_WIDE).update(
        {"window_start": _now() - timedelta(seconds=WINDOW + 1)})
    s.commit()
    s.close()
    _fail(Session, uid, "203.0.113.200")   # the old window is over: this one starts a new count
    assert _lock(Session, uid, HOME) is None
    s = Session()
    assert s.query(SignInLockout).filter(SignInLockout.source == L.ACCOUNT_WIDE).one().failed_attempts == 1
    s.close()


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

class _FakeLimiter:
    """The cache's sliding window, in memory: counts per key, and a peek that never counts."""

    def __init__(self):
        self.counts = {}

    def check_rate_limit(self, key, limit, window, prefix="rate_limit", fail_open=False):
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key] <= limit, max(0, limit - self.counts[key]), 0

    def peek_rate_limit(self, key, limit, window, prefix="rate_limit"):
        return self.counts.get(key, 0) >= limit, 60


def test_a_name_that_is_no_account_is_refused_at_the_same_point(Session, limits, monkeypatch):
    from app.core import rate_limiter as rl
    monkeypatch.setattr(rl, "rate_limiter", _FakeLimiter())
    uid = _add_user(Session, username="real-person")

    def attempt(name):
        s = Session()
        svc = A.AuthService(s)
        svc._check_rate_limit = lambda *a, **k: None
        try:
            svc.authenticate_user(name, "a-guess", ATTACKER)
        except A.AccountLockedError as e:
            return ("refused", e.scope)
        except A.InvalidCredentialsError:
            return ("wrong",)
        finally:
            s.close()

    for name in ("real-person", "nobody-here"):
        seen = [attempt(name) for _ in range(THRESHOLD + 1)]
        assert seen == [("wrong",)] * THRESHOLD + [("refused", "address")], (name, seen)
    assert _lock(Session, uid, ATTACKER) is not None


def test_the_name_mimicry_fails_open_when_the_cache_is_down(monkeypatch, limits):
    from app.core import rate_limiter as rl

    class _Down:
        def check_rate_limit(self, *a, **k):
            raise rl.RateLimiterUnavailable("down")

        def peek_rate_limit(self, *a, **k):
            raise rl.RateLimiterUnavailable("down")

    monkeypatch.setattr(rl, "rate_limiter", _Down())
    L.phantom_failure("nobody", ATTACKER)       # never raises
    assert L.phantom_lock("nobody", ATTACKER) is None
