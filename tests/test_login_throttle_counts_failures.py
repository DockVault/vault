"""The sign-in throttle counts failed attempts only, offline.

Each sign-in attempt is charged to two buckets before any password is checked: its name from its
address (the login limit, 5 by default) and its address (twice that). Nothing was ever given back, so
right passwords counted too: the sixth sign-in to one account in five minutes from one address was
refused, and everyone behind one address (an office, a reverse proxy without TRUSTED_PROXIES) shared
ten sign-ins per five minutes. Since 0.33.0 the smart lockout bounds guessing, and a right password is
not a guess: a sign-in that succeeds now gives its charges back (RateLimiter.release, and the database
fallback's count while the cache is down). Attempts are still charged before the check, so parallel
guesses cannot pass the limit. A device's sync bucket keeps counting successes, which is what it is for.
test_login_throttle.py drives the same on a running stack, with the cache and without it.
"""
import tempfile
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import rate_limiter as R  # noqa: E402
from app.core.models import AuditLog, RateLimitRecord, RoleEnum, SignInLockout, User  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.services import auth_service as A  # noqa: E402

pytestmark = pytest.mark.unit

LIMIT = 5
HOME = "198.51.100.10"
PASSWORD = "right-password-123"


class _Redis:
    """The sorted sets the sliding-window script keeps, with the script's own steps: prune what fell out
    of the window, refuse at the limit, else add the entry."""

    def __init__(self):
        self.sets = {}

    def _script(self, script, numkeys, key, window_start, now, limit, ttl, entry_id, window):
        assert script is R.RateLimiter._SLIDING_WINDOW_SCRIPT
        members = self.sets.setdefault(key, {})
        for member, score in list(members.items()):
            if score <= float(window_start):
                del members[member]
        if len(members) >= int(limit):
            return [0, 0, str(int(float(now)) + int(window))]
        members[entry_id] = float(now)
        return [1, int(limit) - len(members), str(int(float(now)) + int(window))]

    eval = _script

    def zrem(self, key, member):
        return 1 if self.sets.get(key, {}).pop(member, None) is not None else 0

    def count(self, prefix):
        return sum(len(m) for k, m in self.sets.items() if k.startswith(prefix))


@pytest.fixture(autouse=True)
def _breaker_closed():
    R._cb_record_success()
    yield
    R._cb_record_success()


@pytest.fixture
def cache(monkeypatch):
    redis = _Redis()
    monkeypatch.setattr(R, "rate_limiter", R.RateLimiter(redis))
    return redis


@pytest.fixture
def limits(monkeypatch):
    values = {"max_login_attempts": LIMIT, "lockout_backstop_multiplier": 1000,
              "rate_limit_login_window_seconds": 300, "lockout_duration": 15}
    monkeypatch.setattr(A.rate_limit_settings, "effective", lambda key: values[key])
    return values


@pytest.fixture
def Session():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'throttle.db'}", connect_args={"timeout": 60})
        for model in (User, AuditLog, SignInLockout, RateLimitRecord):
            model.__table__.create(engine)
        yield sessionmaker(bind=engine, autocommit=False, autoflush=False)
        engine.dispose()


def _add(Session, name=None):
    s = Session()
    u = User(username=name or f"u_{uuid.uuid4().hex[:8]}", password_hash=hash_password(PASSWORD),
             role=RoleEnum.USER)
    s.add(u)
    s.commit()
    name = u.username
    s.close()
    return name


def _sign_in(Session, name, password=None, address=HOME):
    s = Session()
    svc = A.AuthService(s)
    svc._terminate_existing_sessions = lambda *a, **k: None
    svc._create_session = lambda *a, **k: "session-token"
    try:
        svc.authenticate_user(name, password or PASSWORD, address)
        return 200
    except A.RateLimitExceededError:
        return 429
    except A.AccountLockedError:
        return 403
    except A.InvalidCredentialsError:
        return 401
    finally:
        s.close()


# --------------------------------------------------------------------------- the limiter

def test_a_named_charge_is_given_back_and_only_that_one(cache):
    rl = R.rate_limiter
    assert rl.check_rate_limit("login_ip:x", 3, 60, fail_open=False, entry_id="mine")[0]
    assert rl.check_rate_limit("login_ip:x", 3, 60, fail_open=False)[0]
    assert cache.count("rate_limit:login_ip:x") == 2
    assert rl.release("login_ip:x", "mine") is True
    assert cache.count("rate_limit:login_ip:x") == 1
    assert rl.release("login_ip:x", "mine") is False, "given back once"
    assert rl.release("login_ip:x", "someone-else") is False


def test_giving_back_never_raises_and_skips_an_open_breaker(monkeypatch):
    class _Down:
        def zrem(self, *a):
            raise ConnectionError("down")
    assert R.RateLimiter(_Down()).release("login_ip:x", "mine") is False

    calls = []

    class _Tripwire:
        def zrem(self, *a):
            calls.append(a)
            return 1
    R._cb_record_failure(time.time())
    assert R.RateLimiter(_Tripwire()).release("login_ip:x", "mine") is False
    assert calls == [], "the cache was reached while the breaker was open"


# --------------------------------------------------------------------------- sign-ins, with the cache

def test_twelve_right_passwords_in_a_row_from_one_address_all_sign_in(Session, limits, cache):
    name = _add(Session)
    assert [_sign_in(Session, name) for _ in range(12)] == [200] * 12
    assert cache.count("rate_limit:") == 0, "every charge was given back"


def test_eleven_accounts_behind_one_address_all_sign_in(Session, limits, cache):
    names = [_add(Session) for _ in range(11)]
    assert [_sign_in(Session, n) for n in names] == [200] * 11


def test_wrong_passwords_are_still_refused_at_the_limit_for_a_name(Session, limits, cache):
    name = _add(Session)
    assert [_sign_in(Session, name, "wrong") for _ in range(LIMIT + 1)] == [401] * LIMIT + [429]


def test_wrong_passwords_are_still_refused_at_twice_the_limit_for_an_address(Session, limits, cache):
    names = [_add(Session) for _ in range(2 * LIMIT + 1)]
    seen = [_sign_in(Session, n, "wrong") for n in names]
    assert seen == [401] * (2 * LIMIT) + [429]


def test_a_right_password_gives_back_its_own_charge_and_not_the_failures(Session, limits, cache):
    name = _add(Session)
    assert [_sign_in(Session, name, "wrong") for _ in range(LIMIT - 1)] == [401] * (LIMIT - 1)
    assert _sign_in(Session, name) == 200
    # Four failures still count: one more is allowed, the next is refused.
    assert [_sign_in(Session, name, "wrong") for _ in range(2)] == [401, 429]


def test_a_name_that_is_no_account_keeps_its_charges(Session, limits, cache, monkeypatch):
    from app.core import sign_in_lockout as L
    monkeypatch.setattr(L, "phantom_attempt", lambda name, address, check: (check(), None)[1])
    assert [_sign_in(Session, "nobody-here", "x") for _ in range(LIMIT + 1)] == [401] * LIMIT + [429]


def test_a_refusal_after_the_password_keeps_its_charges(Session, limits, cache):
    # The right password for an account an administrator locked, or deactivated: refused, and counted.
    name = _add(Session)
    s = Session()
    s.query(User).filter(User.username == name).update({"is_active": False})
    s.commit()
    s.close()
    assert [_sign_in(Session, name) for _ in range(LIMIT + 1)] == [401] * LIMIT + [429]


# --------------------------------------------------------------------------- sign-ins, cache down

@pytest.fixture
def cache_down(monkeypatch, limits):
    """The cache unreachable: the throttle falls back to a fixed-window count in the database. Here the
    count is kept in memory with the same rules (_db_throttle_charge / _db_throttle_release)."""
    counts = {}

    def charge(identifier, action, limit, window):
        start = datetime(2026, 9, 1)
        counts[(identifier, action)] = counts.get((identifier, action), 0) + 1
        if counts[(identifier, action)] > limit:
            return False, 30, None
        return True, 0, (identifier, action, start)

    def release(identifier, action, window_start):
        assert window_start == datetime(2026, 9, 1)
        counts[(identifier, action)] = max(0, counts.get((identifier, action), 0) - 1)

    class _Unavailable:
        def check_rate_limit(self, *a, **k):
            raise R.RateLimiterUnavailable("down")

        def release(self, *a, **k):
            raise AssertionError("a database charge given back to the cache")

    monkeypatch.setattr(R, "rate_limiter", _Unavailable())
    monkeypatch.setattr(A.AuthService, "_db_throttle_charge", staticmethod(charge))
    monkeypatch.setattr(A.AuthService, "_db_throttle_release", staticmethod(release))
    return counts


def test_with_the_cache_down_right_passwords_are_given_back_too(Session, cache_down):
    name = _add(Session)
    assert [_sign_in(Session, name) for _ in range(12)] == [200] * 12
    assert all(v == 0 for v in cache_down.values())


def test_with_the_cache_down_wrong_passwords_are_still_refused(Session, cache_down):
    name = _add(Session)
    assert [_sign_in(Session, name, "wrong") for _ in range(LIMIT + 1)] == [401] * LIMIT + [429]
    names = [_add(Session) for _ in range(2 * LIMIT + 1)]
    for n in names[:LIMIT]:
        _sign_in(Session, n, "wrong")
    assert _sign_in(Session, names[-1]) == 429, "the address has had twice the limit of failures"


def test_the_database_count_given_back_is_that_windows_and_never_below_zero(Session, monkeypatch):
    s = Session()
    start = datetime(2026, 9, 1, 12, 0, 0)
    s.add(RateLimitRecord(id=uuid.uuid4(), identifier="198.51.100.10", action="login_ip", attempt_count=2,
                          window_start=start, last_attempt=start))
    s.commit()

    @contextmanager
    def ctx():
        session = Session()
        try:
            yield session
            session.commit()
        finally:
            session.close()

    monkeypatch.setattr(A, "get_db_context", ctx)
    A.AuthService._db_throttle_release("198.51.100.10", "login_ip", start)
    A.AuthService._db_throttle_release("198.51.100.10", "login_ip", start - timedelta(minutes=5))  # an older window
    s.expire_all()
    assert s.query(RateLimitRecord).one().attempt_count == 1
    for _ in range(3):
        A.AuthService._db_throttle_release("198.51.100.10", "login_ip", start)
    s.expire_all()
    assert s.query(RateLimitRecord).one().attempt_count == 0
    s.close()


# --------------------------------------------------------------------------- temporary credentials

class _Q:
    def __init__(self, result):
        self.result = result

    def filter(self, *a, **k):
        return self

    def first(self):
        return self.result

    def update(self, *a, **k):
        return 1


class _DB:
    def __init__(self, cred):
        self.cred = cred

    def query(self, model, *a):
        return _Q(self.cred if model is A.TemporaryCredential else None)

    def commit(self):
        pass


def _cred(device_id):
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    user = type("U", (), {"is_active": True, "is_locked": False, "locked_until": None, "role": RoleEnum.USER})()
    return type("C", (), {"id": uuid.uuid4(), "device_id": device_id, "credential_hash": "h", "is_active": True,
                          "is_used": False, "expires_at": future, "deactivate_at": None, "user": user})()


@pytest.mark.parametrize("device_id,door_web,given_back", [
    (None, False, "username"),       # the SFTP door, a credential with no device: its own name's bucket
    (None, True, "login"),           # the web door: the login buckets
    ("dev-1", False, None),          # a device's sync credential: its bucket keeps counting
])
def test_a_temporary_credential_that_signs_in_gives_back_its_login_charges(monkeypatch, device_id, door_web,
                                                                            given_back):
    svc = A.AuthService.__new__(A.AuthService)
    svc.db = _DB(_cred(device_id))
    svc._check_rate_limit = lambda *a, **k: {"charges": [("cache", "login", "e1")]}
    svc._check_username_rate_limit = lambda *a, **k: {"charges": [("cache", "username", "e2")]}
    svc._check_device_rate_limit = lambda *a, **k: {"charges": [("cache", "device", "e3")]}
    svc._create_session = lambda *a, **k: "session-token"
    monkeypatch.setattr(A, "verify_temporary_credential", lambda *a, **k: True)
    monkeypatch.setattr("app.core.temp_scope.attach_scope", lambda *a, **k: None)
    back = []
    monkeypatch.setattr(A.AuthService, "_give_back", lambda self, throttle: back.append(throttle))
    if door_web and device_id is not None:
        pytest.skip("the web door refuses a device's credential")
    svc.authenticate_temporary_credential("temp_x", "cred", HOME, allow_device_credential=not door_web)
    assert [t["charges"][0][1] for t in back if t] == ([given_back] if given_back else [])
