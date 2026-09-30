"""An administrator's automatic lock always ends, and the server's operator can unlock any account from
the host, offline on a real database.

With a lockout duration of 0 (ACCOUNT_LOCKOUT_MINUTES=0, settable only in .env) an automatic lock has no
end: it lasts until an administrator clears it. Wrong passwords for every administrator's name (about
twenty each, from anywhere) then locked every administrator out for good, and the only documented way
back, an administrator's unlock, needed an administrator who could sign in. Now an administrator's
automatic lock has an end when the duration is 0 (15 minutes from one address; the account-wide pause
once its count has lost a failure, 72 minutes by default), a lock with no end that an administrator
already holds is given one, and `python dockvault.py accounts --action unlock` clears any account's
locks from the host. Other accounts, and names that are no account, keep a lock with no end.
test_administrator_lock_ends_live.py drives the host unlock on a running stack.
"""
import tempfile
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

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

THRESHOLD, MULTIPLE, WINDOW = 3, 2, 300
BACKSTOP = THRESHOLD * MULTIPLE
ATTACKER, HOME = "203.0.113.66", "198.51.100.10"
PASSWORD = "right-password-123"
T0 = datetime(2026, 9, 1, 12, 0, 0)


class _Clock:
    def __init__(self):
        self.t = T0


@pytest.fixture
def clock(monkeypatch):
    c = _Clock()
    monkeypatch.setattr(L, "utcnow", lambda: c.t)
    return c


@pytest.fixture
def limits(monkeypatch):
    values = {"max_login_attempts": THRESHOLD, "lockout_backstop_multiplier": MULTIPLE,
              "rate_limit_login_window_seconds": WINDOW, "lockout_duration": 0}
    monkeypatch.setattr(A.rate_limit_settings, "effective", lambda key: values[key])
    return values


@pytest.fixture
def Session():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'lockout.db'}", connect_args={"timeout": 60})
        for model in (User, AuditLog, SignInLockout):
            model.__table__.create(engine)
        yield sessionmaker(bind=engine, autocommit=False, autoflush=False)
        engine.dispose()


def _add(Session, role=RoleEnum.USER, **kw):
    s = Session()
    u = User(username=kw.pop("username", f"u_{uuid.uuid4().hex[:8]}"), password_hash=hash_password(PASSWORD),
             role=role, **kw)
    s.add(u)
    s.commit()
    uid = u.id
    s.close()
    return uid


def _fail(Session, uid, address):
    s = Session()
    try:
        A.AuthService(s)._record_failed_login("x", address, s.get(User, uid))
    finally:
        s.close()


def _lock(Session, uid, address):
    s = Session()
    try:
        return L.lock_in_force(s, uid, address)
    finally:
        s.close()


def _sign_in(Session, uid, address, password=None):
    password = password or PASSWORD
    s = Session()
    svc = A.AuthService(s)
    svc._check_rate_limit = lambda *a, **k: None
    svc._terminate_existing_sessions = lambda *a, **k: None
    svc._create_session = lambda *a, **k: "session-token"
    try:
        svc.authenticate_user(s.get(User, uid).username, password, address)
        return "signed in"
    except A.AccountLockedError as e:
        return ("locked", e.scope, e.locked_until)
    except A.InvalidCredentialsError:
        return "wrong"
    finally:
        s.close()


# --------------------------------------------------------------------------- arming, duration 0

def test_an_administrators_address_lock_ends_after_15_minutes_and_a_users_does_not(Session, limits, clock):
    admin, user = _add(Session, RoleEnum.ADMIN), _add(Session)
    for _ in range(THRESHOLD):
        _fail(Session, admin, ATTACKER)
        _fail(Session, user, ATTACKER)
    assert _lock(Session, admin, ATTACKER).locked_until == T0 + timedelta(minutes=L.ADMINISTRATOR_LOCK_MINUTES)
    assert _lock(Session, user, ATTACKER).locked_until is None

    clock.t = T0 + timedelta(minutes=L.ADMINISTRATOR_LOCK_MINUTES, seconds=1)
    assert _sign_in(Session, admin, ATTACKER) == "signed in"
    assert _sign_in(Session, user, ATTACKER)[:2] == ("locked", L.SCOPE_ADDRESS)


def test_an_administrators_account_wide_lock_ends_too(Session, limits, clock):
    admin, user = _add(Session, RoleEnum.ADMIN), _add(Session)
    for i in range(BACKSTOP):
        _fail(Session, admin, f"203.0.113.{i + 1}")
        _fail(Session, user, f"203.0.113.{i + 1}")
    lock = _lock(Session, admin, HOME)
    assert lock.scope == L.SCOPE_ACCOUNT
    # No sooner than the count has lost a failure (24 h / backstop), as any account-wide pause.
    assert lock.locked_until == T0 + max(timedelta(minutes=L.ADMINISTRATOR_LOCK_MINUTES),
                                         L.account_interval(BACKSTOP))
    user_lock = _lock(Session, user, HOME)
    assert user_lock.scope == L.SCOPE_ACCOUNT and user_lock.locked_until is None

    clock.t = lock.locked_until + timedelta(seconds=1)
    assert _sign_in(Session, admin, HOME) == "signed in"
    assert _sign_in(Session, user, HOME)[:2] == ("locked", L.SCOPE_ACCOUNT)


def test_a_duration_set_is_used_for_everyone(Session, limits, clock):
    limits["lockout_duration"] = 5
    admin = _add(Session, RoleEnum.ADMIN)
    for _ in range(THRESHOLD):
        _fail(Session, admin, ATTACKER)
    assert _lock(Session, admin, ATTACKER).locked_until == T0 + timedelta(minutes=5)


def test_the_lock_an_administrator_locked_administrators_count_would_arm_ends(Session, limits, clock):
    # An account an administrator locked arms no lock of its own; a password attempt at a count at its
    # limit is refused as the lock the next failure would arm (count_at_limit).
    admin = _add(Session, RoleEnum.ADMIN)
    for _ in range(THRESHOLD):
        _fail(Session, admin, ATTACKER)
    s = Session()
    s.query(SignInLockout).update({"locked_at": None, "locked_until": None})
    s.commit()
    assert L.count_at_limit(s, admin, ATTACKER, administrator=True).locked_until == \
        T0 + timedelta(minutes=L.ADMINISTRATOR_LOCK_MINUTES)
    assert L.count_at_limit(s, admin, ATTACKER).locked_until is None
    s.close()


def test_the_sign_in_path_passes_the_account_s_role_to_count_at_limit(Session, limits, clock, monkeypatch):
    seen = []
    real = L.count_at_limit

    def spy(db, user_id, address, **kw):
        seen.append(kw.get("administrator"))
        return real(db, user_id, address, **kw)

    monkeypatch.setattr(L, "count_at_limit", spy)
    for role in (RoleEnum.ADMIN, RoleEnum.USER):
        uid = _add(Session, role, is_locked=True, locked_until=None)     # locked by an administrator
        _sign_in(Session, uid, ATTACKER)
    assert seen == [True, False]


# --------------------------------------------------------------------------- locks armed with no end

def _seed_open_lock(Session, uid, source, *, armed=T0 - timedelta(hours=1), count=BACKSTOP):
    s = Session()
    s.add(SignInLockout(id=uuid.uuid4(), user_id=uid, source=source, failed_attempts=count,
                        window_start=armed, last_failure_at=armed, locked_at=armed, locked_until=None))
    s.commit()
    s.close()


def test_an_open_lock_an_administrator_holds_is_given_an_end_and_released(Session, limits, clock):
    admin, user = _add(Session, RoleEnum.ADMIN), _add(Session)
    for uid in (admin, user):
        _seed_open_lock(Session, uid, ATTACKER, count=THRESHOLD)
        _seed_open_lock(Session, uid, L.ACCOUNT_WIDE)
    s = Session()
    assert L.end_administrators_open_locks(s) == 2
    s.commit()
    ends = {r.source: r.locked_until for r in s.query(SignInLockout).filter(SignInLockout.user_id == admin)}
    armed = T0 - timedelta(hours=1)
    assert ends[ATTACKER] == armed + timedelta(minutes=L.ADMINISTRATOR_LOCK_MINUTES)
    assert ends[L.ACCOUNT_WIDE] == armed + max(timedelta(minutes=L.ADMINISTRATOR_LOCK_MINUTES),
                                               L.account_interval(BACKSTOP))
    assert all(r.locked_until is None
               for r in s.query(SignInLockout).filter(SignInLockout.user_id == user)), "a user's keeps no end"
    assert L.end_administrators_open_locks(s) == 0
    assert L.release_expired(s) == 1                 # the address lock; the pause runs 4 h from its arming
    s.commit()
    s.close()


def test_one_accounts_open_locks_only(Session, limits, clock):
    a, b = _add(Session, RoleEnum.ADMIN), _add(Session, RoleEnum.ADMIN)
    _seed_open_lock(Session, a, ATTACKER)
    _seed_open_lock(Session, b, ATTACKER)
    s = Session()
    assert L.end_administrators_open_locks(s, user_id=a) == 1
    s.commit()
    assert s.query(SignInLockout).filter(SignInLockout.user_id == b).one().locked_until is None
    s.close()


def test_an_administrator_with_a_lock_from_before_signs_in_once_it_has_run_out(Session, limits, clock):
    # A lock armed with no end by an earlier release, or while the account was not an administrator.
    admin = _add(Session, RoleEnum.ADMIN)
    _seed_open_lock(Session, admin, ATTACKER, count=THRESHOLD, armed=T0 - timedelta(minutes=16))
    assert _sign_in(Session, admin, ATTACKER) == "signed in"
    s = Session()
    (row,) = s.query(AuditLog).filter(AuditLog.action == L.AUTO_UNLOCKED_ACTION).all()
    assert row.details["scope"] == L.SCOPE_ADDRESS and row.details["cleared_by"] == "sign_in"
    s.close()


def test_a_recent_one_still_refuses_until_it_has(Session, limits, clock):
    admin = _add(Session, RoleEnum.ADMIN)
    _seed_open_lock(Session, admin, ATTACKER, count=THRESHOLD, armed=T0 - timedelta(minutes=5))
    result = _sign_in(Session, admin, ATTACKER)
    assert result[:2] == ("locked", L.SCOPE_ADDRESS) and result[2] == T0 + timedelta(minutes=10)


def test_a_user_with_such_a_lock_stays_locked(Session, limits, clock):
    user = _add(Session)
    _seed_open_lock(Session, user, ATTACKER, count=THRESHOLD, armed=T0 - timedelta(days=3))
    assert _sign_in(Session, user, ATTACKER) == ("locked", L.SCOPE_ADDRESS, None)


def test_the_periodic_release_gives_those_locks_an_end_first_and_keeps_it():
    import inspect
    from app.api import api_server
    source = inspect.getsource(api_server.cleanup_expired_sessions)
    assert source.count("sign_in_lockout.end_administrators_open_locks(db)") == 1
    assert source.count("sign_in_lockout.release_expired(db)") == 1
    block = source[source.index("sign_in_lockout.end_administrators_open_locks(db)"):]
    block = block[:block.index("except Exception as lockout_err")]
    assert block.index("end_administrators_open_locks") < block.index("release_expired")
    assert block.count("db.commit()") == 1 and "if " not in block.split("db.commit()")[0].split("prune_stale")[1]


# --------------------------------------------------------------------------- names that are no account

class _Store:
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


def test_a_name_that_is_no_account_keeps_a_lock_with_no_end_like_an_ordinary_account(limits, clock, monkeypatch):
    store = _Store(clock)
    monkeypatch.setattr(L, "_phantom_store", lambda: store)
    for _ in range(THRESHOLD):
        L.phantom_failure("nobody-here", ATTACKER)
    clock.t = T0 + timedelta(minutes=L.ADMINISTRATOR_LOCK_MINUTES + 1)
    lock = L.phantom_lock("nobody-here", ATTACKER)
    assert lock is not None and lock.locked_until is None


# --------------------------------------------------------------------------- the host unlock

def test_the_host_tool_unlocks_an_account_and_records_it_as_the_host_operators(Session, limits, clock,
                                                                                monkeypatch):
    from app.core import credential_changes as cc
    from app.core import database, host_operator
    uid = _add(Session, RoleEnum.ADMIN, username="root2")
    for i in range(BACKSTOP):          # an address lock at ATTACKER, then the account-wide one
        _fail(Session, uid, ATTACKER if i < THRESHOLD else f"203.0.113.{i + 1}")
    s = Session()                      # and an administrator's lock on top
    s.query(User).filter(User.id == uid).update({"is_locked": True, "locked_until": None,
                                                  "failed_login_attempts": 7})
    s.commit()
    s.close()

    @contextmanager
    def ctx():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    monkeypatch.setattr(database, "get_db_context", ctx)
    told = []
    api = SimpleNamespace(_notify_account_status_changes=lambda db, user, **kw: told.append((user.username, kw)))
    args = host_operator.build_parser().parse_args(["unlock", "--username", "root2", "--confirm-username", "root2"])
    with pytest.raises(host_operator._Answer) as done:
        host_operator._run(args, api)
    assert done.value.code == 0
    assert done.value.obj == {"ok": True, "account": "root2", "was_locked": True, "sign_in_locks_cleared": 2}

    s = Session()
    account = s.get(User, uid)
    assert (account.is_locked, account.locked_until, account.failed_login_attempts) == (False, None, 0)
    assert s.query(SignInLockout).filter(SignInLockout.user_id == uid).count() == 0
    (row,) = s.query(AuditLog).filter(AuditLog.action == "USER_LOCK_CHANGED").all()
    assert row.username == cc.HOST_OPERATOR and row.resource_id == str(uid)
    assert row.details["was_locked"] is True and row.details["sign_in_locks_cleared"] == 2
    s.close()
    assert told == [("root2", {"by_name": cc.HOST_OPERATOR, "locked": (True, False), "sign_in_locks_cleared": 2})]


def test_the_host_unlock_needs_the_username_typed_again(Session, limits, clock, monkeypatch):
    from app.core import database, host_operator
    uid = _add(Session, username="alice", is_locked=True)

    @contextmanager
    def ctx():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    monkeypatch.setattr(database, "get_db_context", ctx)
    args = host_operator.build_parser().parse_args(["unlock", "--username", "alice", "--confirm-username", "alicE"])
    with pytest.raises(host_operator._Answer) as done:
        host_operator._run(args, SimpleNamespace())
    assert done.value.code == 2 and not done.value.obj["ok"]
    s = Session()
    assert s.get(User, uid).is_locked is True
    s.close()


# --------------------------------------------------------------------------- the update pre-check

def _cli():
    import importlib.util
    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("dockvault_cli_lock", root / "dockvault.py")
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    return cli


@pytest.mark.parametrize("env,current,target,flagged", [
    ({"ACCOUNT_LOCKOUT_MINUTES": "0"}, "0.33.0", "v0.33.1", True),
    ({"ACCOUNT_LOCKOUT_MINUTES": " 0 "}, "0.32.6", "0.34.0", True),
    ({"ACCOUNT_LOCKOUT_MINUTES": "0"}, "unknown", "v0.33.1", True),      # where it starts is not known
    ({"ACCOUNT_LOCKOUT_MINUTES": "0"}, "0.33.1", "v0.34.0", False),      # already has it
    ({"ACCOUNT_LOCKOUT_MINUTES": "0"}, "0.32.6", "v0.33.0", False),      # does not reach it
    ({"ACCOUNT_LOCKOUT_MINUTES": "15"}, "0.33.0", "v0.33.1", False),
    ({"ACCOUNT_LOCKOUT_MINUTES": ""}, "0.33.0", "v0.33.1", False),
    ({"ACCOUNT_LOCKOUT_MINUTES": "zero"}, "0.33.0", "v0.33.1", False),
    ({}, "0.33.0", "v0.33.1", False),
    ({"TRUSTED_PROXIES": "172.16.0.0/12", "RATE_LIMIT_LOGIN_ATTEMPTS": "0"}, "0.33.0", "v0.33.1", False),
])
def test_the_update_pre_check_names_a_lockout_duration_of_0_and_nothing_else(env, current, target, flagged):
    notes = _cli().env_upgrade_notes(env, current, target)
    assert bool(notes) == flagged
    if flagged:
        (note,) = notes
        assert "ACCOUNT_LOCKOUT_MINUTES=0" in note and "15 minutes" in note
        assert "accounts --action unlock" in note
        assert "72 minutes" in note, "the pause from every address ends later than the 15 minutes"
        assert "before 0.33.0" in note, "a lock an older release armed stays, like an administrator's"


def test_the_documented_end_of_an_administrators_lock_names_both_locks():
    # With a duration of 0 a lock from one address ends after 15 minutes, and the account-wide pause
    # no sooner than its count has lost a failure (72 minutes with the defaults), not after 15.
    root = Path(__file__).resolve().parent.parent
    example = (root / ".env.example").read_text(encoding="utf-8")
    example = example[example.index("# Failed sign-ins lock an account against new sign-ins"):
                      example.index("\nACCOUNT_LOCKOUT_MINUTES=")]
    config = (root / "app" / "core" / "config.py").read_text(encoding="utf-8")
    config = config[config.index("# How long (minutes) new sign-ins stay refused"):
                    config.index("account_lockout_minutes: int")]
    for text in (example, config):
        assert text.count("15 minutes") == 1 and text.count("72 minutes") == 1, text


def test_the_host_tool_offers_the_unlock():
    from app.core import host_operator
    cli = _cli()
    assert "unlock" in dict(cli.ACCOUNT_ACTIONS) and "unlock" in host_operator.ACTIONS
