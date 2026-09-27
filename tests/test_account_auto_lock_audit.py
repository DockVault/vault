"""Failed sign-ins that lock an account, and the timer that unlocks it, are both audited.

Enough wrong passwords lock an account for a while, and the lock lifts by itself when the time runs
out. Neither was recorded: every failure wrote the same "Invalid username or password" login_failure
row whether or not it armed the lock, and the unlock wrote nothing, so a lock could only be inferred
by counting. Now the failure that arms the lock writes an ``account_auto_locked`` row (the account,
the address, the count and when the lock ends), and each release writes ``account_auto_unlocked``,
saying whether the timer or a sign-in cleared it. Each row is added to the transaction that makes
the change, so the two commit together or not at all.

The failure count is also kept in the database now. It was read into Python, increased by one and
written back, so failures arriving together each wrote the same number and all but one were lost.

These run the real code against the real users and audit_logs tables in a throwaway SQLite database.
test_account_auto_lock_audit_live.py drives the same through sign-in on a running stack, including
failures sent in parallel.

The rows are built by AuditLogger.build_row, so they get what every audit row gets (the request's
channel, method, route and user agent, and the name redaction) while committing with the lock itself.
"""
import re
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import request_context as rc  # noqa: E402
from app.core.models import AuditLog, RoleEnum, User  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.services import auth_service as A  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
MAX_ATTEMPTS = 3
LOCK_MINUTES = 15
IP = "203.0.113.7"


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


@pytest.fixture
def limits(monkeypatch):
    values = {"max_login_attempts": MAX_ATTEMPTS, "lockout_duration": LOCK_MINUTES}
    monkeypatch.setattr(A.rate_limit_settings, "effective", lambda key: values[key])
    return values


@pytest.fixture
def db_factory():
    """A file-backed database, so two sessions can see each other's commits."""
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'locks.db'}")
        User.__table__.create(engine)
        AuditLog.__table__.create(engine)
        # The application's own session flags.
        yield sessionmaker(bind=engine, autocommit=False, autoflush=False)
        engine.dispose()


def _add_user(Session, **kw):
    s = Session()
    u = User(username=kw.pop("username", f"u_{uuid.uuid4().hex[:8]}"),
             password_hash=hash_password("right-password-123"), role=RoleEnum.USER, **kw)
    s.add(u)
    s.commit()
    uid = u.id
    s.close()
    return uid


def _load(Session, uid):
    s = Session()
    return s, s.query(User).filter(User.id == uid).first()


def _rows(Session, action):
    s = Session()
    try:
        return s.query(AuditLog).filter(AuditLog.action == action).order_by(AuditLog.timestamp).all()
    finally:
        s.close()


def _fail(Session, uid, ip=IP):
    s, user = _load(Session, uid)
    try:
        A.AuthService(s)._record_failed_login(user.username, ip, user)
    finally:
        s.close()


def _state(Session, uid):
    s, user = _load(Session, uid)
    try:
        return user.failed_login_attempts, user.is_locked, user.locked_until
    finally:
        s.close()


# --------------------------------------------------------------------------- the failure count

def test_a_failure_adds_one_to_the_stored_count_not_to_the_one_this_request_loaded(db_factory, limits):
    """The lost update, made deterministic: another request's failures commit after this one loaded
    the account. The old read-add-write stored 1 here, overwriting them."""
    uid = _add_user(db_factory)
    s, user = _load(db_factory, uid)
    assert user.failed_login_attempts == 0

    other = db_factory()
    other.query(User).filter(User.id == uid).update({"failed_login_attempts": 2})
    other.commit()
    other.close()

    try:
        A.AuthService(s)._record_failed_login(user.username, IP, user)
        assert user.failed_login_attempts == 3, "the in-memory copy follows the stored count"
    finally:
        s.close()
    assert _state(db_factory, uid)[0] == 3


def test_the_count_is_not_computed_in_python():
    src = (ROOT / "app" / "services" / "auth_service.py").read_text(encoding="utf-8")
    start = src.index("    def _record_failed_login(")
    end = re.compile(r"^(    )?(def|class) ", re.M).search(src, start + 10)
    body = src[start:end.start() if end else len(src)]
    assert "self.db.commit()" in body, "the slice did not reach the end of the method"
    code = [ln for ln in body.splitlines() if not ln.strip().startswith("#")]
    assert not [ln for ln in code if "failed_login_attempts +=" in ln]
    assert ".returning(users.c.failed_login_attempts, users.c.is_locked, users.c.locked_until)" in body


# --------------------------------------------------------------------------- arming the lock

def test_the_failure_that_arms_the_lock_is_recorded_once(db_factory, limits):
    uid = _add_user(db_factory)
    for _ in range(MAX_ATTEMPTS - 1):
        _fail(db_factory, uid)
    assert _rows(db_factory, A.AUTO_LOCKED_ACTION) == [], "no row before the lock is armed"
    assert _state(db_factory, uid)[1] is False

    before = _now()
    _fail(db_factory, uid)
    count, locked, until = _state(db_factory, uid)
    assert (count, locked) == (MAX_ATTEMPTS, True)
    assert before + timedelta(minutes=LOCK_MINUTES - 1) < until < _now() + timedelta(minutes=LOCK_MINUTES + 1)

    rows = _rows(db_factory, A.AUTO_LOCKED_ACTION)
    assert len(rows) == 1
    row = rows[0]
    assert row.user_id == uid and row.resource_id == str(uid) and row.resource_type == "user"
    assert row.ip_address == IP and row.status == "success"
    assert row.details == {"failed_attempts": MAX_ATTEMPTS, "locked_until": until.isoformat()}

    # Failures against the running lock move its end but do not record it again.
    _fail(db_factory, uid)
    _fail(db_factory, uid)
    assert _state(db_factory, uid)[0] == MAX_ATTEMPTS + 2
    assert len(_rows(db_factory, A.AUTO_LOCKED_ACTION)) == 1


def test_an_administrators_lock_is_never_turned_into_a_timed_one_or_recorded_as_automatic(db_factory, limits):
    uid = _add_user(db_factory, is_locked=True, locked_until=None, failed_login_attempts=MAX_ATTEMPTS)
    _fail(db_factory, uid)
    count, locked, until = _state(db_factory, uid)
    assert (count, locked, until) == (MAX_ATTEMPTS + 1, True, None)
    assert _rows(db_factory, A.AUTO_LOCKED_ACTION) == []


def test_a_lock_armed_after_an_expired_one_is_recorded(db_factory, limits):
    """An expired lock that nothing has cleared yet is not a running lock: the next lock is new."""
    uid = _add_user(db_factory, is_locked=True, locked_until=_now() - timedelta(minutes=1),
                    failed_login_attempts=MAX_ATTEMPTS)
    _fail(db_factory, uid)
    assert _state(db_factory, uid)[1] is True
    assert len(_rows(db_factory, A.AUTO_LOCKED_ACTION)) == 1


def test_a_failure_for_an_unknown_name_records_nothing(db_factory, limits):
    s = db_factory()
    try:
        A.AuthService(s)._record_failed_login("nobody", IP)
    finally:
        s.close()
    assert _rows(db_factory, A.AUTO_LOCKED_ACTION) == []


# --------------------------------------------------------------------------- releasing the lock

def test_the_timer_releases_only_expired_timed_locks_and_records_each(db_factory):
    expired = _add_user(db_factory, is_locked=True, locked_until=_now() - timedelta(minutes=2),
                        failed_login_attempts=5)
    running = _add_user(db_factory, is_locked=True, locked_until=_now() + timedelta(minutes=10),
                        failed_login_attempts=5)
    admin_lock = _add_user(db_factory, is_locked=True, locked_until=None, failed_login_attempts=1)
    open_ = _add_user(db_factory)
    expired_until = _state(db_factory, expired)[2]

    s = db_factory()
    try:
        assert A.release_expired_locks(s) == 1
        s.commit()
    finally:
        s.close()

    assert _state(db_factory, expired) == (0, False, None)
    assert _state(db_factory, running)[1] is True
    assert _state(db_factory, admin_lock) == (1, True, None)
    assert _state(db_factory, open_)[1] is False

    rows = _rows(db_factory, A.AUTO_UNLOCKED_ACTION)
    assert len(rows) == 1
    row = rows[0]
    assert row.user_id == expired and row.resource_id == str(expired) and row.ip_address is None
    assert row.details == {"locked_until": expired_until.isoformat(), "failed_attempts": 5,
                           "cleared_by": "timer"}

    s = db_factory()
    try:
        assert A.release_expired_locks(s) == 0, "a second pass finds nothing left to release"
    finally:
        s.close()


def test_nothing_is_released_unless_the_caller_commits(db_factory):
    uid = _add_user(db_factory, is_locked=True, locked_until=_now() - timedelta(minutes=2))
    s = db_factory()
    try:
        assert A.release_expired_locks(s) == 1
        s.rollback()
    finally:
        s.close()
    assert _state(db_factory, uid)[1] is True
    assert _rows(db_factory, A.AUTO_UNLOCKED_ACTION) == []


def test_a_sign_in_releases_its_own_expired_lock_and_records_where_it_came_from(db_factory, limits):
    uid = _add_user(db_factory, is_locked=True, locked_until=_now() - timedelta(minutes=2),
                    failed_login_attempts=MAX_ATTEMPTS)
    other = _add_user(db_factory, is_locked=True, locked_until=_now() - timedelta(minutes=2))

    s, user = _load(db_factory, uid)
    svc = A.AuthService(s)
    svc._check_rate_limit = lambda *a, **k: None
    try:
        with pytest.raises(A.InvalidCredentialsError):
            svc.authenticate_user(user.username, "wrong-password", IP)
    finally:
        s.close()

    # Released before the password was checked, so the wrong password counts from zero again.
    assert _state(db_factory, uid) == (1, False, None)
    assert _state(db_factory, other)[1] is True, "a sign-in releases only its own account"
    rows = _rows(db_factory, A.AUTO_UNLOCKED_ACTION)
    assert len(rows) == 1
    assert rows[0].user_id == uid and rows[0].ip_address == IP
    assert rows[0].details["cleared_by"] == "sign_in"


def test_a_sign_in_with_the_right_password_after_the_lock_expired_succeeds(db_factory, limits):
    uid = _add_user(db_factory, is_locked=True, locked_until=_now() - timedelta(minutes=2),
                    failed_login_attempts=MAX_ATTEMPTS)
    s, user = _load(db_factory, uid)
    svc = A.AuthService(s)
    svc._check_rate_limit = lambda *a, **k: None
    svc._terminate_existing_sessions = lambda *a, **k: None
    svc._create_session = lambda *a, **k: "session-token"
    try:
        signed_in, token = svc.authenticate_user(user.username, "right-password-123", IP)
        assert token == "session-token" and signed_in.is_locked is False
    finally:
        s.close()
    assert _state(db_factory, uid) == (0, False, None)
    assert [r.details["cleared_by"] for r in _rows(db_factory, A.AUTO_UNLOCKED_ACTION)] == ["sign_in"]


# --------------------------------------------------------------------------- wiring

def test_the_periodic_cleanup_releases_through_the_audited_path():
    src = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    reaper = src[src.index("async def cleanup_expired_sessions"):]
    reaper = reaper[:reaper.index("\ndef ")]
    assert "unlocked = release_expired_locks(db)" in reaper
    # The old bulk update, which released locks without recording them, is gone.
    assert not re.search(r'\{"is_locked": False, "failed_login_attempts": 0', reaper)


def test_a_lock_row_goes_through_the_loggers_name_redaction(db_factory):
    from app.services.audit_logger import REDACTED_NAME_KEYS
    s = db_factory()
    try:
        row = A._lock_audit_row(s, A.AUTO_LOCKED_ACTION, uuid.uuid4(), "maria", IP,
                                {"failed_attempts": 3, **{k: "a name" for k in REDACTED_NAME_KEYS}})
    finally:
        s.close()
    assert row.details == {"failed_attempts": 3}


# --------------------------------------------------------------------------- one transaction, one row

class _Route:
    path = "/auth/login"


@pytest.fixture(params=["web", "sftp"])
def signing_in(request):
    """A sign-in as each server sees it: a web request, or the SFTP process, whose every row is
    on the SFTP channel. Yields what the rows it writes should carry."""
    if request.param == "web":
        token = rc.set_request_context(rc.RequestContext("POST", "/auth/login", "Mozilla/5.0", "web",
                                                         {"route": _Route()}))
        yield ("web", "POST", "/auth/login", "Mozilla/5.0")
        rc.reset_request_context(token)
    else:
        rc.set_process_default_channel("sftp")
        yield ("sftp", None, None, None)
        rc.set_process_default_channel(None)


def _request_fields(row):
    return (row.channel, row.method, row.endpoint, row.user_agent)


def test_the_lock_row_carries_the_sign_in_that_armed_it(db_factory, limits, signing_in):
    uid = _add_user(db_factory, failed_login_attempts=MAX_ATTEMPTS - 1)
    _fail(db_factory, uid)
    (row,) = _rows(db_factory, A.AUTO_LOCKED_ACTION)
    assert _request_fields(row) == signing_in and row.ip_address == IP


def test_the_unlock_row_carries_the_sign_in_that_cleared_it(db_factory, limits, signing_in):
    uid = _add_user(db_factory, is_locked=True, locked_until=_now() - timedelta(minutes=2),
                    failed_login_attempts=MAX_ATTEMPTS)
    s, user = _load(db_factory, uid)
    svc = A.AuthService(s)
    svc._check_rate_limit = lambda *a, **k: None
    try:
        with pytest.raises(A.InvalidCredentialsError):
            svc.authenticate_user(user.username, "wrong-password", IP)
    finally:
        s.close()
    (row,) = _rows(db_factory, A.AUTO_UNLOCKED_ACTION)
    assert _request_fields(row) == signing_in and row.ip_address == IP


def test_the_timer_unlock_row_has_no_request(db_factory):
    """The periodic cleanup runs outside any request: no channel, route or address."""
    _add_user(db_factory, is_locked=True, locked_until=_now() - timedelta(minutes=2))
    s = db_factory()
    try:
        assert A.release_expired_locks(s) == 1
        s.commit()
    finally:
        s.close()
    (row,) = _rows(db_factory, A.AUTO_UNLOCKED_ACTION)
    assert _request_fields(row) == (None, None, None, None) and row.ip_address is None


def _count_commits(s):
    """Replace the session's commit with one that records, for each commit, the audit rows it
    writes (those pending in the session at that moment)."""
    commits, real = [], s.commit

    def commit():
        commits.append(sorted(o.action for o in s.new if isinstance(o, AuditLog)))
        real()
    s.commit = commit
    return commits


def test_the_lock_and_its_row_are_one_commit(db_factory, limits):
    uid = _add_user(db_factory, failed_login_attempts=MAX_ATTEMPTS - 1)
    s, user = _load(db_factory, uid)
    commits = _count_commits(s)
    try:
        A.AuthService(s)._record_failed_login(user.username, IP, user)
    finally:
        s.close()
    assert commits == [[A.AUTO_LOCKED_ACTION]], "one commit, and it writes the lock's row"
    assert _state(db_factory, uid)[1] is True


def test_a_lock_whose_commit_fails_leaves_neither_the_lock_nor_its_row(db_factory, limits):
    uid = _add_user(db_factory, failed_login_attempts=MAX_ATTEMPTS - 1)
    s, user = _load(db_factory, uid)

    def failing_commit():
        s.flush()                    # everything reached the database, then the commit failed
        raise RuntimeError("commit failed")
    s.commit = failing_commit
    try:
        with pytest.raises(RuntimeError):
            A.AuthService(s)._record_failed_login(user.username, IP, user)
        s.rollback()
    finally:
        s.close()
    assert _state(db_factory, uid) == (MAX_ATTEMPTS - 1, False, None)
    assert _rows(db_factory, A.AUTO_LOCKED_ACTION) == []


def test_an_unlock_and_its_row_are_one_commit_made_by_the_caller(db_factory):
    _add_user(db_factory, is_locked=True, locked_until=_now() - timedelta(minutes=2))
    s = db_factory()
    commits = _count_commits(s)
    try:
        assert A.release_expired_locks(s) == 1
        assert commits == [], "release_expired_locks commits nothing itself"
        s.commit()
    finally:
        s.close()
    assert commits == [[A.AUTO_UNLOCKED_ACTION]]
