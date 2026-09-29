"""A sign-in with a password ends only its own channel's earlier sessions, offline on a real database.

A password sign-in marked every other session of the account inactive (a temporary credential's
excepted). The web never reads that mark (it refuses a session only once it is revoked), but SFTP checks
it on every operation: so a second SFTP password connection cut off the first, a client's parallel
connections cut each other off, and a web sign-in cut off the account's SFTP connections, key ones
included, dropping an upload in flight. Now each session records where it was signed in
(active_sessions.channel), a web sign-in marks only the earlier web sessions (and those an earlier
release wrote, with no channel), and an SFTP sign-in, by password or key, marks nothing. Revoking,
locking and deactivating still end every session. test_sign_in_channels_live.py drives it over SFTP and
the web on a running stack.
"""
import tempfile
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core.models import (ActiveSession, AuditLog, RoleEnum, SignInLockout, TemporaryCredential,  # noqa: E402
                             User)
from app.core.security import hash_password  # noqa: E402
from app.services import auth_service as A  # noqa: E402

pytestmark = pytest.mark.unit

PASSWORD = "right-password-123"
HOME = "198.51.100.10"


@pytest.fixture
def Session(monkeypatch):
    monkeypatch.setattr(A, "_best_effort_cache", lambda code, op: None)   # no session cache here
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'channels.db'}", connect_args={"timeout": 60})
        for model in (User, AuditLog, SignInLockout, TemporaryCredential, ActiveSession):
            model.__table__.create(engine)
        yield sessionmaker(bind=engine, autocommit=False, autoflush=False)
        engine.dispose()


@pytest.fixture
def account(Session):
    s = Session()
    u = User(username=f"u_{uuid.uuid4().hex[:8]}", password_hash=hash_password(PASSWORD), role=RoleEnum.USER)
    s.add(u)
    s.commit()
    out = (u.id, u.username)
    s.close()
    return out


def _service(s):
    svc = A.AuthService(s)
    svc._check_rate_limit = lambda *a, **k: None
    return svc


def _sign_in(Session, name, channel):
    s = Session()
    try:
        _user, token = _service(s).authenticate_user(name, PASSWORD, HOME, channel=channel)
        return token
    finally:
        s.close()


def _key_session(Session, uid):
    s = Session()
    try:
        return A.AuthService(s).create_sftp_key_session(s.get(User, uid), HOME)
    finally:
        s.close()


def _rows(Session, uid):
    s = Session()
    try:
        return [(r.channel, bool(r.is_active), r.temp_credential_id is not None)
                for r in s.query(ActiveSession).filter(ActiveSession.user_id == uid)
                .order_by(ActiveSession.started_at, ActiveSession.id)]
    finally:
        s.close()


def _seed(Session, uid, channel, temp=False):
    s = Session()
    cred_id = None
    if temp:
        from datetime import datetime, timedelta
        later = datetime.utcnow() + timedelta(hours=1)
        cred = TemporaryCredential(id=uuid.uuid4(), user_id=uid, temp_username=f"temp_{uuid.uuid4().hex[:8]}",
                                   credential_hash="x", expires_at=later, deactivate_at=later)
        s.add(cred)
        s.flush()
        cred_id = cred.id
    s.add(ActiveSession(id=uuid.uuid4(), session_token=uuid.uuid4().hex, user_id=uid, ip_address=HOME,
                        channel=channel, temp_credential_id=cred_id))
    s.commit()
    s.close()


def test_sessions_record_where_they_were_signed_in(Session, account):
    uid, name = account
    _sign_in(Session, name, A.WEB_CHANNEL)
    _sign_in(Session, name, A.SFTP_CHANNEL)
    _key_session(Session, uid)
    assert sorted(c for c, _a, _t in _rows(Session, uid)) == ["sftp", "sftp", "web"]


def test_sftp_sign_ins_end_no_other_session(Session, account):
    uid, name = account
    _sign_in(Session, name, A.WEB_CHANNEL)
    for _ in range(3):
        _sign_in(Session, name, A.SFTP_CHANNEL)
    _key_session(Session, uid)
    assert all(active for _c, active, _t in _rows(Session, uid)), _rows(Session, uid)


def test_a_web_sign_in_marks_only_the_earlier_web_sessions(Session, account):
    uid, name = account
    _seed(Session, uid, None)                       # written by an earlier release: counts as web
    _seed(Session, uid, A.WEB_CHANNEL, temp=True)   # a temporary credential's: never
    _sign_in(Session, name, A.SFTP_CHANNEL)
    _key_session(Session, uid)
    _sign_in(Session, name, A.WEB_CHANNEL)
    _sign_in(Session, name, A.WEB_CHANNEL)
    rows = _rows(Session, uid)
    assert rows == [(None, False, False), ("web", True, True), ("sftp", True, False), ("sftp", True, False),
                    ("web", False, False), ("web", True, False)], rows


def test_the_default_channel_is_the_web(Session, account):
    uid, name = account
    s = Session()
    try:
        _service(s).authenticate_user(name, PASSWORD, HOME)
    finally:
        s.close()
    assert _rows(Session, uid) == [("web", True, False)]


def test_the_sftp_server_signs_in_on_the_sftp_channel():
    import ast
    import inspect
    import textwrap
    from app.sftp import sftp_server as S
    tree = ast.parse(textwrap.dedent(inspect.getsource(S.SFTPServer.check_auth_password)))
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
             and getattr(n.func, "attr", None) == "authenticate_user"]
    assert calls and all(any(k.arg == "channel" and getattr(k.value, "id", None) == "SFTP_CHANNEL"
                             for k in c.keywords) for c in calls)


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
        return _Q(self.cred if model is TemporaryCredential else None)

    def commit(self):
        pass


@pytest.mark.parametrize("sftp_door,channel", [(True, "sftp"), (False, "web")])
def test_a_temporary_credentials_session_records_its_door(monkeypatch, sftp_door, channel):
    from datetime import datetime, timedelta, timezone
    later = datetime.now(timezone.utc) + timedelta(hours=1)
    owner = type("U", (), {"is_active": True, "is_locked": False, "locked_until": None, "role": RoleEnum.USER})()
    cred = type("C", (), {"id": uuid.uuid4(), "device_id": None, "credential_hash": "h", "is_active": True,
                          "is_used": False, "expires_at": later, "deactivate_at": None, "user": owner})()
    svc = A.AuthService.__new__(A.AuthService)
    svc.db = _DB(cred)
    svc._check_rate_limit = svc._check_username_rate_limit = lambda *a, **k: None
    made = []
    svc._create_session = lambda *a, **k: made.append(k.get("channel")) or "session-token"
    monkeypatch.setattr(A, "verify_temporary_credential", lambda *a, **k: True)
    monkeypatch.setattr("app.core.temp_scope.attach_scope", lambda *a, **k: None)
    svc.authenticate_temporary_credential("temp_x", "cred", HOME, allow_device_credential=sftp_door)
    assert made == [channel]
