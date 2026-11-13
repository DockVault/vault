"""Renewing a sign-in ("Stay signed in") through the sign-in pipeline (app/services/sign_in.py, renew).

The route (POST /auth/session/extend) hands the renewal to the pipeline, which owns its order: a refusal before
anything changes; the new session made first, short-lived until the renewal has won, so at no moment is the old
session ended with the new one not yet there; the old session ended by one conditional update, with one winner; a
loser deletes the row it made and mints nothing; a row left by a crash ends on its own.
"""
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import pytest
import sqlalchemy as sa
from fastapi import HTTPException
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.core.models import (ActiveSession, AuditLog, Group, RoleEnum, SecondFactorAction,  # noqa: E402
                             SecondFactorEnrollment, SystemSetting, TemporaryCredential, User, user_groups)
from app.core.security import create_access_token, hash_password  # noqa: E402
from app.core.session_hash_utils import hash_session_token  # noqa: E402
from app.services import auth_service, sign_in  # noqa: E402

pytestmark = pytest.mark.unit

TABLES = (User.__table__, Group.__table__, user_groups, SystemSetting.__table__, AuditLog.__table__,
          SecondFactorAction.__table__, SecondFactorEnrollment.__table__, TemporaryCredential.__table__,
          ActiveSession.__table__)


@pytest.fixture
def db(monkeypatch):
    monkeypatch.setattr(auth_service, "denylist_token", lambda *a, **k: None)
    monkeypatch.setattr(auth_service, "_best_effort_cache", lambda *a, **k: None, raising=False)
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'renewal.db'}")
        copies = sa.MetaData()
        for table in TABLES:
            sa.Table(table.name, copies, *[sa.Column(c.name, c.type, primary_key=c.primary_key) for c in table.columns])
        copies.create_all(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


def _signed_in(db, name="pat", plain="the-old-session", **claims):
    """An account with one live web session, and the verified payload of its token."""
    user = User(username=name, email=f"{name}@example.com", password_hash=hash_password("the-account-password-1"),
                role=RoleEnum.USER, is_active=True, is_locked=False)
    db.add(user)
    db.commit()
    db.add(ActiveSession(session_token=hash_session_token(plain), user_id=user.id, ip_address="127.0.0.1",
                         expires_at=datetime.utcnow() + timedelta(days=1)))
    db.commit()
    now = int(datetime.now(timezone.utc).timestamp())
    old = {"sub": str(user.id), "username": user.username, "session_token": plain, "is_temporary": False,
           "iat": now - 600, "exp": now + 60, "auth_time": now - 600, "amr": ["pwd"]}
    old.update(claims)
    return user, old


def _rows(db):
    db.expire_all()
    return db.query(ActiveSession).order_by(ActiveSession.started_at).all()


def _row_of(db, plain):
    db.expire_all()
    return db.query(ActiveSession).filter(ActiveSession.session_token == hash_session_token(plain)).one()


def _naive(moment):
    return moment.astimezone(timezone.utc).replace(tzinfo=None) if moment.tzinfo else moment


def test_the_new_session_exists_before_the_old_one_is_ended_and_lives_minutes_until_then(db, monkeypatch):
    user, old = _signed_in(db)
    seen = {}
    real_end = api._end_web_session

    def end(db_, session_token, user_id=None):
        rows = _rows(db_)
        seen["rows"] = [(r.session_token == hash_session_token(old["session_token"]), bool(r.revoked), bool(r.is_active),
                         _naive(r.expires_at)) for r in rows]
        return real_end(db_, session_token, user_id=user_id)
    monkeypatch.setattr(api, "_end_web_session", end)
    began = datetime.utcnow()
    renewed = sign_in.renew(db, user, old, client_ip="127.0.0.1")
    # When the old session was about to be ended, both rows were there and live, and the new one had minutes to live.
    assert len(seen["rows"]) == 2 and all(not revoked and active for _, revoked, active, _ in seen["rows"])
    held = [expires for is_old, _, _, expires in seen["rows"] if not is_old]
    assert len(held) == 1 and began <= held[0] <= datetime.utcnow() + sign_in.RENEWAL_HOLD
    assert sign_in.RENEWAL_HOLD <= timedelta(minutes=5)
    # Won: the old session is ended durably, the new one has its full life and is the one the token names.
    new_plain = jwt.decode(renewed.access_token, options={"verify_signature": False})["session_token"]
    assert new_plain != old["session_token"]
    assert _row_of(db, old["session_token"]).revoked is True and _row_of(db, old["session_token"]).is_active is False
    new_row = _row_of(db, new_plain)
    assert not new_row.revoked and new_row.is_active
    assert _naive(new_row.expires_at) > datetime.utcnow() + timedelta(days=30)
    assert len(_rows(db)) == 2


def test_a_renewal_that_does_not_win_deletes_the_row_it_made_and_mints_nothing(db, monkeypatch):
    user, old = _signed_in(db)
    real_end = api._end_web_session

    def ended_meanwhile(db_, session_token, user_id=None):
        # Another call (a second renewal, a sign-out, a revocation) ends the session after this one made its row.
        db_.query(ActiveSession).filter(ActiveSession.session_token == hash_session_token(session_token)).update(
            {ActiveSession.revoked: True, ActiveSession.is_active: False}, synchronize_session=False)
        db_.commit()
        assert len(_rows(db_)) == 2
        return real_end(db_, session_token, user_id=user_id)
    monkeypatch.setattr(api, "_end_web_session", ended_meanwhile)
    monkeypatch.setattr(api, "_renewed_token", lambda *a, **k: pytest.fail("a renewal that lost minted a token"))
    with pytest.raises(HTTPException) as refused:
        sign_in.renew(db, user, old, client_ip="127.0.0.1")
    assert refused.value.status_code == 401
    rows = _rows(db)
    assert len(rows) == 1 and rows[0].session_token == hash_session_token(old["session_token"])
    assert db.query(AuditLog).filter(AuditLog.action == "session_extended").count() == 0


def test_a_session_already_ended_is_refused_before_anything_is_made(db, monkeypatch):
    user, old = _signed_in(db)
    db.query(ActiveSession).update({ActiveSession.revoked: True, ActiveSession.is_active: False})
    db.commit()
    made = []
    monkeypatch.setattr(auth_service.AuthService, "_create_session", lambda *a, **k: made.append(1) or "x")
    with pytest.raises(HTTPException) as refused:
        sign_in.renew(db, user, old, client_ip="127.0.0.1")
    assert refused.value.status_code == 401 and made == [] and len(_rows(db)) == 1
    # Another account's session is not this account's to renew: refused the same way, nothing made.
    other, _ = _signed_in(db, "sam", "sams-session")
    with pytest.raises(HTTPException) as refused:
        sign_in.renew(db, user, {**old, "session_token": "sams-session"}, client_ip="127.0.0.1")
    assert refused.value.status_code == 401 and made == []
    assert not _row_of(db, "sams-session").revoked


def test_a_failure_while_the_new_row_is_filled_leaves_the_old_session_as_it_was(db, monkeypatch):
    user, old = _signed_in(db)

    def broken(*a, **k):
        raise RuntimeError("the marks could not be carried")
    monkeypatch.setattr(api, "_carry_session_marks", broken)
    with pytest.raises(RuntimeError):
        sign_in.renew(db, user, old, client_ip="127.0.0.1")
    rows = _rows(db)
    assert len(rows) == 1 and not rows[0].revoked and rows[0].is_active
    assert rows[0].session_token == hash_session_token(old["session_token"])


def test_a_row_left_by_a_crash_ends_on_its_own(db, monkeypatch):
    """The process dies between making the new row and ending the old one: nothing deletes the row, and no token
    of it exists. It carries minutes of life, so the session cleanup ends it; the old session is untouched."""
    user, old = _signed_in(db)

    class Crash(BaseException):
        pass

    def crash(*a, **k):
        raise Crash()
    monkeypatch.setattr(api, "_carry_session_marks", crash)
    monkeypatch.setattr(sign_in, "_drop_unwon_session", lambda *a, **k: None)     # the process is gone
    with pytest.raises(Crash):
        sign_in.renew(db, user, old, client_ip="127.0.0.1")
    rows = _rows(db)
    assert len(rows) == 2
    left = [r for r in rows if r.session_token != hash_session_token(old["session_token"])][0]
    assert left.expires_at is not None and _naive(left.expires_at) <= datetime.utcnow() + sign_in.RENEWAL_HOLD
    assert not _row_of(db, old["session_token"]).revoked
    # The cleanup's own rule (an active row past its expiry) ends it once the minutes are over.
    db.query(ActiveSession).filter(ActiveSession.id == left.id).update(
        {ActiveSession.expires_at: datetime.utcnow() - timedelta(seconds=1)})
    db.commit()
    auth_service.AuthService(db).cleanup_expired_sessions()
    db.expire_all()
    assert db.query(ActiveSession).filter(ActiveSession.id == left.id).one().is_active is False
    assert _row_of(db, old["session_token"]).is_active is True


def test_a_refusal_comes_before_anything_changes(db, monkeypatch):
    user, old = _signed_in(db)
    made = []
    monkeypatch.setattr(auth_service.AuthService, "_create_session", lambda *a, **k: made.append(1) or "x")
    now = int(datetime.now(timezone.utc).timestamp())
    for refused_old in ({**old, "auth_time": now - 25 * 3600},            # past the renewal limit
                        {**old, "is_temporary": True},                     # a temporary credential's session
                        {k: v for k, v in old.items() if k != "session_token"}):
        with pytest.raises(HTTPException) as refused:
            sign_in.renew(db, user, refused_old, client_ip="127.0.0.1")
        assert refused.value.status_code == 403
    rows = _rows(db)
    assert made == [] and len(rows) == 1 and not rows[0].revoked and rows[0].is_active
    assert db.query(AuditLog).count() == 0


def test_the_renewal_is_recorded_once_with_both_sessions_and_the_sign_in_time(db):
    user, old = _signed_in(db, amr=["pwd", "totp"], mfa_at=123, idp="the-provider")
    renewed = sign_in.renew(db, user, old, client_ip="203.0.113.9")
    claims = jwt.decode(renewed.access_token, options={"verify_signature": False})
    # How the person signed in travels unchanged; the sign-in time is the original one.
    assert (claims["amr"], claims["mfa_at"], claims["idp"], claims["auth_time"]) == (
        ["pwd", "totp"], 123, "the-provider", old["auth_time"])
    assert renewed.expires_at > datetime.now(timezone.utc)
    rows = db.query(AuditLog).filter(AuditLog.action == "session_extended").all()
    assert len(rows) == 1 and rows[0].ip_address == "203.0.113.9"
    details = rows[0].details
    assert details["ended_session"] == hash_session_token(old["session_token"])[:8]
    assert details["new_session"] == hash_session_token(claims["session_token"])[:8]
    assert details["signed_in_at"].endswith("Z")


def test_the_route_hands_the_renewal_to_the_pipeline(db, monkeypatch):
    user, old = _signed_in(db)
    token = create_access_token(data={k: v for k, v in old.items() if k not in ("iat", "exp")},
                                expires_delta=timedelta(minutes=30))
    calls = []
    expires = datetime(2030, 1, 2, 3, 4, 5, 678, tzinfo=timezone.utc)

    def renew(db_, user_, old_, *, client_ip, now=None):
        calls.append((user_.username, old_["session_token"], client_ip))
        return sign_in.Renewed(access_token="the-new-token", expires_at=expires)
    monkeypatch.setattr(sign_in, "renew", renew)
    request = Request({"type": "http", "method": "POST", "path": "/auth/session/extend",
                       "headers": [(b"authorization", f"Bearer {token}".encode())],
                       "client": ("127.0.0.1", 50000), "query_string": b""})
    answer = run_coroutine(api.extend_session(request=request, current_user=user, db=db))
    assert calls == [("pat", "the-old-session", "127.0.0.1")]
    assert answer == {"access_token": "the-new-token", "token_type": "bearer", "expires_at": "2030-01-02T03:04:05Z"}
