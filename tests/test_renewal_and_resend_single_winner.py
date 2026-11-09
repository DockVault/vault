"""One winner where two requests race, offline on a real database.

"Stay signed in" mints a new session only when its own call ended the old one: a request whose session was
ended between its sign-in check and the renewal (by a sign-out in another tab, or a second renewal with the
same token) gets 401 and leaves no new session; a renewal that wins carries the released zero-knowledge
envelope of the old session to the new one. Sending an invitation again revokes it by one conditional
update: a resend that finds it already revoked gets 409 and makes nothing. And the Get-started list keeps a
passed test message in its own row, so the item stays done after the audit row is archived.
"""
import tempfile
import uuid
from datetime import datetime, timedelta
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
from app.core.models import (AccountInvitation, ActiveSession, AuditLog, Group, RoleEnum,  # noqa: E402
                             SecondFactorAction, SecondFactorEnrollment, SystemSetting, TemporaryCredential, User,
                             user_groups)
from app.core.security import create_access_token, hash_password  # noqa: E402
from app.core.session_hash_utils import hash_session_token  # noqa: E402

pytestmark = pytest.mark.unit


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'race.db'}")
        # The tables these paths read, as plain columns: the rows the tests write carry no foreign keys to
        # tables not made here.
        copies = sa.MetaData()
        for table in (User.__table__, Group.__table__, user_groups, SystemSetting.__table__, AuditLog.__table__,
                      SecondFactorAction.__table__, SecondFactorEnrollment.__table__,
                      TemporaryCredential.__table__, ActiveSession.__table__, AccountInvitation.__table__):
            sa.Table(table.name, copies, *[sa.Column(c.name, c.type, primary_key=c.primary_key)
                                           for c in table.columns])
        copies.create_all(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


def _user(db, name="pat", role=RoleEnum.USER):
    user = User(username=name, email=f"{name}@example.com", password_hash=hash_password("the-account-password-1"),
                role=role, is_active=True, is_locked=False)
    db.add(user)
    db.commit()
    return user


def _request(token=""):
    headers = [(b"authorization", f"Bearer {token}".encode())] if token else []
    return Request({"type": "http", "method": "POST", "path": "/x", "headers": headers,
                    "client": ("127.0.0.1", 50000), "query_string": b""})


def test_a_renewal_whose_session_was_ended_meanwhile_mints_nothing(db):
    user = _user(db)
    plain = "the-old-session"
    # The session was ended between this request's sign-in check and its renewal.
    db.add(ActiveSession(session_token=hash_session_token(plain), user_id=user.id, ip_address="127.0.0.1",
                         expires_at=datetime.utcnow() + timedelta(days=1), is_active=False, revoked=True))
    db.commit()
    token = create_access_token(data={"sub": str(user.id), "username": user.username, "session_token": plain,
                                      "is_temporary": False}, expires_delta=timedelta(minutes=30))
    with pytest.raises(HTTPException) as refused:
        run_coroutine(api.extend_session(request=_request(token), current_user=user, db=db))
    assert refused.value.status_code == 401
    assert db.query(ActiveSession).count() == 1          # no new session


def test_a_renewal_of_a_live_session_ends_it_and_makes_one_new(db, monkeypatch):
    from app.services import auth_service
    monkeypatch.setattr(auth_service, "denylist_token", lambda *a, **k: None)
    monkeypatch.setattr(auth_service, "_best_effort_cache", lambda *a, **k: None, raising=False)
    user = _user(db, "live")
    plain = "a-live-session"
    db.add(ActiveSession(session_token=hash_session_token(plain), user_id=user.id, ip_address="127.0.0.1",
                         expires_at=datetime.utcnow() + timedelta(days=1)))
    db.commit()
    token = create_access_token(data={"sub": str(user.id), "username": user.username, "session_token": plain,
                                      "is_temporary": False}, expires_delta=timedelta(minutes=30))
    answer = run_coroutine(api.extend_session(request=_request(token), current_user=user, db=db))
    assert answer["access_token"] and answer["expires_at"].endswith("Z")
    rows = db.query(ActiveSession).all()
    assert len(rows) == 2 and sum(1 for r in rows if r.revoked) == 1
    # The same token again: its session is ended, so nothing more is made.
    with pytest.raises(HTTPException) as refused:
        run_coroutine(api.extend_session(request=_request(token), current_user=user, db=db))
    assert refused.value.status_code == 401 and db.query(ActiveSession).count() == 2


def test_a_renewal_carries_the_released_envelope_to_the_new_session(db, monkeypatch):
    """A session whose zero-knowledge envelope was released after an emailed code keeps that release when it is
    renewed: the new row carries the old row's time, so the renewal does not ask for another code."""
    from app.services import auth_service
    monkeypatch.setattr(auth_service, "denylist_token", lambda *a, **k: None)
    monkeypatch.setattr(auth_service, "_best_effort_cache", lambda *a, **k: None, raising=False)
    user = _user(db, "released")
    plain = "a-released-session"
    released = datetime(2026, 1, 2, 3, 4, 5)
    db.add(ActiveSession(session_token=hash_session_token(plain), user_id=user.id, ip_address="127.0.0.1",
                         expires_at=datetime.utcnow() + timedelta(days=1), zk_envelope_released_at=released))
    db.commit()
    token = create_access_token(data={"sub": str(user.id), "username": user.username, "session_token": plain,
                                      "is_temporary": False}, expires_delta=timedelta(minutes=30))
    answer = run_coroutine(api.extend_session(request=_request(token), current_user=user, db=db))
    new_plain = jwt.decode(answer["access_token"], options={"verify_signature": False})["session_token"]
    assert new_plain and new_plain != plain
    db.expire_all()
    new_row = db.query(ActiveSession).filter(ActiveSession.session_token == hash_session_token(new_plain)).one()
    assert new_row.zk_envelope_released_at == released
    # A renewal of a session with nothing released carries nothing.
    plain2 = "a-plain-session"
    db.add(ActiveSession(session_token=hash_session_token(plain2), user_id=user.id, ip_address="127.0.0.1",
                         expires_at=datetime.utcnow() + timedelta(days=1)))
    db.commit()
    token2 = create_access_token(data={"sub": str(user.id), "username": user.username, "session_token": plain2,
                                       "is_temporary": False}, expires_delta=timedelta(minutes=30))
    answer2 = run_coroutine(api.extend_session(request=_request(token2), current_user=user, db=db))
    new_plain2 = jwt.decode(answer2["access_token"], options={"verify_signature": False})["session_token"]
    db.expire_all()
    row2 = db.query(ActiveSession).filter(ActiveSession.session_token == hash_session_token(new_plain2)).one()
    assert row2.zk_envelope_released_at is None


def _invitation(db, maker):
    inv = AccountInvitation(username="newbie", role="user", token_prefix="abcdefabcdef", token_hash="h" * 64,
                            expires_at=datetime.utcnow() + timedelta(hours=24), created_by=maker.id)
    db.add(inv)
    db.commit()
    return inv


def test_a_resend_that_finds_the_invitation_already_revoked_makes_nothing(db, monkeypatch):
    maker = _user(db, "maker", RoleEnum.ADMIN)
    inv = _invitation(db, maker)
    monkeypatch.setattr(api, "_account_policy", lambda db_: {"invite_enabled": True, "invite_ttl_hours": 24})
    monkeypatch.setattr(api, "_invite_pepper", lambda: "p" * 32)
    from app.core import invitations
    monkeypatch.setattr(invitations, "pepper_ok", lambda pepper: True)
    monkeypatch.setattr(api, "email_in_use", lambda db_, value: False)
    resend = api.resend_invite
    while hasattr(resend, "__wrapped__"):
        resend = resend.__wrapped__
    # The route reads the row as pending first, then revokes it by condition; simulate the other resend
    # landing in between by revoking it once the pending check has read it.
    original_status = api._invite_status

    def status_then_race(row, now):
        result = original_status(row, now)
        db.execute(sa.update(AccountInvitation.__table__).where(AccountInvitation.__table__.c.id == row.id)
                   .values(revoked_at=datetime.utcnow()))
        db.commit()
        return result
    monkeypatch.setattr(api, "_invite_status", status_then_race)
    with pytest.raises(HTTPException) as refused:
        run_coroutine(resend(invite_id=str(inv.id), current_user=maker, db=db, request=None))
    assert refused.value.status_code == 409
    assert db.query(AccountInvitation).count() == 1


def test_another_administrator_cannot_resend(db, monkeypatch):
    maker = _user(db, "maker2", RoleEnum.ADMIN)
    other = _user(db, "other", RoleEnum.ADMIN)
    inv = _invitation(db, maker)
    resend = api.resend_invite
    while hasattr(resend, "__wrapped__"):
        resend = resend.__wrapped__
    with pytest.raises(HTTPException) as refused:
        run_coroutine(resend(invite_id=str(inv.id), current_user=other, db=db, request=None))
    assert refused.value.status_code == 403 and "Only the administrator who sent this invitation" in refused.value.detail
    assert db.query(AccountInvitation).filter(AccountInvitation.revoked_at.isnot(None)).count() == 0


def test_a_passed_test_message_stays_on_the_list_after_its_audit_row_is_gone(db, monkeypatch):
    monkeypatch.setattr(api, "_smtp_configured", lambda db_: True)
    assert api._get_started_view(db)["items"]["email"] is False
    api._record_test_email_sent(db)
    assert db.query(AuditLog).count() == 0                # no audit row at all, as after archiving
    assert api._get_started_view(db)["items"]["email"] is True
    first = api._get_started_view(db)["recorded"]["test_email_sent_at"]
    api._record_test_email_sent(db)                       # a second send changes nothing
    assert api._get_started_view(db)["recorded"]["test_email_sent_at"] == first
