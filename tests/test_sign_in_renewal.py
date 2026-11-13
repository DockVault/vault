"""Renewing a sign-in ("Stay signed in") through the sign-in pipeline (app/services/sign_in.py, renew).

The route (POST /auth/session/extend) hands the renewal to the pipeline, which owns its order: a refusal before
anything changes; the account's turn at its sessions taken, and the old session read under it; the new session
made and the old one ended in that one transaction, committed together. So a revocation of the account's sessions
(which takes the same turn) is wholly before a renewal or wholly after it, a second request with the same token
finds the session ended, and a crash before the commit leaves nothing.
"""
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import pytest
import sqlalchemy as sa
from fastapi import HTTPException
from sqlalchemy.orm import Query, sessionmaker
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
OLD = "the-old-session"


@pytest.fixture
def denylisted(monkeypatch):
    calls = []
    monkeypatch.setattr(auth_service, "denylist_token", lambda token, ttl: calls.append((token, ttl)))
    monkeypatch.setattr(auth_service, "_best_effort_cache", lambda *a, **k: None, raising=False)
    return calls


@pytest.fixture
def db(denylisted, monkeypatch):
    monkeypatch.setattr(api, "_force_close_after_commit", lambda *a, **k: None)
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


def _signed_in(db, name="pat", plain=OLD, **claims):
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


def _committed(db):
    """What another connection sees: the committed session rows, as (is the old one, revoked)."""
    with db.get_bind().connect() as other:
        found = other.execute(sa.text("SELECT session_token, revoked FROM active_sessions")).fetchall()
    return sorted((token == hash_session_token(OLD), bool(revoked)) for token, revoked in found)


def _naive(moment):
    return moment.astimezone(timezone.utc).replace(tzinfo=None) if moment.tzinfo else moment


# --------------------------------------------------------------------------- one transaction

def test_the_new_session_and_the_end_of_the_old_one_are_committed_together(db, monkeypatch):
    user, old = _signed_in(db)
    seen = {}
    real_end = api._end_web_session

    def end(db_, session_token, user_id=None):
        seen["inside"] = len(db_.query(ActiveSession).all())        # this transaction: the new row is written
        seen["committed"] = _committed(db_)                          # another connection: nothing of it yet
        return real_end(db_, session_token, user_id=user_id)
    monkeypatch.setattr(api, "_end_web_session", end)
    renewed = sign_in.renew(db, user, old, client_ip="127.0.0.1")
    assert seen == {"inside": 2, "committed": [(True, False)]}
    # After the commit: the old session ended durably, the new one live with its full life, in one step.
    assert _committed(db) == [(False, False), (True, True)]
    new_plain = jwt.decode(renewed.access_token, options={"verify_signature": False})["session_token"]
    assert new_plain != OLD
    old_row, new_row = _row_of(db, OLD), _row_of(db, new_plain)
    assert old_row.revoked is True and old_row.is_active is False
    assert not new_row.revoked and new_row.is_active and new_row.channel == "web"
    assert _naive(new_row.expires_at) > datetime.utcnow() + timedelta(days=30)


def test_a_crash_before_the_commit_leaves_nothing(db, monkeypatch):
    user, old = _signed_in(db)

    class Crash(BaseException):
        pass

    def crash(*a, **k):
        raise Crash()
    monkeypatch.setattr(api, "_end_web_session", crash)
    monkeypatch.setattr(api, "_renewed_token", lambda *a, **k: pytest.fail("a renewal that did not finish minted a token"))
    with pytest.raises(Crash):
        sign_in.renew(db, user, old, client_ip="127.0.0.1")
    assert _committed(db) == [(True, False)]
    rows = _rows(db)
    assert len(rows) == 1 and not rows[0].revoked and rows[0].is_active


def test_an_end_that_did_not_take_leaves_no_session_without_its_token(db, monkeypatch):
    """Not reachable while the turn and the row are held; if the old session's end ever reports that it ended
    nothing, the session just made is ended durably and nothing is minted."""
    user, old = _signed_in(db)
    real_end = api._end_web_session

    def end(db_, session_token, user_id=None):
        if session_token == OLD:
            db_.commit()
            return None, False
        return real_end(db_, session_token, user_id=user_id)
    monkeypatch.setattr(api, "_end_web_session", end)
    monkeypatch.setattr(api, "_renewed_token", lambda *a, **k: pytest.fail("minted a token"))
    with pytest.raises(HTTPException) as refused:
        sign_in.renew(db, user, old, client_ip="127.0.0.1")
    assert refused.value.status_code == 401
    made = [r for r in _rows(db) if r.session_token != hash_session_token(OLD)]
    assert len(made) == 1 and made[0].revoked is True and made[0].is_active is False


# --------------------------------------------------------------------------- the account's turn

def _order(monkeypatch):
    """Records, in order: the account's turn, each read that locks its row, the new session row, the old one's end."""
    log = []
    real_turn, real_for_update = api._sessions_turn, Query.with_for_update
    real_create, real_end = auth_service.AuthService._create_session, api._end_web_session

    def turn(db_, user_id):
        log.append(("turn", str(user_id)))
        return real_turn(db_, user_id)

    def for_update(self, **kw):
        log.append(("lock", self.column_descriptions[0]["name"], kw))
        return real_for_update(self, **kw)

    def create(self, *a, **kw):
        log.append(("create", kw.get("commit")))
        return real_create(self, *a, **kw)

    def end(db_, session_token, user_id=None):
        log.append(("end", session_token == OLD))
        return real_end(db_, session_token, user_id=user_id)
    monkeypatch.setattr(api, "_sessions_turn", turn)
    monkeypatch.setattr(Query, "with_for_update", for_update)
    monkeypatch.setattr(auth_service.AuthService, "_create_session", create)
    monkeypatch.setattr(api, "_end_web_session", end)
    return log


def test_the_turn_is_taken_first_and_the_old_session_is_read_locked_under_it(db, monkeypatch):
    user, old = _signed_in(db)
    log = _order(monkeypatch)
    sign_in.renew(db, user, old, client_ip="127.0.0.1")
    assert log == [("turn", str(user.id)),
                   ("lock", "ActiveSession", {}),              # the old session, so nothing ends it in between
                   ("create", False),                          # written, not committed
                   ("end", True)]                              # ends the old one and commits both


def test_the_turn_is_an_advisory_lock_on_the_account_where_the_database_has_them(db):
    from app.core import sign_in_lockout

    class Postgres:
        """A session on PostgreSQL, as far as the turn looks: its dialect's name, and what it executes."""
        def __init__(self):
            self.ran = []

        def get_bind(self):
            return type("Bind", (), {"dialect": type("Dialect", (), {"name": "postgresql"})()})()

        def execute(self, statement, params=None):
            self.ran.append((str(statement), params))

    pg = Postgres()
    api._sessions_turn(pg, "3f0e9c3a-5d0e-4b53-9d6e-0f6f4c0d7a11")
    assert pg.ran == [("SELECT pg_advisory_xact_lock(:cls, hashtext(:account))",
                       {"cls": api._SESSIONS_TURN_CLASS, "account": "3f0e9c3a-5d0e-4b53-9d6e-0f6f4c0d7a11"})]
    # Held to the end of the transaction (the xact form), and in a class of its own: never the sign-in turn's queue.
    assert api._SESSIONS_TURN_CLASS == 0x5354 != sign_in_lockout._TURN_LOCK_CLASS
    # Elsewhere nothing is taken: the tests' database, and a stand-in store with no engine.
    ran = []
    real_execute = db.execute
    db.execute = lambda *a, **k: ran.append(a) or real_execute(*a, **k)
    api._sessions_turn(db, "3f0e9c3a-5d0e-4b53-9d6e-0f6f4c0d7a11")
    api._sessions_turn(object(), "3f0e9c3a-5d0e-4b53-9d6e-0f6f4c0d7a11")
    assert ran == []


def test_a_revocation_of_the_accounts_sessions_takes_the_same_turn_before_it_reads_them(db, monkeypatch):
    user, old = _signed_in(db)
    log = []
    real_turn, real_query = api._sessions_turn, db.query

    def turn(db_, user_id):
        log.append(("turn", str(user_id)))
        return real_turn(db_, user_id)

    def query(*entities):
        if entities and entities[0] is ActiveSession:
            log.append(("sessions read",))
        return real_query(*entities)
    monkeypatch.setattr(api, "_sessions_turn", turn)
    monkeypatch.setattr(db, "query", query)
    assert api._revoke_sessions(db, user_id=user.id, actor_username="admin", durable=True) == 1
    db.commit()
    assert log[0] == ("turn", str(user.id)) and ("sessions read",) in log[1:]
    assert log.count(("turn", str(user.id))) == 1
    # A temporary credential's sessions are not an account's: its sessions are never renewed, so no turn.
    log.clear()
    api._revoke_sessions(db, temp_credential_id=None, user_id=None, actor_username="admin")
    assert not [entry for entry in log if entry[0] == "turn"]


def test_a_revocation_that_came_first_leaves_the_renewal_nothing_to_renew(db):
    user, old = _signed_in(db)
    assert api._revoke_sessions(db, user_id=user.id, actor_username="admin", durable=True) == 1
    db.commit()
    with pytest.raises(HTTPException) as refused:
        sign_in.renew(db, user, old, client_ip="127.0.0.1")
    assert refused.value.status_code == 401 and _committed(db) == [(True, True)]


def test_a_revocation_that_comes_after_the_renewal_ends_the_new_session(db):
    user, old = _signed_in(db)
    renewed = sign_in.renew(db, user, old, client_ip="127.0.0.1")
    new_plain = jwt.decode(renewed.access_token, options={"verify_signature": False})["session_token"]
    assert api._revoke_sessions(db, user_id=user.id, actor_username="admin", durable=True) == 1
    db.commit()
    assert _row_of(db, new_plain).revoked is True and _committed(db) == [(False, True), (True, True)]


# --------------------------------------------------------------------------- refusals

def test_a_session_already_ended_is_refused_with_nothing_made(db, monkeypatch):
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


def test_a_refusal_comes_before_anything_changes(db, monkeypatch):
    user, old = _signed_in(db)
    touched = []
    monkeypatch.setattr(auth_service.AuthService, "_create_session", lambda *a, **k: touched.append("create") or "x")
    monkeypatch.setattr(api, "_sessions_turn", lambda *a, **k: touched.append("turn"))
    now = int(datetime.now(timezone.utc).timestamp())
    for refused_old in ({**old, "auth_time": now - 25 * 3600},            # past the renewal limit
                        {**old, "is_temporary": True},                     # a temporary credential's session
                        {k: v for k, v in old.items() if k != "session_token"}):
        with pytest.raises(HTTPException) as refused:
            sign_in.renew(db, user, refused_old, client_ip="127.0.0.1")
        assert refused.value.status_code == 403
    rows = _rows(db)
    assert touched == [] and len(rows) == 1 and not rows[0].revoked and rows[0].is_active
    assert db.query(AuditLog).count() == 0


def test_a_second_factor_the_account_now_needs_is_shown_by_the_tokens_methods_or_its_two_factor_time(db, monkeypatch):
    """The renewal rules refuse an account that now needs a second factor its token does not show. The token shows
    one in its methods, or by ``mfa_at``: two kinds of factor were present at that sign-in (the methods need not
    name the second, as when an identity provider's own second factor is trusted)."""
    user, old = _signed_in(db)
    monkeypatch.setattr(api, "_login_second_factor_in_effect", lambda db_, user_: True)
    with pytest.raises(HTTPException) as refused:
        sign_in.renew(db, user, old, client_ip="127.0.0.1")                              # the password alone
    assert refused.value.status_code == 403 and "second factor" in refused.value.detail
    with pytest.raises(HTTPException):
        sign_in.renew(db, user, {**old, "amr": [], "mfa_at": None}, client_ip="127.0.0.1")
    assert len(_rows(db)) == 1
    assert sign_in.renew(db, user, {**old, "amr": [], "mfa_at": 1700000000}, client_ip="127.0.0.1").access_token


# --------------------------------------------------------------------------- the records

def test_the_renewal_is_recorded_once_and_the_old_token_is_refused_for_the_rest_of_its_life(db, denylisted):
    user, old = _signed_in(db, amr=["pwd", "totp"], mfa_at=123, idp="the-provider")
    renewed = sign_in.renew(db, user, old, client_ip="203.0.113.9")
    claims = jwt.decode(renewed.access_token, options={"verify_signature": False})
    # How the person signed in travels unchanged; the sign-in time is the original one.
    assert (claims["amr"], claims["mfa_at"], claims["idp"], claims["auth_time"]) == (
        ["pwd", "totp"], 123, "the-provider", old["auth_time"])
    assert renewed.expires_at > datetime.now(timezone.utc)
    # The old token is denylisted for what is left of its life (about a minute here), never the new one.
    assert len(denylisted) == 1 and denylisted[0][0] == OLD and 0 < denylisted[0][1] <= 60
    rows = db.query(AuditLog).filter(AuditLog.action == "session_extended").all()
    assert len(rows) == 1 and rows[0].ip_address == "203.0.113.9"
    details = rows[0].details
    assert details["ended_session"] == hash_session_token(OLD)[:8]
    assert details["new_session"] == hash_session_token(claims["session_token"])[:8]
    assert details["signed_in_at"].endswith("Z")


def test_what_the_person_proved_in_the_old_session_is_carried_once_the_renewal_is_committed(db, monkeypatch):
    user, old = _signed_in(db)
    seen = []
    real = api._carry_session_marks

    def carry(db_, old_row, new_session):
        seen.append(_committed(db_))
        return real(db_, old_row, new_session)
    monkeypatch.setattr(api, "_carry_session_marks", carry)
    sign_in.renew(db, user, old, client_ip="127.0.0.1")
    assert seen == [[(False, False), (True, True)]]


def test_the_route_hands_the_renewal_to_the_pipeline_off_the_event_loop(db, monkeypatch):
    user, old = _signed_in(db)
    token = create_access_token(data={k: v for k, v in old.items() if k not in ("iat", "exp")},
                                expires_delta=timedelta(minutes=30))
    calls = []
    expires = datetime(2030, 1, 2, 3, 4, 5, 678, tzinfo=timezone.utc)
    loop_thread = []

    def renew(db_, user_, old_, *, client_ip, now=None):
        calls.append((user_.username, old_["session_token"], client_ip, threading.get_ident()))
        return sign_in.Renewed(access_token="the-new-token", expires_at=expires)
    monkeypatch.setattr(sign_in, "renew", renew)
    request = Request({"type": "http", "method": "POST", "path": "/auth/session/extend",
                       "headers": [(b"authorization", f"Bearer {token}".encode())],
                       "client": ("127.0.0.1", 50000), "query_string": b""})

    async def call():
        loop_thread.append(threading.get_ident())
        return await api.extend_session(request=request, current_user=user, db=db)
    answer = run_coroutine(call())
    assert [c[:3] for c in calls] == [("pat", OLD, "127.0.0.1")]
    # It may wait for the account's turn, so it does not run on the loop's thread.
    assert calls[0][3] != loop_thread[0]
    assert answer == {"access_token": "the-new-token", "token_type": "bearer", "expires_at": "2030-01-02T03:04:05Z"}
