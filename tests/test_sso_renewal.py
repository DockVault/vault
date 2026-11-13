"""Renewing a session that came through an identity provider ("Stay signed in", app/services/sign_in.py renew).

Such a session is renewed only while the provider's sign-in could be made again: the identity still linked, the
provider turned on, no refusal by the provider in force and its freshness window not run out; an account that
signs in only through its provider has no other session renewed. Each refusal is a sentence that says how to sign
in again. What the old session remembers of the provider's sign-in (the provider's session id and subject, its
authentication time, the logout hint) is copied to the new session before the old one is ended, so a provider's
logout finds one of the two at every moment, whichever of the two comes first.
"""
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import pytest
import sqlalchemy as sa
from fastapi import HTTPException
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.core import sso_only  # noqa: E402
from app.core.models import (ActiveSession, AuditLog, ExternalIdentity, Group, RoleEnum,  # noqa: E402
                             SecondFactorAction, SecondFactorEnrollment, SsoProvider, SsoSession, SystemSetting,
                             TemporaryCredential, User, user_groups)
from app.core.security import hash_password  # noqa: E402
from app.core.session_hash_utils import hash_session_token  # noqa: E402
from app.services import auth_service, sign_in, sso_sign_in  # noqa: E402

pytestmark = pytest.mark.unit

TABLES = (User.__table__, Group.__table__, user_groups, SystemSetting.__table__, AuditLog.__table__,
          SecondFactorAction.__table__, SecondFactorEnrollment.__table__, TemporaryCredential.__table__,
          ActiveSession.__table__, SsoProvider.__table__, ExternalIdentity.__table__, SsoSession.__table__)
OLD = "the-old-session"


@pytest.fixture
def db(monkeypatch):
    monkeypatch.setattr(auth_service, "denylist_token", lambda *a, **k: None)
    monkeypatch.setattr(auth_service, "_best_effort_cache", lambda *a, **k: None, raising=False)
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'sso-renewal.db'}")
        copies = sa.MetaData()
        for table in TABLES:
            sa.Table(table.name, copies, *[sa.Column(c.name, c.type, primary_key=c.primary_key) for c in table.columns])
        copies.create_all(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


def _provider(db, *, name="Contoso", state="enabled", **policy):
    row = SsoProvider(id=uuid.uuid4(), state=state, kind="oidc", name=name, label="Sign in with " + name,
                      show_on_sign_in=True, policy=dict(policy) or None)
    db.add(row)
    db.commit()
    return row


def _through(db, provider, *, name="pat", sso_only_account=False, signed_in=None, refused=None, record=True, hint="enc:hint"):
    """An account linked to ``provider``, with one live web session that came through it, and its token's payload."""
    user = User(username=name, email=f"{name}@example.com", password_hash=hash_password("the-account-password-1"),
                role=RoleEnum.USER, is_active=True, is_locked=False, sso_only=sso_only_account or None)
    db.add(user)
    db.commit()
    signed_in = signed_in or datetime.utcnow() - timedelta(minutes=10)
    identity = ExternalIdentity(id=uuid.uuid4(), user_id=user.id, provider_id=provider.id, issuer="https://idp.example",
                                subject="subject-1", subject_source="oidc:sub", linked_at=signed_in - timedelta(days=90),
                                linked_by="self", last_sign_in_at=signed_in, refused_at=refused)
    session = ActiveSession(id=uuid.uuid4(), session_token=hash_session_token(OLD), user_id=user.id,
                            ip_address="127.0.0.1", expires_at=datetime.utcnow() + timedelta(days=1))
    db.add_all([identity, session])
    if record:
        db.add(SsoSession(session_id=session.id, provider_id=provider.id, idp_sid="sid-1", idp_sub="subject-1",
                          auth_time=signed_in, id_token_enc=hint))
    db.commit()
    now = int(datetime.now(timezone.utc).timestamp())
    old = {"sub": str(user.id), "username": user.username, "session_token": OLD, "is_temporary": False,
           "iat": now - 600, "exp": now + 60, "auth_time": now - 600, "amr": ["pwd"], "idp": str(provider.id)}
    return user, identity, old


def _sessions(db):
    db.expire_all()
    return db.query(ActiveSession).order_by(ActiveSession.started_at).all()


def _row_of(db, plain):
    db.expire_all()
    return db.query(ActiveSession).filter(ActiveSession.session_token == hash_session_token(plain)).one()


def _records(db):
    db.expire_all()
    return {r.session_id: r for r in db.query(SsoSession).all()}


def _untouched(db):
    rows = _sessions(db)
    return (len(rows) == 1 and rows[0].session_token == hash_session_token(OLD) and not rows[0].revoked
            and rows[0].is_active and len(_records(db)) <= 1)


def _named_by_the_provider(db, provider, sid="sid-1"):
    """The sessions a back-channel logout naming ``sid`` would end: what the route asks the database."""
    db.expire_all()
    return [r.session_id for r in db.query(SsoSession).filter(SsoSession.provider_id == provider.id,
                                                              SsoSession.idp_sid == sid).all()]


# --------------------------------------------------------------------------- what travels to the new session

def test_the_new_session_takes_over_the_providers_session_and_the_old_one_keeps_no_hint(db):
    p = _provider(db)
    user, identity, old = _through(db, p)
    old_id = _row_of(db, OLD).id
    renewed = sign_in.renew(db, user, old, client_ip="127.0.0.1")
    claims = jwt.decode(renewed.access_token, options={"verify_signature": False})
    assert claims["idp"] == str(p.id) and claims["auth_time"] == old["auth_time"]
    new_row = _row_of(db, claims["session_token"])
    records = _records(db)
    assert set(records) == {old_id, new_row.id}
    kept, moved = records[old_id], records[new_row.id]
    # The provider's logout finds the new session by the same session id and subject; the time and the hint moved.
    assert (moved.provider_id, moved.idp_sid, moved.idp_sub, moved.auth_time, moved.id_token_enc) == (
        p.id, "sid-1", "subject-1", kept.auth_time, "enc:hint")
    assert kept.id_token_enc is None and kept.idp_sid == "sid-1"
    assert _row_of(db, OLD).revoked and not new_row.revoked
    assert new_row.id in _named_by_the_provider(db, p)


def test_a_session_with_no_record_of_the_provider_is_renewed_with_none(db):
    p = _provider(db)
    user, identity, old = _through(db, p, record=False)
    renewed = sign_in.renew(db, user, old, client_ip="127.0.0.1")
    assert jwt.decode(renewed.access_token, options={"verify_signature": False})["idp"] == str(p.id)
    assert _records(db) == {} and len(_sessions(db)) == 2


def test_the_providers_session_is_on_the_new_row_before_the_old_session_is_ended(db, monkeypatch):
    p = _provider(db)
    user, identity, old = _through(db, p)
    seen = {}
    real_end = api._end_web_session

    def end(db_, session_token, user_id=None):
        if session_token == OLD:
            seen["named"] = _named_by_the_provider(db_, p)
            seen["live"] = [s.id for s in _sessions(db_) if not s.revoked]
        return real_end(db_, session_token, user_id=user_id)
    monkeypatch.setattr(api, "_end_web_session", end)
    sign_in.renew(db, user, old, client_ip="127.0.0.1")
    # At the moment the old session was about to end, a logout naming the provider's session found both.
    assert len(seen["named"]) == 2 and sorted(seen["named"], key=str) == sorted(seen["live"], key=str)


# --------------------------------------------------------------------------- the race with a provider's logout

def _provider_logout(db_, provider, sid="sid-1"):
    """What a back-channel logout does with the sessions it finds: ends them durably."""
    ids = _named_by_the_provider(db_, provider, sid)
    db_.query(ActiveSession).filter(ActiveSession.id.in_(ids)).update(
        {ActiveSession.revoked: True, ActiveSession.is_active: False}, synchronize_session=False)
    db_.commit()
    return ids


def test_a_logout_that_comes_first_leaves_no_session_and_no_token(db, monkeypatch):
    """The provider's logout lands after the renewal made its new session and before it ended the old one: it finds
    both, the renewal does not win, deletes what it made and mints nothing."""
    p = _provider(db)
    user, identity, old = _through(db, p)
    real_end = api._end_web_session
    found = []

    def end(db_, session_token, user_id=None):
        if session_token == OLD:
            found.extend(_provider_logout(db_, p))
        return real_end(db_, session_token, user_id=user_id)
    monkeypatch.setattr(api, "_end_web_session", end)
    monkeypatch.setattr(api, "_renewed_token", lambda *a, **k: pytest.fail("a renewal that lost minted a token"))
    with pytest.raises(HTTPException) as refused:
        sign_in.renew(db, user, old, client_ip="127.0.0.1")
    assert refused.value.status_code == 401 and len(found) == 2
    rows = _sessions(db)
    assert len(rows) == 1 and rows[0].session_token == hash_session_token(OLD) and rows[0].revoked
    # The copy of the provider's session went with the row the renewal made.
    assert set(_records(db)) == {rows[0].id}


def test_a_logout_that_comes_after_the_renewal_finds_the_new_session(db):
    p = _provider(db)
    user, identity, old = _through(db, p)
    renewed = sign_in.renew(db, user, old, client_ip="127.0.0.1")
    new_plain = jwt.decode(renewed.access_token, options={"verify_signature": False})["session_token"]
    assert not _row_of(db, new_plain).revoked
    ended = _provider_logout(db, p)
    assert _row_of(db, new_plain).id in ended and _row_of(db, new_plain).revoked
    assert len(ended) == 2          # the new session, and the old one's record (ended already)


def test_a_copy_that_fails_leaves_the_old_session_and_nothing_else(db, monkeypatch):
    p = _provider(db)
    user, identity, old = _through(db, p)

    def broken(*a, **k):
        raise RuntimeError("the provider's session could not be copied")
    monkeypatch.setattr(sign_in, "carry_renewed_provider_session", broken)
    with pytest.raises(RuntimeError):
        sign_in.renew(db, user, old, client_ip="127.0.0.1")
    assert _untouched(db)


# --------------------------------------------------------------------------- the provider's rules

def _refused(db, user, old):
    made = []
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(auth_service.AuthService, "_create_session", lambda *a, **k: made.append(1) or "x")
        with pytest.raises(HTTPException) as refused:
            sign_in.renew(db, user, old, client_ip="127.0.0.1")
    assert refused.value.status_code == 403 and made == [] and _untouched(db)
    assert db.query(AuditLog).filter(AuditLog.action == "session_extended").count() == 0
    return refused.value.detail


AGAIN = "Sign in through Contoso again to stay signed in."
OFF = "Signing in through Contoso is turned off. Sign in again another way, or ask an administrator."
UNLINKED = "Your account is no longer linked to the identity provider this sign-in came through. Sign in again."


def test_an_identity_that_was_unlinked_is_not_renewed(db):
    p = _provider(db)
    user, identity, old = _through(db, p)
    db.delete(identity)
    db.commit()
    assert _refused(db, user, old) == UNLINKED
    # A provider the token names that is no provider at all, or another account's link: the same.
    assert _refused(db, user, {**old, "idp": "not-a-provider"}) == UNLINKED
    assert _refused(db, user, {**old, "idp": str(uuid.uuid4())}) == UNLINKED


@pytest.mark.parametrize("state", ["disabled", "draft", "tested"])
def test_a_provider_that_is_not_turned_on_is_not_renewed(db, state):
    p = _provider(db)
    user, identity, old = _through(db, p)
    p.state = state
    db.commit()
    assert _refused(db, user, old) == OFF


def test_a_provider_that_was_removed_is_not_renewed(db):
    p = _provider(db)
    user, identity, old = _through(db, p)
    db.delete(p)
    db.commit()
    assert _refused(db, user, old) == ("Signing in through your identity provider is turned off. Sign in again "
                                       "another way, or ask an administrator.")


def test_a_refusal_by_the_provider_is_not_renewed_until_a_later_sign_in_lifts_it(db):
    p = _provider(db, sso_freshness_days=0)             # the window off: a refusal counts whatever the window
    signed_in = datetime.utcnow() - timedelta(hours=2)
    user, identity, old = _through(db, p, signed_in=signed_in, refused=signed_in + timedelta(hours=1))
    assert _refused(db, user, old) == AGAIN
    # A sign-in the provider admitted after the refusal lifts it.
    identity.last_sign_in_at = datetime.utcnow()
    db.commit()
    assert sign_in.renew(db, user, old, client_ip="127.0.0.1").access_token


def test_a_freshness_window_that_ran_out_is_not_renewed(db):
    p = _provider(db, sso_freshness_days=1)
    user, identity, old = _through(db, p, signed_in=datetime.utcnow() - timedelta(days=1, minutes=1))
    assert _refused(db, user, old) == AGAIN


@pytest.mark.parametrize("case", ["inside the window", "the window off", "the default window"])
def test_a_fresh_identity_is_renewed(db, case):
    policy = {"inside the window": {"sso_freshness_days": 1}, "the window off": {"sso_freshness_days": 0},
              "the default window": {}}[case]
    p = _provider(db, **policy)
    age = timedelta(hours=23) if case == "inside the window" else timedelta(days=20)
    user, identity, old = _through(db, p, signed_in=datetime.utcnow() - age)
    assert sign_in.renew(db, user, old, client_ip="127.0.0.1").access_token


def test_an_account_that_is_provider_only_now_keeps_no_session_made_another_way(db):
    p = _provider(db)
    user, identity, old = _through(db, p, sso_only_account=True, record=False)
    without = {k: v for k, v in old.items() if k != "idp"}
    said = _refused(db, user, without)
    assert said == sso_only.provider_only_message(db, user) and "Contoso" in said
    # The same account's session that came through the provider is renewed.
    assert sign_in.renew(db, user, old, client_ip="127.0.0.1").access_token


def test_an_account_with_a_password_keeps_its_own_session_whatever_its_provider_says(db):
    """A session made with the password, of an account that is not provider-only, is not the provider's: a refusal
    or a lapse pauses the account's keys and temporary credentials, and the password still signs it in."""
    p = _provider(db, sso_freshness_days=1)
    signed_in = datetime.utcnow() - timedelta(days=3)
    user, identity, old = _through(db, p, signed_in=signed_in, refused=signed_in + timedelta(hours=1), record=False)
    without = {k: v for k, v in old.items() if k != "idp"}
    assert sign_in.renew(db, user, without, client_ip="127.0.0.1").access_token


# --------------------------------------------------------------------------- a rule that changes while it runs

def test_a_refusal_that_lands_while_the_renewal_runs_ends_the_new_session_too(db, monkeypatch):
    """The provider refuses the person after the renewal checked its rules and before it finished: the refusal ended
    the sessions it saw; the renewal asks its rules again once it has won and ends the session it made."""
    p = _provider(db)
    user, identity, old = _through(db, p)
    real_end = api._end_web_session

    def end(db_, session_token, user_id=None):
        out = real_end(db_, session_token, user_id=user_id)
        if session_token == OLD:
            db_.query(ExternalIdentity).filter(ExternalIdentity.id == identity.id).update(
                {ExternalIdentity.refused_at: datetime.utcnow() + timedelta(seconds=1)}, synchronize_session=False)
            db_.commit()
        return out
    monkeypatch.setattr(api, "_end_web_session", end)
    monkeypatch.setattr(api, "_renewed_token", lambda *a, **k: pytest.fail("a refused renewal minted a token"))
    with pytest.raises(HTTPException) as refused:
        sign_in.renew(db, user, old, client_ip="127.0.0.1")
    assert refused.value.status_code == 403 and refused.value.detail == AGAIN
    rows = _sessions(db)
    assert len(rows) == 2 and all(r.revoked and not r.is_active for r in rows)
    assert db.query(AuditLog).filter(AuditLog.action == "session_extended").count() == 0


def test_the_answer_for_a_provider_is_read_from_the_rows_as_they_are_now(db):
    p = _provider(db, sso_freshness_days=2)
    user, identity, old = _through(db, p, signed_in=datetime.utcnow() - timedelta(days=1))
    assert sso_sign_in.renewal_refusal(db, user, str(p.id)) is None
    identity.last_sign_in_at = datetime.utcnow() - timedelta(days=2, minutes=1)
    db.commit()
    assert sso_sign_in.renewal_refusal(db, user, str(p.id)) == AGAIN
    # Another account linked to the same provider is asked about its own link.
    other = User(username="sam", email="sam@example.com", password_hash="x", role=RoleEnum.USER, is_active=True)
    db.add(other)
    db.commit()
    assert sso_sign_in.renewal_refusal(db, other, str(p.id)) == UNLINKED
