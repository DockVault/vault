"""Renewing a session that came through an identity provider ("Stay signed in", app/services/sign_in.py renew).

Such a session is renewed only while the provider's sign-in could be made again: the identity still linked, the
provider turned on, no refusal by the provider in force, its freshness window not run out, and its own second
factor still trusted when that is what stood in for the vault's. An account that signs in only through its
provider has no other session renewed. Each refusal is a sentence that says how to sign in again. What the old
session remembers of the provider's sign-in (the provider's session id and subject, its authentication time, the
logout hint) moves to the new session in the renewal's own transaction, so a provider's logout that names the
session finds the live one, whichever comes first.

The tokens here are shaped as a provider sign-in makes them: no method of the vault's own in ``amr`` (the provider
proved who the person is), ``idp`` naming the provider, and ``mfa_at`` when the provider's second factor was
trusted and present.
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
from app.services import auth_service, sign_in, sso_freshness, sso_sign_in  # noqa: E402

pytestmark = pytest.mark.unit

TABLES = (User.__table__, Group.__table__, user_groups, SystemSetting.__table__, AuditLog.__table__,
          SecondFactorAction.__table__, SecondFactorEnrollment.__table__, TemporaryCredential.__table__,
          ActiveSession.__table__, SsoProvider.__table__, ExternalIdentity.__table__, SsoSession.__table__)
OLD = "the-old-session"


@pytest.fixture
def db(monkeypatch):
    monkeypatch.setattr(auth_service, "denylist_token", lambda *a, **k: None)
    monkeypatch.setattr(auth_service, "_best_effort_cache", lambda *a, **k: None, raising=False)
    monkeypatch.setattr(api, "_force_close_after_commit", lambda *a, **k: None)
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


def _link(db, user, provider, *, signed_in=None, refused=None, subject="subject-1"):
    signed_in = signed_in or datetime.utcnow() - timedelta(minutes=10)
    identity = ExternalIdentity(id=uuid.uuid4(), user_id=user.id, provider_id=provider.id, issuer="https://idp.example",
                                subject=subject, subject_source="oidc:sub", linked_at=signed_in - timedelta(days=90),
                                linked_by="self", last_sign_in_at=signed_in, refused_at=refused)
    db.add(identity)
    db.commit()
    return identity


def _through(db, provider, *, name="pat", sso_only_account=False, signed_in=None, refused=None, record=True,
             hint="enc:hint", **claims):
    """An account linked to ``provider``, with one live web session that came through it, and its token's payload."""
    user = User(username=name, email=f"{name}@example.com", password_hash=hash_password("the-account-password-1"),
                role=RoleEnum.USER, is_active=True, is_locked=False, sso_only=sso_only_account or None)
    db.add(user)
    db.commit()
    identity = _link(db, user, provider, signed_in=signed_in, refused=refused)
    session = ActiveSession(id=uuid.uuid4(), session_token=hash_session_token(OLD), user_id=user.id,
                            ip_address="127.0.0.1", expires_at=datetime.utcnow() + timedelta(days=1))
    db.add(session)
    if record:
        db.add(SsoSession(session_id=session.id, provider_id=provider.id, idp_sid="sid-1", idp_sub="subject-1",
                          auth_time=identity.last_sign_in_at, id_token_enc=hint))
    db.commit()
    now = int(datetime.now(timezone.utc).timestamp())
    old = {"sub": str(user.id), "username": user.username, "session_token": OLD, "is_temporary": False,
           "iat": now - 600, "exp": now + 60, "auth_time": now - 600, "amr": [], "idp": str(provider.id)}
    old.update(claims)
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


def _committed_records(db):
    """What another connection sees of the provider's sessions: (the provider's session id, has a logout hint)."""
    with db.get_bind().connect() as other:
        found = other.execute(sa.text("SELECT idp_sid, id_token_enc FROM sso_sessions")).fetchall()
    return sorted((sid, hint is not None) for sid, hint in found)


def _untouched(db):
    rows = _sessions(db)
    return (len(rows) == 1 and rows[0].session_token == hash_session_token(OLD) and not rows[0].revoked
            and rows[0].is_active and len(_records(db)) <= 1)


def _live_named_by_the_provider(db, provider, sid="sid-1"):
    """The live sessions a back-channel logout naming ``sid`` finds."""
    db.expire_all()
    ids = [r.session_id for r in db.query(SsoSession).filter(SsoSession.provider_id == provider.id,
                                                             SsoSession.idp_sid == sid).all()]
    return [s.id for s in db.query(ActiveSession).filter(ActiveSession.id.in_(ids)).all() if not s.revoked]


# --------------------------------------------------------------------------- what moves to the new session

def test_the_providers_session_moves_to_the_new_session_with_its_hint(db):
    p = _provider(db)
    user, identity, old = _through(db, p)
    old_id = _row_of(db, OLD).id
    signed_in_at = _records(db)[old_id].auth_time
    renewed = sign_in.renew(db, user, old, client_ip="127.0.0.1")
    claims = jwt.decode(renewed.access_token, options={"verify_signature": False})
    assert claims["idp"] == str(p.id) and claims["auth_time"] == old["auth_time"] and claims["amr"] == []
    new_row = _row_of(db, claims["session_token"])
    records = _records(db)
    assert set(records) == {old_id, new_row.id}
    kept, moved = records[old_id], records[new_row.id]
    # The provider's logout finds the new session by the same session id and subject; the time and the hint moved.
    assert (moved.provider_id, moved.idp_sid, moved.idp_sub, moved.auth_time, moved.id_token_enc) == (
        p.id, "sid-1", "subject-1", signed_in_at, "enc:hint")
    assert kept.id_token_enc is None and kept.idp_sid == "sid-1"
    assert _row_of(db, OLD).revoked and not new_row.revoked
    assert _live_named_by_the_provider(db, p) == [new_row.id]


def test_a_session_with_no_record_of_the_provider_is_renewed_with_none(db):
    p = _provider(db)
    user, identity, old = _through(db, p, record=False)
    renewed = sign_in.renew(db, user, old, client_ip="127.0.0.1")
    assert jwt.decode(renewed.access_token, options={"verify_signature": False})["idp"] == str(p.id)
    assert _records(db) == {} and len(_sessions(db)) == 2


def test_the_providers_session_moves_in_the_renewals_own_transaction(db, monkeypatch):
    """Nothing of the move is visible before the commit that ends the old session: until then a logout finds the
    old session, with its hint; after it, the new one. Never both live, never neither."""
    p = _provider(db)
    user, identity, old = _through(db, p)
    seen = {}
    real_end = api._end_web_session

    def end(db_, session_token, user_id=None):
        if session_token == OLD:
            seen["inside"] = sorted((r.idp_sid, r.id_token_enc is not None) for r in db_.query(SsoSession).all())
            seen["committed"] = _committed_records(db_)
        return real_end(db_, session_token, user_id=user_id)
    monkeypatch.setattr(api, "_end_web_session", end)
    sign_in.renew(db, user, old, client_ip="127.0.0.1")
    assert seen == {"inside": [("sid-1", False), ("sid-1", True)], "committed": [("sid-1", True)]}
    assert _committed_records(db) == [("sid-1", False), ("sid-1", True)]


def test_a_copy_that_fails_fails_the_renewal_and_the_old_session_stands(db, monkeypatch):
    p = _provider(db)
    user, identity, old = _through(db, p)

    def broken(*a, **k):
        raise RuntimeError("the provider's session could not be copied")
    monkeypatch.setattr(sign_in, "carry_renewed_provider_session", broken)
    monkeypatch.setattr(api, "_renewed_token", lambda *a, **k: pytest.fail("a renewal that failed minted a token"))
    with pytest.raises(RuntimeError):
        sign_in.renew(db, user, old, client_ip="127.0.0.1")
    assert _untouched(db) and _committed_records(db) == [("sid-1", True)]


# --------------------------------------------------------------------------- a provider's logout, before and after

def _provider_logout(db, provider, sid="sid-1"):
    """A back-channel logout naming ``sid``, as the route applies it: the sessions found, ended durably."""
    ids = [r.session_id for r in db.query(SsoSession).filter(SsoSession.provider_id == provider.id,
                                                             SsoSession.idp_sid == sid).all()]
    ended = api._revoke_sessions(db, session_ids=ids, actor_username="provider logout", durable=True)
    db.commit()
    return ended


def test_a_logout_that_came_first_leaves_the_renewal_nothing_to_renew(db, monkeypatch):
    p = _provider(db)
    user, identity, old = _through(db, p)
    assert _provider_logout(db, p) == 1
    monkeypatch.setattr(api, "_renewed_token", lambda *a, **k: pytest.fail("minted a token"))
    with pytest.raises(HTTPException) as refused:
        sign_in.renew(db, user, old, client_ip="127.0.0.1")
    assert refused.value.status_code == 401
    rows = _sessions(db)
    assert len(rows) == 1 and rows[0].revoked and len(_records(db)) == 1
    assert _live_named_by_the_provider(db, p) == []


def test_a_logout_that_comes_after_the_renewal_ends_the_new_session(db):
    p = _provider(db)
    user, identity, old = _through(db, p)
    renewed = sign_in.renew(db, user, old, client_ip="127.0.0.1")
    new_plain = jwt.decode(renewed.access_token, options={"verify_signature": False})["session_token"]
    assert _live_named_by_the_provider(db, p) == [_row_of(db, new_plain).id]
    assert _provider_logout(db, p) == 1
    assert _row_of(db, new_plain).revoked and _live_named_by_the_provider(db, p) == []


# --------------------------------------------------------------------------- the provider's rules

def _refused(db, user, old):
    touched = []
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(auth_service.AuthService, "_create_session", lambda *a, **k: touched.append("create") or "x")
        patch.setattr(api, "_sessions_turn", lambda *a, **k: touched.append("turn"))
        with pytest.raises(HTTPException) as refused:
            sign_in.renew(db, user, old, client_ip="127.0.0.1")
    assert refused.value.status_code == 403 and touched == [] and _untouched(db)
    assert db.query(AuditLog).filter(AuditLog.action == "session_extended").count() == 0
    return refused.value.detail


AGAIN = "Sign in through Contoso again to stay signed in."
OFF = "Signing in through Contoso is turned off. Sign in again another way, or ask an administrator."
UNLINKED = "Your account is no longer linked to the identity provider this sign-in came through. Sign in again."
FACTOR = "Signing in now needs your second factor; sign in again."


def test_an_identity_that_was_unlinked_is_not_renewed(db):
    p = _provider(db)
    user, identity, old = _through(db, p)
    db.delete(identity)
    db.commit()
    assert _refused(db, user, old) == UNLINKED
    # A provider the token names that is no provider at all, or one the account was never linked to: the same.
    assert _refused(db, user, {**old, "idp": "not-a-provider"}) == UNLINKED
    assert _refused(db, user, {**old, "idp": str(uuid.uuid4())}) == UNLINKED


def test_a_link_to_another_provider_does_not_stand_in_for_the_one_the_session_came_through(db):
    p, q = _provider(db), _provider(db, name="Fabrikam")
    user, identity, old = _through(db, p)
    _link(db, user, q, subject="subject-at-fabrikam")
    db.delete(identity)
    db.commit()
    assert _refused(db, user, old) == UNLINKED
    # Nor does another account's link to the same provider.
    other = User(username="sam", email="sam@example.com", password_hash="x", role=RoleEnum.USER, is_active=True)
    db.add(other)
    db.commit()
    _link(db, other, p, subject="subject-of-sam")
    assert _refused(db, user, old) == UNLINKED
    assert sso_sign_in.renewal_refusal(db, other, str(p.id)) is None


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
    """Inside a wide window, so nothing but the refusal can refuse it."""
    p = _provider(db, sso_freshness_days=30)
    signed_in = datetime.utcnow() - timedelta(hours=2)
    user, identity, old = _through(db, p, signed_in=signed_in, refused=signed_in + timedelta(hours=1))
    assert _refused(db, user, old) == AGAIN
    # A refusal stamped at the very moment of the last sign-in counts as after it.
    identity.refused_at = identity.last_sign_in_at
    db.commit()
    assert sso_freshness.deadline_of(identity, p).refused is True and _refused(db, user, old) == AGAIN
    # A sign-in the provider admitted after the refusal lifts it.
    identity.last_sign_in_at = datetime.utcnow()
    db.commit()
    assert sign_in.renew(db, user, old, client_ip="127.0.0.1").access_token


def test_a_refusal_counts_with_the_window_off(db):
    p = _provider(db, sso_freshness_days=0)
    signed_in = datetime.utcnow() - timedelta(hours=2)
    user, identity, old = _through(db, p, signed_in=signed_in, refused=signed_in + timedelta(hours=1))
    assert _refused(db, user, old) == AGAIN


def test_the_freshness_window_ends_at_its_moment(db):
    p = _provider(db, sso_freshness_days=1)
    signed_in = datetime(2026, 3, 1, 12, 0, 0)
    user, identity, old = _through(db, p, signed_in=signed_in)
    due = signed_in + timedelta(days=1)
    asked = lambda now: sso_sign_in.renewal_refusal(db, user, str(p.id), now=now)       # noqa: E731
    assert asked(due - timedelta(seconds=1)) is None
    assert asked(due) == AGAIN and asked(due + timedelta(seconds=1)) == AGAIN
    # Through the renewal, long past it.
    assert _refused(db, user, old) == AGAIN


@pytest.mark.parametrize("case", ["inside the window", "the window off", "the default window"])
def test_a_fresh_identity_is_renewed(db, case):
    policy = {"inside the window": {"sso_freshness_days": 1}, "the window off": {"sso_freshness_days": 0},
              "the default window": {}}[case]
    p = _provider(db, **policy)
    age = timedelta(hours=23) if case == "inside the window" else timedelta(days=20)
    user, identity, old = _through(db, p, signed_in=datetime.utcnow() - age)
    assert sign_in.renew(db, user, old, client_ip="127.0.0.1").access_token


# --------------------------------------------------------------------------- the second factor after a provider

def test_a_provider_sign_in_whose_second_factor_is_trusted_is_renewed_when_the_account_needs_one(db, monkeypatch):
    """The account has a second factor in effect; the provider's own was trusted and present, so the sign-in was
    whole without the vault's code and its token names no method. Signing in through the provider again ends the
    same way, so the renewal goes through."""
    p = _provider(db, sso_trust_idp_mfa=True)
    user, identity, old = _through(db, p, mfa_at=1700000000)
    monkeypatch.setattr(api, "_login_second_factor_in_effect", lambda db_, user_: True)
    assert sign_in.renew(db, user, old, client_ip="127.0.0.1").access_token


def test_the_providers_second_factor_stands_in_only_while_it_is_trusted(db, monkeypatch):
    p = _provider(db, sso_trust_idp_mfa=True)
    user, identity, old = _through(db, p, mfa_at=1700000000)
    monkeypatch.setattr(api, "_login_second_factor_in_effect", lambda db_, user_: True)
    p.policy = {"sso_trust_idp_mfa": False}
    db.commit()
    # The trust was turned off since: signing in again would ask for the vault's own factor.
    assert _refused(db, user, old) == FACTOR
    # A token that shows a factor of the vault's own (a code after the provider) does not depend on the trust.
    assert sign_in.renew(db, user, {**old, "amr": ["totp"]}, client_ip="127.0.0.1").access_token


def test_without_a_second_factor_in_effect_the_trust_does_not_matter(db, monkeypatch):
    p = _provider(db)                                    # nothing trusted, the default
    user, identity, old = _through(db, p)
    monkeypatch.setattr(api, "_login_second_factor_in_effect", lambda db_, user_: False)
    assert sign_in.renew(db, user, old, client_ip="127.0.0.1").access_token


def test_a_provider_sign_in_that_showed_no_second_factor_is_not_renewed_once_one_is_needed(db, monkeypatch):
    """The renewal rules' own refusal: no method of the vault's, and no ``mfa_at``."""
    p = _provider(db, sso_trust_idp_mfa=True)
    user, identity, old = _through(db, p)
    monkeypatch.setattr(api, "_login_second_factor_in_effect", lambda db_, user_: True)
    assert _refused(db, user, old) == FACTOR


# --------------------------------------------------------------------------- provider-only accounts

def test_an_account_that_is_provider_only_now_keeps_no_session_made_another_way(db):
    p = _provider(db)
    user, identity, old = _through(db, p, sso_only_account=True, record=False)
    without = {**{k: v for k, v in old.items() if k != "idp"}, "amr": ["pwd"]}
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
    without = {**{k: v for k, v in old.items() if k != "idp"}, "amr": ["pwd"]}
    assert sign_in.renew(db, user, without, client_ip="127.0.0.1").access_token


# --------------------------------------------------------------------------- which time the limit counts from

LIMIT = "You have been signed in for as long as this vault allows at a stretch; sign in again."


def test_a_provider_session_days_old_still_renews_within_the_vaults_own_limit(db):
    """The renewal limit counts from the moment the vault's sign-in completed (the token's ``auth_time``), never
    from the provider's own session, which may be days old: that time stays with the provider's session."""
    provider = _provider(db)
    long_ago = datetime.utcnow() - timedelta(days=3)
    user, identity, old = _through(db, provider, signed_in=long_ago)
    assert [r.auth_time for r in _records(db).values()] == [long_ago]
    renewed = sign_in.renew(db, user, old, client_ip="127.0.0.1")
    claims = jwt.decode(renewed.access_token, options={"verify_signature": False})
    assert claims["auth_time"] == old["auth_time"]                 # the vault's own, carried by the renewal
    kept = _records(db)                                            # the provider's, with its session, old and new
    assert len(kept) == 2 and {r.auth_time for r in kept.values()} == {long_ago}


def test_the_limit_ends_a_provider_sign_in_by_the_vaults_time_however_fresh_the_providers_session(db):
    provider = _provider(db)
    user, identity, old = _through(db, provider)                   # the provider's session: ten minutes old
    now = int(datetime.now(timezone.utc).timestamp())
    with pytest.raises(HTTPException) as refused:
        sign_in.renew(db, user, {**old, "auth_time": now - 25 * 3600}, client_ip="127.0.0.1")
    assert refused.value.status_code == 403 and refused.value.detail == LIMIT
    assert _untouched(db)
