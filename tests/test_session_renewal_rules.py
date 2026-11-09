"""The rules behind "Stay signed in" (POST /auth/session/extend), offline on a real database.

A sign-in is renewed only up to the renewal limit counted from the sign-in itself (auth_time: the old
token's, else its iat), the limit being the administrator's setting, never shorter than the session timeout
nor longer than 30 days, 24 hours by default; a renewal is refused when the account now needs a second
factor at sign-in and its token shows none; the new token carries the identity claims of the old one and
auth_time, and lives for the session timeout, cut at the limit.
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
from app.core import second_factor as sf  # noqa: E402
from app.core.models import (Group, RoleEnum, SecondFactorAction, SecondFactorEnrollment, SystemSetting,  # noqa: E402
                             User, user_groups)
from app.core.security import encrypt_secret, hash_password  # noqa: E402

pytestmark = pytest.mark.unit

HOUR = 3600


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'renewal.db'}")
        copies = sa.MetaData()
        for table in (User.__table__, Group.__table__, user_groups, SystemSetting.__table__,
                      SecondFactorAction.__table__, SecondFactorEnrollment.__table__):
            copy = table.to_metadata(copies)
            for column in copy.columns:
                if column.server_default is not None and "now()" in str(getattr(column.server_default, "arg", "")):
                    column.server_default = sa.schema.DefaultClause(sa.text("CURRENT_TIMESTAMP"))
        copies.create_all(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        # The session timeout the tests count with: thirty minutes, whatever the environment says.
        session.add(SystemSetting(key=api._SETTINGS_KEY, value={"session_timeout": 30}))
        session.commit()
        yield session
        session.close()
        engine.dispose()


def _user(db, name="pat"):
    user = User(username=name, email=f"{name}@example.com", password_hash=hash_password("the-account-password-1"),
                role=RoleEnum.USER, is_active=True, is_locked=False)
    db.add(user)
    db.commit()
    return user


def _settings(db, **values):
    row = db.query(SystemSetting).filter(SystemSetting.key == api._SETTINGS_KEY).first()
    if row is None:
        row = SystemSetting(key=api._SETTINGS_KEY, value={})
        db.add(row)
    row.value = {**(row.value or {}), **values}
    db.commit()


def _old(signed_in_ago_seconds, now=None, **more):
    """An old token's claims, signed in `signed_in_ago_seconds` before `now` (the test's own moment, so the
    limit is counted from the same instant the renewal is judged at; the current time when not given)."""
    now = int((now or datetime.now(timezone.utc)).timestamp())
    claims = {"sub": "x", "session_token": "s", "is_temporary": False, "iat": now - signed_in_ago_seconds,
              "exp": now + 60}
    claims.update(more)
    return claims


def _refusal(fn, *args, **kw):
    with pytest.raises(HTTPException) as refused:
        fn(*args, **kw)
    return refused.value


def test_the_default_limit_is_a_day_from_the_sign_in(db):
    user = _user(db)
    now = datetime.now(timezone.utc)
    auth_time, expires_at = api._renewal_terms(db, user, _old(23 * HOUR, now), now)
    assert auth_time == _old(23 * HOUR, now)["iat"]
    # The session timeout (30 minutes here) is shorter than what is left of the limit.
    assert abs((expires_at - now).total_seconds() - 30 * 60) < 5
    # Twenty minutes before the limit the new token ends at the limit, not after it.
    _, expires_at = api._renewal_terms(db, user, _old(24 * HOUR - 20 * 60, now), now)
    assert abs((expires_at - now).total_seconds() - 20 * 60) < 5
    refused = _refusal(api._renewal_terms, db, user, _old(24 * HOUR + 1, now), now)
    assert refused.status_code == 403 and "as long as this vault allows" in refused.detail
    # At the limit, with nothing left to hand out, the renewal is refused too.
    assert _refusal(api._renewal_terms, db, user, _old(24 * HOUR - 2, now), now).status_code == 403


def test_auth_time_outlives_every_renewal_and_wins_over_iat(db):
    user = _user(db)
    now = int(datetime.now(timezone.utc).timestamp())
    # A renewed token: its iat is recent, its auth_time the original sign-in thirteen hours ago.
    refused = _refusal(api._renewal_terms, db, user, _old(60, auth_time=now - 25 * HOUR))
    assert "as long as this vault allows" in refused.detail
    auth_time, _ = api._renewal_terms(db, user, _old(60, auth_time=now - 2 * HOUR))
    assert auth_time == now - 2 * HOUR


def test_the_administrators_limit_applies_and_is_never_shorter_than_the_session_timeout(db):
    user = _user(db)
    _settings(db, session_renewal_max_hours=1)
    assert _refusal(api._renewal_terms, db, user, _old(70 * 60)).status_code == 403
    api._renewal_terms(db, user, _old(50 * 60))
    # A three-hour session timeout lifts a one-hour limit to three hours.
    _settings(db, session_timeout=180)
    api._renewal_terms(db, user, _old(2 * HOUR))
    assert _refusal(api._renewal_terms, db, user, _old(3 * HOUR + 1)).status_code == 403
    # Thirty days is the most any setting gives.
    _settings(db, session_renewal_max_hours=5000, session_timeout=30)
    assert api._session_renewal_limit(db) == timedelta(days=30)


def test_a_token_without_a_sign_in_time_is_not_renewed(db):
    user = _user(db)
    refused = _refusal(api._renewal_terms, db, user, {"sub": "x", "session_token": "s"})
    assert refused.status_code == 403 and "sign in again" in refused.detail


def test_an_account_that_now_needs_a_second_factor_is_refused_unless_its_token_shows_one(db):
    user = _user(db)
    api._renewal_terms(db, user, _old(60))   # no factor enrolled: the password alone still signs in
    db.add(SecondFactorEnrollment(user_id=user.id, method="totp", secret_enc=encrypt_secret(sf.generate_totp_secret()),
                                  status="active", last_used_step=0))
    db.commit()
    refused = _refusal(api._renewal_terms, db, user, _old(60))
    assert refused.status_code == 403 and "second factor" in refused.detail
    assert _refusal(api._renewal_terms, db, user, _old(60, amr=["pwd"])).status_code == 403
    api._renewal_terms(db, user, _old(60, amr=["pwd", "totp"]))
    # The administrator's switch for the second factor at sign-in off: the password alone signs in again.
    db.add(SecondFactorAction(key="login", require_otp=False, require_password=False))
    db.commit()
    api._renewal_terms(db, user, _old(60))


def test_the_renewed_token_carries_the_identity_claims_and_the_sign_in_time(db):
    user = _user(db)
    now = datetime.now(timezone.utc)
    old = _old(2 * HOUR, now, amr=["pwd", "totp"], mfa_at=1700000000, idp="corp", nonce="dropped")
    auth_time, expires_at = api._renewal_terms(db, user, old, now)
    token = api._renewed_token(user, old, "new-session-token", auth_time, expires_at, now)
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["amr"] == ["pwd", "totp"] and claims["mfa_at"] == 1700000000 and claims["idp"] == "corp"
    assert claims["auth_time"] == old["iat"] and claims["session_token"] == "new-session-token"
    assert claims["sub"] == str(user.id) and claims["is_temporary"] is False and "nonce" not in claims
    assert abs(claims["exp"] - int(expires_at.timestamp())) <= 1
    assert api.RENEWAL_CLAIMS == ("amr", "mfa_at", "auth_time", "idp")


def test_the_session_probe_is_the_route_that_answers_auth_session():
    # The helper that says when a temporary credential ends sits next to the probe; the probe, not the
    # helper, is what GET /auth/session serves (the web app reads its navigation and that end from it).
    routes = [r for r in api.app.routes if getattr(r, "path", None) == "/auth/session" and "GET" in r.methods]
    assert [r.endpoint.__name__ for r in routes] == ["get_session_access"]
    assert not any(getattr(r, "endpoint", None) is api._temp_session_end for r in api.app.routes)
