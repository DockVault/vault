"""Letting a sign-in last longer is under its own step-up (PUT /settings), offline on a real database.

A save that makes the effective session timeout or the effective "Stay signed in" limit longer (a raised
value, or one cleared to a longer default) needs admin.session_limits.write: the password every time, plus
the second factor whenever the account has one. A save that shortens either, or leaves both alone, takes
the ordinary settings step-up. A save that changes the second-factor policy and loosens a session limit at
once is refused: each needs its own confirmation.
"""
import tempfile
from pathlib import Path

import pytest
import sqlalchemy as sa
from fastapi import HTTPException
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.core import otp_service  # noqa: E402
from app.core import second_factor_actions as acts  # noqa: E402
from app.core.models import (AuditLog, OtpCode, RoleEnum, SecondFactorAction, SecondFactorEnrollment,  # noqa: E402
                             SecondFactorRecoveryCode, SystemSetting, User)
from app.core.security import hash_password  # noqa: E402

pytestmark = pytest.mark.unit

ACTION = "admin.session_limits.write"
PASSWORD = "the-account-password-1"
DEFAULT_TIMEOUT = api.settings.jwt_access_token_expire_minutes


class _Reached(Exception):
    """The save got past its step-up to the validation of its values."""


@pytest.fixture(autouse=True)
def quiet(monkeypatch):
    monkeypatch.setattr(otp_service, "_resolve_redis", lambda redis: None)
    from app.core import rate_limiter
    monkeypatch.setattr(rate_limiter.rate_limiter, "check_rate_limit", lambda **kw: (True, 0, 0))
    monkeypatch.setattr(api, "_current_session_hash", lambda request: request.headers.get("x-test-session"))


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'limits.db'}")
        copies = sa.MetaData()
        for model in (User, AuditLog, OtpCode, SecondFactorAction, SecondFactorEnrollment, SecondFactorRecoveryCode,
                      SystemSetting):
            table = model.__table__.to_metadata(copies)
            for column in table.columns:
                if column.server_default is not None and "now()" in str(getattr(column.server_default, "arg", "")):
                    column.server_default = sa.schema.DefaultClause(sa.text("CURRENT_TIMESTAMP"))
        copies.create_all(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        session.add(SystemSetting(key=api._SETTINGS_KEY,
                                  value={"session_timeout": 60, "session_renewal_max_hours": 24}))
        session.commit()
        yield session
        session.close()
        engine.dispose()


@pytest.fixture
def admin(db):
    user = User(username="ada", email="ada@example.com", password_hash=hash_password(PASSWORD),
                role=RoleEnum.ADMIN, is_active=True, is_locked=False)
    db.add(user)
    db.commit()
    return user


@pytest.fixture
def routed(monkeypatch):
    """Which step-up a save asked for, and whether it got past it; nothing is written."""
    seen = []
    monkeypatch.setattr(api, "_enforce_step_up", lambda db, user, request, action: seen.append(action))

    def reached(payload, db):
        raise _Reached()
    monkeypatch.setattr(api, "_validate_settings_payload", reached)
    return seen


def _request(receipt=None):
    headers = [(b"x-test-session", b"s-1")]
    if receipt:
        headers.append((b"x-second-factor", receipt.encode()))
    return Request({"type": "http", "method": "PUT", "path": "/settings", "headers": headers,
                    "client": ("127.0.0.1", 50000), "query_string": b""})


def _save(db, user, payload, receipt=None):
    return run_coroutine(api.update_settings(payload=payload, request=_request(receipt), current_user=user, db=db))


def test_the_action_is_fixed_password_every_time_and_guarded():
    assert acts.fixed_policy(ACTION) == "password_always"
    from app.core import fixed_step_up
    assert ACTION in fixed_step_up.GUARDED


@pytest.mark.parametrize("payload", [
    {"session_timeout": 120},                                   # a longer timeout
    {"session_renewal_max_hours": 48},                          # a longer renewal limit
])
def test_a_longer_limit_without_the_password_is_refused(db, admin, routed, payload):
    with pytest.raises(HTTPException) as refused:
        _save(db, admin, payload)
    assert refused.value.status_code == 403
    assert refused.value.detail["reason"] == "step_up_required" and refused.value.detail["action"] == ACTION
    assert routed == []


def test_a_limit_cleared_to_a_default_it_already_equals_is_not_a_loosening(db, admin, routed):
    with pytest.raises(_Reached):
        _save(db, admin, {"session_renewal_max_hours": 0})      # the default is 24 hours, as stored
    assert routed == ["admin.settings.write"]


def test_a_timeout_cleared_to_a_longer_default_is_a_loosening(db, admin, routed):
    row = db.query(SystemSetting).filter(SystemSetting.key == api._SETTINGS_KEY).first()
    row.value = {"session_timeout": 5, "session_renewal_max_hours": 24}
    db.commit()
    assert DEFAULT_TIMEOUT > 5
    with pytest.raises(HTTPException) as refused:
        _save(db, admin, {"session_timeout": 0})
    assert refused.value.detail["action"] == ACTION


@pytest.mark.parametrize("payload", [
    {"session_timeout": 30},
    {"session_renewal_max_hours": 12},
    {"session_timeout": 60, "session_renewal_max_hours": 24},  # unchanged
    {"app_name": "Vault"},                                      # not a session limit at all
])
def test_a_shorter_or_unchanged_limit_takes_the_ordinary_path(db, admin, routed, payload):
    with pytest.raises(_Reached):
        _save(db, admin, payload)
    assert routed == ["admin.settings.write"]


def test_with_the_password_a_longer_limit_goes_through(db, admin, routed):
    answer = run_coroutine(api.second_factor_step_up(
        body=api.SecondFactorStepUpRequest(action=ACTION, method="", code="", password=PASSWORD),
        request=_request(), current_user=admin, db=db))
    with pytest.raises(_Reached):
        _save(db, admin, {"session_renewal_max_hours": 72}, receipt=answer["receipt"])
    assert routed == []                                         # this save's one confirmation was the password


def test_the_second_factor_policy_and_a_longer_limit_are_saved_separately(db, admin, routed):
    with pytest.raises(HTTPException) as refused:
        _save(db, admin, {"mfa_mode": "required", "session_timeout": 240})
    assert refused.value.status_code == 400 and "separately" in refused.value.detail


def test_a_limit_saved_with_a_cleared_timeout_is_checked_against_the_default_that_will_apply(db, monkeypatch):
    # Stored: a ten-hour timeout. The save clears it (back to the deployment's 30 minutes here) and sets a
    # two-hour limit, which the timeout that will apply allows; checked against the stored ten hours, it was
    # refused.
    monkeypatch.setattr(api.settings, "jwt_access_token_expire_minutes", 30)
    row = db.query(SystemSetting).filter(SystemSetting.key == api._SETTINGS_KEY).first()
    row.value = {"session_timeout": 600, "session_renewal_max_hours": 24}
    db.commit()
    api._validate_settings_payload({"session_timeout": 0, "session_renewal_max_hours": 2}, db)
    # And the other way: a limit shorter than a timeout set in the same save is still refused.
    with pytest.raises(HTTPException) as refused:
        api._validate_settings_payload({"session_timeout": 600, "session_renewal_max_hours": 2}, db)
    assert refused.value.status_code == 400 and "at least the session timeout" in refused.value.detail


def test_a_longer_limit_still_meets_the_matrix_rule_for_an_ordinary_save(db, admin):
    # The matrix asks for the second factor on settings saves and this administrator has none: an ordinary
    # save is refused enroll_required, and so is one that also lengthens the timeout, before any password.
    db.add(SecondFactorAction(key="admin.settings.write", require_otp=True, require_password=False))
    db.commit()
    for payload in ({"app_name": "x"}, {"session_timeout": 120, "app_name": "x"}, {"session_timeout": 120}):
        with pytest.raises(HTTPException) as refused:
            _save(db, admin, payload)
        assert refused.value.status_code == 403, payload
        assert refused.value.detail["reason"] == "enroll_required", (payload, refused.value.detail)
        assert refused.value.detail["action"] == "admin.settings.write", payload


def test_a_whole_page_save_that_sends_the_second_factor_policy_back_unchanged_may_lengthen_the_timeout(db, admin):
    # The settings page sends every key; the policy as it is in force is no change to it.
    from app.core import second_factor_policy as pol
    unchanged = dict(pol.effective_policy({}))
    with pytest.raises(HTTPException) as refused:
        _save(db, admin, {**unchanged, "session_timeout": 120})
    assert refused.value.detail["reason"] == "step_up_required" and refused.value.detail["action"] == ACTION


@pytest.mark.parametrize("changed", [{"mfa_mode": "required"}, {"mfa_mode": "nonsense"}, {"mfa_email_code_ttl_minutes": "5"},
                                     {"mfa_allowed_methods": ["totp", "email"]}, {"mfa_required_user_ids": ["u-1"]}])
def test_a_changed_or_unreadable_policy_value_counts_as_a_change(changed):
    from app.core import second_factor_policy as pol
    assert api._changes_second_factor_policy({}, {**pol.effective_policy({}), **changed})
    assert not api._changes_second_factor_policy({}, dict(pol.effective_policy({})))
    assert not api._changes_second_factor_policy({}, {"app_name": "x"})


def test_the_step_up_is_limited_to_ten_an_account_in_five_minutes():
    # The live tests' helper (tests/_sf_helpers.py) turns to a second administrator when this limit answers;
    # pinned here so a change to the limit is seen, not hidden by that fallback.
    import ast
    from pathlib import Path
    source = (Path(__file__).resolve().parents[1] / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    fn = next(n for n in ast.walk(ast.parse(source))
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "second_factor_step_up")
    calls = [c for c in ast.walk(fn) if isinstance(c, ast.Call) and ast.unparse(c.func).endswith("check_rate_limit")]
    assert len(calls) == 1
    kw = {k.arg: ast.unparse(k.value) for k in calls[0].keywords}
    assert (kw["limit"], kw["window"], kw["prefix"], kw["fail_open"]) == ("10", "300", "'sf_step_up'", "False"), kw
    assert "current_user.id" in kw["identifier"], kw
