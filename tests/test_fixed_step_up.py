"""Step-ups the admin's matrix cannot switch off (app/core/fixed_step_up.py), offline on a real database.

Two policies. "compliance": the password and a TOTP or recovery code, never an email code, and an account
with no TOTP enrollment is refused outright. "password always": the password every time, plus whatever
second factor the account has enrolled, email codes included, so an installation whose only
administrator has no second factor can still act. These drive the real step-up route
(POST /auth/second-factor/step-up) and the helper a guarded route calls, with every toggle of the
matrix switched off, on a throwaway SQLite database, for two throwaway fixed actions.
"""
import tempfile
import uuid
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
from app.core import fixed_step_up, otp_service  # noqa: E402
from app.core import second_factor as sf  # noqa: E402
from app.core import second_factor_actions as acts  # noqa: E402
from app.core import second_factor_policy as pol  # noqa: E402
from app.core.models import (AuditLog, OtpCode, RoleEnum, SecondFactorAction, SecondFactorEnrollment,  # noqa: E402
                             SecondFactorRecoveryCode, User)
from app.core.security import encrypt_secret, hash_password  # noqa: E402

pytestmark = pytest.mark.unit

SHIPPED = dict(acts.FIXED_STEP_UP_ACTIONS)
COMPLIANCE = "test.case.open"
RETENTION = "test.retention.write"
PASSWORD = "the-account-password-1"


@pytest.fixture(autouse=True)
def fixed(monkeypatch):
    """Two fixed actions, one per policy; the rate limit, the cache and the session read from the request."""
    monkeypatch.setattr(acts, "FIXED_STEP_UP_ACTIONS", {
        COMPLIANCE: ("Open a case", pol.POLICY_COMPLIANCE),
        RETENTION: ("Change retention", pol.POLICY_PASSWORD_ALWAYS),
    })
    monkeypatch.setattr(fixed_step_up, "GUARDED", set())
    monkeypatch.setattr(otp_service, "_resolve_redis", lambda redis: None)
    from app.core import rate_limiter
    monkeypatch.setattr(rate_limiter.rate_limiter, "check_rate_limit", lambda **kw: (True, 0, 0))
    monkeypatch.setattr(api, "_current_session_hash", lambda request: request.headers.get("x-test-session"))


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'stepup.db'}")
        # A copy of each table with SQLite's spelling of "now" where Postgres's is the default.
        copies = sa.MetaData()
        for model in (User, AuditLog, OtpCode, SecondFactorAction, SecondFactorEnrollment, SecondFactorRecoveryCode):
            table = model.__table__.to_metadata(copies)
            for column in table.columns:
                if column.server_default is not None and "now()" in str(getattr(column.server_default, "arg", "")):
                    column.server_default = sa.schema.DefaultClause(sa.text("CURRENT_TIMESTAMP"))
        copies.create_all(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        # Every toggle of the matrix off, the fixed keys included (the API never writes those; the
        # database might hold them anyway).
        for key in [*acts.ACTION_KEYS, COMPLIANCE, RETENTION]:
            session.add(SecondFactorAction(key=key, require_otp=False, require_password=False))
        session.commit()
        yield session
        session.close()
        engine.dispose()


def _admin(db, name="ada"):
    user = User(username=name, email=f"{name}@example.com", password_hash=hash_password(PASSWORD),
                role=RoleEnum.ADMIN, is_active=True, is_locked=False)
    db.add(user)
    db.commit()
    return user


def _enroll_totp(db, user):
    seed = sf.generate_totp_secret()
    db.add(SecondFactorEnrollment(user_id=user.id, method="totp", secret_enc=encrypt_secret(seed), status="active",
                                  last_used_step=0))
    db.commit()
    return seed


def _enroll_email(db, user):
    db.add(SecondFactorEnrollment(user_id=user.id, method="email", status="active", last_used_step=0))
    db.commit()


def _recovery_code(db, user):
    (plain, prefix, digest), = sf.generate_recovery_codes(1)
    db.add(SecondFactorRecoveryCode(user_id=user.id, code_prefix=prefix, code_hash=digest))
    db.commit()
    return plain


def _totp_now(seed):
    return sf._totp_at_step(seed, sf.current_totp_step())


def _request(session="session-1", receipt=None):
    headers = [(b"x-test-session", session.encode())]
    if receipt:
        headers.append((b"x-second-factor", receipt.encode()))
    return Request({"type": "http", "method": "POST", "path": "/guarded", "headers": headers,
                    "client": ("127.0.0.1", 50000), "query_string": b""})


def _step_up(db, user, action, *, method="", code="", password=None, session="session-1"):
    body = api.SecondFactorStepUpRequest(action=action, method=method, code=code, password=password)
    return run_coroutine(api.second_factor_step_up(body=body, request=_request(session), current_user=user, db=db))


def _refusal(fn, *args, **kw):
    with pytest.raises(HTTPException) as refused:
        fn(*args, **kw)
    return refused.value


def _guarded(db, user, action, receipt=None, session="session-1"):
    return fixed_step_up.enforce(db, user, _request(session, receipt), action)


# --------------------------------------------------------------------------- the policies, pure

@pytest.mark.parametrize("policy,method,expected", [
    (pol.POLICY_COMPLIANCE, None, {"password": True, "otp": False, "must_enroll": True}),
    (pol.POLICY_COMPLIANCE, "email", {"password": True, "otp": False, "must_enroll": True}),
    (pol.POLICY_COMPLIANCE, "totp", {"password": True, "otp": True, "must_enroll": False}),
    (pol.POLICY_PASSWORD_ALWAYS, None, {"password": True, "otp": False, "must_enroll": False}),
    (pol.POLICY_PASSWORD_ALWAYS, "email", {"password": True, "otp": True, "must_enroll": False}),
    (pol.POLICY_PASSWORD_ALWAYS, "totp", {"password": True, "otp": True, "must_enroll": False}),
    (pol.POLICY_FACTOR_WHEN_ENROLLED, None, {"password": False, "otp": False, "must_enroll": False}),
    (pol.POLICY_FACTOR_WHEN_ENROLLED, "totp", {"password": False, "otp": True, "must_enroll": False}),
])
def test_what_each_policy_demands(policy, method, expected):
    assert pol.resolve_fixed_requirement(policy, active_method=method) == expected


def test_an_unknown_policy_is_an_error():
    with pytest.raises(ValueError):
        pol.resolve_fixed_requirement("sometimes", active_method=None)


# --------------------------------------------------------------------------- an administrator with no second factor

def test_an_unenrolled_single_admin_passes_password_always_with_the_password(db):
    ada = _admin(db)
    refused = _refusal(_guarded, db, ada, RETENTION)
    assert refused.status_code == 403 and refused.detail["reason"] == "step_up_required"
    assert refused.detail["methods"] == ["password"]
    receipt = _step_up(db, ada, RETENTION, method="password", password=PASSWORD)["receipt"]
    assert _guarded(db, ada, RETENTION, receipt) is None


def test_password_always_refuses_a_wrong_password(db):
    ada = _admin(db)
    refused = _refusal(_step_up, db, ada, RETENTION, method="password", password="not-it")
    assert refused.status_code == 403
    assert db.query(AuditLog).filter(AuditLog.action == "step_up_password_failed").count() == 1


def test_an_unenrolled_admin_is_refused_by_the_compliance_policy(db):
    ada = _admin(db)
    for fn in (lambda: _step_up(db, ada, COMPLIANCE, method="password", password=PASSWORD),
               lambda: _guarded(db, ada, COMPLIANCE)):
        refused = _refusal(fn)
        assert refused.status_code == 403
        assert refused.detail["reason"] == "enroll_required" and refused.detail["methods"] == []


def test_an_enrollment_never_confirmed_is_no_second_factor_for_either_policy(db):
    # An account that began enrolling TOTP and never entered a code has an unconfirmed enrollment. It is not a
    # second factor: password always still asks for the password alone, and compliance still sends the
    # account to enroll first.
    ada = _admin(db)
    db.add(SecondFactorEnrollment(user_id=ada.id, method="totp", secret_enc=encrypt_secret(sf.generate_totp_secret()),
                                  status="unconfirmed", last_used_step=0))
    db.commit()
    assert fixed_step_up.requirement(db, ada, RETENTION)[1] is False
    assert _refusal(_guarded, db, ada, RETENTION).detail["methods"] == ["password"]
    receipt = _step_up(db, ada, RETENTION, method="password", password=PASSWORD)["receipt"]
    assert _guarded(db, ada, RETENTION, receipt) is None
    for fn in (lambda: _step_up(db, ada, COMPLIANCE, method="password", password=PASSWORD),
               lambda: _guarded(db, ada, COMPLIANCE)):
        refused = _refusal(fn)
        assert refused.status_code == 403 and refused.detail["reason"] == "enroll_required"


# --------------------------------------------------------------------------- with TOTP

def test_compliance_needs_the_password_and_a_totp_code(db):
    ada = _admin(db)
    seed = _enroll_totp(db, ada)
    assert _refusal(_guarded, db, ada, COMPLIANCE).detail["methods"] == ["totp", "recovery", "password"]
    # A code without the password, and the password without a code, are both refused.
    assert _refusal(_step_up, db, ada, COMPLIANCE, method="totp", code=_totp_now(seed)).status_code == 403
    assert _refusal(_step_up, db, ada, COMPLIANCE, method="password", password=PASSWORD).status_code == 403
    db.query(SecondFactorEnrollment).update({"last_used_step": 0})
    db.commit()
    receipt = _step_up(db, ada, COMPLIANCE, method="totp", code=_totp_now(seed), password=PASSWORD)["receipt"]
    assert _guarded(db, ada, COMPLIANCE, receipt) is None


def test_compliance_takes_a_recovery_code(db):
    ada = _admin(db)
    _enroll_totp(db, ada)
    code = _recovery_code(db, ada)
    receipt = _step_up(db, ada, COMPLIANCE, method="recovery", code=code, password=PASSWORD)["receipt"]
    assert _guarded(db, ada, COMPLIANCE, receipt) is None


def test_password_always_also_asks_for_the_enrolled_factor(db):
    ada = _admin(db)
    seed = _enroll_totp(db, ada)
    assert _refusal(_step_up, db, ada, RETENTION, method="password", password=PASSWORD).status_code == 403
    receipt = _step_up(db, ada, RETENTION, method="totp", code=_totp_now(seed), password=PASSWORD)["receipt"]
    assert _guarded(db, ada, RETENTION, receipt) is None


# --------------------------------------------------------------------------- email codes

def _email_code(db, user, action):
    return otp_service.issue(db, purpose=f"sf:{action}", user_id=user.id, destination=user.email, ttl_minutes=5)


def test_an_email_code_is_refused_only_by_the_compliance_policy(db):
    ada = _admin(db)
    _enroll_email(db, ada)
    # Compliance: an account whose second factor is email codes has to enroll TOTP first.
    refused = _refusal(_step_up, db, ada, COMPLIANCE, method="email", code=_email_code(db, ada, COMPLIANCE),
                       password=PASSWORD)
    assert refused.status_code == 403 and refused.detail["reason"] == "enroll_required"
    assert _refusal(_guarded, db, ada, COMPLIANCE).detail["reason"] == "enroll_required"
    # Password always: the email code counts.
    assert _refusal(_guarded, db, ada, RETENTION).detail["methods"] == ["email", "recovery", "password"]
    receipt = _step_up(db, ada, RETENTION, method="email", code=_email_code(db, ada, RETENTION),
                       password=PASSWORD)["receipt"]
    assert _guarded(db, ada, RETENTION, receipt) is None


# --------------------------------------------------------------------------- receipts

def test_a_receipt_is_bound_to_its_action_its_session_and_is_used_once(db):
    ada = _admin(db)
    receipt = _step_up(db, ada, RETENTION, method="password", password=PASSWORD, session="session-1")["receipt"]
    assert _refusal(_guarded, db, ada, COMPLIANCE, receipt).status_code == 403              # another action
    assert _guarded(db, ada, RETENTION, receipt, session="session-1") is None
    assert _refusal(_guarded, db, ada, RETENTION, receipt, session="session-1").status_code == 403   # once
    # Shown in another session it is refused, and spent: it no longer serves the session that earned it.
    receipt = _step_up(db, ada, RETENTION, method="password", password=PASSWORD, session="session-1")["receipt"]
    assert _refusal(_guarded, db, ada, RETENTION, receipt, session="session-2").status_code == 403
    assert _refusal(_guarded, db, ada, RETENTION, receipt, session="session-1").status_code == 403


def test_a_receipt_for_a_matrix_action_does_not_open_a_fixed_one(db):
    ada = _admin(db)
    receipt = sf.issue_step_up_receipt(db, user_id=ada.id, action="admin.settings.write", session_hash="session-1")
    assert _refusal(_guarded, db, ada, RETENTION, receipt).status_code == 403


def test_a_temporary_credential_is_refused_even_with_a_receipt(db):
    ada = _admin(db)
    receipt = _step_up(db, ada, RETENTION, method="password", password=PASSWORD)["receipt"]
    ada._is_temp_session = True
    refused = _refusal(_guarded, db, ada, RETENTION, receipt)
    assert refused.status_code == 403 and "temporary credential" in refused.detail


# --------------------------------------------------------------------------- the matrix never weakens it

def test_the_matrix_rows_are_never_read_for_a_fixed_action(db, monkeypatch):
    ada = _admin(db)
    monkeypatch.setattr(api, "_sf_action_toggles", lambda *_a: (_ for _ in ()).throw(AssertionError("read")))
    req, has_active = api._sf_requirement_for(db, ada, RETENTION)
    assert req == {"password": True, "otp": False, "must_enroll": False} and has_active is False


def test_the_matrix_cannot_change_a_fixed_action(db):
    update = api.update_second_factor_action.__wrapped__
    refused = _refusal(lambda: run_coroutine(update(key=RETENTION, body=api.SecondFactorActionToggle(require_otp=False),
                                                    request=_request(), current_user=_admin(db), db=db)))
    assert refused.status_code == 404


def test_the_step_up_routes_accept_a_fixed_action_and_nothing_unknown(db):
    ada = _admin(db)
    body = api.SecondFactorChallengeRequest(action=RETENTION)
    assert run_coroutine(api.second_factor_challenge(body=body, request=_request(), current_user=ada, db=db)) == {
        "second_factor_required": True, "methods": ["password"]}
    unknown = api.SecondFactorChallengeRequest(action="test.nothing")
    assert _refusal(lambda: run_coroutine(api.second_factor_challenge(
        body=unknown, request=_request(), current_user=ada, db=db))).status_code == 404
    assert _refusal(_step_up, db, ada, "test.nothing", method="password", password=PASSWORD).status_code == 404


# --------------------------------------------------------------------------- guarding and the boot contract

def test_guard_records_the_action_and_checks_it(db):
    check = fixed_step_up.guard(RETENTION)
    assert check.action == RETENTION and fixed_step_up.GUARDED == {RETENTION}
    ada = _admin(db)
    assert _refusal(check, db, ada, _request()).status_code == 403
    receipt = _step_up(db, ada, RETENTION, method="password", password=PASSWORD)["receipt"]
    assert check(db, ada, _request(receipt=receipt)) is None


def test_guard_refuses_an_action_that_is_not_fixed():
    with pytest.raises(LookupError):
        fixed_step_up.guard("admin.settings.write")


def test_the_boot_contract_refuses_a_fixed_action_no_route_guards():
    fixed_step_up.guard(RETENTION)
    assert fixed_step_up.contract_problems() == [f"fixed step-ups no route guards: ['{COMPLIANCE}']"]
    with pytest.raises(RuntimeError, match="no route guards"):
        api._assert_step_up_boot_contract()
    fixed_step_up.guard(COMPLIANCE)
    assert fixed_step_up.contract_problems() == []
    api._assert_step_up_boot_contract()


def test_the_boot_contract_refuses_a_guard_left_for_an_action_no_longer_listed(monkeypatch):
    fixed_step_up.guard(RETENTION)
    fixed_step_up.guard(COMPLIANCE)
    monkeypatch.setattr(acts, "FIXED_STEP_UP_ACTIONS", {RETENTION: ("Change retention", pol.POLICY_PASSWORD_ALWAYS)})
    assert fixed_step_up.contract_problems() == [f"guarded as fixed step-ups but not listed: ['{COMPLIANCE}']"]


def test_the_boot_contract_refuses_an_unknown_policy(monkeypatch):
    monkeypatch.setattr(acts, "FIXED_STEP_UP_ACTIONS", {RETENTION: ("Change retention", "sometimes")})
    monkeypatch.setattr(fixed_step_up, "GUARDED", {RETENTION})
    assert fixed_step_up.contract_problems() == [f"{RETENTION} has an unknown policy 'sometimes'"]


def test_the_shipped_list_holds_known_policies_and_nothing_the_matrix_could_switch_off():
    # The real list, as the application ships it (the fixture replaces it for the other tests).
    assert all(isinstance(name, str) and name for name, _policy in SHIPPED.values())
    assert all(policy in pol.FIXED_POLICIES for _name, policy in SHIPPED.values())
    assert not set(SHIPPED) & set(acts.ACTION_KEYS)
