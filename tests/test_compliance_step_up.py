"""The compliance step-up, offline on a real database (app/core/fixed_step_up.py, compliance_step_up).

Every step of compliance access that grants or uses the power to read someone else's vault asks for the
password and a TOTP or recovery code, every time: with every switch of the step-up matrix off (the rows of the
compliance keys themselves included), an email code is refused and an account without TOTP must enroll first.
A receipt opens only the action and the session it was earned for, once. The keys are fixed step-ups the
matrix lists read-only and cannot change, each guarded by the compliance router, so the boot contract holds.
"""
import ast
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
from app.api import compliance_router  # noqa: E402
from app.core import fixed_step_up, otp_service  # noqa: E402
from app.core import second_factor as sf  # noqa: E402
from app.core import second_factor_actions as acts  # noqa: E402
from app.core import second_factor_policy as pol  # noqa: E402
from app.core.models import (AuditLog, OtpCode, RoleEnum, SecondFactorAction, SecondFactorEnrollment,  # noqa: E402
                             SecondFactorRecoveryCode, User)
from app.core.security import encrypt_secret, hash_password  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
PASSWORD = "the-account-password-1"
KEYS = ("compliance.grant.propose", "compliance.grant.approve", "compliance.grant.reconfirm",
        "compliance.case.request", "compliance.case.approve", "compliance.case.export", "compliance.hold.place",
        "compliance.hold.decide")
REQUEST, APPROVE = "compliance.case.request", "compliance.case.approve"


@pytest.fixture(autouse=True)
def quiet(monkeypatch):
    monkeypatch.setattr(otp_service, "_resolve_redis", lambda redis: None)
    from app.core import rate_limiter
    monkeypatch.setattr(rate_limiter.rate_limiter, "check_rate_limit", lambda **kw: (True, 0, 0))
    monkeypatch.setattr(api, "_current_session_hash", lambda request: request.headers.get("x-test-session"))


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'stepup.db'}")
        copies = sa.MetaData()
        for model in (User, AuditLog, OtpCode, SecondFactorAction, SecondFactorEnrollment, SecondFactorRecoveryCode):
            table = model.__table__.to_metadata(copies)
            for column in table.columns:
                if column.server_default is not None and "now()" in str(getattr(column.server_default, "arg", "")):
                    column.server_default = sa.schema.DefaultClause(sa.text("CURRENT_TIMESTAMP"))
        copies.create_all(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        # Every switch of the matrix off, the compliance keys included (the API never writes them; the
        # database might hold them anyway).
        for key in [*acts.ACTION_KEYS, *KEYS]:
            session.add(SecondFactorAction(key=key, require_otp=False, require_password=False))
        session.commit()
        yield session
        session.close()
        engine.dispose()


def _account(db, name="ada", role=RoleEnum.ADMIN):
    user = User(username=name, email=f"{name}@example.com", password_hash=hash_password(PASSWORD), role=role,
                is_active=True, is_locked=False)
    db.add(user)
    db.commit()
    return user


def _enroll_totp(db, user):
    seed = sf.generate_totp_secret()
    db.add(SecondFactorEnrollment(user_id=user.id, method="totp", secret_enc=encrypt_secret(seed), status="active",
                                  last_used_step=0))
    db.commit()
    return seed


def _recovery_code(db, user):
    (plain, prefix, digest), = sf.generate_recovery_codes(1)
    db.add(SecondFactorRecoveryCode(user_id=user.id, code_prefix=prefix, code_hash=digest))
    db.commit()
    return plain


def _request(session="session-1", receipt=None):
    headers = [(b"x-test-session", session.encode())]
    if receipt:
        headers.append((b"x-second-factor", receipt.encode()))
    return Request({"type": "http", "method": "POST", "path": "/compliance", "headers": headers,
                    "client": ("127.0.0.1", 50000), "query_string": b""})


def _step_up(db, user, action, *, method="", code="", password=None, session="session-1"):
    body = api.SecondFactorStepUpRequest(action=action, method=method, code=code, password=password)
    return run_coroutine(api.second_factor_step_up(body=body, request=_request(session), current_user=user, db=db))


def _refusal(fn, *args, **kw):
    with pytest.raises(HTTPException) as refused:
        fn(*args, **kw)
    return refused.value


def _check(action):
    return {c.action: c for c in _checks()}[action]


def _checks():
    return [v for v in vars(compliance_router).values() if callable(v) and getattr(v, "action", None)]


def _receipt(db, user, action, session="session-1"):
    return _step_up(db, user, action, method="recovery", code=_recovery_code(db, user), password=PASSWORD,
                    session=session)["receipt"]


# --------------------------------------------------------------------------- the keys

def test_each_compliance_step_is_fixed_under_the_compliance_policy_and_kept_out_of_the_matrix():
    assert tuple(acts.COMPLIANCE_STEP_UPS) == KEYS
    for key in KEYS:
        assert acts.FIXED_STEP_UP_ACTIONS[key] == (acts.COMPLIANCE_STEP_UPS[key], pol.POLICY_COMPLIANCE)
        assert acts.is_step_up_action(key)
    assert not set(KEYS) & set(acts.ACTION_KEYS)


def test_the_router_guards_each_and_the_boot_contract_holds():
    assert sorted(c.action for c in _checks()) == sorted(KEYS)
    assert set(KEYS) <= fixed_step_up.GUARDED
    assert fixed_step_up.contract_problems() == []
    api._assert_step_up_boot_contract()


@pytest.mark.parametrize("action", ["admin.retention.write", "admin.audit_privacy.write", acts.OWNER_KEY_RESET,
                                    "admin.settings.write", "compliance.case.nothing"])
def test_only_a_compliance_action_gets_the_compliance_check(action):
    with pytest.raises(LookupError):
        fixed_step_up.compliance_step_up(action)


def test_the_router_names_no_permission_and_uses_no_endpoint_group():
    source = (ROOT / "app" / "api" / "compliance_router.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {
        n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    for forbidden in ("require_endpoint_permission", "PermissionEnum", "require_step_up", "require_permission"):
        assert forbidden not in names, forbidden


# --------------------------------------------------------------------------- what it asks for

@pytest.mark.parametrize("action", KEYS)
def test_an_account_without_totp_is_refused_with_every_switch_off(db, action):
    ada = _account(db)
    refused = _refusal(_check(action), db, ada, _request())
    assert refused.status_code == 403 and refused.detail["reason"] == "enroll_required"
    assert _refusal(_step_up, db, ada, action, method="password", password=PASSWORD).detail["reason"] == \
        "enroll_required"


@pytest.mark.parametrize("action", KEYS)
def test_the_password_and_a_code_are_asked_every_time_with_every_switch_off(db, action):
    ada = _account(db)
    seed = _enroll_totp(db, ada)
    refused = _refusal(_check(action), db, ada, _request())
    assert refused.status_code == 403 and refused.detail["reason"] == "step_up_required"
    assert refused.detail["methods"] == ["totp", "recovery", "password"]
    totp = sf._totp_at_step(seed, sf.current_totp_step())
    assert _refusal(_step_up, db, ada, action, method="totp", code=totp).status_code == 403
    assert _refusal(_step_up, db, ada, action, method="password", password=PASSWORD).status_code == 403
    db.query(SecondFactorEnrollment).update({"last_used_step": 0})
    db.commit()
    receipt = _step_up(db, ada, action, method="totp", code=totp, password=PASSWORD)["receipt"]
    assert _check(action)(db, ada, _request(receipt=receipt)) is None


def test_an_ordinary_user_is_asked_the_same(db):
    una = _account(db, "una", RoleEnum.USER)
    _enroll_totp(db, una)
    assert _refusal(_check(REQUEST), db, una, _request()).detail["reason"] == "step_up_required"
    assert _check(REQUEST)(db, una, _request(receipt=_receipt(db, una, REQUEST))) is None


def test_an_email_code_never_counts(db):
    ada = _account(db)
    db.add(SecondFactorEnrollment(user_id=ada.id, method="email", status="active", last_used_step=0))
    db.commit()
    code = otp_service.issue(db, purpose=f"sf:{REQUEST}", user_id=ada.id, destination=ada.email, ttl_minutes=5)
    refused = _refusal(_step_up, db, ada, REQUEST, method="email", code=code, password=PASSWORD)
    assert refused.status_code == 403 and refused.detail["reason"] == "enroll_required"
    assert _refusal(_check(REQUEST), db, ada, _request()).detail["reason"] == "enroll_required"


# --------------------------------------------------------------------------- receipts

def test_a_receipt_opens_its_action_and_its_session_once(db):
    ada = _account(db)
    _enroll_totp(db, ada)
    receipt = _receipt(db, ada, REQUEST)
    assert _refusal(_check(APPROVE), db, ada, _request(receipt=receipt)).status_code == 403       # another action
    assert _check(REQUEST)(db, ada, _request(receipt=receipt)) is None
    assert _refusal(_check(REQUEST), db, ada, _request(receipt=receipt)).status_code == 403       # once
    receipt = _receipt(db, ada, REQUEST)
    assert _refusal(_check(REQUEST), db, ada, _request("session-2", receipt)).status_code == 403  # another session


def test_a_receipt_of_a_weaker_policy_or_another_account_opens_nothing(db):
    ada, bo = _account(db), _account(db, "bo")
    _enroll_totp(db, ada)
    _enroll_totp(db, bo)
    weaker = sf.issue_step_up_receipt(db, user_id=ada.id, action="admin.retention.write", session_hash="session-1")
    assert _refusal(_check(REQUEST), db, ada, _request(receipt=weaker)).status_code == 403
    matrix = sf.issue_step_up_receipt(db, user_id=ada.id, action="admin.settings.write", session_hash="session-1")
    assert _refusal(_check(REQUEST), db, ada, _request(receipt=matrix)).status_code == 403
    theirs = _receipt(db, bo, REQUEST)
    assert _refusal(_check(REQUEST), db, ada, _request(receipt=theirs)).status_code == 403


def test_a_temporary_credential_is_refused(db):
    ada = _account(db)
    _enroll_totp(db, ada)
    receipt = _receipt(db, ada, REQUEST)
    ada._is_temp_session = True
    assert "temporary credential" in _refusal(_check(REQUEST), db, ada, _request(receipt=receipt)).detail


# --------------------------------------------------------------------------- the matrix

def test_the_matrix_lists_them_read_only_as_always_required(db):
    listed = run_coroutine(api.list_second_factor_actions(current_user=_account(db), db=db))
    assert not {a["key"] for a in listed["actions"]} & set(KEYS)
    fixed = {f["key"]: f for f in listed["fixed"]}
    assert set(fixed) == set(acts.FIXED_STEP_UP_ACTIONS)
    for key in KEYS:
        assert fixed[key] == {"key": key, "name": acts.COMPLIANCE_STEP_UPS[key], "policy": "compliance",
                              "requires": "Always: your password and an authenticator or recovery code "
                                          "(never an email code)", "fixed": True}
    assert fixed["admin.retention.write"]["requires"] == ("Always: your password, and your second factor when you "
                                                          "have one")


def test_the_matrix_cannot_change_one(db):
    ada = _account(db)
    update = api.update_second_factor_action.__wrapped__
    refused = _refusal(lambda: run_coroutine(update(key=REQUEST, body=api.SecondFactorActionToggle(require_otp=False),
                                                    request=_request(), current_user=ada, db=db)))
    assert refused.status_code == 404
    bulk = api.update_second_factor_actions_bulk.__wrapped__
    refused = _refusal(lambda: run_coroutine(bulk(body=api.SecondFactorActionsBulk(actions=[
        {"key": REQUEST, "require_otp": False}]), request=_request(), current_user=ada, db=db)))
    assert refused.status_code == 400


def test_the_web_app_shows_them_below_the_matrix_without_a_switch():
    script = (ROOT / "static" / "js" / "compliance.js").read_text(encoding="utf-8")
    app = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    index = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    assert "window.renderFixedStepUps = renderFixedStepUps;" in script
    assert "innerHTML" not in script and "'input'" not in script
    assert app.count("window.renderFixedStepUps((data && data.fixed) || [])") == 1
    assert index.count('<script src="/static/js/compliance.js?v=') == 1
