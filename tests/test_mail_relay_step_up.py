"""Changing or testing the mail server settings is under its own fixed step-up, offline on a real database.

A sending profile's create, save, delete and test send, a save of the older SMTP settings in the general
settings, and their test send (POST /settings/test-email) each need admin.mail_relay.write: the administrator's
password every time, plus their second factor when they have one, whatever the step-up matrix says. Refused, the
route changes and sends nothing; with the receipt it goes ahead. A settings save that leaves the SMTP settings as
they are stored takes the ordinary settings step-up, and one that also changes the second-factor policy or
lengthens a sign-in is refused: each needs its own confirmation.
"""
import ast
import smtplib
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
from app.api import email_studio_router as studio  # noqa: E402
from app.core import email_send, fixed_step_up, mail_relay, otp_service  # noqa: E402
from app.core import second_factor_actions as acts  # noqa: E402
from app.core.models import (AuditLog, EmailProfile, OtpCode, RoleEnum, SecondFactorAction,  # noqa: E402
                             SecondFactorEnrollment, SecondFactorRecoveryCode, SystemSetting, User)
from app.core.security import encrypt_secret, hash_password  # noqa: E402

pytestmark = pytest.mark.unit

ACTION = "admin.mail_relay.write"
PASSWORD = "the-account-password-1"
RELAY_PASSWORD = "the-relay-password-2"
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def quiet(monkeypatch):
    monkeypatch.setattr(otp_service, "_resolve_redis", lambda redis: None)
    from app.core import rate_limiter
    monkeypatch.setattr(rate_limiter.rate_limiter, "check_rate_limit", lambda **kw: (True, 0, 0))
    monkeypatch.setattr(api, "_current_session_hash", lambda request: request.headers.get("x-test-session"))


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'relay.db'}")
        copies = sa.MetaData()
        for model in (User, AuditLog, OtpCode, SecondFactorAction, SecondFactorEnrollment, SecondFactorRecoveryCode,
                      SystemSetting, EmailProfile):
            table = model.__table__.to_metadata(copies)
            if model is EmailProfile:
                table.indexes.clear()     # the one-default index is partial on PostgreSQL only
            for column in table.columns:
                if column.server_default is not None and "now()" in str(getattr(column.server_default, "arg", "")):
                    column.server_default = sa.schema.DefaultClause(sa.text("CURRENT_TIMESTAMP"))
        copies.create_all(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


@pytest.fixture
def admin(db):
    user = User(username="ada", email="ada@example.test", password_hash=hash_password(PASSWORD),
                role=RoleEnum.ADMIN, is_active=True, is_locked=False)
    db.add(user)
    db.commit()
    return user


@pytest.fixture
def sent(monkeypatch):
    """Each profile test send that reached the mail server. Nothing leaves."""
    out = []
    monkeypatch.setattr(email_send, "smtp_send", lambda cfg, msg: out.append(cfg["smtp_server"]))
    return out


def _request(receipt=None, method="POST", path="/"):
    headers = [(b"x-test-session", b"s-1")]
    if receipt:
        headers.append((b"x-second-factor", receipt.encode()))
    return Request({"type": "http", "method": method, "path": path, "headers": headers,
                    "client": ("127.0.0.1", 50000), "query_string": b""})


def _receipt(db, admin, action=ACTION):
    answer = run_coroutine(api.second_factor_step_up(
        body=api.SecondFactorStepUpRequest(action=action, method="", code="", password=PASSWORD),
        request=_request(), current_user=admin, db=db))
    return answer["receipt"]


def _asked_for_the_step_up(refused):
    assert refused.value.status_code == 403
    detail = refused.value.detail
    assert detail["reason"] == "step_up_required" and detail["action"] == ACTION, detail
    assert "password" in detail["methods"], detail


def _profile(db, **over):
    p = EmailProfile(name="Relay", smtp_server="mail.example.test", smtp_port=587, smtp_username="relay-user",
                     smtp_password=encrypt_secret(RELAY_PASSWORD), from_email="vault@example.test", is_default=True,
                     **over)
    db.add(p)
    db.commit()
    return p


def _body(**over):
    return studio.ProfileIn(**{"name": "Relay", "smtp_server": "mail.example.test", "smtp_port": 587,
                               "smtp_username": "relay-user", "from_email": "vault@example.test", **over})


def _profiles(db):
    db.expire_all()
    return db.query(EmailProfile).all()


# --------------------------------------------------------------------------- the action

def test_the_action_is_fixed_password_every_time_guarded_and_listed():
    assert acts.fixed_policy(ACTION) == "password_always"
    assert ACTION == mail_relay.STEP_UP_ACTION and ACTION not in acts.ACTION_KEYS
    assert ACTION in fixed_step_up.GUARDED
    assert fixed_step_up.contract_problems() == []
    api._assert_step_up_boot_contract()
    [listed] = [row for row in fixed_step_up.describe() if row["key"] == ACTION]
    assert listed["name"] == "Change or test the mail server settings" and listed["fixed"] is True
    assert listed["requires"] == "Always: your password, and your second factor when you have one"


def _calls(path, function):
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == function)
    return [c for c in ast.walk(fn) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)]


@pytest.mark.parametrize("path,function,check", [
    ("app/api/email_studio_router.py", "create_profile", "_step_up"),
    ("app/api/email_studio_router.py", "update_profile", "_step_up"),
    ("app/api/email_studio_router.py", "delete_profile", "_step_up"),
    ("app/api/email_studio_router.py", "test_profile", "_step_up"),
    ("app/api/api_server.py", "update_settings", "_mail_relay_step_up"),
    ("app/api/api_server.py", "send_test_email", "_mail_relay_step_up"),
])
def test_each_route_calls_the_check_in_its_body(path, function, check):
    # The boot contract sees the action guarded once the module makes its check; this pins each route's call.
    assert [c.func.id for c in _calls(path, function)].count(check) == 1


def test_the_check_is_made_where_the_routes_are_and_for_this_action_only():
    for path, name in (("app/api/email_studio_router.py", "_step_up"), ("app/api/api_server.py", "_mail_relay_step_up")):
        tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
        made = [n for n in tree.body if isinstance(n, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in n.targets)]
        assert len(made) == 1 and ast.unparse(made[0].value).endswith("guard(" + (
            "mail_relay" if path.endswith("router.py") else "_mail_relay") + ".STEP_UP_ACTION)"), path
    assert studio._step_up.action == ACTION and api._mail_relay_step_up.action == ACTION


# --------------------------------------------------------------------------- a sending profile

def test_creating_a_profile_needs_the_step_up(db, admin):
    with pytest.raises(HTTPException) as refused:
        run_coroutine(studio.create_profile(payload=_body(), request=_request(), admin=admin, db=db))
    _asked_for_the_step_up(refused)
    assert _profiles(db) == []
    out = run_coroutine(studio.create_profile(payload=_body(), request=_request(_receipt(db, admin)), admin=admin,
                                              db=db))
    assert out["name"] == "Relay" and len(_profiles(db)) == 1


def test_saving_a_profile_needs_the_step_up_even_when_nothing_moves(db, admin):
    p = _profile(db)
    with pytest.raises(HTTPException) as refused:
        run_coroutine(studio.update_profile(profile_id=p.id, payload=_body(name="Renamed"), request=_request(),
                                            admin=admin, db=db))
    _asked_for_the_step_up(refused)
    assert [x.name for x in _profiles(db)] == ["Relay"]
    out = run_coroutine(studio.update_profile(profile_id=p.id, payload=_body(name="Renamed"),
                                              request=_request(_receipt(db, admin)), admin=admin, db=db))
    assert out["name"] == "Renamed" and out["has_password"] is True


def test_a_profile_save_refused_by_the_relay_rule_spends_no_receipt(db, admin):
    p = _profile(db)
    receipt = _receipt(db, admin)
    with pytest.raises(HTTPException) as refused:
        run_coroutine(studio.update_profile(profile_id=p.id, payload=_body(smtp_server="elsewhere.example"),
                                            request=_request(receipt), admin=admin, db=db))
    assert refused.value.status_code == 400 and refused.value.detail["reason"] == mail_relay.REASON
    out = run_coroutine(studio.update_profile(profile_id=p.id, payload=_body(name="Renamed"),
                                              request=_request(receipt), admin=admin, db=db))
    assert out["name"] == "Renamed"


def test_deleting_a_profile_needs_the_step_up(db, admin):
    p = _profile(db)
    with pytest.raises(HTTPException) as refused:
        run_coroutine(studio.delete_profile(profile_id=p.id, request=_request(), admin=admin, db=db))
    _asked_for_the_step_up(refused)
    assert len(_profiles(db)) == 1
    run_coroutine(studio.delete_profile(profile_id=p.id, request=_request(_receipt(db, admin)), admin=admin, db=db))
    assert _profiles(db) == []


@pytest.mark.parametrize("stored", [True, False], ids=["stored-profile", "unsaved-profile"])
def test_a_profile_test_send_needs_the_step_up(db, admin, sent, stored):
    fields = ({"profile_id": _profile(db).id} if stored else
              {"smtp_server": "mail.example.test", "smtp_port": 587, "from_email": "vault@example.test"})
    payload = studio.ProfileTestIn(to_addr="someone@example.test", **fields)
    with pytest.raises(HTTPException) as refused:
        run_coroutine(studio.test_profile(payload=payload, request=_request(), admin=admin, db=db))
    _asked_for_the_step_up(refused)
    assert sent == []
    run_coroutine(studio.test_profile(payload=payload, request=_request(_receipt(db, admin)), admin=admin, db=db))
    assert sent == ["mail.example.test"]


def test_a_receipt_for_another_fixed_action_opens_no_profile_route(db, admin):
    other = _receipt(db, admin, action="admin.auth_policy.write")
    with pytest.raises(HTTPException) as refused:
        run_coroutine(studio.create_profile(payload=_body(), request=_request(other), admin=admin, db=db))
    _asked_for_the_step_up(refused)
    assert _profiles(db) == []


def test_a_receipt_is_used_once(db, admin):
    receipt = _receipt(db, admin)
    run_coroutine(studio.create_profile(payload=_body(), request=_request(receipt), admin=admin, db=db))
    with pytest.raises(HTTPException) as refused:
        run_coroutine(studio.create_profile(payload=_body(name="Second"), request=_request(receipt), admin=admin,
                                            db=db))
    _asked_for_the_step_up(refused)
    assert [x.name for x in _profiles(db)] == ["Relay"]


# --------------------------------------------------------------------------- the older settings

def _store(db, **values):
    db.add(SystemSetting(key=api._SETTINGS_KEY, value={"smtp_server": "mail.example.test", "smtp_port": 587,
                                                      "smtp_username": "relay-user", "smtp_password": RELAY_PASSWORD,
                                                      "from_email": "vault@example.test", "session_timeout": 60,
                                                      "session_renewal_max_hours": 24, **values}))
    db.commit()


def _stored(db):
    db.expire_all()
    return dict(db.get(SystemSetting, api._SETTINGS_KEY).value)


def _save(db, admin, payload, receipt=None):
    return run_coroutine(api.update_settings(payload=payload, request=_request(receipt, "PUT", "/settings"),
                                             current_user=admin, db=db))


@pytest.mark.parametrize("change", [
    {"smtp_server": "elsewhere.example", "smtp_password": "a-new-one"},
    {"smtp_port": 2525, "smtp_password": "a-new-one"},
    {"smtp_password": RELAY_PASSWORD},             # a password sent counts, whether or not it matched
    {"smtp_password": ""},                         # and so does removing it
    {"smtp_allow_insecure_tls": False, "smtp_server": "", "app_name": "Vault"},
], ids=["server", "port", "same-password", "removed-password", "server-emptied"])
def test_a_settings_save_that_changes_the_smtp_settings_needs_the_step_up(db, admin, change):
    _store(db)
    before = _stored(db)
    with pytest.raises(HTTPException) as refused:
        _save(db, admin, change)
    _asked_for_the_step_up(refused)
    assert _stored(db) == before
    _save(db, admin, change, receipt=_receipt(db, admin))
    after = _stored(db)
    assert all(after[k] == v for k, v in change.items())


@pytest.mark.parametrize("payload", [
    {"app_name": "Changed"},
    # A whole-page save: the SMTP settings sent back as GET /settings returned them (no password).
    {"smtp_server": "mail.example.test", "smtp_port": 587, "smtp_username": "relay-user",
     "from_email": "vault@example.test", "app_name": "Changed"},
], ids=["no-smtp-key", "whole-page"])
def test_a_settings_save_that_leaves_the_smtp_settings_takes_the_ordinary_step_up(db, admin, monkeypatch, payload):
    _store(db)
    seen = []
    monkeypatch.setattr(api, "_enforce_step_up", lambda db_, user, request, action: seen.append(action))
    _save(db, admin, payload)
    assert seen == ["admin.settings.write"]
    assert _stored(db)["app_name"] == "Changed" and _stored(db)["smtp_password"] == RELAY_PASSWORD


@pytest.mark.parametrize("other", [{"session_timeout": 240}, {"mfa_mode": "required"}],
                         ids=["longer-session", "second-factor-policy"])
def test_the_smtp_settings_are_saved_on_their_own(db, admin, other):
    _store(db)
    with pytest.raises(HTTPException) as refused:
        _save(db, admin, {"smtp_server": "elsewhere.example", "smtp_password": "a-new-one", **other},
              receipt=_receipt(db, admin))
    assert refused.value.status_code == 400 and "on their own" in refused.value.detail
    assert _stored(db)["smtp_server"] == "mail.example.test"


def test_the_settings_test_send_needs_the_step_up(db, admin, monkeypatch):
    _store(db, smtp_username="", smtp_password="", smtp_port=2525)
    connected = []

    class Server:
        def __init__(self, host, port, *a, **k):
            connected.append((host, port))

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def ehlo(self):
            pass

        def has_extn(self, name):
            return False

        def send_message(self, msg):
            pass

    monkeypatch.setattr(smtplib, "SMTP", Server)
    with pytest.raises(HTTPException) as refused:
        run_coroutine(api.send_test_email(request=_request(), current_user=admin, db=db))
    _asked_for_the_step_up(refused)
    assert connected == []
    answer = run_coroutine(api.send_test_email(request=_request(_receipt(db, admin)), current_user=admin, db=db))
    assert answer == {"message": "Test email sent to ada@example.test"}
    assert connected == [("mail.example.test", 2525)]
