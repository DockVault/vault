"""The stored SMTP password goes only where it was entered for, offline on a throwaway database.

A request that changes a mail relay's server, port or username, or turns its certificate check off, while keeping
a stored password, must carry the password (app/core/mail_relay.py). A sending profile's save and its test send,
and a save of the older SMTP settings held with the general settings, are refused without it (400, reason
``smtp_password_required``), with nothing saved or sent and the refusal in the audit log; with it they go ahead and
the change is recorded. A request that changes none of these keeps the stored password, as before.
"""
import tempfile
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from fastapi import HTTPException
from sqlalchemy.orm import sessionmaker

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.api import email_studio_router as studio  # noqa: E402
from app.core import email_send, mail_relay  # noqa: E402
from app.core.models import AuditLog, EmailProfile, RoleEnum, SystemSetting, User  # noqa: E402
from app.core.security import decrypt_secret, encrypt_secret  # noqa: E402

pytestmark = pytest.mark.unit

STORED = "stored-relay-password-1"
FRESH = "fresh-relay-password-2"
REFUSAL = {"reason": "smtp_password_required", "message": mail_relay.REENTER_PASSWORD}
RELAY = {"smtp_server": "mail.example.test", "smtp_port": 587, "smtp_username": "relay-user"}


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'relay.db'}")
        copies = sa.MetaData()
        for model in (User, AuditLog, SystemSetting, EmailProfile):
            table = model.__table__.to_metadata(copies)
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
    user = User(username="ada", email="ada@example.test", password_hash="x", role=RoleEnum.ADMIN,
                is_active=True, is_locked=False)
    db.add(user)
    db.commit()
    return user


@pytest.fixture(autouse=True)
def quiet(monkeypatch):
    from app.core import rate_limiter
    monkeypatch.setattr(rate_limiter.rate_limiter, "check_rate_limit", lambda **kw: (True, 0, 0))
    monkeypatch.setattr(api, "_enforce_step_up", lambda *a, **k: None)


@pytest.fixture
def sent(monkeypatch):
    """What each test send would have sent: the relay and the password it would have used. Nothing leaves."""
    out = []

    def record(cfg, msg):
        out.append({k: cfg.get(k) for k in (*mail_relay.FIELDS, mail_relay.PASSWORD)})
    monkeypatch.setattr(email_send, "smtp_send", record)
    return out


def _request():
    return SimpleNamespace(headers={}, client=SimpleNamespace(host="192.0.2.10"))


def _refusals(db):
    db.expire_all()
    return [r for r in db.query(AuditLog).all() if r.action == "mail_relay_change_refused"]


def _rows(db, action):
    db.expire_all()
    return [r for r in db.query(AuditLog).all() if r.action == action]


# --------------------------------------------------------------------------- the rule itself

def test_the_rule_reads_a_relay_without_case_spaces_or_a_missing_port():
    assert mail_relay.relay(" Mail.Example.TEST ", None, " u ") == mail_relay.relay("mail.example.test", 587, "u")
    assert mail_relay.relay(port="2525").port == 2525
    assert mail_relay.relay(port="not-a-port").port == "not-a-port"      # differs from every port
    assert mail_relay.of({"smtp_allow_insecure_tls": "false"}).insecure_tls is False
    assert mail_relay.of({"smtp_allow_insecure_tls": "true"}).insecure_tls is True


@pytest.mark.parametrize("after,moved", [
    ({"smtp_server": "elsewhere.example"}, {"smtp_server"}),
    ({"smtp_port": 2525}, {"smtp_port"}),
    ({"smtp_username": "someone-else"}, {"smtp_username"}),
    ({"smtp_allow_insecure_tls": True}, {"smtp_allow_insecure_tls"}),
    ({"smtp_server": "MAIL.example.test "}, set()),
])
def test_what_moves_where_the_password_goes(after, moved):
    before = mail_relay.of(RELAY)
    assert set(mail_relay.changes(before, mail_relay.of({**RELAY, **after}))) == moved


def test_turning_the_certificate_check_back_on_moves_nothing():
    insecure = mail_relay.of({**RELAY, "smtp_allow_insecure_tls": True})
    assert mail_relay.changes(insecure, mail_relay.of(RELAY)) == {}


@pytest.mark.parametrize("stored,kept,server,refused", [
    (True, True, "elsewhere.example", True),     # the one case refused
    (False, True, "elsewhere.example", False),   # no stored password: nothing to send
    (True, False, "elsewhere.example", False),   # the request carries a password, or removes the stored one
    (True, True, "", False),                     # no server: nothing is sent anywhere
])
def test_only_a_kept_stored_password_pointed_at_a_new_server_is_refused(stored, kept, server, refused):
    moved = mail_relay.refused(mail_relay.of(RELAY), mail_relay.of({**RELAY, "smtp_server": server}),
                               password_stored=stored, password_kept=kept)
    assert bool(moved) is refused


def test_a_settings_save_changes_the_relay_only_when_a_relay_field_or_a_password_changes():
    stored = {**RELAY, "smtp_password": STORED, "app_name": "Vault"}
    assert not mail_relay.settings_change(stored, {"app_name": "Other"})
    assert not mail_relay.settings_change(stored, {**RELAY, "smtp_port": "587", "app_name": "Vault"})
    assert mail_relay.settings_change(stored, {"smtp_server": "elsewhere.example"})
    assert mail_relay.settings_change(stored, {"smtp_password": STORED})       # never says whether it matched
    assert mail_relay.settings_change(stored, {"smtp_password": ""})           # removing it
    assert not mail_relay.settings_change({**RELAY}, {"smtp_password": ""})    # nothing stored, nothing removed
    assert mail_relay.settings_change(stored, {"smtp_allow_insecure_tls": True})


# --------------------------------------------------------------------------- a sending profile's save

def _profile(db, password=STORED, **over):
    p = EmailProfile(name="Relay", smtp_server=RELAY["smtp_server"], smtp_port=RELAY["smtp_port"],
                     smtp_username=RELAY["smtp_username"],
                     smtp_password=encrypt_secret(password) if password else None,
                     from_email="vault@example.test", is_default=True, **over)
    db.add(p)
    db.commit()
    return p


def _update(db, admin, p, **over):
    body = {"name": p.name, "smtp_server": p.smtp_server, "smtp_port": p.smtp_port,
            "smtp_username": p.smtp_username, "from_email": p.from_email,
            "smtp_allow_insecure_tls": bool(p.smtp_allow_insecure_tls), **over}
    return run_coroutine(studio.update_profile(profile_id=p.id, payload=studio.ProfileIn(**body),
                                               request=_request(), admin=admin, db=db))


def _reloaded(db, p):
    db.expire_all()
    return db.get(EmailProfile, p.id)


@pytest.mark.parametrize("over", [{"smtp_server": "elsewhere.example"}, {"smtp_port": 2525},
                                  {"smtp_username": "someone-else"}, {"smtp_allow_insecure_tls": True}],
                         ids=["server", "port", "username", "certificate-check"])
def test_a_profile_save_that_moves_the_stored_password_without_it_is_refused(db, admin, over):
    p = _profile(db)
    with pytest.raises(HTTPException) as refused:
        _update(db, admin, p, name="Renamed", **over)
    assert refused.value.status_code == 400 and refused.value.detail == REFUSAL
    kept = _reloaded(db, p)
    assert (kept.name, kept.smtp_server, kept.smtp_port, kept.smtp_username, kept.smtp_allow_insecure_tls) == (
        "Relay", RELAY["smtp_server"], RELAY["smtp_port"], RELAY["smtp_username"], False)
    assert decrypt_secret(kept.smtp_password) == STORED
    [row] = _refusals(db)
    field = next(iter(over))
    assert row.status == "failure" and row.details["surface"] == "profile_update"
    assert row.details["profile_id"] == str(p.id) and set(row.details["changes"]) == {field}
    assert STORED not in str(row.details)
    assert _rows(db, "email_profile_updated") == []


def test_a_profile_save_with_the_password_moves_it_and_records_the_change(db, admin):
    p = _profile(db)
    out = _update(db, admin, p, smtp_server="elsewhere.example", smtp_password=FRESH)
    assert out["smtp_server"] == "elsewhere.example" and out["has_password"] is True
    assert decrypt_secret(_reloaded(db, p).smtp_password) == FRESH
    [row] = _rows(db, "email_profile_updated")
    assert row.details["changes"] == {
        "smtp_server": {"old": RELAY["smtp_server"], "new": "elsewhere.example"},
        "smtp_password": {"old": "(set)", "new": "(set)"}}
    assert FRESH not in str(row.details) and _refusals(db) == []


def test_a_profile_save_that_moves_nothing_keeps_the_stored_password(db, admin):
    p = _profile(db, smtp_allow_insecure_tls=True)
    # A rename, another From, the server's case, and the certificate check turned back on: no password asked.
    out = _update(db, admin, p, name="Renamed", from_email="other@example.test",
                  smtp_server="MAIL.example.test", smtp_allow_insecure_tls=False)
    assert out["name"] == "Renamed" and out["has_password"] is True
    assert decrypt_secret(_reloaded(db, p).smtp_password) == STORED
    [row] = _rows(db, "email_profile_updated")
    assert "changes" not in row.details or not row.details["changes"]
    assert _refusals(db) == []


def test_a_profile_with_no_stored_password_may_be_pointed_anywhere(db, admin):
    p = _profile(db, password=None)
    out = _update(db, admin, p, smtp_server="elsewhere.example")
    assert out["smtp_server"] == "elsewhere.example" and out["has_password"] is False
    [row] = _rows(db, "email_profile_updated")
    assert row.details["changes"] == {"smtp_server": {"old": RELAY["smtp_server"], "new": "elsewhere.example"}}


# --------------------------------------------------------------------------- a sending profile's test send

def _test(db, admin, **fields):
    return run_coroutine(studio.test_profile(payload=studio.ProfileTestIn(to_addr="someone@example.test", **fields),
                                             request=_request(), admin=admin, db=db))


@pytest.mark.parametrize("overlay", [{"smtp_server": "elsewhere.example"}, {"smtp_port": 2525},
                                     {"smtp_username": "someone-else"}, {"smtp_allow_insecure_tls": True}],
                         ids=["server", "port", "username", "certificate-check"])
def test_a_test_send_over_a_stored_profile_without_the_password_is_refused(db, admin, sent, overlay):
    p = _profile(db)
    with pytest.raises(HTTPException) as refused:
        _test(db, admin, profile_id=p.id, **overlay)
    assert refused.value.status_code == 400 and refused.value.detail == REFUSAL
    assert sent == []
    [row] = _refusals(db)
    assert row.details["surface"] == "profile_test" and set(row.details["changes"]) == set(overlay)
    assert _rows(db, "email_profile_test_sent") == []


def test_a_test_send_with_the_password_goes_where_it_is_pointed(db, admin, sent):
    p = _profile(db)
    _test(db, admin, profile_id=p.id, smtp_server="elsewhere.example", smtp_allow_insecure_tls=True,
          smtp_password=FRESH)
    [used] = sent
    assert used["smtp_server"] == "elsewhere.example" and used["smtp_password"] == FRESH
    assert used["smtp_allow_insecure_tls"] is True
    [row] = _rows(db, "email_profile_test_sent")
    assert set(row.details["changes"]) == {"smtp_server", "smtp_allow_insecure_tls"}
    assert decrypt_secret(_reloaded(db, p).smtp_password) == STORED      # a test saves nothing


def test_a_test_send_that_moves_nothing_uses_the_stored_password(db, admin, sent):
    p = _profile(db)
    _test(db, admin, profile_id=p.id, smtp_server=" Mail.example.test", smtp_port=587, smtp_username="relay-user",
          from_email="other@example.test")
    [used] = sent
    assert used["smtp_password"] == STORED and _refusals(db) == []


def test_an_unsaved_profile_is_tested_with_what_it_is_given(db, admin, sent):
    _test(db, admin, smtp_server="anywhere.example", smtp_port=465, from_email="vault@example.test",
          smtp_allow_insecure_tls=True)
    [used] = sent
    assert used["smtp_server"] == "anywhere.example" and used["smtp_password"] == ""
    assert _refusals(db) == []


# --------------------------------------------------------------------------- the older settings (PUT /settings)

def _store(db, **values):
    db.add(SystemSetting(key=api._SETTINGS_KEY, value={**RELAY, "smtp_password": STORED,
                                                      "from_email": "vault@example.test", **values}))
    db.commit()


def _stored(db):
    db.expire_all()
    return dict(db.get(SystemSetting, api._SETTINGS_KEY).value)


def _save(db, admin, payload):
    return run_coroutine(api.update_settings(payload=payload, request=_request(), current_user=admin, db=db))


@pytest.mark.parametrize("change", [{"smtp_server": "elsewhere.example"}, {"smtp_port": 2525},
                                    {"smtp_username": "someone-else"}, {"smtp_allow_insecure_tls": True}],
                         ids=["server", "port", "username", "certificate-check"])
def test_a_settings_save_that_moves_the_stored_password_without_it_is_refused(db, admin, change):
    _store(db)
    before = _stored(db)
    with pytest.raises(HTTPException) as refused:
        _save(db, admin, {"app_name": "Changed", **change})
    assert refused.value.status_code == 400 and refused.value.detail == REFUSAL
    assert _stored(db) == before
    [row] = _refusals(db)
    assert row.details["surface"] == "settings" and set(row.details["changes"]) == set(change)
    assert STORED not in str(row.details)
    assert _rows(db, "settings_updated") == []


def test_a_settings_save_with_the_password_moves_it_and_records_the_change(db, admin):
    _store(db)
    _save(db, admin, {"smtp_server": "elsewhere.example", "smtp_password": FRESH})
    stored = _stored(db)
    assert stored["smtp_server"] == "elsewhere.example" and stored["smtp_password"] == FRESH
    [row] = _rows(db, "settings_updated")
    assert row.details["changes"]["smtp_server"] == {"old": RELAY["smtp_server"], "new": "elsewhere.example"}
    assert row.details["changes"]["smtp_password"] == {"old": "(set)", "new": "(set)"}
    assert _refusals(db) == []


def test_a_whole_page_save_sends_the_relay_back_and_keeps_the_stored_password(db, admin):
    # The settings page sends back everything GET /settings returned (no password) with its own changes.
    _store(db, app_name="Vault")
    page = {k: v for k, v in _stored(db).items() if k != "smtp_password"}
    _save(db, admin, {**page, "smtp_server": "MAIL.example.test", "smtp_port": "587", "app_name": "Changed"})
    stored = _stored(db)
    assert stored["app_name"] == "Changed" and stored["smtp_password"] == STORED
    assert _refusals(db) == []


def test_a_settings_save_that_removes_the_stored_password_may_move_the_relay(db, admin):
    _store(db)
    _save(db, admin, {"smtp_server": "elsewhere.example", "smtp_password": ""})
    stored = _stored(db)
    assert stored["smtp_server"] == "elsewhere.example" and not stored["smtp_password"]


def test_emptying_the_server_sends_nothing_and_needs_no_password_but_a_new_one_does(db, admin):
    _store(db)
    _save(db, admin, {"smtp_server": ""})
    assert _stored(db)["smtp_server"] == "" and _stored(db)["smtp_password"] == STORED
    with pytest.raises(HTTPException) as refused:
        _save(db, admin, {"smtp_server": "elsewhere.example"})
    assert refused.value.detail == REFUSAL and _stored(db)["smtp_server"] == ""


def test_settings_with_no_stored_password_may_be_pointed_anywhere(db, admin):
    db.add(SystemSetting(key=api._SETTINGS_KEY, value=dict(RELAY)))
    db.commit()
    _save(db, admin, {"smtp_server": "elsewhere.example"})
    assert _stored(db)["smtp_server"] == "elsewhere.example"


# --------------------------------------------------------------------------- the older settings' test send

def test_the_settings_test_send_reads_nothing_from_the_request():
    """POST /settings/test-email sends with the stored settings alone: it takes no body and reads none, so no
    request can point the stored password elsewhere through it."""
    import ast
    import inspect
    import textwrap
    fn = api.send_test_email
    assert list(inspect.signature(fn).parameters) == ["request", "current_user", "db"]
    tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    reads = {ast.unparse(n) for n in ast.walk(tree)
             if isinstance(n, ast.Attribute) and ast.unparse(n.value) == "request"}
    assert reads <= {"request.headers", "request.client"}, reads
