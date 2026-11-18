"""Emailed links are built on the configured public address only, never on a request's Host header.

A request's Host header is whatever its sender wrote. Building an emailed link on it would send a reset or
invitation token, or a link to sign in, to an address the sender chose. Each case runs with a forged Host,
twice: with no public address configured (ALLOWED_HOSTS empty), where no tokened link is emailed (the
self-service reset sends nothing; an invitation's or an administrator's reset link is handed over relative, for
the administrator's own page to complete; a notice's email goes without its link), and with one configured,
where every link is built on it. tests/test_email_default_templates.py pins that no caller passes the request
at all.
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
from app.core import email_actions  # noqa: E402
from app.core.models import (AccountInvitation, AdminGrant, AuditLog, CredentialChange,  # noqa: E402
                             PasswordResetToken, RoleEnum, SystemSetting, User)

pytestmark = pytest.mark.unit

FORGED = "evil.example"
CONFIGURED = "https://vault.example.com"
PEPPER = "p" * 48


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'links.db'}")
        for model in (User, AdminGrant, CredentialChange, AuditLog, AccountInvitation, SystemSetting,
                      PasswordResetToken):
            model.__table__.create(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


@pytest.fixture(params=["no public address", "a public address"])
def address(request, monkeypatch):
    value = "" if request.param == "no public address" else CONFIGURED
    monkeypatch.setattr(email_actions, "vault_url", lambda: value)
    return value


@pytest.fixture
def sent(monkeypatch):
    """Every email the server asks to send: (action, recipient, action_context)."""
    out = []

    def _send(db, action, recipient=None, action_context=None, **kw):
        out.append((action, recipient, dict(action_context or {})))
        return True

    monkeypatch.setattr(email_actions, "send_action_email", _send)
    return out


def _forged_request():
    from starlette.requests import Request
    return Request({"type": "http", "method": "POST", "path": "/x", "raw_path": b"/x", "query_string": b"",
                    "headers": [(b"host", FORGED.encode())], "client": ("198.51.100.7", 40000),
                    "server": (FORGED, 443), "scheme": "https", "root_path": ""})


def _user(db, name, role=RoleEnum.ADMIN, email=None):
    u = User(username=name, email=email, password_hash="x", role=role, is_active=True, is_locked=False)
    db.add(u)
    db.commit()
    return u


def _no_forged_host(*things):
    assert FORGED not in repr(things), things


def test_an_invitation_is_emailed_only_on_the_public_address_made_and_sent_again(db, monkeypatch, address, sent):
    monkeypatch.setattr(api, "_invite_pepper", lambda: PEPPER)
    monkeypatch.setattr(api, "_account_policy", lambda db: {"invite_enabled": True, "email_requirement": "optional",
                                                           "invite_ttl_hours": 24})
    monkeypatch.setattr(api, "_enforce_step_up", lambda *a, **k: None)
    alice = _user(db, "alice")
    made = run_coroutine(api.create_invite(payload=api.InviteCreate(username="newbie", email="new@example.com"),
                                           current_user=alice, db=db, request=_forged_request()))
    again = run_coroutine(api.resend_invite(invite_id=made["id"], current_user=alice, db=db,
                                            request=_forged_request()))
    for answer in (made, again):
        assert answer["invite_url"].startswith(f"{address}/?invite="), answer["invite_url"]
        assert answer["public_address_configured"] is bool(address)
        assert answer["email_sent"] is bool(address)
    if address:
        assert [a for a, _, _ in sent] == ["account_invite", "account_invite"]
        assert [c["link"] for _, _, c in sent] == [made["invite_url"], again["invite_url"]]
    else:
        assert sent == [], "an invitation was emailed with no public address to build its link on"
    _no_forged_host(made, again, sent)


def test_a_self_service_reset_is_sent_only_on_the_public_address(db, monkeypatch, address):
    from app.core import rate_limiter
    started = []
    monkeypatch.setattr(rate_limiter.rate_limiter, "check_rate_limit", lambda *a, **k: (True, 0, 0))
    monkeypatch.setattr(api, "_password_reset_policy", lambda db: (True, 5))
    monkeypatch.setattr(api, "_smtp_configured", lambda db: True)
    monkeypatch.setattr(api, "_resolve_reset_user", lambda db, identifier: SimpleNamespace(id=uuid.uuid4()))
    monkeypatch.setattr(api, "_mint_and_send_reset_async", lambda user_id, base: started.append(base))
    answer = run_coroutine(api.forgot_password(body=api.ForgotPasswordRequest(identifier="carol"),
                                               request=_forged_request(), db=db))
    assert answer.status_code == 202
    assert started == ([CONFIGURED] if address else []), started


def test_a_reset_email_is_neither_minted_nor_sent_without_a_public_address(db, monkeypatch, sent):
    monkeypatch.setattr(api, "_reset_pepper", lambda: PEPPER)
    carol = _user(db, "carol", RoleEnum.USER, email="carol@example.com")
    assert api._mint_and_send_reset(db, carol, "", created_by_id=None) is False
    assert sent == [] and db.query(PasswordResetToken).count() == 0
    assert api._mint_and_send_reset(db, carol, CONFIGURED, created_by_id=None) is True
    assert sent[0][2]["link"].startswith(f"{CONFIGURED}/?reset=")


def test_an_administrators_reset_link_is_relative_without_a_public_address_and_not_emailed(db, monkeypatch, address,
                                                                                           sent):
    monkeypatch.setattr(api, "_reset_pepper", lambda: PEPPER)
    monkeypatch.setattr(api, "_smtp_configured", lambda db: True)
    carol = _user(db, "carol", RoleEnum.USER, email="carol@example.com")

    def change(delivery):
        return api._apply_credential_change(db, "reset_link", carol, {"delivery": delivery}, actor_id=None,
                                            actor_name="x", request=_forged_request())

    copied = change("copy")
    assert copied["reset_link"].startswith(f"{address}/?reset="), copied
    if address:
        assert change("email") == {"email_sent": True} and sent[0][2]["link"].startswith(f"{CONFIGURED}/?reset=")
    else:
        with pytest.raises(HTTPException) as refused:
            change("email")
        assert refused.value.status_code == 400 and "ALLOWED_HOSTS" in refused.value.detail
        assert sent == []
    _no_forged_host(copied, sent)


def test_the_promotion_reset_is_emailed_only_on_the_public_address(db, monkeypatch, address, sent):
    monkeypatch.setattr(api, "_reset_pepper", lambda: PEPPER)
    monkeypatch.setattr(api, "_smtp_configured", lambda db: True)
    monkeypatch.setattr(api, "_notify_account_change", lambda *a, **k: None)
    carol = _user(db, "carol", RoleEnum.ADMIN, email="carol@example.com")
    alice = _user(db, "alice")
    handed = api._hand_over_promotion_reset(db, {"user_id": carol.id}, by=alice, request=_forged_request())
    if address:
        assert handed["emailed"] is True and sent[0][2]["link"].startswith(f"{CONFIGURED}/?reset=")
    else:
        assert handed["emailed"] is False and sent == []
        assert handed["reset_link"].startswith("/?reset="), handed
    _no_forged_host(handed, sent)


def test_the_ssh_key_notice_links_only_to_the_public_address(db, monkeypatch, address):
    fired = []
    monkeypatch.setattr(api, "_fire_action_email", lambda db, action, **kw: fired.append(kw["action_context"]))
    monkeypatch.setattr(api, "_notify_users", lambda *a, **k: None)
    report = {"maker": "alice", "because": "demoted",
              "owners": [{"user_id": uuid.uuid4(), "username": "carol", "email": "carol@example.com",
                          "keys": [("laptop", "SHA256:abc")]}]}
    api._announce_keys_reported(db, report, request=_forged_request())
    assert [c["link"] for c in fired] == ([f"{CONFIGURED}/#profile"] if address else [""]), fired


def test_an_administrators_emailed_reset_link_is_refused_before_anything_is_made_or_held(db, monkeypatch, sent):
    """With no public address the route refuses at once, beside its other pre-checks: a reset link that would be the
    account's second change in 14 days was held, its approvers told, and refused only at approval."""
    import inspect
    monkeypatch.setattr(email_actions, "vault_url", lambda: "")
    monkeypatch.setattr(api, "_smtp_configured", lambda db: True)
    asked = []
    monkeypatch.setattr(api, "_credential_change", lambda *a, **k: asked.append(a) or pytest.fail("reached"))
    alice = _user(db, "alice")
    carol = _user(db, "carol", RoleEnum.USER, email="carol@example.com")
    route = inspect.unwrap(api.admin_send_reset_link)
    with pytest.raises(HTTPException) as refused:
        run_coroutine(route(user_id=carol.id, request=_forged_request(), current_user=alice, db=db))
    assert refused.value.status_code == 400 and "ALLOWED_HOSTS" in refused.value.detail
    assert asked == [] and sent == [] and db.query(CredentialChange).count() == 0


def test_settings_report_whether_a_public_address_is_configured():
    """The page shows the reset switch's note and the invitation dialog's reason from this flag, which is the
    helper's own answer. (get_settings runs PostgreSQL-only SQL, so it is read here rather than called.)"""
    import ast
    tree = ast.parse((Path(__file__).resolve().parents[1] / "app" / "api" / "api_server.py").read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.name == "get_settings")
    flags = [n for n in ast.walk(fn) if isinstance(n, ast.Assign)
             and ast.unparse(n.targets[0]) == "data['public_address_configured']"]
    assert len(flags) == 1 and ast.unparse(flags[0].value) == "bool(_public_base_url())", [ast.unparse(f) for f in flags]


def test_the_share_notice_links_only_to_the_public_address(address):
    """The share is made on the sharer's request, Host and all; the notice's context is built without it."""
    share = SimpleNamespace(expires_at=None)
    assert api._share_notice_context(share) == {"link": f"{CONFIGURED}/#shared" if address else "", "expires": ""}
    import ast
    import inspect
    assert list(inspect.signature(api._share_notice_context).parameters) == ["share"], "it must not see the request"
    body = ast.parse(inspect.getsource(inspect.unwrap(api.create_share)).lstrip())
    uses = [ast.unparse(n) for n in ast.walk(body) if isinstance(n, ast.Name) and n.id == "_share_ctx"]
    assigned = [ast.unparse(n) for n in ast.walk(body) if isinstance(n, ast.Assign)
                and any(getattr(t, "id", None) == "_share_ctx" for t in n.targets)]
    assert assigned == ["_share_ctx = _share_notice_context(share)"] and len(uses) == 2, (assigned, uses)
    assert "_fire_action_email_bulk(db, 'share_created', _share_pairs, _share_ctx)" in ast.unparse(body)


def test_the_upload_notice_links_only_to_the_public_address(db, monkeypatch, address):
    """The upload's request is the anonymous uploader's, and the notice goes to the link's owner by email."""
    fired = []
    monkeypatch.setattr(api, "_notify_users", lambda *a, **k: True)
    monkeypatch.setattr(api, "_fire_action_email", lambda db, action, **kw: fired.append(kw["action_context"]))
    owner = SimpleNamespace(id=uuid.uuid4(), email="owner@example.com", username="owner")
    api._tell_receiver_owner(db, _forged_request(), SimpleNamespace(id=uuid.uuid4(), label="drop"), owner,
                             SimpleNamespace(id=uuid.uuid4()), SimpleNamespace(id=uuid.uuid4()))
    assert [c["link"] for c in fired] == ([f"{CONFIGURED}/#uploadlinks/drops"] if address else [""]), fired
    _no_forged_host(fired)
