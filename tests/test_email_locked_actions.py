"""The emails about a person's encryption key are locked: the built-in text, through the default profile.

The code that releases an encryption-key envelope during the hold after an administrator changed someone's
sign-in details (app/core/envelope_hold.py) must reach the person, and administrators are who that hold is
about. An email an administrator could bind to a template of their own, or to that template's sending profile,
would let them route every code through a relay they run, or carry it in a link. So the release code and the
encryption-key notice are locked actions: they ignore whatever is bound to them, and Email Studio refuses to
change them at all.
test_email_locked_actions_live.py sends one through a running deployment and a mail sink.
"""
import inspect
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import email_studio_router as studio  # noqa: E402
from app.core import email_actions, email_send  # noqa: E402
from app.core.models import EmailAction, EmailProfile, EmailTemplate  # noqa: E402
from _async_run import run_coroutine  # noqa: E402

pytestmark = pytest.mark.unit

LOCKED = ["encryption_key_release_code", "encryption_key_notice"]
ADMINS_RELAY = {"smtp_server": "relay.example", "from_email": "relay-of-the-admin@example.com", "from_name": ""}
DEFAULT = {"smtp_server": "mail.example", "from_email": "vault@example.com", "from_name": ""}
CUSTOM_BODY = ('<p>Code {{action.code}} {{action.change}} {{action.link}}</p>'
               '<p><a href="https://relay.example/c?k={{action.code}}">Release your key</a></p>')


class _Db:
    def __init__(self, action=None, template=None, profile=None):
        self.action, self.template, self.profile = action, template, profile

    def get(self, model, key):
        if model is EmailAction:
            return self.action if self.action is not None and key == self.action.key else None
        if model is EmailProfile:
            return self.profile if self.profile is not None and key == self.profile.id else None
        if model is EmailTemplate:
            return self.template if self.template is not None and key == self.template.id else None
        return None


@pytest.fixture
def sent(monkeypatch):
    out = []
    monkeypatch.setattr(email_send, "_profile_to_cfg", lambda p: dict(ADMINS_RELAY))
    monkeypatch.setattr(email_send, "resolve_default_config", lambda db: dict(DEFAULT))
    monkeypatch.setattr(email_send, "build_message", lambda cfg, *, to_addr, subject, text_body, html_body,
                        inline_images: {"cfg": cfg, "to": to_addr, "subject": subject, "html": html_body})
    monkeypatch.setattr(email_send, "smtp_send", lambda cfg, msg: out.append(msg))
    monkeypatch.setattr(email_actions, "brand_name", lambda db: "Vault")
    return out


def _bound(key):
    """The action bound to an administrator's own template, whose profile is the administrator's relay."""
    profile = SimpleNamespace(id=uuid.uuid4())
    template = SimpleNamespace(id=uuid.uuid4(), name="mine", subject="Your code", body_html=CUSTOM_BODY,
                               profile_id=profile.id)
    action = SimpleNamespace(key=key, name="n", description="d", category=email_actions.SYSTEM, enabled=True,
                             template=template, template_id=template.id)
    return _Db(action, template, profile)


def _send(db, key):
    return email_actions.send_action_email(
        db, key, recipient={"email": "person@example.com", "username": "person"},
        action_context={"code": "0123456789ab", "expires": "in 15 minutes", "change": "what happened",
                        "when": "now", "link": "https://vault.example.com/?reset=x"})


@pytest.mark.parametrize("key", LOCKED)
def test_a_bound_template_and_its_profile_change_neither_the_sender_nor_the_body(sent, key):
    assert _send(_bound(key), key) is True
    (msg,) = sent
    assert msg["cfg"] == DEFAULT, "sent through the administrator's profile"
    assert "relay.example" not in msg["html"] and "Release your key" not in msg["html"]
    builtin = email_actions.SPEC_BY_KEY[key]
    assert msg["subject"] == builtin["default_subject"].replace("{{vault.name}}", "Vault")
    assert "Hi person" in msg["html"]
    if key == "encryption_key_release_code":
        assert "0123456789ab" in msg["html"]


def test_an_action_that_is_not_locked_still_sends_its_bound_template(sent):
    """The same harness sees a customization where one is allowed: it is the lock that makes the difference."""
    assert _send(_bound("password_reset"), "password_reset") is True
    (msg,) = sent
    assert msg["cfg"] == ADMINS_RELAY and "relay.example" in msg["html"]


def test_the_catalog_names_exactly_the_encryption_key_emails_and_the_owners_notices_as_locked():
    for key in LOCKED:
        assert email_actions.SPEC_BY_KEY[key]["category"] == email_actions.LOCKED
    assert {a["key"] for a in email_actions.ACTION_CATALOG if a["category"] == email_actions.LOCKED} == (
        set(LOCKED) | {"compliance_access_notice", "vault_access_notice"})
    # Always sent, and no default template is made for them: what they send is their built-in wording.
    assert email_actions.LOCKED in email_actions.ALWAYS_ON
    assert not set(LOCKED) & {p["key"] for p in email_actions.default_template_payloads()}


UPDATE = inspect.unwrap(studio.update_action)


@pytest.mark.parametrize("key", LOCKED)
def test_email_studio_refuses_any_change_and_shows_it_locked(key, monkeypatch):
    db = _bound(key)
    db.action.template_id = None
    db.commit = lambda: None
    monkeypatch.setattr(studio, "_audit", lambda *a, **k: None)
    for change in (studio.ActionUpdateIn(template_id=db.template.id), studio.ActionUpdateIn(template_id=None),
                   studio.ActionUpdateIn(enabled=False)):
        with pytest.raises(HTTPException) as refused:
            run_coroutine(UPDATE(key, change, request=None, admin=None, db=db))
        assert refused.value.status_code == 409 and db.action.template_id is None and db.action.enabled is True
    # The listing says it is locked, even for a row that still says it is a system action: the catalog decides.
    assert db.action.category == email_actions.SYSTEM
    assert studio._action_out(db.action)["locked"] is True


def test_email_studio_still_binds_a_template_to_an_action_that_is_not_locked(monkeypatch):
    db = _bound("password_reset")
    db.action.template_id = None
    db.commit = lambda: None
    monkeypatch.setattr(studio, "_audit", lambda *a, **k: None)
    out = run_coroutine(UPDATE("password_reset", studio.ActionUpdateIn(template_id=db.template.id), request=None,
                               admin=None, db=db))
    assert out["locked"] is False and out["template_id"] == str(db.template.id)


def test_the_web_app_shows_a_locked_email_without_a_template_choice():
    from pathlib import Path
    app_js = (Path(__file__).resolve().parents[1] / "static" / "js" / "app.js").read_text(encoding="utf-8")
    body = app_js[app_js.index("function buildActionRow("):app_js.index("async function saveAction(")]
    assert body.count("const locked = a.category === 'locked';") == 1
    start = body.index("    if (locked) {\n")
    locked = body[start:body.index("    } else {\n", start)]
    assert "templates.forEach" not in locked and "<select" not in locked and "createElement('select')" not in locked
    assert "built-in wording" in locked
