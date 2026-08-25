"""The optional automated-email TRIGGERS wired into real flows (welcome, sign-in, temp-credential,
vault-member add).

Each is opt-in: it delivers only when the admin has turned the action ON (and it's bound to a template),
and it never blocks or breaks the flow that triggered it (the send is fanned out on a background thread).
These exercise the real endpoints against a live instance + Mailpit; a message can take a moment because
the send is asynchronous, so each assertion polls.
"""
import os
import time

import pytest
import requests

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.integration

MAILPIT_URL = os.environ.get("VAULT_MAILPIT_URL")
MAILPIT_SMTP_HOST = os.environ.get("VAULT_MAILPIT_SMTP_HOST")
MAILPIT_SMTP_PORT = os.environ.get("VAULT_MAILPIT_SMTP_PORT", "1025")
_mailpit = pytest.mark.skipif(not (MAILPIT_URL and MAILPIT_SMTP_HOST),
                              reason="no Mailpit sink (bring the round up WITH_MAILPIT)")


def _mp_clear():
    requests.delete(f"{MAILPIT_URL}/api/v1/messages", timeout=10)


def _mp_wait(to, timeout=15):
    to = to.lower()
    deadline = time.time() + timeout
    while time.time() < deadline:
        for m in requests.get(f"{MAILPIT_URL}/api/v1/messages", timeout=10).json().get("messages", []):
            if to in [a.get("Address", "").lower() for a in m.get("To", [])]:
                full = requests.get(f"{MAILPIT_URL}/api/v1/message/{m['ID']}", timeout=10).json()
                return m, full
        time.sleep(0.4)
    return None, None


def _mp_none(to, settle=3.0):
    """Assert NO message reaches `to` within a short settle window (for the disabled/negative cases)."""
    to = to.lower()
    deadline = time.time() + settle
    while time.time() < deadline:
        for m in requests.get(f"{MAILPIT_URL}/api/v1/messages", timeout=10).json().get("messages", []):
            if to in [a.get("Address", "").lower() for a in m.get("To", [])]:
                return False
        time.sleep(0.3)
    return True


@pytest.fixture
def mailpit_profile(admin):
    """A default sending profile pointed at Mailpit, restored after the test."""
    before = admin.get("/email/profiles").json()["profiles"]
    for p in before:
        admin.delete(f"/email/profiles/{p['id']}")
    admin.post("/email/profiles", json={"name": "MP", "smtp_server": MAILPIT_SMTP_HOST,
                                        "smtp_port": int(MAILPIT_SMTP_PORT), "smtp_username": "",
                                        "from_email": "sender@example.com", "is_default": True})
    yield
    for p in admin.get("/email/profiles").json()["profiles"]:
        admin.delete(f"/email/profiles/{p['id']}")


def _default_template_id(admin, key):
    for t in admin.get("/email/templates").json()["templates"]:
        if t.get("default_key") == key:
            return t["id"]
    raise AssertionError(f"no default template for {key}")


def _set_action(admin, key, *, enabled):
    # Bind the built-in default template and set the enabled flag (both needed for an optional action).
    admin.put(f"/email/actions/{key}",
              json={"template_id": _default_template_id(admin, key) if enabled else None, "enabled": enabled})


@pytest.fixture
def welcome_off(admin):
    # Keep account_welcome OFF around tests that would otherwise email every account the suite creates.
    _set_action(admin, "account_welcome", enabled=False)
    yield
    _set_action(admin, "account_welcome", enabled=False)


@_mailpit
def test_account_welcome_delivered_on_admin_create(admin, mailpit_profile):
    _mp_clear()
    _set_action(admin, "account_welcome", enabled=True)
    try:
        email = f"welc-{unique('u')}@example.com"
        u = admin.create_user(email=email)
        try:
            m, _ = _mp_wait(email)
            assert m is not None, "welcome email was not delivered to the new account"
            assert "welcome" in (m.get("Subject") or "").lower()
        finally:
            admin.delete_user(u["id"])
    finally:
        _set_action(admin, "account_welcome", enabled=False)


@_mailpit
def test_account_welcome_not_sent_when_disabled(admin, mailpit_profile, welcome_off):
    _mp_clear()
    email = f"nowelc-{unique('u')}@example.com"
    u = admin.create_user(email=email)
    try:
        assert _mp_none(email), "a welcome email was sent even though the action is disabled"
    finally:
        admin.delete_user(u["id"])


@_mailpit
def test_login_alert_delivered_on_signin(admin, mailpit_profile, welcome_off):
    _mp_clear()
    _set_action(admin, "login_alert", enabled=True)
    email = f"login-{unique('u')}@example.com"
    u = admin.create_user(email=email)
    try:
        _mp_clear()   # ignore any welcome; we only assert the sign-in alert below
        member = ApiClient(BASE_URL)
        member.login(u["_username"], u["_password"])       # a real (non-temp) sign-in
        m, _ = _mp_wait(email)
        assert m is not None, "sign-in alert was not delivered"
        assert "sign-in" in (m.get("Subject") or "").lower()
    finally:
        _set_action(admin, "login_alert", enabled=False)
        admin.delete_user(u["id"])


@_mailpit
def test_temp_credential_issued_delivered_to_owner(admin, admin_creds, mailpit_profile, welcome_off):
    # The admin account has an email (ADMIN_EMAIL); minting a temp credential notifies the owner.
    _mp_clear()
    _set_action(admin, "temp_credential_issued", enabled=True)
    try:
        me = admin.get("/users/me").json()
        owner_email = (me.get("email") or "").strip()
        if not owner_email:
            pytest.skip("admin account has no email to notify")
        r = admin.post("/auth/temp-credentials", json={"note": unique("trig")})
        assert r.status_code == 200, r.text
        m, _ = _mp_wait(owner_email)
        assert m is not None, "temp-credential notice was not delivered to the owner"
        assert "temporary" in (m.get("Subject") or "").lower()
    finally:
        _set_action(admin, "temp_credential_issued", enabled=False)


@_mailpit
def test_vault_member_added_emails_only_a_new_member(admin, mailpit_profile, welcome_off):
    _mp_clear()
    _set_action(admin, "vault_member_added", enabled=True)
    email = f"member-{unique('u')}@example.com"
    u = admin.create_user(email=email)
    vault = admin.create_vault(name=unique("vt"), password="Vaultpassw0rd!1")
    try:
        r = admin.post(f"/vaults/{vault['id']}/permissions", json={"user_id": u["id"], "level": "read"})
        assert r.status_code in (200, 201), r.text
        m, _ = _mp_wait(email)
        assert m is not None, "the new member was not emailed"
        assert "vault" in (m.get("Subject") or "").lower()
        # A re-grant that only changes the level must NOT email again (idempotent membership).
        _mp_clear()
        r2 = admin.post(f"/vaults/{vault['id']}/permissions", json={"user_id": u["id"], "level": "write"})
        assert r2.status_code in (200, 201), r2.text
        assert _mp_none(email), "a level change re-emailed an existing member"
    finally:
        _set_action(admin, "vault_member_added", enabled=False)
        admin.delete_vault(vault["id"])
        admin.delete_user(u["id"])


@_mailpit
def test_share_created_emails_the_recipient(admin, mailpit_profile, welcome_off):
    _mp_clear()
    _set_action(admin, "share_created", enabled=True)
    orig_sharing = admin.get("/settings").json().get("sharing_enabled")
    admin.put("/settings", json={"sharing_enabled": True})
    email = f"share-{unique('u')}@example.com"
    recipient = admin.create_user(email=email)
    vault = admin.create_vault(name=unique("shv"))   # passwordless so it can be shared
    tag = admin.post("/share-tags", json={"name": unique("shtag"), "allowed_audiences": ["users"],
                                          "auto_enroll_new_users": True,
                                          "max_recipients_cap": 100, "max_downloads_cap": 100}).json()
    try:
        _mp_clear()   # ignore the member/welcome mail; assert the share notice below
        r = admin.post("/shares", json={"vault_id": vault["id"], "tag_id": tag["id"],
                                        "target_type": "vault", "claim_audience": "users",
                                        "audience_user_ids": [recipient["id"]]})
        assert r.status_code == 200, r.text
        m, _ = _mp_wait(email)
        assert m is not None, "the share recipient was not emailed"
        assert "shared" in (m.get("Subject") or "").lower()
    finally:
        _set_action(admin, "share_created", enabled=False)
        if orig_sharing is not None:
            admin.put("/settings", json={"sharing_enabled": orig_sharing})
        admin.delete_vault(vault["id"])
        admin.delete_user(recipient["id"])
