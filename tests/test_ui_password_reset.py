"""Settings-independent UI for the password-reset flow: the login "Forgot password?" affordance (shown
only when self-service is enabled) and the /?reset=<token> set-a-new-password page."""
import os
import re
import time

import pytest
import requests
from playwright.sync_api import Page, expect

from conftest import unique

pytestmark = pytest.mark.ui

MAILPIT_URL = os.environ.get("VAULT_MAILPIT_URL")
MAILPIT_SMTP_HOST = os.environ.get("VAULT_MAILPIT_SMTP_HOST")
MAILPIT_SMTP_PORT = os.environ.get("VAULT_MAILPIT_SMTP_PORT", "1025")
_mailpit = pytest.mark.skipif(not (MAILPIT_URL and MAILPIT_SMTP_HOST), reason="no Mailpit sink")


@pytest.fixture
def reset_enabled(admin):
    before = admin.get("/settings").json().get("password_reset_enabled")
    admin.put("/settings", json={"password_reset_enabled": True})
    yield
    admin.put("/settings", json={"password_reset_enabled": bool(before)})


@pytest.fixture
def mailpit_profile(admin):
    for p in admin.get("/email/profiles").json()["profiles"]:
        admin.delete(f"/email/profiles/{p['id']}")
    admin.post("/email/profiles", json={"name": "MP", "smtp_server": MAILPIT_SMTP_HOST,
                                        "smtp_port": int(MAILPIT_SMTP_PORT), "smtp_username": "",
                                        "from_email": "sender@example.com", "is_default": True})
    yield
    for p in admin.get("/email/profiles").json()["profiles"]:
        admin.delete(f"/email/profiles/{p['id']}")


def _mp_token_for(email, timeout=15):
    email = email.lower()
    deadline = time.time() + timeout
    while time.time() < deadline:
        for m in requests.get(f"{MAILPIT_URL}/api/v1/messages", timeout=10).json().get("messages", []):
            if email in [a.get("Address", "").lower() for a in m.get("To", [])]:
                full = requests.get(f"{MAILPIT_URL}/api/v1/message/{m['ID']}", timeout=10).json()
                mm = re.search(r"[?&]reset=([A-Za-z0-9_-]+)", full.get("HTML", ""))
                return mm.group(1) if mm else None
        time.sleep(0.4)
    return None


def test_forgot_password_link_shows_and_submits(page: Page, reset_enabled):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    # the link appears once /auth/policy reports self-service on
    expect(page.locator("#show-forgot-link")).to_be_visible(timeout=8000)
    page.click("#show-forgot-link")
    expect(page.locator("#forgot-form")).to_be_visible()
    page.fill("#forgot-identifier", "whoever-" + unique("x"))
    page.click("#forgot-form button[type=submit]")
    # enumeration-safe: the same message shows regardless of whether the account exists
    expect(page.locator("#forgot-message")).to_be_visible()
    expect(page.locator("#forgot-message")).to_contain_text("reset link has been sent")


def test_forgot_password_link_hidden_when_disabled(page: Page, admin):
    before = admin.get("/settings").json().get("password_reset_enabled")
    admin.put("/settings", json={"password_reset_enabled": False})
    try:
        page.goto("/")
        expect(page.locator("#login-screen")).to_be_visible()
        page.wait_for_timeout(1500)                      # let the policy fetch resolve
        expect(page.locator("#show-forgot-link")).to_be_hidden()
    finally:
        admin.put("/settings", json={"password_reset_enabled": bool(before)})


@_mailpit
def test_reset_page_sets_a_new_password(page: Page, admin, reset_enabled, mailpit_profile):
    requests.delete(f"{MAILPIT_URL}/api/v1/messages", timeout=10)
    email = f"uireset-{unique('u')}@example.com"
    u = admin.create_user(email=email)
    try:
        assert admin.post(f"/users/{u['id']}/send-reset-link").json().get("email_sent") is True
        token = _mp_token_for(email)
        assert token, "no reset link delivered"
        page.goto(f"/?reset={token}")
        expect(page.locator("#reset-screen")).to_be_visible(timeout=8000)
        expect(page.locator("#reset-card-body")).to_contain_text("Set a new password")
        page.fill("#reset-card-body input[type=password]", "UiBrandNew!9")
        page.click("#reset-card-body button[type=submit]")
        expect(page.locator("#reset-card-body")).to_contain_text("Password updated", timeout=8000)
        # the new password works
        assert admin.post("/auth/login", json={"username": u["_username"], "password": "UiBrandNew!9"}).status_code == 200
    finally:
        admin.delete_user(u["id"])
