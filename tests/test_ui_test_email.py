"""The Send Test Email button reaches a real endpoint (it used to 404), and now saves the Email-tab
fields before sending so a filled-but-unsaved form no longer reports "SMTP is not configured"."""
import os
import time

import pytest
import requests
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

MAILPIT_URL = os.environ.get("VAULT_MAILPIT_URL")
MAILPIT_SMTP_HOST = os.environ.get("VAULT_MAILPIT_SMTP_HOST")
MAILPIT_SMTP_PORT = os.environ.get("VAULT_MAILPIT_SMTP_PORT", "1025")


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


@pytest.fixture
def admin_page(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    return page


def test_test_email_button_hits_real_endpoint(admin_page: Page):
    page = admin_page
    page.click('.sidebar-item[data-section="settings"]')
    page.click('.tab-btn[data-tab="email"]')
    btn = page.locator("#test-email-btn")
    expect(btn).to_be_visible(timeout=10000)
    responses = []
    page.on("response", lambda r: responses.append((r.url, r.status)) if "/settings/test-email" in r.url else None)
    btn.click()
    # the button reports a concrete outcome (not the old blank/hang), proving the endpoint answered
    expect(page.locator("#test-email-result")).not_to_have_text("", timeout=15000)
    # and the endpoint exists (no 404)
    assert responses, "no /settings/test-email request was observed"
    assert all(status != 404 for _, status in responses), responses


@pytest.mark.skipif(not (MAILPIT_URL and MAILPIT_SMTP_HOST),
                    reason="no Mailpit sink (bring the round up with WITH_MAILPIT=1 / MAILPIT_HTTP_PORT)")
def test_test_email_saves_the_form_before_sending(admin_page: Page, admin):
    """Filling the Email tab and clicking Send Test Email — WITHOUT a separate Save — now delivers,
    instead of the old "SMTP is not configured" (the button reads STORED settings, so it saves the
    fields first). Proven end to end against Mailpit."""
    keys = ("smtp_server", "smtp_port", "smtp_username", "from_email", "from_name")
    snap = {k: admin.get("/settings").json().get(k) for k in keys}
    requests.delete(f"{MAILPIT_URL}/api/v1/messages", timeout=10)
    page = admin_page
    try:
        page.click('.sidebar-item[data-section="settings"]')
        page.click('.tab-btn[data-tab="email"]')
        # Fill the form only — do NOT click any Save button.
        page.fill("#setting-smtp-server", MAILPIT_SMTP_HOST)
        page.fill("#setting-smtp-port", str(MAILPIT_SMTP_PORT))
        page.fill("#setting-smtp-username", "")
        page.fill("#setting-from-email", "vault@example.com")
        page.click("#test-email-btn")
        expect(page.locator("#test-email-result")).to_have_text("✓ Email sent", timeout=15000)
        # the message really arrived
        to = (admin.get("/users/me").json().get("email") or "vault@example.com").lower()
        deadline = time.time() + 15
        arrived = False
        while time.time() < deadline and not arrived:
            for m in requests.get(f"{MAILPIT_URL}/api/v1/messages", timeout=10).json().get("messages", []):
                if to in [a.get("Address", "").lower() for a in m.get("To", [])]:
                    arrived = True
                    break
            if not arrived:
                time.sleep(0.5)
        assert arrived, "test email did not reach Mailpit after saving the form"
    finally:
        admin.put("/settings", json=snap)
