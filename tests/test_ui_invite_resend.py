"""The invitation dialog says before submit whether the invitation will be emailed or must be copied; a pending
invitation can be sent again from its row (a new link shown once, the row still pending, who invited named)."""
import pytest
from playwright.sync_api import Page, expect

from conftest import unique

pytestmark = pytest.mark.ui

ACCOUNT_KEYS = ("email_requirement", "invite_enabled", "invite_ttl_hours", "signup_enabled",
                "signup_email_domain_mode", "signup_email_domains", "login_identifier",
                "email_change_requires_verification")


@pytest.fixture
def invites_on(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ACCOUNT_KEYS}
    admin.put("/settings", json={"invite_enabled": True, "email_requirement": "optional",
                                 "signup_email_domain_mode": "off", "signup_email_domains": []})
    yield before.get("smtp_configured") is True
    admin.put("/settings", json=snap)


def _login_admin(page: Page, admin_creds):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", admin_creds["username"])
    page.fill("#password", admin_creds["password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def test_the_dialog_says_how_the_invitation_goes_out(page: Page, admin_creds, invites_on):
    mail_ready = invites_on
    _login_admin(page, admin_creds)
    page.click('.sidebar-item[data-section="users"]')
    page.click("#invite-user-btn")
    expect(page.locator("#invite-user-modal")).to_be_visible(timeout=10000)
    note = page.locator("#invite-send-note")
    expect(note).to_contain_text("Without an email address, you copy the invitation link")
    page.fill("#invite-email", "someone@example.test")
    if mail_ready:
        expect(note).to_contain_text("will be emailed to someone@example.test")
    else:
        expect(note).to_contain_text("Email is not set up here")
    page.fill("#invite-email", "")
    expect(note).to_contain_text("Without an email address")


def test_a_pending_invitation_can_be_sent_again_from_its_row(page: Page, admin, admin_creds, invites_on):
    inv = admin.post("/invites", json={"username": unique("again"), "role": "user"}).json()
    try:
        _login_admin(page, admin_creds)
        page.click('.sidebar-item[data-section="users"]')
        row = page.locator(f'#invites-list .invite-row[data-invite-id="{inv["id"]}"]')
        expect(row).to_be_visible(timeout=10000)
        expect(row.locator(".invite-by .person-chip")).to_have_text(admin_creds["username"])
        row.locator("button.invite-resend").click()
        expect(page.locator("#confirm-modal")).to_be_visible()
        page.locator('#confirm-modal button:has-text("Send again")').click()
        expect(page.locator("#invite-link-result")).to_be_visible(timeout=10000)
        link = page.locator("#invite-link-value").inner_text()
        assert "invite=" in link and inv["token"] not in link
        expect(page.locator("#invite-link-expiry")).to_contain_text("no longer works")
        page.click("#invite-done-footer .close-modal-btn")
        expect(row).to_contain_text("pending")
        # The old link is dead.
        assert admin.get(f"/invites/{inv['token']}").status_code == 404
    finally:
        admin.delete(f"/invites/{inv['id']}")
