"""The account-settings email-change UI: direct change when unrestricted, and the code flow when the
organization requires verification.

The plaintext code only reaches the new mailbox, so the browser test proves the UI SWITCHES to the
code-entry step (the confirm/apply itself is covered by the API tests). It drives the switch through
the enumeration-safe path — a change to an already-in-use address returns the same 202 — so no real
mail send is needed.
"""
import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui


@pytest.fixture
def restore_settings(admin):
    before = admin.get("/settings").json()
    keys = ("email_change_requires_verification", "smtp_server", "from_email", "smtp_port")
    snap = {k: before.get(k) for k in keys}
    yield
    admin.put("/settings", json=snap)


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_account(page: Page):
    page.evaluate("() => openUserSettingsModal()")
    expect(page.locator("#user-settings-modal")).to_be_visible(timeout=10000)


def test_direct_email_change_when_unrestricted(page: Page, admin, restore_settings):
    admin.put("/settings", json={"email_change_requires_verification": False})
    u = admin.create_user(role="user")
    try:
        _login(page, u["_username"], u["_password"])
        _open_account(page)
        expect(page.locator("#us-email-code-row")).to_be_hidden()   # no verification step
        new = "moved-" + u["_username"] + "@example.com"
        page.fill("#us-new-email", new)
        page.fill("#us-email-cur-pw", u["_password"])
        page.click("#us-email-form button[type=submit]")
        expect(page.locator("#us-email-display")).to_have_text(new, timeout=10000)
        expect(page.locator("#us-email-code-row")).to_be_hidden()
    finally:
        admin.delete_user(u["id"])


def test_verification_required_switches_to_the_code_step(page: Page, admin, restore_settings):
    # enable the policy (two PUTs: SMTP must be stored before the flag can be turned on)
    admin.put("/settings", json={"smtp_server": "127.0.0.1", "from_email": "vault@example.com", "smtp_port": "1"})
    admin.put("/settings", json={"email_change_requires_verification": True})
    in_use = admin.get("/users/me").json()["email"]            # the admin's address is definitely in use
    u = admin.create_user(role="user")
    try:
        _login(page, u["_username"], u["_password"])
        _open_account(page)
        expect(page.locator("#us-email-code-row")).to_be_hidden()   # hidden until the flow starts
        # Changing to an in-use address takes the same enumeration-safe path (202, no mail), so the UI
        # reaches the code-entry step without needing a real send.
        page.fill("#us-new-email", in_use)
        page.fill("#us-email-cur-pw", u["_password"])
        page.click("#us-email-form button[type=submit]")
        expect(page.locator("#us-email-code-row")).to_be_visible(timeout=10000)  # switched to verification
        expect(page.locator("#us-email-code")).to_be_visible()
        # the email is NOT changed yet — it only applies after a valid code is confirmed
        expect(page.locator("#us-email-display")).not_to_have_text(in_use)
    finally:
        admin.delete_user(u["id"])


def test_no_console_errors_in_the_email_change_ui(page: Page, admin, restore_settings):
    admin.put("/settings", json={"email_change_requires_verification": False})
    u = admin.create_user(role="user")
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    try:
        _login(page, u["_username"], u["_password"])
        _open_account(page)
        page.wait_for_timeout(600)
        assert not errors, f"account modal produced console errors: {errors}"
    finally:
        admin.delete_user(u["id"])
