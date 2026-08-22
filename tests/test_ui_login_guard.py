"""Browser coverage for the Sign-in-method lockout warning (Settings -> Accounts & Access).

Choosing "Email only" surfaces a live panel: a serious (red) COMPLETE list of admins who would be
locked out — with a stronger note if it's the current user — and an orange generic COUNT of users
without an email. It clears when a username-bearing mode is chosen again.
"""
import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

RESTORE_KEYS = ("login_identifier",)


@pytest.fixture
def restore_settings(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in RESTORE_KEYS}
    yield
    admin.put("/settings", json=snap)


def _login_admin(page: Page, admin_creds):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", admin_creds["username"])
    page.fill("#password", admin_creds["password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_accounts_tab(page: Page):
    page.click('.sidebar-item[data-section="settings"]')
    expect(page.locator("#settings-tab-accounts, .tab-btn[data-tab='accounts']").first).to_be_visible(timeout=10000)
    page.click('.tab-btn[data-tab="accounts"]')
    expect(page.locator("#setting-login-identifier")).to_be_visible(timeout=10000)
    # Wait for the async settings load to populate the select — otherwise populateAccountsPolicy can
    # run AFTER our selection and reset it to the stored value.
    expect(page.locator("#setting-login-identifier")).to_have_value("username", timeout=10000)
    page.wait_for_timeout(1200)   # absorb any second settings load before interacting


def _select_email(page: Page):
    """Choose 'Email only' and make it stick. A settings load that finishes just after the click can
    reset the field once; re-select until it holds (models a user simply picking it again)."""
    sel = page.locator("#setting-login-identifier")
    for _ in range(4):
        page.select_option("#setting-login-identifier", "email")
        try:
            expect(sel).to_have_value("email", timeout=2500)
            return
        except AssertionError:
            page.wait_for_timeout(400)
    expect(sel).to_have_value("email", timeout=2500)


def test_email_mode_warns_about_admins_and_users_without_email(page: Page, admin, admin_creds, restore_settings):
    admin.put("/settings", json={"login_identifier": "username"})
    other_admin = admin.create_user(role="admin", email=None)
    a_user = admin.create_user(role="user", email=None)
    try:
        _login_admin(page, admin_creds)
        _open_accounts_tab(page)
        warn = page.locator("#login-identifier-warning")
        expect(warn).to_be_hidden()
        _select_email(page)
        # the serious (red) admin panel lists the emailless admin by name
        expect(warn).to_be_visible(timeout=10000)
        expect(warn.locator(".alert-error")).to_contain_text(other_admin["_username"])
        # the orange user panel is a generic count (no username listed)
        expect(warn.locator(".alert-warning")).to_contain_text("without an email")
        # switching back to a username-bearing mode clears the warning (wait for the select to settle
        # off 'email' first, so a late settings reload can't race the assertion)
        page.select_option("#setting-login-identifier", "either")
        expect(page.locator("#setting-login-identifier")).not_to_have_value("email", timeout=10000)
        expect(warn).to_be_hidden(timeout=10000)
    finally:
        admin.delete_user(other_admin["id"])
        admin.delete_user(a_user["id"])


def test_no_console_errors_toggling_login_identifier(page: Page, admin, admin_creds, restore_settings):
    admin.put("/settings", json={"login_identifier": "username"})
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    _login_admin(page, admin_creds)
    _open_accounts_tab(page)
    _select_email(page)
    page.wait_for_timeout(600)
    page.select_option("#setting-login-identifier", "username")
    assert not errors, f"login-identifier warning produced console errors: {errors}"
