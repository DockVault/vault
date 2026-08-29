"""The admin Settings -> Accounts & Access tab renders and behaves.

Covers: the tab opens and its controls render with a live policy summary; the invitation and
self-signup sub-controls enable/disable with their master switches; the signup-domain chip editor
adds and removes domains; the email-change verification toggle is disabled until SMTP is configured;
a save round-trips through reload; and the tab produces no console errors.

Every to_be_disabled()/to_be_enabled() is preceded by a visibility assertion so a MISSING control
can't pass as merely disabled. The save/reload test restores the settings it changed.
"""
import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

TAB = "#settings-tab-accounts"


@pytest.fixture
def restore_settings(admin):
    keys = ("email_requirement", "invite_enabled", "invite_ttl_hours", "signup_enabled",
            "signup_email_domain_mode", "signup_email_domains", "login_identifier",
            "email_change_requires_verification", "email_change_otp_ttl_minutes",
            "password_reset_enabled", "password_reset_ttl_minutes", "smtp_server", "from_email")
    before = admin.get("/settings").json()
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


def _logout(page: Page):
    page.evaluate("() => { localStorage.clear(); sessionStorage.clear(); }")
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)


def _open_accounts_tab(page: Page):
    page.click('.sidebar-item[data-section="settings"]')
    expect(page.locator("#settings-section")).to_be_visible(timeout=10000)
    page.click('#settings-section .tab-btn[data-tab="accounts"]')
    expect(page.locator(TAB)).to_be_visible()


def test_tab_renders_with_controls_and_summary(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_accounts_tab(page)
    for sel in ("#setting-invite-enabled", "#setting-signup-enabled", "#setting-invite-ttl-hours",
                "#setting-signup-domain-mode", "#setting-email-requirement",
                "#setting-login-identifier", "#setting-email-change-verification"):
        expect(page.locator(sel)).to_be_visible()
    # the live summary is populated (non-vacuous: not the "—" placeholder)
    expect(page.locator("#accounts-policy-summary")).not_to_have_text("—")


def test_sub_controls_follow_their_master_switches(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_accounts_tab(page)
    ttl = page.locator("#setting-invite-ttl-hours")
    mode = page.locator("#setting-signup-domain-mode")
    expect(ttl).to_be_visible(); expect(mode).to_be_visible()
    # Wait for the async settings load to finish before toggling: invite-by-link defaults ON, so the
    # load re-checks the box after render — toggling before it settles lets the late load override the
    # click ("clicking did not change its state"). Waiting for the loaded state races it out.
    expect(page.locator("#setting-invite-enabled")).to_be_checked()
    # master OFF -> the sub-control is disabled. Set a known OFF state first (invite now defaults ON),
    # so this tests the follow-the-master behavior independent of the shipped default.
    page.set_checked("#setting-invite-enabled", False)
    expect(ttl).to_be_disabled()
    page.set_checked("#setting-signup-enabled", False)
    expect(mode).to_be_disabled()
    # turning the masters on enables them
    page.set_checked("#setting-invite-enabled", True)
    expect(ttl).to_be_enabled()
    page.set_checked("#setting-signup-enabled", True)
    expect(mode).to_be_enabled()
    # and back off disables again
    page.set_checked("#setting-invite-enabled", False)
    expect(ttl).to_be_disabled()


def test_domain_chip_add_and_remove(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_accounts_tab(page)
    page.check("#setting-signup-enabled")
    page.select_option("#setting-signup-domain-mode", "allowlist")
    inp = page.locator("#setting-signup-domain-input")
    expect(inp).to_be_enabled()
    inp.fill("Example.COM")
    page.click("#setting-signup-domain-add")
    chip = page.locator("#setting-signup-domains-list .chip", has_text="example.com")
    expect(chip).to_be_visible()          # added, normalized to lowercase
    # adding the same domain again does not duplicate it
    inp.fill("example.com")
    page.click("#setting-signup-domain-add")
    expect(page.locator("#setting-signup-domains-list .chip")).to_have_count(1)
    # remove it
    chip.locator(".chip-remove").click()
    expect(page.locator("#setting-signup-domains-list .chip")).to_have_count(0)


def test_email_change_toggle_disabled_without_smtp(page: Page, admin_creds, admin, restore_settings):
    # ensure SMTP is not configured for this check
    admin.put("/settings", json={"smtp_server": "", "from_email": ""})
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_accounts_tab(page)
    ecv = page.locator("#setting-email-change-verification")
    expect(ecv).to_be_visible()
    expect(ecv).to_be_disabled()          # gated behind SMTP being configured


def test_save_round_trips_through_reload(page: Page, admin_creds, restore_settings):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_accounts_tab(page)
    # invite-by-link defaults ON — wait for the loaded state before editing (this also races out the
    # async settings load, so the fields below aren't touched while the form is still populating).
    expect(page.locator("#setting-invite-enabled")).to_be_checked()
    page.fill("#setting-invite-ttl-hours", "96")
    page.select_option("#setting-login-identifier", "either")
    page.click("#save-all-settings-btn")
    page.wait_for_timeout(1200)           # let the PUT settle
    # fresh session from scratch, then back to the tab — proves it persisted server-side
    _logout(page)
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_accounts_tab(page)
    expect(page.locator("#setting-invite-enabled")).to_be_checked()
    expect(page.locator("#setting-invite-ttl-hours")).to_have_value("96")
    expect(page.locator("#setting-login-identifier")).to_have_value("either")


def test_password_reset_and_otp_ttl_controls_round_trip(page: Page, admin_creds, restore_settings):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_accounts_tab(page)
    for sel in ("#setting-password-reset-enabled", "#setting-password-reset-ttl-minutes",
                "#setting-email-change-otp-ttl-minutes"):
        expect(page.locator(sel)).to_be_visible()
    page.check("#setting-password-reset-enabled")
    page.fill("#setting-password-reset-ttl-minutes", "12")
    page.fill("#setting-email-change-otp-ttl-minutes", "9")
    page.click("#save-all-settings-btn")
    page.wait_for_timeout(1200)
    _logout(page)
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_accounts_tab(page)
    expect(page.locator("#setting-password-reset-enabled")).to_be_checked()
    expect(page.locator("#setting-password-reset-ttl-minutes")).to_have_value("12")
    expect(page.locator("#setting-email-change-otp-ttl-minutes")).to_have_value("9")


def test_no_console_errors_on_the_tab(page: Page, admin_creds):
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_accounts_tab(page)
    page.check("#setting-signup-enabled")
    page.select_option("#setting-signup-domain-mode", "denylist")
    page.wait_for_timeout(800)
    assert not errors, f"Accounts & Access tab produced console errors: {errors}"
