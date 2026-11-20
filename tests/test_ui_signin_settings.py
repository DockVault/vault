"""Settings -> Sign-in in the browser (static/js/settings-signin.js): an administrator sees whether a passkey can be
made at the vault's address, changes a passkey setting with their password, finds the change still there after a
reload, and reads the server's own sentence when a change is refused.

Needs a stack with an address passkeys can be made at (ALLOWED_HOSTS naming the address the test opens)."""
import pytest
from playwright.sync_api import Page, expect

from _settings_ui import show_advanced

pytestmark = pytest.mark.ui

VERIFY = '#signin-passkey-settings [data-setting="webauthn_require_uv"]'
ATTESTATION = '#signin-passkey-settings [data-setting="webauthn_attestation"]'


def _open(page: Page, admin_creds):
    page.set_viewport_size({"width": 1280, "height": 900})
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", admin_creds["username"])
    page.fill("#password", admin_creds["password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    _open_page(page)


def _open_page(page: Page):
    page.evaluate("() => document.querySelector('.sidebar-item[data-section=\"settings\"]').click()")
    expect(page.locator("#settings-section")).to_be_visible(timeout=10000)
    page.locator('#settings-section .tab-btn[data-tab="signin"]').click()
    expect(page.locator("#settings-tab-signin")).to_be_visible()
    expect(page.locator('#signin-passkey-settings [data-setting="webauthn_mode"]')).to_be_visible(timeout=10000)


def _save_with_the_password(page: Page, row, admin_creds):
    row.get_by_role("button", name="Save").click()
    expect(page.locator("#stepup-modal.active")).to_be_visible(timeout=10000)
    page.fill("#stepup-password-input", admin_creds["password"])
    page.locator("#stepup-modal-body .btn-primary").click()
    expect(page.locator("#stepup-modal.active")).to_be_hidden(timeout=10000)


def test_the_page_says_where_passkeys_are_made_and_lists_the_settings(page: Page, admin_creds):
    errors = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    _open(page, admin_creds)
    line = page.locator("#signin-passkey-readiness")
    expect(line).to_be_visible()
    if "No passkey can be made" in (line.text_content() or ""):
        pytest.skip("this stack has no address a passkey can be made at (ALLOWED_HOSTS)")
    expect(line).to_contain_text("Passkeys can be made at " + page.evaluate("() => location.origin"))
    # The essential settings show; the rest wait behind "Show advanced settings", like on every other page.
    box = page.locator("#signin-passkey-settings")
    expect(box.locator('[data-setting="webauthn_mode"] select')).to_have_value("optional")
    expect(box.locator('[data-setting="webauthn_sign_in"]')).to_be_visible()
    expect(box.locator('[data-setting="webauthn_enrollment_grace_days"]')).to_be_hidden()
    show_advanced(page, "signin")
    expect(box.locator('[data-setting="webauthn_enrollment_grace_days"]')).to_be_visible()
    assert box.locator("[data-setting]").count() == 9
    # Nothing to save until something is changed.
    expect(page.locator(VERIFY).get_by_role("button", name="Save")).to_be_disabled()
    assert errors == [], errors


def test_a_change_asks_for_the_password_and_holds_after_a_reload(page: Page, admin_creds):
    _open(page, admin_creds)
    box = page.locator(VERIFY + " input[type=checkbox]")
    expect(box).to_be_checked()
    try:
        box.uncheck()
        _save_with_the_password(page, page.locator(VERIFY), admin_creds)
        expect(page.locator(VERIFY + " input[type=checkbox]")).not_to_be_checked(timeout=10000)
        # The row drawn again says the change can be undone, and has nothing more to save.
        expect(page.locator(VERIFY).get_by_role("button", name="Use the default")).to_be_visible()
        expect(page.locator(VERIFY).get_by_role("button", name="Save")).to_be_disabled()
        page.reload()
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        _open_page(page)
        expect(page.locator(VERIFY + " input[type=checkbox]")).not_to_be_checked()
    finally:
        # Back to the deployment's value, through the page, with the password again.
        back = page.locator(VERIFY).get_by_role("button", name="Use the default")
        if back.count():
            back.click()
            expect(page.locator("#stepup-modal.active")).to_be_visible(timeout=10000)
            page.fill("#stepup-password-input", admin_creds["password"])
            page.locator("#stepup-modal-body .btn-primary").click()
            expect(page.locator(VERIFY + " input[type=checkbox]")).to_be_checked(timeout=10000)
    expect(page.locator(VERIFY).get_by_role("button", name="Use the default")).to_have_count(0)


def test_a_change_the_server_refuses_is_said_in_its_words_and_asks_for_no_password(page: Page, admin_creds):
    _open(page, admin_creds)
    show_advanced(page, "signin")
    row = page.locator(ATTESTATION)
    row.locator("select").select_option("direct")
    row.get_by_role("button", name="Save").click()
    said = row.locator(".signin-setting-said")
    expect(said).to_contain_text("Direct attestation needs trust anchors", timeout=10000)
    expect(said).to_have_attribute("role", "alert")
    expect(page.locator("#stepup-modal.active")).to_have_count(0)
    # Nothing changed: the page read again shows the value in force.
    page.locator('#settings-section .tab-btn[data-tab="signin"]').click()
    expect(page.locator(ATTESTATION + " select")).to_have_value("none", timeout=10000)
