"""Browser coverage for the public self-signup affordance on the login screen.

Pre-auth only (never signs in), so the applyServerPreferences skin-reload caveat does not apply. The
"New here?" toggle and the signup form appear only when signup is enabled; the email field's
presence/required state follows policy; the login-identifier label follows policy; and the end-to-end
flow creates an account and returns to the sign-in form (the visitor is NOT auto-signed-in).
"""
import pytest
from playwright.sync_api import Page, expect

from conftest import unique

pytestmark = pytest.mark.ui

ACCOUNT_KEYS = ("signup_enabled", "email_requirement", "login_identifier",
                "signup_email_domain_mode", "signup_email_domains")
STRONG_PW = "S1gnup-Passw0rd!"


@pytest.fixture
def restore_settings(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ACCOUNT_KEYS}
    yield snap
    admin.put("/settings", json=snap)


def _set(admin, **kw):
    assert admin.put("/settings", json=kw).status_code == 200


def _cleanup(admin, username):
    for u in admin.get("/users").json():
        if u.get("username") == username:
            admin.delete_user(u["id"])
            return


def test_affordance_hidden_when_signup_disabled(page: Page, admin, restore_settings):
    _set(admin, signup_enabled=False)
    page.goto("/")
    expect(page.locator("#login-form")).to_be_visible(timeout=10000)
    expect(page.locator("#signup-toggle")).to_be_hidden()
    expect(page.locator("#signup-form")).to_be_hidden()


def test_toggle_reveals_signup_form_and_back(page: Page, admin, restore_settings):
    _set(admin, signup_enabled=True, email_requirement="optional", login_identifier="username")
    page.goto("/")
    expect(page.locator("#signup-toggle")).to_be_visible(timeout=10000)
    page.locator("#show-signup-link").click()
    expect(page.locator("#signup-form")).to_be_visible()
    expect(page.locator("#login-form")).to_be_hidden()
    page.locator("#show-login-link").click()
    expect(page.locator("#login-form")).to_be_visible()
    expect(page.locator("#signup-form")).to_be_hidden()


def test_email_field_required_shape(page: Page, admin, restore_settings):
    _set(admin, signup_enabled=True, email_requirement="required", login_identifier="username")
    page.goto("/")
    expect(page.locator("#signup-toggle")).to_be_visible(timeout=10000)
    page.locator("#show-signup-link").click()
    expect(page.locator("#signup-email-group")).to_be_visible()
    expect(page.locator("#signup-email-label")).to_have_text("Email")
    assert page.locator("#signup-email").evaluate("el => el.required") is True


def test_email_field_optional_shape(page: Page, admin, restore_settings):
    _set(admin, signup_enabled=True, email_requirement="optional", login_identifier="username")
    page.goto("/")
    expect(page.locator("#signup-toggle")).to_be_visible(timeout=10000)
    page.locator("#show-signup-link").click()
    expect(page.locator("#signup-email-group")).to_be_visible()
    expect(page.locator("#signup-email-label")).to_have_text("Email (optional)")
    assert page.locator("#signup-email").evaluate("el => el.required") is False


@pytest.mark.parametrize("mode,label", [
    ("username", "Username"),
    ("email", "Email"),
    ("either", "Username or email"),
])
def test_login_identifier_label_follows_policy(page: Page, admin, restore_settings, mode, label):
    _set(admin, signup_enabled=True, login_identifier=mode,
         email_requirement=("required" if mode in ("email", "either") else "optional"))
    page.goto("/")
    expect(page.locator("#username-label")).to_have_text(label, timeout=10000)


def test_signup_end_to_end_returns_to_login(page: Page, admin, restore_settings):
    _set(admin, signup_enabled=True, email_requirement="optional", login_identifier="username",
         signup_email_domain_mode="off")
    name = unique("uisignup")
    try:
        page.goto("/")
        expect(page.locator("#signup-toggle")).to_be_visible(timeout=10000)
        page.locator("#show-signup-link").click()
        page.locator("#signup-username").fill(name)
        page.locator("#signup-password").fill(STRONG_PW)
        page.locator("#signup-form button[type=submit]").click()
        # success banner shows, the login form returns, and the username is prefilled
        banner = page.locator("#login-error")
        expect(banner).to_be_visible(timeout=10000)
        expect(banner).to_contain_text("Account created")
        expect(page.locator("#login-form")).to_be_visible()
        assert page.locator("#username").input_value() == name
        # the account really exists
        assert any(u.get("username") == name for u in admin.get("/users").json())
    finally:
        _cleanup(admin, name)
