"""The login screen labels its identifier field to match the org's login policy.

The page is pre-auth, so it learns the policy from the public /auth/login-policy endpoint and updates
the label + the input's autocomplete accordingly. Asserted for each mode, with no console errors.
"""
import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui


@pytest.fixture
def restore_login_policy(admin):
    before = admin.get("/settings").json()
    snap = {"login_identifier": before.get("login_identifier")}
    yield
    admin.put("/settings", json=snap)


def _label_for(page: Page, mode: str, admin):
    admin.put("/settings", json={"login_identifier": mode})
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    return page.locator("#username-label"), page.locator("#username")


def test_username_mode_label(page: Page, admin, restore_login_policy):
    # First switch to email so the label is provably NOT the static default, then back to username —
    # proving the JS actively re-applied the username default rather than the page never having run.
    label, inp = _label_for(page, "email", admin)
    expect(label).to_have_text("Email")
    label, inp = _label_for(page, "username", admin)
    expect(label).to_have_text("Username")
    expect(inp).to_have_attribute("autocomplete", "username")


def test_email_mode_label(page: Page, admin, restore_login_policy):
    label, inp = _label_for(page, "email", admin)
    expect(label).to_have_text("Email")
    expect(inp).to_have_attribute("autocomplete", "email")


def test_either_mode_label(page: Page, admin, restore_login_policy):
    label, inp = _label_for(page, "either", admin)
    expect(label).to_have_text("Username or email")
    expect(inp).to_have_attribute("autocomplete", "username")


def test_no_console_errors_applying_the_label(page: Page, admin, restore_login_policy):
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    _label_for(page, "either", admin)
    page.wait_for_timeout(500)
    assert not errors, f"login screen produced console errors: {errors}"
