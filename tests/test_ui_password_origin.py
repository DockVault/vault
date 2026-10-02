"""Browser: making an account an administrator warns first when its password was set by someone else,
and, with no email to send the reset link, shows the promoting administrator the link to hand over.

test_password_origin_live.py covers the API; this checks the page."""
import pytest
from playwright.sync_api import Page, expect

from _account_change_helpers import psql

pytestmark = pytest.mark.ui


def _login(page: Page, username, password):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _edit(page: Page, user):
    page.evaluate("document.querySelector('.sidebar-item[data-section=\"users\"]').click()")
    expect(page.locator(".exp-row").first).to_be_visible(timeout=15000)
    page.fill("#users-search", user["_username"])
    row = page.locator(f'.exp-row[data-id="{user["id"]}"]')
    expect(row).to_have_count(1, timeout=10000)
    row.scroll_into_view_if_needed()
    row.click()
    edit = page.locator(f'.edit-user-btn[data-user-id="{user["id"]}"]')
    expect(edit).to_be_visible(timeout=10000)
    edit.scroll_into_view_if_needed()
    edit.click()
    expect(page.locator("#edit-user-role")).to_be_visible(timeout=10000)


def test_promoting_warns_then_hands_over_the_link(page: Page, admin, admin_creds):
    bob = admin.create_user(role="user")          # the administrator chose its password
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _edit(page, bob)
        page.select_option("#edit-user-role", "admin")
        page.locator("#edit-user-form button[type=submit]").click()
        confirm = page.locator("#confirm-modal.active")
        expect(confirm).to_be_visible(timeout=10000)
        expect(page.locator("#confirm-modal-message")).to_contain_text(
            f"{bob['_username']}'s password was set by {admin_creds['username']}")
        expect(page.locator("#confirm-modal-message")).to_contain_text("makes that password unusable")
        page.click("#confirm-modal-confirm-btn")
        overlay = page.locator(".reset-link-overlay")
        expect(overlay).to_be_visible(timeout=15000)
        expect(overlay).to_contain_text(f"Password reset link for {bob['_username']}")
        assert "?reset=" in overlay.locator("input").input_value()
        assert psql(f"SELECT role FROM users WHERE id = '{bob['id']}'").lower() == "admin"
    finally:
        admin.delete_user(bob["id"])


def test_cancelling_the_warning_changes_nothing(page: Page, admin, admin_creds):
    bob = admin.create_user(role="user")
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _edit(page, bob)
        page.select_option("#edit-user-role", "admin")
        page.locator("#edit-user-form button[type=submit]").click()
        expect(page.locator("#confirm-modal.active")).to_be_visible(timeout=10000)
        page.click("#confirm-modal-cancel-btn")
        expect(page.locator("#confirm-modal.active")).to_have_count(0, timeout=10000)
        assert psql(f"SELECT role FROM users WHERE id = '{bob['id']}'").lower() == "user"
        assert psql(f"SELECT count(*) FROM audit_logs WHERE action = 'password_reset_at_promotion' "
                    f"AND resource_id = '{bob['id']}'") == "0"
    finally:
        admin.delete_user(bob["id"])
