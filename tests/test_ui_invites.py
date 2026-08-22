"""Browser coverage for the admin invitation UI: the Invite button gates on the org policy, the modal
shows the invite link exactly once with a copy affordance, and the pending list revokes in place."""
import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

ACCOUNT_KEYS = ("invite_enabled", "invite_ttl_hours", "email_requirement",
                "signup_email_domain_mode", "signup_email_domains")


@pytest.fixture
def restore_settings(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ACCOUNT_KEYS}
    yield
    admin.put("/settings", json=snap)


def _login_admin(page: Page, admin_creds):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", admin_creds["username"])
    page.fill("#password", admin_creds["password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_users(page: Page):
    page.click('.sidebar-item[data-section="users"]')
    expect(page.locator("#users-section")).to_be_visible(timeout=10000)


def test_invite_button_gated_on_policy(page: Page, admin, admin_creds, restore_settings):
    admin.put("/settings", json={"invite_enabled": False})
    _login_admin(page, admin_creds)
    _open_users(page)
    expect(page.locator("#invite-user-btn")).to_be_hidden()
    # enable, revisit -> the button appears (loadUsers refetches settings and re-gates)
    admin.put("/settings", json={"invite_enabled": True})
    page.click('.sidebar-item[data-section="dashboard"]')
    _open_users(page)
    expect(page.locator("#invite-user-btn")).to_be_visible(timeout=10000)


def test_invite_modal_shows_link_once_and_lists_pending(page: Page, admin, admin_creds, restore_settings):
    admin.put("/settings", json={"invite_enabled": True, "email_requirement": "optional",
                                 "signup_email_domain_mode": "off"})
    try:
        page.context.grant_permissions(["clipboard-write"])  # so navigator.clipboard.writeText resolves
    except Exception:
        pass
    _login_admin(page, admin_creds)
    _open_users(page)
    page.click("#invite-user-btn")
    expect(page.locator("#invite-user-modal")).to_be_visible(timeout=10000)
    uname = "uiinv" + str(abs(hash(page.url)) % 100000)
    page.fill("#invite-username", uname)
    page.click("#invite-submit-btn")
    # the show-once panel reveals a link with the "shown only once" warning
    expect(page.locator("#invite-link-result")).to_be_visible(timeout=10000)
    link = page.locator("#invite-link-value").inner_text()
    assert "invite=" in link, f"expected an ?invite= link, got {link!r}"
    expect(page.locator("#invite-link-result .alert-warning")).to_contain_text("only once")
    # the fields step is gone (link is not re-shown on a re-open of the fields)
    expect(page.locator("#invite-user-fields")).to_be_hidden()
    # copy affordance runs (label flips)
    page.click("#invite-link-copy")
    expect(page.locator("#invite-link-copy")).to_contain_text("Copied", timeout=5000)
    page.click("#invite-done-footer .close-modal-btn")
    # the pending list now shows the invitation with a revoke control
    expect(page.locator(f'#invites-list .invite-row:has-text("{uname}")')).to_be_visible(timeout=10000)
    try:
        row = page.locator(f'#invites-list .invite-row:has-text("{uname}")')
        expect(row).to_contain_text("pending")
        row.locator('button:has-text("Revoke")').click()
        # after revoke the row is no longer pending (either drops from the list or flips status)
        expect(page.locator(f'#invites-list .invite-row:has-text("{uname}")')).not_to_contain_text("pending", timeout=10000)
    finally:
        # clean up any invite left for this username
        for inv in admin.get("/invites").json():
            if inv["username"] == uname and inv["status"] == "pending":
                admin.delete(f"/invites/{inv['id']}")


def test_no_console_errors_in_invite_flow(page: Page, admin, admin_creds, restore_settings):
    admin.put("/settings", json={"invite_enabled": True})
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    _login_admin(page, admin_creds)
    _open_users(page)
    page.click("#invite-user-btn")
    expect(page.locator("#invite-user-modal")).to_be_visible(timeout=10000)
    page.wait_for_timeout(500)
    assert not errors, f"invite UI produced console errors: {errors}"
