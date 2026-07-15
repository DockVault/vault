"""UI papercut fixes: a non-admin dashboard doesn't fire admin-only endpoints, and a rejected
0-byte upload doesn't stick in the tray as 'active'."""
import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def test_non_admin_dashboard_skips_admin_only_calls(page: Page, admin):
    u = admin.create_user(role="user")
    try:
        _login(page, u["_username"], u["_password"])
        reqs = []
        page.on("request", lambda r: reqs.append(r.url))
        page.click('.sidebar-item[data-section="dashboard"]')
        page.wait_for_timeout(1500)
        # the admin-only endpoints are gated for a non-admin -> not called at all (no 403 noise)
        hit = [x for x in reqs if x.split("?")[0].rstrip("/").endswith("/users") or "/audit/events" in x]
        assert not hit, hit
        # and the events panel shows the honest message, not the misleading "Event logging not configured"
        expect(page.locator("#events-feed")).to_contain_text("administrators")
    finally:
        admin.delete_user(u["id"])


def test_zero_byte_upload_not_counted_active(page: Page, admin, admin_creds):
    v = admin.create_vault(name="upload-tray-test")
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        page.click('.sidebar-item[data-section="vaults"]')
        page.click(f'.open-vault-btn[data-vault-id="{v["id"]}"]')
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)
        page.set_input_files(
            "#file-upload-input",
            files=[{"name": "empty.txt", "mimeType": "text/plain", "buffer": b""}],
        )
        head = page.locator(".up-tray-head")
        expect(head).to_be_visible(timeout=10000)
        # the failed 0-byte upload is finished, not active — the header must not say "N active"
        expect(head).not_to_contain_text("active")
    finally:
        admin.delete_vault(v["id"])
