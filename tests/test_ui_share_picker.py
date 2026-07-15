"""The vault share/grant picker searches the server (so non-admins can find recipients)."""
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


def test_share_picker_searches_server_and_renders(page: Page, admin, admin_creds):
    v = admin.create_vault(name="share-picker-vault")
    target = admin.create_user(username="picker-recipient")
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        page.click('.sidebar-item[data-section="vaults"]')
        page.click(f'.open-vault-btn[data-vault-id="{v["id"]}"]')
        page.wait_for_timeout(600)  # let openVault set state.currentVault
        # open the grant picker (its "Grant access" button lives in the vault's access view)
        page.evaluate("() => window.openVaultGrantModal && window.openVaultGrantModal()")
        expect(page.locator("#vault-grant-search")).to_be_visible(timeout=8000)
        # before typing: the type-to-search prompt, not a preloaded directory
        expect(page.locator("#vault-grant-list")).to_contain_text("Type at least 2")
        # typing fires the scoped /users/search and renders the match
        with page.expect_response(lambda r: "/users/search" in r.url):
            page.fill("#vault-grant-search", "picker")
        expect(page.locator("#vault-grant-list")).to_contain_text("picker-recipient", timeout=8000)
    finally:
        admin.delete_user(target["id"])
        admin.delete_vault(v["id"])


def test_share_picker_surfaces_search_error_not_empty_copy(page: Page, admin, admin_creds):
    """A failed search (rate-limited/permission/network) shows the actual reason, NOT the
    'No matching users.' copy the empty-success path uses — which would look like the recipient
    simply doesn't exist. The error toast is suppressed (silent), so the list is the only signal."""
    v = admin.create_vault(name="share-picker-err-vault")
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        page.click('.sidebar-item[data-section="vaults"]')
        page.click(f'.open-vault-btn[data-vault-id="{v["id"]}"]')
        page.wait_for_timeout(600)  # let openVault set state.currentVault
        # Force the search to fail with a rate-limit style error.
        page.route(
            "**/users/search*",
            lambda route: route.fulfill(
                status=429,
                content_type="application/json",
                body='{"detail": "Rate limit exceeded. Try again shortly."}',
            ),
        )
        page.evaluate("() => window.openVaultGrantModal && window.openVaultGrantModal()")
        expect(page.locator("#vault-grant-search")).to_be_visible(timeout=8000)
        page.fill("#vault-grant-search", "abc")
        # the real reason is surfaced; the misleading empty-result copy is NOT shown
        expect(page.locator("#vault-grant-list")).to_contain_text("Rate limit exceeded", timeout=8000)
        expect(page.locator("#vault-grant-list")).not_to_contain_text("No matching users")
    finally:
        admin.delete_vault(v["id"])
