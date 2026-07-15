"""The vault share/grant picker searches the server (so non-admins can find recipients)."""
import re

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
    v = admin.create_vault(name="uir-share-vault")
    target = admin.create_user(username="uir-picktarget")
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
            page.fill("#vault-grant-search", "uir-pick")
        expect(page.locator("#vault-grant-list")).to_contain_text("uir-picktarget", timeout=8000)
    finally:
        admin.delete_user(target["id"])
        admin.delete_vault(v["id"])
