"""Per-vault size in the UI: pick a size on create, and honest quota display in admin Settings."""
import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

GIB = 1024 ** 3


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def test_create_vault_with_chosen_size(page: Page, admin, admin_creds):
    name = "ui-size-3gb"
    _login(page, admin_creds["username"], admin_creds["password"])
    page.click('.sidebar-item[data-section="vaults"]')
    page.click("#create-vault-btn")
    expect(page.locator("#create-vault-modal")).to_be_visible()
    # the size input defaults to 1 and the availability note is shown
    expect(page.locator("#vault-size-gb")).to_have_value("1")
    expect(page.locator("#vault-size-avail")).to_be_visible()
    page.fill("#vault-name", name)
    page.fill("#vault-size-gb", "3")
    page.click("#create-vault-form button[type=submit]")
    expect(page.locator("#create-vault-modal")).not_to_be_visible(timeout=8000)
    # the created vault carries the chosen size
    v = next((x for x in admin.get("/vaults").json() if x["name"] == name), None)
    try:
        assert v is not None, "created vault not found"
        assert v["size_limit"] == 3 * GIB
    finally:
        if v:
            admin.delete_vault(v["id"])


def test_settings_quota_display_is_honest(page: Page, admin, admin_creds):
    # backend treats absent/0 quota as UNLIMITED; the field must show BLANK, not a fake 10/100
    admin.put("/settings", json={"default_user_quota": 0, "max_vault_size": 0})
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        page.click('.sidebar-item[data-section="settings"]')
        page.click('.tab-btn[data-tab="storage"]')
        expect(page.locator("#setting-default-quota")).to_have_value("")
        expect(page.locator("#setting-max-vault-size")).to_have_value("")
        expect(page.locator("#setting-default-quota")).to_have_attribute("placeholder", "Unlimited")
    finally:
        admin.put("/settings", json={"default_user_quota": 1000, "max_vault_size": 1000})
