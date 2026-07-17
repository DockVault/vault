"""The Console-skin sidebar group labels must not sit over an empty section run.

The v2 skin injects presentational rail headers (Overview / Storage / Access / System) assuming
each group leads with a visible item. A scoped temporary credential hides whole groups of nav
items, so the headers over the now-empty runs must be hidden too — while a full admin keeps them.
"""
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


def _label(page: Page, text: str):
    return page.locator(".sidebar-nav .nav-group-label", has_text=text)


def test_admin_keeps_all_nav_group_labels(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    # a full admin sees every group populated -> every header stays
    for text in ("Overview", "Storage", "Access", "System"):
        expect(_label(page, text)).to_be_visible()


def test_scoped_temp_cred_hides_empty_group_labels(page: Page, admin):
    # a credential that can reach only Dashboard + Vaults
    scope = {"v": 1, "pages": ["dashboard", "vaults"], "caps": [],
             "vault_caps_default": ["vault.see_info"], "temp": {}}
    body = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 60, "scope": scope, "vault_access_mode": "all", "selected_vaults": []}).json()
    _login(page, body["temp_username"], body["credential"])
    # non-vacuous anchor: the scope really took effect (temp-creds/monitor items are hidden), so the
    # hidden-label assertions below are about a genuinely empty run — not a missing v1-skin element
    expect(page.locator('.sidebar-item[data-section="temp-creds"]')).to_be_hidden()
    expect(page.locator('.sidebar-item[data-section="monitor"]')).to_be_hidden()
    # the populated groups keep their header...
    expect(_label(page, "Overview")).to_be_visible()
    expect(_label(page, "Storage")).to_be_visible()
    # ...and the headers over the hidden temp-creds/users/groups and monitor/settings runs are gone
    expect(_label(page, "Access")).to_be_hidden()
    expect(_label(page, "System")).to_be_hidden()
