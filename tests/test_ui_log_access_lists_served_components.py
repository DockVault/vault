"""The log access page lists only the log components this deployment serves.

The page listed every component the log system knows, two of them with a "coming soon" badge: a flag for a
component the server cannot serve, and a token for it would fetch nothing. Now the list is the served ones, as
GET /settings/logs reports them, and nothing on the page is promised.
"""
import pytest
from playwright.sync_api import Page, expect

from _settings_ui import show_advanced

pytestmark = pytest.mark.ui


def _login(page: Page, creds):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", creds["username"])
    page.fill("#password", creds["password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def test_only_served_components_are_listed(page: Page, admin, admin_creds):
    served = admin.get("/settings/logs").json()
    assert set(served["serveable"]) < set(served["components"]), "nothing unserved to leave out: the test would prove nothing"
    _login(page, admin_creds)
    page.click('.sidebar-item[data-section="settings"]')
    expect(page.locator("#settings-section")).to_be_visible(timeout=10000)
    expect(page.locator("#save-all-settings-btn")).to_have_attribute("data-settings-ready", "true", timeout=15000)
    page.click('#settings-section .tab-btn[data-tab="logs"]')
    expect(page.locator("#settings-tab-logs")).to_be_visible()
    show_advanced(page, "logs")
    rows = page.locator("#log-flags input[type=checkbox]")
    expect(rows).to_have_count(len(served["serveable"]), timeout=10000)
    listed = {c for c in page.evaluate("() => [...document.querySelectorAll('#log-flags input')].map(i => i.dataset.component)")}
    assert listed == set(served["serveable"]), listed
    expect(page.locator("#log-flags")).not_to_contain_text("coming soon")
