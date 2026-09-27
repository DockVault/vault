"""The Settings -> Storage panel populates from the real endpoint."""
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


@pytest.fixture
def admin_page(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    return page


def test_storage_panel_shows_real_values(admin_page: Page):
    # Real byte figures instead of the "N/A" the panel showed when the endpoint 404'd.
    page = admin_page
    page.click('.sidebar-item[data-section="settings"]')
    page.click('.tab-btn[data-tab="storage"]')
    page.wait_for_timeout(1500)
    expect(page.locator("#storage-stat-total")).not_to_have_text("N/A", timeout=10000)
    expect(page.locator("#storage-stat-used")).not_to_have_text("N/A")
    expect(page.locator("#storage-stat-available")).not_to_have_text("N/A")
