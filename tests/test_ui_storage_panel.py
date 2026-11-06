"""The Settings -> Storage panel populates from the real endpoint."""
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


def test_storage_panel_says_the_free_space_the_volume_keeps(admin_page: Page):
    """The panel says the floor of free space in force (MIN_FREE_SPACE_GB), as /storage/stats reports it: on the
    shipped default the larger of 2 GB and 5% of the volume, so never none on a volume that says its size."""
    page = admin_page
    page.click('.sidebar-item[data-section="settings"]')
    page.click('.tab-btn[data-tab="storage"]')
    floor = page.locator("#storage-stat-floor")
    # "Keeps no free space ..." when the floor is off: on the default it is a size.
    expect(floor).to_contain_text(re.compile(r"^Keeps \d[\d.,]* ?[KMGT]?i?B of this volume free"), timeout=10000)
    expect(floor).to_contain_text("MIN_FREE_SPACE_GB")
