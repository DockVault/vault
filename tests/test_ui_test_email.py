"""The Send Test Email button reaches a real endpoint (it used to 404)."""
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


def test_test_email_button_hits_real_endpoint(admin_page: Page):
    page = admin_page
    page.click('.sidebar-item[data-section="settings"]')
    page.click('.tab-btn[data-tab="email"]')
    btn = page.locator("#test-email-btn")
    expect(btn).to_be_visible(timeout=10000)
    responses = []
    page.on("response", lambda r: responses.append((r.url, r.status)) if "/settings/test-email" in r.url else None)
    btn.click()
    # the button reports a concrete outcome (not the old blank/hang), proving the endpoint answered
    expect(page.locator("#test-email-result")).not_to_have_text("", timeout=15000)
    # and the endpoint exists (no 404)
    assert responses, "no /settings/test-email request was observed"
    assert all(status != 404 for _, status in responses), responses
