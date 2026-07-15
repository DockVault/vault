"""Live Monitor + Storage panels populate from real endpoints; the dead events poll is gone."""
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


def test_live_monitor_stats_render(admin_page: Page):
    # The headline tiles populate from /monitor/stats; since an admin is logged in the counts
    # are >= 1 (they used to be stuck at 0 because the endpoint 404'd).
    page = admin_page
    page.click('.sidebar-item[data-section="monitor"]')
    expect(page.locator("#monitor-active-users")).not_to_have_text("0", timeout=10000)
    expect(page.locator("#monitor-active-sessions")).not_to_have_text("0")


def test_monitor_ws_failure_does_not_poll_events(admin_page: Page):
    # Force the WebSocket to fail at construction — the exact path that used to fall back to
    # polling a non-existent /monitor/events endpoint. After the fallback removal it must retry
    # the WebSocket instead, so no request to /monitor/events is ever made.
    page = admin_page
    reqs = []
    page.on("request", lambda r: reqs.append(r.url))
    page.evaluate("() => { window.WebSocket = function () { throw new Error('blocked'); }; }")
    page.click('.sidebar-item[data-section="monitor"]')
    page.wait_for_timeout(6500)  # longer than the old 5s poll interval, so a poll would have fired
    assert not any("/monitor/events" in u for u in reqs), [u for u in reqs if "/monitor/events" in u]


def test_storage_panel_shows_real_values(admin_page: Page):
    # Real byte figures instead of the "N/A" the panel showed when the endpoint 404'd.
    page = admin_page
    page.click('.sidebar-item[data-section="settings"]')
    page.click('.tab-btn[data-tab="storage"]')
    page.wait_for_timeout(1500)
    expect(page.locator("#storage-stat-total")).not_to_have_text("N/A", timeout=10000)
    expect(page.locator("#storage-stat-used")).not_to_have_text("N/A")
    expect(page.locator("#storage-stat-available")).not_to_have_text("N/A")
