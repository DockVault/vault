"""UI e2e for the update-check controls (Settings -> General). The /api/update-status response is
mocked via page.route, so these are deterministic and never hit the real network — they run on any
live instance regardless of whether UPDATE_CHECK_ENABLED is set."""
import json
import time

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui


def _login(page, username, password):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_general(page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    page.click('.sidebar-item[data-section="settings"]')
    expect(page.locator("#settings-tab-general")).to_be_visible(timeout=10000)


def _mock_status(page, payload):
    page.route("**/api/update-status*", lambda route: route.fulfill(
        status=200, content_type="application/json", body=json.dumps(payload)))


def test_update_controls_and_banner_when_enabled(page: Page, admin_creds):
    _mock_status(page, {"enabled": True, "managed": False, "current": "0.6.0", "latest": "0.9.0",
                        "update_available": True, "url": "https://github.com/DockVault/vault/releases",
                        "notes": "x", "checked_at": 1700000000, "interval_minutes": 360})
    _open_general(page, admin_creds)
    # controls appear when the check is enabled
    expect(page.locator("#update-controls")).to_be_visible()
    expect(page.locator("#update-check-now-btn")).to_be_visible()
    expect(page.locator("#update-interval-input")).to_have_value("360")
    expect(page.locator("#update-last-checked")).to_contain_text("Last checked")
    # a newer release -> the banner shows with the version
    expect(page.locator("#update-banner")).to_be_visible()
    expect(page.locator("#update-banner-text")).to_contain_text("0.9.0")


def test_update_controls_hidden_when_disabled(page: Page, admin_creds):
    _mock_status(page, {"enabled": False, "managed": False, "current": "0.6.0",
                        "update_available": False, "interval_minutes": 360})
    _open_general(page, admin_creds)
    expect(page.locator("#update-controls")).to_be_hidden()
    expect(page.locator("#update-banner")).to_be_hidden()


def test_check_now_issues_a_forced_check(page: Page, admin_creds):
    forced = {"n": 0}

    def handle(route):
        if "force=1" in route.request.url:
            forced["n"] += 1
        route.fulfill(status=200, content_type="application/json", body=json.dumps(
            {"enabled": True, "managed": False, "current": "0.6.0", "latest": "0.6.0",
             "update_available": False, "checked_at": 1700000000, "interval_minutes": 60}))

    page.route("**/api/update-status*", handle)
    _open_general(page, admin_creds)
    expect(page.locator("#update-check-now-btn")).to_be_visible()
    page.click("#update-check-now-btn")
    deadline = time.time() + 5
    while forced["n"] == 0 and time.time() < deadline:
        page.wait_for_timeout(150)
    assert forced["n"] >= 1, "clicking Check for updates must issue a force=1 request"
