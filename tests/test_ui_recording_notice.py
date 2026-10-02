"""The notice page and the banner after a change, in a browser (static/recording.html, static/js/notice-banner.js).

The page shows the levels and the stores with no console errors and fits a phone's width. After a change of the
levels, a user sees the banner when they sign in, and while they are signed in when the change is saved; "I've
read it" takes it down, and it does not come back on a reload.
"""
import pytest
from playwright.sync_api import Page, expect

from _recording_levels import latest, levels_restored  # noqa: F401 -- a fixture

pytestmark = pytest.mark.ui

ACTION = "admin.audit_privacy.write"


def _save(admin, password, levels):
    receipt = admin.post("/auth/second-factor/step-up",
                         json={"action": ACTION, "method": "password", "code": password}).json()["receipt"]
    r = admin.put("/settings/recording", json={"levels": levels}, headers={"X-Second-Factor": receipt})
    assert r.status_code == 200, r.text
    return r.json()["version"]


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def test_the_page_shows_the_levels_and_fits_a_phone(page: Page):
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.set_viewport_size({"width": 375, "height": 812})
    page.goto("/recording")
    expect(page.locator("#levels dt")).to_have_count(5, timeout=10000)
    expect(page.locator("#stores li").first).to_be_visible()
    expect(page.locator("#history-section")).to_be_hidden()
    assert page.evaluate("() => document.documentElement.scrollWidth") <= 375
    assert not errors, errors


def test_the_login_page_links_the_notice(page: Page):
    page.goto("/")
    link = page.locator('#login-screen a[href="/recording"]')
    expect(link).to_be_visible()


def test_the_banner_after_a_change_until_it_is_read(page: Page, admin, admin_creds, temp_user, levels_restored):
    _save(admin, admin_creds["password"], dict(levels_restored, user_agent="none"))
    _login(page, temp_user["_username"], temp_user["_password"])
    banner = page.locator('.notice-banner[data-notice="recording-levels"]')
    expect(banner).to_be_visible(timeout=10000)
    expect(banner.locator('a[href="/recording"]')).to_be_visible()
    banner.locator("button:has-text(\"I've read it\")").click()
    expect(banner).to_be_hidden(timeout=10000)
    # A change saved while the user is signed in shows the banner at once, over the socket sign-in opened.
    page.wait_for_function("() => window.dockvaultSocketState === 'open'", timeout=20000)
    _save(admin, admin_creds["password"], dict(levels_restored, user_agent="full", emails="none"))
    expect(banner).to_be_visible(timeout=20000)
    banner.locator("button:has-text(\"I've read it\")").click()
    expect(banner).to_be_hidden(timeout=10000)
    # Read is read: a reload does not bring it back.
    page.reload()
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    page.wait_for_timeout(2000)
    expect(page.locator('.notice-banner[data-notice="recording-levels"]')).to_have_count(0)
