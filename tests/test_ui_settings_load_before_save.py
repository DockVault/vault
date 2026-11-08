"""Settings: nothing can be saved until the settings have loaded, and every handler on the page is wired once.

Save sends every field of the form. The form holds blanks and defaults until the settings are on the page,
so a Save after a failed load (a timeout, a 5xx) wrote those blanks over every setting: the password rule back
to its floor, sharing and the public links off. Save was disabled while the load ran and enabled whether it
succeeded or not. Now it is enabled only by a successful load; a failed load says so and offers Retry.

The page's handlers (the tab bar, the log-access controls, the brand colour and asset controls) were attached
on every visit to Settings, so after three visits one click on a tab sent three rounds of its reads, and one
toggle three saves. Each is wired once now. The tab bar handler also reached the other pages' tab bars (every
.tabs .tab-btn), where it closed this page's open tab; it is scoped to this page.
"""
import re
from urllib.parse import urlparse

import pytest
from playwright.sync_api import Page, expect

from _settings_ui import show_advanced

pytestmark = pytest.mark.ui

SAVE = "#save-all-settings-btn"
BANNER = "#settings-load-error"
_SETTINGS_GET = re.compile(r".*/settings(\?.*)?$")


@pytest.fixture
def settings_admin(admin):
    u = admin.create_user(role="admin")
    yield u
    admin.delete_user(u["id"])


def _login(page: Page, user):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", user["_username"])
    page.fill("#password", user["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_settings(page: Page):
    page.click('.sidebar-item[data-section="settings"]')
    expect(page.locator("#settings-section")).to_be_visible(timeout=10000)


def _wait_ready(page: Page):
    expect(page.locator(SAVE)).to_have_attribute("data-settings-ready", "true", timeout=15000)


def _requests(page: Page, method: str, path: str) -> list:
    """Every request of ``method`` to exactly ``path`` from now on."""
    seen = []
    page.on("request", lambda r: seen.append(r.url) if r.method == method and urlparse(r.url).path == path else None)
    return seen


def test_a_failed_settings_load_keeps_save_disabled_and_retry_recovers(page: Page, settings_admin):
    _login(page, settings_admin)
    failures = []

    def fail(route):
        if route.request.method == "GET":
            failures.append(route.request.url)
            route.fulfill(status=500, json={"detail": "not now"})
        else:
            route.continue_()

    page.route(_SETTINGS_GET, fail)
    _open_settings(page)
    page.wait_for_timeout(1500)  # the load has failed and the page has settled
    assert failures, "the settings read was not attempted"
    expect(page.locator(BANNER)).to_be_visible()
    expect(page.locator(SAVE)).to_be_disabled()
    expect(page.locator(SAVE)).not_to_have_attribute("data-settings-ready", "true")

    # The server is back: Retry loads the settings, and only then is Save live.
    page.unroute(_SETTINGS_GET, fail)
    page.click("#settings-load-retry")
    _wait_ready(page)
    expect(page.locator(SAVE)).to_be_enabled()
    expect(page.locator(BANNER)).to_be_hidden()


def test_three_visits_then_one_click_send_one_request_each(page: Page, settings_admin):
    _login(page, settings_admin)
    for _ in range(3):
        _open_settings(page)
        _wait_ready(page)
        page.click('.sidebar-item[data-section="dashboard"]')
        expect(page.locator("#dashboard-section")).to_be_visible()
    _open_settings(page)
    _wait_ready(page)
    page.wait_for_timeout(1000)  # the visit's own reads are done

    tab_reads = _requests(page, "GET", "/settings/logs")
    page.click('#settings-section .tab-btn[data-tab="logs"]')
    expect(page.locator("#settings-tab-logs")).to_be_visible()
    page.wait_for_timeout(1000)
    assert len(tab_reads) == 1, f"one tab click, {len(tab_reads)} reads"

    saves = _requests(page, "PUT", "/settings/logs")
    show_advanced(page, "logs")  # the toggle is an advanced setting of the page
    toggle = page.locator("#log-stealth-toggle")
    expect(toggle).to_be_visible()
    was = toggle.is_checked()
    toggle.click()
    page.wait_for_timeout(1000)
    assert len(saves) == 1, f"one toggle, {len(saves)} saves"
    toggle.click()  # as it was
    page.wait_for_timeout(1000)
    assert toggle.is_checked() == was


def test_another_pages_tab_bar_leaves_the_settings_tab_open(page: Page, settings_admin):
    _login(page, settings_admin)
    _open_settings(page)
    _wait_ready(page)
    expect(page.locator("#settings-tab-general")).to_have_class(re.compile(r"\bactive\b"))
    page.click('.sidebar-item[data-section="shared"]')
    expect(page.locator("#shared-section")).to_be_visible(timeout=10000)
    page.click('[data-shared-tab="by-me"]')
    _open_settings(page)
    expect(page.locator("#settings-tab-general")).to_have_class(re.compile(r"\bactive\b"))
    expect(page.locator("#settings-tab-general")).to_be_visible()
