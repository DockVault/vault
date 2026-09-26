"""UI — the Activity page: an administrator's Overview counts and the Events tab, wide and on a phone.

Logs in as a THROWAWAY admin, so a skin or preference stored on the shared account cannot change the page."""
import pytest
from playwright.sync_api import Page, expect

from conftest import unique

pytestmark = pytest.mark.ui


@pytest.fixture
def activity_admin(admin):
    u = admin.create_user(role="admin")
    yield u
    admin.delete_user(u["id"])


def _login(page: Page, user, width=1280, height=900):
    page.set_viewport_size({"width": width, "height": height})
    page.goto("/")
    page.fill("#username", user["_username"])
    page.fill("#password", user["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_activity(page: Page):
    toggle = page.locator("#mobile-nav-toggle")
    if toggle.is_visible():
        toggle.click()
    page.click('.sidebar-item[data-section="activity"]')
    expect(page.locator("#activity-section")).to_be_visible(timeout=10000)


def test_the_activity_page_is_for_administrators_only(page: Page, admin, temp_user):
    _login(page, temp_user)
    expect(page.locator('.sidebar-item[data-section="activity"]')).to_be_hidden()


def test_the_overview_counts_and_opens_events(page: Page, anon, activity_admin):
    anon.post("/auth/login", json={"username": unique("ghost"), "password": "not-it-1"})
    _login(page, activity_admin)
    _open_activity(page)
    tiles = page.locator("#activity-stats .activity-stat")
    expect(tiles).to_have_count(4)
    expect(tiles.nth(1)).to_contain_text("Failed sign-ins")
    expect(tiles.nth(1).locator(".activity-stat-num")).not_to_have_text("…", timeout=10000)
    tiles.nth(1).click()                                     # the tile opens Events, filtered
    expect(page.locator("#activity-tab-events")).to_be_visible()
    expect(page.locator("#activity-status")).to_have_value("failed")
    expect(page.locator("#activity-rows tr").first).to_contain_text("Sign-in failed", timeout=10000)


def test_events_filter_by_user_and_open_a_row(page: Page, anon, activity_admin):
    name = unique("ghost")
    anon.post("/auth/login", json={"username": name, "password": "not-it-1"})
    _login(page, activity_admin)
    _open_activity(page)
    page.click('[data-activity-tab="events"]')
    page.fill("#activity-user", name)
    page.click("#activity-search")
    rows = page.locator("#activity-rows tr.activity-row")
    expect(rows).to_have_count(1, timeout=10000)
    expect(page.locator("#activity-summary")).to_have_text("Showing 1 of 1 event")
    rows.first.click()
    modal = page.locator("#activity-event-modal")
    expect(modal).to_be_visible()
    expect(modal).to_contain_text("Sign-in failed")
    expect(modal).to_contain_text("POST /auth/login")
    expect(modal).to_contain_text(name)
    page.keyboard.press("Escape")
    expect(modal).to_be_hidden()


def test_on_a_phone_the_filters_fold_and_results_are_cards(page: Page, anon, activity_admin):
    name = unique("ghost")
    anon.post("/auth/login", json={"username": name, "password": "not-it-1"})
    _login(page, activity_admin, width=390, height=844)
    _open_activity(page)
    page.click('[data-activity-tab="events"]')
    expect(page.locator("#activity-filters")).to_be_hidden()
    expect(page.locator(".activity-table-wrap")).to_be_hidden()
    page.click("#activity-filters-toggle")
    expect(page.locator("#activity-filters")).to_be_visible()
    page.fill("#activity-user", name)
    page.click("#activity-search")
    expect(page.locator("#activity-filters")).to_be_hidden()            # folds away after a search
    expect(page.locator("#activity-filters-toggle")).to_have_text("Filters (1)")
    expect(page.locator("#activity-cards .activity-card")).to_have_count(1, timeout=10000)
    assert page.evaluate("() => document.documentElement.scrollWidth") <= 391


def test_one_checklist_open_at_a_time(page: Page, activity_admin):
    _login(page, activity_admin)
    _open_activity(page)
    page.click('[data-activity-tab="events"]')
    page.click("#activity-pick-category summary")
    expect(page.locator("#activity-pick-category")).to_have_attribute("open", "")
    page.click("#activity-pick-channel summary")
    expect(page.locator("#activity-pick-category")).not_to_have_attribute("open", "")
    page.click("#activity-section h2")                                   # a click elsewhere closes it
    expect(page.locator("#activity-pick-channel")).not_to_have_attribute("open", "")


def test_the_events_export_downloads_the_rows_on_screen(page: Page, anon, activity_admin):
    name = unique("ghost")
    anon.post("/auth/login", json={"username": name, "password": "not-it-1"})
    _login(page, activity_admin)
    _open_activity(page)
    page.click('[data-activity-tab="events"]')
    page.fill("#activity-user", name)
    page.click("#activity-search")
    expect(page.locator("#activity-rows tr.activity-row")).to_have_count(1, timeout=10000)
    page.fill("#activity-user", "someone-else")          # the export uses the filters searched with
    with page.expect_download() as dl:
        page.click('[data-activity-export="csv"]')
    path = dl.value.path()
    text = open(path, encoding="utf-8").read()
    assert dl.value.suggested_filename.startswith("activity-") and dl.value.suggested_filename.endswith(".csv")
    assert text.count("\n") == 2 and name in text
    expect(page.locator(".toast").last).to_contain_text("Exported 1 event")


def test_settings_audit_log_points_to_the_events_tab(page: Page, activity_admin):
    _login(page, activity_admin)
    page.click('.sidebar-item[data-section="settings"]')
    page.click('#settings-section .tab-btn[data-tab="audit"]')
    page.click("#audit-open-activity")
    expect(page.locator("#activity-section")).to_be_visible(timeout=10000)
    expect(page.locator("#activity-tab-events")).to_be_visible()
    expect(page.locator("#activity-tab-overview")).to_be_hidden()
    # The tab is searched on arrival: at least this admin's own sign-in is listed.
    expect(page.locator("#activity-rows tr.activity-row").first).to_be_visible(timeout=10000)
    expect(page.locator("#activity-summary")).to_contain_text("Showing")
