"""UI — the Activity page: the summary band, the events list and its detail, wide and on a phone.

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


def _filter_by_person(page: Page, name):
    """Type a name into the filter panel's Person field: free text is a "contains" match."""
    page.click("#act-filter-btn")
    field = page.locator("#act-fp-user")
    expect(field).to_be_visible()
    field.fill(name)
    field.press("Enter")


def test_the_band_counts_and_filters_the_list(page: Page, anon, activity_admin):
    anon.post("/auth/login", json={"username": unique("ghost"), "password": "not-it-1"})
    _login(page, activity_admin)
    _open_activity(page)
    failed = page.locator("#act-p-signin .act-signin-row").nth(1)
    expect(failed).to_contain_text("Failed", timeout=10000)
    assert int(failed.locator(".act-rank-count").inner_text().replace(",", "")) >= 1
    page.click("#act-p-time .act-key-btn[data-fkey=key-bad]")          # the "failed or refused" key
    expect(page.locator("#act-chips")).to_contain_text("Status: Failed or refused")
    expect(page.locator("#activity-rows tr.act-row").first).to_contain_text("Failed", timeout=10000)


def test_events_filter_by_user_and_open_a_row(page: Page, anon, activity_admin):
    name = unique("ghost")
    anon.post("/auth/login", json={"username": name, "password": "not-it-1"})
    _login(page, activity_admin)
    _open_activity(page)
    _filter_by_person(page, name)
    rows = page.locator("#activity-rows tr.act-row")
    expect(rows).to_have_count(1, timeout=10000)
    expect(page.locator("#activity-summary")).to_have_text("1–1 of 1")
    expect(page.locator("#act-chips")).to_contain_text(f"Person contains: {name}")
    page.keyboard.press("Escape")                                           # closes the filter panel
    rows.first.click()
    pane = page.locator("#act-detail")
    expect(pane).to_be_visible()
    expect(pane).to_contain_text("Sign-in failed")
    expect(pane).to_contain_text("POST /auth/login")
    expect(pane).to_contain_text(name)
    page.keyboard.press("Escape")
    expect(pane).to_be_hidden()


def test_on_a_phone_the_filters_are_a_sheet_and_results_are_rows(page: Page, anon, activity_admin):
    name = unique("ghost")
    anon.post("/auth/login", json={"username": name, "password": "not-it-1"})
    _login(page, activity_admin, width=390, height=844)
    _open_activity(page)
    expect(page.locator("#act-table")).to_be_hidden()
    page.click("#act-filter-btn")
    sheet = page.locator("#act-filter-modal")
    expect(sheet).to_be_visible()
    page.fill("#act-fp-user", name)
    page.locator("#act-fp-user").press("Enter")
    expect(page.locator("#act-fp-done")).to_have_text("Show 1 event", timeout=10000)
    page.click("#act-fp-done")
    expect(sheet).to_be_hidden()
    expect(page.locator("#act-filter-label")).to_have_text("Filters 1")
    expect(page.locator("#activity-cards .act-card")).to_have_count(1, timeout=10000)
    assert page.evaluate("() => document.documentElement.scrollWidth") <= 391


def test_the_filter_panel_closes_on_a_click_elsewhere(page: Page, activity_admin):
    _login(page, activity_admin)
    _open_activity(page)
    page.click("#act-filter-btn")
    expect(page.locator("#act-filter-panel")).to_be_visible()
    expect(page.locator("#act-filter-btn")).to_have_attribute("aria-expanded", "true")
    page.click("#activity-section h2")                                   # a click elsewhere closes it
    expect(page.locator("#act-filter-panel")).to_be_hidden()
    expect(page.locator("#act-filter-btn")).to_have_attribute("aria-expanded", "false")


def test_the_events_export_downloads_the_rows_that_match(page: Page, anon, activity_admin):
    name = unique("ghost")
    anon.post("/auth/login", json={"username": name, "password": "not-it-1"})
    _login(page, activity_admin)
    _open_activity(page)
    _filter_by_person(page, name)
    expect(page.locator("#activity-rows tr.act-row")).to_have_count(1, timeout=10000)
    page.keyboard.press("Escape")
    page.click("#activity-export")
    with page.expect_download() as dl:
        page.click('[data-activity-export="csv"]')
    path = dl.value.path()
    text = open(path, encoding="utf-8").read()
    assert dl.value.suggested_filename.startswith("activity-") and dl.value.suggested_filename.endswith(".csv")
    assert text.count("\n") == 2 and name in text
    expect(page.locator(".toast").last).to_contain_text("Exported 1 event")


def test_an_event_the_server_records_on_its_own_is_by_the_system(page: Page, activity_admin):
    """A file deleted at its expiry has no one behind it: the page says System, not Unknown, which
    stays for a row whose actor is simply not recorded. The events are served here, so the test does
    not wait for the sweep."""
    import json

    def event(action, label, automatic):
        return {"id": action, "timestamp": "2026-09-26T12:00:00+00:00", "action": action, "label": label,
                "category": "files", "severity": "info", "automatic": automatic, "status": "success",
                "channel": None, "username": None, "temp_credential_id": None, "ip_address": None,
                "method": None, "endpoint": None, "user_agent": None, "resource_type": "file",
                "resource_id": action, "details": {}, "error_message": None,
                "names": {"vault": None, "item": None}}

    body = json.dumps({"events": [event("file_expired", "File deleted at its expiry", True),
                                  event("file_download", "File download started", False)],
                       "next_cursor": None, "total": 2})
    page.route(lambda url: "/activity/events" in url,
               lambda route: route.fulfill(status=200, content_type="application/json", body=body))
    _login(page, activity_admin)
    _open_activity(page)
    rows = page.locator("#activity-rows tr.act-row")
    expect(rows).to_have_count(2, timeout=10000)
    expect(rows.nth(0).locator("td").nth(2)).to_have_text("System")
    expect(rows.nth(1).locator("td").nth(2)).to_have_text("Unknown")
