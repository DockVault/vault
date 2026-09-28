"""UI — what the Activity page says when there is nothing to show, when a read fails, when an event
from a link is gone, when the range is in the past, and when the person is signed in with a temporary
credential (the page then asks the server nothing: every refused request would be a row in the log)."""
import re

import pytest
from playwright.sync_api import Page, expect

from _activity_ui import activity_admin, filter_by_person, login, open_activity, rows  # noqa: F401
from conftest import ApiClient, unique

pytestmark = pytest.mark.ui


def test_no_match_names_the_range_and_offers_a_way_out(page: Page, activity_admin):
    login(page, activity_admin)
    open_activity(page)
    filter_by_person(page, unique("nobody"))
    empty = page.locator("#act-empty")
    expect(empty).to_contain_text("No events match these filters in the last 7 days.", timeout=10000)
    expect(rows(page)).to_have_count(0)
    expect(page.locator("#activity-export")).to_have_attribute("aria-disabled", "true")
    empty.get_by_role("button", name="Search all time").click()
    expect(empty).to_contain_text("No events match these filters in all time.", timeout=10000)
    expect(empty.get_by_role("button", name="Search all time")).to_have_count(0)
    empty.get_by_role("button", name="Clear filters").click()
    expect(empty).to_be_hidden(timeout=10000)
    expect(rows(page).first).to_be_visible()


def test_a_range_in_the_past_is_not_live(page: Page, activity_admin):
    login(page, activity_admin,
          path="/#activity?range=custom&from=2001-01-01T00:00:00.000Z&to=2001-01-02T00:00:00.000Z")
    expect(page.locator("#activity-section")).to_be_visible(timeout=10000)
    empty = page.locator("#act-empty")
    expect(empty).to_contain_text("No events in this time range.", timeout=10000)
    expect(page.locator("#act-live")).to_have_attribute("data-state", "notlive")
    expect(page.locator("#act-live-label")).to_have_text("Not live")
    expect(page.locator("#act-range-custom")).to_have_attribute("aria-checked", "true")
    empty.get_by_role("button", name="Show all time").click()
    expect(rows(page).first).to_be_visible(timeout=10000)
    expect(page.locator("#act-live")).to_have_attribute("data-state", "live", timeout=10000)


def test_a_failed_read_says_so_keeps_the_rows_and_can_be_tried_again(page: Page, activity_admin):
    login(page, activity_admin)
    open_activity(page)
    failing = {"on": True}

    def events(route):
        if failing["on"] and "ids=" not in route.request.url:
            return route.fulfill(status=500, json={"detail": "The database is busy."})
        return route.continue_()

    def summary(route):
        if failing["on"]:
            return route.fulfill(status=500, json={"detail": "The database is busy."})
        return route.continue_()

    page.route(re.compile(r"/activity/events\?"), events)
    page.route(re.compile(r"/activity/summary\?"), summary)
    shown = rows(page).count()
    page.click("#act-range [data-range='30d']")
    alert = page.locator("#act-list-alert")
    expect(alert).to_contain_text("Events could not be loaded: The database is busy.", timeout=10000)
    expect(rows(page)).to_have_count(shown)                          # the rows on screen stay
    for panel in ("time", "cat", "signin", "active"):
        expect(page.locator(f"#act-p-{panel} .act-plot-note")).to_have_text("Couldn't load.")
    failing["on"] = False
    alert.get_by_role("button", name="Try again").click()
    expect(alert).to_be_hidden(timeout=10000)
    page.locator("#act-p-cat .act-retry").click()
    expect(page.locator("#act-p-cat .act-rank-row").first).to_be_visible(timeout=10000)


def test_an_event_from_a_link_that_is_gone_says_so(page: Page, activity_admin):
    login(page, activity_admin, path="/#activity?range=7d&ev=00000000-0000-4000-8000-000000000000")
    pane = page.locator("#act-detail")
    expect(pane).to_contain_text("This event could not be found.", timeout=10000)
    expect(rows(page).first).to_be_visible()                          # the list loads as usual
    pane.get_by_role("button", name="Close details").click()
    expect(pane).to_be_hidden()


def test_a_temporary_credential_gets_the_own_sign_in_message_and_nothing_is_asked(page: Page, activity_admin):
    owner = ApiClient()
    owner.login(activity_admin["_username"], activity_admin["_password"])
    r = owner.post("/auth/temp-credentials", json={"note": unique("audit")})
    assert r.status_code == 200, r.text
    tc = r.json()
    asked = []
    page.on("request", lambda req: asked.append(req.url) if "/activity/" in req.url else None)
    page.set_viewport_size({"width": 1440, "height": 900})
    # A copied link opened with the temporary credential: not followed, and dropped.
    page.goto("/#activity?range=24h&user=someone")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", tc["temp_username"])
    page.fill("#password", tc["credential"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    page.wait_for_timeout(1000)
    assert page.evaluate("() => location.hash") == ""
    assert not page.locator("#activity-section").is_visible()
    # Reached anyway (the sidebar or a remembered view): the page says why, and asks nothing.
    page.evaluate("() => navigateToSection('activity')")
    blocked = page.locator("#act-blocked")
    expect(blocked).to_have_text("Activity needs your own administrator sign-in. You're signed in with a "
                                 "temporary credential, which can't open the activity log.")
    expect(page.locator("#act-band")).to_be_hidden()
    expect(page.locator("#act-toolbar")).to_be_hidden()
    page.wait_for_timeout(2000)
    assert asked == [], asked


def test_the_person_typeahead_offers_accounts_never_a_name_typed_at_a_sign_in(page: Page, admin, anon,
                                                                              activity_admin):
    """A name typed at a failed sign-in can be a password typed into the wrong box: it stays in the list,
    where someone looks for it, and is never offered to someone typing two letters of something else."""
    stem = unique("ta").lower()
    anon.post("/auth/login", json={"username": f"{stem}-typed", "password": "not-it-1"})
    account = admin.create_user(username=f"{stem}-account")
    try:
        login(page, activity_admin)
        open_activity(page)
        page.click("#act-filter-btn")
        with page.expect_response(lambda r: "/activity/usernames" in r.url):
            page.locator("#act-fp-user").press_sequentially(stem)
        expect(page.locator("#act-filter-panel .act-ta-item .act-ta-label")).to_have_text([f"{stem}-account"])
    finally:
        admin.delete_user(account["id"])


def test_a_copied_link_shows_another_administrator_only_the_names_they_may_see(page: Page, admin,
                                                                               activity_admin):
    owner = ApiClient()
    owner.login(activity_admin["_username"], activity_admin["_password"])
    secret = unique("Project Nightjar")
    vault = owner.create_vault(name=secret)
    other = admin.create_user(role="admin")
    try:
        login(page, other, path=f"/#activity?range=24h&vault={vault['id']}")
        expect(page.locator("#activity-section")).to_be_visible(timeout=10000)
        expect(page.locator("#act-chips")).to_contain_text(f"Vault: name not shown ({vault['id'][:6]})")
        expect(rows(page).first).to_be_visible(timeout=10000)           # the vault's creation, by its owner
        rows(page).first.click()
        expect(page.locator("#act-detail")).to_contain_text("Not shown")
        assert secret not in page.locator("body").inner_text()
    finally:
        admin.delete_user(other["id"])
        owner.delete_vault(vault["id"])
