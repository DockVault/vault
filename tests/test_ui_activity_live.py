"""UI — the Activity page is live: an event appears at the top as it happens, waits behind a pill while
someone reads, is counted while the page is paused, and still arrives when the socket or its signal is
lost.

Each event here is a failed sign-in by a name no account has, written from another client while the
page is open and filtered to that name, so nothing else a test run writes can land in the list."""
import re
import time

import pytest
from playwright.sync_api import Page, expect

from _activity_ui import activity_admin, failed_sign_in, filter_by_person, login, open_activity, rows  # noqa: F401
from conftest import unique

pytestmark = pytest.mark.ui


def _ids_read(resp):
    return "/activity/events" in resp.url and "ids=" in resp.url


def _open_on(page: Page, user, name):
    login(page, user)
    open_activity(page)
    filter_by_person(page, name)
    expect(rows(page)).to_have_count(1, timeout=10000)
    expect(page.locator("#act-live")).to_have_attribute("data-state", "live", timeout=10000)


def test_a_new_event_appears_at_the_top_of_an_idle_list(page: Page, anon, activity_admin):
    # Reduced motion keeps the new-row tint still for ten seconds, so the test can read it.
    page.emulate_media(reduced_motion="reduce")
    name = failed_sign_in(anon)
    _open_on(page, activity_admin, name)
    first = rows(page).first.get_attribute("data-id")
    # Someone watching: the pointer rests on the list. Only a pointer that moved in the last 1.5 s holds
    # rows back.
    rows(page).first.hover()
    page.wait_for_timeout(1700)

    # An event that does not match the filter: the page asks for it by id, with the filter, and the
    # server answers with nothing.
    with page.expect_response(_ids_read, timeout=10000) as other:
        failed_sign_in(anon)
    assert f"user={name}" in other.value.url
    assert other.value.json()["events"] == []
    expect(rows(page)).to_have_count(1)

    started = time.monotonic()
    with page.expect_response(_ids_read, timeout=10000):
        failed_sign_in(anon, name)
    expect(rows(page)).to_have_count(2, timeout=5000)
    assert time.monotonic() - started < 5
    top = rows(page).first
    assert top.get_attribute("data-id") != first
    expect(top).to_contain_text("Sign-in failed")
    expect(top).to_have_class(re.compile(r"\bis-new\b"))
    # No fade: the skins' reduced-motion rule leaves at most a microsecond of transition.
    assert float(top.evaluate("r => getComputedStyle(r).transitionDuration").rstrip("s") or 0) < 0.01
    expect(page.locator("#activity-summary")).to_have_text("1–2 of 2")


def test_with_the_detail_open_new_events_wait_behind_the_pill(page: Page, anon, activity_admin):
    name = failed_sign_in(anon)
    _open_on(page, activity_admin, name)
    rows(page).first.click()
    pane = page.locator("#act-detail")
    expect(pane.locator(".act-d-pos")).to_have_text("1 of 1")
    shown = rows(page).first.get_attribute("data-id")
    page.mouse.move(1, 1)                                     # only the open detail holds rows back now
    page.wait_for_timeout(1700)

    with page.expect_response(_ids_read, timeout=10000):
        failed_sign_in(anon, name)
    pill = page.locator("#act-new-pill")
    expect(pill).to_be_visible(timeout=5000)
    expect(pill).to_have_text("↑ 1 new event")
    page.wait_for_timeout(2000)
    expect(pill).to_be_visible()
    expect(rows(page)).to_have_count(1)                       # nothing moved under the reader
    expect(pane.locator(".act-d-pos")).to_have_text("1 of 1")

    pill.click()
    expect(pill).to_be_hidden()
    expect(rows(page)).to_have_count(2)
    expect(rows(page).nth(1)).to_have_attribute("data-id", shown)
    expect(rows(page).nth(1)).to_have_attribute("aria-current", "true")   # the selection stayed on its event
    expect(pane.locator(".act-d-pos")).to_have_text("2 of 2")
    expect(pane).to_be_visible()


def test_a_row_committed_late_goes_in_by_its_time(page: Page, anon, activity_admin):
    """A row whose transaction commits after a newer one's is fetched by its id, so it is not lost, and
    it goes in among the rows by its time. The first read of the list here leaves the middle row out,
    as a read made before that row committed would; its signal then brings it in."""
    name = unique("ghost")
    for _ in range(3):
        failed_sign_in(anon, name)
        time.sleep(1.1)
    held = {}

    def first_read_without_the_middle_row(route):
        if "ids=" in route.request.url or held.get("done"):
            return route.continue_()
        resp = route.fetch()
        body = resp.json()
        if len(body.get("events", [])) == 3:
            held["row"] = body["events"].pop(1)
            body["total"] = 2
            held["done"] = True
        return route.fulfill(response=resp, json=body)

    login(page, activity_admin)
    open_activity(page)
    page.route(lambda url: "/activity/events" in url, first_read_without_the_middle_row)
    filter_by_person(page, name)
    expect(rows(page)).to_have_count(2, timeout=10000)
    page.unroute(lambda url: "/activity/events" in url)
    late = held["row"]["id"]
    page.mouse.move(1, 1)
    page.wait_for_timeout(1700)
    with page.expect_response(_ids_read, timeout=10000):
        page.evaluate("""id => window.dispatchEvent(new CustomEvent('dockvault:activity',
                         { detail: { events: [{ id, category: 'sign_in' }] } }))""", late)
    expect(rows(page)).to_have_count(3, timeout=5000)
    expect(rows(page).nth(1)).to_have_attribute("data-id", late)


def test_pause_counts_new_events_and_resume_shows_them(page: Page, anon, activity_admin):
    name = failed_sign_in(anon)
    _open_on(page, activity_admin, name)
    pause = page.locator("#act-pause")
    pause.click()
    expect(pause).to_have_attribute("aria-pressed", "true")
    expect(pause).to_contain_text("Resume")
    expect(page.locator("#act-live-label")).to_have_text("Paused")

    failed_sign_in(anon, name)
    expect(page.locator("#act-live-label")).to_have_text("Paused · 1 new", timeout=10000)
    expect(rows(page)).to_have_count(1)
    # What the viewer does still works while paused: opening an event.
    rows(page).first.click()
    expect(page.locator("#act-detail")).to_be_visible()
    page.keyboard.press("Escape")

    page.mouse.move(1, 1)
    page.wait_for_timeout(1700)
    pause.click()
    expect(pause).to_have_attribute("aria-pressed", "false")
    expect(page.locator("#act-live-label")).to_have_text("Live")
    expect(rows(page)).to_have_count(2, timeout=5000)


def test_with_the_socket_down_the_page_says_delayed_and_polls(page: Page, anon, activity_admin):
    name = failed_sign_in(anon)
    _open_on(page, activity_admin, name)
    assert page.locator("#act-live").get_attribute("aria-live") is None     # status, not a live region
    page.evaluate("""() => {
        window.__RealWS = window.WebSocket;
        window.WebSocket = function () { throw new Error('blocked by test'); };
        closeAppSocket();
    }""")
    expect(page.locator("#act-live-label")).to_have_text("Delayed", timeout=13000)
    expect(page.locator("#act-announce")).to_have_text("Live updates are delayed.")

    page.mouse.move(1, 1)
    failed_sign_in(anon, name)                   # no socket: only the 15-second poll can bring it
    expect(rows(page)).to_have_count(2, timeout=20000)

    page.evaluate("() => { window.WebSocket = window.__RealWS; connectAppSocket(); }")
    expect(page.locator("#act-live-label")).to_have_text("Live", timeout=10000)
    expect(page.locator("#act-announce")).to_have_text("Live updates are back.")


def test_a_lost_signal_is_found_by_the_safety_poll(page: Page, anon, activity_admin):
    """The socket stays up but the signal for the event never reaches the page, as when the server
    could not publish it: the minute's safety poll still brings the row in."""
    name = failed_sign_in(anon)
    _open_on(page, activity_admin, name)
    page.evaluate("""() => {
        const real = window.handleSocketFrame;
        window.handleSocketFrame = (data) => { if (!(data && data.type === 'activity')) real(data); };
    }""")
    reads = []
    page.on("request", lambda r: reads.append(r.url.split("?", 1)[-1]) if "/activity/events" in r.url else None)
    page.mouse.move(1, 1)
    failed_sign_in(anon, name)
    page.wait_for_timeout(3000)
    assert rows(page).count() == 1, reads                                # the signal was lost
    expect(page.locator("#act-live-label")).to_have_text("Live")
    expect(rows(page)).to_have_count(2, timeout=65000)
