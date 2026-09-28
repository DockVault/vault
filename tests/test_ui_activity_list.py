"""UI — the Activity page's list: numbered pages and their counts, "All" loading as it scrolls, the keys
and the detail's Newer and Older moving across a page's edge, an event opened from a link, the page
size kept on the account, the phone's full-screen detail, and reads that write nothing to the log."""
import math
import re

import pytest
from playwright.sync_api import Page, expect

from _activity_ui import (activity_admin, failed_sign_in, filter_by_person, login, open_activity, ready,  # noqa: F401
                          rows, sign_in, sign_out, summary, total_of)

pytestmark = pytest.mark.ui


def _ids(page: Page):
    return page.locator("#activity-rows tr.act-row").evaluate_all("rs => rs.map((r) => r.dataset.id)")


def _size(page: Page, value):
    page.select_option("#act-page-size", value)


def test_numbered_pages_and_their_counts(page: Page, activity_admin):
    login(page, activity_admin)
    open_activity(page)
    _size(page, "25")
    expect(page.locator("#activity-summary")).to_have_text(re.compile(r"^1–25 of [\d,]+$"), timeout=10000)
    n = total_of(summary(page))
    assert n > 50, "the log should hold more than two pages of events by now"
    # With no time picked on the chart, the band counts what the list counts.
    band = page.locator("#act-p-time .act-key-btn[data-fkey=key-all] .act-num").inner_text()
    assert int(band.replace(",", "")) == n
    last = math.ceil(n / 25)
    pager = page.locator("#act-pager")
    expect(pager.locator(".act-pager-info")).to_have_text(f"Showing 1–25 of {n:,}")
    expect(pager.locator(".act-pg-num[aria-current=page]")).to_have_text("1")
    expect(pager.locator(".act-pg-num").last).to_have_text(f"{last:,}")
    one = _ids(page)
    assert len(one) == 25

    pager.locator(".act-pg-next").click()
    expect(page.locator("#activity-summary")).to_have_text(f"26–50 of {n:,}", timeout=10000)
    expect(pager.locator(".act-pg-num[aria-current=page]")).to_have_text("2")
    two = _ids(page)
    assert len(two) == 25 and not set(one) & set(two)
    assert "page=2" in page.evaluate("() => location.hash")

    pager.locator(".act-pg-num").last.click()
    start = 25 * (last - 1) + 1
    expect(page.locator("#activity-summary")).to_have_text(f"{start:,}–{n:,} of {n:,}", timeout=10000)
    expect(rows(page)).to_have_count(n - start + 1)
    expect(pager.locator(".act-pg-next")).to_be_disabled()


def test_all_loads_as_the_list_scrolls(page: Page, anon, activity_admin):
    name = failed_sign_in(anon)
    login(page, activity_admin)
    open_activity(page)
    _size(page, "all")
    expect(page.locator("#activity-summary")).to_have_text(re.compile(r"^100 of [\d,]+ loaded$"), timeout=10000)
    expect(page.locator("#act-pager .act-pg-num")).to_have_count(0)            # no page numbers in "All"
    sentinel = page.locator("#activity-rows tr.act-more.is-sentinel")
    expect(sentinel).to_have_text("Loading more events…")
    sentinel.scroll_into_view_if_needed()
    expect(page.locator("#activity-summary")).to_have_text(re.compile(r"^200 of [\d,]+ loaded$"), timeout=10000)
    filter_by_person(page, name)
    expect(page.locator("#activity-rows tr.act-more")).to_have_text("That's all: 1 event matches.", timeout=10000)


def _event(i):
    return {"id": f"00000000-0000-4000-8000-{i:012d}", "timestamp": f"2026-09-{27 - i // 86400:02d}T"
            f"{23 - (i // 3600) % 24:02d}:{59 - (i // 60) % 60:02d}:{59 - i % 60:02d}+00:00",
            "action": "file_download", "label": "File download started", "category": "files",
            "severity": "info", "automatic": False, "status": "success", "channel": "web",
            "username": "someone", "temp_credential_id": None, "ip_address": "192.0.2.1", "method": "GET",
            "endpoint": "/files/{file_id}/download", "user_agent": None, "resource_type": "file",
            "resource_id": str(i), "details": {}, "error_message": None, "names": {"vault": None, "item": None},
            "cursor": f"m{i}"}


def test_all_stops_at_five_thousand_until_asked_for_more(page: Page, activity_admin):
    """The server is stood in for here: 2,500 rows an answer, so the cap is reached in two reads."""
    step = 2500
    asked = []

    def serve(route):
        url = route.request.url
        if "ids=" in url or "count_only" in url or "after=" in url:
            return route.fulfill(json={"events": [], "count": 0, "more": False})
        cursor = re.search(r"[?&]cursor=m(\d+)", url)
        begin = int(cursor.group(1)) + 1 if cursor else 0
        asked.append(begin)
        events = [_event(i) for i in range(begin, begin + step)]
        return route.fulfill(json={"events": events, "next_cursor": events[-1]["cursor"], "total": 20000,
                                   "head_cursor": "m0"})

    page.route(re.compile(r"/activity/events\?"), serve)
    login(page, activity_admin)
    open_activity(page)
    _size(page, "all")
    expect(page.locator("#activity-summary")).to_have_text("2,500 of 20,000 loaded", timeout=10000)
    page.locator("#activity-rows tr.act-more.is-sentinel").scroll_into_view_if_needed()
    capped = page.locator("#activity-rows tr.act-more.is-capped")
    expect(capped).to_contain_text("5,000 events loaded. More would slow this page down: narrow the filters "
                                   "or export them.", timeout=15000)
    expect(page.locator("#activity-rows tr.act-more.is-sentinel")).to_have_count(0)
    reads = len(asked)
    page.wait_for_timeout(1000)
    assert len(asked) == reads                                               # it stopped reading
    capped.get_by_role("button", name="Load 1,000 more anyway").click()
    expect(page.locator("#activity-summary")).to_have_text("7,500 of 20,000 loaded", timeout=15000)
    expect(page.locator("#activity-rows tr.act-more.is-capped")).to_contain_text("7,500 events loaded.")


def test_the_keys_and_newer_older_move_across_a_page_edge(page: Page, activity_admin):
    login(page, activity_admin)
    open_activity(page)
    _size(page, "25")
    expect(page.locator("#activity-summary")).to_have_text(re.compile(r"^1–25 of"), timeout=10000)
    pos = page.locator("#act-detail .act-d-pos")
    rows(page).nth(24).click()
    expect(pos).to_have_text("25 of 25")

    page.keyboard.press("j")
    expect(page.locator("#activity-summary")).to_have_text(re.compile(r"^26–50 of"), timeout=10000)
    expect(pos).to_have_text("1 of 25")
    expect(rows(page).first).to_have_attribute("aria-current", "true")
    assert page.evaluate("() => !!document.activeElement.closest('#activity-rows')")    # the keys keep working
    page.keyboard.press("ArrowDown")
    expect(pos).to_have_text("2 of 25")
    page.keyboard.press("k")
    expect(pos).to_have_text("1 of 25")
    page.keyboard.press("ArrowUp")
    expect(page.locator("#activity-summary")).to_have_text(re.compile(r"^1–25 of"), timeout=10000)
    expect(pos).to_have_text("25 of 25")
    expect(page.locator("#act-detail")).to_be_visible()

    page.click("#act-detail .act-d-older")
    expect(page.locator("#activity-summary")).to_have_text(re.compile(r"^26–50 of"), timeout=10000)
    expect(pos).to_have_text("1 of 25")
    page.click("#act-detail .act-d-newer")
    expect(page.locator("#activity-summary")).to_have_text(re.compile(r"^1–25 of"), timeout=10000)
    expect(pos).to_have_text("25 of 25")
    page.click("#act-detail .act-d-newer")
    expect(pos).to_have_text("24 of 25")


def test_on_the_page_itself_the_keys_are_the_pages_own(page: Page, activity_admin):
    """A single-letter shortcut acts only with focus in the list, the band or the detail (WCAG 2.1.4);
    elsewhere the arrow keys scroll the page."""
    login(page, activity_admin)
    open_activity(page)
    first = rows(page).first
    first.click()
    page.keyboard.press("Escape")
    expect(page.locator("#act-detail")).to_be_hidden()
    expect(first).to_be_focused()                                  # focus went back to the row
    page.evaluate("() => document.activeElement.blur()")
    for key in ("j", "k", "/"):
        page.keyboard.press(key)
    expect(first).to_have_attribute("aria-current", "true")
    assert page.evaluate("() => document.activeElement === document.body")
    y = page.evaluate("() => scrollY")
    page.keyboard.press("ArrowDown")
    page.wait_for_function("y => scrollY > y", arg=y, timeout=5000)


def test_newer_and_older_work_on_an_event_opened_from_a_link(page: Page, admin, activity_admin):
    events = admin.get("/activity/events", params={"limit": 100}).json()["events"]
    assert len(events) == 100
    newer, target, older = events[69], events[70], events[71]
    login(page, activity_admin, path=f"/#activity?range=all&ev={target['id']}")
    expect(page.locator("#activity-section")).to_be_visible(timeout=10000)
    pane = page.locator("#act-detail")
    stored = pane.locator(".act-d-stored")
    expect(stored).to_contain_text(target["id"][:8], timeout=10000)
    expect(pane.locator(".act-d-pos")).to_have_text("Not in the list below")
    pane.locator(".act-d-older").click()
    expect(stored).to_contain_text(older["id"][:8])
    pane.locator(".act-d-newer").click()
    expect(stored).to_contain_text(target["id"][:8])
    pane.locator(".act-d-newer").click()
    expect(stored).to_contain_text(newer["id"][:8])
    expect(pane).to_be_visible()


def test_the_page_size_is_kept_after_signing_in_again(page: Page, activity_admin):
    login(page, activity_admin)
    open_activity(page)
    expect(page.locator("#act-page-size")).to_have_value("50")
    _size(page, "25")
    sign_out(page)                           # at once: the choice is saved as the page is left
    sign_in(page, activity_admin)
    open_activity(page)
    expect(page.locator("#act-page-size")).to_have_value("25")
    expect(page.locator("#activity-summary")).to_have_text(re.compile(r"^1–25 of"), timeout=10000)


def test_on_a_phone_the_detail_is_full_screen_with_newer_and_older(page: Page, activity_admin):
    login(page, activity_admin, width=390, height=844)
    open_activity(page)
    cards = page.locator("#activity-cards .act-card")
    expect(cards.first).to_be_visible()
    second = cards.nth(1).get_attribute("data-id")
    cards.first.click()
    dialog = page.locator("#activity-event-modal")
    expect(dialog).to_be_visible()
    page.wait_for_function("() => document.querySelector('#activity-event-modal .modal-content')"
                           ".getBoundingClientRect().top <= 1", timeout=5000)      # once the dialog has opened
    box = dialog.locator(".modal-content").bounding_box()
    assert box["x"] <= 1 and box["y"] <= 1 and box["width"] >= 388 and box["height"] >= 840, box
    where = dialog.locator(".act-sheet-pos")
    expect(where).to_have_text("1 of 50")
    expect(dialog.locator(".act-d-newer")).to_be_disabled()
    dialog.locator(".act-d-older").click()
    expect(where).to_have_text("2 of 50")
    page.go_back()                                                   # the phone's back gesture
    expect(dialog).to_be_hidden()
    shown = page.locator(f'#activity-cards .act-card[data-id="{second}"]')
    expect(shown).to_have_attribute("aria-current", "true")
    expect(shown).to_be_in_viewport()
    assert page.evaluate("() => location.hash").startswith("#activity")


def test_using_the_page_writes_nothing_to_the_log(page: Page, admin, anon, activity_admin):
    """Every read the page makes (the list, the band, Now, the typeaheads, an event by id, the counts)
    leaves the log as it was: a read that wrote a row would signal it, and the page would read again."""
    name = failed_sign_in(anon)
    login(page, activity_admin)
    page.wait_for_timeout(1000)                       # the sign-in's own rows are in before the mark
    newest = admin.get("/activity/events", params={"limit": 1}).json()["events"][0]["id"]
    open_activity(page)
    page.locator("#act-p-time .act-hit").last.click()
    page.locator("#act-p-cat .act-rank-row").first.click()
    page.click("#act-chips .act-clear-all")
    page.click("#act-range [data-range='30d']")
    ready(page)
    page.locator("#act-pager .act-pg-next").click()
    rows(page).first.click()
    page.click("#act-detail .act-d-older")
    page.click("#act-detail .act-d-close")
    page.locator("#act-p-now .act-now-row").first.click()
    page.keyboard.press("Escape")
    page.click("#act-filter-btn")
    with page.expect_response(lambda r: "/activity/usernames" in r.url):
        page.locator("#act-fp-user").press_sequentially(name[:4])
    with page.expect_response(lambda r: "/activity/temp-credentials" in r.url):
        page.locator("#act-fp-tc").press_sequentially("te")
    page.keyboard.press("Escape")
    if page.locator("#act-filter-panel").is_visible():
        page.keyboard.press("Escape")
    expect(page.locator("#act-filter-panel")).to_be_hidden()
    filter_by_person(page, name)
    page.click("#act-pause")
    page.click("#act-pause")
    page.wait_for_timeout(1500)
    written = admin.get("/activity/events", params={"after": newest, "user": activity_admin["_username"],
                                                    "user_match": "exact", "limit": 200}).json()["events"]
    assert [(e["action"], e["endpoint"]) for e in written] == []


@pytest.mark.parametrize("skin,height", [("v2", 32), ("v1", 38)])
def test_every_row_is_one_height_a_status_badge_included(page: Page, anon, activity_admin, skin, height):
    failed_sign_in(anon)                                    # a row with a status badge on the first page
    page.add_init_script(f"try {{ localStorage.setItem('ui', '{skin}'); }} catch (e) {{}}")
    login(page, activity_admin)
    open_activity(page)
    assert page.locator("#activity-rows tr.act-row .badge").count() >= 1
    heights = rows(page).evaluate_all("rs => rs.map((r) => Math.round(r.getBoundingClientRect().height))")
    assert set(heights) == {height}, heights


def test_the_list_stays_put_as_the_detail_opens(page: Page, activity_admin):
    """The row under the pointer does not move when its detail opens beside it."""
    login(page, activity_admin)
    open_activity(page)
    before = page.locator("#act-list").bounding_box()
    rows(page).nth(3).click()
    expect(page.locator("#act-detail")).to_be_visible()
    after = page.locator("#act-list").bounding_box()
    assert after["y"] == before["y"], (before, after)
    assert page.locator("#act-detail").bounding_box()["y"] == after["y"]


_PANEL_ON_SCREEN = """() => {
    const inner = document.querySelector('#act-detail .act-detail-inner');
    const bar = document.getElementById('act-toolbar').getBoundingClientRect();
    const r = inner.getBoundingClientRect();
    return {top: r.top, bottom: r.bottom, barBottom: bar.bottom, height: innerHeight,
            drawer: getComputedStyle(document.getElementById('act-detail')).position};
}"""


@pytest.mark.parametrize("skin,width,height", [("v2", 1024, 768), ("v1", 1280, 800)])
def test_the_tablet_drawer_stays_on_screen_as_the_list_scrolls(page: Page, activity_admin, skin, width, height):
    """Below a 980 px section the detail is a drawer over the list. Its panel stays under the toolbar and
    inside the window however far the list scrolls, so Newer and Older move through a pane in view."""
    page.add_init_script(f"try {{ localStorage.setItem('ui', '{skin}'); }} catch (e) {{}}")
    login(page, activity_admin, width=width, height=height)
    open_activity(page)
    _size(page, "100")
    expect(page.locator("#activity-summary")).to_have_text(re.compile(r"^1–"), timeout=10000)
    rows(page).nth(1).click()
    expect(page.locator("#act-detail .act-detail-inner")).to_be_visible()
    assert page.evaluate(_PANEL_ON_SCREEN)["drawer"] == "absolute", "not the tablet drawer at this width"
    room = page.evaluate("() => document.getElementById('act-list').getBoundingClientRect().bottom"
                         " + scrollY - innerHeight")
    assert room > 900, f"the list must be longer than the window by 900 px for this test ({room})"
    for dy in (600, min(1500, int(room) - 10)):
        page.evaluate(f"() => window.scrollTo(0, {dy})")
        page.wait_for_timeout(250)
        at = page.evaluate(_PANEL_ON_SCREEN)
        assert at["top"] >= at["barBottom"] - 1 and at["bottom"] <= at["height"] + 1, (dy, at)
    page.keyboard.press("j")
    expect(page.locator("#act-detail .act-d-pos")).to_have_text(re.compile(r"^3 of"))
    expect(page.locator("#act-detail .act-d-older")).to_be_in_viewport()
