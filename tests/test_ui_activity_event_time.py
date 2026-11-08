"""UI: the Activity page carries an event's time with its id wherever it hands the event on, so that an event of a day
the archive keeps (no row of the audit log any more) can be found again in the hour that time names:

- the details' "Copy link to this event" and, on a phone, the sheet's menu item copy a link with the event's time;
- a link opened on the page's first visit, and on coming back to the page, reads the event with the link's time.

The server's side is in test_activity_archived_event.py; the helpers that build the link and read it back in
test_activity_page_helpers.py.
"""
from datetime import datetime, timedelta, timezone
import uuid
from urllib.parse import parse_qs, quote, urlsplit

import pytest
from playwright.sync_api import Page, expect

from _activity_ui import activity_admin, failed_sign_in, login, open_activity  # noqa: F401

pytestmark = pytest.mark.ui

# Every text the page copies, whichever way it copies it (the clipboard, or the copy command on a hidden field).
_WATCH_COPIES = """
window.__copied = [];
try {
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: {
        writeText: (t) => { window.__copied.push(t); return Promise.resolve(); } } });
} catch (e) { /* the copy command below catches it then */ }
const __exec = document.execCommand.bind(document);
document.execCommand = function (cmd) {
    if (cmd === 'copy') {
        const field = document.querySelector('.act-copy-buffer');
        if (field) window.__copied.push(field.value);
        return true;
    }
    return __exec.apply(document, arguments);
};
"""


def _event_of(admin, name):
    """The newest event of the person ``name``, as the Events list gives it (its id and its time)."""
    events = admin.get("/activity/events", params={"user": name, "limit": 5}).json()["events"]
    assert events, f"no event of {name}"
    return events[0]


def _copied_link(page: Page) -> dict:
    page.wait_for_function("() => window.__copied.length === 1", timeout=10000)
    link = page.evaluate("() => window.__copied[0]")
    fragment = urlsplit(link).fragment
    assert fragment.startswith("activity?"), link
    return {k: v[0] for k, v in parse_qs(fragment.split("?", 1)[1]).items()}


def test_the_details_copy_a_link_with_the_event_s_time(page: Page, anon, admin, activity_admin):
    name = failed_sign_in(anon)
    ev = _event_of(admin, name)
    page.add_init_script(_WATCH_COPIES)
    login(page, activity_admin, path=f"/#activity?range=24h&user={quote(name)}")
    row = page.locator(f'#activity-rows tr.act-row[data-id="{ev["id"]}"]')
    expect(row).to_be_visible(timeout=15000)
    row.click()
    pane = page.locator("#act-detail")
    expect(pane.locator(".act-d-stored")).to_contain_text(ev["id"][:8], timeout=10000)
    pane.locator('button[aria-label="Copy link to this event"]').click()
    link = _copied_link(page)
    assert link["ev"] == ev["id"] and link["at"] == ev["timestamp"], link


def test_on_a_phone_the_sheet_s_menu_copies_a_link_with_the_event_s_time(page: Page, anon, admin, activity_admin):
    name = failed_sign_in(anon)
    ev = _event_of(admin, name)
    page.add_init_script(_WATCH_COPIES)
    login(page, activity_admin, width=390, height=844, path=f"/#activity?range=24h&user={quote(name)}")
    card = page.locator(f'#activity-cards .act-card[data-id="{ev["id"]}"]')
    expect(card).to_be_visible(timeout=15000)
    card.click()
    dialog = page.locator("#activity-event-modal")
    expect(dialog).to_be_visible()
    dialog.locator(".act-sheet-more").click()
    dialog.get_by_role("menuitem", name="Copy link to this event").click()
    link = _copied_link(page)
    assert link["ev"] == ev["id"] and link["at"] == ev["timestamp"], link


def _a_time():
    """A time an hour ago, as the page carries an event's (ISO, in UTC, with microseconds)."""
    return (datetime.now(timezone.utc) - timedelta(hours=1)).replace(microsecond=654321).isoformat()


def _read_of(event_id: str):
    return lambda r: f"/activity/events/{event_id}" in r.url and not r.url.endswith("/reveal")


def test_a_link_opened_on_the_page_s_first_visit_reads_the_event_with_its_time(page: Page, activity_admin):
    """An event the list does not show (no row of the log: one of an archived day) is read on its own: with the
    link's time, the hour the server looks for it in."""
    linked, when = str(uuid.uuid4()), _a_time()
    with page.expect_request(_read_of(linked), timeout=20000) as asked:
        login(page, activity_admin, path=f"/#activity?range=7d&ev={linked}&at={quote(when, safe='')}")
    query = parse_qs(urlsplit(asked.value.url).query)
    assert query.get("at") == [when], asked.value.url


def test_a_link_opened_on_coming_back_to_the_page_reads_the_event_with_its_time(page: Page, activity_admin):
    login(page, activity_admin)
    open_activity(page)
    page.click('.sidebar-item[data-section="vaults"]')
    expect(page.locator("#activity-section")).to_be_hidden(timeout=10000)
    linked, when = str(uuid.uuid4()), _a_time()
    page.evaluate("(h) => history.replaceState(null, '', location.pathname + location.search + h)",
                  f"#activity?range=7d&ev={linked}&at={quote(when, safe='')}")
    with page.expect_request(_read_of(linked), timeout=20000) as asked:
        page.click('.sidebar-item[data-section="activity"]')
    query = parse_qs(urlsplit(asked.value.url).query)
    assert query.get("at") == [when], asked.value.url
