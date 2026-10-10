"""UI — the Activity page's integrity strip (static/js/audit-integrity.js) takes one line, so the list still starts
near the top of a 1280 x 800 window: the status, the head shortened with its Copy, and Details, which holds the whole
head, the line to keep it somewhere else, the archive and what the chain proves. A failure is shown in full below
the line, never folded into Details. The page is served its own integrity status (the stack's chain may have sealed
nothing yet)."""
import json
import re

import pytest
from playwright.sync_api import Page, expect

from _activity_ui import activity_admin, login, open_activity, rows  # noqa: F401

pytestmark = pytest.mark.ui

HEAD = "dvchain1:42:" + "ab" * 32
STATUS = {"head": HEAD, "sealed_through": "2026-10-10T12:00:00Z", "key_id": "k1", "key_shared": True,
          "outcome": "clean", "checked_at": "2026-10-10T12:19:58Z", "failures": [], "warnings": [], "stopped": None,
          "claim": "Tamper-evident against changes made in the database without the server's key; not against the "
                   "server's operator.",
          "archive": {"hot_days": 90, "start_after_days": 14, "starts_on": "2026-10-24T12:00:00Z", "days": 0}}


def _serve(page: Page, status):
    page.route(re.compile(r"/activity/integrity$"), lambda route: route.fulfill(
        status=200, content_type="application/json", body=json.dumps(status)))


def _strip(page):
    return page.locator("#act-integrity")


def test_the_strip_takes_one_line_and_the_list_starts_near_the_top(page: Page, activity_admin):
    page.add_init_script("try { localStorage.setItem('ui', 'v1'); } catch (e) {}")
    _serve(page, STATUS)
    login(page, activity_admin, width=1280, height=800)
    open_activity(page)
    strip = _strip(page)
    expect(strip).to_be_visible()
    expect(strip.locator(".act-integrity-line strong")).to_have_text(re.compile(r"^The audit log is sealed through "))
    expect(strip.locator(".act-integrity-code")).to_have_attribute("title", HEAD)
    expect(strip.locator(".act-integrity-copy")).to_be_visible()
    box = strip.bounding_box()
    assert box["height"] <= 48, box                           # one line
    with_strip = rows(page).first.bounding_box()["y"]
    page.evaluate("() => { document.getElementById('act-integrity').hidden = true; }")
    without = rows(page).first.bounding_box()["y"]
    assert with_strip - without <= 60 and without < 450, (with_strip, without)


def test_details_hold_the_whole_head_and_what_the_chain_proves(page: Page, activity_admin):
    _serve(page, STATUS)
    login(page, activity_admin)
    open_activity(page)
    more = _strip(page).locator(".act-integrity-more")
    expect(more.locator(".act-integrity-full")).to_be_hidden()
    more.locator("summary").click()
    expect(more.locator(".act-integrity-full")).to_have_text("Head: " + HEAD)
    expect(more).to_contain_text("Keep this line somewhere else")
    expect(more).to_contain_text("Last checked")
    expect(more).to_contain_text("set AUDIT_CHAIN_KEY to give it a key of its own")
    expect(more.locator(".act-integrity-archive")).to_contain_text("audit days older than 90 days are kept compressed")
    expect(more).to_contain_text("not against the server's operator")


def test_a_failure_is_shown_in_full_outside_the_details(page: Page, activity_admin):
    failing = dict(STATUS, outcome="failed", failures=[{"kind": "rows-missing", "message": "3 rows of an hour are gone",
                                                        "first_seen": "2026-10-10T12:00:00Z", "last_seen": None}])
    _serve(page, failing)
    login(page, activity_admin)
    open_activity(page)
    strip = _strip(page)
    expect(strip).to_have_attribute("data-state", "failed")
    failure = strip.locator(":scope > .act-integrity-failure")
    expect(failure).to_be_visible()
    expect(failure).to_contain_text("rows-missing: 3 rows of an hour are gone")
    expect(strip.locator(".act-integrity-more[open]")).to_have_count(0)
