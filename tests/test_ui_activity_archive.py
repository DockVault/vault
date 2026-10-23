"""UI — the Activity page says what it reads of archived days (static/js/activity-archive.js).

The stack's own log has no archived day (archiving starts after a grace period, and only on days older than
the row window), so the page is served its own responses with an `archive` note added: a list that read rows
only says where the archive is and how to search it; one that searched it says how many archived days it read
and names a day it could not read, as a warning; the band says which panels count archived days and which count
rows only. A refused range shows the server's reason. No console error; the notes fit a phone's width.
"""
import json
import re

import pytest
from playwright.sync_api import Page, expect

from _activity_ui import activity_admin, login, open_activity  # noqa: F401

pytestmark = pytest.mark.ui

ROWS_ONLY = {"oldest_day": "2026-06-01", "newest_day": "2026-07-12", "days": 42, "searched": False,
             "unreadable": [], "max_days": 31}
SEARCHED = dict(ROWS_ONLY, searched=True, searched_days=3,
                unreadable=[{"day": "2026-07-02", "reason": "block-altered"}])
BAND = {"oldest_day": "2026-06-01", "newest_day": "2026-07-12", "days": 42,
        "counted": ["events", "categories", "sign_ins"], "rows_only": ["people", "addresses"], "unreadable": []}


def _serve(page: Page, path_re, note):
    def handle(route):
        response = route.fetch()
        data = response.json()
        if isinstance(data, dict) and "count" not in data:
            data["archive"] = note
        route.fulfill(response=response, body=json.dumps(data))
    page.route(re.compile(path_re), handle)


def _list(page):
    return page.locator("#act-archive-list")


def _band(page):
    return page.locator("#act-archive-band")


def test_the_list_and_the_band_say_what_they_read_of_the_archive(page: Page, activity_admin):
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    login(page, activity_admin)
    _serve(page, r"/activity/events(\?|/search)", ROWS_ONLY)
    _serve(page, r"/activity/summary(\?|/search)", BAND)
    open_activity(page)
    expect(_list(page)).to_be_visible()
    expect(_list(page)).to_have_text(
        "Days up to 2026-07-12 are archived and not in this list. To search them, choose a time range that starts "
        "on or before 2026-07-12: at most 31 archived days at a time.")
    expect(_list(page)).not_to_have_class(re.compile(r"text-warning"))
    expect(_band(page)).to_have_text(
        "Days up to 2026-07-12 are archived: the chart, the categories and the sign-ins count them from the "
        "archive's summaries; the most active people and the most active addresses count the days still kept as "
        "rows only.")
    assert not errors, errors


def test_a_searched_list_names_the_day_it_could_not_read_as_a_warning(page: Page, activity_admin):
    login(page, activity_admin)
    _serve(page, r"/activity/events(\?|/search)", SEARCHED)
    _serve(page, r"/activity/summary(\?|/search)", dict(BAND, counted=[], rows_only=["events", "categories",
                                                                                      "sign_ins", "people",
                                                                                      "addresses"]))
    open_activity(page)
    expect(_list(page)).to_contain_text("This list includes 3 archived days, read from the archive.")
    expect(_list(page)).to_contain_text("2026-07-02 (block-altered)")
    expect(_list(page)).to_have_class(re.compile(r"text-warning"))
    expect(_band(page)).to_contain_text("these filters need the events themselves")


def test_no_note_without_an_archive_and_a_refused_range_shows_why(page: Page, activity_admin):
    login(page, activity_admin)
    open_activity(page)
    expect(_list(page)).to_be_hidden()
    expect(_band(page)).to_be_hidden()

    def refuse(route):
        route.fulfill(status=400, content_type="application/json", body=json.dumps(
            {"detail": "This range reaches 40 archived days; a search reads at most 31 at a time. "
                       "Choose a shorter range."}))
    page.route(re.compile(r"/activity/events(\?|/search)"), refuse)
    page.fill("#act-search", "archived-range")
    expect(page.locator("#act-list-alert")).to_contain_text("a search reads at most 31 at a time", timeout=10000)
    expect(_list(page)).to_be_hidden()


def test_the_notes_fit_a_phone(page: Page, activity_admin):
    login(page, activity_admin, width=375, height=800)
    _serve(page, r"/activity/events(\?|/search)", SEARCHED)
    _serve(page, r"/activity/summary(\?|/search)", BAND)
    open_activity(page)
    expect(_list(page)).to_be_visible()
    for box in (_list(page), _band(page)):
        width = box.evaluate("e => e.getBoundingClientRect().right")
        assert width <= 375, width
    assert page.evaluate("document.documentElement.scrollWidth") <= 375
