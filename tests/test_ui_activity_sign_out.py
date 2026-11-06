"""What the Activity page draws after a sign-out, in a real browser (static/js/activity.js: get, resetActivity).

The answers to the reads made for the person who signed out are drawn for nobody: not the list, the summary or the
Now panel of the next person who signs in on the same tab. Here the first person's three reads are made, answered
by the server for them, and held on their way; they sign out, the next person signs in on the tab and opens the
page (its reads are answered and drawn), and the held answers then arrive. Their rows, top people and counts are
marked, so that one drawn would show. The page's own counters of those reads start again at each sign-out, so the
next person's first reads carry the same numbers as the first person's.

Waits are on state, never on time, but for the moment after the held answers arrive in which something must not
be drawn.
"""
import pytest
from playwright.sync_api import Page, expect

from _activity_ui import login, open_activity, sign_in, sign_out
from conftest import unique

pytestmark = pytest.mark.ui

COUNT = 424242
DRAWN_COUNT = "424,242"


@pytest.fixture
def two_admins(admin):
    ada = admin.create_user(role="admin")
    ben = admin.create_user(role="admin")
    yield ada, ben
    admin.delete_user(ada["id"])
    admin.delete_user(ben["id"])


def _marked(path, body, marker):
    """The answer the server gave the first person, marked: every row's person, every top person, every count."""
    if "/activity/events" in path:
        assert body.get("events"), "the list held no row to mark"
        for row in body["events"]:
            row["username"] = marker
    elif "/activity/summary" in path:
        assert body.get("top_users"), "the summary held no top person to mark"
        for i, row in enumerate(body["top_users"]):
            row["username"] = f"{marker}-{i}"
    elif "/activity/now" in path:
        for key in ("sessions", "people", "temporary_credentials"):
            body[key] = COUNT
    return body


def test_answers_for_the_person_who_signed_out_are_drawn_for_nobody(page: Page, two_admins):
    ada, ben = two_admins
    marker = unique("left-signed-out")
    errors = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    held, holding = [], {"on": True}

    def hold(route):
        if not holding["on"]:
            route.continue_()
            return
        held.append((route, route.fetch()))

    page.route(lambda url: "/activity/events?" in url or "/activity/summary?" in url
               or url.endswith("/activity/now"), hold)
    login(page, ada)
    page.click('.sidebar-item[data-section="activity"]')
    expect(page.locator("#activity-section")).to_be_visible(timeout=10000)
    for _ in range(300):
        if len(held) >= 3:
            break
        page.wait_for_timeout(50)
    kinds = sorted(r.request.url.split("/activity/")[1].split("?")[0] for r, _a in held)
    assert kinds == ["events", "now", "summary"], kinds
    sign_out(page)

    holding["on"] = False
    sign_in(page, ben)
    open_activity(page)
    finished = []
    page.on("requestfinished", lambda r: "/activity/" in r.url and finished.append(r.url))
    for route, answer in held:
        route.fulfill(response=answer, json=_marked(route.request.url, answer.json(), marker))
    for _ in range(300):
        if sum(1 for u in finished if any(u == r.request.url for r, _a in held)) >= len(held):
            break
        page.wait_for_timeout(50)
    # The page has had the answers; a request of its own, sent and answered after them, then a few turns of its
    # event loop, so that whatever it does with them is done.
    page.evaluate("() => fetch('/health').then((r) => r.text())")
    page.evaluate("() => new Promise((done) => setTimeout(() => setTimeout(done, 0), 0))")
    page.wait_for_timeout(500)
    text = page.locator("#activity-section").inner_text()
    assert marker not in text, "an answer for the person who signed out was drawn for the next person"
    assert marker not in page.content()
    assert DRAWN_COUNT not in text and str(COUNT) not in text, "a count for the person who signed out was drawn"
    assert errors == []
