"""What the Activity page draws after a sign-out, in a real browser (static/js/activity.js: get, resetActivity).

The answers to the reads made for the person who signed out are drawn for nobody: not the list, the summary or the
Now panel of the next person who signs in on the same tab. Here the first person's three reads are made, answered
by the server for them, and held on their way; they sign out, the next person signs in on the tab and opens the
page (its reads are answered and drawn), and the held answers then arrive. Their rows, top people and counts are
marked, so that one drawn would show. The page's own counters of those reads start again at each sign-out, so the
next person's first reads carry the same numbers as the first person's.

What the first person unlocked stays with them too: the vaults whose names they unlocked with the vault password
(a receipt each, kept for 15 minutes) are forgotten at their sign-out, so none of the next person's reads carries
one. And an export of the events on its way at the sign-out stops: one whose answer has not come yet is cancelled,
and one whose answer is being read never lands in the browser's downloads.

Waits are on state, never on time, but for the moments after which something must not happen.
"""
import uuid

import pytest
from playwright.sync_api import Page, expect

from _account_change_helpers import psql
from _activity_ui import login, open_activity, sign_in, sign_out
from _recording_levels import levels_restored, store, wait_for  # noqa: F401 -- a fixture
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


def test_the_vault_unlocks_of_the_person_who_signed_out_are_forgotten(page: Page, admin, admin_creds, two_admins,
                                                                      temp_vault_pw, levels_restored):
    """The stack's administrator unlocks a password vault's names on the page (the vault is theirs); another
    administrator signs in on the same tab and opens the page: none of their reads carries that receipt."""
    _ada, ben = two_admins
    store(dict(levels_restored, names="full"))
    name = f"ui-unlock-{uuid.uuid4().hex[:12]}.txt"
    up = admin.post(f"/vaults/{temp_vault_pw['id']}/files", files=[("files", (name, b"0123456789", "text/plain"))],
                    headers={"X-Vault-Password": temp_vault_pw["_password"]})
    assert up.status_code in (200, 201), up.text[:200]
    row_id = wait_for(lambda: psql("SELECT id FROM audit_logs WHERE details->>'vault_id' = '%s' AND resource_type = "
                                   "'file' AND recorded->'names'->'values' ? 'file_name' ORDER BY timestamp DESC "
                                   "LIMIT 1" % temp_vault_pw["id"]))
    page.set_viewport_size({"width": 1440, "height": 900})
    page.goto("/")
    sign_in(page, {"_username": admin_creds["username"], "_password": admin_creds["password"]})
    page.goto(f"/#activity?ev={row_id}")
    page.reload()
    detail = page.locator("#act-detail")
    form = detail.locator("form.act-unlock")
    expect(form).to_be_visible(timeout=15000)
    receipts = []
    page.on("request", lambda r: "/activity/" in r.url and receipts.append(r.headers.get("x-activity-unlock")))
    form.locator("input[type=password]").fill(temp_vault_pw["_password"])
    form.locator("button[type=submit]").click()
    expect(detail).to_contain_text(name, timeout=15000)
    assert any(receipts), "the receipt was not sent while its holder was signed in"

    page.evaluate("() => logout()")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    receipts.clear()
    sign_in(page, ben)
    open_activity(page)
    assert receipts, "the page read nothing"
    assert not any(receipts), "the next person's reads carry the receipt of the person who signed out"


# Marks, in the page, each export of the events (POST /activity/export) that is cancelled.
WATCH_CANCELS = """() => {
    window.__cancelled = [];
    const fetchOf = window.fetch;
    window.fetch = function (url, init) {
        const sent = fetchOf.apply(this, arguments);
        sent.catch((e) => { if (e && e.name === 'AbortError' && String(url).includes('/activity/export')) window.__cancelled.push(String(url)); });
        return sent;
    };
}"""

# Holds the page's read of an export's answer until window.__letRead() is called.
HOLD_READ = """() => {
    const read = Response.prototype.blob;
    Response.prototype.blob = function () {
        if (!String(this.url).includes('/activity/export')) return read.call(this);
        return new Promise((resolve, reject) => {
            window.__letRead = () => read.call(this).then(resolve, reject);
        });
    };
}"""


def _export(page: Page):
    page.click("#activity-export")
    page.click('[data-activity-export="csv"]')


def test_an_export_whose_answer_has_not_come_at_a_sign_out_is_cancelled(page: Page, two_admins):
    ada, _ben = two_admins
    held = []
    downloads = []
    page.on("download", lambda d: downloads.append(d))
    try:
        login(page, ada)
        open_activity(page)
        page.route(lambda url: url.endswith("/activity/export"), lambda route: held.append(route))
        page.evaluate(WATCH_CANCELS)
        _export(page)
        for _ in range(300):
            if held:
                break
            page.wait_for_timeout(50)
        assert len(held) == 1, "the export was not asked for"
        page.evaluate("() => logout()")
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        page.wait_for_function("() => window.__cancelled.length === 1", timeout=10000)
        page.wait_for_timeout(1000)
        assert downloads == []
        expect(page.locator("#toast-container .toast-error")).to_have_count(0)
    finally:
        for route in held:
            try:
                route.abort()
            except Exception:  # noqa: BLE001 -- already cancelled by the page
                pass


def test_an_export_being_read_at_a_sign_out_never_lands_in_the_downloads(page: Page, two_admins):
    ada, _ben = two_admins
    downloads = []
    page.on("download", lambda d: downloads.append(d))
    login(page, ada)
    open_activity(page)
    page.evaluate(HOLD_READ)
    _export(page)
    page.wait_for_function("() => typeof window.__letRead === 'function'", timeout=30000)
    page.evaluate("() => logout()")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.evaluate("() => window.__letRead()")
    page.wait_for_timeout(1500)                     # the moment in which the file would be handed over
    assert downloads == [], "the export landed in the downloads after the sign-out"
    expect(page.locator("#toast-container .toast-error")).to_have_count(0)
