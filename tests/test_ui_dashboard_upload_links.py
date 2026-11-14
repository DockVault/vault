"""What the dashboard asks about upload links (static/js/dashboard-actions.js, refreshReceiverAvailability in app.js).

The Needs-attention lane lists a person's upload links (files waiting, an expiry) whenever upload links are
switched on, whatever tags the person may make new links with now; switched off, it asks nothing about them. The
policy is asked once at a sign-in, however many parts of the page want it. What it said is the signed-in person's
own: the next person signed in on the same tab starts from nothing, not from the last person's answer.
"""
import json
import re
from urllib.parse import urlparse

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

_MB = 1024 * 1024


def _requests(page: Page, pattern: str) -> list:
    seen, wanted = [], re.compile(pattern)
    page.on("request", lambda req: seen.append(urlparse(req.url).path) if wanted.search(urlparse(req.url).path) else None)
    return seen


def _sign_in(page: Page, user):
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", user["_username"])
    page.fill("#password", user["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _lane_drawn(page: Page):
    expect(page.locator("#dashboard-lanes")).to_be_visible(timeout=15000)
    expect(page.locator("#lane-attention > *").first).to_be_attached(timeout=15000)


@pytest.fixture
def person(admin):
    u = admin.create_user(role="user")
    yield u
    admin.delete_user(u["id"])


@pytest.fixture
def links_setting(admin):
    before = admin.get("/settings").json().get("public_receivers_enabled")

    def put(on: bool):
        assert admin.put("/settings", json={"public_receivers_enabled": on}).status_code in (200, 204)
    yield put
    put(bool(before))


def test_switched_off_a_sign_in_asks_the_policy_once_and_no_link(page: Page, person, links_setting):
    links_setting(False)
    links = _requests(page, r"^/receivers(/|$)")
    policy = _requests(page, r"^/receiver-policy$")
    page.goto("/")
    _sign_in(page, person)
    _lane_drawn(page)
    page.wait_for_load_state("networkidle", timeout=15000)
    assert links == [], links
    assert policy == ["/receiver-policy"], policy


def test_switched_on_the_lane_asks_for_the_links_even_with_no_tag_to_make_one(page: Page, person, links_setting):
    links_setting(True)
    # This person may make no new link (no tag allows them), and may still have links of their own.
    page.route("**/receiver-policy", lambda route: route.fulfill(
        status=200, content_type="application/json",
        body=json.dumps({"enabled": True, "user_cap": 50, "remaining": 50, "tags": []})))
    links = _requests(page, r"^/receivers$")
    page.goto("/")
    _sign_in(page, person)
    _lane_drawn(page)
    page.wait_for_load_state("networkidle", timeout=15000)
    assert links == ["/receivers"], links
    expect(page.locator("#qa-upload-link")).to_have_count(0)
    expect(page.locator("#nav-uploadlinks")).to_be_hidden()


# A Get started list with every step still to do, whatever this deployment has done: drawn for an administrator.
_GET_STARTED = {"dismissed": False, "done": False, "items": {}}


def test_the_next_person_on_the_tab_does_not_start_from_the_last_ones_answer(page: Page, admin, person, links_setting):
    links_setting(True)
    tag = admin.post("/receiver-tags", json={
        "name": "DashTag-" + person["_username"][-8:], "min_token_len": 10, "max_file_bytes_cap": 100 * _MB,
        "max_total_bytes_cap": 500 * _MB, "auto_enroll_new_users": True, "is_active": True})
    assert tag.status_code in (200, 201), tag.text
    # The first person is an administrator, so the Get started list is drawn for them.
    first = admin.create_user(role="admin")
    other = admin.create_user(role="user")
    page.route("**/admin/get-started", lambda route: route.fulfill(
        status=200, content_type="application/json", body=json.dumps(_GET_STARTED))
        if route.request.method == "GET" else route.continue_())
    try:
        page.goto("/")
        _sign_in(page, first)
        expect(page.locator("#qa-upload-link")).to_be_visible(timeout=15000)
        expect(page.locator("#dashboard-get-started .get-started-list > *").first).to_be_visible(timeout=15000)
        page.evaluate("() => logout()")
        # The signed-out tab keeps nothing of what the dashboard drew for this person.
        for lane in ("#lane-attention", "#lane-recent", "#lane-waiting", "#lane-favourites"):
            expect(page.locator(f"{lane} > *")).to_have_count(0)
        expect(page.locator("#dashboard-quick-actions > *")).to_have_count(0)
        expect(page.locator("#dashboard-get-started .get-started-list > *")).to_have_count(0)
        # The next person's policy is on its way (held), and says that they may make no link.
        held = []
        page.route("**/receiver-policy", lambda route: held.append(route))
        _sign_in(page, other)
        deadline = 50
        while not held and deadline:
            page.wait_for_timeout(100)
            deadline -= 1
        assert held, "the next person's policy was not asked for"
        page.wait_for_timeout(1500)
        # Nothing of the last person's answer: no "New upload link" before this person's own answer.
        expect(page.locator("#qa-upload-link")).to_have_count(0)
        for route in held:
            route.fulfill(status=200, content_type="application/json",
                          body=json.dumps({"enabled": True, "user_cap": 50, "remaining": 50, "tags": []}))
        page.unroute("**/receiver-policy")
        _lane_drawn(page)
        expect(page.locator("#qa-upload-link")).to_have_count(0)
        expect(page.locator("#nav-uploadlinks")).to_be_hidden()
    finally:
        admin.delete_user(first["id"])
        admin.delete_user(other["id"])
        admin.delete(f"/receiver-tags/{tag.json()['id']}")


def test_a_renewal_while_the_policy_is_on_its_way_still_decides_the_upload_links_item(
        page: Page, admin, person, links_setting):
    links_setting(True)
    tag = admin.post("/receiver-tags", json={
        "name": "RenewTag-" + person["_username"][-8:], "min_token_len": 10, "max_file_bytes_cap": 100 * _MB,
        "max_total_bytes_cap": 500 * _MB, "auto_enroll_new_users": True, "is_active": True})
    assert tag.status_code in (200, 201), tag.text
    policy = _requests(page, r"^/receiver-policy$")
    held = []

    def hold_first(route):
        if held:
            route.continue_()
        else:
            held.append((route, route.fetch()))

    page.route("**/receiver-policy", hold_first)
    try:
        page.goto("/")
        _sign_in(page, person)
        for _ in range(150):
            if held:
                break
            page.wait_for_timeout(100)
        assert held, "the policy was not asked for"
        # The sign-in is renewed while the policy's answer is on its way: the tab holds another token when it comes.
        old = page.evaluate("() => authToken")
        page.evaluate("() => SessionWatch.armAt(Date.now() + 61000)")
        expect(page.locator("#session-expiry-modal.active")).to_be_visible(timeout=10000)
        page.click("#session-stay")
        page.wait_for_function("(t) => authToken && authToken !== t", arg=old, timeout=10000)
        route, response = held[0]
        route.fulfill(response=response)
        # Asked again for the session the tab holds now, and the item decided.
        expect(page.locator("#nav-uploadlinks")).to_be_visible(timeout=10000)
        assert len(policy) == 2, policy
    finally:
        page.unroute("**/receiver-policy")
        admin.delete(f"/receiver-tags/{tag.json()['id']}")
