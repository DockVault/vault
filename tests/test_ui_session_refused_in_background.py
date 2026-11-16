"""A background request refused for the session signs the tab out once, and the sign-in screen says why.

The warning checks with the server when its count reaches zero, but any request the page sends may be refused
first: a poll whose answer arrives in the second between the token's end and that check, or a request after the
session was ended elsewhere. Whichever refusal comes first signs the tab out, once (static/js/app.js apiRequest,
static/js/session-watch.js refusedSession), and the sign-in screen is never left without a reason: that the
session ran out when it was ending anyway, that it has ended for any other 401, the server's own sentence for a
403 that names the account. Nothing more is sent with the spent token, and a later refusal of the same session
changes nothing.
"""
import base64
import json
import time

import pytest
import requests
from playwright.sync_api import Page, expect

from conftest import BASE_URL
from _sf_helpers import put_settings_allowing_longer_sessions
from _ui_hand_over import HeldSignOut, mark_old, still_old, wait_replaced

pytestmark = pytest.mark.ui

RAN_OUT = "Your session ended because nobody chose to stay signed in"
ENDED = "Your session has ended. Sign in again."


@pytest.fixture
def person(admin):
    u = admin.create_user(role="user")
    yield u
    admin.delete_user(u["id"])


class _Sent:
    """The page's requests, with the moment each was sent and the bearer it carried."""

    def __init__(self, page: Page):
        self.rows = []
        page.on("request", lambda r: self.rows.append((time.time(), r.method, r.url.split("/", 3)[-1],
                                                        r.headers.get("authorization", ""))))

    def sign_outs(self):
        return [row for row in self.rows if row[1] == "POST" and row[2].startswith("auth/sign-out")]

    def with_token_after_sign_out(self, token):
        first = self.sign_outs()[0][0]
        return [row for row in self.rows if row[0] > first and row[3] == f"Bearer {token}"
                and not row[2].startswith("auth/sign-out")]


def _login(page: Page, user) -> str:
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", user["_username"])
    page.fill("#password", user["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    page.wait_for_load_state("networkidle", timeout=15000)
    # The page that shows the app: after the sign-out a new page is put in its place, which says why.
    mark_old(page)
    return page.evaluate("() => authToken")


def _end_on_the_server(token: str):
    r = requests.post(f"{BASE_URL}/auth/sign-out", headers={"Authorization": f"Bearer {token}"}, timeout=15)
    assert r.status_code in (200, 204), r.text
    assert requests.get(f"{BASE_URL}/users/me", headers={"Authorization": f"Bearer {token}"},
                        timeout=15).status_code == 401


def _poll(page: Page, token: str):
    """The unread-count poll, as its timer sends it (silent: it shows no error of its own), sent by the page that
    shows the app while it still holds `token`. Not waited for: a refusal signs the tab out on its way."""
    assert page.evaluate("(t) => window.__oldPage === true && !_pageEnded && authToken === t", token), \
        "the page was signed out, or holds another token, before the test's poll"
    page.evaluate("() => { refreshNotifUnread(); }")


def _signed_out_saying(page: Page, signing_out: HeldSignOut, sentence: str):
    """The page that sent the refused request, its sign-out held on its way: signed out, its token gone, the sign-in
    screen saying why."""
    signing_out.wait()
    assert still_old(page), "the page was replaced before its sign-out was answered"
    expect(page.locator("#login-screen")).to_be_visible(timeout=10000)
    note = page.locator("#login-error")
    expect(note).to_contain_text(sentence, timeout=5000)
    assert note.get_attribute("role") == "alert"
    assert page.evaluate("() => _pageEnded === true && authToken === null")


def _replaced_saying(page: Page, signing_out: HeldSignOut, sentence: str):
    """The sign-out let through: the page put in place of the one that showed the app says the same."""
    signing_out.release()
    wait_replaced(page)
    note = page.locator("#login-error")
    expect(note).to_contain_text(sentence, timeout=5000)
    assert note.get_attribute("role") == "alert"


def _hold_the_warnings_check(page: Page) -> list:
    held = []
    page.route("**/users/me", lambda route: held.append(route))
    return held


def _until_held(page: Page, held: list, seconds: float):
    deadline = time.time() + seconds
    while not held and time.time() < deadline:
        page.wait_for_timeout(100)
    assert len(held) == 1, "the warning did not ask the server at the end of its count"


def test_a_poll_refused_at_the_real_end_before_the_warnings_check_says_the_session_ran_out(
        page: Page, admin, admin_creds, person):
    # A session that really runs out: two minutes.
    before = admin.get("/settings").json().get("session_timeout") or 0
    assert admin.put("/settings", json={"session_timeout": 2}).status_code in (200, 204)
    try:
        token = _login(page, person)
    finally:
        restored = put_settings_allowing_longer_sessions(admin, admin_creds["password"], {"session_timeout": before})
        assert restored.status_code in (200, 204), restored.text
    sent = _Sent(page)
    # The page's own minute poll is stopped, so that the test's poll is the request refused first.
    page.evaluate("() => clearInterval(notifPollTimer)")
    part = token.split(".")[1]
    exp = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))["exp"]
    # The count on this device reaches zero (a second early at most): the warning asks the server, and that check
    # is held on its way while the token runs out.
    held = _hold_the_warnings_check(page)
    _until_held(page, held, 150)
    while time.time() < exp + 1:
        page.wait_for_timeout(200)
    # A poll's refusal of the token that ran out arrives first. The page's sign-out is held, so that the page
    # stays while the warning's own check comes back.
    signing_out = HeldSignOut(page)
    _poll(page, token)
    _signed_out_saying(page, signing_out, RAN_OUT)
    # The person starts to sign in again; then the warning's own check comes back refused too: on the same page,
    # it changes nothing, neither the reason nor what the person typed.
    page.fill("#username", "someone-else")
    held[0].continue_()
    page.unroute("**/users/me")
    page.wait_for_timeout(1500)
    assert still_old(page), "the page went: the check's refusal reached nothing to test"
    expect(page.locator("#login-error")).to_contain_text(RAN_OUT)
    assert page.input_value("#username") == "someone-else"
    assert page.evaluate("() => authToken") is None
    assert len(sent.sign_outs()) == 1, sent.sign_outs()
    assert sent.with_token_after_sign_out(token) == [], sent.with_token_after_sign_out(token)
    _replaced_saying(page, signing_out, RAN_OUT)


def test_a_session_ended_on_the_server_at_the_end_of_its_count_says_it_ended(page: Page, person):
    token = _login(page, person)
    sent = _Sent(page)
    held = _hold_the_warnings_check(page)
    # Ended on the server, and the count on this device reaches zero: the warning's check is held on its way.
    _end_on_the_server(token)
    page.evaluate("() => SessionWatch.armAt(Date.now() + 1000)")
    _until_held(page, held, 10)
    # A poll's refusal arrives first, saying the session was ended: not that it ran out. The warning's check then
    # comes back refused on the same page, its sign-out held: it signs nothing out again, so the reason stays and
    # what the person started to type is kept.
    signing_out = HeldSignOut(page)
    _poll(page, token)
    _signed_out_saying(page, signing_out, ENDED)
    page.fill("#username", "someone-else")
    held[0].continue_()
    page.unroute("**/users/me")
    page.wait_for_timeout(1500)
    assert still_old(page), "the page went: the check's refusal reached nothing to test"
    expect(page.locator("#login-error")).to_contain_text(ENDED)
    assert page.input_value("#username") == "someone-else"
    assert len(sent.sign_outs()) == 1, sent.sign_outs()
    _replaced_saying(page, signing_out, ENDED)


def test_a_session_ended_elsewhere_signs_out_saying_it_ended_not_that_it_ran_out(page: Page, person):
    token = _login(page, person)
    sent = _Sent(page)
    assert page.evaluate("() => SessionWatch.remaining()") > 600
    # Ended by the server long before its end (as an administrator, a password change or a revocation ends one).
    _end_on_the_server(token)
    signing_out = HeldSignOut(page)
    _poll(page, token)
    _signed_out_saying(page, signing_out, ENDED)
    note = page.locator("#login-error").inner_text()
    assert "nobody chose" not in note and "expired" not in note.lower(), note
    page.wait_for_timeout(1500)
    assert len(sent.sign_outs()) == 1, sent.sign_outs()
    assert sent.with_token_after_sign_out(token) == [], sent.with_token_after_sign_out(token)
    _replaced_saying(page, signing_out, ENDED)


def test_a_refusal_for_the_account_signs_out_with_the_servers_sentence(page: Page, person):
    token = _login(page, person)
    sent = _Sent(page)
    page.route("**/notifications/unread-count", lambda route: route.fulfill(
        status=403, content_type="application/json", body='{"detail": "User account is locked"}'))
    signing_out = HeldSignOut(page)
    _poll(page, token)
    _signed_out_saying(page, signing_out, "User account is locked")
    page.wait_for_timeout(1000)
    assert len(sent.sign_outs()) == 1, sent.sign_outs()
    _replaced_saying(page, signing_out, "User account is locked")
