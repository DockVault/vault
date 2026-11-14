"""A background request refused for the session signs the tab out once, and the sign-in screen says why.

The warning checks with the server when its count reaches zero, but any request the page sends may be refused
first: a poll whose answer arrives in the second between the token's end and that check, or a request after the
session was ended elsewhere. Whichever refusal comes first signs the tab out, once (static/js/app.js apiRequest,
static/js/session-watch.js refusedSession), and the sign-in screen is never left without a reason: that the
session ran out when it was ending anyway, that it has ended for any other 401, the server's own sentence for a
403 that names the account. Nothing more is sent with the spent token, and a later refusal of the same session
changes nothing.
"""
import time

import pytest
import requests
from playwright.sync_api import Page, expect

from conftest import BASE_URL

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
    return page.evaluate("() => authToken")


def _end_on_the_server(token: str):
    r = requests.post(f"{BASE_URL}/auth/sign-out", headers={"Authorization": f"Bearer {token}"}, timeout=15)
    assert r.status_code in (200, 204), r.text
    assert requests.get(f"{BASE_URL}/users/me", headers={"Authorization": f"Bearer {token}"},
                        timeout=15).status_code == 401


def _poll(page: Page):
    """The unread-count poll, as its timer sends it (silent: it shows no error of its own)."""
    page.evaluate("() => refreshNotifUnread()")


def _signed_out_saying(page: Page, sentence: str):
    expect(page.locator("#login-screen")).to_be_visible(timeout=10000)
    note = page.locator("#login-error")
    expect(note).to_contain_text(sentence, timeout=5000)
    assert note.get_attribute("role") == "alert"
    assert page.evaluate("() => authToken") is None


def test_a_poll_refused_before_the_warnings_own_check_signs_out_saying_the_session_ran_out(page: Page, person):
    token = _login(page, person)
    sent = _Sent(page)
    held = []
    page.route("**/users/me", lambda route: held.append(route))
    # The session is over on the server, and the count on this device reaches zero: the warning asks the
    # server, and that check is held on its way.
    _end_on_the_server(token)
    page.evaluate("() => SessionWatch.armAt(Date.now() + 1000)")
    deadline = time.time() + 10
    while not held and time.time() < deadline:
        page.wait_for_timeout(100)
    assert len(held) == 1, "the warning did not ask the server at the end of its count"
    # A poll's refusal arrives first.
    _poll(page)
    _signed_out_saying(page, RAN_OUT)
    # Then the warning's own check comes back refused too: it changes nothing.
    held[0].continue_()
    page.unroute("**/users/me")
    page.wait_for_timeout(1500)
    expect(page.locator("#login-error")).to_contain_text(RAN_OUT)
    assert len(sent.sign_outs()) == 1, sent.sign_outs()
    assert sent.with_token_after_sign_out(token) == [], sent.with_token_after_sign_out(token)


def test_a_session_ended_elsewhere_signs_out_saying_it_ended_not_that_it_ran_out(page: Page, person):
    token = _login(page, person)
    sent = _Sent(page)
    assert page.evaluate("() => SessionWatch.remaining()") > 600
    # Ended by the server long before its end (as an administrator, a password change or a revocation ends one).
    _end_on_the_server(token)
    _poll(page)
    _signed_out_saying(page, ENDED)
    note = page.locator("#login-error").inner_text()
    assert "nobody chose" not in note and "expired" not in note.lower(), note
    page.wait_for_timeout(1500)
    assert len(sent.sign_outs()) == 1, sent.sign_outs()
    assert sent.with_token_after_sign_out(token) == [], sent.with_token_after_sign_out(token)


def test_a_refusal_for_the_account_signs_out_with_the_servers_sentence(page: Page, person):
    _login(page, person)
    sent = _Sent(page)
    page.route("**/notifications/unread-count", lambda route: route.fulfill(
        status=403, content_type="application/json", body='{"detail": "User account is locked"}'))
    _poll(page)
    _signed_out_saying(page, "User account is locked")
    page.wait_for_timeout(1000)
    assert len(sent.sign_outs()) == 1, sent.sign_outs()
