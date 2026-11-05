"""Signing out with many tabs of one session open leaves the sign-in that follows its rate limit, in a real browser,
at the auth requests' limit a vault ships with (static/js/app.js: logout, SIGN_OUT_TOLD; app/core/rate_limiter.py:
SIGN_OUT_BUCKET).

A sign-out in one tab tells every other tab holding the same session, and they sign out at once. The person then
signs in again, from the same address, a moment later; the sign-in is in the auth requests' class, counted by
address, ten a minute as shipped. So the told tabs send nothing of their own: no second sign-out (the first tab's
ended the session) and no request for the sign-in screen's policy (sent without a token, so counted by address),
which they ask for when they are next shown instead. Held for the sign-out button and for a session that has run
out, with eleven tabs: one sign-out is sent, the session is ended, at most one request for the policy, and the
sign-in right after is let in.

The tabs' own timers (the notifications' unread count, once a minute) are stopped while this runs: a tab whose own
request meets the ended session signs out by itself, as it should, and that is not what is counted here.
"""
import time

import pytest
from playwright.sync_api import Page, expect

from _sign_out_helpers import expired_copy, session_row, shipped_auth_limit
from _ui_hand_over import sign_in_on_the_tab

pytestmark = pytest.mark.ui

TABS = 11


@pytest.fixture
def ana(admin):
    user = admin.create_user()
    yield user
    admin.delete_user(user["id"])


def _tabs_of_one_session(page: Page, account):
    """`page` signed in, and TABS - 1 more tabs opened after it, which take its stored session."""
    sign_in_on_the_tab(page, account)
    token = page.evaluate("() => authToken")
    tabs = [page]
    for _ in range(TABS - 1):
        tab = page.context.new_page()
        tab.goto("/")
        expect(tab.locator("#dashboard-screen")).to_be_visible(timeout=30000)
        tabs.append(tab)
    assert [t.evaluate("() => authToken") for t in tabs] == [token] * TABS
    for t in tabs:
        t.evaluate("() => { clearInterval(notifPollTimer); }")
    return tabs, token


def _auth_requests(page: Page):
    """The sign-outs and the requests for the sign-in screen's policy every tab sends from now on."""
    seen = {"sign-out": [], "policy": []}

    def note(r):
        if r.method == "POST" and r.url.endswith("/auth/sign-out"):
            seen["sign-out"].append(r)
        elif r.method == "GET" and r.url.endswith("/auth/policy"):
            seen["policy"].append(r)

    page.context.on("request", note)
    return seen


def _all_signed_out(tabs):
    for t in tabs:
        expect(t.locator("#login-screen")).to_be_visible(timeout=15000)
    assert [t.evaluate("() => authToken") for t in tabs] == [None] * TABS


def _ended(token, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if session_row(token) == "f|t":
            return
        time.sleep(0.2)
    raise AssertionError(f"the session was not ended on the server: {session_row(token)}")


def _sign_in_again(page: Page, account):
    """The person signs in again on the first tab at once; the sign-in's answer."""
    page.fill("#username", account["_username"])
    page.fill("#password", account["_password"])
    with page.expect_response(lambda r: r.request.method == "POST" and r.url.endswith("/auth/login"),
                              timeout=15000) as login:
        page.click("#login-form button[type=submit]")
    return login.value


def test_the_sign_out_button_with_many_tabs_open_leaves_the_sign_in_that_follows_its_budget(
        page: Page, admin, ana):
    tabs, token = _tabs_of_one_session(page, ana)
    with shipped_auth_limit(admin) as limit:
        seen = _auth_requests(page)
        page.click("#profile-btn")
        page.click("#dropdown-logout-btn")
        _all_signed_out(tabs)
        _ended(token)
        page.wait_for_timeout(1000)               # a moment in which a told tab's own request would come
        sign_outs, policies = list(seen["sign-out"]), list(seen["policy"])
        login = _sign_in_again(page, ana)
        assert login.headers.get("x-ratelimit-limit") == str(limit), "the shipped limit was not the one in force"
        assert login.status == 200, f"the sign-in after the sign-out was refused: {login.status} {login.text()[:160]}"
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        assert len(sign_outs) == 1, f"{len(sign_outs)} sign-outs sent for one session"
        assert sign_outs[0].headers.get("authorization") == f"Bearer {token}"
        assert len(policies) <= 1, f"the sign-in screen's policy was asked for {len(policies)} times"


def test_a_session_that_runs_out_in_many_tabs_leaves_the_sign_in_that_follows_its_budget(page: Page, admin, ana):
    tabs, token = _tabs_of_one_session(page, ana)
    expired = expired_copy(token)
    with shipped_auth_limit(admin) as limit:
        seen = _auth_requests(page)
        for t in tabs:                            # the session's token runs out in every tab
            t.evaluate("(x) => { authToken = x; }", expired)
        # The first tab's next request is refused: it signs out, and tells the others.
        page.evaluate("() => { apiRequest('/users/me').catch(() => {}); }")
        _all_signed_out(tabs)
        _ended(token)
        page.wait_for_timeout(1000)
        sign_outs, policies = list(seen["sign-out"]), list(seen["policy"])
        login = _sign_in_again(page, ana)
        assert login.headers.get("x-ratelimit-limit") == str(limit), "the shipped limit was not the one in force"
        assert login.status == 200, f"the sign-in after the expiry was refused: {login.status} {login.text()[:160]}"
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        assert len(sign_outs) == 1, f"{len(sign_outs)} sign-outs sent for one session"
        assert sign_outs[0].headers.get("authorization") == f"Bearer {expired}"
        assert len(policies) <= 1, f"the sign-in screen's policy was asked for {len(policies)} times"
