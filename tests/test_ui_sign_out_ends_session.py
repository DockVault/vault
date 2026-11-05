"""Every way the web app signs out ends the session on the server, in a real browser (static/js/app.js:
logout, _endServerSession).

Every sign-out goes through logout(), which signs the page out at once and asks the server to end the session it
held (POST /auth/sign-out, which answers without Clear-Site-Data). Held here, path by path, each time by reading
the token back from the server afterwards:

- the sign-out button, through the profile menu: the call carries the tab's token, and the token is refused from
  then on, while the look stored in this browser stays (the answer itself, without Clear-Site-Data, is held by
  tests/test_api_sign_out.py: the browser does not hand a kept-alive request's answer to a test);
- a refusal of the session the tab holds (a 401): the page signs out, and the session, still live on the server,
  is ended;
- a session that has run out: its expired token's refusal signs the page out, and the session's row is ended too;
- a sign-out after a two-factor sign-in;
- a sign-out in another tab: a tab holding the same token signs out at once (told by the other tab, not by a
  refusal), sends nothing of its own, asks for the sign-in screen's policy only when it is next shown (once), and
  leaves a session stored since by another tab (and the uploads saved since), while a tab of another account stays
  signed in; the tab the person signs out in asks for that policy at once;
- the sign-in check of a tab being loaded: a refusal of the session (a 401, an account's 403) ends the session and
  signs out the other tabs; a check that could not be answered (a server error, a proxy's 502 or 503 while the
  vault restarts, a proxy's own 403 page, a rate limit, no answer at all) signs out that tab alone, as it always
  did, and the session and the other tabs using it go on;
- no answer from the server (offline): the page is signed out all the same;
- a preference saved at the sign-out is sent before the session is ended, so it is not refused; a save that does
  not come back holds the sign-out for at most three seconds.

The idle lock of zero-knowledge keys does not sign out (it forgets the keys only), so it has no call to make.
Waits are on state, never on time, but for the bound on the held save and the moments in which something must
not happen.
"""
import json
import time

import pytest
import requests
from playwright.sync_api import Page, expect

from _account_change_helpers import signed_in
from _sf_helpers import enroll_totp
from _sign_out_helpers import expired_copy, session_row
from _ui_hand_over import sign_in_on_the_tab, sign_out
from conftest import BASE_URL

pytestmark = pytest.mark.ui

SIGN_OUT = "/auth/sign-out"


def _is_sign_out(request):
    return request.method == "POST" and request.url.endswith(SIGN_OUT)


def _refused(token):
    return requests.get(f"{BASE_URL}/users/me", headers={"Authorization": f"Bearer {token}"}, timeout=30).status_code


@pytest.fixture
def ana(admin):
    user = admin.create_user()
    yield user
    admin.delete_user(user["id"])


def _ended(token, seconds=15):
    """Wait until the server shows the session `token` names ended (its row inactive and revoked)."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if session_row(token) == "f|t":
            return
        time.sleep(0.2)
    raise AssertionError(f"the session was not ended on the server: {session_row(token)}")


def _signed_out_by(page: Page, action, token, session_of=None):
    """Run `action` (which signs the page out); the page sends the sign-out with `token`, is signed out at once,
    and the server ends the session (of `session_of`, `token` by default). What the call did is read back from the
    server, not from its answer: the request is kept alive, and the browser does not hand the answer of a kept-alive
    request to the test (tests/test_api_sign_out.py holds the answer itself)."""
    with page.expect_request(_is_sign_out, timeout=15000) as sent:
        action()
    assert sent.value.headers.get("authorization") == f"Bearer {token}"
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    assert page.evaluate("() => authToken") is None
    _ended(session_of or token)


def test_the_sign_out_button_ends_the_session_and_keeps_the_stored_look(page: Page, ana):
    sign_in_on_the_tab(page, ana)
    page.evaluate("() => { localStorage.setItem('theme', 'dark'); localStorage.setItem('accent', 'teal'); }")
    token = page.evaluate("() => authToken")
    assert _refused(token) == 200

    def button():
        page.click("#profile-btn")
        page.click("#dropdown-logout-btn")

    _signed_out_by(page, button, token)
    assert _refused(token) == 401
    assert session_row(token) == "f|t"
    assert page.evaluate("() => [localStorage.getItem('theme'), localStorage.getItem('accent')]") == ["dark", "teal"]
    assert page.evaluate("() => localStorage.getItem('authToken') || sessionStorage.getItem('authToken')") is None


def test_a_refusal_of_the_session_signs_out_and_ends_it_on_the_server(page: Page, ana):
    sign_in_on_the_tab(page, ana)
    token = page.evaluate("() => authToken")
    # A refusal of the tab's own session (a proxy's, say), while the session is still live on the server.
    page.route("**/sign-out-probe", lambda route: route.fulfill(
        status=401, content_type="application/json", body='{"detail": "Could not validate credentials"}'))
    _signed_out_by(page, lambda: page.evaluate("() => { apiRequest('/sign-out-probe').catch(() => {}); }"), token)
    assert _refused(token) == 401 and session_row(token) == "f|t"


def test_a_session_that_has_run_out_is_ended_at_its_sign_out(page: Page, ana):
    sign_in_on_the_tab(page, ana)
    token = page.evaluate("() => authToken")
    expired = expired_copy(token)
    assert _refused(expired) == 401 and session_row(token) == "t|f"
    page.evaluate("(t) => { authToken = t; }", expired)       # the tab's token runs out
    _signed_out_by(page, lambda: page.evaluate("() => { apiRequest('/users/me').catch(() => {}); }"), expired)
    assert session_row(token) == "f|t"
    assert _refused(token) == 401, "the session's unexpired token still works"


def test_a_sign_out_after_a_two_factor_sign_in_ends_that_session(page: Page, admin):
    eve = admin.create_user()
    try:
        _secret, codes = enroll_totp(eve, signed_in(eve))
        page.goto("/")
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        page.fill("#username", eve["_username"])
        page.fill("#password", eve["_password"])
        page.click("#login-form button[type=submit]")
        card = page.locator("#login-second-factor")
        expect(card).to_be_visible(timeout=15000)
        card.get_by_role("button", name="Use a recovery code instead").click()
        page.fill("#sf-code-input", codes.pop(0))
        card.locator("button").last.click()
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        token = page.evaluate("() => authToken")
        assert _refused(token) == 200
        _signed_out_by(page, lambda: sign_out(page), token)
        assert _refused(token) == 401 and session_row(token) == "f|t"
    finally:
        admin.delete_user(eve["id"])


def test_a_sign_out_in_another_tab_signs_out_the_tabs_of_that_session_only(page: Page, admin, ana):
    ben = admin.create_user()
    try:
        sign_in_on_the_tab(page, ana)
        token = page.evaluate("() => authToken")
        context = page.context
        same = context.new_page()                    # opened after: it takes the stored session, ana's
        same.goto("/")
        expect(same.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        assert same.evaluate("() => authToken") == token
        # ben signs in on a third tab, which finds no stored session when it loads (the other two keep theirs).
        other = context.new_page()
        other.add_init_script("localStorage.removeItem('authToken'); sessionStorage.removeItem('authToken');")
        sign_in_on_the_tab(other, ben)
        ben_token = other.evaluate("() => authToken")
        assert ben_token != token
        sent = []
        context.on("request", lambda r: _is_sign_out(r) and sent.append(r))

        _signed_out_by(page, lambda: sign_out(page), token)
        # The tab holding the same token signs out at once, told so by the first tab rather than by a refusal of
        # its next request, and says why.
        expect(same.locator("#login-screen")).to_be_visible(timeout=5000)
        assert same.evaluate("() => authToken") is None
        expect(same.locator("#toast-container .toast", has_text="Signed out in another tab.")).to_have_count(1)
        expect(same.locator("#toast-container .toast", has_text="Session expired")).to_have_count(0)
        # It sent no sign-out of its own: the first tab's ended the session.
        same.wait_for_timeout(1000)
        assert len(sent) == 1, f"{len(sent)} sign-outs sent for one session"
        # ben's tab stays signed in, and so does his session.
        expect(other.locator("#dashboard-screen")).to_be_visible()
        expect(other.locator("#toast-container .toast", has_text="Signed out in another tab.")).to_have_count(0)
        assert other.evaluate("() => authToken") == ben_token
        assert _refused(ben_token) == 200 and _refused(token) == 401
    finally:
        admin.delete_user(ben["id"])


SAVED_SINCE = "() => zkUploadStore.get('saved-since').then((r) => !!r)"


def test_a_tab_told_late_leaves_the_session_stored_since_by_another_tab(page: Page, ana):
    """A tab the browser froze in the background is told of a sign-out when it wakes, and the person may have
    signed in again in another tab since: the session then stored for this browser is that new one. The told tab
    signs out (it held the ended session) and leaves the stored one where it is, so the other tab's next load still
    finds it, and the zero-knowledge uploads saved in this browser (which every tab shares), now that session's, so
    they can be resumed. A full sign-out still empties that store (the control)."""
    sign_in_on_the_tab(page, ana)
    token = page.evaluate("() => authToken")
    sent = []
    page.context.on("request", lambda r: _is_sign_out(r) and sent.append(r))
    # Signed in again since, in another tab, which stored its session for this browser and saved an upload.
    page.evaluate("() => { localStorage.setItem('authToken', 'stored-since'); "
                  "localStorage.setItem('currentUser', '{\"username\": \"since\"}'); }")
    saved = page.evaluate("() => zkUploadStore.put({ sessionId: 'saved-since', vaultId: 'v', createdAt: Date.now(), "
                          "schema: zkUploadStore.schemaVersion(), blob: zkUploadStore.neutralBlob(new Blob(['x'])) })")
    assert saved == {"ok": True}, saved
    assert page.evaluate(SAVED_SINCE) is True
    # The message of the tab that ended this tab's session, delivered late.
    page.evaluate("(tail) => new BroadcastChannel('dockvault-sign-out').postMessage({ type: 'signed-out', token: tail })",
                  token[-24:])
    expect(page.locator("#login-screen")).to_be_visible(timeout=5000)
    assert page.evaluate("() => authToken") is None
    assert page.evaluate("() => [localStorage.getItem('authToken'), localStorage.getItem('currentUser')]") \
        == ["stored-since", '{"username": "since"}']
    page.wait_for_timeout(1000)
    assert sent == [], "a tab told of the sign-out sent one of its own"
    assert page.evaluate(SAVED_SINCE) is True, "the uploads saved by the session stored since were wiped"
    # The control: a full sign-out on this tab empties the store, as it always did.
    page.evaluate("() => logout()")
    _until(page, lambda: page.evaluate(SAVED_SINCE) is False, "a full sign-out left the saved uploads")


def _is_policy(request):
    return request.method == "GET" and request.url.endswith("/auth/policy")


def test_the_tab_that_signs_out_asks_for_the_sign_in_policy_at_once(page: Page, ana):
    """The tab the person signs out in shows the sign-in screen at once, labelled by the policy of that moment: it
    asks for the policy straight away, with no event of being shown or focused (only a tab told of the sign-out
    waits for one)."""
    sign_in_on_the_tab(page, ana)
    page.evaluate("() => { window.__shownOrFocused = 0; const n = () => { window.__shownOrFocused += 1; };"
                  " document.addEventListener('visibilitychange', n); window.addEventListener('focus', n); }")
    with page.expect_request(_is_policy, timeout=5000) as asked:
        page.evaluate("() => logout()")
    assert asked.value.headers.get("authorization") is None
    expect(page.locator("#login-screen")).to_be_visible(timeout=5000)
    assert page.evaluate("() => window.__shownOrFocused") == 0, "the tab was shown or focused: no proof it asked at once"


def test_a_tab_told_of_a_sign_out_asks_for_the_sign_in_policy_when_it_is_next_shown_once(page: Page, ana):
    """Told of a sign-out, a tab does not ask for the sign-in screen's policy at once (every tab of the session is
    told at the same moment, and those requests count against the address the person signs in from again); it asks
    when it is next shown or focused, once, so the screen it shows then is labelled by the policy of that moment."""
    sign_in_on_the_tab(page, ana)
    same = page.context.new_page()
    same.goto("/")
    expect(same.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    asked = []
    same.on("request", lambda r: _is_policy(r) and asked.append(r))
    sign_out(page)
    expect(same.locator("#login-screen")).to_be_visible(timeout=5000)
    same.wait_for_timeout(1000)
    assert asked == [], "the told tab asked for the policy at once"
    # Hidden first: not yet.
    same.evaluate("() => { Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true });"
                  " document.dispatchEvent(new Event('visibilitychange')); }")
    same.wait_for_timeout(500)
    assert asked == [], "asked while the tab was hidden"
    # Shown again: once.
    with same.expect_request(_is_policy, timeout=5000):
        same.evaluate("() => { Object.defineProperty(document, 'visibilityState', { value: 'visible', configurable: true });"
                      " document.dispatchEvent(new Event('visibilitychange')); }")
    same.evaluate("() => { window.dispatchEvent(new Event('focus')); }")
    same.wait_for_timeout(1000)
    assert len(asked) == 1, f"asked {len(asked)} times"


def _load_check_answered(tab: Page, answer):
    """Answer the sign-in check of `tab`'s next load (GET /users/me) with `answer`: a status and a detail, a page
    ("page", a status and its HTML: a proxy's own answer, not JSON), or "no answer" (the request fails, so the fetch
    throws)."""
    if answer == "no answer":
        tab.route("**/users/me", lambda route: route.abort("connectionrefused"))
        return
    if answer[0] == "page":
        _page, status, html = answer
        tab.route("**/users/me", lambda route: route.fulfill(status=status, content_type="text/html", body=html))
        return
    status, detail = answer
    tab.route("**/users/me", lambda route: route.fulfill(status=status, content_type="application/json",
                                                         body=json.dumps({"detail": detail})))


# A proxy's own refusal: an HTML page, not the vault's JSON. Its words are no account's state, even where they read
# like one: only the vault's own detail says that.
PROXY_403_PAGE = ("<html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1>"
                  "<p>Access from your address is locked by this proxy. The account is inactive here.</p></body></html>")


@pytest.mark.parametrize("answer", [
    (503, "Service Unavailable"),
    (502, "Bad Gateway"),
    (500, "Internal Server Error"),
    (429, "Rate limit exceeded. Please try again later."),
    (403, "Forbidden"),
    ("page", 403, PROXY_403_PAGE),
    "no answer",
], ids=["503", "502", "500", "429", "403-not-the-account", "403-a-proxys-page", "no-answer"])
def test_a_sign_in_check_at_load_that_could_not_be_answered_signs_out_that_tab_alone(page: Page, ana, answer):
    """One reload while the vault restarts behind a proxy, or a network blip: that tab goes to the sign-in screen as
    it always did, but nothing refused the session, so it is not ended and the other tab using it stays signed
    in."""
    sign_in_on_the_tab(page, ana)
    token = page.evaluate("() => authToken")
    sent = []
    page.context.on("request", lambda r: _is_sign_out(r) and sent.append(r))
    second = page.context.new_page()
    _load_check_answered(second, answer)
    second.goto("/")
    expect(second.locator("#login-screen")).to_be_visible(timeout=15000)
    assert second.evaluate("() => authToken") is None
    page.wait_for_timeout(1500)                   # a moment in which a call or another tab's message would come
    assert sent == [], "the session was ended on the server"
    assert page.evaluate("() => authToken") == token
    expect(page.locator("#dashboard-screen")).to_be_visible()
    expect(page.locator("#toast-container .toast", has_text="Signed out in another tab.")).to_have_count(0)
    assert _refused(token) == 200 and session_row(token) == "t|f"


@pytest.mark.parametrize("refusal", [
    (401, "Could not validate credentials"),
    (403, "User account is locked"),
    (403, "User account is inactive"),
], ids=["401", "403-locked", "403-inactive"])
def test_a_refusal_of_the_sign_in_check_at_load_ends_the_session_for_every_tab(page: Page, ana, refusal):
    """The control: a refusal of the session at a tab's load (here from a proxy, while the session is still live on
    the server) ends the session there, with the tab's token, and the other tab of the session is told."""
    sign_in_on_the_tab(page, ana)
    token = page.evaluate("() => authToken")
    second = page.context.new_page()
    _load_check_answered(second, refusal)
    with second.expect_request(_is_sign_out, timeout=15000) as sent:
        second.goto("/")
    assert sent.value.headers.get("authorization") == f"Bearer {token}"
    expect(second.locator("#login-screen")).to_be_visible(timeout=15000)
    expect(page.locator("#login-screen")).to_be_visible(timeout=5000)
    expect(page.locator("#toast-container .toast", has_text="Signed out in another tab.")).to_have_count(1)
    _ended(token)
    assert _refused(token) == 401


def test_the_page_signs_out_even_when_the_server_cannot_be_reached(page: Page, ana):
    sign_in_on_the_tab(page, ana)
    token = page.evaluate("() => authToken")
    page.route(f"**{SIGN_OUT}", lambda route: route.abort("internetdisconnected"))
    with page.expect_request(_is_sign_out, timeout=15000):
        page.evaluate("() => logout()")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    assert page.evaluate("() => authToken") is None
    assert page.evaluate("() => localStorage.getItem('authToken') || sessionStorage.getItem('authToken')") is None
    # The call never reached the server, so the session there runs on until it expires: nothing else could end it.
    assert _refused(token) == 200


def _hold_preference_saves(page: Page):
    """Hold each save of a preference (PUT /users/me/preferences) until the test lets it go."""
    held = []
    page.route("**/users/me/preferences",
               lambda route: held.append(route) if route.request.method == "PUT" else route.continue_())
    return held


def _until(page: Page, condition, what):
    for _ in range(200):
        if condition():
            return
        page.wait_for_timeout(25)
    raise AssertionError(what)


def test_a_preference_saved_at_the_sign_out_is_sent_before_the_session_ends(page: Page, ana):
    sign_in_on_the_tab(page, ana)
    token = page.evaluate("() => authToken")
    held = _hold_preference_saves(page)
    sent = []
    page.on("request", lambda r: _is_sign_out(r) and sent.append(r))
    page.evaluate("() => { saveUserPreference({ activity_page_size: '25' }); logout(); }")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    _until(page, lambda: len(held) == 1, "the save was not sent")
    page.wait_for_timeout(500)                    # a moment in which an early sign-out would have been sent
    assert sent == [], "the session was ended while a save of its own was on its way"
    with page.expect_request(_is_sign_out, timeout=15000):
        with page.expect_response(lambda r: r.request.method == "PUT" and r.url.endswith("/users/me/preferences"),
                                  timeout=15000) as saved:
            held.pop().continue_()
    assert saved.value.status == 200, "the save was refused: the session had ended before it"
    _ended(token)
    assert _refused(token) == 401
    kept = signed_in(ana).get("/users/me/preferences")
    assert kept.status_code == 200 and kept.json().get("activity_page_size") == "25", kept.text


def test_a_save_that_does_not_come_back_holds_the_sign_out_three_seconds_at_most(page: Page, ana):
    sign_in_on_the_tab(page, ana)
    token = page.evaluate("() => authToken")
    held = _hold_preference_saves(page)
    started = time.monotonic()
    with page.expect_request(_is_sign_out, timeout=15000):
        page.evaluate("() => { saveUserPreference({ activity_page_size: '25' }); logout(); }")
    waited = time.monotonic() - started
    assert len(held) == 1 and 2.5 <= waited < 10, waited
    _ended(token)
    assert _refused(token) == 401
    held.pop().abort()
