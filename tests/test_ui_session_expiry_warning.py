"""The stay-or-sign-out warning (static/js/session-watch.js).

A minute before the session ends a dialog with a count-down ring opens, focusing no button (a stray Enter
chooses nothing); it can be closed without choosing and the count goes on; "Stay signed in" renews the
token (the old one is refused from then on), and so does closing the warning; doing nothing signs the person
out, and the sign-in screen says why. It opens over any other dialog, measures the session's life on this
device's own clock, and offers a temporary credential no renewal.
"""
import base64
import json
from email.utils import parsedate_to_datetime

import pytest
import requests
from playwright.sync_api import Page, expect

from conftest import BASE_URL
from _sf_helpers import put_settings_allowing_longer_sessions

pytestmark = pytest.mark.ui


@pytest.fixture
def person(admin):
    u = admin.create_user(role="user")
    yield u
    admin.delete_user(u["id"])


def _login(page: Page, user):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", user["_username"])
    page.fill("#password", user["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _stored_token(page: Page):
    return page.evaluate("() => localStorage.getItem('authToken') || sessionStorage.getItem('authToken')")


def _new_token(page: Page, than: str) -> str:
    """The token stored once the renewal the page asked for has come back (the request is sent at once; the
    answer arrives a moment later)."""
    page.wait_for_function(
        "t => (localStorage.getItem('authToken') || sessionStorage.getItem('authToken')) !== t", arg=than,
        timeout=10000)
    return _stored_token(page)


def test_the_warning_focuses_nothing_can_be_dismissed_and_stay_renews_the_token(page: Page, person):
    _login(page, person)
    old = _stored_token(page)
    assert old
    page.evaluate("() => SessionWatch.armAt(Date.now() + 63000)")
    modal = page.locator("#session-expiry-modal.active")
    expect(modal).to_be_visible(timeout=10000)
    seconds = int(page.locator("#session-expiry-seconds").inner_text())
    assert 50 <= seconds <= 61, seconds
    # No button has focus: Enter and Space choose nothing.
    assert page.evaluate("() => !(document.activeElement && document.activeElement.closest('#session-expiry-modal button'))")
    page.keyboard.press("Enter")
    page.keyboard.press("Space")
    expect(modal).to_be_visible()
    expect(page.locator("#dashboard-screen")).to_be_visible()
    # The count goes down; the ring is drawn.
    page.wait_for_timeout(1600)
    assert int(page.locator("#session-expiry-seconds").inner_text()) < seconds
    offset = page.evaluate("() => parseFloat(document.getElementById('session-ring-fill').style.strokeDashoffset)")
    assert offset > 0
    # Stay: a new token, the dialog gone, the old token refused.
    with page.expect_request(lambda r: r.url.endswith("/auth/session/extend") and r.method == "POST"):
        page.click("#session-stay")
    expect(modal).to_be_hidden(timeout=10000)
    expect(page.locator("#toast-container")).to_contain_text("You stay signed in")
    new = _stored_token(page)
    assert new and new != old
    # Closing the warning with Escape counts as staying too: a person who dismisses it is present.
    page.evaluate("() => SessionWatch.armAt(Date.now() + 61000)")
    expect(modal).to_be_visible(timeout=10000)
    with page.expect_request(lambda r: r.url.endswith("/auth/session/extend") and r.method == "POST"):
        page.keyboard.press("Escape")
    expect(modal).to_be_hidden(timeout=10000)
    expect(page.locator("#dashboard-screen")).to_be_visible()
    newer = _new_token(page, new)
    assert newer and newer != new
    old, new = new, newer
    assert requests.get(f"{BASE_URL}/users/me", headers={"Authorization": f"Bearer {old}"}, timeout=15).status_code == 401
    assert requests.get(f"{BASE_URL}/users/me", headers={"Authorization": f"Bearer {new}"}, timeout=15).status_code == 200
    # The page still works on the new token.
    page.click('.sidebar-item[data-section="vaults"]')
    expect(page.locator("#vaults-section")).to_be_visible()


def test_doing_nothing_signs_out_and_the_sign_in_screen_says_why(page: Page, admin, admin_creds, person):
    # A session that really ends: two minutes. The page counts down on its own clock and, at zero, the server
    # (which refuses the expired token) has the last word.
    before = admin.get("/settings").json().get("session_timeout") or 0
    assert admin.put("/settings", json={"session_timeout": 2}).status_code in (200, 204)
    try:
        _login(page, person)
    finally:
        # Back to the longer timeout: that save asks for the administrator's password.
        restored = put_settings_allowing_longer_sessions(admin, admin_creds["password"], {"session_timeout": before})
        assert restored.status_code in (200, 204), restored.text
    # Two minutes at most: the count read from the server's clock errs early, never late.
    assert page.evaluate("() => SessionWatch.remaining()") <= 120
    expect(page.locator("#session-expiry-modal.active")).to_be_visible(timeout=75000)
    expect(page.locator("#login-screen")).to_be_visible(timeout=90000)
    expect(page.locator("#login-error")).to_contain_text("Your session ended because nobody chose to stay")
    assert page.get_attribute("#login-error", "role") == "alert"
    expect(page.locator("#session-expiry-modal.active")).to_be_hidden()


def test_another_tab_of_the_same_browser_carries_on_after_a_renewal(page: Page, person):
    _login(page, person)
    other = page.context.new_page()
    other.goto("/")
    expect(other.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    old = _stored_token(page)
    other_token_before = other.evaluate("() => authToken")
    assert other_token_before == old
    # The first tab stays signed in; the second learns of it and takes the new token.
    page.evaluate("() => SessionWatch.armAt(Date.now() + 62000)")
    expect(page.locator("#session-expiry-modal.active")).to_be_visible(timeout=10000)
    page.click("#session-stay")
    expect(page.locator("#session-expiry-modal.active")).to_be_hidden(timeout=10000)
    new = _stored_token(page)
    assert new != old
    other.wait_for_function("t => authToken === t", arg=new, timeout=10000)
    # And it still works there: a page that needs the token draws.
    other.click('.sidebar-item[data-section="vaults"]')
    expect(other.locator("#vaults-section")).to_be_visible()
    expect(other.locator("#login-screen")).to_be_hidden()
    other.close()



def test_the_warning_opens_over_an_open_dialog_and_gets_the_keys(page: Page, person):
    _login(page, person)
    old = _stored_token(page)
    page.evaluate("() => openModal('note-editor-modal')")
    expect(page.locator("#note-editor-modal.active")).to_be_visible()
    page.evaluate("() => SessionWatch.armAt(Date.now() + 61000)")
    modal = page.locator("#session-expiry-modal.active")
    expect(modal).to_be_visible(timeout=10000)
    # What is under the pointer at the Stay button is the warning itself, not the dialog beneath.
    assert page.evaluate("""() => {
        const b = document.getElementById('session-stay').getBoundingClientRect();
        const hit = document.elementFromPoint(b.left + b.width / 2, b.top + b.height / 2);
        return !!(hit && hit.closest('#session-expiry-modal'));
    }""")
    assert page.evaluate("() => parseInt(getComputedStyle(document.getElementById('session-expiry-modal')).zIndex, 10) > 1000")
    # Keys reach the warning: focus is inside it, and Escape acts on it (which counts as staying signed in)...
    assert page.evaluate("() => !!document.activeElement.closest('#session-expiry-modal')")
    with page.expect_request(lambda r: r.url.endswith("/auth/session/extend") and r.method == "POST"):
        page.keyboard.press("Escape")
    expect(modal).to_be_hidden(timeout=10000)
    # ...while the dialog the person was in is still open, with what they typed.
    expect(page.locator("#note-editor-modal.active")).to_be_visible()
    assert _new_token(page, old) != old


def test_the_warning_paints_over_the_step_up_and_gets_the_keys(page: Page, person):
    """The step-up dialog is lifted above the other dialogs and sits later in the page; the warning still
    paints over it, and focus is in the warning."""
    _login(page, person)
    page.evaluate("() => { requestStepUpReceipt('test', ['password']); }")
    expect(page.locator("#stepup-modal.active")).to_be_visible(timeout=10000)
    assert page.evaluate("() => document.getElementById('stepup-modal').style.zIndex") == "1100"
    page.evaluate("() => SessionWatch.armAt(Date.now() + 61000)")
    modal = page.locator("#session-expiry-modal.active")
    expect(modal).to_be_visible(timeout=10000)
    assert page.evaluate("""() => {
        const b = document.getElementById('session-stay').getBoundingClientRect();
        const hit = document.elementFromPoint(b.left + b.width / 2, b.top + b.height / 2);
        return !!(hit && hit.closest('#session-expiry-modal'));
    }""")
    assert page.evaluate("() => !!(document.activeElement && document.activeElement.closest('#session-expiry-modal'))")
    expect(page.locator("#stepup-modal.active")).to_be_visible()


def test_a_device_clock_far_ahead_does_not_end_the_session(page: Page, person):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    # This device's clock runs five hours ahead of the server's, longer than any token the stack hands out.
    page.evaluate("() => { const real = Date.now.bind(Date); Date.now = () => real() + 300 * 60 * 1000; }")
    page.fill("#username", person["_username"])
    page.fill("#password", person["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    page.wait_for_timeout(2500)
    # Nothing fired: the lifetime is measured on this device from the token's arrival.
    expect(page.locator("#session-expiry-modal.active")).to_be_hidden()
    expect(page.locator("#login-screen")).to_be_hidden()
    assert page.evaluate("() => SessionWatch.remaining()") > 60 * 60
    # Even a count that reaches zero here asks the server, which still accepts the token: no sign-out.
    page.evaluate("() => SessionWatch.armAt(Date.now() + 1500)")
    page.wait_for_timeout(4000)
    expect(page.locator("#login-screen")).to_be_hidden()
    expect(page.locator("#dashboard-screen")).to_be_visible()
    assert page.evaluate("() => SessionWatch.remaining()") > 60 * 60
    # And a clock behind the server's changes nothing either.
    page.evaluate("() => { const real = Date.now.bind(Date); Date.now = () => real() - 600 * 60 * 1000; }")
    page.evaluate("() => SessionWatch.armFromToken(authToken)")
    page.wait_for_timeout(1500)
    expect(page.locator("#session-expiry-modal.active")).to_be_hidden()
    expect(page.locator("#dashboard-screen")).to_be_visible()


def _claims(token: str) -> dict:
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def _server_left(token: str) -> float:
    """The seconds the token has left, as the server counts them (its Date header against the token's exp)."""
    r = requests.get(f"{BASE_URL}/users/me", headers={"Authorization": f"Bearer {token}"}, timeout=15)
    assert r.status_code == 200
    return _claims(token)["exp"] - parsedate_to_datetime(r.headers["Date"]).timestamp()


def test_a_token_with_no_stored_arrival_is_timed_by_the_server(page: Page, person):
    """A token held from before its arrival was stored (the first load after an upgrade) is not taken for one
    that just arrived: the time it has left comes from the server, whatever this device's clock says, and the
    arrival that implies is stored so a reload agrees."""
    _login(page, person)
    token = _stored_token(page)
    claims = _claims(token)
    lifetime = claims["exp"] - claims["iat"]
    # The token ages, so one taken for just arrived would read about twenty seconds more than the server.
    page.wait_for_timeout(20000)
    page.evaluate("() => { localStorage.removeItem('authTokenAt'); sessionStorage.removeItem('authTokenAt'); }")
    # This device's clock runs two hours ahead, from the reload on.
    page.add_init_script("(() => { const real = Date.now.bind(Date); Date.now = () => real() + 2 * 3600 * 1000; })()")
    page.reload()
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    page.wait_for_function("full => SessionWatch.remaining() > 0 && SessionWatch.remaining() < full - 10",
                           arg=lifetime, timeout=10000)
    left = page.evaluate("() => SessionWatch.remaining()")
    assert abs(left - _server_left(token)) <= 4, (left, lifetime)
    assert page.evaluate("() => !!(localStorage.getItem('authTokenAt') || sessionStorage.getItem('authTokenAt'))")
    # A reload reads the stored arrival and agrees, with no second correction needed.
    page.reload()
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    page.wait_for_function("() => SessionWatch.remaining() > 0", timeout=10000)
    left = page.evaluate("() => SessionWatch.remaining()")
    assert abs(left - _server_left(token)) <= 4, (left, lifetime)


def test_a_temporary_credential_is_warned_about_its_end_and_offered_no_renewal(page: Page, admin):
    v = admin.create_vault(name="warn-temp")
    try:
        scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": ["vault.see_info", "vault.see_files"], "temp": {}}
        tc = admin.post("/auth/temp-credentials", json={"validity_minutes": 30, "scope": scope,
                                                        "vault_access_mode": "all", "selected_vaults": []})
        assert tc.status_code == 200, tc.text
        page.goto("/")
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        page.fill("#username", tc.json()["temp_username"])
        page.fill("#password", tc.json()["credential"])
        page.click("#login-form button[type=submit]")
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        page.wait_for_function("() => window.SessionWatch && SessionWatch.isTemporary()", timeout=10000)
        # Timed to the credential's end (30 minutes), not the token's longer life.
        assert page.evaluate("() => SessionWatch.remaining()") <= 31 * 60
        page.evaluate("() => SessionWatch.armAt(Date.now() + 61000)")
        expect(page.locator("#session-expiry-modal.active")).to_be_visible(timeout=10000)
        expect(page.locator("#session-stay")).to_be_hidden()
        expect(page.locator("#session-expiry-text")).to_contain_text("temporary access")
        expect(page.locator("#session-signout")).to_be_visible()
    finally:
        admin.delete_vault(v["id"])
