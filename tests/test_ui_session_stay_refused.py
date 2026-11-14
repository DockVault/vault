"""The warning's "Stay signed in" refused, or beaten to it by another tab (static/js/session-watch.js, stay).

When the server will not renew the sign-in, the session is over: the tab signs out and the sign-in screen says why,
with the server's own sentence for a refusal of the account. When another tab of the same browser renewed the
sign-in first, the token this tab sent is spent: it takes the renewed one and carries on, with no error.
"""
import pytest
import requests
from playwright.sync_api import Page, expect

from conftest import BASE_URL

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


def _warn(page: Page):
    page.evaluate("() => SessionWatch.armAt(Date.now() + 61000)")
    expect(page.locator("#session-expiry-modal.active")).to_be_visible(timeout=10000)


def test_a_renewal_refused_for_the_account_signs_out_with_the_servers_sentence(page: Page, person):
    _login(page, person)
    page.wait_for_load_state("networkidle", timeout=15000)
    _warn(page)
    # The server refuses the renewal for the account, in its own words.
    page.route("**/auth/session/extend", lambda route: route.fulfill(
        status=403, content_type="application/json", body='{"detail": "User account is inactive"}'))
    page.click("#session-stay")
    expect(page.locator("#login-screen")).to_be_visible(timeout=10000)
    note = page.locator("#login-error")
    expect(note).to_contain_text("User account is inactive", timeout=5000)
    assert note.get_attribute("role") == "alert"
    expect(page.locator("#session-expiry-modal.active")).to_be_hidden()
    expect(page.locator("#toast-container")).not_to_contain_text("Could not extend")


def test_an_account_made_inactive_while_the_warning_is_open_signs_the_tab_out_with_a_reason(page: Page, admin, person):
    # The page learns of it at once, from whichever of its requests is refused first (an unread-count poll, within
    # a tenth of a second here): the tab signs out, and the sign-in screen says why.
    _login(page, person)
    _warn(page)
    assert admin.patch(f"/users/{person['id']}", json={"is_active": False}).status_code in (200, 204)
    page.evaluate("() => { if (typeof refreshNotifUnread === 'function') refreshNotifUnread(); }")
    expect(page.locator("#login-screen")).to_be_visible(timeout=10000)
    note = page.locator("#login-error")
    expect(note).not_to_be_empty(timeout=5000)
    assert note.inner_text().strip() in ("Your session has ended. Sign in again.", "User account is inactive")
    assert note.get_attribute("role") == "alert"
    expect(page.locator("#session-expiry-modal.active")).to_be_hidden()
    expect(page.locator("#toast-container")).not_to_contain_text("Could not extend")


def test_a_renewal_beaten_by_another_tab_takes_its_token(page: Page, person):
    _login(page, person)
    other = page.context.new_page()
    other.goto("/")
    expect(other.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    old = page.evaluate("() => authToken")
    assert other.evaluate("() => authToken") == old
    # The second tab does not hear of the first tab's renewal in time (as when both are clicked at once).
    other.evaluate("() => { if (typeof _signOutChannel !== 'undefined' && _signOutChannel) _signOutChannel.close(); }")
    # The first tab stays signed in: the old token is spent from then on.
    _warn(page)
    page.click("#session-stay")
    expect(page.locator("#session-expiry-modal.active")).to_be_hidden(timeout=10000)
    page.wait_for_function("t => authToken && authToken !== t", arg=old, timeout=10000)
    new = page.evaluate("() => authToken")
    assert requests.get(f"{BASE_URL}/users/me", headers={"Authorization": f"Bearer {old}"}, timeout=15).status_code == 401
    # The second tab, still on the old token, asks too: refused, it takes the renewed token and carries on.
    assert other.evaluate("() => authToken") == old
    _warn(other)
    with other.expect_response(lambda r: r.url.endswith("/auth/session/extend")) as answer:
        other.click("#session-stay")
    assert answer.value.status == 401
    other.wait_for_function("t => authToken === t", arg=new, timeout=10000)
    expect(other.locator("#session-expiry-modal.active")).to_be_hidden(timeout=10000)
    expect(other.locator("#login-screen")).to_be_hidden()
    expect(other.locator("#toast-container")).not_to_contain_text("Could not extend")
    assert other.evaluate("() => SessionWatch.remaining()") > 120
    other.click('.sidebar-item[data-section="vaults"]')
    expect(other.locator("#vaults-section")).to_be_visible()
    # And the first tab was not signed out by it.
    expect(page.locator("#dashboard-screen")).to_be_visible()
    assert page.evaluate("() => authToken") == new
    other.close()
