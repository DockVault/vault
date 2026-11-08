"""The stay-or-sign-out warning (static/js/session-watch.js).

A minute before the session ends a dialog with a count-down ring opens, focusing no button (a stray Enter
chooses nothing); it can be closed without choosing and the count goes on; "Stay signed in" renews the
token (the old one is refused from then on); doing nothing signs the person out, and the sign-in screen says
why.
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


def _stored_token(page: Page):
    return page.evaluate("() => localStorage.getItem('authToken') || sessionStorage.getItem('authToken')")


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
    # Escape closes it without choosing; the count goes on and the dialog can come back.
    page.keyboard.press("Escape")
    expect(modal).to_be_hidden()
    expect(page.locator("#dashboard-screen")).to_be_visible()
    page.evaluate("() => SessionWatch.show()")
    expect(modal).to_be_visible()
    # Stay: a new token, the dialog gone, the old token refused.
    with page.expect_request(lambda r: r.url.endswith("/auth/session/extend") and r.method == "POST"):
        page.click("#session-stay")
    expect(modal).to_be_hidden(timeout=10000)
    expect(page.locator("#toast-container")).to_contain_text("You stay signed in")
    new = _stored_token(page)
    assert new and new != old
    assert requests.get(f"{BASE_URL}/users/me", headers={"Authorization": f"Bearer {old}"}, timeout=15).status_code == 401
    assert requests.get(f"{BASE_URL}/users/me", headers={"Authorization": f"Bearer {new}"}, timeout=15).status_code == 200
    # The page still works on the new token.
    page.click('.sidebar-item[data-section="vaults"]')
    expect(page.locator("#vaults-section")).to_be_visible()


def test_doing_nothing_signs_out_and_the_sign_in_screen_says_why(page: Page, person):
    _login(page, person)
    page.evaluate("() => SessionWatch.armAt(Date.now() + 61500)")
    expect(page.locator("#session-expiry-modal.active")).to_be_visible(timeout=10000)
    expect(page.locator("#login-screen")).to_be_visible(timeout=75000)
    expect(page.locator("#login-error")).to_contain_text("Your session ended")
    expect(page.locator("#session-expiry-modal.active")).to_be_hidden()
