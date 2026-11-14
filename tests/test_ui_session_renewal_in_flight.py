"""A request refused while this tab's own renewal is on its way is answered, not failed (static/js/app.js apiRequest).

"Stay signed in" ends the old session on the server at once. A request the page sends with the old token before the
renewal's answer is stored is refused; the refusal waits for the renewal, the tab carries on with the new token, and
the request is sent once more with it: its caller gets the answer, the person stays signed in, and neither session
is ended.
"""
import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui


@pytest.fixture
def person(admin):
    u = admin.create_user(role="user")
    yield u
    admin.delete_user(u["id"])


def test_a_request_refused_during_this_tabs_renewal_is_sent_again_with_the_new_token(page: Page, person):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", person["_username"])
    page.fill("#password", person["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    page.wait_for_load_state("networkidle", timeout=15000)
    old = page.evaluate("() => authToken")
    sign_outs = []
    page.on("request", lambda r: sign_outs.append(r.url) if r.url.endswith("/auth/sign-out") else None)
    # The renewal reaches the server (which ends the old session), and its answer is held on the way back.
    held = []

    def hold(route):
        held.append((route, route.fetch()))

    page.route("**/auth/session/extend", hold)
    page.evaluate("() => SessionWatch.armAt(Date.now() + 61000)")
    expect(page.locator("#session-expiry-modal.active")).to_be_visible(timeout=10000)
    page.click("#session-stay")
    for _ in range(100):
        if held:
            break
        page.wait_for_timeout(100)
    assert held, "the renewal was not sent"
    # A request with the old token meanwhile: refused by the server.
    page.evaluate("""() => { window.__answer = apiRequest('/vaults').then(
        (v) => ({ answered: Array.isArray(v) }), (e) => ({ failed: e.message })); }""")
    page.wait_for_timeout(1500)
    route, response = held[0]
    route.fulfill(response=response)
    page.unroute("**/auth/session/extend")
    assert page.evaluate("() => window.__answer") == {"answered": True}
    new = page.evaluate("() => authToken")
    assert new and new != old
    expect(page.locator("#dashboard-screen")).to_be_visible()
    expect(page.locator("#login-screen")).to_be_hidden()
    page.wait_for_timeout(1000)
    assert sign_outs == [], sign_outs
