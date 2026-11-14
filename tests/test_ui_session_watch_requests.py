"""The session warning's own requests end (static/js/session-watch.js).

The warning asks the server for the account only for the Date of the answer (the time a token has left, on the
server's clock). An answer whose body nobody reads stays open in the browser for as long as the page lives, so
the warning reads each body to its end: once the page has settled after a sign-in, no request is still open.
"""
import time

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui


@pytest.fixture
def person(admin):
    u = admin.create_user(role="user")
    yield u
    admin.delete_user(u["id"])


def test_no_request_stays_open_once_a_sign_in_has_settled(page: Page, person):
    open_ = {}
    page.on("request", lambda r: open_.__setitem__(id(r), r.url.split("/", 3)[-1]))
    page.on("requestfinished", lambda r: open_.pop(id(r), None))
    page.on("requestfailed", lambda r: open_.pop(id(r), None))
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    # No stored arrival for the new token: the warning asks the server for the time it has left.
    page.evaluate("() => { localStorage.removeItem('authTokenAt'); sessionStorage.removeItem('authTokenAt'); }")
    with page.expect_request(lambda r: r.url.endswith("/users/me")):
        page.fill("#username", person["_username"])
        page.fill("#password", person["_password"])
        page.click("#login-form button[type=submit]")
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    deadline = time.time() + 10
    while open_ and time.time() < deadline:
        page.wait_for_timeout(250)
    assert not open_, f"still open: {sorted(open_.values())}"
    page.wait_for_load_state("networkidle", timeout=10000)
