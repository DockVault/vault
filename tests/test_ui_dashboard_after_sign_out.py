"""A dashboard draw still on its way when its session ends draws nothing (static/js/app.js apiRequest,
static/js/dashboard-actions.js).

The dashboard asks the server for several things and draws each answer as it comes. An answer that comes back
after the person signed out is the last person's: it is not written into the page. Here the Needs-attention lane's
answer is let through while the page waits for its sign-out (the page is replaced once the sign-out is over), and
the lane, kept by reference since the sign-out takes it out of the document, holds none of it. The same answer, let
through while the person is still signed in, is drawn (the control). The dashboard's own answers on their way at a
sign-out are 0.34.3's: tests/test_ui_sign_out_replaces_the_page.py,
test_a_request_on_its_way_when_the_session_ends_cannot_write_into_the_new_page.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest
from playwright.sync_api import Page, expect

from conftest import unique
from _ui_hand_over import ON_ITS_WAY, added, sign_out_as, still_old, wait_replaced, watch_added

pytestmark = pytest.mark.ui


class _HoldFirst:
    """The first answer to ``glob`` is held on its way to the page; the rest pass."""

    def __init__(self, page: Page, glob: str):
        self.page, self.glob, self.held = page, glob, []
        page.route(glob, self._route)

    def _route(self, route):
        if self.held:
            route.continue_()
        else:
            self.held.append(route)

    def wait(self):
        for _ in range(150):
            if self.held:
                return
            self.page.wait_for_timeout(100)
        raise AssertionError(f"nothing asked for {self.glob}")

    def release(self, body):
        self.held[0].fulfill(status=200, content_type="application/json", body=json.dumps(body))
        self.page.unroute(self.glob)


def _sign_in(page: Page, user):
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", user["_username"])
    page.fill("#password", user["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _sign_out_by_hand(page: Page):
    page.click("#profile-btn")
    page.click("#dropdown-logout-btn")


@pytest.fixture
def ana(admin):
    user = admin.create_user(role="user")
    yield user
    admin.delete_user(user["id"])


@pytest.mark.parametrize("signed_out", [False, True], ids=["control_signed_in", "sign_out_on_its_way"])
def test_an_answer_that_comes_back_after_the_sign_out_is_not_drawn(page: Page, ana, signed_out):
    marker = unique("AnaShare")
    soon = (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    # Her share that expires tomorrow: what the lane lists as needing her attention.
    answer = {"shares": [{"id": "s-1", "status": "active", "expires_at": soon, "target_name": marker,
                          "vault_name": marker}]}
    errors = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    held = _HoldFirst(page, "**/shares")
    page.goto("/")
    _sign_in(page, ana)
    held.wait()                      # the Needs-attention lane is waiting for it
    page.evaluate("() => { window.__lane = document.getElementById('lane-attention'); }")
    if not signed_out:
        held.release(answer)
        expect(page.locator("#lane-attention")).to_contain_text(marker, timeout=10000)
        assert errors == [], errors
        return
    signing_out = sign_out_as(page, ON_ITS_WAY, lambda: _sign_out_by_hand(page), markers=[marker])
    watch_added(page)
    held.release(answer)
    page.wait_for_timeout(1500)
    assert still_old(page), "the page went: the answer reached nothing to test"
    assert added(page) == [], added(page)
    assert marker not in page.evaluate("() => window.__lane.textContent"), "the answer was drawn into her lane"
    assert errors == [], errors
    signing_out.release()
    wait_replaced(page)
