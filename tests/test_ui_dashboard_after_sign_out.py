"""A dashboard draw still on its way when its session ends draws nothing (static/js/app.js loadDashboardStats,
static/js/dashboard-actions.js).

The dashboard asks the server for several things and draws each answer as it comes. An answer that comes back
after the person signed out, or after the next person signed in and their own dashboard was drawn, is the last
person's: it is not written into the page. The page is replaced once the sign-out is over (static/js/app.js
_replacePageAfterSignOut), and the next person signs in on the page put in its place.
"""
import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, BASE_URL, unique
from _ui_hand_over import replaced

pytestmark = pytest.mark.ui


class _HoldFirst:
    """The first answer to ``glob`` is fetched from the server and held on its way to the page; the rest pass."""

    def __init__(self, page: Page, glob: str):
        self.page, self.glob, self.held = page, glob, []
        page.route(glob, self._route)

    def _route(self, route):
        if self.held:
            route.continue_()
        else:
            self.held.append((route, route.fetch()))

    def wait(self):
        for _ in range(150):
            if self.held:
                return
            self.page.wait_for_timeout(100)
        raise AssertionError(f"nothing asked for {self.glob}")

    def release(self):
        route, response = self.held[0]
        route.fulfill(response=response)
        self.page.unroute(self.glob)


def _sign_in(page: Page, user):
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", user["_username"])
    page.fill("#password", user["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _sign_out(page: Page):
    with replaced(page):
        page.click("#profile-btn")
        page.click("#dropdown-logout-btn")


@pytest.fixture
def people(admin):
    ana, ben = admin.create_user(role="user"), admin.create_user(role="user")
    yield ana, ben
    admin.delete_user(ana["id"])
    admin.delete_user(ben["id"])


def test_an_answer_that_comes_back_after_the_sign_out_is_not_drawn(page: Page, people):
    ana, _ben = people
    held = _HoldFirst(page, "**/shares")
    page.goto("/")
    _sign_in(page, ana)
    held.wait()                      # the Needs-attention lane is waiting for it
    _sign_out(page)
    held.release()
    page.wait_for_timeout(1500)
    expect(page.locator("#lane-attention > *")).to_have_count(0)


def test_the_last_persons_slow_answer_does_not_overwrite_the_next_persons_dashboard(page: Page, people):
    ana, ben = people
    client = ApiClient(BASE_URL)
    client.login(ana["_username"], ana["_password"])
    hers = [client.create_vault(name=unique("AnaVault"))["name"] for _ in range(3)]
    other = ApiClient(BASE_URL)
    other.login(ben["_username"], ben["_password"])
    his = other.create_vault(name=unique("BenVault"))["name"]
    held = _HoldFirst(page, "**/vaults")
    page.goto("/")
    _sign_in(page, ana)
    held.wait()                      # her dashboard is waiting for her vaults
    _sign_out(page)
    _sign_in(page, ben)
    expect(page.locator("#lane-recent")).to_contain_text(his, timeout=15000)
    expect(page.locator("#dashboard-vaults-count")).to_have_text("1")
    held.release()                   # her answer arrives now
    page.wait_for_timeout(2000)
    expect(page.locator("#dashboard-vaults-count")).to_have_text("1")
    for name in hers:
        expect(page.locator("#dashboard-section")).not_to_contain_text(name)
    expect(page.locator("#lane-recent")).to_contain_text(his)
