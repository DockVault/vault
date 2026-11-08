"""The administrators' sidebar items (Users, Groups, Activity, Settings) belong to an administrator's own
session, and to nobody else on the same tab.

They are hidden by default and were shown for an administrator at sign-in, but nothing hid them again: not
the sign-out, not the next sign-in. An administrator who signed out, then a user who signed in on the same tab
without a reload, found Groups, Activity and Settings in their sidebar, and opening Settings asked the server
for every administrator-only read, each refused and each recorded as a refused administrator action. A saved
view did the same after a reload: any saved section whose item existed was restored, hidden or not.

Now the items are set both ways at sign-in and hidden at sign-out, and the sidebar refuses a hidden item (a
click, a restored view, a script): the dashboard opens instead, and no administrator route is asked.

Every to_be_hidden() is preceded by to_be_attached(): Playwright reports a missing element as hidden, so without
the guard these would pass against a page that never had the items.
"""
import re
from urllib.parse import urlparse

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

ADMIN_ITEMS = ("groups", "activity", "settings")
# The routes only an administrator's own session may read. The account's own /users/me and the scoped
# /users/search are everyone's.
_ADMIN_ROUTE = re.compile(r"^/(settings|groups|users|audit|activity)(/|$)")
_EVERYONES = ("/users/me", "/users/search")


def _item(page: Page, section: str):
    return page.locator(f'.sidebar-item[data-section="{section}"]')


def _login(page: Page, username: str, password: str):
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _sign_out_in_app(page: Page):
    """The app's own sign-out, not a reload: the page and its sidebar stay as they were."""
    page.click("#profile-btn")
    page.click("#dropdown-logout-btn")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)


def _admin_requests(page: Page) -> list:
    """Every request to an administrator route from now on, as its path."""
    seen = []

    def on_request(req):
        path = urlparse(req.url).path
        if _ADMIN_ROUTE.match(path) and not path.startswith(_EVERYONES):
            seen.append(f"{req.method} {path}")

    page.on("request", on_request)
    return seen


def _expect_admin_items_hidden(page: Page):
    for section in ADMIN_ITEMS:
        expect(_item(page, section)).to_be_attached()
        expect(_item(page, section)).to_be_hidden()


def test_a_user_after_an_administrator_on_the_same_tab_gets_no_administrator_items(page: Page, admin, admin_creds):
    """Both ways: hidden for the user who follows an administrator, back for the administrator who follows."""
    u = admin.create_user(role="user")
    try:
        page.goto("/")
        _login(page, admin_creds["username"], admin_creds["password"])
        for section in ADMIN_ITEMS:
            expect(_item(page, section)).to_be_visible()

        _sign_out_in_app(page)
        _expect_admin_items_hidden(page)  # already at sign-out, before anyone signs in

        asked = _admin_requests(page)
        _login(page, u["_username"], u["_password"])
        _expect_admin_items_hidden(page)
        # Moving about as the user asks nothing of the administrator routes either.
        page.click('.sidebar-item[data-section="vaults"]')
        expect(page.locator("#vaults-section")).to_be_visible(timeout=10000)
        page.click('.sidebar-item[data-section="dashboard"]')
        expect(page.locator("#dashboard-section")).to_be_visible(timeout=10000)
        page.wait_for_timeout(1500)
        assert not asked, f"a user's session asked an administrator route: {asked}"

        _sign_out_in_app(page)
        _login(page, admin_creds["username"], admin_creds["password"])
        for section in ADMIN_ITEMS:
            expect(_item(page, section)).to_be_visible()
    finally:
        admin.delete_user(u["id"])


def test_a_saved_settings_view_restores_the_dashboard_for_a_user(page: Page, admin):
    """The saved view is the browser's, not the account's: an administrator's saved Settings, restored on a
    reload for a user, opens the dashboard and asks for no settings."""
    u = admin.create_user(role="user")
    try:
        page.goto("/")
        _login(page, u["_username"], u["_password"])
        page.evaluate("() => sessionStorage.setItem('dv_nav', JSON.stringify({section: 'settings'}))")
        asked = _admin_requests(page)
        page.reload()
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        expect(page.locator("#dashboard-lanes")).to_be_visible(timeout=10000)  # the dashboard really rendered
        expect(page.locator("#dashboard-section")).to_have_class(re.compile(r"\bactive\b"))
        expect(page.locator("#settings-section")).not_to_have_class(re.compile(r"\bactive\b"))
        _expect_admin_items_hidden(page)
        page.wait_for_timeout(1500)
        assert not asked, f"restoring a saved Settings view asked an administrator route: {asked}"
    finally:
        admin.delete_user(u["id"])


def test_a_hidden_item_is_refused_when_scripted(page: Page, admin):
    """A click on a hidden item, or navigateToSection with its name, opens the dashboard, not the page."""
    u = admin.create_user(role="user")
    try:
        page.goto("/")
        _login(page, u["_username"], u["_password"])
        page.click('.sidebar-item[data-section="vaults"]')
        expect(page.locator("#vaults-section")).to_be_visible(timeout=10000)
        asked = _admin_requests(page)
        page.evaluate("() => navigateToSection('settings')")
        expect(page.locator("#dashboard-section")).to_have_class(re.compile(r"\bactive\b"))
        expect(page.locator("#settings-section")).not_to_have_class(re.compile(r"\bactive\b"))
        page.click('.sidebar-item[data-section="vaults"]')
        expect(page.locator("#vaults-section")).to_be_visible(timeout=10000)
        page.evaluate("() => document.querySelector('.sidebar-item[data-section=\"groups\"]').click()")
        expect(page.locator("#dashboard-section")).to_have_class(re.compile(r"\bactive\b"))
        expect(page.locator("#groups-section")).not_to_have_class(re.compile(r"\bactive\b"))
        page.wait_for_timeout(1000)
        assert not asked, f"a refused item asked an administrator route: {asked}"
    finally:
        admin.delete_user(u["id"])
