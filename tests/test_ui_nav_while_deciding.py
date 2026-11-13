"""A sidebar item that an answer still on its way will show or hide is not refused meanwhile.

The sidebar refuses a hidden item: a click, navigateToSection and a restored view open the dashboard instead.
But Compliance (and Activity for an account that is not an administrator) is shown or hidden by the account's
standing, and Upload links by the account's upload-link policy, and both answers come after sign-in. Until
they came, the item was hidden, so a reload on the Compliance page or on Upload links landed on the dashboard,
and a notice's link to Compliance opened right after sign-in did too.

Now such an item is being decided from sign-in until its answer. Asked for meanwhile, its section opens empty
(nothing drawn, nothing asked of the server) and waits: the answer then loads the page, or, when the item
stays hidden, opens the dashboard. Going elsewhere, or signing out, ends the wait.

Waits are on state, never on time; a request is held by routing it and let go by continuing it.
"""
import re
from urllib.parse import urlparse

import pytest
from playwright.sync_api import Page, expect

from _auditor_helpers import forget_grants, grant_right, new_auditor_account, two_admins
from conftest import unique

pytestmark = pytest.mark.ui

ACTIVE = re.compile(r"\bactive\b")
_MB = 1024 * 1024


class _Held:
    """Requests matching ``glob`` held by the route until let go."""

    def __init__(self, page: Page, glob: str):
        self.page, self.glob, self.routes = page, glob, []
        page.route(glob, lambda route: self.routes.append(route))

    def wait(self, count=1):
        for _ in range(300):
            if len(self.routes) >= count:
                return
            self.page.wait_for_timeout(50)
        raise AssertionError(f"no request to {self.glob} was held")

    def release(self):
        for route in self.routes:
            route.continue_()
        self.routes = []
        self.page.unroute(self.glob)


def _item(page: Page, section: str):
    return page.locator(f'.sidebar-item[data-section="{section}"]')


def _section(page: Page, section: str):
    return page.locator(f"#{section}-section")


def _login(page: Page, username: str, password: str, codes=None):
    if page.url in ("", "about:blank"):
        page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    if codes is not None:
        card = page.locator("#login-second-factor")
        expect(card).to_be_visible(timeout=15000)
        card.get_by_role("button", name="Use a recovery code instead").click()
        page.fill("#sf-code-input", codes.pop(0))
        card.locator("button").last.click()
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _requests(page: Page, pattern: str) -> list:
    """Every request from now on whose path matches ``pattern``, as "METHOD path"."""
    seen, wanted = [], re.compile(pattern)

    def on_request(req):
        path = urlparse(req.url).path
        if wanted.search(path):
            seen.append(f"{req.method} {path}")

    page.on("request", on_request)
    return seen


def _until(page: Page, happened, why: str):
    for _ in range(300):
        if happened():
            return
        page.wait_for_timeout(50)
    raise AssertionError(why)


def _expect_waiting(page: Page, section: str):
    """The section is the one on screen, with nothing of it drawn, waiting for its answer."""
    expect(_section(page, section)).to_have_class(ACTIVE)
    expect(_section(page, section)).to_be_hidden()
    assert _section(page, section).get_attribute("aria-busy") == "true"
    assert page.evaluate("() => navWaiting && navWaiting.section") == section
    expect(_item(page, section)).to_be_attached()
    expect(_item(page, section)).to_be_hidden()


def _expect_not_waiting(page: Page, section: str):
    assert page.evaluate("() => navWaiting") is None
    assert page.evaluate("(s) => document.getElementById(s + '-section').style.visibility", section) == ""
    assert _section(page, section).get_attribute("aria-busy") is None


def _expect_the_dashboard(page: Page):
    expect(_section(page, "dashboard")).to_have_class(ACTIVE)
    expect(page.locator("#dashboard-lanes")).to_be_visible(timeout=10000)   # the dashboard really rendered
    expect(_item(page, "dashboard")).to_have_class(ACTIVE)


# What the Compliance page itself asks (everything but the account's own standing), and the Activity page.
_PAGES_ASK = r"^/compliance/(?!me$)|^/activity(/|$)|^/audit(/|$)"


def test_compliance_asked_for_right_after_sign_in_waits_for_the_answer_and_opens(page: Page, admin_creds):
    page.goto("/")
    held = _Held(page, "**/compliance/me")
    asked = _requests(page, _PAGES_ASK)
    _login(page, admin_creds["username"], admin_creds["password"])
    page.evaluate("() => navigateToSection('compliance')")
    held.wait()
    _expect_waiting(page, "compliance")
    expect(_section(page, "dashboard")).not_to_have_class(ACTIVE)
    assert not asked, f"the page asked the server before it was known to be this account's: {asked}"
    held.release()
    expect(page.locator("#compliance-section.active .cmp-title")).to_be_visible(timeout=15000)
    expect(_item(page, "compliance")).to_be_visible()
    expect(_item(page, "compliance")).to_have_class(ACTIVE)
    _expect_not_waiting(page, "compliance")


def test_a_reload_on_the_compliance_page_comes_back_to_it(page: Page, admin_creds):
    page.goto("/")
    _login(page, admin_creds["username"], admin_creds["password"])
    expect(_item(page, "compliance")).to_be_visible(timeout=15000)
    _item(page, "compliance").click()
    expect(page.locator("#compliance-section.active .cmp-title")).to_be_visible(timeout=15000)
    held = _Held(page, "**/compliance/me")
    page.reload()
    held.wait()
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    _expect_waiting(page, "compliance")
    held.release()
    expect(page.locator("#compliance-section.active .cmp-title")).to_be_visible(timeout=15000)
    expect(_item(page, "compliance")).to_have_class(ACTIVE)


def test_a_user_who_asks_for_compliance_or_activity_meanwhile_lands_on_the_dashboard(page: Page, admin):
    u = admin.create_user(role="user")
    try:
        page.goto("/")
        held = _Held(page, "**/compliance/me")
        asked = _requests(page, _PAGES_ASK)
        _login(page, u["_username"], u["_password"])
        page.evaluate("() => navigateToSection('compliance')")
        held.wait()
        _expect_waiting(page, "compliance")
        # Activity, decided by the same answer for an account that is not an administrator: the same wait.
        page.evaluate("() => document.querySelector('.sidebar-item[data-section=\"activity\"]').click()")
        _expect_waiting(page, "activity")
        expect(_section(page, "compliance")).not_to_have_class(ACTIVE)
        assert page.evaluate("() => document.getElementById('compliance-section').style.visibility") == ""
        held.release()
        _expect_the_dashboard(page)
        expect(_section(page, "activity")).not_to_have_class(ACTIVE)
        expect(_section(page, "compliance")).not_to_have_class(ACTIVE)
        _expect_not_waiting(page, "activity")
        for section in ("compliance", "activity"):
            expect(_item(page, section)).to_be_attached()
            expect(_item(page, section)).to_be_hidden()
        # Decided now: the item is refused at once, and a saved view of it restores the dashboard.
        page.click('.sidebar-item[data-section="vaults"]')
        expect(_section(page, "vaults")).to_have_class(ACTIVE)
        page.evaluate("() => navigateToSection('compliance')")
        _expect_the_dashboard(page)
        page.evaluate("() => sessionStorage.setItem('dv_nav', JSON.stringify({section: 'compliance'}))")
        page.reload()
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        page.wait_for_function("() => !navDeciding.has('compliance')", timeout=15000)
        _expect_the_dashboard(page)
        expect(_section(page, "compliance")).not_to_have_class(ACTIVE)
        page.wait_for_timeout(1000)
        assert not asked, f"a user's session asked a page it may not have: {asked}"
    finally:
        admin.delete_user(u["id"])


def test_going_elsewhere_or_signing_out_ends_the_wait(page: Page, admin, admin_creds):
    u = admin.create_user(role="user")
    try:
        page.goto("/")
        held = _Held(page, "**/compliance/me")
        _login(page, admin_creds["username"], admin_creds["password"])
        page.evaluate("() => navigateToSection('compliance')")
        held.wait()
        _expect_waiting(page, "compliance")
        # Elsewhere by the sidebar: the answer, when it comes, shows the item and moves nobody.
        page.click('.sidebar-item[data-section="vaults"]')
        expect(_section(page, "vaults")).to_have_class(ACTIVE)
        _expect_not_waiting(page, "compliance")
        held.release()
        expect(_item(page, "compliance")).to_be_visible(timeout=15000)
        expect(_section(page, "vaults")).to_have_class(ACTIVE)
        expect(_section(page, "compliance")).not_to_have_class(ACTIVE)

        # Signed out while waiting: the answer of the person who has gone opens nothing for the next one.
        page.evaluate("() => logout()")
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        held = _Held(page, "**/compliance/me")
        _login(page, admin_creds["username"], admin_creds["password"])
        page.evaluate("() => navigateToSection('compliance')")
        held.wait()
        _expect_waiting(page, "compliance")
        page.evaluate("() => logout()")
        expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
        _expect_not_waiting(page, "compliance")
        assert page.evaluate("() => navDeciding.size") == 0
        held.release()
        _login(page, u["_username"], u["_password"])
        page.wait_for_function("() => !navDeciding.has('compliance')", timeout=15000)
        _expect_the_dashboard(page)
        expect(_section(page, "compliance")).not_to_have_class(ACTIVE)
        expect(_item(page, "compliance")).to_be_attached()
        expect(_item(page, "compliance")).to_be_hidden()
    finally:
        admin.delete_user(u["id"])


@pytest.fixture
def upload_links_on(admin):
    before = admin.get("/settings").json().get("public_receivers_enabled")
    admin.put("/settings", json={"public_receivers_enabled": True})
    r = admin.post("/receiver-tags", json={
        "name": unique("NavTag"), "min_token_len": 10, "max_file_bytes_cap": 100 * _MB,
        "max_total_bytes_cap": 500 * _MB, "auto_enroll_new_users": True, "is_active": True,
    })
    assert r.status_code in (200, 201), r.text
    yield r.json()
    admin.delete(f"/receiver-tags/{r.json()['id']}")
    admin.put("/settings", json={"public_receivers_enabled": bool(before)})


def test_a_reload_on_upload_links_comes_back_to_it_and_to_the_dashboard_once_they_are_off(
        page: Page, admin, admin_creds, upload_links_on):
    page.goto("/")
    _login(page, admin_creds["username"], admin_creds["password"])
    expect(page.locator("#nav-uploadlinks")).to_be_visible(timeout=15000)
    page.click("#nav-uploadlinks")
    expect(_section(page, "uploadlinks")).to_have_class(ACTIVE)
    held = _Held(page, "**/receiver-policy")
    asked = _requests(page, r"^/receivers(/|$)")
    page.reload()
    held.wait()
    _expect_waiting(page, "uploadlinks")
    assert not asked, f"the page asked the server before it was known to be this account's: {asked}"
    held.release()
    expect(page.locator("#nav-uploadlinks")).to_have_class(ACTIVE, timeout=15000)
    expect(_section(page, "uploadlinks")).to_be_visible()
    _expect_not_waiting(page, "uploadlinks")
    _until(page, lambda: asked, "the page, once shown, did not load")

    # Switched off: the same reload waits for the answer, then opens the dashboard.
    assert admin.put("/settings", json={"public_receivers_enabled": False}).status_code in (200, 204)
    del asked[:]
    page.reload()
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    page.wait_for_function("() => !navDeciding.has('uploadlinks')", timeout=15000)
    _expect_the_dashboard(page)
    expect(_section(page, "uploadlinks")).not_to_have_class(ACTIVE)
    expect(page.locator("#nav-uploadlinks")).to_be_attached()
    expect(page.locator("#nav-uploadlinks")).to_be_hidden()
    page.wait_for_timeout(1000)
    assert not asked, f"a page that is switched off was asked for: {asked}"


@pytest.fixture(scope="module")
def auditor(admin):
    """uma, whose auditor right is in force: Compliance and Activity are hers, and she is no administrator."""
    with two_admins(admin) as admins:
        uma, _uma_c, codes = new_auditor_account(admin)
        grant_right(admins, uma["id"])
        try:
            yield uma, codes
        finally:
            forget_grants(uma["id"])


@pytest.mark.parametrize("section,drawn", [("compliance", "#compliance-section.active .cmp-title"),
                                           ("activity", "#activity-section.active")])
def test_an_auditors_reload_on_compliance_or_activity_comes_back_to_it(page: Page, auditor, section, drawn):
    uma, codes = auditor
    page.goto("/")
    _login(page, uma["_username"], uma["_password"], codes)
    expect(_item(page, section)).to_be_visible(timeout=15000)
    _item(page, section).click()
    expect(page.locator(drawn)).to_be_visible(timeout=15000)
    held = _Held(page, "**/compliance/me")
    page.reload()
    held.wait()
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    _expect_waiting(page, section)
    held.release()
    expect(page.locator(drawn)).to_be_visible(timeout=15000)
    expect(_item(page, section)).to_have_class(ACTIVE)
    _expect_not_waiting(page, section)
