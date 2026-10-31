"""A sign-in sent before the page has finished loading is held, said so, and sent once the page is ready.

The sign-in screen is on screen and usable before the page's scripts have all run (app.js, which signs in,
loads at the end of the page). Until then the browser must not send the form itself (static/js/auth-boot.js
stops that, so nothing typed goes into an address), and a press of Sign in used to do nothing at all, with
no word said. Now the button says the page is still loading until it can sign in; a sign-in sent in that
time, by the button or the Enter key, is held, the note under the button says so (to a screen reader too,
as a status), and once the page is ready it is sent, once, with what the fields then hold.

These tests hold app.js back (a route that is not answered) to make the page slow, in both skins, at desktop
and at phone width.
"""
import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

PHONE = {"width": 390, "height": 844}
DESKTOP = {"width": 1280, "height": 800}
NOTE = "The page is still loading. You will be signed in as soon as it is ready."


class _SlowPage:
    """Opens the page with every request for app.js held until release(); records the sign-in requests and
    every address a request went to."""

    def __init__(self, page: Page, base_url: str, skin: str, viewport: dict):
        self.page = page
        self.home = base_url.rstrip("/") + "/"
        self.routes = []
        self.logins = []
        self.urls = []
        page.add_init_script(f"try {{ localStorage.setItem('ui', '{skin}'); }} catch (e) {{}}")
        page.set_viewport_size(viewport)
        page.on("request", self._seen)
        page.route("**/static/js/app.js*", lambda route: self.routes.append(route))
        page.goto(self.home, wait_until="commit")
        expect(page.locator("#login-form")).to_be_visible(timeout=30000)
        for _ in range(150):
            if self.routes:
                break
            page.wait_for_timeout(100)
        assert self.routes, "the page never asked for app.js"

    def _seen(self, request):
        self.urls.append(request.url)
        if request.method == "POST" and request.url.split("?")[0].endswith("/auth/login"):
            self.logins.append(request.post_data or "")

    def release(self):
        self.page.unroute("**/static/js/app.js*")
        for route in self.routes:
            try:
                route.continue_()
            except Exception:
                pass
        self.routes = []


@pytest.fixture
def slow(page: Page, base_url, request):
    made = []

    def open_(skin, viewport):
        s = _SlowPage(page, base_url, skin, viewport)
        made.append(s)
        return s
    yield open_
    for s in made:
        s.release()


def _fits(page: Page, selector: str):
    box = page.locator(selector).bounding_box()
    width = page.evaluate("() => document.documentElement.clientWidth")
    assert box and box["x"] >= 0 and box["x"] + box["width"] <= width + 1, (selector, box, width)


@pytest.mark.parametrize("skin, viewport, how", [
    ("v2", "desktop", "button"),
    ("v1", "desktop", "enter"),
    ("v2", "phone", "enter"),
    ("v1", "phone", "button"),
])
def test_a_sign_in_sent_while_the_page_loads_is_held_said_so_and_sent_once(page: Page, slow, admin_creds,
                                                                           skin, viewport, how):
    s = slow(skin, PHONE if viewport == "phone" else DESKTOP)
    button = page.locator("#login-submit")
    note = page.locator("#login-loading-note")
    # Until the page can sign in, the button says it is loading: to the eye, and as the button's name.
    expect(button).to_have_text("Loading…")
    expect(page.get_by_role("button", name="Loading…", exact=True)).to_be_visible()
    expect(note).to_have_text("")

    page.fill("#username", admin_creds["username"])
    page.fill("#password", admin_creds["password"])
    if how == "button":
        button.click(no_wait_after=True)
    else:
        page.locator("#password").press("Enter", no_wait_after=True)
    expect(note).to_have_text(NOTE)
    expect(note).to_have_attribute("role", "status")
    expect(note).to_be_visible()
    if viewport == "phone":
        _fits(page, "#login-submit")
        _fits(page, "#login-loading-note")
        assert page.evaluate("() => document.documentElement.scrollWidth <= window.innerWidth")
    # Pressed again while it waits: still one sign-in, sent later.
    page.locator("#password").press("Enter", no_wait_after=True)
    button.click(no_wait_after=True)
    page.wait_for_timeout(1500)
    assert s.logins == [], "a sign-in left before the page could send it"
    assert page.url == s.home

    s.release()
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=30000)
    page.wait_for_timeout(1000)
    assert len(s.logins) == 1, s.logins
    assert admin_creds["password"] in s.logins[0], "the sign-in sent was not the one typed"
    typed = (admin_creds["username"], admin_creds["password"])
    assert [u for u in s.urls if any(t in u for t in typed)] == [], "something typed went into an address"
    assert page.url.split("#")[0] == s.home


def test_a_held_sign_in_is_sent_with_what_the_fields_hold_when_the_page_is_ready(page: Page, slow, admin_creds):
    """Typed wrong, sent, then put right before the page was ready: the corrected one is sent, once."""
    s = slow("v2", DESKTOP)
    page.fill("#username", admin_creds["username"])
    page.fill("#password", "not-the-password-0f3a")
    page.locator("#password").press("Enter", no_wait_after=True)
    expect(page.locator("#login-loading-note")).to_have_text(NOTE)
    page.fill("#password", admin_creds["password"])
    s.release()
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=30000)
    page.wait_for_timeout(1000)
    assert len(s.logins) == 1 and admin_creds["password"] in s.logins[0], s.logins


def test_a_held_sign_in_whose_field_was_emptied_meanwhile_is_not_sent(page: Page, slow, admin_creds):
    """Held, then the password cleared before the page was ready: nothing is sent, and the field says it is
    needed, as a press of Sign in with it empty would."""
    s = slow("v2", DESKTOP)
    page.fill("#username", admin_creds["username"])
    page.fill("#password", admin_creds["password"])
    page.locator("#password").press("Enter", no_wait_after=True)
    expect(page.locator("#login-loading-note")).to_have_text(NOTE)
    page.fill("#password", "")
    s.release()
    expect(page.locator("#login-submit")).to_have_text("Sign in", timeout=30000)
    page.wait_for_timeout(1500)
    assert s.logins == [], s.logins
    assert page.evaluate("() => document.getElementById('password').validationMessage"), "the field says nothing"
    expect(page.locator("#dashboard-screen")).to_be_hidden()


def test_a_held_sign_in_that_is_refused_says_why(page: Page, slow):
    s = slow("v1", DESKTOP)
    page.fill("#username", "no-such-account-6b1e")
    page.fill("#password", "Not-A-Password-6b1e")
    page.locator("#login-submit").click(no_wait_after=True)
    expect(page.locator("#login-loading-note")).to_have_text(NOTE)
    s.release()
    expect(page.locator("#login-error")).to_be_visible(timeout=30000)
    expect(page.locator("#login-loading-note")).to_have_text("")
    expect(page.locator("#login-submit")).to_have_text("Sign in")
    page.wait_for_timeout(1000)
    assert len(s.logins) == 1, s.logins


@pytest.mark.parametrize("skin", ["v1", "v2"])
def test_once_the_page_has_loaded_the_button_says_sign_in_and_signs_in(page: Page, admin_creds, skin):
    page.add_init_script(f"try {{ localStorage.setItem('ui', '{skin}'); }} catch (e) {{}}")
    page.goto("/")
    expect(page.locator("#login-submit")).to_have_text("Sign in")
    expect(page.get_by_role("button", name="Sign in", exact=True)).to_be_visible()
    page.fill("#username", admin_creds["username"])
    page.fill("#password", admin_creds["password"])
    page.locator("#password").press("Enter")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    expect(page.locator("#login-loading-note")).to_have_text("")
