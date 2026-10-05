"""A form sent before the web app has loaded never puts what was typed into an address.

app.js binds every form's submit handler and loads at the end of <body>; until it has run, the
sign-in screen is on screen and usable. These tests hold app.js back (a route that is not answered
while the form is sent), send the sign-in, sign-up and password-reset forms, and check that no
request carries the typed values, in its address or its body, and that the page does not move.
Then app.js is let through and signing in works as usual. With scripts off the sign-in goes out
as a POST to the page: nothing typed lands in an address, and the server refuses it without
sending any of it back.

What keeps the values in: a capture-phase submit listener that static/js/auth-boot.js installs from
<head>, and method="post" on every form (tests/test_forms_never_sent_by_the_browser.py pins both
without a browser).
"""
import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

USER = "early-user-5d2f"
SECRET = "Early-Secret-81c7-qx"
EMAIL = "early-5d2f@example.com"
TYPED = (USER, SECRET, EMAIL)

# Records each submit event that reaches the window (after the document's listeners), so a test
# knows the browser really tried to send the form and the check below is not vacuous.
_COUNT_SUBMITS = "window.__submits = []; window.addEventListener('submit', e => window.__submits.push(e.target.id));"


class _AppHeld:
    """Holds every request for app.js until release(), and records requests and page moves."""

    def __init__(self, page: Page):
        self.page = page
        self.routes = []
        self.requests = []
        self.moves = []
        page.on("request", lambda r: self.requests.append((r.method, r.url, r.post_data or "")))
        page.on("framenavigated", lambda f: f == page.main_frame and self.moves.append(f.url))
        page.route("**/static/js/app.js*", lambda route: self.routes.append(route))

    def open(self, base_url: str):
        self.home = base_url.rstrip("/") + "/"
        self.page.goto(self.home, wait_until="commit")
        expect(self.page.locator("#login-form")).to_be_visible(timeout=30000)
        for _ in range(150):
            if self.routes:
                break
            self.page.wait_for_timeout(100)
        assert self.routes, "the page never asked for app.js"
        self.page.evaluate(_COUNT_SUBMITS)

    def leaked(self):
        return [(m, u) for m, u, body in self.requests if any(t in u or t in body for t in TYPED)]

    def release(self):
        self.page.unroute("**/static/js/app.js*")
        for route in self.routes:
            try:
                route.continue_()
            except Exception:
                pass
        self.routes = []

    def check_nothing_left(self, form_id: str):
        self.page.wait_for_timeout(1500)  # time for a navigation the browser might start
        assert self.leaked() == [], self.leaked()
        assert [m for m, u, _ in self.requests if m != "GET"] == []
        assert self.page.url == self.home
        assert self.moves == [self.home], self.moves
        # The browser did try to send this form (the submit event fired): the check above is real.
        assert self.page.evaluate("window.__submits") == [form_id]


@pytest.fixture
def held(page: Page, base_url):
    h = _AppHeld(page)
    h.open(base_url)
    try:
        yield h
    finally:
        h.release()


def test_sign_in_before_app_js_sends_nothing_and_works_once_it_loads(page: Page, held, admin_creds):
    page.fill("#username", USER)
    page.fill("#password", SECRET)
    page.click("#login-form button[type=submit]", no_wait_after=True)
    held.check_nothing_left("login-form")

    held.release()
    expect(page.locator("#login-screen")).to_be_visible()
    page.wait_for_load_state("load", timeout=30000)  # app.js (and what follows it) has run
    page.fill("#username", admin_creds["username"])
    page.fill("#password", admin_creds["password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _send_hidden_form(page: Page, form_id: str, values: dict):
    # Sign-up and reset are display:none until app.js shows them; requestSubmit() sends them the
    # way pressing Enter would, constraint checks included.
    page.evaluate("""([id, values]) => {
        for (const [field, v] of Object.entries(values)) document.getElementById(field).value = v;
        document.getElementById(id).requestSubmit();
    }""", [form_id, values])


def test_sign_up_before_app_js_sends_nothing(page: Page, held):
    _send_hidden_form(page, "signup-form", {"signup-username": USER, "signup-email": EMAIL,
                                            "signup-password": SECRET})
    held.check_nothing_left("signup-form")


def test_password_reset_request_before_app_js_sends_nothing(page: Page, held):
    _send_hidden_form(page, "forgot-form", {"forgot-identifier": EMAIL})
    held.check_nothing_left("forgot-form")


def test_with_scripts_off_the_sign_in_goes_out_as_a_post_and_nothing_comes_back(browser, base_url):
    home = base_url.rstrip("/") + "/"
    context = browser.new_context(java_script_enabled=False, base_url=base_url)
    try:
        page = context.new_page()
        sent = []
        page.on("request", lambda r: sent.append((r.method, r.url, r.post_data or "")))
        page.goto(home)
        expect(page.locator("#login-form")).to_be_visible()
        page.fill("#username", USER)
        page.fill("#password", SECRET)
        with page.expect_navigation() as nav:
            page.click("#login-form button[type=submit]")
        posts = [(u, body) for m, u, body in sent if m == "POST"]
        assert len(posts) == 1 and posts[0][0] == home, posts
        assert SECRET in posts[0][1]  # the body, which no address carries
        assert [u for _, u, _ in sent if any(t in u for t in TYPED)] == []
        assert page.url == home
        assert nav.value.status == 405
        assert all(t not in page.content() for t in TYPED)
    finally:
        context.close()
