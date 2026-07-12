"""Auth boot: no flash of the app shell on an expired/again-logged-out load.

auth-boot.js marks <html data-auth="pending"> pre-paint when a token is cached, so
CSS shows a neutral splash; app.js then verifies the token (GET /users/me) and only
reveals the dashboard on success, or routes to login on 401. These tests prove the
dashboard shell is NEVER activated for an expired token (the previous behaviour
briefly showed the app before bouncing to login).
"""
import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

# Records whether #dashboard-screen EVER gained the `active` class during the load.
# Registered as an init script so it runs before app.js on every navigation.
_OBSERVE_DASHBOARD = """
window.__dashEverActive = false;
document.addEventListener('DOMContentLoaded', () => {
    const dash = document.getElementById('dashboard-screen');
    if (!dash) return;
    const check = () => { if (dash.classList.contains('active')) window.__dashEverActive = true; };
    check();
    new MutationObserver(check).observe(dash, { attributes: true, attributeFilter: ['class'] });
});
"""

# Samples every frame whether #login-screen is actually displayed during an
# AUTHENTICATED boot (until the dashboard appears). Catches the regression where the
# splash is released one round-trip too early and the login form flashes on refresh.
_OBSERVE_LOGIN_FLASH = """
window.__loginFlashed = false;
document.addEventListener('DOMContentLoaded', () => {
    const login = document.getElementById('login-screen');
    const dash = document.getElementById('dashboard-screen');
    if (!login || !dash) return;
    let done = false;
    const sample = () => {
        if (done) return;
        if (dash.classList.contains('active')) { done = true; return; }  // boot complete
        if (getComputedStyle(login).display !== 'none') window.__loginFlashed = true;
        requestAnimationFrame(sample);
    };
    requestAnimationFrame(sample);
});
"""


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


@pytest.fixture
def fresh_user(admin):
    u = admin.create_user(role="user")
    yield u
    admin.delete_user(u["id"])


def test_logged_out_first_paint_is_login_no_splash(page: Page):
    """With no cached token, the login screen paints directly — no boot splash."""
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    assert page.get_attribute("html", "data-auth") is None
    expect(page.locator("#dashboard-screen")).to_be_hidden()


def test_expired_token_never_reveals_dashboard(page: Page, fresh_user):
    """An expired cached token routes straight to login and NEVER flashes the app."""
    _login(page, fresh_user["_username"], fresh_user["_password"])

    # Corrupt the token (keep currentUser cached) to simulate expiry, and make the
    # server's verification deterministic with a 401.
    page.evaluate("localStorage.setItem('authToken','expired.invalid.token')")
    page.route(
        "**/users/me",
        lambda route: route.fulfill(
            status=401, content_type="application/json",
            body='{"detail":"Session expired. Please log in again."}',
        ),
    )
    page.add_init_script(_OBSERVE_DASHBOARD)

    page.reload(wait_until="load")
    # Lands on login...
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    expect(page.locator("#dashboard-screen")).to_be_hidden()
    # ...and the dashboard shell was never activated at any point during the boot.
    assert page.evaluate("window.__dashEverActive") is False
    page.unroute("**/users/me")


def test_valid_token_boots_through_splash_to_dashboard(page: Page, fresh_user):
    """A valid cached token boots (via the splash) to the dashboard on reload, with NO
    flash of the login form under the splash."""
    _login(page, fresh_user["_username"], fresh_user["_password"])
    page.add_init_script(_OBSERVE_LOGIN_FLASH)
    # Token is present + valid; a reload restores the dashboard without a login prompt.
    page.reload(wait_until="load")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    expect(page.locator("#login-screen")).to_be_hidden()
    # data-auth is cleared once the dashboard is revealed.
    assert page.get_attribute("html", "data-auth") is None
    # The login screen was never displayed during the authenticated boot (the splash
    # must cover the whole verify + permissions load).
    assert page.evaluate("window.__loginFlashed") is False
