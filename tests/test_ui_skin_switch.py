"""UI-skin switch (Classic v1 / Console v2) end-to-end tests.

The app ships two peer skins over the same DOM: ui-v2.css (v2 "Console", the
DEFAULT) and redesign.css (v1 "Classic"), selected pre-paint by js/ui-boot.js
from localStorage `ui` and toggled from the profile dropdown (theme.js). The
choice — and the theme/accent/background axes — also persist server-side per
account (GET/PUT /users/me/preferences) so they follow the user across devices.

Each test gets a fresh browser context (pytest-playwright) AND a fresh throwaway
user (no saved server preferences), so the default-skin assertions are isolated
from state other tests may have persisted for the shared admin account.
"""
import re

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui


def _submit_login(page: Page, username: str, password: str):
    """Fill + submit the login form (login screen already visible)."""
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _login(page: Page, username: str, password: str):
    page.goto("/")
    _submit_login(page, username, password)


@pytest.fixture
def fresh_user(admin):
    """A throwaway non-admin user with NO saved preferences, deleted on teardown."""
    u = admin.create_user(role="user")
    yield u
    admin.delete_user(u["id"])


@pytest.fixture
def fresh_admin(admin):
    """A throwaway ADMIN user (for tests needing admin-only sidebar sections),
    with no saved preferences so the default skin is deterministic."""
    u = admin.create_user(role="admin")
    yield u
    admin.delete_user(u["id"])


@pytest.fixture
def logged_in(page: Page, fresh_user):
    _login(page, fresh_user["_username"], fresh_user["_password"])
    return page


def _wait_server_prefs(page: Page, timeout: int = 8000, **expected):
    """Wait until the server has persisted the expected preferences. Preference PUTs
    are fire-and-forget from the client, so a fresh-device reload must not race them."""
    page.wait_for_function(
        """async (exp) => {
            const t = localStorage.getItem('authToken'); if (!t) return false;
            const r = await fetch('/users/me/preferences', { headers: { Authorization: 'Bearer ' + t } });
            if (!r.ok) return false;
            const p = await r.json();
            return Object.keys(exp).every(k => p[k] === exp[k]);
        }""",
        arg=expected, timeout=timeout,
    )


def _skin_state(page: Page):
    return page.evaluate(
        """() => ({
            ui: document.documentElement.getAttribute('data-ui'),
            v1disabled: document.getElementById('skin-v1').disabled,
            v2disabled: document.getElementById('skin-v2').disabled,
        })"""
    )


def _open_profile_dropdown(page: Page):
    page.click("#profile-btn")
    expect(page.locator(".profile-menu.active")).to_be_visible()


def _switch_skin(page: Page, choice: str):
    _open_profile_dropdown(page)
    with page.expect_navigation(wait_until="load", timeout=15000):
        page.click(f'.ui-choice[data-ui-choice="{choice}"]')
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def test_default_skin_is_console(logged_in: Page):
    """Out of the box (fresh account, empty localStorage) the Console skin is active."""
    st = _skin_state(logged_in)
    assert st["ui"] == "v2"
    assert st["v2disabled"] is False
    assert st["v1disabled"] is True
    # The switcher shows Console as selected.
    _open_profile_dropdown(logged_in)
    expect(logged_in.locator('.ui-choice[data-ui-choice="v2"]')).to_have_class(
        re.compile(r"\bselected\b")
    )


def test_switch_to_classic_persists_and_back(logged_in: Page):
    """Choosing Classic swaps the stylesheet, survives a reload, and the
    switcher can return to Console."""
    page = logged_in
    _switch_skin(page, "v1")
    st = _skin_state(page)
    assert st["ui"] is None
    assert st["v1disabled"] is False and st["v2disabled"] is True

    # Persistence: a hard reload keeps the Classic skin.
    page.reload(wait_until="load")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    st = _skin_state(page)
    assert st["ui"] is None and st["v1disabled"] is False

    # The switcher reflects the choice and can switch back to Console.
    _open_profile_dropdown(page)
    expect(page.locator('.ui-choice[data-ui-choice="v1"]')).to_have_class(
        re.compile(r"\bselected\b")
    )
    with page.expect_navigation(wait_until="load", timeout=15000):
        page.click('.ui-choice[data-ui-choice="v2"]')
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    st = _skin_state(page)
    assert st["ui"] == "v2"
    assert st["v2disabled"] is False and st["v1disabled"] is True


def test_skin_syncs_from_server_on_fresh_device(page: Page, fresh_user):
    """A skin choice saved on one device is applied on a brand-new device (empty
    localStorage) via the server preference — the cross-device sync contract."""
    u, p = fresh_user["_username"], fresh_user["_password"]
    _login(page, u, p)
    _switch_skin(page, "v1")            # persists ui=v1 to the server
    assert _skin_state(page)["ui"] is None
    _wait_server_prefs(page, ui="v1")   # ensure the PUT landed before wiping local state

    # Simulate a brand-new device: wipe ALL local state, then log in again.
    page.evaluate("localStorage.clear(); sessionStorage.clear();")
    page.reload(wait_until="load")
    _submit_login(page, u, p)

    # Despite empty localStorage, the server preference (Classic) is applied.
    assert _skin_state(page)["ui"] is None


def test_theme_accent_background_sync_from_server(page: Page, fresh_user):
    """Theme/accent/background chosen on one device are restored on a fresh one."""
    u, p = fresh_user["_username"], fresh_user["_password"]
    _login(page, u, p)

    # Deterministically set DARK: ensure light first so the toggle definitely flips to
    # (and persists) dark regardless of the test browser's default color scheme — a bare
    # "if != dark: toggle" would no-op on a dark-defaulting browser and persist nothing.
    if page.get_attribute("html", "data-theme") != "light":
        page.click("#theme-toggle")
    assert page.get_attribute("html", "data-theme") == "light"
    page.click("#theme-toggle")
    assert page.get_attribute("html", "data-theme") == "dark"
    _open_profile_dropdown(page)
    page.click('.accent-swatch[data-accent="indigo"]')
    page.click('.bg-swatch[data-bg="navy"]')
    assert page.get_attribute("html", "data-accent") == "indigo"
    assert page.get_attribute("html", "data-bg") == "navy"

    # Ensure all three actually reached the server before wiping local state (the PUTs are
    # fire-and-forget, so a bare reload would race them).
    _wait_server_prefs(page, theme="dark", accent="indigo", background="navy")

    # Fresh device (Chromium headless defaults to LIGHT, so dark can only come from the
    # server): clear local state, log in again — the server restores all three.
    page.evaluate("localStorage.clear(); sessionStorage.clear();")
    page.reload(wait_until="load")
    _submit_login(page, u, p)
    html = page.locator("html")
    expect(html).to_have_attribute("data-theme", "dark")
    expect(html).to_have_attribute("data-accent", "indigo")
    expect(html).to_have_attribute("data-bg", "navy")


def test_console_keeps_theme_accent_and_background_axes(logged_in: Page):
    """Dark/light, accent and background pickers still work under Console (default)."""
    page = logged_in
    assert _skin_state(page)["ui"] == "v2"  # Console is the default now

    # Start from a known light theme, capture its background, then toggle to dark.
    if page.get_attribute("html", "data-theme") != "light":
        page.click("#theme-toggle")
    assert page.get_attribute("html", "data-theme") == "light"
    light_bg = page.evaluate("getComputedStyle(document.body).backgroundColor")
    page.click("#theme-toggle")
    assert page.get_attribute("html", "data-theme") == "dark"
    # Wait out the background-color transition before comparing (getComputedStyle
    # returns the mid-transition value otherwise).
    page.wait_for_function(
        "prev => getComputedStyle(document.body).backgroundColor !== prev",
        arg=light_bg, timeout=3000,
    )
    dark_bg = page.evaluate("getComputedStyle(document.body).backgroundColor")
    assert dark_bg != light_bg

    # Accent picker: choosing indigo re-tints the brand token.
    _open_profile_dropdown(page)
    page.click('.accent-swatch[data-accent="indigo"]')
    assert page.get_attribute("html", "data-accent") == "indigo"
    brand = page.evaluate(
        "getComputedStyle(document.documentElement).getPropertyValue('--brand-secondary').trim()"
    )
    assert brand == "#818cf8"  # v2 dark indigo

    # Background picker: navy retints the surface ramp.
    page.click('.bg-swatch[data-bg="navy"]')
    assert page.get_attribute("html", "data-bg") == "navy"
    page.wait_for_function(
        "prev => getComputedStyle(document.body).backgroundColor !== prev",
        arg=dark_bg, timeout=3000,
    )
    navy_bg = page.evaluate("getComputedStyle(document.body).backgroundColor")
    assert navy_bg != dark_bg

    # All axes persist together with the skin across a reload.
    page.reload(wait_until="load")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    html = page.locator("html")
    expect(html).to_have_attribute("data-ui", "v2")
    expect(html).to_have_attribute("data-theme", "dark")
    expect(html).to_have_attribute("data-accent", "indigo")
    expect(html).to_have_attribute("data-bg", "navy")


def test_console_nav_sections_still_work(page: Page, fresh_admin):
    """Under Console every sidebar section still activates its view, and the
    injected rail group labels are presentational extras."""
    _login(page, fresh_admin["_username"], fresh_admin["_password"])
    assert _skin_state(page)["ui"] == "v2"

    labels = page.eval_on_selector_all(
        ".nav-group-label", "els => els.map(e => e.textContent)"
    )
    assert labels == ["Overview", "Storage", "Access", "System"]

    for section in ["vaults", "temp-creds", "users", "groups", "monitor",
                    "settings", "dashboard"]:
        page.evaluate(
            f"document.querySelector('.sidebar-item[data-section=\"{section}\"]').click()"
        )
        expect(page.locator(f"#{section}-section")).to_be_visible()
        assert "active" in page.get_attribute(
            f'.sidebar-item[data-section="{section}"]', "class"
        )
