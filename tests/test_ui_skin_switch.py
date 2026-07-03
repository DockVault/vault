"""UI-skin switch (Classic v1 / Console v2) end-to-end tests.

The app ships two peer skins over the same DOM: redesign.css (v1, default)
and ui-v2.css (v2), selected pre-paint by js/ui-boot.js from localStorage
`ui` and toggled from the profile dropdown (theme.js). These tests pin the
switch mechanics and prove the theme/accent/background axes and the nav
keep working under the new skin.

Each test gets a fresh browser context (pytest-playwright), so localStorage
starts clean and the default-skin assertions are isolated.
"""
import re

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


@pytest.fixture
def logged_in(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    return page


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


def test_default_skin_is_classic(logged_in: Page):
    """Out of the box (empty localStorage) the Classic skin is active."""
    st = _skin_state(logged_in)
    assert st["ui"] is None
    assert st["v1disabled"] is False
    assert st["v2disabled"] is True
    # The switcher shows Classic as selected.
    _open_profile_dropdown(logged_in)
    expect(logged_in.locator('.ui-choice[data-ui-choice="v1"]')).to_have_class(
        re.compile(r"\bselected\b")
    )


def test_switch_to_console_persists_and_back(logged_in: Page):
    """Choosing Console swaps the stylesheet, survives a reload, and the
    switcher can return to Classic."""
    page = logged_in
    _switch_skin(page, "v2")
    st = _skin_state(page)
    assert st["ui"] == "v2"
    assert st["v2disabled"] is False and st["v1disabled"] is True

    # Persistence: a hard reload keeps the Console skin.
    page.reload(wait_until="load")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    st = _skin_state(page)
    assert st["ui"] == "v2" and st["v2disabled"] is False

    # The switcher reflects the choice and can switch back.
    _open_profile_dropdown(page)
    expect(page.locator('.ui-choice[data-ui-choice="v2"]')).to_have_class(
        re.compile(r"\bselected\b")
    )
    with page.expect_navigation(wait_until="load", timeout=15000):
        page.click('.ui-choice[data-ui-choice="v1"]')
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    st = _skin_state(page)
    assert st["ui"] is None
    assert st["v1disabled"] is False and st["v2disabled"] is True


def test_console_keeps_theme_accent_and_background_axes(logged_in: Page):
    """Dark/light, accent and background pickers still work under Console."""
    page = logged_in
    _switch_skin(page, "v2")

    # Dark theme applies and repaints the page charcoal (v2 dark surface-1).
    page.evaluate("localStorage.setItem('theme','light')")
    page.reload(wait_until="load")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    light_bg = page.evaluate("getComputedStyle(document.body).backgroundColor")
    page.click("#theme-toggle")
    assert page.get_attribute("html", "data-theme") == "dark"
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
    navy_bg = page.evaluate("getComputedStyle(document.body).backgroundColor")
    assert navy_bg != dark_bg

    # All three axes persist together with the skin across a reload.
    page.reload(wait_until="load")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    html = page.locator("html")
    expect(html).to_have_attribute("data-ui", "v2")
    expect(html).to_have_attribute("data-theme", "dark")
    expect(html).to_have_attribute("data-accent", "indigo")
    expect(html).to_have_attribute("data-bg", "navy")


def test_console_nav_sections_still_work(logged_in: Page):
    """Under Console every sidebar section still activates its view, and the
    injected rail group labels are presentational extras."""
    page = logged_in
    _switch_skin(page, "v2")

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
