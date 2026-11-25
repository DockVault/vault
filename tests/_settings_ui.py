"""The Settings pages in the browser, for a test that works with one of them.

While Settings is open the side rail (the drawer on a phone) is the settings menu (static/js/settings-menu.js):
Back, the title, the one Advanced switch (static/js/settings-levels.js), and the pages, each a button with
its page's data-tab. The page's own list of buttons stays in #settings-section, hidden."""
import re

from playwright.sync_api import Page, expect

MENU = "#sidebar .sidebar-settings-nav"
SWITCH = "#settings-advanced-switch"


def is_phone(page: Page) -> bool:
    """Whether the sidebar is a drawer at this width (mobile.css), opened by the top bar's menu button."""
    return page.evaluate("() => matchMedia('(max-width: 860px)').matches")


def open_drawer(page: Page) -> None:
    """On a phone, open the sidebar drawer (a wide screen's rail is always there)."""
    if not is_phone(page):
        return
    toggle = page.locator("#mobile-nav-toggle")
    if toggle.get_attribute("aria-expanded") != "true":
        toggle.click()
    expect(toggle).to_have_attribute("aria-expanded", "true")


def close_drawer(page: Page) -> None:
    """On a phone, close the drawer and wait for it to slide out."""
    if not is_phone(page):
        return
    if page.locator("#mobile-nav-toggle").get_attribute("aria-expanded") == "true":
        page.keyboard.press("Escape")
    page.wait_for_function("() => getComputedStyle(document.getElementById('sidebar')).visibility === 'hidden'")


def open_settings(page: Page) -> None:
    """Open Settings from the sidebar, unless it is open already (while Settings is open the rail shows the
    settings menu, not the Settings item). A reload restores the section it was on: leave Settings first
    (leave_settings) for a reload that should land elsewhere."""
    section = page.locator("#settings-section")
    if section.is_visible():
        return
    open_drawer(page)
    page.click('.sidebar-item[data-section="settings"]')
    expect(section).to_be_visible(timeout=10000)
    close_drawer(page)


def settings_item(page: Page, tab: str):
    """The settings menu's item for the Settings page ``tab`` (its data-tab name)."""
    return page.locator(f'{MENU} .sidebar-settings-item[data-tab="{tab}"]')


def open_settings_page(page: Page, tab: str) -> None:
    """Open the Settings page ``tab`` from the settings menu (in the drawer on a phone), Settings being open."""
    open_drawer(page)
    settings_item(page, tab).click()
    expect(page.locator(f"#settings-tab-{tab}")).to_have_class(re.compile(r"\bactive\b"))
    close_drawer(page)


def leave_settings(page: Page) -> None:
    """Leave Settings by the menu's Back button; the rail shows the sections again."""
    open_drawer(page)
    page.locator(f"{MENU} .sidebar-back").click()
    expect(page.locator("#settings-section")).to_be_hidden()
    close_drawer(page)


def show_advanced(page: Page, tab: str = "") -> None:
    """Turn the Advanced switch on (it shows the advanced settings on every page), Settings being open. A switch
    already on is left as it is. ``tab``, a page's data-tab name, is kept for the callers that name the page
    they work on: once the switch is on, none of that page's settings is hidden by its level."""
    switch = page.locator(SWITCH)
    if switch.get_attribute("aria-checked") != "true":
        open_drawer(page)
        switch.click()
        close_drawer(page)
    expect(switch).to_have_attribute("aria-checked", "true")
    if tab:
        expect(page.locator(f"#settings-tab-{tab} .setting-level-hidden")).to_have_count(0)
