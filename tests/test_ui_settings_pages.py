"""Settings you can find: while Settings is open the side rail is the settings menu (static/js/settings-menu.js),
the pages under six headings (a sixth, Sign-in, hidden until it has a page), with Back to the section open before
and the Advanced switch in its head. The page's own list stays in the page, hidden at every width, and the open
page takes the full width. On a phone the drawer shows the same menu. A long help text says one sentence, with
the rest under "More"."""
import re

import pytest
from playwright.sync_api import Page, expect

from _settings_ui import MENU, close_drawer, leave_settings, open_drawer, settings_item

pytestmark = pytest.mark.ui

GROUPS = ["Organisation", "Security and access", "Sharing and links", "Email", "Records", "Sign-in"]


def _login(page: Page, admin_creds):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", admin_creds["username"])
    page.fill("#password", admin_creds["password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    open_drawer(page)
    page.click('.sidebar-item[data-section="settings"]')
    expect(page.locator("#save-all-settings-btn")).to_have_attribute("data-settings-ready", "true", timeout=15000)
    close_drawer(page)


@pytest.mark.parametrize("skin", ["v1", "v2"])
def test_the_rail_is_the_settings_menu_under_six_headings(page: Page, admin_creds, skin):
    page.set_viewport_size({"width": 1280, "height": 900})
    page.goto("/")
    page.evaluate("ui => localStorage.setItem('ui', ui)", skin)
    _login(page, admin_creds)
    menu = page.locator(MENU)
    expect(menu).to_be_visible()
    expect(menu).to_have_attribute("aria-label", "Settings")
    # The sections' menu is gone while Settings is open.
    expect(page.locator('.sidebar-item[data-section="dashboard"]')).to_be_hidden()
    expect(menu.locator(".sidebar-settings-title")).to_have_text("Settings")
    expect(page.locator("#sidebar-settings-back")).to_have_accessible_name("Back")
    titles = [t.strip() for t in menu.locator(".sidebar-settings-group:not([hidden]) .nav-group-label").all_text_contents()]
    assert [t.lower() for t in titles] == [g.lower() for g in GROUPS], titles   # drawn in capitals
    expect(settings_item(page, "signin")).to_have_text("Sign-in methods")
    expect(menu.locator(".sidebar-settings-item")).to_have_count(13)
    # The items have no icons, and the open page is marked.
    expect(menu.locator(".sidebar-settings-item .sidebar-icon")).to_have_count(0)
    expect(settings_item(page, "general")).to_have_class(re.compile(r"\bactive\b"))
    expect(settings_item(page, "general")).to_have_attribute("aria-current", "page")
    # The page's own list is hidden, and the open page takes the section's width.
    expect(page.locator("#settings-section .settings-nav")).to_be_hidden()
    section = page.locator("#settings-section").bounding_box()
    general = page.locator("#settings-tab-general").bounding_box()
    assert abs(general["x"] - section["x"]) < 2 and abs(general["width"] - section["width"]) < 2, (section, general)
    # Every page still opens by its item, from any group; the menu follows.
    settings_item(page, "email").click()
    expect(page.locator("#settings-tab-email")).to_be_visible()
    expect(page.locator("#settings-tab-general")).to_be_hidden()
    expect(settings_item(page, "email")).to_have_attribute("aria-current", "page")
    expect(settings_item(page, "general")).not_to_have_attribute("aria-current", "page")
    assert menu.locator(".sidebar-settings-item[aria-current=page]").count() == 1
    settings_item(page, "logs").click()
    expect(page.locator("#settings-tab-logs")).to_be_visible()


def test_back_returns_to_the_section_open_before_settings(page: Page, admin_creds):
    page.set_viewport_size({"width": 1280, "height": 900})
    _login(page, admin_creds)
    leave_settings(page)
    expect(page.locator("#dashboard-section")).to_be_visible()
    page.click('.sidebar-item[data-section="vaults"]')
    expect(page.locator("#vaults-section")).to_be_visible(timeout=10000)
    page.click('.sidebar-item[data-section="settings"]')
    expect(page.locator(MENU)).to_be_visible()
    # Focus moves into the menu, to the open page.
    expect(settings_item(page, "general")).to_be_focused()
    page.click("#sidebar-settings-back")
    expect(page.locator("#vaults-section")).to_be_visible(timeout=10000)
    expect(page.locator(MENU)).to_be_hidden()
    expect(page.locator('.sidebar-item[data-section="vaults"]')).to_be_visible()
    expect(page.locator('.sidebar-item[data-section="vaults"]')).to_be_focused()


def test_a_hidden_group_stays_hidden_in_the_menu(page: Page, admin_creds):
    page.set_viewport_size({"width": 1280, "height": 900})
    _login(page, admin_creds)
    group = page.locator(f'{MENU} .sidebar-settings-group[data-settings-group="email"]')
    expect(group).to_be_visible()
    page.evaluate("() => { document.querySelector('#settings-section [data-settings-group=\"email\"]').hidden = true; }")
    expect(group).to_be_hidden()
    page.evaluate("() => { document.querySelector('#settings-section [data-settings-group=\"email\"]').hidden = false; }")
    expect(group).to_be_visible()


def test_a_rail_saved_collapsed_opens_in_full_in_settings(page: Page, admin_creds):
    page.set_viewport_size({"width": 1280, "height": 900})
    page.goto("/")
    page.evaluate("() => localStorage.setItem('sidebarCollapsed', 'true')")
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", admin_creds["username"])
    page.fill("#password", admin_creds["password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    sidebar = page.locator("#sidebar")
    expect(sidebar).to_have_class(re.compile(r"\bcollapsed\b"))
    page.click('.sidebar-item[data-section="settings"]')
    expect(page.locator(MENU)).to_be_visible()
    expect(sidebar).not_to_have_class(re.compile(r"\bcollapsed\b"))
    expect(settings_item(page, "general")).to_be_visible()
    page.click("#sidebar-settings-back")
    expect(page.locator("#dashboard-section")).to_be_visible()
    expect(sidebar).to_have_class(re.compile(r"\bcollapsed\b"))   # as saved
    page.evaluate("() => localStorage.removeItem('sidebarCollapsed')")


def test_a_phone_shows_the_same_menu_in_the_drawer(page: Page, admin_creds):
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto("/")
    page.evaluate("() => localStorage.setItem('ui', 'v2')")
    _login(page, admin_creds)
    nav = page.locator("#settings-section .settings-nav")
    expect(nav).to_be_hidden()
    open_drawer(page)
    menu = page.locator(MENU)
    expect(menu).to_be_visible()
    expect(page.locator('.sidebar-item[data-section="dashboard"]')).to_be_hidden()
    expect(menu.locator(".sidebar-settings-item")).to_have_count(13)
    for part in ("#sidebar-settings-back", "#settings-advanced-switch"):
        expect(page.locator(part)).to_be_visible()
    # Choosing a page opens it and closes the drawer.
    settings_item(page, "email").click()
    page.wait_for_function("() => getComputedStyle(document.getElementById('sidebar')).visibility === 'hidden'")
    expect(page.locator("#settings-tab-email")).to_be_visible()
    expect(page.locator("#mobile-nav-toggle")).to_have_attribute("aria-expanded", "false")
    assert page.evaluate("() => document.documentElement.scrollWidth") <= 391


def test_long_help_texts_say_one_sentence_with_the_rest_under_more(page: Page, admin_creds):
    page.set_viewport_size({"width": 1280, "height": 900})
    _login(page, admin_creds)
    # Nothing in Settings shows more than forty words of help at once: every help-like text (the paragraph
    # under a setting, a <small> hint, an email hint) on every page, as Settings has drawn it, More closed.
    counts = page.evaluate(
        "() => { const SEL = '#settings-section .form-help, #settings-section p.text-secondary,"
        "                      #settings-section small, #settings-section .email-hint';"
        "  const helps = [...document.querySelectorAll(SEL)].filter(el => !el.closest('.help-more')"
        "      && !el.querySelector('.form-help, p.text-secondary, small, .email-hint'));"
        "  const shown = el => [...el.childNodes].filter(c => !(c.nodeType === 1 && c.classList.contains('help-more')))"
        "      .map(c => c.textContent).join('');"
        "  const words = t => t.trim().split(/\\s+/).filter(Boolean).length;"
        "  return { all: helps.length, split: helps.filter(el => el.querySelector('.help-more')).length,"
        "           tooLong: helps.filter(el => words(shown(el)) > 40).map(el => shown(el).trim().slice(0, 80)) }; }")
    assert counts["all"] > 50, counts              # the check reaches the Settings markup, not one class
    assert counts["split"] >= 10, counts           # the page shortened the long ones itself, on opening
    assert counts["tooLong"] == [], counts["tooLong"]
    # A split keeps its markup: code spans and bold words still sit in the part under More.
    assert page.evaluate(
        "() => document.querySelectorAll('#settings-section .help-more-text code,"
        " #settings-section .help-more-text strong').length") > 0
    # The rule itself, on a help text that has more to say than one sentence.
    page.evaluate(
        "() => { const el = document.createElement('small'); el.className = 'form-help'; el.id = 'probe-help';"
        "  el.textContent = 'Keep this on for everyday use. ' + Array.from({length: 45}, (_, i) => 'word' + i).join(' ') + '. Turn it off only when a tool of yours cannot follow it.';"
        "  document.querySelector('#settings-tab-general .card .p-lg').appendChild(el); SettingsHelp.shorten(); }")
    probe = page.locator("#probe-help")
    expect(probe.locator("details.help-more")).to_have_count(1)
    expect(probe).to_contain_text("Keep this on for everyday use.")
    summary = probe.locator("details.help-more > summary")
    expect(summary).to_have_text("More")
    assert not page.evaluate("() => document.querySelector('#probe-help details').open")
    summary.click()
    assert page.evaluate("() => document.querySelector('#probe-help details').open")
    expect(probe.locator(".help-more-text")).to_contain_text("Turn it off only when")
    # Shortened once: a second pass changes nothing.
    assert page.evaluate("() => SettingsHelp.shorten()") == 0


def test_the_page_list_is_a_group_of_buttons_and_marks_the_open_page(page: Page, admin_creds):
    """Not a tab list: a labelled group of plain buttons; the open page's button says so with aria-current. The
    menu's items click these buttons, so they still mark the open page."""
    page.set_viewport_size({"width": 1280, "height": 900})
    _login(page, admin_creds)
    nav = page.locator("#settings-section .settings-nav")
    expect(nav).to_have_attribute("role", "group")
    expect(nav).to_have_attribute("aria-label", "Settings pages")
    assert page.locator("#settings-section [role=tablist], #settings-section [role=tab]").count() == 0
    assert page.locator(f"{MENU} [role=tablist], {MENU} [role=tab]").count() == 0
    general = nav.locator('.tab-btn[data-tab="general"]')
    email = nav.locator('.tab-btn[data-tab="email"]')
    expect(general).to_have_attribute("aria-current", "page")
    settings_item(page, "email").click()
    expect(email).to_have_attribute("aria-current", "page")
    expect(general).not_to_have_attribute("aria-current", "page")
    assert nav.locator(".tab-btn[aria-current=page]").count() == 1
    # The email editor's Code / Render / Split switch is a group of toggle buttons too.
    toggle = page.locator("#settings-tab-email .et-view-toggle")
    expect(toggle).to_have_attribute("role", "group")
    expect(toggle.locator('.et-view[data-view="code"]')).to_have_attribute("aria-pressed", "true")


@pytest.mark.parametrize("section,attr,second", [
    ("shared", "data-shared-tab", "by-me"),
    ("notes", "data-notes-tab", "received"),
    ("uploadlinks", "data-rc-tab", "vaults"),
])
def test_the_other_page_strips_mark_the_open_page_too(page: Page, admin_creds, section, attr, second):
    page.set_viewport_size({"width": 1280, "height": 900})
    _login(page, admin_creds)
    leave_settings(page)   # the rail shows the sections again
    item = page.locator(f'.sidebar-item[data-section="{section}"]')
    if not item.is_visible():
        pytest.skip(f"the {section} page is not offered on this install")
    item.click()
    strip = page.locator(f"#{section}-section .tabs").first
    expect(strip).to_have_attribute("role", "group")
    assert strip.get_attribute("aria-label")
    assert page.locator(f"#{section}-section [role=tablist]").count() == 0
    other = strip.locator(f'.tab-btn[{attr}="{second}"]')
    other.click()
    expect(other).to_have_attribute("aria-current", "page")
    assert strip.locator(".tab-btn[aria-current=page]").count() == 1
