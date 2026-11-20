"""Settings you can find: on a wide screen the pages are a list at the left under five headings (a sixth,
Sign-in, hidden until it has a page), the open page beside it; on a phone the same buttons are the strip and the
headings are not shown. A long help text says one sentence, with the rest under "More"."""
import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

GROUPS = ["Organisation", "Security and access", "Sharing and links", "Email", "Records", "Sign-in"]


def _login(page: Page, admin_creds):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", admin_creds["username"])
    page.fill("#password", admin_creds["password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    page.click('.sidebar-item[data-section="settings"]')
    expect(page.locator("#save-all-settings-btn")).to_have_attribute("data-settings-ready", "true", timeout=15000)


@pytest.mark.parametrize("skin", ["v1", "v2"])
def test_wide_screens_list_the_pages_at_the_left_under_six_headings(page: Page, admin_creds, skin):
    page.set_viewport_size({"width": 1280, "height": 900})
    page.goto("/")
    page.evaluate("ui => localStorage.setItem('ui', ui)", skin)
    _login(page, admin_creds)
    nav = page.locator("#settings-section .settings-nav")
    titles = [t.strip() for t in nav.locator(".settings-nav-group:not([hidden]) .settings-nav-title").all_text_contents()]  # drawn in capitals
    assert titles == GROUPS, titles
    expect(nav.locator('.settings-nav-group[data-settings-group="signin"] .tab-btn')).to_have_text("Sign-in methods")
    assert nav.locator(".tab-btn").count() == 13
    # The list is at the left of the open page, both starting at the same height.
    nav_box = nav.bounding_box()
    page_box = page.locator("#settings-tab-general").bounding_box()
    assert nav_box and page_box
    assert nav_box["x"] + nav_box["width"] <= page_box["x"] + 1, (nav_box, page_box)
    assert abs(nav_box["y"] - page_box["y"]) < 8, (nav_box, page_box)
    # Every page still opens by its button, from any group, and the search still lands on it.
    page.click('#settings-section .tab-btn[data-tab="email"]')
    expect(page.locator("#settings-tab-email")).to_be_visible()
    expect(page.locator("#settings-tab-general")).to_be_hidden()
    email_box = page.locator("#settings-tab-email").bounding_box()
    assert email_box["x"] >= nav_box["x"] + nav_box["width"] - 1
    page.click('#settings-section .tab-btn[data-tab="logs"]')
    expect(page.locator("#settings-tab-logs")).to_be_visible()


def test_a_phone_keeps_the_strip_without_headings(page: Page, admin_creds):
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto("/")
    page.evaluate("() => localStorage.setItem('ui', 'v2')")
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", admin_creds["username"])
    page.fill("#password", admin_creds["password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    drawer = page.locator("#mobile-nav-toggle")
    if drawer.is_visible():
        drawer.click()
    page.click('.sidebar-item[data-section="settings"]')
    expect(page.locator("#save-all-settings-btn")).to_have_attribute("data-settings-ready", "true", timeout=15000)
    nav = page.locator("#settings-section .settings-nav")
    for title in nav.locator(".settings-nav-title").all():
        expect(title).to_be_hidden()
    first = nav.locator(".tab-btn").nth(0).bounding_box()
    second = nav.locator(".tab-btn").nth(1).bounding_box()
    assert first and second and abs(first["y"] - second["y"]) < 2 and second["x"] > first["x"], (first, second)
    # The page sits under the strip, not beside it.
    strip = nav.bounding_box()
    body = page.locator("#settings-tab-general").bounding_box()
    assert body["y"] >= strip["y"] + strip["height"] - 1


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


def test_the_page_strip_is_a_group_of_buttons_and_marks_the_open_page(page: Page, admin_creds):
    """Not a tab list: a labelled group of plain buttons; the open page's button says so with aria-current."""
    page.set_viewport_size({"width": 1280, "height": 900})
    _login(page, admin_creds)
    nav = page.locator("#settings-section .settings-nav")
    expect(nav).to_have_attribute("role", "group")
    expect(nav).to_have_attribute("aria-label", "Settings pages")
    assert page.locator("#settings-section [role=tablist], #settings-section [role=tab]").count() == 0
    general = nav.locator('.tab-btn[data-tab="general"]')
    email = nav.locator('.tab-btn[data-tab="email"]')
    expect(general).to_have_attribute("aria-current", "page")
    email.click()
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
