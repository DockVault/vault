"""Settings you can find: on a wide screen the pages are a list at the left under five headings (a sixth,
Sign-in, hidden until it has a page), the open page beside it; on a phone the same buttons are the strip and the
headings are not shown. A long help text says one sentence, with the rest under "More"."""
import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

GROUPS = ["Organisation", "Security and access", "Sharing and links", "Email", "Records"]


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
def test_wide_screens_list_the_pages_at_the_left_under_five_headings(page: Page, admin_creds, skin):
    page.set_viewport_size({"width": 1280, "height": 900})
    page.goto("/")
    page.evaluate("ui => localStorage.setItem('ui', ui)", skin)
    _login(page, admin_creds)
    nav = page.locator("#settings-section .settings-nav")
    titles = [t.strip() for t in nav.locator(".settings-nav-group:not([hidden]) .settings-nav-title").all_text_contents()]  # drawn in capitals
    assert titles == GROUPS, titles
    expect(nav.locator('.settings-nav-group[data-settings-group="signin"]')).to_be_hidden()
    assert nav.locator(".tab-btn").count() == 12
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
    # Nothing in Settings shows more than forty words of help at once.
    too_long = page.evaluate(
        "() => [...document.querySelectorAll('#settings-section .form-help')]"
        "  .map(el => { const d = el.querySelector('.help-more'); const shown = d ? el.textContent.replace(d.textContent, '') : el.textContent;"
        "              return shown.trim().split(/\\s+/).filter(Boolean).length; })"
        "  .filter(n => n > 40)")
    assert too_long == [], too_long
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
