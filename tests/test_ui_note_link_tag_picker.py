"""UI — note-link tag admin: the list shows each tag's colour + icon, and the editor uses a colour
swatch picker + an icon preview grid (not dropdowns)."""
import re

import pytest
from playwright.sync_api import Page, expect

from conftest import unique

pytestmark = pytest.mark.ui


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_notelinks(page: Page):
    page.click('.sidebar-item[data-section="settings"]')
    page.click('#settings-section .tab-btn[data-tab="notelinks"]')
    expect(page.locator("#settings-tab-notelinks")).to_be_visible(timeout=10000)


def test_list_shows_colour_dot_and_icon(page: Page, admin, admin_creds):
    # The seeded "Open" tag has border_color=green + icon=globe.
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_notelinks(page)
    row = page.locator("#nl-tags-list .share-tag-row", has_text="Open")
    expect(row).to_be_visible(timeout=10000)
    expect(row.locator(".nl-color-dot")).to_have_count(1)
    expect(row.locator("svg.icon")).to_have_count(1)  # the tag icon


def test_editor_swatch_and_icon_grid_persist(page: Page, admin, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_notelinks(page)
    name = unique("PickTag")
    page.click("#nl-tag-add-btn")
    expect(page.locator("#nl-tag-editor")).to_be_visible()
    page.fill("#nl-tag-name", name)
    # Colour: click the teal swatch -> hidden input reflects it + swatch is selected.
    page.click('#nl-tag-color-swatches .accent-swatch[data-color="teal"]')
    expect(page.locator("#nl-tag-color")).to_have_value("teal")
    expect(page.locator('#nl-tag-color-swatches .accent-swatch[data-color="teal"]')).to_have_class(
        re.compile(r"\bselected\b"))
    # Icon: click the lock icon-choice -> hidden input reflects it.
    page.click('#nl-tag-icon-grid .icon-choice[data-icon="lock"]')
    expect(page.locator("#nl-tag-icon")).to_have_value("lock")
    # Save -> the API sees the chosen colour + icon.
    page.click("#nl-tag-save-btn")
    expect(page.locator("#nl-tags-list", has_text=name)).to_be_visible(timeout=10000)
    tag = next(t for t in admin.get("/note-link-tags").json() if t["name"] == name)
    assert tag["border_color"] == "teal" and tag["icon"] == "lock"


def test_no_colour_icon_dropdowns_remain(page: Page, admin_creds):
    # The old <select> pickers must be gone (replaced by swatches + grid).
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_notelinks(page)
    page.click("#nl-tag-add-btn")
    expect(page.locator("#nl-tag-editor")).to_be_visible()
    assert page.evaluate("() => document.getElementById('nl-tag-color').tagName") == "INPUT"
    assert page.evaluate("() => document.getElementById('nl-tag-icon').tagName") == "INPUT"
    expect(page.locator("#nl-tag-color-swatches .accent-swatch").first).to_be_visible()
    expect(page.locator("#nl-tag-icon-grid .icon-choice").first).to_be_visible()
