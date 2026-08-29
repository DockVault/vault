"""UI — the admin Settings -> Note Links tab: enable toggle + per-user cap + the note-link tag manager."""
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


@pytest.fixture
def restore_settings(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ("public_note_links_enabled", "public_note_link_user_cap")}
    yield
    admin.put("/settings", json=snap)


def test_toggle_and_cap_persist(page: Page, admin, admin_creds, restore_settings):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_notelinks(page)
    # The Save-All button is disabled until settings finish loading; wait so the click isn't swallowed.
    expect(page.locator("#save-all-settings-btn")).to_be_enabled(timeout=10000)
    page.set_checked("#setting-public-note-links-enabled", True)
    page.fill("#setting-public-note-link-user-cap", "25")
    page.click("#save-all-settings-btn")
    page.wait_for_timeout(1500)
    # Persisted server-side.
    s = admin.get("/settings").json()
    assert s["public_note_links_enabled"] is True
    assert s["public_note_link_user_cap"] == 25


def test_tag_manager_lists_defaults_and_adds(page: Page, admin, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_notelinks(page)
    # Seeded defaults are listed.
    for name in ("Open", "Restricted", "Confidential"):
        expect(page.locator("#nl-tags-list", has_text=name)).to_be_visible(timeout=10000)
    # Add a new tag via the editor.
    name = unique("UITag")
    page.click("#nl-tag-add-btn")
    expect(page.locator("#nl-tag-editor")).to_be_visible()
    page.fill("#nl-tag-name", name)
    page.fill("#nl-tag-min-token-len", "14")
    page.select_option("#nl-tag-require-secret", "pin")
    page.select_option("#nl-tag-min-pin-len", "6")
    page.click("#nl-tag-save-btn")
    expect(page.locator("#nl-tags-list", has_text=name)).to_be_visible(timeout=10000)
    # And it's persisted (API sees it with the chosen policy).
    tag = next(t for t in admin.get("/note-link-tags").json() if t["name"] == name)
    assert tag["min_token_len"] == 14 and tag["require_secret"] == "pin" and tag["min_pin_len"] == 6


def test_add_tag_below_token_floor_shows_error(page: Page, admin, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_notelinks(page)
    page.click("#nl-tag-add-btn")
    expect(page.locator("#nl-tag-editor")).to_be_visible()
    page.fill("#nl-tag-name", unique("BadTag"))
    page.fill("#nl-tag-min-token-len", "3")   # below the 6 floor -> server 400
    page.click("#nl-tag-save-btn")
    expect(page.locator("#nl-tag-editor-error")).to_be_visible(timeout=10000)
    expect(page.locator("#nl-tag-editor")).to_be_visible()   # editor stays open on error


def test_no_console_errors_on_notelinks_tab(page: Page, admin, admin_creds):
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_notelinks(page)
    page.wait_for_timeout(800)
    assert not errors, f"console errors on the Note Links tab: {errors}"
