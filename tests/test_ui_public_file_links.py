"""UI — public FILE/FOLDER links admin surface: the Public Links settings tab exposes the
`public_file_links_enabled` toggle, the link-tag editor lets an admin pick which targets a tag allows
(notes / files / folders), and there is an admin oversight card for public file/folder links."""
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


def _open_publiclinks(page: Page):
    page.click('.sidebar-item[data-section="settings"]')
    page.click('#settings-section .tab-btn[data-tab="notelinks"]')
    expect(page.locator("#settings-tab-notelinks")).to_be_visible(timeout=10000)


@pytest.fixture
def restore_file_links(admin):
    started = admin.get("/settings").json().get("public_file_links_enabled", False)
    yield
    admin.put("/settings", json={"public_file_links_enabled": bool(started)})


def test_file_links_toggle_persists(page: Page, admin, admin_creds, restore_file_links):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_publiclinks(page)
    expect(page.locator("#setting-public-file-links-enabled")).to_be_visible()
    # The Save-All button is disabled until settings finish loading; wait so an async load doesn't
    # reset the box after we check it (and so the click isn't swallowed).
    expect(page.locator("#save-all-settings-btn")).to_be_enabled(timeout=10000)
    page.set_checked("#setting-public-file-links-enabled", True)
    page.click("#save-all-settings-btn")
    page.wait_for_timeout(1500)
    assert admin.get("/settings").json().get("public_file_links_enabled") is True


def test_tag_editor_target_checkboxes_default_note_and_persist(page: Page, admin, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_publiclinks(page)
    page.click("#nl-tag-add-btn")
    expect(page.locator("#nl-tag-editor")).to_be_visible()
    # A fresh tag defaults to notes only.
    expect(page.locator("#nl-tag-target-note")).to_be_checked()
    expect(page.locator("#nl-tag-target-file")).not_to_be_checked()
    expect(page.locator("#nl-tag-target-folder")).not_to_be_checked()

    name = unique("FileTag")
    page.fill("#nl-tag-name", name)
    page.check("#nl-tag-target-file")
    page.check("#nl-tag-target-folder")
    page.click("#nl-tag-save-btn")
    expect(page.locator("#nl-tags-list", has_text=name)).to_be_visible(timeout=10000)
    tag = next(t for t in admin.get("/note-link-tags").json() if t["name"] == name)
    assert set(tag["allowed_targets"]) == {"note", "file", "folder"}, tag["allowed_targets"]


def test_tag_editor_requires_at_least_one_target(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_publiclinks(page)
    page.click("#nl-tag-add-btn")
    expect(page.locator("#nl-tag-editor")).to_be_visible()
    page.fill("#nl-tag-name", unique("NoTarget"))
    page.uncheck("#nl-tag-target-note")  # nothing selected now
    page.click("#nl-tag-save-btn")
    # A friendly client-side error appears; the editor stays open (nothing was saved).
    err = page.locator("#nl-tag-editor-error")
    expect(err).to_be_visible()
    expect(err).to_contain_text(re.compile(r"at least one", re.I))


def test_admin_file_link_oversight_card_present(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_publiclinks(page)
    # The dedicated admin card + its controls exist.
    expect(page.locator("#pfl-admin-links")).to_be_attached()
    expect(page.locator("#pfl-admin-refresh")).to_be_visible()
    expect(page.locator("#pfl-admin-revoke-all")).to_be_visible()
