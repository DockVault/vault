"""Find in this folder: a box over the loaded listing that narrows the rows by name as you type.

It works on the names the browser already holds (so in a zero-knowledge vault too, whose names are decrypted
in the browser before they are listed), in both views; an empty match says so; Escape clears it; entering
another folder starts clear; Select all takes what is shown.
"""
import pytest
from playwright.sync_api import Page, expect

from conftest import unique

pytestmark = pytest.mark.ui


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


@pytest.fixture
def world(admin):
    v = admin.create_vault(name=unique("find"))
    vid = v["id"]
    for name in ("report-2026.pdf", "report-2025.pdf", "notes.txt"):
        r = admin.post(f"/vaults/{vid}/files", files=[("files", (name, b"x", "application/octet-stream"))])
        r.raise_for_status()
    folder = admin.post(f"/vaults/{vid}/folders", json={"name": "Reports archive"}).json()["folder"]["id"]
    try:
        yield v, folder
    finally:
        admin.delete_vault(vid)


def _names(page: Page, view: str):
    sel = "#vault-files-table-body .file-name" if view == "table" else "#vault-files-grid .file-tile .file-name"
    return [t.strip() for t in page.locator(sel).all_inner_texts()]


def test_the_box_narrows_both_views_and_clears_on_leaving(page: Page, admin_creds, world):
    v, folder = world
    _login(page, admin_creds["username"], admin_creds["password"])
    page.click('.sidebar-item[data-section="vaults"]')
    page.click(f'.open-vault-btn[data-vault-id="{v["id"]}"]')
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)
    page.click('[data-files-view="table"]')
    expect(page.locator("#vault-files-table-body tr")).to_have_count(4, timeout=15000)
    box = page.locator("#files-filter")
    expect(box).to_be_visible()
    box.fill("report")
    # Folders and files alike, matched without regard to case.
    assert sorted(_names(page, "table")) == ["Reports archive", "report-2025.pdf", "report-2026.pdf"]
    box.fill("2026")
    assert _names(page, "table") == ["report-2026.pdf"]
    # The grid shows the same narrowing.
    page.click('[data-files-view="grid"]')
    assert _names(page, "grid") == ["report-2026.pdf"]
    # Nothing matches: the listing says so, naming what was typed.
    box.fill("zzz-nothing")
    expect(page.locator("#vault-files-grid")).to_contain_text("Nothing here matches")
    expect(page.locator("#vault-files-grid")).to_contain_text("zzz-nothing")
    page.click('[data-files-view="table"]')
    expect(page.locator("#vault-files-table-body")).to_contain_text("Nothing here matches")
    # Escape clears the box and everything is back.
    box.press("Escape")
    expect(box).to_have_value("")
    expect(page.locator("#vault-files-table-body tr")).to_have_count(4)
    # Select all takes what is shown.
    box.fill("report-")
    page.locator("#files-select-all").check()
    expect(page.locator("#files-bulk-count")).to_have_text("2")
    page.click("#files-bulk-clear")
    # Entering a folder starts clear.
    box.fill("report")
    page.click(f'.file-name[data-folder-id="{folder}"]')
    expect(page.locator("#vault-breadcrumb")).to_contain_text("Reports archive", timeout=10000)
    expect(box).to_have_value("")
    assert page.evaluate("() => state.filesFilter || ''") == ""


def test_a_filter_that_matches_nothing_is_announced(page: Page, admin_creds, world):
    """The empty match is said from a status region that stays on the page (the empty state is drawn anew on
    every keystroke and so cannot announce itself); a match says how many, and a clear box says nothing."""
    v, _folder = world
    _login(page, admin_creds["username"], admin_creds["password"])
    page.click('.sidebar-item[data-section="vaults"]')
    page.click(f'.open-vault-btn[data-vault-id="{v["id"]}"]')
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)
    expect(page.locator("#vault-files-table-body tr")).to_have_count(4, timeout=15000)
    status = page.locator("#files-filter-status")
    expect(status).to_have_attribute("role", "status")
    expect(status).to_have_text("")
    box = page.locator("#files-filter")
    box.fill("zzz-nothing")
    expect(status).to_have_text("Nothing here matches “zzz-nothing”.")
    box.fill("2026")
    expect(status).to_have_text("1 item here matches “2026”.")
    box.fill("report")
    expect(status).to_have_text("3 items here match “report”.")
    box.press("Escape")
    expect(status).to_have_text("")
