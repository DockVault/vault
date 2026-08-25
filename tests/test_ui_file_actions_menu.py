"""Per-row multi-action hover cluster + right-click context menu + tile-overflow fix.

  * unit — the refactor is wired in (hover-cluster markup + the context-menu functions + icons).
  * ui   — a real browser: the resting row is collapsed (cluster hidden), hovering reveals the
           edit/copy/move/delete cluster, and right-click opens a gated context menu.
"""
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.unit
def test_action_cluster_and_context_menu_are_wired():
    app = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    idx = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    css = (ROOT / "static" / "css" / "components.css").read_text(encoding="utf-8")

    # resting row collapses edit/copy/move/delete into a hover cluster behind a "more" button.
    assert "action-more-wrap" in app
    assert "action-cluster" in app
    assert "data-action=\"more\"" in app
    # the right-click menu + shared dispatcher + hash copy.
    assert "function openContextMenu(" in app
    assert "function runFileAction(" in app
    assert "function copyFileHash(" in app
    assert "'contextmenu'" in app  # right-click wiring
    # new sprite icons.
    assert 'id="i-more"' in idx and 'id="i-hash"' in idx
    # CSS for the cluster (hover reveal) + the context menu, in the shared base.
    assert ".action-more-wrap:hover .action-cluster" in css
    assert ".context-menu-item" in css


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_vault(page: Page, vault_id: str, view: str):
    page.click('.sidebar-item[data-section="vaults"]')
    page.click(f'.open-vault-btn[data-vault-id="{vault_id}"]')
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)
    page.click(f'[data-files-view="{view}"]')


def _upload(page: Page, name="doc.txt"):
    page.set_input_files("#file-upload-input",
                         files=[{"name": name, "mimeType": "text/plain", "buffer": b"x"}])


@pytest.mark.ui
def test_hover_cluster_hidden_at_rest_and_revealed_on_hover(page: Page, admin, admin_creds):
    """The edit/copy/move/delete cluster is hidden at rest (so a tile does not overflow with
    five-plus icons) and slides out when the "more" area is hovered."""
    v = admin.create_vault(name="cluster")
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault(page, v["id"], "grid")
        _upload(page)
        tile = page.locator("#vault-files-grid .file-tile").first
        expect(tile).to_be_visible(timeout=15000)

        cluster = tile.locator(".action-cluster")
        expect(cluster).to_have_count(1)
        # hidden at rest -> the resting row is just [more][share][download].
        assert cluster.evaluate("el => getComputedStyle(el).visibility") == "hidden"
        # the rename button lives in the cluster (still in the DOM, just hidden).
        expect(tile.locator('.action-cluster button[data-action="rename-file"]')).to_have_count(1)

        # hover the more-wrap -> the cluster becomes visible.
        tile.locator(".action-more-wrap").hover()
        expect(cluster).to_have_css("visibility", "visible")
        # a revealed cluster button is clickable and runs its action.
        tile.locator('.action-cluster button[data-action="rename-file"]').click()
        expect(page.locator("#rename-modal")).to_be_visible(timeout=8000)
    finally:
        admin.delete_vault(v["id"])


@pytest.mark.ui
def test_right_click_opens_a_gated_context_menu(page: Page, admin, admin_creds):
    v = admin.create_vault(name="ctxmenu")
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault(page, v["id"], "table")
        _upload(page)
        row = page.locator("#vault-files-table-body tr").first
        expect(row).to_be_visible(timeout=15000)

        row.click(button="right")
        menu = page.locator("#file-context-menu")
        expect(menu).to_be_visible()
        # a permitted set of actions for an admin on a Standard vault.
        for act in ("preview", "rename-file", "copy-file", "move-file", "share-file",
                    "download", "file-info", "copy-sha256", "delete-file"):
            expect(menu.locator(f'button[data-action="{act}"]')).to_have_count(1)

        # clicking "File info" runs the same action as the row button.
        menu.locator('button[data-action="file-info"]').click()
        expect(page.locator("#file-info-modal")).to_be_visible(timeout=8000)
        page.locator("#file-info-modal .close-modal-btn").click()

        # Escape dismisses the menu.
        row.click(button="right")
        expect(menu).to_be_visible()
        page.keyboard.press("Escape")
        expect(menu).to_be_hidden()
    finally:
        admin.delete_vault(v["id"])


@pytest.mark.ui
def test_more_button_opens_the_context_menu(page: Page, admin, admin_creds):
    """The "more" button is the touch/keyboard path to the same menu the hover cluster mirrors."""
    v = admin.create_vault(name="morebtn")
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault(page, v["id"], "table")
        _upload(page)
        row = page.locator("#vault-files-table-body tr").first
        expect(row).to_be_visible(timeout=15000)
        row.locator('button[data-action="more"]').click()
        expect(page.locator("#file-context-menu")).to_be_visible()
        # clicking outside dismisses it.
        page.locator("#vault-view-section").click(position={"x": 5, "y": 5})
        expect(page.locator("#file-context-menu")).to_be_hidden()
    finally:
        admin.delete_vault(v["id"])
