"""One way to act on a file: the row shows its most used actions and a More button that opens the one menu,
which a right click opens too, in the same order in the table and the grid.

  * unit — the menu and its dispatcher are wired, and the old hover cluster is gone for good.
  * ui   — a real browser: the resting row shows [More][Share][Download] for a file and [More][Share] for a
           folder in both views; More and a right click open the one gated menu.
"""
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.unit
def test_the_one_menu_is_wired_and_the_hover_cluster_is_gone():
    app = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    idx = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    css = (ROOT / "static" / "css" / "components.css").read_text(encoding="utf-8")

    assert "data-action=\"more\"" in app
    assert "function openContextMenu(" in app
    assert "function runFileAction(" in app
    assert "function copyFileHash(" in app
    assert "'contextmenu'" in app  # right-click wiring
    assert 'id="i-more"' in idx and 'id="i-hash"' in idx
    assert ".context-menu-item" in css
    # The row offers its actions one way: no second, hover-revealed set of the same actions.
    for text, name in ((app, "app.js"), (css, "components.css")):
        assert "action-cluster" not in text, name
        assert "action-more-wrap" not in text, name
        assert "ctx-menu-open" not in text, name


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


def _actions(row):
    return row.locator(".file-actions button[data-action]").evaluate_all(
        "els => els.map(b => b.getAttribute('data-action'))")


@pytest.mark.ui
def test_the_row_shows_the_same_actions_in_the_table_and_the_grid(page: Page, admin, admin_creds):
    v = admin.create_vault(name="oneway")
    admin.post(f"/vaults/{v['id']}/folders", json={"name": "papers"}).raise_for_status()
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault(page, v["id"], "table")
        _upload(page)
        file_row = page.locator("#vault-files-table-body tr:has(.file-name[data-file-id])").first
        folder_row = page.locator("#vault-files-table-body tr:has(.file-name[data-folder-id])").first
        expect(file_row).to_be_visible(timeout=15000)
        assert _actions(file_row) == ["more", "share-file", "download"]
        assert _actions(folder_row) == ["more", "share-folder"]
        # Every button is on screen at rest: nothing waits for a hover.
        for b in file_row.locator(".file-actions button").all():
            assert b.evaluate("el => getComputedStyle(el).visibility") == "visible"
        page.click('[data-files-view="grid"]')
        file_tile = page.locator("#vault-files-grid .file-tile:has(.file-name[data-file-id])").first
        folder_tile = page.locator("#vault-files-grid .file-tile:has(.file-name[data-folder-id])").first
        expect(file_tile).to_be_visible()
        assert _actions(file_tile) == ["more", "share-file", "download"]
        assert _actions(folder_tile) == ["more", "share-folder"]
        assert page.locator(".action-cluster").count() == 0
        # The menu lists the rest, Rename and Delete among them, in one order for both views.
        file_tile.locator('button[data-action="more"]').click()
        menu = page.locator("#file-context-menu")
        expect(menu).to_be_visible()
        grid_order = menu.locator("button[data-action]").evaluate_all("els => els.map(b => b.getAttribute('data-action'))")
        assert "rename-file" in grid_order and "delete-file" in grid_order
        page.keyboard.press("Escape")
        page.click('[data-files-view="table"]')
        page.locator("#vault-files-table-body tr:has(.file-name[data-file-id])").first.locator('button[data-action="more"]').click()
        table_order = menu.locator("button[data-action]").evaluate_all("els => els.map(b => b.getAttribute('data-action'))")
        assert table_order == grid_order
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

        # Open the menu via the "more" button (a reliable left-click in headless Chromium).
        row.locator('button[data-action="more"]').click()
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

        # A right-click (contextmenu) on the row ALSO opens the menu -- exercise the handler directly
        # via a dispatched contextmenu event (headless Chromium's synthetic right-click is unreliable).
        page.evaluate(
            "() => { const r = document.querySelector('#vault-files-table-body tr');"
            " r.dispatchEvent(new MouseEvent('contextmenu', {bubbles: true, clientX: 120, clientY: 120})); }"
        )
        expect(menu).to_be_visible()
        # Escape dismisses the menu.
        page.keyboard.press("Escape")
        expect(menu).to_be_hidden()
    finally:
        admin.delete_vault(v["id"])


@pytest.mark.ui
def test_more_button_opens_the_context_menu(page: Page, admin, admin_creds):
    """The "more" button is the touch/keyboard path to the same menu a right click opens."""
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


@pytest.mark.ui
def test_the_menu_gives_focus_back_to_more(page: Page, admin, admin_creds):
    """A keyboard user keeps their place: Escape on the menu returns focus to the row's More button, More says
    whether its menu is open (aria-expanded), the menu has a name, and a dialog opened from the menu (Rename)
    returns focus to More when it is cancelled."""
    v = admin.create_vault(name="focusback")
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault(page, v["id"], "table")
        _upload(page, "keep-my-place.txt")
        row = page.locator("#vault-files-table-body tr:has(.file-name[data-file-id])").first
        expect(row).to_be_visible(timeout=10000)
        more = row.locator('button[data-action="more"]')
        expect(more).to_have_attribute("aria-expanded", "false")
        more.focus()
        page.keyboard.press("Enter")
        menu = page.locator("#file-context-menu")
        expect(menu).to_be_visible()
        expect(menu).to_have_attribute("aria-label", "Actions for keep-my-place.txt")
        expect(more).to_have_attribute("aria-expanded", "true")
        page.keyboard.press("ArrowDown")
        page.keyboard.press("Escape")
        expect(menu).to_be_hidden()
        assert page.evaluate("() => document.activeElement && document.activeElement.getAttribute('data-action')") == "more"
        expect(more).to_have_attribute("aria-expanded", "false")
        # Rename from the menu, then cancel: focus comes back to More (the dialog recorded it as its opener).
        more.click()
        expect(menu).to_be_visible()
        menu.locator('.context-menu-item[data-action="rename-file"]').click()
        expect(page.locator("#rename-modal.active")).to_be_visible()
        expect(page.locator("#rename-name-input")).to_be_focused()
        page.keyboard.press("Escape")
        expect(page.locator("#rename-modal.active")).to_be_hidden()
        page.wait_for_timeout(100)
        assert page.evaluate("() => document.activeElement && document.activeElement.getAttribute('data-action')") == "more"
        # A click elsewhere closes the menu without pulling focus back to the row.
        more.click()
        expect(menu).to_be_visible()
        page.locator("#files-filter").click()
        expect(menu).to_be_hidden()
        expect(page.locator("#files-filter")).to_be_focused()
    finally:
        admin.delete_vault(v["id"])
