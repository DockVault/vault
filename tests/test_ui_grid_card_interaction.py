"""Grid (gallery) view card interaction.

A file gets Rename/Delete/Share/Download affordances in grid; the controls live in an in-flow
action row BELOW the icon — the checkbox in a left cluster, the action buttons right-aligned with
Download on the far right. The whole card is clickable to open/preview and the name is
keyboard-operable. Clicking a control must NOT also trigger the card's open action.
"""
import re

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_vault_grid_with_file(page: Page, vault_id: str):
    page.click('.sidebar-item[data-section="vaults"]')
    page.click(f'.open-vault-btn[data-vault-id="{vault_id}"]')
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)
    page.set_input_files(
        "#file-upload-input",
        files=[{"name": "report.bin", "mimeType": "application/octet-stream", "buffer": b"z" * 24}],
    )
    page.click('[data-files-view="grid"]')
    expect(page.locator("#vault-files-grid .file-tile").first).to_be_visible(timeout=10000)


def test_grid_file_edit_and_split_clusters(page: Page, admin, admin_creds):
    v = admin.create_vault(name="grid-edit")
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault_grid_with_file(page, v["id"])
        tile = page.locator("#vault-files-grid .file-tile").first
        # a file now has an Edit(rename) affordance in grid, in the RIGHT cluster
        expect(tile.locator('.tile-tr button[data-action="rename-file"]')).to_have_count(1)
        expect(tile.locator('.tile-tr button[data-action="delete-file"]')).to_have_count(1)
        # Download moved to the RIGHT cluster (far right); the checkbox stays in the LEFT cluster
        expect(tile.locator('.tile-tr button[data-action="download"]')).to_have_count(1)
        expect(tile.locator('.tile-tl input.file-check')).to_have_count(1)
        expect(tile.locator('.tile-tl button[data-action="download"]')).to_have_count(0)
    finally:
        admin.delete_vault(v["id"])


def test_grid_action_row_below_icon_and_download_far_right(page: Page, admin, admin_creds):
    """The tile's action controls sit in an in-flow row BELOW the icon (not painted over it), and
    Download is the far-right action. Regression guard: the clusters were previously
    position:absolute pinned to the tile's top corners, overlapping the icon. (The identical fix in
    both skins is locked by test_static_grid_actions.py.)"""
    v = admin.create_vault(name="grid-actrow")
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault_grid_with_file(page, v["id"])
        tile = page.locator("#vault-files-grid .file-tile").first
        expect(tile).to_be_visible()

        # (1) the action row is in normal flow (not absolute) and sits at/below the icon's bottom
        actions = tile.locator(".tile-actions")
        assert actions.evaluate("el => getComputedStyle(el).position") == "static"
        ab = actions.bounding_box()
        ib = tile.locator(".tile-icon").bounding_box()
        assert ab and ib, "missing bounding boxes"
        assert ab["y"] >= ib["y"] + ib["height"] - 1, f"action row overlaps the icon: {ab} vs {ib}"

        # (2) Download is present in the RIGHT cluster and is the right-most action button
        dl = tile.locator('.tile-tr button[data-action="download"]')
        expect(dl).to_have_count(1)
        assert tile.locator('.tile-tr .action-btn').last.get_attribute("data-action") == "download"
        dlb = dl.bounding_box()
        rnb = tile.locator('.tile-tr button[data-action="rename-file"]').bounding_box()
        assert dlb and rnb and dlb["x"] > rnb["x"], f"Download not right of Rename: {dlb} vs {rnb}"
    finally:
        admin.delete_vault(v["id"])


def test_grid_whole_card_click_opens_preview(page: Page, admin, admin_creds):
    v = admin.create_vault(name="grid-click")
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault_grid_with_file(page, v["id"])
        # click a non-control area of the card (the icon) — the whole card opens the preview
        page.locator("#vault-files-grid .file-tile .tile-icon").first.click()
        expect(page.locator("#file-preview-modal")).to_be_visible(timeout=8000)
    finally:
        admin.delete_vault(v["id"])


def test_grid_checkbox_click_does_not_open_preview(page: Page, admin, admin_creds):
    v = admin.create_vault(name="grid-guard")
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault_grid_with_file(page, v["id"])
        tile = page.locator("#vault-files-grid .file-tile").first
        tile.locator("input.file-check").click()
        # the control-click must NOT bubble into the card's open action; settle first so an
        # erroneous async openFilePreview would have had time to render the modal
        expect(tile).to_have_class(re.compile(r"\bis-selected\b"))
        page.wait_for_timeout(400)
        expect(page.locator("#file-preview-modal")).not_to_be_visible()
    finally:
        admin.delete_vault(v["id"])


def test_grid_name_keyboard_opens_preview(page: Page, admin, admin_creds):
    v = admin.create_vault(name="grid-kbd")
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault_grid_with_file(page, v["id"])
        name = page.locator("#vault-files-grid .file-tile .file-name").first
        # the name is role=button tabindex=0 -> Enter activates it
        expect(name).to_have_attribute("role", "button")
        name.focus()
        name.press("Enter")
        expect(page.locator("#file-preview-modal")).to_be_visible(timeout=8000)
    finally:
        admin.delete_vault(v["id"])
