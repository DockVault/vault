"""UI — the Move/Copy clipboard: stage an item, navigate, and Paste it into the open folder.

Copies leave the original and stay on the clipboard; moves relocate the item and leave the clipboard.
The staged item's name is rendered with textContent, so it is never HTML.
"""
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


def _open_vault(page: Page, vault_id: str):
    page.click('.sidebar-item[data-section="vaults"]')
    page.click(f'.open-vault-btn[data-vault-id="{vault_id}"]')
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)


def _upload(client, vault_id, name, content, folder_id=None):
    files = [("files", (name, content, "text/plain"))]
    params = {"folder_id": folder_id} if folder_id else None
    r = client.post(f"/vaults/{vault_id}/files", files=files, params=params)
    r.raise_for_status()
    return r.json()["files"][0]["id"]


def _mkfolder(client, vault_id, name):
    r = client.post(f"/vaults/{vault_id}/folders", json={"name": name})
    r.raise_for_status()
    return r.json()["folder"]["id"]


def _stage(page: Page, fid: str, action: str):
    """Stage a file for move/copy. The copy/move buttons now live in a hover cluster that is hidden
    at rest, so drive it through the always-visible right-click context menu instead."""
    page.locator(f'tr:has(.file-name[data-file-id="{fid}"])').first.click(button="right")
    page.locator(f'#file-context-menu button[data-action="{action}"]').click()


def test_copy_file_via_clipboard_keeps_original(page: Page, admin, admin_creds):
    v = admin.create_vault(name=unique("uicp"))
    vid = v["id"]
    fid = _upload(admin, vid, unique("doc") + ".txt", b"clipboard copy\n" * 20)
    folder = _mkfolder(admin, vid, unique("dst"))
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault(page, vid)
        # Stage the file for copy.
        _stage(page, fid, "copy-file")
        expect(page.locator("#move-copy-bar")).to_be_visible()
        expect(page.locator("#move-copy-count")).to_have_text("1")
        # Enter the destination folder and paste.
        page.click(f'.file-name[data-folder-id="{folder}"]')
        page.click("#move-copy-paste")
        # The copy appears in the folder (a file row that is not the original folder link).
        expect(page.locator("#vault-view-section .file-name[data-file-id]")).to_be_visible(timeout=10000)
        # Copy semantics: the clipboard stays populated for another paste.
        expect(page.locator("#move-copy-bar")).to_be_visible()
        # And the original is still at the vault root.
        _open_vault(page, vid)
        expect(page.locator(f'.file-name[data-file-id="{fid}"]')).to_be_visible(timeout=10000)
    finally:
        admin.delete_vault(vid)


def test_move_file_via_clipboard_relocates_and_clears(page: Page, admin, admin_creds):
    v = admin.create_vault(name=unique("uimv"))
    vid = v["id"]
    fid = _upload(admin, vid, unique("doc") + ".txt", b"clipboard move\n" * 20)
    folder = _mkfolder(admin, vid, unique("dst"))
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault(page, vid)
        _stage(page, fid, "move-file")
        expect(page.locator("#move-copy-bar")).to_be_visible()
        page.click(f'.file-name[data-folder-id="{folder}"]')
        page.click("#move-copy-paste")
        # The moved file (same id) now shows in the folder.
        expect(page.locator(f'.file-name[data-file-id="{fid}"]')).to_be_visible(timeout=10000)
        # Move semantics: the clipboard empties after a successful relocation.
        expect(page.locator("#move-copy-bar")).to_be_hidden()
        # And it is gone from the vault root.
        _open_vault(page, vid)
        expect(page.locator(f'.file-name[data-file-id="{fid}"]')).to_have_count(0)
    finally:
        admin.delete_vault(vid)


def test_no_console_errors_when_staging(page: Page, admin, admin_creds):
    v = admin.create_vault(name=unique("uierr"))
    vid = v["id"]
    fid = _upload(admin, vid, unique("doc") + ".txt", b"data")
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault(page, vid)
        _stage(page, fid, "copy-file")
        expect(page.locator("#move-copy-bar")).to_be_visible()
        page.wait_for_timeout(500)
        assert not errors, f"console errors while staging a copy: {errors}"
    finally:
        admin.delete_vault(vid)
