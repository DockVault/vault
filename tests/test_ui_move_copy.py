"""UI — the Copied Items staging panel (Move/Copy).

Stage files via the right-click menu (opened from the "more" button), open the Copied Items panel,
select a subset, and Paste (copies) / Move (cuts) them into the open folder. A copy is KEPT after
pasting so it can be dropped into many folders; a move leaves the list once relocated;
Delete-from-list drops one item without clearing the rest. Names/locations render with textContent,
so a staged item's name is never HTML.
"""
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

from conftest import unique

ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- unit lane

@pytest.mark.unit
def test_copied_items_panel_is_wired():
    app = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    idx = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    css = (ROOT / "static" / "css" / "components.css").read_text(encoding="utf-8")
    assert 'id="copied-items-btn"' in idx and 'id="copied-items-panel"' in idx
    assert 'id="ci-list"' in idx and 'id="ci-mixed-modal"' in idx
    assert "function renderCopiedItems(" in app
    assert "function _ciShowMixedModal(" in app
    assert "function _ciDeleteSelected(" in app
    assert "keepAfter" in app                       # keep-after-paste flag
    # the old always-visible bar is gone.
    assert 'id="move-copy-bar"' not in idx
    # The panel is position:fixed z-index:1500 with display:flex; its `hidden` attribute must be
    # honoured, or a hidden panel intercepts clicks on the toolbar beneath it (a real regression:
    # it blocked #create-folder-btn for 30s). This rule restores display:none when hidden.
    assert ".ci-panel[hidden]" in css


# --------------------------------------------------------------------------- ui lane


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
    """Stage a file for move/copy via the right-click menu (opened from the "more" button)."""
    page.locator(f'tr:has(.file-name[data-file-id="{fid}"]) button[data-action="more"]').first.click()
    page.locator(f'#file-context-menu button[data-action="{action}"]').click()


def _open_panel(page: Page):
    page.locator("#copied-items-btn").click()
    expect(page.locator("#copied-items-panel")).to_be_visible()


@pytest.mark.ui
def test_copy_paste_keeps_original_and_stays_staged(page: Page, admin, admin_creds):
    v = admin.create_vault(name=unique("uicp"))
    vid = v["id"]
    fid = _upload(admin, vid, unique("doc") + ".txt", b"clipboard copy\n" * 20)
    dst = _mkfolder(admin, vid, unique("dst"))
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault(page, vid)
        _stage(page, fid, "copy-file")
        expect(page.locator("#copied-items-btn")).to_be_visible()
        expect(page.locator("#copied-items-count")).to_have_text("1")

        # Enter the destination folder, then paste the selected item into it.
        page.click(f'.file-name[data-folder-id="{dst}"]')
        _open_panel(page)
        expect(page.locator(".ci-item")).to_have_count(1)
        page.locator("#ci-select-all").check()
        page.locator('#ci-action-buttons button:has-text("Paste")').click()
        expect(page.locator("#vault-view-section .file-name[data-file-id]")).to_be_visible(timeout=10000)

        # A copy KEEPS the item staged (so it can be pasted into more folders).
        expect(page.locator("#copied-items-count")).to_have_text("1")
        # The original is still at the vault root.
        _open_vault(page, vid)
        expect(page.locator(f'.file-name[data-file-id="{fid}"]')).to_be_visible(timeout=10000)
    finally:
        admin.delete_vault(vid)


@pytest.mark.ui
def test_move_paste_relocates_and_leaves_the_list(page: Page, admin, admin_creds):
    v = admin.create_vault(name=unique("uimv"))
    vid = v["id"]
    fid = _upload(admin, vid, unique("doc") + ".txt", b"clipboard move\n" * 20)
    dst = _mkfolder(admin, vid, unique("dst"))
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault(page, vid)
        _stage(page, fid, "move-file")
        page.click(f'.file-name[data-folder-id="{dst}"]')
        _open_panel(page)
        page.locator("#ci-select-all").check()
        page.locator('#ci-action-buttons button:has-text("Move")').click()

        # The moved file (same id) now shows in the folder.
        expect(page.locator(f'.file-name[data-file-id="{fid}"]')).to_be_visible(timeout=10000)
        # A move LEAVES the list -> the toolbar button hides (nothing staged).
        expect(page.locator("#copied-items-btn")).to_be_hidden()
        # And it is gone from the vault root.
        _open_vault(page, vid)
        expect(page.locator(f'.file-name[data-file-id="{fid}"]')).to_have_count(0)
    finally:
        admin.delete_vault(vid)


@pytest.mark.ui
def test_kept_copy_pastes_into_two_folders(page: Page, admin, admin_creds):
    """The owner's core use case: keep a copy staged and paste it into several folders."""
    v = admin.create_vault(name=unique("uikeep"))
    vid = v["id"]
    fid = _upload(admin, vid, unique("doc") + ".txt", b"multi-paste\n" * 10)
    a = _mkfolder(admin, vid, unique("A"))
    b = _mkfolder(admin, vid, unique("B"))
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault(page, vid)
        _stage(page, fid, "copy-file")
        _open_panel(page)
        page.locator("#ci-select-all").check()

        # Paste into A.
        page.click(f'.file-name[data-folder-id="{a}"]')
        page.locator('#ci-action-buttons button:has-text("Paste")').click()
        expect(page.locator("#vault-view-section .file-name[data-file-id]")).to_be_visible(timeout=10000)
        expect(page.locator("#copied-items-count")).to_have_text("1")  # still staged

        # Back to root, into B, paste again (the selection persists).
        _open_vault(page, vid)
        page.click(f'.file-name[data-folder-id="{b}"]')
        page.locator('#ci-action-buttons button:has-text("Paste")').click()
        expect(page.locator("#vault-view-section .file-name[data-file-id]")).to_be_visible(timeout=10000)

        # Both folders now hold one file (verified server-side).
        a_files = [i for i in admin.get(f"/vaults/{vid}/files", params={"folder_id": a}).json()["items"] if i["type"] == "file"]
        b_files = [i for i in admin.get(f"/vaults/{vid}/files", params={"folder_id": b}).json()["items"] if i["type"] == "file"]
        assert len(a_files) == 1 and len(b_files) == 1, (a_files, b_files)
    finally:
        admin.delete_vault(vid)


@pytest.mark.ui
def test_delete_from_list_removes_only_the_selected(page: Page, admin, admin_creds):
    v = admin.create_vault(name=unique("uidel"))
    vid = v["id"]
    f1 = _upload(admin, vid, unique("one") + ".txt", b"a")
    f2 = _upload(admin, vid, unique("two") + ".txt", b"b")
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault(page, vid)
        _stage(page, f1, "copy-file")
        _stage(page, f2, "copy-file")
        _open_panel(page)
        expect(page.locator(".ci-item")).to_have_count(2)

        # Select only the first and delete it from the list.
        page.locator(f'.ci-item[data-ci-id="{f1}"] .ci-check').check()
        page.locator('#ci-action-buttons button:has-text("Delete from list")').click()
        expect(page.locator(".ci-item")).to_have_count(1)
        expect(page.locator("#copied-items-count")).to_have_text("1")
        expect(page.locator(f'.ci-item[data-ci-id="{f2}"]')).to_have_count(1)  # the other stays
    finally:
        admin.delete_vault(vid)


@pytest.mark.ui
def test_mixed_selection_opens_the_paste_move_modal(page: Page, admin, admin_creds):
    v = admin.create_vault(name=unique("uimix"))
    vid = v["id"]
    f_copy = _upload(admin, vid, unique("c") + ".txt", b"copyme")
    f_move = _upload(admin, vid, unique("m") + ".txt", b"moveme")
    dst = _mkfolder(admin, vid, unique("dst"))
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault(page, vid)
        _stage(page, f_copy, "copy-file")
        _stage(page, f_move, "move-file")
        page.click(f'.file-name[data-folder-id="{dst}"]')
        _open_panel(page)
        page.locator("#ci-select-all").check()

        # A mixed selection collapses Paste + Move into one "Paste/Move" that confirms via a modal.
        page.locator('#ci-action-buttons button:has-text("Paste/Move")').click()
        expect(page.locator("#ci-mixed-modal")).to_be_visible()
        expect(page.locator("#ci-mixed-body")).to_contain_text("will be copied")
        expect(page.locator("#ci-mixed-body")).to_contain_text("will be moved")
        page.locator("#ci-mixed-confirm").click()

        # Copy stays staged, move leaves -> one item remains.
        expect(page.locator("#copied-items-count")).to_have_text("1", timeout=10000)
    finally:
        admin.delete_vault(vid)


@pytest.mark.ui
def test_no_console_errors_when_staging_and_opening_the_panel(page: Page, admin, admin_creds):
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
        expect(page.locator("#copied-items-btn")).to_be_visible()
        _open_panel(page)
        page.wait_for_timeout(400)
        assert not errors, f"console errors while staging a copy: {errors}"
    finally:
        admin.delete_vault(vid)
