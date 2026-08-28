"""Edit-filename modal: separate name + extension fields, caret at the end of the name, the
extension read-only until double-clicked, and a Windows-style warning before an extension change
whose "Keep extension" returns to the modal instead of closing it.

  * unit — the dialog is wired in (renameVaultItem uses showRenameDialog, not the shared showPrompt).
  * ui   — a real browser: the split logic, the field split + caret, and the extension-change warning.
"""
import re
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.unit
def test_rename_dialog_is_wired_in():
    app = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    idx = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    assert "function _splitNameExt(" in app
    assert "function showRenameDialog(" in app
    # renameVaultItem must use the dedicated dialog, not the shared confirm/prompt input.
    m = re.search(r"async function renameVaultItem\(.*?\n(.*?)\n}\n", app, re.S)
    assert m, "renameVaultItem not found"
    body = m.group(1)
    assert "showRenameDialog(" in body and "showPrompt(" not in body
    assert 'id="rename-modal"' in idx
    assert 'id="rename-name-input"' in idx and 'id="rename-ext-input"' in idx
    assert 'id="rename-warning"' in idx


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_vault_table(page: Page, vault_id: str):
    page.click('.sidebar-item[data-section="vaults"]')
    page.click(f'.open-vault-btn[data-vault-id="{vault_id}"]')
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)
    page.click('[data-files-view="table"]')


@pytest.mark.ui
def test_split_name_ext_logic(page: Page, admin, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])

    def split(n, folder=False):
        return page.evaluate("([n, f]) => _splitNameExt(n, f)", [n, folder])

    assert split("doc.txt") == {"name": "doc", "ext": "txt"}
    assert split("archive.tar.gz") == {"name": "archive.tar", "ext": "gz"}
    assert split(".env") == {"name": ".env", "ext": None}          # dotfile: all name
    assert split("noext") == {"name": "noext", "ext": None}
    assert split("trailingdot.") == {"name": "trailingdot.", "ext": None}
    assert split("anything.txt", True) == {"name": "anything.txt", "ext": None}  # folder: no ext


@pytest.mark.ui
def test_rename_fields_caret_and_extension_warning(page: Page, admin, admin_creds):
    v = admin.create_vault(name="rename")
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault_table(page, v["id"])
        page.set_input_files("#file-upload-input",
                             files=[{"name": "doc.txt", "mimeType": "text/plain", "buffer": b"x"}])
        row = page.locator("#vault-files-table-body tr").first
        expect(row).to_be_visible(timeout=15000)
        # Rename lives in the hover cluster / context menu now; open it via the "more" button.
        row.locator('button[data-action="more"]').click()
        page.locator('#file-context-menu button[data-action="rename-file"]').click()

        expect(page.locator("#rename-modal")).to_be_visible()
        # separate fields split at the last dot; the extension is read-only to start.
        expect(page.locator("#rename-name-input")).to_have_value("doc")
        expect(page.locator("#rename-ext-input")).to_have_value("txt")
        assert page.locator("#rename-ext-input").get_attribute("readonly") is not None
        # the caret sits at the END of the name part.
        page.wait_for_function(
            "() => { const i = document.getElementById('rename-name-input');"
            " return document.activeElement === i && i.selectionStart === i.value.length"
            " && i.selectionEnd === i.value.length; }",
            timeout=3000,
        )
        # renaming only the NAME saves without a warning.
        page.fill("#rename-name-input", "renamed")
        page.click("#rename-save")
        expect(page.locator("#rename-modal")).to_be_hidden()
        expect(page.locator("#vault-files-table-body")).to_contain_text("renamed.txt")

        # now change the EXTENSION -> a warning; the warning must not be visible before saving.
        page.locator("#vault-files-table-body tr").first.locator('button[data-action="more"]').click()
        page.locator('#file-context-menu button[data-action="rename-file"]').click()
        expect(page.locator("#rename-modal")).to_be_visible()
        expect(page.locator("#rename-warning")).to_be_hidden()  # gated: hidden until an ext change is saved
        page.locator("#rename-ext-input").dblclick()
        assert page.locator("#rename-ext-input").get_attribute("readonly") is None  # editable now
        page.fill("#rename-ext-input", "md")
        page.click("#rename-save")
        expect(page.locator("#rename-warning")).to_be_visible()
        expect(page.locator("#rename-modal")).to_be_visible()  # NOT closed

        # "Keep extension" reverts the extension, re-locks it, and returns to the still-open dialog.
        page.click("#rename-warn-keep")
        expect(page.locator("#rename-warning")).to_be_hidden()
        expect(page.locator("#rename-modal")).to_be_visible()
        expect(page.locator("#rename-ext-input")).to_have_value("txt")  # reverted to the original
        assert page.locator("#rename-ext-input").get_attribute("readonly") is not None  # re-locked

        # change it again and confirm with "Change it anyway".
        page.locator("#rename-ext-input").dblclick()
        page.fill("#rename-ext-input", "md")
        page.click("#rename-save")
        expect(page.locator("#rename-warning")).to_be_visible()
        page.click("#rename-warn-proceed")
        expect(page.locator("#rename-modal")).to_be_hidden()
        expect(page.locator("#vault-files-table-body")).to_contain_text("renamed.md")
    finally:
        admin.delete_vault(v["id"])


@pytest.mark.ui
def test_rename_folder_has_no_extension_field(page: Page, admin, admin_creds):
    v = admin.create_vault(name="renfolder")
    try:
        assert admin.post(f"/vaults/{v['id']}/folders", json={"name": "myfolder"}).status_code in (200, 201)
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault_table(page, v["id"])
        folder_row = page.locator("#vault-files-table-body tr", has=page.locator(".file-name[data-folder-id]")).first
        expect(folder_row).to_be_visible(timeout=15000)
        folder_row.locator('button[data-action="more"]').click()
        page.locator('#file-context-menu button[data-action="rename-folder"]').click()
        expect(page.locator("#rename-modal")).to_be_visible()
        expect(page.locator("#rename-name-input")).to_have_value("myfolder")
        expect(page.locator("#rename-ext-wrap")).to_be_hidden()  # folders have no extension field
    finally:
        admin.delete_vault(v["id"])
