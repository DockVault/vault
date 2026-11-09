"""The selection bar copies and cuts into the Copied Items list, folders can be selected, and a paste waits the
time the server asks for.

  * Selecting a folder is possible (its checkbox exists); Select all takes files and folders.
  * Copy and Cut on the selection bar stage every selected item into the staging list in one go, with one notice,
    and clear the selection; Copy is not offered in a zero-knowledge vault, Cut still is.
  * A paste answered 429 with Retry-After waits that long and tries again, once per item, and then succeeds.
"""
import json

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


def _open_vault(page: Page, vault_id: str):
    page.click('.sidebar-item[data-section="vaults"]')
    page.click(f'.open-vault-btn[data-vault-id="{vault_id}"]')
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)
    page.click('[data-files-view="table"]')


def _upload(client, vault_id, name, content=b"x", folder_id=None):
    params = {"folder_id": folder_id} if folder_id else None
    r = client.post(f"/vaults/{vault_id}/files", files=[("files", (name, content, "text/plain"))], params=params)
    r.raise_for_status()
    return r.json()["files"][0]["id"]


def _mkfolder(client, vault_id, name):
    r = client.post(f"/vaults/{vault_id}/folders", json={"name": name})
    r.raise_for_status()
    return r.json()["folder"]["id"]


@pytest.fixture
def world(admin):
    v = admin.create_vault(name=unique("selcc"))
    fid = _upload(admin, v["id"], unique("doc") + ".txt", b"copy me\n" * 10)
    folder = _mkfolder(admin, v["id"], unique("fold"))
    dest = _mkfolder(admin, v["id"], unique("dest"))
    try:
        yield {"vault": v, "file": fid, "folder": folder, "dest": dest}
    finally:
        admin.delete_vault(v["id"])


def test_folders_select_and_copy_cut_stage_the_whole_selection(page: Page, admin_creds, world):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_vault(page, world["vault"]["id"])
    expect(page.locator("#vault-files-table-body tr")).to_have_count(3, timeout=15000)
    # A folder has a checkbox too, and Select all takes everything listed.
    expect(page.locator(f'.file-check[data-id="{world["folder"]}"]')).to_have_count(1)
    page.locator("#files-select-all").check()
    expect(page.locator("#files-bulk-count")).to_have_text("3")
    copy = page.locator("#files-bulk-copy")
    expect(copy).to_be_visible()
    expect(page.locator("#files-bulk-cut")).to_be_visible()
    copy.click()
    expect(page.locator("#toast-container")).to_contain_text("Copied 3 items")
    expect(page.locator("#copied-items-count")).to_have_text("3")
    # The selection empties once staged.
    expect(page.locator("#files-bulk-bar")).to_be_hidden()
    # Cut re-stages the same items as moves: still three in the list, now cut.
    page.locator(f'.file-check[data-id="{world["file"]}"]').check()
    page.locator("#files-bulk-cut").click()
    expect(page.locator("#toast-container")).to_contain_text("Cut 1 item.")
    expect(page.locator("#copied-items-count")).to_have_text("3")
    page.locator("#copied-items-btn").click()
    expect(page.locator("#copied-items-panel")).to_be_visible()
    moves = page.evaluate("() => (state.moveCopyClip || []).filter(e => e.action === 'move').length")
    assert moves == 1


def test_copy_is_not_offered_in_a_zero_knowledge_vault_but_cut_is(page: Page, admin_creds, world):
    """Driven on the bar's own logic with the open vault marked zero-knowledge: the same code path the page runs
    when a zero-knowledge vault is open (the files of such a vault are never copied server-side)."""
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_vault(page, world["vault"]["id"])
    expect(page.locator("#vault-files-table-body tr")).to_have_count(3, timeout=15000)
    page.locator(f'.file-check[data-id="{world["file"]}"]').check()
    expect(page.locator("#files-bulk-copy")).to_be_visible()
    page.evaluate("() => { state.currentVault.type = 'zero_knowledge'; updateFilesBulkBar(); }")
    expect(page.locator("#files-bulk-copy")).to_be_hidden()
    expect(page.locator("#files-bulk-cut")).to_be_visible()
    page.evaluate("() => { state.currentVault.type = 'standard'; updateFilesBulkBar(); }")
    expect(page.locator("#files-bulk-copy")).to_be_visible()


def test_a_paste_waits_the_time_the_server_asks_and_tries_again(page: Page, admin_creds, world):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_vault(page, world["vault"]["id"])
    expect(page.locator("#vault-files-table-body tr")).to_have_count(3, timeout=15000)
    page.locator(f'.file-check[data-id="{world["file"]}"]').check()
    page.locator("#files-bulk-copy").click()
    expect(page.locator("#copied-items-count")).to_have_text("1")
    # The first copy request is answered as the account's own copies being ahead of it; the second goes through.
    seen = {"n": 0}

    def answer(route):
        seen["n"] += 1
        if seen["n"] == 1:
            route.fulfill(status=429, headers={"Retry-After": "1", "Content-Type": "application/json"},
                          body=json.dumps({"detail": "This account already has 1 copy or move running at once."}))
        else:
            route.continue_()

    page.route(f"**/files/{world['file']}/copy", answer)
    page.click(f'.file-name[data-folder-id="{world["dest"]}"]')
    page.locator("#copied-items-btn").click()
    expect(page.locator("#copied-items-panel")).to_be_visible()
    page.locator("#ci-select-all").check()
    page.locator('#ci-action-buttons button:has-text("Paste")').click()
    expect(page.locator("#toast-container")).to_contain_text("waiting 1s", timeout=5000)
    expect(page.locator("#toast-container")).to_contain_text("Pasted 1 item", timeout=15000)
    assert seen["n"] == 2, seen
    expect(page.locator("#vault-files-table-body .file-name[data-file-id]")).to_have_count(1, timeout=10000)


def test_the_row_menu_follows_the_same_copy_rule_as_the_bar(page: Page, admin_creds, world):
    """In a zero-knowledge vault the row's own menu offers no Copy either (Move stays), as the selection bar
    does; one rule decides both. Driven on the open vault marked zero-knowledge, as the bar's test is."""
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_vault(page, world["vault"]["id"])
    expect(page.locator("#vault-files-table-body tr")).to_have_count(3, timeout=15000)

    def menu_labels(item_id):
        page.evaluate("id => openContextMenu((state.currentFiles || []).find(i => i.id === id), 10, 10)", item_id)
        menu = page.locator("#file-context-menu")
        expect(menu).to_be_visible()
        labels = [t.strip() for t in menu.locator(".context-menu-item").all_text_contents()]
        page.keyboard.press("Escape")
        expect(menu).to_be_hidden()
        return labels

    assert "Copy" in menu_labels(world["file"])
    assert "Copy" in menu_labels(world["folder"])
    page.evaluate("() => { state.currentVault.type = 'zero_knowledge'; }")
    for item in (world["file"], world["folder"]):
        labels = menu_labels(item)
        assert "Copy" not in labels and "Add to copy list" not in labels, labels
        assert "Move" in labels or "Add to move list" in labels, labels
    page.evaluate("() => { state.currentVault.type = 'standard'; }")
