"""The upload page (/u) collects properly, and the drop vault can be triaged.

The page shows the deployment's name and, for a link without a code, the owner's message before anything is
sent (a protected link's message appears once its code is accepted); it takes several files at once and gives
a receipt (the name as sent, size, time, a reference). A file whose name the drop vault already holds is stored
under a new name, which the owner sees and the uploader is not told. The owner's drop vault has a Move to vault
action that moves the received files into a vault of the owner's. The owner sees the message on the drop-vault
card.
"""
import pytest
from playwright.sync_api import Page, expect

from conftest import unique

pytestmark = pytest.mark.ui

_MB = 1024 * 1024


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


@pytest.fixture
def receivers_enabled(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ("public_receivers_enabled", "public_receiver_user_cap")}
    admin.put("/settings", json={"public_receivers_enabled": True, "public_receiver_user_cap": 50})
    yield
    admin.put("/settings", json=snap)


@pytest.fixture
def link(admin, receivers_enabled):
    tag = admin.post("/receiver-tags", json={"name": unique("rtag"), "min_token_len": 6, "require_secret": "none",
                                             "max_total_bytes_cap": 100 * _MB, "auto_enroll_new_users": True}).json()
    rec = admin.post("/receivers", json={"tag_id": tag["id"], "max_total_bytes": 10 * _MB, "label": unique("Drop"),
                                         "message": "Please send the signed pages."})
    assert rec.status_code == 200, rec.text
    return rec.json()


def test_the_page_takes_several_files_and_gives_a_receipt(page: Page, admin, link):
    # The same name already in the drop vault: the page's copy is stored under a new name.
    page.goto(f"/u/{link['token']}")
    expect(page.locator("#form")).to_be_visible(timeout=15000)
    expect(page.locator("#owner-message")).to_have_text("Please send the signed pages.")
    brand = admin.get("/branding").json().get("name") or admin.get("/branding").json().get("app_name")
    if brand:
        expect(page.locator("#brand")).to_contain_text(brand)
    expect(page.locator("#upload-btn")).to_be_disabled()
    page.set_input_files("#file-input", files=[
        {"name": "one.txt", "mimeType": "text/plain", "buffer": b"one"},
        {"name": "two.txt", "mimeType": "text/plain", "buffer": b"two two"},
    ])
    expect(page.locator("#files li")).to_have_count(2)
    expect(page.locator("#upload-btn")).to_have_text("Upload 2 files")
    # One can be taken out again before sending.
    page.set_input_files("#file-input", files=[{"name": "three.txt", "mimeType": "text/plain", "buffer": b"3"}])
    expect(page.locator("#files li")).to_have_count(3)
    page.locator('#files li button[aria-label="Remove three.txt"]').click()
    expect(page.locator("#files li")).to_have_count(2)
    page.click("#upload-btn")
    expect(page.locator("#receipt")).to_be_visible(timeout=20000)
    rows = page.locator("#receipt-rows tr")
    expect(rows).to_have_count(2)
    expect(page.locator("#receipt-intro")).to_contain_text("2 files were delivered")
    refs = [t.strip() for t in page.locator("#receipt-rows td.ref").all_inner_texts()]
    assert all(len(r) == 8 for r in refs), refs
    names = sorted(f["name"] for f in admin.get(f"/vaults/{link['vault_id']}/files").json()["items"])
    assert names == ["one.txt", "two.txt"]
    ids = {f["name"]: f["id"][:8].upper() for f in admin.get(f"/vaults/{link['vault_id']}/files").json()["items"]}
    assert set(refs) == set(ids.values())
    # Sending the same name again: delivered, stored under a new name the owner sees; the receipt names the
    # file as it was sent and says nothing of the rename.
    page.click("#more-btn")
    expect(page.locator("#form")).to_be_visible()
    expect(page.locator("#files li")).to_have_count(0)
    page.set_input_files("#file-input", files=[{"name": "one.txt", "mimeType": "text/plain", "buffer": b"again"}])
    page.click("#upload-btn")
    expect(page.locator("#receipt")).to_be_visible(timeout=20000)
    expect(page.locator("#receipt-rows tr").last).to_contain_text("one.txt")
    assert "(2)" not in page.locator("#receipt").inner_text()
    assert "renamed" not in page.locator("#receipt").inner_text().lower()
    names = sorted(f["name"] for f in admin.get(f"/vaults/{link['vault_id']}/files").json()["items"])
    assert names == ["one (2).txt", "one.txt", "two.txt"]


def test_a_protected_link_shows_the_owners_message_once_the_code_is_accepted(page: Page, admin, receivers_enabled):
    tag = admin.post("/receiver-tags", json={"name": unique("rtag"), "min_token_len": 6, "require_secret": "pin",
                                             "min_pin_len": 4, "max_total_bytes_cap": 100 * _MB,
                                             "auto_enroll_new_users": True}).json()
    rec = admin.post("/receivers", json={"tag_id": tag["id"], "max_total_bytes": 10 * _MB, "label": unique("Drop"),
                                         "pin": "4321", "message": "Please send the signed pages."})
    assert rec.status_code == 200, rec.text
    page.goto(f"/u/{rec.json()['token']}")
    expect(page.locator("#form")).to_be_visible(timeout=15000)
    expect(page.locator("#secret-input")).to_be_visible()
    # Before the code: the brand and the prompt, and no message anywhere on the page.
    expect(page.locator("#owner-message")).to_be_hidden()
    assert "Please send the signed pages." not in page.content()
    page.set_input_files("#file-input", files=[{"name": "one.txt", "mimeType": "text/plain", "buffer": b"one"}])
    page.fill("#secret-input", "4321")
    page.click("#upload-btn")
    expect(page.locator("#owner-message")).to_have_text("Please send the signed pages.", timeout=15000)
    expect(page.locator("#receipt")).to_be_visible(timeout=20000)


def test_the_owner_triages_the_drop_vault_into_a_vault(page: Page, admin, admin_creds, link):
    anon = admin.clone_anonymous()
    for name in ("a.txt", "b.txt"):
        o = anon.post(f"/receivers/{link['token']}/upload-session", json={"filename": name, "total_size": 1, "total_chunks": 1})
        sid = o.json()["session_id"]
        anon.put(f"/receivers/{link['token']}/upload-session/{sid}/chunks/0", data=b"x",
                 headers={"Content-Type": "application/octet-stream"})
        assert anon.post(f"/receivers/{link['token']}/upload-session/{sid}/complete", json={}).status_code == 200
    dest = admin.create_vault(name=unique("Dest"))
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        page.click('.sidebar-item[data-section="uploadlinks"]')
        page.click('button[data-rc-tab="vaults"]')
        card = page.locator(".rc-vault-card", has_text=link["label"]).first
        expect(card).to_be_visible(timeout=15000)
        expect(card.locator(".rc-message")).to_have_text("Please send the signed pages.")
        card.locator('button:has-text("Open vault")').click()
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=15000)
        expect(page.locator("#vault-files-table-body tr")).to_have_count(2, timeout=15000)
        expect(page.locator("#move-to-vault-btn")).to_be_visible()   # with nothing selected: everything here
        page.locator('.file-check[data-id]').first.check()
        page.locator("#files-bulk-move-vault").click()               # with a selection: the selected files
        expect(page.locator("#move-to-vault-modal.active")).to_be_visible()
        expect(page.locator("#mtv-summary")).to_contain_text("1 file selected")
        page.select_option("#mtv-dest", dest["id"])
        page.click("#mtv-move")
        expect(page.locator("#toast-container")).to_contain_text("Moved 1 file", timeout=15000)
        expect(page.locator("#vault-files-table-body tr")).to_have_count(1, timeout=15000)
        moved = admin.get(f"/vaults/{dest['id']}/files").json()["items"]
        assert len(moved) == 1
    finally:
        admin.delete_vault(dest["id"])
