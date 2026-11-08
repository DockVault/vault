"""A view-only share's recipient can view a file in the browser, and still cannot download it.

The share dialog says "View only (recipients can view files in the browser but not download them)" and that a
preview cannot stop copying. In the recipient's own session the shared vault opens from the Shared page, a
file's preview shows its content through the preview route, and the download route refuses them.
"""
import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.ui


def _login(page: Page, user):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", user["_username"])
    page.fill("#password", user["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


@pytest.fixture
def view_only_share(admin):
    before = admin.get("/settings").json().get("sharing_enabled")
    admin.put("/settings", json={"sharing_enabled": True})
    recipient = admin.create_user(role="user")
    client = ApiClient(BASE_URL)
    client.login(recipient["_username"], recipient["_password"])
    vault = admin.create_vault(name=unique("deck"))
    r = admin.post(f"/vaults/{vault['id']}/files", files=[("files", ("brief.txt", b"look, do not take\n" * 5, "text/plain"))])
    assert r.status_code == 200, r.text
    fid = next(f["id"] for f in admin.get(f"/vaults/{vault['id']}/files").json()["items"] if f["name"] == "brief.txt")
    tag = admin.post("/share-tags", json={"name": unique("votag"), "auto_enroll_new_users": True,
                                          "allowed_audiences": ["anyone_internal"], "max_recipients_cap": 10,
                                          "allow_view_only": True}).json()
    share = admin.post("/shares", json={"vault_id": vault["id"], "tag_id": tag["id"], "target_type": "vault",
                                        "claim_audience": "anyone_internal", "view_only": True})
    assert share.status_code == 200, share.text
    assert client.post("/shares/claim", json={"token": share.json()["link_token"]}).status_code == 200
    try:
        yield recipient, client, vault, fid
    finally:
        admin.delete_vault(vault["id"])
        admin.delete_user(recipient["id"])
        admin.put("/settings", json={"sharing_enabled": before})


def test_the_recipient_previews_in_the_browser_and_cannot_download(page: Page, view_only_share):
    recipient, client, vault, fid = view_only_share
    _login(page, recipient)
    page.click('.sidebar-item[data-section="shared"]')
    card = page.locator(f'[data-share-id]', has_text=vault["name"]).first
    expect(card).to_be_visible(timeout=15000)
    expect(card).to_contain_text("View only (preview in the browser, no download)")
    page.evaluate("id => openSharedItem(id)", vault["id"])
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=15000)
    page.click(f'.file-name[data-file-id="{fid}"]')
    expect(page.locator("#file-preview-modal")).to_be_visible(timeout=10000)
    expect(page.locator("#file-preview-body")).to_contain_text("look, do not take", timeout=15000)
    # The same session cannot download.
    assert client.get(f"/vaults/{vault['id']}/files/{fid}/download").status_code == 403


def test_the_share_dialog_says_what_view_only_means(page: Page, admin_creds):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", admin_creds["username"])
    page.fill("#password", admin_creds["password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    label = page.locator('label:has(#share-view-only)')
    expect(label).to_have_text("View only (recipients can view files in the browser but not download them)")
    expect(page.locator("#share-viewonly-group .form-help")).to_contain_text("cannot stop copying")
