"""UI — the recipient "Shared" tab: cards for claimed shares, opening one into the vault browser,
and the "Claim a link" box.

Setup is done through the API (enable sharing, create vaults + a file + shares, claim one as the
recipient); the browser then logs in AS the recipient and drives the tab.
"""
import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, unique

pytestmark = pytest.mark.ui


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _tag(admin):
    r = admin.post("/share-tags", json={"name": unique("uistag"), "auto_enroll_new_users": True,
                                        "allowed_audiences": ["anyone_internal"], "max_recipients_cap": 10})
    assert r.status_code == 200, r.text
    return r.json()


def _share(admin, vid, tag):
    r = admin.post("/shares", json={"vault_id": vid, "tag_id": tag["id"], "target_type": "vault",
                                    "claim_audience": "anyone_internal"})
    assert r.status_code == 200, r.text
    return r.json()


def test_shared_tab_lists_opens_and_claims(page: Page, admin):
    admin.put("/settings", json={"sharing_enabled": True})
    v1 = admin.create_vault(name=unique("uiShareA"))
    v2 = admin.create_vault(name=unique("uiShareB"))
    recipient = admin.create_user(role="user")
    try:
        # a file in v1 so opening the shared vault shows something
        admin.post(f"/vaults/{v1['id']}/files",
                   files=[("files", ("shared-doc.txt", b"hello shared", "text/plain"))])
        tag = _tag(admin)
        s1 = _share(admin, v1["id"], tag)   # pre-claimed via API -> a card should already show
        s2 = _share(admin, v2["id"], tag)   # claimed through the UI box below

        rc = ApiClient()
        rc.login(recipient["_username"], recipient["_password"])
        assert rc.post("/shares/claim", json={"token": s1["link_token"]}).status_code == 200

        # --- log in as the recipient and open the Shared tab ---
        _login(page, recipient["_username"], recipient["_password"])
        page.click('.sidebar-item[data-section="shared"]')
        expect(page.locator("#shared-section")).to_be_visible()
        # the pre-claimed vault's card is present
        card1 = page.locator(f'#shared-list .vault-card[data-share-id="{s1["id"]}"]')
        expect(card1).to_be_visible(timeout=10000)
        expect(card1).to_contain_text(v1["name"])

        # --- open the shared vault: the standard browser shows the file ---
        card1.locator(".open-shared-btn").click()
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)
        expect(page.get_by_text("shared-doc.txt")).to_be_visible(timeout=10000)

        # --- back to Shared, claim the second share via the link box ---
        page.click('.sidebar-item[data-section="shared"]')
        expect(page.locator("#shared-section")).to_be_visible()
        page.fill("#claim-link-input", s2["link_token"])
        with page.expect_response(
            lambda r: r.url.rstrip("/").endswith("/shares/claim") and r.request.method == "POST"
        ) as resp:
            page.click("#claim-link-btn")
        assert resp.value.ok, f"claim failed: {resp.value.status}"
        # the newly-claimed vault's card now appears
        expect(page.locator(f'#shared-list .vault-card[data-share-id="{s2["id"]}"]')).to_be_visible(timeout=10000)
    finally:
        admin.delete_user(recipient["id"])
        admin.delete_vault(v1["id"])
        admin.delete_vault(v2["id"])


def test_shared_tab_empty_state(page: Page, admin):
    """A user with no claimed shares sees the empty state + the claim box."""
    admin.put("/settings", json={"sharing_enabled": True})
    u = admin.create_user(role="user")
    try:
        _login(page, u["_username"], u["_password"])
        page.click('.sidebar-item[data-section="shared"]')
        expect(page.locator("#shared-section")).to_be_visible()
        expect(page.locator("#claim-link-input")).to_be_visible()
        expect(page.locator("#shared-list")).to_contain_text("Nothing shared with you yet", timeout=10000)
    finally:
        admin.delete_user(u["id"])
