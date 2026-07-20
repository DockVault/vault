"""UI — a directly-pushed share appears as an 'Available' card in the recipient's Shared-with-me tab
and can be claimed in one click (no link needed)."""
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


def _tag(admin):
    r = admin.post("/share-tags", json={"name": unique("dpuitag"), "auto_enroll_new_users": True,
                                        "allowed_audiences": ["users"], "max_recipients_cap": 10})
    assert r.status_code == 200, r.text
    return r.json()


def test_pushed_share_shows_available_and_claims(page: Page, admin):
    admin.put("/settings", json={"sharing_enabled": True})
    v = admin.create_vault(name=unique("dpuiv"))
    recipient = admin.create_user(role="user")
    try:
        share = admin.post("/shares", json={"vault_id": v["id"], "tag_id": _tag(admin)["id"],
                                            "target_type": "vault", "claim_audience": "users",
                                            "audience_user_ids": [recipient["id"]]}).json()
        _login(page, recipient["_username"], recipient["_password"])
        page.click('.sidebar-item[data-section="shared"]')
        expect(page.locator("#shared-section")).to_be_visible()
        card = page.locator(f'#shared-list .vault-card[data-share-id="{share["id"]}"]')
        expect(card).to_be_visible(timeout=10000)
        expect(card).to_contain_text("Available")
        # claim it in one click
        with page.expect_response(
            lambda r: r.url.rstrip("/").endswith(f"/shares/{share['id']}/claim") and r.request.method == "POST"
        ) as resp:
            card.locator('button:has-text("Claim")').click()
        assert resp.value.ok, f"claim failed: {resp.value.status}"
        # after reload it becomes an openable (claimed) card — no more Claim button
        card2 = page.locator(f'#shared-list .vault-card[data-share-id="{share["id"]}"]')
        expect(card2.locator(".open-shared-btn")).to_be_visible(timeout=10000)
    finally:
        admin.delete_user(recipient["id"])
        admin.delete_vault(v["id"])
