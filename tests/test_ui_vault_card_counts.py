"""A vault card counts the vault's members and departments, and says nothing it does not know.

Every card read "1 members": the page fell back to 1 because the list never sent a count. The card
now shows the counts the server sends -- the owner and direct members, then any departments granted
access -- with "member" for one, and leaves them off entirely for a caller who may not see the
vault's access lists rather than inventing a number.
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


def _card_meta(page: Page, vault_id: str):
    page.evaluate("() => navigateToSection('vaults')")
    page.wait_for_selector("#vaults-section.active", timeout=10000)
    meta = page.locator(f'.vault-card[data-vault-id="{vault_id}"] .vault-meta')
    expect(meta).to_be_visible(timeout=10000)
    return meta


def test_the_card_counts_the_members_and_says_member_for_one(page: Page, admin, temp_user,
                                                             temp_user_client):
    vault = temp_user_client.create_vault(name=unique("card-own"))
    other = admin.create_user(role="user")
    dept = admin.post("/groups", json={"name": unique("card-dept")}).json()
    try:
        _login(page, temp_user["_username"], temp_user["_password"])
        meta = _card_meta(page, vault["id"])
        expect(meta).to_contain_text("1 member")
        expect(meta).not_to_contain_text("1 members")
        expect(meta).to_contain_text("0 files")

        r = temp_user_client.post(f"/vaults/{vault['id']}/permissions",
                                  json={"user_id": other["id"], "level": "read"})
        assert r.status_code in (200, 201), r.text
        page.reload()
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        meta = _card_meta(page, vault["id"])
        expect(meta).to_contain_text("2 members")
        expect(meta).not_to_contain_text("department")

        r = admin.post(f"/vaults/{vault['id']}/group-access",
                       json={"group_id": dept["id"], "permission": "read"})
        assert r.status_code in (200, 201), r.text
        page.reload()
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        expect(_card_meta(page, vault["id"])).to_contain_text("2 members · 1 department")
    finally:
        temp_user_client.delete_vault(vault["id"])
        admin.delete_user(other["id"])
        admin.delete(f"/groups/{dept['id']}")


def test_a_read_only_member_sees_no_member_count(page: Page, admin, temp_user, temp_vault):
    r = admin.post(f"/vaults/{temp_vault['id']}/permissions",
                   json={"user_id": temp_user["id"], "level": "read"})
    assert r.status_code in (200, 201), r.text
    _login(page, temp_user["_username"], temp_user["_password"])
    meta = _card_meta(page, temp_vault["id"])
    expect(meta).to_contain_text("0 files")
    expect(meta).not_to_contain_text("member")
    expect(meta).not_to_contain_text("department")
