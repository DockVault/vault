"""Removing a zero-knowledge member without the key, and the rotation it leaves owed, in real browsers.

Only someone who holds a zero-knowledge vault's key may rotate it: the rotation happens in their
browser, which mints the new key and so learns it. Two things follow in the web app, and this file
drives both with real crypto:

  * Someone who may manage the vault but does not hold its key (here a keyless Manager) removes a
    member with the removal alone. The confirmation says so, no rotation is attempted, and the
    server leaves the vault owing one.
  * A key holder who opens a vault that owes a rotation is told, and the notice's button runs a
    rotation that removes nobody -- in a direct vault and in a team (hierarchical) vault, where it
    has to replace the team keypair. Afterwards the notice is gone and the holder's browser can
    still unwrap the new key, so the wrap it wrote for them is usable, not merely stored.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import Page, expect

from conftest import (
    ApiClient, BASE_URL, ZK_EPHEMERAL_STUB, ZK_WRAPPED_DEK_STUB, ensure_ecc_keypair,
)
from test_ui_e2e import _create_zk_vault_via_ui, _login, _u

pytestmark = pytest.mark.ui

CAN_UNWRAP_CURRENT_KEY = """async (vaultId) => {
    const dek = await zkGetVaultDek(vaultId);
    return !!dek;
}"""


def _client(person):
    c = ApiClient()
    c.login(person["_username"], person["_password"])
    return c


def _open_vault(page: Page, vault_id: str):
    page.click('.sidebar-item[data-section="vaults"]')
    page.wait_for_selector(f'.open-vault-btn[data-vault-id="{vault_id}"]', timeout=10000)
    page.click(f'.open-vault-btn[data-vault-id="{vault_id}"]')
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)


def _create_team_vault_via_ui(page: Page, owner_client) -> str:
    """Create a team (hierarchical) zero-knowledge vault through the form. The owner's encryption
    key must already be set up and unlocked in this page."""
    vname = _u("team")
    page.click('.sidebar-item[data-section="vaults"]')
    page.click("#create-vault-btn")
    expect(page.locator("#create-vault-modal")).to_be_visible()
    page.fill("#vault-name", vname)
    page.select_option("#vault-type", "zero_knowledge")
    expect(page.locator("#vault-label-group")).to_be_visible(timeout=5000)
    page.fill("#vault-label", vname)
    page.check("#vault-hierarchical")
    page.click("#create-vault-form button[type=submit]")
    expect(page.locator("#create-vault-modal")).to_be_hidden(timeout=15000)
    m = [v for v in owner_client.get("/vaults").json() if v["name"] == vname]
    assert m, "the team vault was not created"
    return m[0]["id"]


def _rotate_from_the_notice(page: Page, owner_client, vault_id: str) -> dict:
    """Open the vault as its key holder, expect the notice, press its button, and return the
    owner's key state once the notice has gone."""
    assert owner_client.get(f"/ecc/vaults/{vault_id}/keys").json()["rekey_owed"] is True
    _open_vault(page, vault_id)
    notice = page.locator("#vault-rekey-notice")
    expect(notice).to_be_visible(timeout=10000)
    expect(notice).to_contain_text("removed from this vault without a key rotation")
    page.click("#vault-rekey-notice-btn")
    expect(notice).to_be_hidden(timeout=20000)
    keys = owner_client.get(f"/ecc/vaults/{vault_id}/keys").json()
    assert keys["rekey_owed"] is False and keys["has_access"] is True
    assert page.evaluate(CAN_UNWRAP_CURRENT_KEY, vault_id) is True, (
        "the rotation stored a key the holder's own browser cannot unwrap")
    return keys


def test_a_manager_without_the_key_removes_and_the_owner_rotates(browser, admin):
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    owner, manager, member = (admin.create_user(role="user") for _ in range(3))
    co, cm, cx = _client(owner), _client(manager), _client(member)
    ctx_o = browser.new_context(base_url=BASE_URL)
    ctx_m = browser.new_context(base_url=BASE_URL)
    page_o, page_m = ctx_o.new_page(), ctx_m.new_page()
    vid = vid_m = None
    try:
        _login(page_o, owner["_username"], owner["_password"])
        vid = _create_zk_vault_via_ui(page_o, co, "passphrase-O-123")
        # The Manager sets up their own encryption key (by creating a vault of their own), so the
        # app lets them open zero-knowledge vaults; they are never given THIS vault's key.
        _login(page_m, manager["_username"], manager["_password"])
        vid_m = _create_zk_vault_via_ui(page_m, cm, "passphrase-M-123")

        ensure_ecc_keypair(cx)
        co.post(f"/ecc/vaults/{vid}/members", json={
            "user_id": member["id"], "wrapped_dek": ZK_WRAPPED_DEK_STUB,
            "ephemeral_public_key": ZK_EPHEMERAL_STUB}).raise_for_status()
        co.post(f"/vaults/{vid}/permissions",
                json={"user_id": member["id"], "level": "read"}).raise_for_status()
        co.post(f"/vaults/{vid}/permissions",
                json={"user_id": manager["id"], "level": "manage"}).raise_for_status()
        assert cm.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is False

        rotations = []
        page_m.on("request", lambda req: rotations.append(req.url) if "/rekey" in req.url else None)
        _open_vault(page_m, vid)
        page_m.click('[data-vault-tab="permissions"]')
        page_m.click(f'button[data-action="revoke-permission"][data-user-id="{member["id"]}"]')
        expect(page_m.locator("#confirm-modal")).to_be_visible(timeout=5000)
        expect(page_m.locator("#confirm-modal-message")).to_contain_text(
            "someone who holds the key will be asked to rotate it")
        page_m.click("#confirm-modal-confirm-btn")

        for _ in range(40):
            listed = {p["user_id"] for p in co.get(f"/vaults/{vid}/permissions").json()}
            if member["id"] not in listed:
                break
            page_m.wait_for_timeout(250)
        else:
            pytest.fail("the member was never removed")
        assert rotations == [], f"a Manager without the key attempted a rotation: {rotations}"
        assert cx.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is False
        keys = co.get(f"/ecc/vaults/{vid}/keys").json()
        assert keys["current_dek_version"] == 1 and keys["rekey_owed"] is True
        # The Manager holds no key, so they are not the one asked to rotate.
        expect(page_m.locator("#vault-rekey-notice")).to_be_hidden()

        keys = _rotate_from_the_notice(page_o, co, vid)
        assert keys["current_dek_version"] == 2
    finally:
        for ctx in (ctx_o, ctx_m):
            try:
                ctx.close()
            except Exception:
                pass
        if vid:
            co.delete_vault(vid)
        if vid_m:
            cm.delete_vault(vid_m)
        for person in (owner, manager, member):
            admin.delete_user(person["id"])
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def test_the_notice_rotates_a_team_vault_whose_member_was_removed_without_a_rotation(browser, admin):
    """A team vault owes a rotation of the whole team keypair, since the removed member saw the team
    private key. The notice's rotation removes nobody and must still replace it."""
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    owner, member = (admin.create_user(role="user") for _ in range(2))
    co, cx = _client(owner), _client(member)
    ctx = browser.new_context(base_url=BASE_URL)
    page = ctx.new_page()
    vids = []
    try:
        _login(page, owner["_username"], owner["_password"])
        vids.append(_create_zk_vault_via_ui(page, co, "passphrase-T-123"))  # sets up the owner's key
        vid = _create_team_vault_via_ui(page, co)
        vids.append(vid)
        assert co.get(f"/ecc/vaults/{vid}/keys").json()["mode"] == "hierarchical"

        ensure_ecc_keypair(cx)
        co.post(f"/ecc/vaults/{vid}/members", json={
            "user_id": member["id"], "wrapped_team_privkey": ZK_WRAPPED_DEK_STUB,
            "team_ephemeral_public_key": ZK_EPHEMERAL_STUB}).raise_for_status()
        co.post(f"/vaults/{vid}/permissions",
                json={"user_id": member["id"], "level": "read"}).raise_for_status()
        # A global admin, who may manage the vault but holds none of its keys, removes the member.
        admin.delete(f"/vaults/{vid}/permissions/{member['id']}").raise_for_status()

        keys = _rotate_from_the_notice(page, co, vid)
        assert keys["team_key_version"] == 2 and keys["current_dek_version"] == 2
    finally:
        try:
            ctx.close()
        except Exception:
            pass
        for v in vids:
            co.delete_vault(v)
        for person in (owner, member):
            admin.delete_user(person["id"])
        admin.put("/settings", json={"zero_knowledge_enabled": False})
