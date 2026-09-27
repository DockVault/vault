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

And three things that must not happen: the notice is not shown to a key holder who may not manage
the vault; a removal whose key check fails removes nobody (removing without a rotation is the weaker
path, taken only when the answer is that the remover holds no key); and a key holder removing
themselves never rotates. Where no browser has to open a vault's key, these use stand-in wraps.
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import Page, expect

from conftest import (
    ApiClient, BASE_URL, ZK_EPHEMERAL_STUB, ZK_WRAPPED_DEK_STUB, create_zk_vault, ensure_ecc_keypair,
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


# --------------------------------------------------------------------------- what must not happen

ROTATION_REQUESTS = ("/member-keys", "/rekey")   # a rotation's first request, and its last


def _watch_rotations(page: Page) -> list:
    seen = []
    page.on("request", lambda req: seen.append(req.url)
            if any(part in req.url for part in ROTATION_REQUESTS) else None)
    return seen


def _stub_share(owner_client, vault_id: str, person: dict, level: str):
    """Share the way the web app does (wrap the key, then grant access), with a stand-in wrap."""
    owner_client.post(f"/ecc/vaults/{vault_id}/members", json={
        "user_id": person["id"], "wrapped_dek": ZK_WRAPPED_DEK_STUB,
        "ephemeral_public_key": ZK_EPHEMERAL_STUB}).raise_for_status()
    owner_client.post(f"/vaults/{vault_id}/permissions",
                      json={"user_id": person["id"], "level": level}).raise_for_status()


def _listed(owner_client, vault_id: str) -> set:
    return {p["user_id"] for p in owner_client.get(f"/vaults/{vault_id}/permissions").json()}


def test_the_notice_is_not_shown_to_a_key_holder_who_cannot_manage_the_vault(browser, admin):
    """A member with read access holds the key, and the vault owes a rotation. The server reports it
    to them, as to every key holder; the notice is still not theirs, since its button rotates the
    key and that needs the right to manage the vault."""
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    owner, reader, gone = (admin.create_user(role="user") for _ in range(3))
    co, cr, cg = _client(owner), _client(reader), _client(gone)
    ctx = browser.new_context(base_url=BASE_URL)
    page = ctx.new_page()
    vid = vid_r = None
    try:
        ensure_ecc_keypair(co)
        vid = create_zk_vault(co)["id"]
        _login(page, reader["_username"], reader["_password"])
        vid_r = _create_zk_vault_via_ui(page, cr, "passphrase-R-123")   # sets up the reader's key
        _stub_share(co, vid, reader, "read")
        ensure_ecc_keypair(cg)
        _stub_share(co, vid, gone, "read")
        admin.delete(f"/vaults/{vid}/permissions/{gone['id']}").raise_for_status()
        keys = cr.get(f"/ecc/vaults/{vid}/keys").json()
        assert keys["has_access"] is True and keys["rekey_owed"] is True, keys

        _open_vault(page, vid)
        # The open refreshes the notice without waiting for it; run that refresh to its end here.
        page.evaluate("() => refreshZkRekeyNotice()")
        expect(page.locator("#vault-rekey-notice")).to_be_hidden()
    finally:
        try:
            ctx.close()
        except Exception:
            pass
        if vid:
            co.delete_vault(vid)
        if vid_r:
            cr.delete_vault(vid_r)
        for person in (owner, reader, gone):
            admin.delete_user(person["id"])
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def test_a_removal_whose_key_check_fails_removes_nobody(browser, admin):
    """Whether the remover holds the key decides between rotating and removing alone. When reading
    that fails -- the network drops, or the server errs -- the app cannot know which applies, so it
    removes nobody and says nothing was changed, rather than take a key holder for someone without
    the key and remove without the rotation they could have run. A refusal is different: the server
    refuses the key check only to someone with no key in the vault, so it is an answer, and the
    removal goes ahead without a rotation. Once the check answers again, the same click rotates and
    removes."""
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    owner, member, other = (admin.create_user(role="user") for _ in range(3))
    co, cx, cy = _client(owner), _client(member), _client(other)
    ctx = browser.new_context(base_url=BASE_URL)
    page = ctx.new_page()
    vid = None
    try:
        _login(page, owner["_username"], owner["_password"])
        vid = _create_zk_vault_via_ui(page, co, "passphrase-F-123")
        for person, client in ((member, cx), (other, cy)):
            ensure_ecc_keypair(client)
            _stub_share(co, vid, person, "read")
        _open_vault(page, vid)
        page.click('[data-vault-tab="permissions"]')
        revoke = page.locator(f'button[data-action="revoke-permission"][data-user-id="{member["id"]}"]')
        expect(revoke).to_be_visible(timeout=10000)

        writes = []   # a removal, or any step of a rotation
        page.on("request", lambda req: writes.append(f"{req.method} {req.url}")
                if (req.method == "DELETE" and "/permissions/" in req.url)
                or any(p in req.url for p in ROTATION_REQUESTS) else None)
        keys_url = re.compile(rf"/ecc/vaults/{vid}/keys(\?|$)")
        toasts = page.locator("#toast-container .toast")
        failures = {
            "the network drops": lambda route: route.abort(),
            "the server errs": lambda route: route.fulfill(
                status=500, content_type="application/json", body='{"detail": "unavailable"}'),
        }
        for how, fail in failures.items():
            expect(toasts).to_have_count(0, timeout=15000)
            page.route(keys_url, fail)
            revoke.click()
            expect(page.locator("#toast-container .toast-error")).to_contain_text(
                "Nothing was changed", timeout=10000)
            expect(page.locator("#confirm-modal")).to_be_hidden()
            page.unroute(keys_url)
            assert writes == [], f"when {how}, the app still acted: {writes}"
        assert {member["id"], other["id"]} <= _listed(co, vid)
        assert cx.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is True

        # A refusal (here a stand-in 403, as the server gives someone with no key in the vault) is
        # an answer: the other member is removed without a rotation.
        page.route(keys_url, lambda route: route.fulfill(
            status=403, content_type="application/json",
            body='{"detail": "No access to this vault\'s keys"}'))
        page.click(f'button[data-action="revoke-permission"][data-user-id="{other["id"]}"]')
        expect(page.locator("#confirm-modal-message")).to_contain_text(
            "You don't hold this vault's key", timeout=10000)
        page.click("#confirm-modal-confirm-btn")
        for _ in range(40):
            if other["id"] not in _listed(co, vid):
                break
            page.wait_for_timeout(250)
        else:
            pytest.fail("a refused key check stopped the removal")
        page.unroute(keys_url)
        assert [w for w in writes if not w.startswith("DELETE")] == [], (
            f"a rotation was attempted without the key: {writes}")
        assert cy.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is False
        del writes[:]

        # The control: with the check answering, the owner (who holds the key) rotates and removes.
        revoke.click()
        expect(page.locator("#confirm-modal-message")).to_contain_text(
            "The vault key will be rotated", timeout=10000)
        page.click("#confirm-modal-confirm-btn")
        for _ in range(60):
            if member["id"] not in _listed(co, vid):
                break
            page.wait_for_timeout(250)
        else:
            pytest.fail("the member was never removed once the check worked")
        assert any("/rekey" in w for w in writes), f"no rotation ran: {writes}"
        assert co.get(f"/ecc/vaults/{vid}/keys").json()["current_dek_version"] == 2
        assert cx.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is False
    finally:
        try:
            ctx.close()
        except Exception:
            pass
        if vid:
            co.delete_vault(vid)
        for person in (owner, member, other):
            admin.delete_user(person["id"])
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def test_a_key_holder_removing_themselves_never_rotates(browser, admin):
    """An administrator who is a member and holds the key removes their own access. Whoever rotates
    learns the new key, so a rotation that removes the person running it would leave them holding
    the key to files added after they left (the server refuses it as well). The app asks whether to
    remove them, never starts a rotation, and the vault is left owing one."""
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    owner = admin.create_user(role="user")
    leaver = admin.create_user(role="admin")
    co, cl = _client(owner), _client(leaver)
    ctx = browser.new_context(base_url=BASE_URL)
    page = ctx.new_page()
    vid = vid_l = None
    try:
        ensure_ecc_keypair(co)
        vid = create_zk_vault(co)["id"]
        _login(page, leaver["_username"], leaver["_password"])
        vid_l = _create_zk_vault_via_ui(page, cl, "passphrase-L-123")   # sets up the leaver's key
        _stub_share(co, vid, leaver, "manage")
        assert cl.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is True

        rotations = _watch_rotations(page)
        _open_vault(page, vid)
        page.click('[data-vault-tab="permissions"]')
        page.click(f'button[data-action="revoke-permission"][data-user-id="{leaver["id"]}"]')
        expect(page.locator("#confirm-modal")).to_be_visible(timeout=10000)
        expect(page.locator("#confirm-modal-message")).to_contain_text("Remove your own access?")
        page.click("#confirm-modal-confirm-btn")

        for _ in range(40):
            if leaver["id"] not in _listed(co, vid):
                break
            page.wait_for_timeout(250)
        else:
            pytest.fail("the administrator's access was never removed")
        assert rotations == [], f"removing themselves started a rotation: {rotations}"
        assert cl.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is False
        assert co.get(f"/ecc/vaults/{vid}/keys").json()["rekey_owed"] is True
    finally:
        try:
            ctx.close()
        except Exception:
            pass
        if vid:
            co.delete_vault(vid)
        if vid_l:
            cl.delete_vault(vid_l)
        for person in (owner, leaver):
            admin.delete_user(person["id"])
        admin.put("/settings", json={"zero_knowledge_enabled": False})
