"""The key proof in real browsers: the web app proves every change to a zero-knowledge vault's keys.

The server refuses a change to a vault's keys without a proof over its exact body (test_zk_key_proof_live.py).
This file drives the web app against it, with real crypto, and checks what it wrote:

* creating a vault installs its first epoch's proof key, and the name-index key is minted with a proof;
* sharing, alone and to five people at once while locked (one passphrase prompt for all five), and a vault
  made before key proofs is set up on the way;
* removing a member rotates the key with a new epoch's proof key and a lineage tag the browser's own
  previous key verifies, in a direct and in a team vault;
* a tab whose request loses its proof gets the server's plain sentence and stays signed in;
* a server that predates proofs is recognised and the request goes without one;
* when the vault's key check is damaged, a manager's removal falls back to removing the access alone,
  and the owner can reset the key.
"""

from __future__ import annotations

import os
import subprocess
import time

import pytest
from playwright.sync_api import Page, expect

from conftest import BASE_URL, ApiClient, ensure_ecc_keypair
from test_ui_e2e import _create_zk_vault_via_ui, _login
from test_ui_zk_rekey_notice import _create_team_vault_via_ui, _open_vault

pytestmark = pytest.mark.ui

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
PASSPHRASE = "passphrase-KP-123"

SHARE = "async ([vaultId, userId]) => { await zkShareVaultToUser(vaultId, userId); return true; }"

# The browser's own check of what a rotation wrote: the new epoch's key check against the new DEK, and
# the lineage tag against the previous one.
VERIFY_EPOCH = """async ([vaultId, epoch, mode]) => {
    const lib = eccLib();
    const keys = await apiRequest(`/ecc/vaults/${vaultId}/keys?key_version=${epoch}`, { silent: true });
    const kp = keys.key_proof;
    const prev = await zkGetVaultDek(vaultId, epoch - 1);
    const out = { source: kp.source, state: kp.state };
    if (mode === 'direct') {
        const dek = await zkGetVaultDek(vaultId, epoch);
        out.checkMatches = (await lib.dekCheck(dek, vaultId, epoch)) === kp.dek_check;
        out.lineage = await lib.verifyKeyLineageTag(prev, { vaultId, prevEpoch: epoch - 1, mode: 'direct',
            nextTeamEpoch: 1, nextVerifierPem: kp.public_key, nextDekCheck: kp.dek_check }, kp.lineage_tag);
    } else {
        out.lineage = await lib.verifyKeyLineageTag(prev, { vaultId, prevEpoch: epoch - 1, mode: 'hierarchical',
            nextTeamEpoch: keys.team_key_version, nextVerifierPem: keys.team_public_key,
            nextTeamWrap: keys.wrapped_dek }, kp.lineage_tag);
    }
    return out;
}"""


def _psql(sql: str) -> str:
    result = subprocess.run(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return (result.stdout or "").strip()


def _client(person):
    c = ApiClient()
    c.login(person["_username"], person["_password"])
    return c


@pytest.fixture
def zk(admin):
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    made = []

    def person(role="user"):
        p = admin.create_user(role=role)
        made.append(p)
        return p, _client(p)

    yield person
    for p in made:
        admin.delete_user(p["id"])
    admin.put("/settings", json={"zero_knowledge_enabled": False})


def _keyed(person_client):
    """A recipient with a registered encryption key (made by the test helper; a share only needs the
    public half)."""
    ensure_ecc_keypair(person_client)


def _revoke_in_ui(page: Page, vault_id: str, user_id: str):
    _open_vault(page, vault_id)
    page.click('[data-vault-tab="permissions"]')
    page.click(f'button[data-action="revoke-permission"][data-user-id="{user_id}"]')
    expect(page.locator("#confirm-modal")).to_be_visible(timeout=10000)


def _wait_for(check, what, tries=80):
    for _ in range(tries):
        if check():
            return
        time.sleep(0.25)
    pytest.fail(f"timed out waiting for {what}")


def test_a_direct_vault_is_created_shared_and_rotated_with_proofs(browser, zk):
    owner, co = zk()
    member, cm = zk()
    _keyed(cm)
    ctx = browser.new_context(base_url=BASE_URL)
    page = ctx.new_page()
    vid = None
    try:
        _login(page, owner["_username"], owner["_password"])
        vid = _create_zk_vault_via_ui(page, co, PASSPHRASE)
        assert _psql(f"SELECT source || '|' || coalesce(lineage_tag, '-') FROM vault_key_proofs "
                     f"WHERE vault_id = '{vid}'") == "create|-"
        assert co.get(f"/ecc/vaults/{vid}/index-key").json()["index_key"], "the name-index key was not minted"
        assert _psql("SELECT details->>'proof' FROM audit_logs WHERE action = 'zk_index_key_wrapped' "
                     f"AND resource_id = '{vid}'") == "key"

        assert page.evaluate(SHARE, [vid, member["id"]]) is True
        co.post(f"/vaults/{vid}/permissions", json={"user_id": member["id"], "level": "read"}).raise_for_status()
        _revoke_in_ui(page, vid, member["id"])
        expect(page.locator("#confirm-modal-message")).to_contain_text("The vault key will be rotated")
        page.click("#confirm-modal-confirm-btn")
        _wait_for(lambda: co.get(f"/ecc/vaults/{vid}/keys").json()["current_dek_version"] == 2, "the rotation")
        assert cm.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is False
        checked = page.evaluate(VERIFY_EPOCH, [vid, 2, "direct"])
        assert checked == {"source": "rotate", "state": "set", "checkMatches": True, "lineage": True}, checked
    finally:
        ctx.close()
        if vid:
            co.delete_vault(vid)


def test_a_team_vault_is_rotated_with_a_proof_and_a_lineage_tag(browser, zk):
    owner, co = zk()
    member, cm = zk()
    _keyed(cm)
    ctx = browser.new_context(base_url=BASE_URL)
    page = ctx.new_page()
    vids = []
    try:
        _login(page, owner["_username"], owner["_password"])
        vids.append(_create_zk_vault_via_ui(page, co, PASSPHRASE))   # sets up the owner's key
        vid = _create_team_vault_via_ui(page, co)
        vids.append(vid)
        assert _psql(f"SELECT source FROM vault_key_proofs WHERE vault_id = '{vid}'") == "create"
        assert page.evaluate(SHARE, [vid, member["id"]]) is True
        co.post(f"/vaults/{vid}/permissions", json={"user_id": member["id"], "level": "read"}).raise_for_status()
        _revoke_in_ui(page, vid, member["id"])
        page.click("#confirm-modal-confirm-btn")
        _wait_for(lambda: co.get(f"/ecc/vaults/{vid}/keys").json()["team_key_version"] == 2, "the team rotation")
        checked = page.evaluate(VERIFY_EPOCH, [vid, 2, "hierarchical"])
        assert checked == {"source": "rotate", "state": "team", "lineage": True}, checked
    finally:
        ctx.close()
        for v in vids:
            co.delete_vault(v)


def test_a_locked_share_to_five_asks_for_the_passphrase_once_and_sets_up_an_old_vault(browser, zk):
    owner, co = zk()
    people = [zk() for _ in range(5)]
    for _, c in people:
        _keyed(c)
    ctx = browser.new_context(base_url=BASE_URL)
    page = ctx.new_page()
    vid = None
    try:
        _login(page, owner["_username"], owner["_password"])
        vid = _create_zk_vault_via_ui(page, co, PASSPHRASE)
        # As a vault made before key proofs: its epoch has no key check yet.
        _psql(f"DELETE FROM vault_key_proofs WHERE vault_id = '{vid}'")
        page.evaluate("() => { zkResetKeys(); window.__prompts = 0; const p = showPrompt; "
                      "showPrompt = (...a) => { window.__prompts++; return p(...a); }; }")
        page.evaluate("([v, ids]) => { window.__shares = Promise.allSettled(ids.map(u => zkShareVaultToUser(v, u)))"
                      ".then(rs => rs.map(r => r.status)); }", [vid, [p["id"] for p, _ in people]])
        expect(page.locator("#confirm-modal-input")).to_be_visible(timeout=10000)
        page.fill("#confirm-modal-input", PASSPHRASE)
        page.click("#confirm-modal-confirm-btn")
        statuses = page.evaluate("() => window.__shares")
        assert statuses == ["fulfilled"] * 5, statuses
        assert page.evaluate("() => window.__prompts") == 1, "more than one passphrase prompt"
        assert _psql(f"SELECT count(*) FROM vault_member_keys WHERE vault_id = '{vid}'") == "6"
        assert _psql(f"SELECT source FROM vault_key_proofs WHERE vault_id = '{vid}'") == "bootstrap"
    finally:
        ctx.close()
        if vid:
            co.delete_vault(vid)


def test_a_request_that_loses_its_proof_is_refused_plainly_and_nobody_is_signed_out(browser, zk):
    owner, co = zk()
    member, cm = zk()
    _keyed(cm)
    ctx = browser.new_context(base_url=BASE_URL)
    page = ctx.new_page()
    vid = None
    try:
        _login(page, owner["_username"], owner["_password"])
        vid = _create_zk_vault_via_ui(page, co, PASSPHRASE)

        def strip(route):
            headers = {k: v for k, v in route.request.headers.items() if k.lower() != "x-zk-key-proof"}
            route.continue_(headers=headers)
        page.route("**/ecc/vaults/*/members", strip)
        error = page.evaluate("async ([v, u]) => { try { await zkShareVaultToUser(v, u); return null; } "
                              "catch (e) { return {status: e.status, reason: e.reason, message: e.message}; } }",
                              [vid, member["id"]])
        assert error["status"] == 428 and error["reason"] == "zk-key-proof-required", error
        assert "Reload the page" in error["message"]
        expect(page.locator("#dashboard-screen")).to_be_visible()
        assert page.evaluate("() => !!authToken"), "the refusal signed the person out"
        assert cm.get(f"/ecc/vaults/{vid}/keys").status_code == 403
    finally:
        ctx.close()
        if vid:
            co.delete_vault(vid)


def test_a_server_without_key_proofs_is_recognised_by_its_plain_404(browser, zk):
    owner, co = zk()
    member, cm = zk()
    _keyed(cm)
    ctx = browser.new_context(base_url=BASE_URL)
    page = ctx.new_page()
    vid = None
    try:
        _login(page, owner["_username"], owner["_password"])
        vid = _create_zk_vault_via_ui(page, co, PASSPHRASE)
        # The challenge route answers as a server that predates it would: 404, {"detail": "Not Found"}.
        page.route("**/key-proof/challenge", lambda route: route.fulfill(
            status=404, content_type="application/json", body='{"detail":"Not Found"}'))
        sent = []
        page.on("request", lambda req: sent.append(req.headers) if req.url.endswith("/members")
                and req.method == "POST" else None)
        error = page.evaluate("async ([v, u]) => { try { await zkShareVaultToUser(v, u); return null; } "
                              "catch (e) { return {status: e.status, reason: e.reason}; } }", [vid, member["id"]])
        assert sent and all("x-zk-key-proof" not in h for h in sent), "an old server was sent a proof"
        # This server does enforce proofs, so the request it got without one is refused.
        assert error == {"status": 428, "reason": "zk-key-proof-required"}, error
        # apiRequest reports a 404's status (and no reason for a plain one).
        seen = page.evaluate("async () => { try { await apiRequest('/no-such-route-here', { silent: true }); } "
                             "catch (e) { return {status: e.status, reason: e.reason === undefined}; } }")
        assert seen == {"status": 404, "reason": True}, seen
    finally:
        ctx.close()
        if vid:
            co.delete_vault(vid)


def _damage(vid):
    """The current epoch's proof key replaced by one nobody holds: its sealed key no longer opens for it."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    stray = ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    _psql(f"UPDATE vault_key_proofs SET proof_public_key = '{stray}' WHERE vault_id = '{vid}'")


def test_a_damaged_key_check_falls_back_to_removal_for_a_manager_and_to_a_reset_for_the_owner(browser, zk):
    owner, co = zk()
    manager, cg = zk()
    member, cm = zk()
    _keyed(cm)
    ctx_o = browser.new_context(base_url=BASE_URL)
    ctx_g = browser.new_context(base_url=BASE_URL)
    page_o, page_g = ctx_o.new_page(), ctx_g.new_page()
    vid = vid_g = None
    try:
        _login(page_o, owner["_username"], owner["_password"])
        vid = _create_zk_vault_via_ui(page_o, co, PASSPHRASE)
        _login(page_g, manager["_username"], manager["_password"])
        vid_g = _create_zk_vault_via_ui(page_g, cg, "passphrase-KG-123")   # the manager's own key
        for person, level in ((manager, "manage"), (member, "read")):
            assert page_o.evaluate(SHARE, [vid, person["id"]]) is True
            co.post(f"/vaults/{vid}/permissions", json={"user_id": person["id"], "level": level}).raise_for_status()
        _damage(vid)

        # The manager removes the member: the rotation cannot be proved, so the removal goes alone.
        _revoke_in_ui(page_g, vid, member["id"])
        page_g.click("#confirm-modal-confirm-btn")
        expect(page_g.locator("#confirm-modal-message")).to_contain_text("without rotating", timeout=20000)
        page_g.click("#confirm-modal-confirm-btn")
        _wait_for(lambda: member["id"] not in {p["user_id"] for p in co.get(f"/vaults/{vid}/permissions").json()},
                  "the removal")
        assert cm.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is False
        assert co.get(f"/ecc/vaults/{vid}/keys").json()["rekey_owed"] is True
        assert _psql(f"SELECT dek_version FROM vaults WHERE id = '{vid}'") == "1"

        # The owner rotates from the notice, is told the key check is damaged, and resets the key.
        _open_vault(page_o, vid)
        notice = page_o.locator("#vault-rekey-notice")
        expect(notice).to_be_visible(timeout=10000)
        page_o.click("#vault-rekey-notice-btn")
        expect(page_o.locator("#confirm-modal-message")).to_contain_text("reset the key", timeout=20000)
        page_o.click("#confirm-modal-confirm-btn")
        expect(notice).to_be_hidden(timeout=20000)
        assert _psql(f"SELECT source FROM vault_key_proofs WHERE vault_id = '{vid}' AND dek_epoch = 2") == "owner_reset"
        assert page_o.evaluate("async (v) => !!(await zkGetVaultDek(v))", vid) is True
        # The vault works again for key changes: the manager rotates normally.
        assert page_g.evaluate("async (v) => { await zkRekeyForRevoke(v, null); return true; }", vid) is True
        assert _psql(f"SELECT source FROM vault_key_proofs WHERE vault_id = '{vid}' AND dek_epoch = 3") == "rotate"
    finally:
        ctx_o.close()
        ctx_g.close()
        if vid:
            co.delete_vault(vid)
        if vid_g:
            cg.delete_vault(vid_g)
