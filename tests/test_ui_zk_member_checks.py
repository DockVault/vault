"""In real browsers: what a member's browser finds about the zero-knowledge key it holds, and what it does.

* A member given a key that is not the vault's cannot upload with it: the upload is refused with the
  reason, nothing reaches the server, the vault shows a warning, and the owner is told.
* The key details show the current epoch's lineage: verified after a rotation by a key holder; failed when
  the tag does not check out (a warning, and uploads still go through); reset by the owner; not verifiable
  for a member who never held the previous key, or an epoch with no stored material.
* When the vault's key check is damaged, its owner resets the key from the warning, and is offered to remove
  whoever set up the damaged material in the same step.
* The share dialog shows a ticked recipient's key fingerprint and when it was set up, and flags a key set up
  soon after an administrator changed the account's sign-in details.
* A key registration whose challenge the server cannot open asks once more with a fresh one.
"""

from __future__ import annotations

import base64
import os
import subprocess
import time

import pytest
from playwright.sync_api import Page, expect

from conftest import BASE_URL, ApiClient
from test_ui_e2e import _create_zk_vault_via_ui, _login
from test_ui_zk_rekey_notice import _open_vault

pytestmark = pytest.mark.ui

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
OWNER_PASS = "passphrase-MC-owner-1"
MEMBER_PASS = "passphrase-MC-member-1"

SHARE = "async ([vaultId, userId]) => { await zkShareVaultToUser(vaultId, userId); return true; }"


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

    def person():
        p = admin.create_user(role="user")
        made.append(p)
        return p, _client(p)

    yield person
    for p in made:
        admin.delete_user(p["id"])
    admin.put("/settings", json={"zero_knowledge_enabled": False})


def _set_up_key(page: Page, passphrase: str):
    """The account's encryption key, set up in this page (left unlocked)."""
    page.click("#profile-btn")
    page.click("#encryption-key-btn")
    expect(page.locator("#encryption-key-modal")).to_be_visible(timeout=5000)
    page.click("#encryption-key-setup-btn")
    expect(page.locator("#confirm-modal")).to_be_visible(timeout=5000)
    page.click("#confirm-modal-confirm-btn")
    for _ in range(2):
        expect(page.locator("#confirm-modal-input")).to_be_visible(timeout=5000)
        page.fill("#confirm-modal-input", passphrase)
        page.click("#confirm-modal-confirm-btn")
    expect(page.locator("#encryption-key-status")).to_contain_text("set up and active", timeout=15000)
    page.locator("#encryption-key-modal .close-modal-btn").first.click()
    expect(page.locator("#encryption-key-modal")).to_be_hidden(timeout=5000)


def _wait_for(check, what, tries=80):
    for _ in range(tries):
        if check():
            return
        time.sleep(0.25)
    pytest.fail(f"timed out waiting for {what}")


def _show_info(page: Page):
    page.click('[data-vault-tab="info"]')
    expect(page.locator("#vault-key-details-card")).to_be_visible(timeout=10000)


def _expect_history(page: Page, state: str):
    """The key history the Info tab shows once the check of the vault as it is now has run. The card of
    the previous look stays on screen until then, so this waits for the state rather than reading it."""
    expect(page.locator("#vault-key-history")).to_have_attribute("data-state", state, timeout=20000)


def _recheck(page: Page, vault_id: str):
    """Forget what this page found, and look again, as a fresh open does."""
    page.evaluate("(v) => { delete zkState.keyChecks[v]; delete zkState.teamKeyMatches[v]; "
                  "delete zkState.vaultDeks[v]; }", vault_id)
    _open_vault(page, vault_id)
    _show_info(page)


def test_a_member_given_a_key_that_is_not_the_vaults_cannot_upload_with_it(browser, zk):
    owner, co = zk()
    member, cm = zk()
    ctx_o, ctx_m = browser.new_context(base_url=BASE_URL), browser.new_context(base_url=BASE_URL)
    page_o, page_m = ctx_o.new_page(), ctx_m.new_page()
    vid = None
    try:
        _login(page_o, owner["_username"], owner["_password"])
        vid = _create_zk_vault_via_ui(page_o, co, OWNER_PASS)
        _login(page_m, member["_username"], member["_password"])
        _set_up_key(page_m, MEMBER_PASS)
        assert page_o.evaluate(SHARE, [vid, member["id"]]) is True
        co.post(f"/vaults/{vid}/permissions", json={"user_id": member["id"], "level": "write"}).raise_for_status()
        # The member's copy replaced by a well-formed wrap of ANOTHER key, as a database edit would.
        planted = page_o.evaluate("""async ([v, u]) => {
            const lib = eccLib();
            const pk = await apiRequest(`/ecc/users/${u}/public-key`, { silent: true });
            const other = await lib.generateVaultDEK();
            const w = await zkWrapDekForRecipient(other, await lib.importPublicKeyPEM(pk.public_key),
                                                  { vaultId: v, recipientUserId: u, dekEpoch: 1 });
            return [w.wrappedDEK, w.ephemeralPublicKey];
        }""", [vid, member["id"]])
        _psql(f"UPDATE vault_member_keys SET encrypted_dek = '{planted[0]}', ephemeral_public_key = '{planted[1]}' "
              f"WHERE vault_id = '{vid}' AND user_id = '{member['id']}'")

        _open_vault(page_m, vid)
        warning = page_m.locator("#vault-key-warning")
        expect(warning).to_be_visible(timeout=20000)
        expect(warning).to_contain_text("does not match")
        page_m.set_input_files("#file-upload-input", files=[{
            "name": "blocked.txt", "mimeType": "text/plain", "buffer": b"never uploaded"}])
        expect(page_m.locator(".toast-error")).to_contain_text("does not match", timeout=15000)
        expect(page_m.locator(".toast-error")).to_contain_text("Nothing was uploaded")
        assert _psql(f"SELECT count(*) FROM files WHERE vault_id = '{vid}'") == "0"
        _show_info(page_m)
        expect(page_m.locator("#vault-key-copy")).to_contain_text("does not match")
        _wait_for(lambda: _psql("SELECT count(*) FROM audit_logs WHERE action = 'zk_key_check_mismatch' "
                                f"AND resource_id = '{vid}' AND details->>'finding' = 'dek_check'") == "1",
                  "the report")
        titles = [n["title"] for n in co.get("/notifications", params={"limit": 50}).json()["notifications"]]
        assert "A member's key for one of your vaults does not match" in titles

        # The owner's own key matches: the owner uploads.
        _open_vault(page_o, vid)
        page_o.set_input_files("#file-upload-input", files=[{
            "name": "fine.txt", "mimeType": "text/plain", "buffer": b"uploaded"}])
        _wait_for(lambda: _psql(f"SELECT count(*) FROM files WHERE vault_id = '{vid}'") == "1", "the owner's upload")
        expect(page_o.locator("#vault-key-warning")).to_be_hidden()
    finally:
        ctx_o.close()
        ctx_m.close()
        if vid:
            co.delete_vault(vid)


def test_the_key_details_show_the_lineage_of_the_current_key(browser, zk):
    owner, co = zk()
    member, cm = zk()
    late, cl = zk()
    ctx_o, ctx_m, ctx_l = (browser.new_context(base_url=BASE_URL) for _ in range(3))
    page_o, page_m, page_l = ctx_o.new_page(), ctx_m.new_page(), ctx_l.new_page()
    vid = None
    try:
        _login(page_o, owner["_username"], owner["_password"])
        vid = _create_zk_vault_via_ui(page_o, co, OWNER_PASS)
        _login(page_m, member["_username"], member["_password"])
        _set_up_key(page_m, MEMBER_PASS)
        _login(page_l, late["_username"], late["_password"])
        _set_up_key(page_l, "passphrase-MC-late-1")
        assert page_o.evaluate(SHARE, [vid, member["id"]]) is True
        co.post(f"/vaults/{vid}/permissions", json={"user_id": member["id"], "level": "write"}).raise_for_status()

        _open_vault(page_m, vid)
        _show_info(page_m)
        _expect_history(page_m, "first")

        # A rotation by the owner, who holds the key: the member held the previous key and verifies it.
        assert page_o.evaluate("async (v) => { await zkRekeyForRevoke(v, null); return true; }", vid) is True
        _recheck(page_m, vid)
        _expect_history(page_m, "verified")
        expect(page_m.locator("#vault-key-warning")).to_be_hidden()

        # Someone who joined after the rotation never held the previous key.
        assert page_o.evaluate(SHARE, [vid, late["id"]]) is True
        co.post(f"/vaults/{vid}/permissions", json={"user_id": late["id"], "level": "read"}).raise_for_status()
        _open_vault(page_l, vid)
        _show_info(page_l)
        _expect_history(page_l, "not-verifiable")

        # A tag that does not check out: a warning and a report, and uploads still go through.
        bogus = base64.b64encode(os.urandom(32)).decode()
        _psql(f"UPDATE vault_key_proofs SET lineage_tag = '{bogus}' WHERE vault_id = '{vid}' AND dek_epoch = 2")
        _recheck(page_m, vid)
        _expect_history(page_m, "failed")
        expect(page_m.locator("#vault-key-warning")).to_contain_text("could not be traced")
        page_m.set_input_files("#file-upload-input", files=[{
            "name": "still.txt", "mimeType": "text/plain", "buffer": b"uploads continue"}])
        _wait_for(lambda: _psql(f"SELECT count(*) FROM files WHERE vault_id = '{vid}'") == "1", "the upload")
        _wait_for(lambda: _psql("SELECT count(*) FROM audit_logs WHERE action = 'zk_key_check_mismatch' "
                                f"AND resource_id = '{vid}' AND details->>'finding' = 'lineage'") == "1",
                  "the lineage report")

        # An owner's reset without the previous key.
        _psql(f"UPDATE vault_key_proofs SET source = 'owner_reset', lineage_tag = NULL "
              f"WHERE vault_id = '{vid}' AND dek_epoch = 2")
        _recheck(page_m, vid)
        _expect_history(page_m, "reset-by-owner")
        expect(page_m.locator("#vault-key-history")).to_contain_text("The owner reset this vault's key on")

        # An epoch with no stored material (made while the server was rolled back): nothing to verify, and
        # the key cannot be checked, which writes as before.
        _psql(f"DELETE FROM vault_key_proofs WHERE vault_id = '{vid}' AND dek_epoch = 2")
        _recheck(page_m, vid)
        _expect_history(page_m, "not-verifiable")
        expect(page_m.locator("#vault-key-copy")).to_contain_text("cannot be checked")
        page_m.set_input_files("#file-upload-input", files=[{
            "name": "rolled.txt", "mimeType": "text/plain", "buffer": b"written as before"}])
        _wait_for(lambda: _psql(f"SELECT count(*) FROM files WHERE vault_id = '{vid}'") == "2", "the upload")
    finally:
        for c in (ctx_o, ctx_m, ctx_l):
            c.close()
        if vid:
            co.delete_vault(vid)


def _damage(vid):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    stray = ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    _psql(f"UPDATE vault_key_proofs SET proof_public_key = '{stray}' WHERE vault_id = '{vid}'")


def test_the_owner_resets_a_damaged_key_and_removes_whoever_set_it_up(browser, zk):
    owner, co = zk()
    member, cm = zk()
    ctx_o, ctx_m = browser.new_context(base_url=BASE_URL), browser.new_context(base_url=BASE_URL)
    page_o, page_m = ctx_o.new_page(), ctx_m.new_page()
    vid = None
    try:
        _login(page_o, owner["_username"], owner["_password"])
        vid = _create_zk_vault_via_ui(page_o, co, OWNER_PASS)
        _login(page_m, member["_username"], member["_password"])
        _set_up_key(page_m, MEMBER_PASS)
        assert page_o.evaluate(SHARE, [vid, member["id"]]) is True
        co.post(f"/vaults/{vid}/permissions", json={"user_id": member["id"], "level": "manage"}).raise_for_status()
        # The member set up the epoch's key check, and it is damaged.
        _damage(vid)
        _psql(f"UPDATE vault_key_proofs SET created_by = '{member['id']}' WHERE vault_id = '{vid}'")

        page_o.evaluate("(v) => { delete zkState.keyChecks[v]; delete zkState.keyProofKeys[v]; }", vid)
        _open_vault(page_o, vid)
        warning = page_o.locator("#vault-key-warning")
        expect(warning).to_contain_text("does not open", timeout=20000)
        page_o.click("#vault-key-warning-reset-btn")
        expect(page_o.locator("#confirm-modal-message")).to_contain_text("Reset this vault's key?", timeout=10000)
        page_o.click("#confirm-modal-confirm-btn")
        expect(page_o.locator("#confirm-modal-message")).to_contain_text(
            f"{member['_username']} set up this vault's current key", timeout=10000)
        page_o.click("#confirm-modal-confirm-btn")
        _wait_for(lambda: _psql(f"SELECT source FROM vault_key_proofs WHERE vault_id = '{vid}' AND dek_epoch = 2")
                  == "owner_reset", "the reset")
        _wait_for(lambda: member["id"] not in {p["user_id"] for p in co.get(f"/vaults/{vid}/permissions").json()},
                  "the removal")
        assert cm.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is False
        expect(warning).to_be_hidden(timeout=20000)
        _show_info(page_o)
        expect(page_o.locator("#vault-key-copy")).to_contain_text("matches the vault's key check")
    finally:
        ctx_o.close()
        ctx_m.close()
        if vid:
            co.delete_vault(vid)


def test_the_share_dialog_shows_the_recipients_key_and_flags_one_set_up_after_an_administrators_change(browser, zk):
    owner, co = zk()
    member, cm = zk()
    ctx_o, ctx_m = browser.new_context(base_url=BASE_URL), browser.new_context(base_url=BASE_URL)
    page_o, page_m = ctx_o.new_page(), ctx_m.new_page()
    vid = None
    try:
        _login(page_o, owner["_username"], owner["_password"])
        vid = _create_zk_vault_via_ui(page_o, co, OWNER_PASS)
        _login(page_m, member["_username"], member["_password"])
        _set_up_key(page_m, MEMBER_PASS)
        own = page_m.evaluate("async () => zkKeyFingerprint((await apiRequest('/ecc/keys/public')).public_key)")

        for flagged in (False, True):
            _psql(f"UPDATE user_keypairs SET registered_after_admin_change = {str(flagged).lower()} "
                  f"WHERE user_id = '{member['id']}'")
            _open_vault(page_o, vid)
            page_o.click('[data-vault-tab="permissions"]')
            page_o.click("#add-permission-btn")
            expect(page_o.locator("#vault-grant-modal")).to_be_visible(timeout=10000)
            page_o.fill("#vault-grant-search", member["_username"])
            row = page_o.locator("#vault-grant-list .pick-row", has_text=member["_username"])
            expect(row).to_be_visible(timeout=10000)
            row.locator("input[type=checkbox]").check()
            info = row.locator(".grant-key-info")
            expect(info).to_contain_text(f"Key {own}", timeout=10000)
            expect(info).to_contain_text("set up")
            flag = row.locator(".grant-key-flag")
            if flagged:
                expect(flag).to_contain_text("Set up within 14 days after an administrator changed")
            else:
                expect(flag).to_have_count(0)
            row.locator("input[type=checkbox]").uncheck()
            expect(info).to_be_empty()
            page_o.locator("#vault-grant-modal .close-modal-btn").first.click()
            expect(page_o.locator("#vault-grant-modal")).to_be_hidden(timeout=5000)
    finally:
        ctx_o.close()
        ctx_m.close()
        if vid:
            co.delete_vault(vid)


def test_a_registration_whose_challenge_cannot_be_opened_asks_once_more(browser, zk):
    person, cp = zk()
    ctx = browser.new_context(base_url=BASE_URL)
    page = ctx.new_page()
    try:
        _login(page, person["_username"], person["_password"])
        seen = {"register": 0, "challenge": 0}

        def challenge(route):
            seen["challenge"] += 1
            route.continue_()

        def register(route):
            seen["register"] += 1
            if seen["register"] == 1:
                # What a server answers for a challenge whose one-time key it cannot open.
                route.fulfill(status=400, content_type="application/json",
                              body='{"detail":"Invalid or expired proof-of-possession challenge."}')
            else:
                route.continue_()
        page.route("**/ecc/keys/register/challenge", challenge)
        page.route("**/ecc/keys/register", register)
        _set_up_key(page, "passphrase-MC-retry-1")
        assert seen == {"register": 2, "challenge": 2}, seen
        assert cp.get("/ecc/keys/public").json()["has_keypair"] is True
    finally:
        ctx.close()


def test_a_member_whose_team_key_is_not_the_vaults_cannot_write_with_it(browser, zk):
    """A team vault whose member was handed another team key -- and the current DEK wrapped to that key, so
    the member can read with it, as a full substitution by someone who can write the database would do --
    while the vault's team public key is still the real one: the member's browser tells the two apart as
    it unwraps the team key, and refuses to write."""
    from test_ui_zk_rekey_notice import _create_team_vault_via_ui
    owner, co = zk()
    member, cm = zk()
    ctx_o, ctx_m = browser.new_context(base_url=BASE_URL), browser.new_context(base_url=BASE_URL)
    page_o, page_m = ctx_o.new_page(), ctx_m.new_page()
    vids = []
    try:
        _login(page_o, owner["_username"], owner["_password"])
        vids.append(_create_zk_vault_via_ui(page_o, co, OWNER_PASS))   # sets up the owner's key
        vid = _create_team_vault_via_ui(page_o, co)
        vids.append(vid)
        _login(page_m, member["_username"], member["_password"])
        _set_up_key(page_m, MEMBER_PASS)
        assert page_o.evaluate(SHARE, [vid, member["id"]]) is True
        co.post(f"/vaults/{vid}/permissions", json={"user_id": member["id"], "level": "write"}).raise_for_status()
        planted = page_o.evaluate("""async ([v, u]) => {
            const lib = eccLib();
            const pk = await apiRequest(`/ecc/users/${u}/public-key`, { silent: true });
            const other = await lib.generateKeypair();
            const w = await zkWrapTeamPrivateKey(other.privateKey, await lib.importPublicKeyPEM(pk.public_key),
                                                 { vaultId: v, recipientUserId: u });
            const t = await zkWrapTeamDek(await lib.generateVaultDEK(), other.publicKey, { vaultId: v, dekEpoch: 1 });
            return [w.wrappedKey, w.ephemeralPublicKey, t.wrappedDEK, t.ephemeralPublicKey];
        }""", [vid, member["id"]])
        _psql(f"UPDATE vault_member_keys SET encrypted_dek = '{planted[0]}', ephemeral_public_key = '{planted[1]}' "
              f"WHERE vault_id = '{vid}' AND user_id = '{member['id']}'")
        team_key = ('{"1": {"wrapped_dek": "%s", "ephemeral_public_key": "%s", "team_key_version": 1}}'
                    % (planted[2], planted[3]))
        _psql(f"UPDATE vaults SET team_key = '{team_key}' WHERE id = '{vid}'")

        _open_vault(page_m, vid)
        expect(page_m.locator("#vault-key-warning")).to_contain_text("does not match", timeout=20000)
        page_m.set_input_files("#file-upload-input", files=[{
            "name": "team.txt", "mimeType": "text/plain", "buffer": b"never uploaded"}])
        expect(page_m.locator(".toast-error")).to_contain_text("does not match", timeout=15000)
        assert _psql(f"SELECT count(*) FROM files WHERE vault_id = '{vid}'") == "0"
        _wait_for(lambda: _psql("SELECT count(*) FROM audit_logs WHERE action = 'zk_key_check_mismatch' "
                                f"AND resource_id = '{vid}' AND details->>'finding' = 'team_key'") == "1",
                  "the team key report")
    finally:
        ctx_o.close()
        ctx_m.close()
        for v in vids:
            co.delete_vault(v)
