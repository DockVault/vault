"""The version-2 key wraps, in a real browser, with the writer switched on.

Everything else about this format is proven by vectors and by source-text pins. What none of that
can show is that the application's own paths produce a usable vault when the writer is enabled:
`wrapVaultDEKV2` has never executed in a page. The three call sites that would use it are dead
while the gate is off, so a wrong argument at any of them ships silently and surfaces for whoever
turns it on first, as a vault that opens for nobody.

Three properties are load-bearing here and each is easy to lose:

  * **Legacy reads first.** The vault is created and shared BEFORE the gate is flipped. A format
    change that stranded existing members would otherwise look like a pass, because every wrap in
    the test would be new.
  * **The stored bytes are checked.** A lifecycle that "works" proves nothing if the gate never
    took effect -- the legacy writer produces a working vault too. Every wrap this test causes is
    fetched from the server and asserted to be a 68-byte version-2 direct wrap.
  * **The recipient actually reads.** Not `has_access`, which is a server-side row. A wrap built
    with the wrong vault, recipient or epoch is well formed, is stored happily, and fails only
    when someone tries to open it.

The gate is turned on per page, in the page, exactly as the content format's live test does. A test
that edited the source constant would prove the format works and prove nothing about the gate. One
flag drives all three wrap constructions -- direct, team DEK, team private key -- so enabling it
for the direct sites enables the others too; there is no per-purpose gate, and adding one would
edit a file a parallel workstream holds.

Deliberately NOT in test_ui_e2e.py: user creation there is being changed by that workstream, and
this file has no reason to collide with it.
"""

from __future__ import annotations

import base64

import pytest
from playwright.sync_api import expect

from conftest import ApiClient, BASE_URL
from test_ui_e2e import _create_zk_vault_via_ui, _login, _u

pytestmark = pytest.mark.ui

ENABLE_V2_WRAPS = """() => {
    const lib = eccLib();
    lib.ZK_WRAP_WRITE_V2 = true;
    return lib.ZK_WRAP_WRITE_V2;
}"""

V2_DIRECT_HEADER = b"DVZ2\x02\x01"
V2_WRAP_BYTES = 68
LEGACY_WRAP_BYTES = 40


def _wrap_for(client, vault_id: str) -> bytes:
    keys = client.get(f"/ecc/vaults/{vault_id}/keys").json()
    assert keys.get("wrapped_dek"), f"no wrap stored for this member: {keys}"
    return base64.b64decode(keys["wrapped_dek"])


def _assert_v2_direct(wrap: bytes, what: str) -> None:
    assert len(wrap) == V2_WRAP_BYTES, (
        f"{what}: {len(wrap)} bytes, so this is not a version-2 wrap -- the gate did not take "
        "effect, and everything else in this test passed on the legacy writer")
    assert wrap[:6] == V2_DIRECT_HEADER, (
        f"{what}: header {wrap[:8]!r} is not a version-2 direct wrap")


def _assert_legacy(wrap: bytes, what: str) -> None:
    assert len(wrap) == LEGACY_WRAP_BYTES, (
        f"{what}: expected the legacy 40-byte wrap, got {len(wrap)} bytes")
    assert wrap[:4] != b"DVZ2", f"{what}: was rewritten to version 2"


def _open_vault(page, vault_id: str, *, tries: int = 12) -> None:
    """Open a vault from the sidebar, re-rendering the list until it appears.

    Deliberately never reloads the page: a reload drops the unlocked encryption key and the next
    action meets the passphrase prompt instead of the vault. A vault that was just shared shows up
    on the next render of the list, which is what re-clicking the section does.
    """
    for attempt in range(tries):
        page.click('.sidebar-item[data-section="vaults"]')
        try:
            page.wait_for_selector(f'.open-vault-btn[data-vault-id="{vault_id}"]', timeout=2500)
            break
        except Exception:
            if attempt == tries - 1:
                raise
            page.wait_for_timeout(500)
    page.click(f'.open-vault-btn[data-vault-id="{vault_id}"]')
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)


def _unlock_key(page, passphrase: str) -> None:
    """Answer the passphrase prompt a fresh login meets before it can touch a vault.

    The unlocked key lives in the page, not in the session, so a new context starts locked. That is
    the state this file cares about: the reader has to work there, with the writer at its default.
    """
    prompt = page.locator("#confirm-modal")
    expect(prompt).to_be_visible(timeout=15000)
    expect(page.locator("#confirm-modal-title")).to_have_text("Unlock encryption key")
    page.fill("#confirm-modal-input", passphrase)
    page.click("#confirm-modal-confirm-btn")
    expect(prompt).to_be_hidden(timeout=15000)


def _grant_via_ui(page, recipient) -> None:
    """The real share path, through the permissions UI, which is what reaches the wrap site."""
    page.click('[data-vault-tab="permissions"]')
    page.click("#add-permission-btn")
    expect(page.locator("#vault-grant-modal")).to_be_visible(timeout=5000)
    page.fill("#vault-grant-search", recipient["_username"])
    page.wait_for_selector(f'#vault-grant-list input[value="{recipient["id"]}"]', timeout=8000)
    page.check(f'#vault-grant-list input[value="{recipient["id"]}"]')
    page.click("#vault-grant-confirm")
    expect(page.locator("#vault-grant-modal")).to_be_hidden(timeout=15000)


def _wait_for_access(client, vault_id: str, page, *, want=True, tries=40) -> dict:
    keys = {}
    for _ in range(tries):
        keys = client.get(f"/ecc/vaults/{vault_id}/keys").json()
        if bool(keys.get("has_access")) == want:
            return keys
        page.wait_for_timeout(300)
    return keys


def _read_a_file(page, vault_id: str, file_id: str) -> bytes:
    """Decrypt through the same seam a download uses. This is the assertion that matters."""
    plain = page.evaluate(
        """async ({ vaultId, id }) => {
            const r = await fetch(`${API_BASE}/vaults/${vaultId}/files/${id}/download`,
                { headers: { 'Authorization': 'Bearer ' + authToken } });
            const kv = zkFileKeyVersion(id);
            const out = await zkMaybeDecryptBlob(await r.blob(), state.currentVault, kv, id);
            return Array.from(new Uint8Array(await out.arrayBuffer()));
        }""",
        {"vaultId": vault_id, "id": file_id},
    )
    return bytes(plain)


@pytest.mark.ui
def test_a_share_written_by_the_version_2_writer_opens_for_its_recipient(browser, admin):
    """The whole point: a wrap the v2 writer produced opens for the person it names.

    The vectors prove the browser agrees with a reference encoder about the bytes. They cannot
    prove the application hands that writer the right vault, the right recipient and the right
    epoch, and a wrong argument at any of those produces bytes that are perfectly well formed and
    open for nobody at all.
    """
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    owner_user = admin.create_user(role="admin")
    member_user = admin.create_user(role="admin")
    owner = ApiClient(); owner.login(owner_user["_username"], owner_user["_password"])
    member = ApiClient(); member.login(member_user["_username"], member_user["_password"])

    body = (f"SHARED UNDER V2 {_u('body')} ").encode() * 8
    name = _u("shared") + ".txt"
    owner_vid = member_vid = None
    owner_ctx = browser.new_context(base_url=BASE_URL)
    member_ctx = browser.new_context(base_url=BASE_URL)
    owner_page = owner_ctx.new_page()
    member_page = member_ctx.new_page()
    try:
        _login(owner_page, owner_user["_username"], owner_user["_password"])
        owner_vid = _create_zk_vault_via_ui(owner_page, owner, "passphrase-owner-123")
        _open_vault(owner_page, owner_vid)
        owner_page.set_input_files("#file-upload-input", files=[
            {"name": name, "mimeType": "text/plain", "buffer": body}])
        for _ in range(40):
            items = owner.get(f"/vaults/{owner_vid}/files").json()["items"]
            if any(i["type"] == "file" for i in items):
                break
            owner_page.wait_for_timeout(500)
        file_id = next(i["id"] for i in items if i["type"] == "file")

        # Created with the gate OFF: the owner's own wrap is legacy, which is the state every
        # existing deployment is in and has to keep working after the switch.
        _assert_legacy(_wrap_for(owner, owner_vid), "the owner's wrap at creation")

        # The recipient needs their own keypair before anyone can wrap to them.
        _login(member_page, member_user["_username"], member_user["_password"])
        member_vid = _create_zk_vault_via_ui(member_page, member, "passphrase-member-123")

        assert owner_page.evaluate(ENABLE_V2_WRAPS) is True, "the gate did not flip"
        _grant_via_ui(owner_page, member_user)

        keys = _wait_for_access(member, owner_vid, owner_page)
        assert keys.get("has_access"), f"the share never landed: {keys}"
        _assert_v2_direct(base64.b64decode(keys["wrapped_dek"]),
                          "the wrap the share path wrote for the member")

        # And it opens. Not has_access -- the bytes, through the member's own key, in their page.
        _open_vault(member_page, owner_vid)
        assert _read_a_file(member_page, owner_vid, file_id) == body, (
            "the member holds a well-formed version-2 wrap that does not open the vault; the "
            "share path bound the wrong vault, recipient or epoch")

        # The owner's pre-switch wrap is untouched and still opens.
        _assert_legacy(_wrap_for(owner, owner_vid), "the owner's wrap after the share")
        assert _read_a_file(owner_page, owner_vid, file_id) == body, (
            "the owner's legacy wrap stopped opening once a version-2 wrap existed beside it")
    finally:
        for client, vid in ((owner, owner_vid), (member, member_vid)):
            if vid:
                client.delete_vault(vid)
        admin.delete_user(owner_user["id"])
        admin.delete_user(member_user["id"])
        admin.put("/settings", json={"zero_knowledge_enabled": False})


@pytest.mark.ui
def test_a_revocation_rewraps_the_survivors_under_version_2_at_the_new_epoch(browser, admin):
    """Revocation rotates the key and re-wraps whoever is left.

    This is where a vault converts wholesale to version 2, and where two of the three silent
    argument mistakes live: stamping the epoch being replaced, and naming the member being removed
    as a recipient of the new key. Both produce well-formed bytes and neither is visible until
    someone tries to open the result.
    """
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    owner_user = admin.create_user(role="admin")
    leaver_user = admin.create_user(role="admin")
    owner = ApiClient(); owner.login(owner_user["_username"], owner_user["_password"])
    leaver = ApiClient(); leaver.login(leaver_user["_username"], leaver_user["_password"])

    body = (f"EPOCH ONE {_u('body')} ").encode() * 8
    name = _u("before") + ".txt"
    owner_vid = leaver_vid = None
    owner_ctx = browser.new_context(base_url=BASE_URL)
    leaver_ctx = browser.new_context(base_url=BASE_URL)
    owner_page = owner_ctx.new_page()
    leaver_page = leaver_ctx.new_page()
    try:
        _login(owner_page, owner_user["_username"], owner_user["_password"])
        owner_vid = _create_zk_vault_via_ui(owner_page, owner, "passphrase-owner-456")
        _open_vault(owner_page, owner_vid)
        owner_page.set_input_files("#file-upload-input", files=[
            {"name": name, "mimeType": "text/plain", "buffer": body}])
        for _ in range(40):
            items = owner.get(f"/vaults/{owner_vid}/files").json()["items"]
            if any(i["type"] == "file" for i in items):
                break
            owner_page.wait_for_timeout(500)
        file_id = next(i["id"] for i in items if i["type"] == "file")

        _login(leaver_page, leaver_user["_username"], leaver_user["_password"])
        leaver_vid = _create_zk_vault_via_ui(leaver_page, leaver, "passphrase-leaver-456")

        # Shared while the gate is OFF, so the rotation has a legacy wrap to replace.
        _grant_via_ui(owner_page, leaver_user)
        assert _wait_for_access(leaver, owner_vid, owner_page).get("has_access")
        _assert_legacy(_wrap_for(leaver, owner_vid), "the member's wrap before the switch")
        epoch_before = owner.get(f"/ecc/vaults/{owner_vid}/keys").json().get(
            "current_dek_version") or 1

        assert owner_page.evaluate(ENABLE_V2_WRAPS) is True
        owner_page.click(
            f'button[data-action="revoke-permission"][data-user-id="{leaver_user["id"]}"]')
        expect(owner_page.locator("#confirm-modal")).to_be_visible(timeout=5000)
        owner_page.click("#confirm-modal-confirm-btn")

        rotated = {}
        for _ in range(40):
            rotated = owner.get(f"/ecc/vaults/{owner_vid}/keys").json()
            revoked = leaver.get(f"/ecc/vaults/{owner_vid}/keys").json()
            if (rotated.get("current_dek_version") == epoch_before + 1
                    and not revoked.get("has_access")):
                break
            owner_page.wait_for_timeout(500)
        assert rotated.get("current_dek_version") == epoch_before + 1, (
            f"the rotation did not advance the epoch: {rotated}")
        assert not leaver.get(f"/ecc/vaults/{owner_vid}/keys").json().get("has_access"), (
            "the removed member still holds a wrap of the rotated key")

        _assert_v2_direct(base64.b64decode(rotated["wrapped_dek"]), "the owner's re-wrap")
        assert rotated.get("key_version") == epoch_before + 1, (
            f"the re-wrap is labelled with the epoch it replaces: {rotated.get('key_version')} "
            f"after rotating to {epoch_before + 1}")

        _open_vault(owner_page, owner_vid)

        # THE assertion of this test, and the one an earlier version of it was missing. Reading the
        # pre-rotation file is NOT it: that file is at epoch 1, so the read resolves the owner's
        # OLD legacy wrap and never touches the version-2 re-wrap the rotation just made. Both of
        # the mistakes this test is named for -- stamping the epoch being replaced, naming the
        # removed member -- passed that read, because it decrypts a different key.
        #
        # Ask for the new epoch's DEK directly. That is the wrap the rotation wrote, and nothing
        # else in the suite opens it.
        opened = owner_page.evaluate(
            """async ({ vaultId, epoch }) => {
                try {
                    const dek = await zkGetVaultDek(vaultId, epoch);
                    return dek ? 'opened' : 'no-dek';
                } catch (e) { return 'error: ' + (e && (e.code || e.message)); }
            }""",
            {"vaultId": owner_vid, "epoch": epoch_before + 1},
        )
        assert opened == "opened", (
            f"the owner cannot open the key the rotation wrapped for them at epoch "
            f"{epoch_before + 1}: {opened}. The re-wrap is well formed and bound to the wrong "
            "vault, recipient or epoch")

        # End to end as well: a file written AFTER the rotation uses the new key, so this reads
        # through the re-wrap rather than around it.
        after_body = (f"EPOCH TWO {_u('after')} ").encode() * 8
        owner_page.set_input_files("#file-upload-input", files=[
            {"name": _u("after") + ".txt", "mimeType": "text/plain", "buffer": after_body}])
        after_id = None
        for _ in range(40):
            items = owner.get(f"/vaults/{owner_vid}/files").json()["items"]
            fresh = [i for i in items if i["type"] == "file" and i["id"] != file_id]
            if fresh:
                after_id = fresh[0]["id"]
                break
            owner_page.wait_for_timeout(500)
        assert after_id, "the post-rotation upload never landed"
        assert _read_a_file(owner_page, owner_vid, after_id) == after_body, (
            "a file written after the rotation does not read back; the re-wrapped key is unusable")

        # And the pre-rotation file still opens, which is the separate promise that a rotation does
        # not strand old content.
        assert _read_a_file(owner_page, owner_vid, file_id) == body, (
            "the owner cannot read their own pre-rotation file after re-wrapping under v2")
    finally:
        for client, vid in ((owner, owner_vid), (leaver, leaver_vid)):
            if vid:
                client.delete_vault(vid)
        admin.delete_user(owner_user["id"])
        admin.delete_user(leaver_user["id"])
        admin.put("/settings", json={"zero_knowledge_enabled": False})


@pytest.mark.ui
def test_a_version_2_wrap_still_opens_in_a_page_that_never_enabled_the_writer(browser, admin):
    """A staged rollout means readers run with the gate off. That is every other page.

    A wrap written by an enabled writer has to be readable by a page at the shipped default -- and
    the gate is per page, so a single-context test cannot see this at all.
    """
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    owner_user = admin.create_user(role="admin")
    member_user = admin.create_user(role="admin")
    owner = ApiClient(); owner.login(owner_user["_username"], owner_user["_password"])
    member = ApiClient(); member.login(member_user["_username"], member_user["_password"])

    body = (f"READ AFTER RELOGIN {_u('body')} ").encode() * 8
    name = _u("relogin") + ".txt"
    owner_vid = member_vid = None
    owner_ctx = browser.new_context(base_url=BASE_URL)
    member_ctx = browser.new_context(base_url=BASE_URL)
    owner_page = owner_ctx.new_page()
    member_page = member_ctx.new_page()
    try:
        _login(owner_page, owner_user["_username"], owner_user["_password"])
        owner_vid = _create_zk_vault_via_ui(owner_page, owner, "passphrase-owner-789")
        _open_vault(owner_page, owner_vid)
        owner_page.set_input_files("#file-upload-input", files=[
            {"name": name, "mimeType": "text/plain", "buffer": body}])
        for _ in range(40):
            items = owner.get(f"/vaults/{owner_vid}/files").json()["items"]
            if any(i["type"] == "file" for i in items):
                break
            owner_page.wait_for_timeout(500)
        file_id = next(i["id"] for i in items if i["type"] == "file")

        _login(member_page, member_user["_username"], member_user["_password"])
        member_vid = _create_zk_vault_via_ui(member_page, member, "passphrase-member-789")

        assert owner_page.evaluate(ENABLE_V2_WRAPS) is True
        _grant_via_ui(owner_page, member_user)
        keys = _wait_for_access(member, owner_vid, owner_page)
        _assert_v2_direct(base64.b64decode(keys["wrapped_dek"]), "the member's v2 wrap")
        member_ctx.close()

        # A completely fresh context: new page, new login, gate at its shipped default.
        fresh_ctx = browser.new_context(base_url=BASE_URL)
        fresh = fresh_ctx.new_page()
        _login(fresh, member_user["_username"], member_user["_password"])
        assert fresh.evaluate("() => eccLib().ZK_WRAP_WRITE_V2") is False, (
            "the gate leaked into a new context, so this test would prove nothing")

        # Opening a zero-knowledge vault in a locked page asks for the passphrase first. The
        # vault list renders before that, so the prompt arrives on the open, not on the login.
        fresh.click('.sidebar-item[data-section="vaults"]')
        fresh.wait_for_selector(f'.open-vault-btn[data-vault-id="{owner_vid}"]', timeout=15000)
        fresh.click(f'.open-vault-btn[data-vault-id="{owner_vid}"]')
        _unlock_key(fresh, "passphrase-member-789")
        expect(fresh.locator("#vault-view-section")).to_be_visible(timeout=15000)

        assert _read_a_file(fresh, owner_vid, file_id) == body, (
            "a version-2 wrap could not be read by a page with the writer at its default")
    finally:
        for client, vid in ((owner, owner_vid), (member, member_vid)):
            if vid:
                client.delete_vault(vid)
        admin.delete_user(owner_user["id"])
        admin.delete_user(member_user["id"])
        admin.put("/settings", json={"zero_knowledge_enabled": False})
