"""Mint-modal UI for the ZK-in-scope admin policy (temp_cred_allow_zk_vaults).

DENY: a zero-knowledge vault is greyed/disabled in the picker with a "not allowed by policy" note.
ALLOW (default): a ZK vault is selectable, but selecting it forces an acknowledge-to-proceed modal
(the holder must enter the master passphrase) before the credential is minted.
"""
import os
import subprocess
import uuid

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _u(p):
    return f"{p}_{uuid.uuid4().hex[:8]}"


def _psql(sql):
    subprocess.run(["docker", "exec", _DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                   capture_output=True, text=True, timeout=20)


def _login(page: Page, username, password):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_temp_modal(page: Page):
    page.click('[data-section="temp-creds"]')
    page.click("#generate-temp-creds-btn")
    expect(page.locator("#generate-temp-creds-modal")).to_be_visible(timeout=8000)


@pytest.fixture
def restore_zk_policy(admin):
    before = admin.get("/settings").json()
    yield
    admin.put("/settings", json={"temp_cred_allow_zk_vaults": bool(before.get("temp_cred_allow_zk_vaults", True))})


def _zk_vault(admin):
    v = admin.create_vault(name=_u("zkui"))
    _psql(f"UPDATE vaults SET type='zero_knowledge' WHERE id='{v['id']}';")
    return v["id"]


def _folder(admin, vault_id):
    response = admin.post(f"/vaults/{vault_id}/folders", json={"name": _u("scope")})
    response.raise_for_status()
    return response.json()["folder"]


def test_deny_greys_zk_vault_with_policy_note(page: Page, admin, admin_creds, restore_zk_policy):
    admin.put("/settings", json={"temp_cred_allow_zk_vaults": False})
    vid = _zk_vault(admin)
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_temp_modal(page)
        page.check("#tc-scope-enable")
        pick = page.locator(f'.tc-vault-pick[value="{vid}"]')
        expect(pick).to_be_visible(timeout=8000)
        expect(pick).to_be_disabled()                              # can't be selected under deny
        note = page.locator(f'.tc-zk-deny-note[data-vault="{vid}"]')
        expect(note).to_be_visible()
        expect(note).to_contain_text("organization policy")
    finally:
        _psql(f"UPDATE vaults SET type='standard' WHERE id='{vid}';")
        admin.delete_vault(vid)


def test_zk_selection_clears_and_omits_object_scope_while_standard_scope_remains(
    page: Page, admin, admin_creds, restore_zk_policy
):
    admin.put("/settings", json={"temp_cred_allow_zk_vaults": True})
    standard = admin.create_vault(name=_u("stdui"))
    folder = _folder(admin, standard["id"])
    zk_id = _zk_vault(admin)
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_temp_modal(page)
        page.check("#tc-scope-enable")

        standard_pick = page.locator(f'.tc-vault-pick[value="{standard["id"]}"]')
        zk_pick = page.locator(f'.tc-vault-pick[value="{zk_id}"]')
        expect(standard_pick).to_be_visible(timeout=8000)
        expect(zk_pick).to_be_enabled()
        standard_pick.check()

        restrict = page.locator("#tc-restrict-enable")
        expect(restrict).to_be_enabled()
        with page.expect_request(
            f"**/vaults/{standard['id']}/files*"
        ) as standard_request_info:
            restrict.check()
        assert standard_request_info.value.method == "GET"
        folder_pick = page.locator(
            f'.tc-restrict-include[data-id="{folder["id"]}"][data-kind="folder"]'
        )
        expect(folder_pick).to_be_visible(timeout=8000)
        folder_pick.check()

        standard_scope = page.evaluate("collectTempScope()")
        standard_entry = next(
            entry
            for entry in standard_scope["selected_vaults"]
            if entry["vault_id"] == standard["id"]
        )
        assert standard_entry["scope_ids"] == {"files": [], "folders": [folder["id"]]}

        # Switch in one DOM event so the availability check observes a single ZK selection,
        # rather than relying on the already-safe zero/two-selection intermediate states.
        page.evaluate(
            """([standardId, zkId]) => {
                const picks = Array.from(document.querySelectorAll('.tc-vault-pick'));
                const standardPick = picks.find(pick => pick.value === standardId);
                const zkPick = picks.find(pick => pick.value === zkId);
                standardPick.checked = false;
                zkPick.checked = true;
                zkPick.dispatchEvent(new Event('change', { bubbles: true }));
            }""",
            [standard["id"], zk_id],
        )

        expect(standard_pick).not_to_be_checked()
        expect(zk_pick).to_be_checked()
        expect(restrict).to_be_disabled()
        expect(restrict).not_to_be_checked()
        expect(page.locator("#tc-restrict-panel")).to_be_hidden()
        expect(page.locator("#tc-restrict-hint")).to_contain_text("whole-vault")
        cleared = page.evaluate(
            """() => ({
                vaultId: _tcRestrict.vaultId,
                files: Array.from(_tcRestrict.files),
                folders: Array.from(_tcRestrict.folders),
                crumbs: _tcRestrict.crumbs,
            })"""
        )
        assert cleared == {
            "vaultId": None,
            "files": [],
            "folders": [],
            "crumbs": [{"id": None, "name": "Root"}],
        }

        # Even if stale/programmatic state points the object picker back at a ZK vault, its loader
        # must clear that state before touching either the listing endpoint or the unlock path.
        zk_file_requests = []

        def record_zk_file_request(request):
            if f"/vaults/{zk_id}/files" in request.url:
                zk_file_requests.append(request.url)

        page.on("request", record_zk_file_request)
        try:
            guarded_load = page.evaluate(
                """async ({ vaultId, folderId }) => {
                    const originalDecrypt = window.zkDecryptListingNames;
                    let decryptCalls = 0;
                    window.zkDecryptListingNames = async (...args) => {
                        decryptCalls += 1;
                        return args[0];
                    };
                    try {
                        const enable = document.getElementById('tc-restrict-enable');
                        enable.disabled = false;
                        enable.checked = true;
                        _tcRestrict.vaultId = vaultId;
                        _tcRestrict.folders.add(folderId);
                        await _tcRestrictLoad(null);
                        return {
                            decryptCalls,
                            disabled: enable.disabled,
                            checked: enable.checked,
                            vaultId: _tcRestrict.vaultId,
                            folders: Array.from(_tcRestrict.folders),
                        };
                    } finally {
                        window.zkDecryptListingNames = originalDecrypt;
                    }
                }""",
                {"vaultId": zk_id, "folderId": folder["id"]},
            )
        finally:
            page.remove_listener("request", record_zk_file_request)

        assert zk_file_requests == []
        assert guarded_load == {
            "decryptCalls": 0,
            "disabled": True,
            "checked": False,
            "vaultId": None,
            "folders": [],
        }

        # Model stale/programmatic UI state and assert the request serializer still refuses to
        # attach object IDs to a ZK grant. Fulfil locally so this payload check creates no credential.
        page.evaluate(
            """({ vaultId, folderId }) => {
                const enable = document.getElementById('tc-restrict-enable');
                enable.disabled = false;
                enable.checked = true;
                _tcRestrict.vaultId = vaultId;
                _tcRestrict.folders.add(folderId);
            }""",
            {"vaultId": zk_id, "folderId": folder["id"]},
        )
        page.route(
            "**/auth/temp-credentials",
            lambda route: route.fulfill(
                status=400,
                content_type="application/json",
                body='{"detail":"request captured by UI test"}',
            ),
        )
        try:
            page.click("#generate-temp-creds-form button[type=submit]")
            expect(page.locator("#tc-zk-ack-modal")).to_be_visible(timeout=8000)
            with page.expect_request("**/auth/temp-credentials") as request_info:
                page.click("#tc-zk-ack-proceed")
            body = request_info.value.post_data_json
            zk_entry = next(
                entry for entry in body["selected_vaults"] if entry["vault_id"] == zk_id
            )
            assert "scope_ids" not in zk_entry, body
        finally:
            page.unroute("**/auth/temp-credentials")
    finally:
        _psql(f"UPDATE vaults SET type='standard' WHERE id='{zk_id}';")
        admin.delete_vault(zk_id)
        admin.delete_vault(standard["id"])


def test_allow_requires_acknowledgment_before_mint(page: Page, admin, admin_creds, restore_zk_policy):
    admin.put("/settings", json={"temp_cred_allow_zk_vaults": True})
    vid = _zk_vault(admin)
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_temp_modal(page)
        page.check("#tc-scope-enable")
        pick = page.locator(f'.tc-vault-pick[value="{vid}"]')
        expect(pick).to_be_enabled()                               # selectable under allow
        pick.check()
        page.click("#generate-temp-creds-form button[type=submit]")
        # the acknowledge modal appears; NOTHING is minted yet
        ack = page.locator("#tc-zk-ack-modal")
        expect(ack).to_be_visible(timeout=8000)
        expect(ack).to_contain_text("master key")
        expect(page.locator("#temp-creds-modal")).to_have_count(0)
        # cancel -> still no mint
        page.click("#tc-zk-ack-cancel")
        expect(ack).to_have_count(0)
        expect(page.locator("#temp-creds-modal")).to_have_count(0)
        # re-submit and this time proceed -> the credential is minted
        page.click("#generate-temp-creds-form button[type=submit]")
        expect(page.locator("#tc-zk-ack-modal")).to_be_visible(timeout=8000)
        page.click("#tc-zk-ack-proceed")
        expect(page.locator("#temp-creds-modal")).to_be_visible(timeout=10000)
    finally:
        _psql(f"UPDATE vaults SET type='standard' WHERE id='{vid}';")
        admin.delete_vault(vid)


def test_allow_all_vaults_mode_requires_acknowledgment(page: Page, admin, admin_creds, restore_zk_policy):
    """An 'all vaults' scope reaches every ZK vault, so it too triggers the master-key acknowledgment."""
    admin.put("/settings", json={"temp_cred_allow_zk_vaults": True})
    vid = _zk_vault(admin)  # owned by admin -> in scope of an 'all' mint
    held_vault_routes = []
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        page.route("**/vaults", lambda route: held_vault_routes.append(route))
        with page.expect_request("**/vaults"):
            _open_temp_modal(page)
        submit = page.locator('#generate-temp-creds-form button[type="submit"]')
        expect(submit).to_be_disabled()
        assert submit.get_attribute("data-temp-scope-ready") is None
        assert held_vault_routes, "the modal did not request the current vault list"
        held_vault_routes.pop(0).continue_()
        page.check("#tc-scope-enable")
        page.check('input[name="tc-vault-mode"][value="all"]')
        expect(submit).to_have_attribute("data-temp-scope-ready", "true", timeout=8000)
        page.click("#generate-temp-creds-form button[type=submit]")
        expect(page.locator("#tc-zk-ack-modal")).to_be_visible(timeout=8000)
        expect(page.locator("#temp-creds-modal")).to_have_count(0)  # not minted until acknowledged
    finally:
        for route in held_vault_routes:
            try:
                route.abort()
            except Exception:
                pass
        page.unroute("**/vaults")
        _psql(f"UPDATE vaults SET type='standard' WHERE id='{vid}';")
        admin.delete_vault(vid)
