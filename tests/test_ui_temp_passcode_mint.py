"""Mint-modal UI for temporary vault passcodes (the controls over the passcode mint backend).

The "Temporary passcode" section appears only when the feature is enabled and least-privilege scoping
is on; a passcode rides the vault-password proof (fail-closed Create if unproven); a zero-knowledge
vault shows a not-available note instead of a control; the minted passcode is shown once on create.
"""
import os
import subprocess

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
_PW = "Sup3r-Secret-PW-9!"
_POLICY_KEYS = [
    "temp_passcodes_enabled", "temp_passcode_allow_custom", "temp_passcode_one_time_default",
    "temp_passcode_single_vault_only", "temp_passcode_min_length",
    "temp_passcode_max_lifetime_minutes",
]


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
def restore_policy(admin):
    before = admin.get("/settings").json()
    yield
    admin.put("/settings", json={k: before[k] for k in _POLICY_KEYS if k in before})


def _enable_feature(admin, **kw):
    admin.put("/settings", json={"temp_passcodes_enabled": True, **kw})


def test_section_hidden_when_feature_disabled(page: Page, admin, admin_creds, restore_policy):
    admin.put("/settings", json={"temp_passcodes_enabled": False})
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_temp_modal(page)
    page.check("#tc-scope-enable")
    # feature off -> the passcode section never appears
    expect(page.locator("#tc-passcode-section")).to_be_hidden()


def test_generated_passcode_shown_once(page: Page, admin, admin_creds, restore_policy):
    _enable_feature(admin)
    v = admin.create_vault(name="pcui-gen", password=_PW)
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_temp_modal(page)
        page.check("#tc-scope-enable")
        expect(page.locator("#tc-passcode-section")).to_be_visible()
        pick = page.locator(f'.tc-vault-pick[value="{v["id"]}"]')
        expect(pick).to_be_visible(timeout=8000)
        pick.check()
        page.fill(f'.tc-vault-pw[data-vault="{v["id"]}"]', _PW)
        page.check("#tc-passcode-enable")
        expect(page.locator("#tc-passcode-opts")).to_be_visible()
        # intercept the mint request to pin the payload the UI builds (collectTempScope)
        with page.expect_request("**/auth/temp-credentials") as ri:
            page.click("#generate-temp-creds-form button[type=submit]")
        body = ri.value.post_data_json
        sv = [x for x in body["selected_vaults"] if x["vault_id"] == v["id"]][0]
        assert sv.get("issue_passcode") is True                 # eligible vault gets a passcode
        assert body.get("passcode_same_for_all") is True        # same-for-all is the default
        # the result modal shows the once-only vault passcode
        modal = page.locator("#temp-creds-modal")
        expect(modal).to_be_visible(timeout=10000)
        expect(modal).to_contain_text("Vault passcode")
    finally:
        admin.delete_vault(v["id"], vault_password=_PW)


def test_fail_closed_when_password_not_proven(page: Page, admin, admin_creds, restore_policy):
    _enable_feature(admin)
    v = admin.create_vault(name="pcui-failclosed", password=_PW)
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_temp_modal(page)
        page.check("#tc-scope-enable")
        page.locator(f'.tc-vault-pick[value="{v["id"]}"]').check()
        # leave the vault password EMPTY, enable the passcode, submit
        page.check("#tc-passcode-enable")
        page.click("#generate-temp-creds-form button[type=submit]")
        err = page.locator("#temp-cred-error")
        expect(err).to_be_visible(timeout=8000)
        expect(err).to_contain_text("Enter the vault password")  # the SPECIFIC unproven-password guard
        # fail-closed: no result modal, the generate modal stays open with state intact
        expect(page.locator("#temp-creds-modal")).to_have_count(0)
        expect(page.locator("#generate-temp-creds-modal")).to_be_visible()
    finally:
        admin.delete_vault(v["id"], vault_password=_PW)


def test_zero_knowledge_vault_shows_not_available_note(page: Page, admin, admin_creds, restore_policy):
    _enable_feature(admin)
    v = admin.create_vault(name="pcui-zk")  # no password; flipped to zero-knowledge below
    try:
        _psql(f"UPDATE vaults SET type='zero_knowledge' WHERE id='{v['id']}';")
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_temp_modal(page)
        page.check("#tc-scope-enable")
        expect(page.locator(f'.tc-vault-pick[value="{v["id"]}"]')).to_be_visible(timeout=8000)
        page.check("#tc-passcode-enable")
        # the ZK row shows the not-available note and offers no custom passcode input
        note = page.locator(".tc-passcode-zk-note")
        expect(note).to_be_visible()
        expect(note).to_contain_text("zero-knowledge")
        expect(page.locator(f'.tc-vault-passcode[data-vault="{v["id"]}"]')).to_have_count(0)
    finally:
        _psql(f"UPDATE vaults SET type='standard' WHERE id='{v['id']}';")
        admin.delete_vault(v["id"])


def test_custom_per_vault_input_appears_when_allowed_and_not_same(page: Page, admin, admin_creds, restore_policy):
    _enable_feature(admin, temp_passcode_allow_custom=True)
    v = admin.create_vault(name="pcui-custom", password=_PW)
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_temp_modal(page)
        page.check("#tc-scope-enable")
        page.locator(f'.tc-vault-pick[value="{v["id"]}"]').check()
        page.check("#tc-passcode-enable")
        pcin = page.locator(f'.tc-vault-passcode[data-vault="{v["id"]}"]')
        # same-for-all is ON by default -> the shared custom input shows, per-vault inputs hidden
        expect(page.locator("#tc-passcode-shared-row")).to_be_visible()
        expect(pcin).to_be_hidden()
        # turn OFF same-for-all -> the per-vault custom input appears, shared row hides
        page.uncheck("#tc-passcode-same")
        expect(pcin).to_be_visible()
        expect(page.locator("#tc-passcode-shared-row")).to_be_hidden()
    finally:
        admin.delete_vault(v["id"], vault_password=_PW)


def test_fail_closed_when_no_eligible_vault_selected(page: Page, admin, admin_creds, restore_policy):
    """The other fail-closed branch: passcode enabled but only an ineligible (no-password) vault
    selected -> Create is blocked telling the user to pick a password-protected standard vault."""
    _enable_feature(admin)
    v = admin.create_vault(name="pcui-nopw")  # no password -> ineligible for a passcode
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_temp_modal(page)
        page.check("#tc-scope-enable")
        page.locator(f'.tc-vault-pick[value="{v["id"]}"]').check()
        page.check("#tc-passcode-enable")
        page.click("#generate-temp-creds-form button[type=submit]")
        err = page.locator("#temp-cred-error")
        expect(err).to_be_visible(timeout=8000)
        expect(err).to_contain_text("password-protected standard vault")
        expect(page.locator("#temp-creds-modal")).to_have_count(0)
    finally:
        admin.delete_vault(v["id"])


def test_section_hidden_in_all_vaults_mode(page: Page, admin, admin_creds, restore_policy):
    """Passcodes attach to per-vault grants, so the section is offered only in 'selected' mode."""
    _enable_feature(admin)
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_temp_modal(page)
    page.check("#tc-scope-enable")
    expect(page.locator("#tc-passcode-section")).to_be_visible()  # selected mode (default)
    page.check('input[name="tc-vault-mode"][value="all"]')
    expect(page.locator("#tc-passcode-section")).to_be_hidden()   # all-vaults mode -> no passcode section


def test_mixed_selection_omits_zk_from_passcode_payload(page: Page, admin, admin_creds, restore_policy):
    """With a ZK and a standard vault both selected, the mint request carries issue_passcode ONLY for
    the standard vault — the server-side ZK exclusion is mirrored in the UI's payload."""
    _enable_feature(admin)
    std = admin.create_vault(name="pcui-std", password=_PW)
    zk = admin.create_vault(name="pcui-zkmix")
    try:
        _psql(f"UPDATE vaults SET type='zero_knowledge' WHERE id='{zk['id']}';")
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_temp_modal(page)
        page.check("#tc-scope-enable")
        page.locator(f'.tc-vault-pick[value="{std["id"]}"]').check()
        page.fill(f'.tc-vault-pw[data-vault="{std["id"]}"]', _PW)
        page.locator(f'.tc-vault-pick[value="{zk["id"]}"]').check()
        page.check("#tc-passcode-enable")
        with page.expect_request("**/auth/temp-credentials") as ri:
            page.click("#generate-temp-creds-form button[type=submit]")
        body = ri.value.post_data_json
        by_id = {x["vault_id"]: x for x in body["selected_vaults"]}
        assert by_id[std["id"]].get("issue_passcode") is True
        assert not by_id[zk["id"]].get("issue_passcode")   # ZK never gets a passcode
        expect(page.locator("#temp-creds-modal")).to_be_visible(timeout=10000)
    finally:
        _psql(f"UPDATE vaults SET type='standard' WHERE id='{zk['id']}';")
        admin.delete_vault(zk["id"])
        admin.delete_vault(std["id"], vault_password=_PW)


def test_same_for_all_shares_one_secret(page: Page, admin, admin_creds, restore_policy):
    """'Same passcode for all' mints one shared secret across the eligible vaults (shown once each)."""
    _enable_feature(admin)
    v1 = admin.create_vault(name="pcui-same1", password=_PW)
    v2 = admin.create_vault(name="pcui-same2", password=_PW)
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_temp_modal(page)
        page.check("#tc-scope-enable")
        for vid in (v1["id"], v2["id"]):
            page.locator(f'.tc-vault-pick[value="{vid}"]').check()
            page.fill(f'.tc-vault-pw[data-vault="{vid}"]', _PW)
        page.check("#tc-passcode-enable")  # same-for-all is on by default
        with page.expect_request("**/auth/temp-credentials") as ri:
            page.click("#generate-temp-creds-form button[type=submit]")
        assert ri.value.post_data_json.get("passcode_same_for_all") is True
        # the result modal shows a passcode line per vault, and they are the SAME secret
        modal = page.locator("#temp-creds-modal")
        expect(modal).to_be_visible(timeout=10000)
        pcs = modal.locator('.cred-field:has(.cred-field-label:has-text("Vault passcode")) .cred-field-input')
        pc_vals = pcs.evaluate_all("els => els.map(e => e.value)")
        assert len(pc_vals) == 2 and pc_vals[0] and pc_vals[0] == pc_vals[1]
    finally:
        admin.delete_vault(v1["id"], vault_password=_PW)
        admin.delete_vault(v2["id"], vault_password=_PW)
