"""Browser-driven end-to-end tests (Playwright) against the live UI.

These drive the real SPA at the configured base_url: login, the
temporary-credential validity flow, vault creation, user creation, and logout.

Run only these:   pytest -m ui
Watch the browser: pytest -m ui --headed
"""
import uuid

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui


def _u(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


@pytest.fixture
def logged_in(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    return page


def test_login_shows_dashboard(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    expect(page.locator("#dashboard-section")).to_be_visible()


def test_login_with_bad_password_shows_error(page: Page, admin_creds):
    page.goto("/")
    page.fill("#username", admin_creds["username"])
    page.fill("#password", "wrong-password-xyz")
    page.click("#login-form button[type=submit]")
    expect(page.locator("#login-error")).to_be_visible(timeout=10000)
    expect(page.locator("#dashboard-screen")).to_be_hidden()


def test_temp_credential_modal_applies_chosen_validity(logged_in: Page):
    page = logged_in
    page.click('.sidebar-item[data-section="temp-creds"]')
    page.click("#generate-temp-creds-btn")

    expect(page.locator("#generate-temp-creds-modal")).to_be_visible()
    page.fill("#temp-cred-validity-minutes", "77")
    page.click("#generate-temp-creds-form button[type=submit]")

    # The one-time credential modal appears with the applied validity.
    modal = page.locator("#temp-creds-modal")
    expect(modal).to_be_visible(timeout=10000)
    expect(modal).to_contain_text("Valid for 77 minutes")
    # The expiry must render as a real date, proving the timestamp is valid.
    expect(modal).not_to_contain_text("Invalid Date")
    # Username + password are shown.
    expect(modal).to_contain_text("temp_")

    page.click("#close-temp-creds-modal")
    expect(modal).to_be_hidden()


def test_temp_credential_end_datetime_overrides_minutes(logged_in: Page):
    page = logged_in
    page.click('.sidebar-item[data-section="temp-creds"]')
    page.click("#generate-temp-creds-btn")
    expect(page.locator("#generate-temp-creds-modal")).to_be_visible()

    # Pick an end ~2 hours in the future via the datetime picker.
    end_iso = page.evaluate(
        "() => { const d = new Date(Date.now() + 2*60*60*1000);"
        " d.setSeconds(0,0);"
        " const p = n => String(n).padStart(2,'0');"
        " return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())}"
        "T${p(d.getHours())}:${p(d.getMinutes())}`; }"
    )
    page.fill("#temp-cred-end-datetime", end_iso)
    page.click("#generate-temp-creds-form button[type=submit]")

    modal = page.locator("#temp-creds-modal")
    expect(modal).to_be_visible(timeout=10000)
    # ~120 minutes (allow the boundary minute).
    expect(modal).to_contain_text("Valid for 1")  # 119 or 120 minutes
    expect(modal).not_to_contain_text("Invalid Date")
    page.click("#close-temp-creds-modal")


def test_create_vault_via_ui(logged_in: Page, admin):
    page = logged_in
    name = _u("uivault")
    page.click('.sidebar-item[data-section="vaults"]')
    page.click("#create-vault-btn")
    expect(page.locator("#create-vault-modal")).to_be_visible()
    page.fill("#vault-name", name)
    page.fill("#vault-desc", "created by playwright")
    page.fill("#vault-password", "ui-vault-pass-123")
    page.click("#create-vault-form button[type=submit]")
    expect(page.locator("#create-vault-modal")).to_be_hidden(timeout=10000)

    try:
        # Confirm via the API that it really exists.
        vaults = admin.get("/vaults").json()
        match = [v for v in vaults if v["name"] == name]
        assert match, f"vault {name} not found via API after UI creation"
    finally:
        for v in match:
            admin.delete_vault(v["id"], vault_password="ui-vault-pass-123")


def test_create_user_via_ui(logged_in: Page, admin):
    page = logged_in
    username = _u("uiuser")
    page.click('.sidebar-item[data-section="users"]')
    page.click("#create-user-btn")
    expect(page.locator("#create-user-modal")).to_be_visible()
    page.fill("#new-username", username)
    page.fill("#new-email", f"{username}@example.com")
    page.fill("#new-password", "ui-user-pass-123456")
    page.select_option("#new-role", "user")
    page.click("#create-user-form button[type=submit]")
    expect(page.locator("#create-user-modal")).to_be_hidden(timeout=10000)

    created = None
    try:
        users = admin.get("/users").json()
        match = [u for u in users if u["username"] == username]
        assert match, f"user {username} not found via API after UI creation"
        created = match[0]
    finally:
        if created:
            admin.delete_user(created["id"])


def test_vault_file_preview_rename_delete(logged_in: Page, admin):
    """Drives the in-vault file browser: preview a file, rename it, delete it.
    These are pure-frontend flows the API tests can't cover."""
    page = logged_in
    vault = admin.create_vault(name=_u("uivault"))  # no password
    vid = vault["id"]
    fname = _u("note") + ".txt"
    admin.post(f"/vaults/{vid}/files",
               files=[("files", (fname, b"preview me please", "text/plain"))])
    try:
        page.click('.sidebar-item[data-section="vaults"]')
        page.wait_for_selector(f'.open-vault-btn[data-vault-id="{vid}"]', timeout=10000)
        page.click(f'.open-vault-btn[data-vault-id="{vid}"]')
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)

        # Click the file name -> preview modal shows the (decrypted, in-memory) content
        page.click(".file-name[data-file-id]")
        expect(page.locator("#file-preview-modal")).to_be_visible(timeout=10000)
        expect(page.locator("#file-preview-body")).to_contain_text("preview me please")
        page.click("#file-preview-modal .close-modal-btn")
        expect(page.locator("#file-preview-modal")).to_be_hidden()

        # Rename via the row action (uses the prompt modal)
        new_name = _u("renamed") + ".txt"
        page.click('.action-btn[data-action="rename-file"]')
        page.fill("#confirm-modal-input", new_name)
        page.click("#confirm-modal-confirm-btn")
        page.wait_for_timeout(1200)
        items = admin.get(f"/vaults/{vid}/files").json()["items"]
        assert any(it["name"] == new_name for it in items), "file was not renamed via the UI"

        # Delete via the row action
        page.click('.action-btn[data-action="delete-file"]')
        page.click("#confirm-modal-confirm-btn")
        page.wait_for_timeout(1200)
        items = admin.get(f"/vaults/{vid}/files").json()["items"]
        assert not items, "file was not deleted via the UI"
    finally:
        admin.delete_vault(vid)


def test_vault_chunked_upload_via_ui(logged_in: Page, admin):
    """Uploading through the file picker drives the resumable chunked manager
    (init → PUT chunk → complete) and shows the upload tray. Verifies the file
    lands in the vault and that the client flow runs with no uncaught JS errors."""
    page = logged_in
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    vault = admin.create_vault(name=_u("uiupload"))
    vid = vault["id"]
    try:
        page.click('.sidebar-item[data-section="vaults"]')
        page.wait_for_selector(f'.open-vault-btn[data-vault-id="{vid}"]', timeout=10000)
        page.click(f'.open-vault-btn[data-vault-id="{vid}"]')
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)

        fname = _u("upload") + ".txt"
        page.set_input_files("#file-upload-input", files=[{
            "name": fname,
            "mimeType": "text/plain",
            "buffer": b"chunked upload via ui " * 64,
        }])

        # Tray appears while the upload runs.
        expect(page.locator("#upload-tray.show")).to_be_visible(timeout=8000)

        # File lands in the vault — proves the whole client chunk flow completed.
        landed = False
        for _ in range(30):
            items = admin.get(f"/vaults/{vid}/files").json()["items"]
            if any(it.get("name") == fname for it in items):
                landed = True
                break
            page.wait_for_timeout(500)
        assert landed, "chunked UI upload never appeared in the vault"
        assert not errors, f"uncaught JS errors during upload: {errors}"
    finally:
        admin.delete_vault(vid)


def test_vault_settings_button_opens_modal(logged_in: Page, admin):
    """The Settings-tab buttons must actually open their modals (regression for the
    missing openModal()/role-case bugs)."""
    page = logged_in
    vault = admin.create_vault(name=_u("uivault"))
    vid = vault["id"]
    try:
        page.click('.sidebar-item[data-section="vaults"]')
        page.wait_for_selector(f'.open-vault-btn[data-vault-id="{vid}"]', timeout=10000)
        page.click(f'.open-vault-btn[data-vault-id="{vid}"]')
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)
        page.click('[data-vault-tab="settings"]')
        page.click("#edit-vault-info-btn")
        expect(page.locator("#edit-vault-info-modal")).to_be_visible(timeout=5000)
    finally:
        admin.delete_vault(vid)


def test_vault_favorite_star_via_ui(logged_in: Page, admin):
    """Star a vault from its card; the star fills and the Favorites filter shows it."""
    page = logged_in
    vault = admin.create_vault(name=_u("favui"))
    vid = vault["id"]
    try:
        page.click('.sidebar-item[data-section="vaults"]')
        page.wait_for_selector(f'.vault-card[data-vault-id="{vid}"]', timeout=10000)
        page.click(f'.vault-card[data-vault-id="{vid}"] .vault-fav')
        expect(page.locator(f'.vault-card[data-vault-id="{vid}"] .vault-fav.is-fav')).to_be_visible(timeout=5000)

        # persisted server-side
        starred = False
        for _ in range(10):
            if admin.get(f"/vaults/{vid}").json().get("is_favorite"):
                starred = True
                break
            page.wait_for_timeout(300)
        assert starred, "star was not persisted"

        # Favorites filter keeps it visible
        page.click('#vault-filter-fav')
        expect(page.locator(f'.vault-card[data-vault-id="{vid}"]')).to_be_visible(timeout=5000)
    finally:
        admin.delete_vault(vid)


def test_create_folder_via_modal(logged_in: Page, admin):
    """New Folder uses the prompt modal (no native prompt) and creates the folder."""
    page = logged_in
    vault = admin.create_vault(name=_u("foldui"))
    vid = vault["id"]
    try:
        page.click('.sidebar-item[data-section="vaults"]')
        page.wait_for_selector(f'.open-vault-btn[data-vault-id="{vid}"]', timeout=10000)
        page.click(f'.open-vault-btn[data-vault-id="{vid}"]')
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)

        page.click("#create-folder-btn")
        expect(page.locator("#confirm-modal")).to_be_visible(timeout=5000)
        name = _u("newdir")
        page.fill("#confirm-modal-input", name)
        page.click("#confirm-modal-confirm-btn")
        page.wait_for_timeout(1200)

        items = admin.get(f"/vaults/{vid}/files").json()["items"]
        assert any(it["name"] == name and it["type"] == "folder" for it in items), "folder not created via modal"
    finally:
        admin.delete_vault(vid)


def test_vault_permissions_table_via_ui(logged_in: Page, admin, temp_user):
    """Permissions tab shows a real date (not 'Invalid Date') and the inline level
    selector updates the grant in place."""
    page = logged_in
    vault = admin.create_vault(name=_u("permui"))
    vid = vault["id"]
    admin.post(f"/vaults/{vid}/permissions", json={"user_id": temp_user["id"], "level": "read"})
    try:
        page.click('.sidebar-item[data-section="vaults"]')
        page.wait_for_selector(f'.open-vault-btn[data-vault-id="{vid}"]', timeout=10000)
        page.click(f'.open-vault-btn[data-vault-id="{vid}"]')
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)

        page.click('[data-vault-tab="permissions"]')
        expect(page.locator("#permissions-table-body select.perm-level-select")).to_be_visible(timeout=5000)
        assert "Invalid Date" not in page.locator("#permissions-table-body").inner_text()

        # Change level inline → persists as write
        page.select_option("#permissions-table-body select.perm-level-select", "write")
        page.wait_for_timeout(1000)
        plist = admin.get(f"/vaults/{vid}/permissions").json()
        assert plist and plist[0]["write_permission"] is True, "inline level change did not persist"
    finally:
        admin.delete_vault(vid)


def test_vault_view_survives_refresh(logged_in: Page, admin):
    """Refreshing while inside a vault restores the vault view (not the dashboard)."""
    page = logged_in
    vault = admin.create_vault(name=_u("refresh"))  # no password → seamless restore
    vid = vault["id"]
    try:
        page.click('.sidebar-item[data-section="vaults"]')
        page.wait_for_selector(f'.open-vault-btn[data-vault-id="{vid}"]', timeout=10000)
        page.click(f'.open-vault-btn[data-vault-id="{vid}"]')
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)
        expect(page.locator("#vault-view-title")).to_have_text(vault["name"], timeout=10000)

        page.reload()

        # Still inside the same vault after the refresh.
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)
        expect(page.locator("#vault-view-title")).to_have_text(vault["name"], timeout=10000)
    finally:
        admin.delete_vault(vid)


def test_vault_file_list_live_updates(logged_in: Page, admin):
    """A file added by someone else shows up without a manual reload (live poll)."""
    page = logged_in
    vault = admin.create_vault(name=_u("live"))
    vid = vault["id"]
    try:
        page.click('.sidebar-item[data-section="vaults"]')
        page.wait_for_selector(f'.open-vault-btn[data-vault-id="{vid}"]', timeout=10000)
        page.click(f'.open-vault-btn[data-vault-id="{vid}"]')
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)

        # Simulate another user uploading a file out-of-band.
        name = _u("ext") + ".txt"
        admin.post(f"/vaults/{vid}/files", files=[("files", (name, b"hello", "text/plain"))])

        # The watcher (≈6s poll) should surface it without us reloading.
        expect(page.locator(f'#vault-files-table-body >> text="{name}"')).to_be_visible(timeout=15000)
    finally:
        admin.delete_vault(vid)


def test_logout_returns_to_login(logged_in: Page):
    page = logged_in
    page.click("#profile-btn")
    page.click("#dropdown-logout-btn")
    expect(page.locator("#login-screen")).to_be_visible(timeout=10000)


# --- June-16 appearance work: background palettes + centered empty states ----

def test_background_palette_picker(logged_in: Page):
    """The profile dropdown exposes 6 background palettes; choosing one sets
    [data-bg] on <html> + marks it selected, and Slate (default) clears it."""
    page = logged_in
    page.click("#profile-btn")
    swatches = page.locator(".bg-swatch[data-bg]")
    expect(swatches).to_have_count(6)
    expect(swatches.first).to_be_visible()

    page.click('.bg-swatch[data-bg="navy"]')
    expect(page.locator("html")).to_have_attribute("data-bg", "navy")
    assert page.eval_on_selector(
        '.bg-swatch[data-bg="navy"]', "e => e.classList.contains('selected')"
    ), "navy swatch was not marked selected"

    page.click('.bg-swatch[data-bg="slate"]')
    assert page.get_attribute("html", "data-bg") is None, "Slate should clear data-bg (default)"


_CENTER_JS = """([ps, cs]) => {
    const p = document.querySelector(ps), c = document.querySelector(cs);
    if (!p || !c) return null;
    const pr = p.getBoundingClientRect(), cr = c.getBoundingClientRect();
    const leftGap = cr.left - pr.left, rightGap = pr.right - cr.right;
    return { leftGap: Math.round(leftGap), rightGap: Math.round(rightGap),
             centered: Math.abs(leftGap - rightGap) <= 6 };
}"""


def test_empty_states_are_centered(page: Page, admin):
    """A fresh zero-state user sees the vaults + temp-creds empty states centered
    in the content area (the shared .empty-state-center block), not top-left."""
    user = admin.create_user(role="user")
    try:
        _login(page, user["_username"], user["_password"])

        page.click('.sidebar-item[data-section="vaults"]')
        page.wait_for_selector("#vaults-list .empty-state-center", timeout=10000)
        vaults = page.evaluate(_CENTER_JS, ["#vaults-list", "#vaults-list .empty-state-center p"])
        assert vaults and vaults["centered"], f"vaults empty state not centered: {vaults}"

        page.click('.sidebar-item[data-section="temp-creds"]')
        page.wait_for_selector("#active-temp-creds .empty-state-center", timeout=10000)
        creds = page.evaluate(_CENTER_JS, ["#active-temp-creds", "#active-temp-creds .empty-state-center p"])
        assert creds and creds["centered"], f"temp-creds empty state not centered: {creds}"
    finally:
        admin.delete_user(user["id"])


# --- Admin SFTP-auth + zero-knowledge policy UI (Settings + Users) -----------

def _gen_ssh_pubkey() -> str:
    """A real, parseable OpenSSH ed25519 public-key line for the add-key form."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    return ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode()


def _open_sftp_settings_tab(page: Page):
    page.click('.sidebar-item[data-section="settings"]')
    expect(page.locator("#settings-section")).to_be_visible(timeout=10000)
    page.click('.tab-btn[data-tab="sftp"]')
    expect(page.locator("#settings-tab-sftp")).to_be_visible(timeout=5000)


def test_settings_zero_knowledge_toggle_persists(logged_in: Page, admin):
    """The SFTP & Encryption tab's zero-knowledge toggle writes the
    zero_knowledge_enabled setting via Save All Changes."""
    page = logged_in
    before = bool(admin.get("/settings").json().get("zero_knowledge_enabled", False))
    try:
        _open_sftp_settings_tab(page)
        cb = page.locator("#setting-zero-knowledge-enabled")
        expect(cb).to_be_visible(timeout=5000)
        cb.check()  # force ON regardless of starting state
        page.click("#save-all-settings-btn")

        ok = False
        for _ in range(12):
            if admin.get("/settings").json().get("zero_knowledge_enabled") is True:
                ok = True
                break
            page.wait_for_timeout(300)
        assert ok, "zero_knowledge_enabled was not persisted from the UI"
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": before})


def test_settings_sftp_temp_cred_group_picker(logged_in: Page, admin):
    """Picking a department in the policy picker shows a removable chip and Save
    persists it into sftp_require_temp_cred_groups."""
    page = logged_in
    gname = _u("hs")
    gid = admin.post("/groups", json={"name": gname}).json()["id"]
    try:
        _open_sftp_settings_tab(page)
        # The freshly-created department is selectable in the picker.
        page.wait_for_selector('#sftp-temp-cred-group-picker .sftp-group-add', timeout=5000)
        page.select_option('#sftp-temp-cred-group-picker .sftp-group-add', gid)
        expect(page.locator('#sftp-temp-cred-group-picker .chip')).to_contain_text(gname)

        page.click("#save-all-settings-btn")
        ok = False
        for _ in range(12):
            if gid in (admin.get("/settings").json().get("sftp_require_temp_cred_groups") or []):
                ok = True
                break
            page.wait_for_timeout(300)
        assert ok, "picked department did not persist to sftp_require_temp_cred_groups"
    finally:
        admin.put("/settings", json={"sftp_require_temp_cred_groups": []})
        admin.delete(f"/groups/{gid}")


def test_user_sftp_password_auth_toggle_via_ui(logged_in: Page, admin):
    """Expanding a user and unchecking 'Allow password authentication' PATCHes
    sftp_password_auth off."""
    page = logged_in
    user = admin.create_user(role="user")
    uid = user["id"]
    try:
        page.click('.sidebar-item[data-section="users"]')
        page.wait_for_selector(f'.exp-row[data-id="{uid}"]', timeout=10000)
        page.click(f'.exp-row[data-id="{uid}"] .exp-toggle')

        toggle = page.locator(f'.sftp-access-toggle[data-user-id="{uid}"][data-field="sftp_password_auth"]')
        expect(toggle).to_be_visible(timeout=5000)
        toggle.uncheck()

        ok = False
        for _ in range(12):
            if admin.get(f"/users/{uid}").json().get("sftp_password_auth") is False:
                ok = True
                break
            page.wait_for_timeout(300)
        assert ok, "sftp_password_auth toggle did not persist"
    finally:
        admin.delete_user(uid)


def test_settings_sftp_group_picker_remove_persists(logged_in: Page, admin):
    """Removing a department chip and saving persists the REMOVAL (the dangerous
    direction: a relaxed department must actually be relaxed in storage)."""
    page = logged_in
    gname = _u("hs")
    gid = admin.post("/groups", json={"name": gname}).json()["id"]
    # Pre-seed the policy with this department via the API.
    admin.put("/settings", json={"sftp_require_temp_cred_groups": [gid]})
    try:
        _open_sftp_settings_tab(page)
        # The seeded department shows as a removable chip; remove it.
        chip = page.locator('#sftp-temp-cred-group-picker .chip', has_text=gname)
        expect(chip).to_be_visible(timeout=5000)
        page.click('#sftp-temp-cred-group-picker .sftp-group-remove')
        expect(page.locator('#sftp-temp-cred-group-picker .chip', has_text=gname)).to_have_count(0)

        page.click("#save-all-settings-btn")
        cleared = False
        for _ in range(12):
            if gid not in (admin.get("/settings").json().get("sftp_require_temp_cred_groups") or []):
                cleared = True
                break
            page.wait_for_timeout(300)
        assert cleared, "removing the department from the picker did not persist"
    finally:
        admin.put("/settings", json={"sftp_require_temp_cred_groups": []})
        admin.delete(f"/groups/{gid}")


def test_settings_sftp_policy_survives_groups_fetch_failure(logged_in: Page, admin):
    """Regression: a transient GET /groups failure must NOT let a later Save wipe
    the stored SFTP temp-cred policy. The picker goes read-only and Save omits the
    key, so the policy is preserved."""
    page = logged_in
    gname = _u("hs")
    gid = admin.post("/groups", json={"name": gname}).json()["id"]
    admin.put("/settings", json={"sftp_require_temp_cred_groups": [gid]})
    try:
        # Make the browser's GET /groups fail for this page.
        page.route("**/groups", lambda route: route.abort())

        page.click('.sidebar-item[data-section="settings"]')
        expect(page.locator("#settings-section")).to_be_visible(timeout=10000)
        page.click('.tab-btn[data-tab="sftp"]')
        # Degraded read-only state is shown, not a silently empty picker.
        expect(page.locator("#sftp-temp-cred-group-picker")).to_contain_text(
            "policy shown read-only", timeout=5000
        )

        # Save — saveAllSettings sends the whole settings object; this is exactly
        # the path that previously serialized an emptied policy and wiped it.
        page.click("#save-all-settings-btn")
        page.wait_for_timeout(1500)

        # The policy is intact.
        groups = admin.get("/settings").json().get("sftp_require_temp_cred_groups") or []
        assert gid in groups, "a /groups fetch failure silently wiped the SFTP policy on save"
    finally:
        page.unroute("**/groups")
        admin.put("/settings", json={"sftp_require_temp_cred_groups": []})
        admin.delete(f"/groups/{gid}")


def test_user_sftp_enabled_toggle_via_ui(logged_in: Page, admin):
    """Unchecking 'SFTP enabled' (the bigger hammer — blocks password AND key)
    PATCHes sftp_enabled off."""
    page = logged_in
    user = admin.create_user(role="user")
    uid = user["id"]
    try:
        page.click('.sidebar-item[data-section="users"]')
        page.wait_for_selector(f'.exp-row[data-id="{uid}"]', timeout=10000)
        page.click(f'.exp-row[data-id="{uid}"] .exp-toggle')

        toggle = page.locator(f'.sftp-access-toggle[data-user-id="{uid}"][data-field="sftp_enabled"]')
        expect(toggle).to_be_visible(timeout=5000)
        toggle.uncheck()

        ok = False
        for _ in range(12):
            if admin.get(f"/users/{uid}").json().get("sftp_enabled") is False:
                ok = True
                break
            page.wait_for_timeout(300)
        assert ok, "sftp_enabled toggle did not persist"
    finally:
        admin.delete_user(uid)


def test_zero_knowledge_vault_end_to_end(page: Page, admin):
    """Full browser zero-knowledge round-trip:
      create a ZK vault (passphrase + keypair set up client-side) →
      upload a file (encrypted in the browser) →
      PROVE the server stored ciphertext it cannot read →
      preview it (decrypted back to plaintext in the browser).

    Runs as a FRESH admin user so it always takes the first-time key-setup path
    (the shared admin's keypair may carry a dummy blob from the API tests)."""
    from conftest import ApiClient

    admin.put("/settings", json={"zero_knowledge_enabled": True})
    user = admin.create_user(role="admin")          # fresh => no ECC keypair yet
    owner = ApiClient()                              # API view as the vault owner
    owner.login(user["_username"], user["_password"])

    vname = _u("zkvault")
    passphrase = "zk-pass-phrase-123"
    marker = _u("zkmark")
    secret = (f"ZERO-KNOWLEDGE-PAYLOAD {marker} ").encode() * 4
    fname = _u("secret") + ".txt"
    vid = None
    try:
        _login(page, user["_username"], user["_password"])
        page.click('.sidebar-item[data-section="vaults"]')
        page.click("#create-vault-btn")
        expect(page.locator("#create-vault-modal")).to_be_visible()
        page.fill("#vault-name", vname)
        # ZK is enabled, so the type selector is offered.
        expect(page.locator("#vault-type-group")).to_be_visible(timeout=5000)
        page.select_option("#vault-type", "zero_knowledge")
        page.click("#create-vault-form button[type=submit]")

        # First-time key setup: enter the passphrase, then confirm it (same modal).
        expect(page.locator("#confirm-modal")).to_be_visible(timeout=5000)
        page.fill("#confirm-modal-input", passphrase)
        page.click("#confirm-modal-confirm-btn")
        page.fill("#confirm-modal-input", passphrase)
        page.click("#confirm-modal-confirm-btn")

        expect(page.locator("#create-vault-modal")).to_be_hidden(timeout=15000)

        match = [v for v in owner.get("/vaults").json() if v["name"] == vname]
        assert match, "ZK vault was not created"
        assert match[0]["type"] == "zero_knowledge"
        vid = match[0]["id"]

        # Open it and upload a file — the client encrypts before the bytes leave.
        page.wait_for_selector(f'.open-vault-btn[data-vault-id="{vid}"]', timeout=10000)
        page.click(f'.open-vault-btn[data-vault-id="{vid}"]')
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)
        page.set_input_files("#file-upload-input", files=[{
            "name": fname, "mimeType": "text/plain", "buffer": secret,
        }])

        fid = None
        for _ in range(40):
            items = owner.get(f"/vaults/{vid}/files").json()["items"]
            hit = [it for it in items if it["type"] == "file"]
            if hit:
                fid = hit[0]["id"]
                break
            page.wait_for_timeout(500)
        assert fid, "encrypted file never landed in the ZK vault"

        # PROOF of zero-knowledge CONTENT: what the server stored is NOT the plaintext.
        raw = owner.get(f"/vaults/{vid}/files/{fid}/download").content
        assert raw != secret, "server stored plaintext — NOT zero-knowledge!"
        assert len(raw) >= len(secret) + 12, "no AES-GCM IV/tag overhead — not encrypted"
        assert marker.encode() not in raw, "plaintext marker leaked into stored ciphertext"

        # PROOF of zero-knowledge NAME: the server returns NO plaintext name (only the
        # client ciphertext, ZK-marked) so it can't read the filename either...
        listed = next(it for it in owner.get(f"/vaults/{vid}/files").json()["items"] if it["id"] == fid)
        assert not listed.get("name"), f"server exposed plaintext ZK name: {listed.get('name')!r}"
        assert (listed.get("enc_name") or "").startswith("zk1:"), "ZK name not stored encrypted at rest"
        assert fname not in (owner.get(f"/vaults/{vid}/files").text), "plaintext name leaked into listing"
        # ...yet the BROWSER decrypts it and shows the real name in the file row.
        page.wait_for_selector(f'.file-name[data-file-name="{fname}"]', timeout=10000)

        # Preview decrypts in-browser back to the original plaintext.
        page.click(".file-name[data-file-id]")
        expect(page.locator("#file-preview-modal")).to_be_visible(timeout=10000)
        expect(page.locator("#file-preview-body")).to_contain_text(marker, timeout=10000)
    finally:
        if vid:
            owner.delete_vault(vid)
        admin.delete_user(user["id"])
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def test_zero_knowledge_upload_resumes_across_reload(page: Page, admin):
    """Zero-knowledge upload resume across a full page reload.

    A ZK upload encrypts the whole file in the browser and streams the CIPHERTEXT
    through the chunked uploader. We start one, upload only the first chunk, persist
    the encrypted blob to IndexedDB exactly as the live uploader does, then RELOAD —
    wiping all in-memory crypto state (DEK + private key + the ciphertext itself).
    Re-opening the vault must restore the upload from IndexedDB and finish it by
    replaying the remaining ciphertext chunks, with the server only ever seeing
    ciphertext (never the plaintext or the DEK) and reassembling the exact bytes."""
    from conftest import ApiClient

    admin.put("/settings", json={"zero_knowledge_enabled": True})
    user = admin.create_user(role="admin")  # fresh => first-time key-setup path
    owner = ApiClient()
    owner.login(user["_username"], user["_password"])

    passphrase = "zk-resume-pass-123"
    marker = _u("zkresume")
    fname = _u("resumed") + ".txt"
    vid = None
    try:
        _login(page, user["_username"], user["_password"])
        vid = _create_zk_vault_via_ui(page, owner, passphrase)

        # Open the vault so the browser holds the unlocked key + DEK.
        page.wait_for_selector(f'.open-vault-btn[data-vault-id="{vid}"]', timeout=10000)
        page.click(f'.open-vault-btn[data-vault-id="{vid}"]')
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)

        # Encrypt in-browser, start a chunked session, upload ONLY chunk 0, and persist
        # the full ciphertext to IndexedDB — the exact state of an interrupted ZK upload.
        setup = _zk_start_partial_upload(page, vid, fname, marker, persist=True)
        assert setup["totalChunks"] >= 2, "payload must span multiple chunks to prove resume"
        sid = setup["sid"]
        # Only the first chunk is on the server so far.
        assert owner.get(f"/vaults/{vid}/uploads/{sid}").json()["received_chunks"] == [0]

        # Drop the saved-view so restoreLastView() can't auto-open the vault on reload —
        # the EXPLICIT re-open below must be the sole trigger for the resume.
        page.evaluate("() => sessionStorage.removeItem('dv_nav')")

        # RELOAD: wipes in-memory ciphertext, DEK and private key.
        page.reload()
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)

        # Re-open the vault — loadVaultFiles() -> refreshResumable() restores the upload
        # from IndexedDB and auto-resumes it (no passphrase needed: resume just replays bytes).
        page.click('.sidebar-item[data-section="vaults"]')
        page.wait_for_selector(f'.open-vault-btn[data-vault-id="{vid}"]', timeout=10000)
        page.click(f'.open-vault-btn[data-vault-id="{vid}"]')
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)

        # The resumed upload finishes and the file lands.
        fid = None
        for _ in range(60):
            items = owner.get(f"/vaults/{vid}/files").json()["items"]
            hit = [it for it in items if it["type"] == "file"]  # ZK name is server-opaque
            if hit:
                fid = hit[0]["id"]
                break
            page.wait_for_timeout(500)
        assert fid, "resumed ZK upload never completed after reload"

        # Proof: the server stored the EXACT ciphertext (byte-for-byte), not plaintext.
        import base64
        raw = owner.get(f"/vaults/{vid}/files/{fid}/download").content
        assert raw == base64.b64decode(setup["cipherB64"]), "resumed bytes are not the original ciphertext"
        assert raw != setup["plainText"].encode(), "server stored plaintext — NOT zero-knowledge!"
        assert marker.encode() not in raw, "plaintext marker leaked into stored ciphertext"

        # On completion the saved ciphertext is dropped from IndexedDB (no dead blob left).
        left = page.evaluate("async (sid) => await zkUploadStore.get(sid)", sid)
        assert left is None, "completed ZK upload left its ciphertext in IndexedDB"
    finally:
        if vid:
            owner.delete_vault(vid)
        admin.delete_user(user["id"])
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def _zk_start_partial_upload(page: Page, vid: str, fname: str, marker: str,
                             chunk_size: int = 64, persist: bool = True):
    """In-browser: encrypt a known plaintext under the vault DEK, start a chunked upload,
    PUT only chunk 0, and (optionally) persist the full ciphertext to IndexedDB the way the
    live uploader does — i.e. the exact on-disk + in-browser state of an interrupted ZK
    upload. Returns {sid, totalChunks, cipherB64, plainText}. Assumes the vault is open so
    the unlocked key + DEK are in memory."""
    return page.evaluate(
        """async ({ vid, fname, marker, chunkSize, persist }) => {
            const enc = new TextEncoder();
            const plain = enc.encode(('ZK-RESUME-PAYLOAD ' + marker + ' ').repeat(20));
            const kv = await zkGetCurrentDekVersion(vid);
            const dek = await zkGetVaultDek(vid, kv);
            const cipher = new Uint8Array(await eccLib().encryptFile(plain.buffer, dek));
            const total = cipher.byteLength;
            const totalChunks = Math.ceil(total / chunkSize);
            // Zero-knowledge: encrypt the name/MIME in the browser; never send the plaintext.
            const encName = await eccLib().encryptName(fname, dek, vid, 'name', kv);
            const encMime = await eccLib().encryptName('text/plain', dek, vid, 'mime', kv);
            const nameBi = await eccLib().nameBlindIndex(fname, dek, vid, kv);
            const auth = { 'Authorization': 'Bearer ' + authToken };
            const initRes = await fetch(`${API_BASE}/vaults/${vid}/uploads`, {
                method: 'POST', headers: { ...auth, 'Content-Type': 'application/json' },
                body: JSON.stringify({ total_size: total,
                    total_chunks: totalChunks, chunk_size: chunkSize,
                    folder_id: null, zk_key_version: kv,
                    enc_name: encName, enc_mime: encMime, name_bi: nameBi }),
            });
            const sid = (await initRes.json()).session_id;
            await fetch(`${API_BASE}/vaults/${vid}/uploads/${sid}/chunks/0`, {
                method: 'PUT', headers: { ...auth, 'Content-Type': 'application/octet-stream' },
                body: cipher.slice(0, Math.min(chunkSize, total)),
            });
            if (persist) {
                await zkUploadStore.put({ sessionId: sid, vaultId: vid, fileName: fname,
                    totalSize: total, mimeType: 'text/plain', folderId: null, keyVersion: kv,
                    totalChunks, chunkSize, blob: new Blob([cipher], { type: 'text/plain' }),
                    encName, encMime, nameBi, createdAt: Date.now() });
            }
            let bin = ''; for (const b of cipher) bin += String.fromCharCode(b);
            return { sid, totalChunks, cipherB64: btoa(bin),
                     plainText: new TextDecoder().decode(plain) };
        }""",
        {"vid": vid, "fname": fname, "marker": marker, "chunkSize": chunk_size, "persist": persist},
    )


def test_zero_knowledge_upload_not_resumable_without_local_ciphertext(page: Page, admin):
    """If the encrypted bytes aren't on THIS device (different browser, or storage cleared),
    a ZK upload must NOT silently resume — re-encrypting would not match the server chunks
    and the plaintext is gone. It surfaces as not-resumable and never auto-completes."""
    from conftest import ApiClient

    admin.put("/settings", json={"zero_knowledge_enabled": True})
    user = admin.create_user(role="admin")
    owner = ApiClient()
    owner.login(user["_username"], user["_password"])

    vid = None
    fname = _u("nolocal") + ".txt"
    try:
        _login(page, user["_username"], user["_password"])
        vid = _create_zk_vault_via_ui(page, owner, "zk-nolocal-pass-1")
        page.wait_for_selector(f'.open-vault-btn[data-vault-id="{vid}"]', timeout=10000)
        page.click(f'.open-vault-btn[data-vault-id="{vid}"]')
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)

        # Partial server-side upload, but DO NOT persist the ciphertext locally.
        setup = _zk_start_partial_upload(page, vid, fname, _u("m"), persist=False)
        sid = setup["sid"]

        page.evaluate("() => sessionStorage.removeItem('dv_nav')")
        page.reload()
        expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
        page.click('.sidebar-item[data-section="vaults"]')
        page.wait_for_selector(f'.open-vault-btn[data-vault-id="{vid}"]', timeout=10000)
        page.click(f'.open-vault-btn[data-vault-id="{vid}"]')
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)

        # The tray surfaces it as not-resumable here (no auto-resume, honest message).
        expect(page.locator("#upload-tray")).to_contain_text("isn't on this device", timeout=8000)

        # It must NOT have auto-completed (no plaintext upload, no spurious finish): the
        # file never appears and the server still has only chunk 0.
        page.wait_for_timeout(3000)
        assert not any(it["type"] == "file" for it in owner.get(f"/vaults/{vid}/files").json()["items"]), \
            "ZK upload completed without the local ciphertext — should be impossible"
        assert owner.get(f"/vaults/{vid}/uploads/{sid}").json()["received_chunks"] == [0]
    finally:
        if vid:
            owner.delete_vault(vid)
        admin.delete_user(user["id"])
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def test_zero_knowledge_upload_cancel_and_prune_clear_indexeddb(page: Page, admin):
    """Cancelling a ZK upload deletes both the server session and the saved ciphertext, and
    the TTL prune evicts stale records — so abandoned uploads leave no dead encrypted blobs."""
    from conftest import ApiClient

    admin.put("/settings", json={"zero_knowledge_enabled": True})
    user = admin.create_user(role="admin")
    owner = ApiClient()
    owner.login(user["_username"], user["_password"])

    vid = None
    fname = _u("cancelled") + ".txt"
    try:
        _login(page, user["_username"], user["_password"])
        vid = _create_zk_vault_via_ui(page, owner, "zk-cancel-pass-1")
        page.wait_for_selector(f'.open-vault-btn[data-vault-id="{vid}"]', timeout=10000)
        page.click(f'.open-vault-btn[data-vault-id="{vid}"]')
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)

        setup = _zk_start_partial_upload(page, vid, fname, _u("m"), persist=True)
        sid = setup["sid"]
        assert page.evaluate("async (sid) => (await zkUploadStore.get(sid)) != null", sid)

        # Cancel through the manager: it must delete the server session AND the IDB record.
        cancelled = page.evaluate(
            """async ({ sid, vid, fname, total, totalChunks }) => {
                const id = 'test_' + sid;
                uploadManager.items.set(id, { id, file: new Blob([new Uint8Array(total)]),
                    vaultId: vid, folderId: null, fileName: fname, totalSize: total,
                    totalChunks, chunkSize: 64, sessionId: sid, received: new Set(),
                    status: 'paused', paused: true, cancelled: false, isZk: true, zkKeyVersion: 1 });
                await uploadManager.cancel(id);
                return { rec: await zkUploadStore.get(sid) };
            }""",
            {"sid": sid, "vid": vid, "fname": fname,
             "total": setup["totalChunks"] * 64, "totalChunks": setup["totalChunks"]},
        )
        assert cancelled["rec"] is None, "cancel left the ciphertext in IndexedDB"
        # Server-side cancel marks the session failed + drops its chunks, so it's no longer
        # offered as resumable (mirrors test_api_files.test_chunked_upload_cancel).
        assert all(s["session_id"] != sid for s in owner.get(f"/vaults/{vid}/uploads").json()), \
            "cancel left the session resumable"

        # TTL prune: an old record is evicted; a fresh one survives.
        pruned = page.evaluate(
            """async (vid) => {
                await zkUploadStore.put({ sessionId: 'old-sid', vaultId: vid, blob: new Blob(['x']),
                    totalChunks: 1, chunkSize: 64, createdAt: Date.now() - 60 * 60 * 1000 });
                await zkUploadStore.put({ sessionId: 'new-sid', vaultId: vid, blob: new Blob(['y']),
                    totalChunks: 1, chunkSize: 64, createdAt: Date.now() });
                await zkUploadStore.pruneOlderThan(30 * 60 * 1000);
                const o = await zkUploadStore.get('old-sid');
                const n = await zkUploadStore.get('new-sid');
                await zkUploadStore.delete('new-sid');
                return { oldGone: o == null, newKept: n != null };
            }""",
            vid,
        )
        assert pruned["oldGone"], "pruneOlderThan did not evict the stale record"
        assert pruned["newKept"], "pruneOlderThan evicted a fresh record"
    finally:
        if vid:
            owner.delete_vault(vid)
        admin.delete_user(user["id"])
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def test_zero_knowledge_upload_store_cleared_on_logout(logged_in: Page):
    """logout() must wipe the ZK upload store so an interrupted upload's ciphertext can't
    sit at rest on a shared machine after the user leaves (parity with the key scrub)."""
    page = logged_in
    gone = page.evaluate(
        """async () => {
            await zkUploadStore.put({ sessionId: 'logout-sid', vaultId: 'v', blob: new Blob(['z']),
                totalChunks: 1, chunkSize: 64, createdAt: Date.now() });
            const before = await zkUploadStore.get('logout-sid');
            logout();                              // fires zkUploadStore.clear() (fail-soft)
            await new Promise(r => setTimeout(r, 400));
            const after = await zkUploadStore.get('logout-sid');
            return { had: before != null, after };
        }"""
    )
    assert gone["had"], "precondition: record was stored"
    assert gone["after"] is None, "logout did not clear the ZK upload store"


def test_zk_upload_store_surfaces_quota_exceeded(logged_in: Page):
    """zkUploadStore.put must REPORT a storage failure rather than swallow it — otherwise a
    full IndexedDB silently drops the ciphertext and 'resumable' silently isn't. A normal put
    returns {ok:true}; a put that hits QuotaExceededError returns {ok:false, quota:true}."""
    page = logged_in
    res = page.evaluate(
        """async () => {
            // Baseline: a normal put succeeds and reports ok.
            const ok = await zkUploadStore.put({ sessionId: 'quota-ok', vaultId: 'v',
                blob: new Blob(['x']), createdAt: Date.now() });
            await zkUploadStore.delete('quota-ok');
            // Force the next put to hit a storage-quota error by making the object-store put
            // throw a QuotaExceededError DOMException (engines raise it sync or via the
            // request 'error' event; the sync throw exercises the classifier deterministically).
            const proto = IDBObjectStore.prototype;
            const orig = proto.put;
            proto.put = function () { throw new DOMException('mock quota', 'QuotaExceededError'); };
            let quota;
            try {
                quota = await zkUploadStore.put({ sessionId: 'quota-fail', vaultId: 'v',
                    blob: new Blob(['y']), createdAt: Date.now() });
            } finally {
                proto.put = orig;
            }

            // ASYNC path: the more common real-engine surface for QuotaExceededError is an
            // async IDBRequest 'error' event that aborts the transaction (NOT a sync throw).
            // Simulate it: a stubbed put returns a fake request, then on a microtask fires its
            // onerror with a quota DOMException and aborts the real tx — so put() must resolve
            // {ok:false, quota:true} via the tx.onabort -> _putResult(reqErr) path. (This guards
            // the fix that REMOVED preventDefault(), which previously let the tx commit ok:true.)
            const origAsync = proto.put;
            proto.put = function () {
                const tx = this.transaction;
                const fakeReq = {};
                Promise.resolve().then(() => {
                    fakeReq.error = new DOMException('mock async quota', 'QuotaExceededError');
                    if (fakeReq.onerror) fakeReq.onerror({ target: fakeReq });
                    try { tx.abort(); } catch (_) {}
                });
                return fakeReq;
            };
            let quotaAsync;
            try {
                quotaAsync = await zkUploadStore.put({ sessionId: 'quota-async', vaultId: 'v',
                    blob: new Blob(['z']), createdAt: Date.now() });
            } finally {
                proto.put = origAsync;
            }
            return { ok, quota, quotaAsync };
        }"""
    )
    assert res["ok"]["ok"] is True, res["ok"]
    assert res["quota"]["ok"] is False, res["quota"]
    assert res["quota"]["quota"] is True, "sync quota error was not classified as a quota failure"
    assert res["quotaAsync"]["ok"] is False, res["quotaAsync"]
    assert res["quotaAsync"]["quota"] is True, "async quota error was not classified as a quota failure"


def test_zk_resume_persistence_unavailable_quiet_and_render_note(logged_in: Page):
    """Two UX invariants of the quota change: (a) IndexedDB being entirely unavailable is the
    documented QUIET graceful degrade — no warning toast, but the item is flagged not-persisted;
    (b) render() shows a 'not resumable' note for an in-flight ZK upload whose ciphertext
    persistence failed, and hides it once the upload is done."""
    page = logged_in
    res = page.evaluate(
        """async () => {
            // (a) unavailable -> no warning, but resumePersisted=false and no warning text.
            let warned = null;
            const origWarn = window.showWarning;
            window.showWarning = (m) => { warned = m; };
            const itA = { id: 'note_a', isZk: true };
            try { uploadManager._noteResumePersistence(itA, { ok: false, unavailable: true }); }
            finally { window.showWarning = origWarn; }

            // (b) render() flags an in-flight non-persisted ZK upload, and unflags it when done.
            const itB = { id: 'note_b', isZk: true, file: new Blob(['x']), fileName: 'n.bin',
                totalSize: 1, totalChunks: 1, chunkSize: 1, received: new Set(),
                status: 'uploading', resumePersisted: false, resumeWarning: 'nope', vaultId: 'v' };
            uploadManager.items.set('note_b', itB);
            uploadManager.render();
            const flagged = !!document.querySelector('#upload-tray .up-warn');
            itB.status = 'done';
            uploadManager.render();
            const hiddenWhenDone = !document.querySelector('#upload-tray .up-warn');
            uploadManager.items.delete('note_b');
            uploadManager.render();
            return { warnedUnavailable: warned, aWarning: itA.resumeWarning,
                     aPersisted: itA.resumePersisted, flagged, hiddenWhenDone };
        }"""
    )
    assert res["warnedUnavailable"] is None, "IndexedDB-unavailable wrongly surfaced a warning"
    assert res["aWarning"] is None
    assert res["aPersisted"] is False
    assert res["flagged"], "render did not flag an in-flight non-persisted ZK upload 'not resumable'"
    assert res["hiddenWhenDone"], "the 'not resumable' note must disappear once the upload is done"


def test_zero_knowledge_upload_quota_fallback_completes_and_warns(page: Page, admin):
    """Quota-exceeded FALLBACK: if the ciphertext can't be persisted for resume (storage
    full), the upload must STILL complete and the user must be WARNED that it won't survive a
    reload — rather than the persistence failing silently. Drives a real ZK upload through
    uploadManager with put() forced to report a quota failure."""
    from conftest import ApiClient

    admin.put("/settings", json={"zero_knowledge_enabled": True})
    user = admin.create_user(role="admin")
    owner = ApiClient()
    owner.login(user["_username"], user["_password"])

    vid = None
    fname = _u("quotafallback") + ".txt"
    try:
        _login(page, user["_username"], user["_password"])
        vid = _create_zk_vault_via_ui(page, owner, "zk-quota-pass-1")
        page.wait_for_selector(f'.open-vault-btn[data-vault-id="{vid}"]', timeout=10000)
        page.click(f'.open-vault-btn[data-vault-id="{vid}"]')
        expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)

        out = page.evaluate(
            """async ({ vid, fname }) => {
                const kv = await zkGetCurrentDekVersion(vid);
                const dek = await zkGetVaultDek(vid, kv);
                const enc = new TextEncoder();
                const plain = enc.encode(('QUOTA-FALLBACK ' + fname + ' ').repeat(25));
                const cipher = new Uint8Array(await eccLib().encryptFile(plain.buffer, dek));
                const encName = await eccLib().encryptName(fname, dek, vid, 'name', kv);
                const encMime = await eccLib().encryptName('text/plain', dek, vid, 'mime', kv);
                const nameBi = await eccLib().nameBlindIndex(fname, dek, vid, kv);
                const chunkSize = 64;
                const blob = new Blob([cipher], { type: 'text/plain' });

                // Force every resume-persistence to report a storage-quota failure (no save).
                const origPut = zkUploadStore.put;
                let putCalls = 0;
                zkUploadStore.put = async () => { putCalls++; return { ok: false, quota: true }; };
                let warned = null;
                const origWarn = window.showWarning;
                window.showWarning = (m) => { warned = m; };

                const id = uploadManager._newId();
                const it = { id, file: blob, vaultId: vid, folderId: null, fileName: fname,
                    totalSize: cipher.byteLength,
                    totalChunks: Math.ceil(cipher.byteLength / chunkSize), chunkSize,
                    sessionId: null, received: new Set(),
                    status: 'queued', error: null, paused: false, cancelled: false,
                    zkKeyVersion: kv, isZk: true, encName, encMime, nameBi };
                uploadManager.items.set(id, it);
                try {
                    await uploadManager.run(id);   // resolves when the upload finishes/fails
                } finally {
                    zkUploadStore.put = origPut;
                    window.showWarning = origWarn;
                }
                // Nothing should have been persisted for resume.
                const rec = it.sessionId ? await zkUploadStore.get(it.sessionId) : null;
                let bin = ''; for (const b of cipher) bin += String.fromCharCode(b);
                return { status: it.status, error: it.error, warned,
                         resumeWarning: it.resumeWarning, resumePersisted: it.resumePersisted,
                         putCalls, sid: it.sessionId, persistedRec: rec, cipherB64: btoa(bin) };
            }""",
            {"vid": vid, "fname": fname},
        )

        # Fallback: the upload still finished despite the persistence failure.
        assert out["status"] == "done", f"upload did not complete (status={out['status']}, err={out['error']})"
        assert out["putCalls"] >= 1, "persistence was never attempted"
        # The user was warned and the item is flagged not-resumable.
        assert out["resumePersisted"] is False, "item not flagged as non-persisted"
        assert out["warned"], "no quota warning surfaced to the user"
        assert out["resumeWarning"], "item carries no resume-warning text"
        assert out["persistedRec"] is None, "ciphertext was persisted despite the quota failure"

        # And the server really did receive + store the file (the exact ciphertext).
        import base64
        fid = None
        for _ in range(40):
            items = owner.get(f"/vaults/{vid}/files").json()["items"]
            hit = [it for it in items if it["type"] == "file"]
            if hit:
                fid = hit[0]["id"]
                break
            page.wait_for_timeout(250)
        assert fid, "quota-fallback upload never landed on the server"
        raw = owner.get(f"/vaults/{vid}/files/{fid}/download").content
        assert raw == base64.b64decode(out["cipherB64"]), "stored bytes are not the original ciphertext"
    finally:
        if vid:
            owner.delete_vault(vid)
        admin.delete_user(user["id"])
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def _create_zk_vault_via_ui(page: Page, owner_client, passphrase: str) -> str:
    """Create a zero-knowledge vault through the UI (generating/using the browser
    keypair via the passphrase prompts) and return its id. Assumes the page is
    logged in and ZK is enabled."""
    vname = _u("zk")
    page.click('.sidebar-item[data-section="vaults"]')
    page.click("#create-vault-btn")
    expect(page.locator("#create-vault-modal")).to_be_visible()
    page.fill("#vault-name", vname)
    expect(page.locator("#vault-type-group")).to_be_visible(timeout=5000)
    page.select_option("#vault-type", "zero_knowledge")
    page.click("#create-vault-form button[type=submit]")
    expect(page.locator("#confirm-modal")).to_be_visible(timeout=5000)
    page.fill("#confirm-modal-input", passphrase)
    page.click("#confirm-modal-confirm-btn")
    page.fill("#confirm-modal-input", passphrase)
    page.click("#confirm-modal-confirm-btn")
    expect(page.locator("#create-vault-modal")).to_be_hidden(timeout=15000)
    m = [v for v in owner_client.get("/vaults").json() if v["name"] == vname]
    assert m, "ZK vault was not created via the UI"
    return m[0]["id"]


def test_zero_knowledge_vault_sharing_two_users(browser, admin):
    """User A wraps the vault DEK in their browser for user B; B unwraps it in
    their browser and reads the file. The definitive proof that client-side ECDH
    re-sharing (wrapVaultDEK -> unwrapVaultDEK across two keypairs) works."""
    from conftest import ApiClient, BASE_URL

    admin.put("/settings", json={"zero_knowledge_enabled": True})
    ua = admin.create_user(role="admin")
    ub = admin.create_user(role="admin")
    ca = ApiClient(); ca.login(ua["_username"], ua["_password"])
    cb = ApiClient(); cb.login(ub["_username"], ub["_password"])

    marker = _u("shared")
    secret = (f"SHARED-ZK-CONTENT {marker} ").encode() * 4
    fname = _u("shared") + ".txt"
    vidA = vidB = None
    ctxA = browser.new_context(base_url=BASE_URL)
    ctxB = browser.new_context(base_url=BASE_URL)
    pageA = ctxA.new_page()
    pageB = ctxB.new_page()
    try:
        # A: create a ZK vault + upload a secret (sets up A's keypair in-browser).
        _login(pageA, ua["_username"], ua["_password"])
        vidA = _create_zk_vault_via_ui(pageA, ca, "passphrase-A-123")
        pageA.click('.sidebar-item[data-section="vaults"]')
        pageA.wait_for_selector(f'.open-vault-btn[data-vault-id="{vidA}"]', timeout=10000)
        pageA.click(f'.open-vault-btn[data-vault-id="{vidA}"]')
        expect(pageA.locator("#vault-view-section")).to_be_visible(timeout=10000)
        pageA.set_input_files("#file-upload-input", files=[{"name": fname, "mimeType": "text/plain", "buffer": secret}])
        for _ in range(40):
            if any(it["type"] == "file" for it in ca.get(f"/vaults/{vidA}/files").json()["items"]):
                break
            pageA.wait_for_timeout(500)

        # B: create their own ZK vault so B's keypair is generated + registered.
        _login(pageB, ub["_username"], ub["_password"])
        vidB = _create_zk_vault_via_ui(pageB, cb, "passphrase-B-123")

        # A: grant B access to vault A via the searchable grant modal — this
        # re-wraps A's DEK to B's public key in A's browser (confirmVaultGrant).
        pageA.click('[data-vault-tab="permissions"]')
        pageA.click("#add-permission-btn")
        expect(pageA.locator("#vault-grant-modal")).to_be_visible(timeout=5000)
        pageA.wait_for_selector(f'#vault-grant-list input[value="{ub["id"]}"]', timeout=8000)
        pageA.check(f'#vault-grant-list input[value="{ub["id"]}"]')
        pageA.click("#vault-grant-confirm")
        expect(pageA.locator("#vault-grant-modal")).to_be_hidden(timeout=15000)

        # B now holds a wrapped DEK for vault A (wrapped by A's browser).
        got = False
        for _ in range(20):
            k = cb.get(f"/ecc/vaults/{vidA}/keys").json()
            if k.get("has_access") and k.get("wrapped_dek"):
                got = True
                break
            pageA.wait_for_timeout(300)
        assert got, "A did not share a wrapped DEK to B"

        # B: open vault A and preview the file — B's browser unwraps + decrypts it.
        pageB.click('.sidebar-item[data-section="vaults"]')
        pageB.wait_for_selector(f'.open-vault-btn[data-vault-id="{vidA}"]', timeout=10000)
        pageB.click(f'.open-vault-btn[data-vault-id="{vidA}"]')
        expect(pageB.locator("#vault-view-section")).to_be_visible(timeout=10000)
        pageB.click(".file-name[data-file-id]")
        expect(pageB.locator("#file-preview-modal")).to_be_visible(timeout=10000)
        expect(pageB.locator("#file-preview-body")).to_contain_text(marker, timeout=10000)
    finally:
        for ctx in (ctxA, ctxB):
            try: ctx.close()
            except Exception: pass
        if vidA: ca.delete_vault(vidA)
        if vidB: cb.delete_vault(vidB)
        admin.delete_user(ua["id"])
        admin.delete_user(ub["id"])
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def test_zero_knowledge_revoke_rotates_dek(browser, admin):
    """Forward-only DEK rotation on revoke, end-to-end across two real browsers:
      A creates a ZK vault, uploads F1 (epoch 1), shares to B; B reads F1.
      A REVOKES B via the UI — A's browser mints a new DEK, re-wraps it for the
        remaining members, and the server bumps the epoch (POST /ecc/.../rekey).
      A then uploads F2 (epoch 2) and can still read BOTH F1 (old epoch) and F2 (new).
      B can no longer obtain a usable DEK and is locked out.
    This is the definitive proof of the forward-secrecy-for-new-content property."""
    from conftest import ApiClient, BASE_URL

    admin.put("/settings", json={"zero_knowledge_enabled": True})
    ua = admin.create_user(role="admin")
    ub = admin.create_user(role="admin")
    ca = ApiClient(); ca.login(ua["_username"], ua["_password"])
    cb = ApiClient(); cb.login(ub["_username"], ub["_password"])

    m1 = _u("f1"); m2 = _u("f2")
    f1 = (f"EPOCH-ONE {m1} ").encode() * 4
    f2 = (f"EPOCH-TWO {m2} ").encode() * 4
    n1 = _u("f1") + ".txt"; n2 = _u("f2") + ".txt"
    vidA = vidB = None
    ctxA = browser.new_context(base_url=BASE_URL)
    ctxB = browser.new_context(base_url=BASE_URL)
    pageA = ctxA.new_page()
    pageB = ctxB.new_page()
    try:
        # A: create a ZK vault + upload F1, then share to B.
        _login(pageA, ua["_username"], ua["_password"])
        vidA = _create_zk_vault_via_ui(pageA, ca, "passphrase-A-123")
        pageA.click('.sidebar-item[data-section="vaults"]')
        pageA.wait_for_selector(f'.open-vault-btn[data-vault-id="{vidA}"]', timeout=10000)
        pageA.click(f'.open-vault-btn[data-vault-id="{vidA}"]')
        expect(pageA.locator("#vault-view-section")).to_be_visible(timeout=10000)
        pageA.set_input_files("#file-upload-input", files=[{"name": n1, "mimeType": "text/plain", "buffer": f1}])
        for _ in range(40):
            if any(it["type"] == "file" for it in ca.get(f"/vaults/{vidA}/files").json()["items"]):
                break
            pageA.wait_for_timeout(500)

        # B: create their own ZK vault so B's keypair exists; then A grants B access.
        _login(pageB, ub["_username"], ub["_password"])
        vidB = _create_zk_vault_via_ui(pageB, cb, "passphrase-B-123")
        pageA.click('[data-vault-tab="permissions"]')
        pageA.click("#add-permission-btn")
        expect(pageA.locator("#vault-grant-modal")).to_be_visible(timeout=5000)
        pageA.wait_for_selector(f'#vault-grant-list input[value="{ub["id"]}"]', timeout=8000)
        pageA.check(f'#vault-grant-list input[value="{ub["id"]}"]')
        pageA.click("#vault-grant-confirm")
        expect(pageA.locator("#vault-grant-modal")).to_be_hidden(timeout=15000)
        for _ in range(20):
            k = cb.get(f"/ecc/vaults/{vidA}/keys").json()
            if k.get("has_access") and k.get("current_dek_version") == 1:
                break
            pageA.wait_for_timeout(300)
        assert cb.get(f"/ecc/vaults/{vidA}/keys").json().get("has_access"), "B never received the DEK"

        # A: REVOKE B via the permissions UI — drives zkRekeyForRevoke + the rekey endpoint.
        pageA.click(f'button[data-action="revoke-permission"][data-user-id="{ub["id"]}"]')
        expect(pageA.locator("#confirm-modal")).to_be_visible(timeout=5000)
        pageA.click("#confirm-modal-confirm-btn")

        # The vault is now epoch 2 and B has lost access (all epochs).
        rotated = False
        for _ in range(40):
            ak = ca.get(f"/ecc/vaults/{vidA}/keys").json()
            bk = cb.get(f"/ecc/vaults/{vidA}/keys").json()
            if ak.get("current_dek_version") == 2 and not bk.get("has_access"):
                rotated = True
                break
            pageA.wait_for_timeout(300)
        assert rotated, "revoke did not rotate the DEK / B still has access"

        # A: upload F2 (now epoch 2).
        pageA.click('[data-vault-tab="files"]')
        pageA.set_input_files("#file-upload-input", files=[{"name": n2, "mimeType": "text/plain", "buffer": f2}])
        # F2 is the epoch-2 file (F1 is epoch 1) — the clean server-side discriminator now
        # that names are opaque to the server.
        fid2 = None
        for _ in range(40):
            hit = [it for it in ca.get(f"/vaults/{vidA}/files").json()["items"]
                   if it["type"] == "file" and it.get("key_version") == 2]
            if hit:
                fid2 = hit[0]["id"]
                break
            pageA.wait_for_timeout(500)
        assert fid2, "F2 never landed (epoch 2)"

        # A can read BOTH the old-epoch file (F1) and the new-epoch file (F2) — A is still
        # inside the vault view on the files tab; A's DEK cache was cleared by the rotation,
        # so each preview re-fetches the right epoch's DEK and decrypts in-browser.
        for name in (n1, n2):
            pageA.wait_for_selector(f'.file-name[data-file-name="{name}"]', timeout=10000)
        for name, marker in ((n1, m1), (n2, m2)):
            pageA.click(f'.file-name[data-file-name="{name}"]')
            expect(pageA.locator("#file-preview-modal")).to_be_visible(timeout=10000)
            expect(pageA.locator("#file-preview-body")).to_contain_text(marker, timeout=10000)
            pageA.click("#file-preview-modal .modal-close")
            expect(pageA.locator("#file-preview-modal")).to_be_hidden(timeout=5000)

        # B is fully locked out: no usable DEK at any epoch (crypto cut-off), AND the file
        # listing no longer succeeds (authz cut-off). The list endpoint surfaces a denied
        # read as a non-200 (it wraps the PermissionError), so "not a successful listing"
        # is the robust check.
        assert not cb.get(f"/ecc/vaults/{vidA}/keys?key_version=2").json().get("has_access")
        assert not cb.get(f"/ecc/vaults/{vidA}/keys?key_version=1").json().get("has_access")
        bf = cb.get(f"/vaults/{vidA}/files")
        assert bf.status_code != 200 or bf.json().get("items") == [], "revoked B can still list files"
    finally:
        for ctx in (ctxA, ctxB):
            try: ctx.close()
            except Exception: pass
        if vidA: ca.delete_vault(vidA)
        if vidB: cb.delete_vault(vidB)
        admin.delete_user(ua["id"])
        admin.delete_user(ub["id"])
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def test_create_vault_locked_to_zk_under_force_policy(logged_in: Page, admin):
    """When the org forces zero-knowledge (no whitelist), the create-vault Type
    selector is locked to zero-knowledge for a non-exempt user."""
    page = logged_in
    admin.put("/settings", json={"zero_knowledge_enabled": True, "force_zero_knowledge": True,
                                 "standard_vault_allowed_groups": []})
    try:
        page.click('.sidebar-item[data-section="vaults"]')
        page.click("#create-vault-btn")
        expect(page.locator("#create-vault-modal")).to_be_visible()
        sel = page.locator("#vault-type")
        expect(sel).to_be_visible(timeout=5000)
        expect(sel).to_have_value("zero_knowledge")
        expect(sel).to_be_disabled()
    finally:
        admin.put("/settings", json={"force_zero_knowledge": False, "standard_vault_allowed_groups": [],
                                     "zero_knowledge_enabled": False})


def test_user_ssh_key_add_and_delete_via_ui(logged_in: Page, admin):
    """Add an SSH key through the user-detail form, then delete it via the row's
    trash button (which uses the confirm modal)."""
    page = logged_in
    user = admin.create_user(role="user")
    uid = user["id"]
    pub = _gen_ssh_pubkey()
    try:
        page.click('.sidebar-item[data-section="users"]')
        page.wait_for_selector(f'.exp-row[data-id="{uid}"]', timeout=10000)
        page.click(f'.exp-row[data-id="{uid}"] .exp-toggle')

        page.fill(f'.ssh-key-name[data-user-id="{uid}"]', "ui-laptop")
        page.fill(f'.ssh-key-public[data-user-id="{uid}"]', pub)
        page.click(f'.ssh-key-add-btn[data-user-id="{uid}"]')

        # Lands via the API -> the whole add flow ran.
        added = None
        for _ in range(15):
            keys = admin.get(f"/users/{uid}/ssh-keys").json()
            if keys:
                added = keys[0]
                break
            page.wait_for_timeout(400)
        assert added and added["name"] == "ui-laptop", "SSH key was not added via the UI"

        # The key item renders; delete it (confirm modal -> confirm).
        expect(page.locator(f'.ssh-keys-list[data-user-id="{uid}"] .ssh-key-item')).to_be_visible(timeout=8000)
        page.click(f'.ssh-key-delete-btn[data-user-id="{uid}"]')
        page.click("#confirm-modal-confirm-btn")

        gone = False
        for _ in range(15):
            if not admin.get(f"/users/{uid}/ssh-keys").json():
                gone = True
                break
            page.wait_for_timeout(400)
        assert gone, "SSH key was not removed via the UI"
    finally:
        admin.delete_user(uid)


def test_set_up_encryption_key_from_profile_menu(page: Page, admin):
    """A user with NO keypair sets one up from the profile menu — without first
    creating a zero-knowledge vault — so others can later share ZK vaults with
    them. Proves the standalone account-level setup wires register/public/private.
    Deliberately does NOT enable ZK at the deployment level: minting a personal
    keypair is independent of the org ZK toggle."""
    from conftest import ApiClient

    user = admin.create_user(role="user")        # fresh => no ECC keypair
    view = ApiClient()
    view.login(user["_username"], user["_password"])
    passphrase = "set-up-key-pass-123"
    try:
        assert view.get("/ecc/keys/public").json().get("has_keypair") is False

        _login(page, user["_username"], user["_password"])
        page.click("#profile-btn")
        page.click("#encryption-key-btn")
        expect(page.locator("#encryption-key-modal")).to_be_visible(timeout=5000)
        # Not-set-up state: the setup button is offered.
        expect(page.locator("#encryption-key-setup-btn")).to_be_visible()
        expect(page.locator("#encryption-key-status")).to_contain_text("don't have an encryption key")

        page.click("#encryption-key-setup-btn")
        # Passphrase, then confirm (same prompt modal reused).
        expect(page.locator("#confirm-modal")).to_be_visible(timeout=5000)
        page.fill("#confirm-modal-input", passphrase)
        page.click("#confirm-modal-confirm-btn")
        page.fill("#confirm-modal-input", passphrase)
        page.click("#confirm-modal-confirm-btn")

        # Status flips to active and the setup button is hidden (no re-setup).
        expect(page.locator("#encryption-key-status")).to_contain_text("set up and active", timeout=15000)
        expect(page.locator("#encryption-key-setup-btn")).to_be_hidden()

        # The server now holds the keypair (public key + opaque private blob).
        assert view.get("/ecc/keys/public").json().get("has_keypair") is True
        assert view.get("/ecc/keys/private").json().get("has_keypair") is True
    finally:
        admin.delete_user(user["id"])
