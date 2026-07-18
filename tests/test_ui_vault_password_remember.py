"""UI — vault-password remembering controls.

Two surfaces: the admin 'Vault Password Handling' card on Settings -> SFTP & Encryption (the org
floor), and the per-user 'Never remember vault passwords' toggle in the 'Your account' modal
(forced-on + disabled when the org floor is set).
"""
import time

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui


def _wait_until(pred, msg, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if pred():
                return
        except Exception:
            pass
        time.sleep(0.25)
    raise AssertionError(msg)


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_sftp_settings(page: Page):
    # Wait for loadSettings' GET /settings to land so the save collect reads populated fields
    # (a bare click races the async load).
    with page.expect_response(
        lambda r: r.url.rstrip("/").endswith("/settings") and r.request.method == "GET"
    ):
        page.click('.sidebar-item[data-section="settings"]')
    expect(page.locator("#settings-section")).to_be_visible()
    page.click('.tab-btn[data-tab="sftp"]')
    expect(page.locator("#settings-tab-sftp")).to_be_visible()


def _open_account_modal(page: Page):
    page.click("#profile-btn")
    page.click("#settings-btn")
    expect(page.locator("#user-settings-modal")).to_be_visible()


@pytest.fixture
def fresh_admin(admin):
    u = admin.create_user(role="admin")
    yield u
    admin.delete_user(u["id"])


def test_org_floor_card_round_trips(page: Page, admin, fresh_admin):
    admin.put("/settings", json={"force_no_remember_vault_password": False})
    try:
        _login(page, fresh_admin["_username"], fresh_admin["_password"])
        _open_sftp_settings(page)

        floor = page.locator("#setting-force-no-remember-vault-password")
        expect(floor).to_be_visible()
        expect(floor).not_to_be_checked()

        floor.check()
        page.click("#save-all-settings-btn")
        # Poll the authoritative store rather than racing the PUT response event (flaky on a
        # cold browser); the save must persist the floor.
        _wait_until(lambda: admin.get("/settings").json().get("force_no_remember_vault_password") is True,
                    "force_no_remember_vault_password did not persist after Save")

        page.reload()
        _open_sftp_settings(page)
        expect(page.locator("#setting-force-no-remember-vault-password")).to_be_checked()
    finally:
        admin.put("/settings", json={"force_no_remember_vault_password": False})


def test_org_floor_arms_client_remember_guard(page: Page, admin, fresh_admin):
    """With the floor ON, applyServerPreferences loads it at boot so rememberVaultPassword refuses to
    cache a password even for a locally-submitted unlock window (the client-cache bypass)."""
    admin.put("/settings", json={"force_no_remember_vault_password": True})
    try:
        _login(page, fresh_admin["_username"], fresh_admin["_password"])
        result = page.evaluate(
            """() => {
                // the floor must be armed at boot (no account modal opened)
                const armed = state.forceNoRememberVaultPassword === true;
                // a locally-submitted 60-min window must NOT be cached
                state.rememberVaultPassword('vault-xyz', 'the-password', 60);
                return { armed, remembered: state.getRememberedVaultPassword('vault-xyz') };
            }"""
        )
        assert result["armed"] is True, "org floor was not loaded into client state at boot"
        assert result["remembered"] is None, "floor did not block the client remember cache"
    finally:
        admin.put("/settings", json={"force_no_remember_vault_password": False})


def test_account_toggle_user_pref_and_org_force(page: Page, admin, fresh_admin):
    admin.put("/settings", json={"force_no_remember_vault_password": False})
    try:
        # --- floor OFF: the per-user toggle is enabled and persists as a preference ---
        _login(page, fresh_admin["_username"], fresh_admin["_password"])
        _open_account_modal(page)
        nr = page.locator("#us-never-remember-pw")
        expect(nr).to_be_visible()
        expect(nr).to_be_enabled()
        expect(nr).not_to_be_checked()
        expect(page.locator("#us-never-remember-forced")).to_be_hidden()

        with page.expect_response(
            lambda r: r.url.rstrip("/").endswith("/users/me/preferences") and r.request.method == "PUT"
        ) as resp_info:
            nr.check()
        assert resp_info.value.ok
        # the fresh admin's stored preference now reflects the opt-out (survives a reload)
        page.reload()
        _open_account_modal(page)
        expect(page.locator("#us-never-remember-pw")).to_be_checked()

        # --- floor ON: the toggle is forced checked + disabled, with the admin note ---
        admin.put("/settings", json={"force_no_remember_vault_password": True})
        page.reload()
        _open_account_modal(page)
        forced = page.locator("#us-never-remember-pw")
        expect(forced).to_be_checked()
        expect(forced).to_be_disabled()
        expect(page.locator("#us-never-remember-forced")).to_be_visible()
    finally:
        admin.put("/settings", json={"force_no_remember_vault_password": False})
