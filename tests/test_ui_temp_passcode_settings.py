"""UI — the 'Temporary Vault Passcodes' card on Settings -> SFTP & Encryption.

Verifies the card renders, its controls reflect GET /settings (the effective-policy overlay), and a
toggle + Save round-trips through PUT /settings (persisted, and re-shown on reload). Policy surface
only — no passcode is minted here.
"""
import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_sftp_settings(page: Page):
    page.click('.sidebar-item[data-section="settings"]')
    expect(page.locator("#settings-section")).to_be_visible()
    page.click('.tab-btn[data-tab="sftp"]')
    expect(page.locator("#settings-tab-sftp")).to_be_visible()


@pytest.fixture
def fresh_admin(admin):
    u = admin.create_user(role="admin")
    yield u
    admin.delete_user(u["id"])


def test_temp_passcode_card_renders_and_round_trips(page: Page, admin, fresh_admin):
    # Known baseline via the API: feature OFF, ZK allowed, generated-only, min length 16.
    admin.put("/settings", json={
        "temp_passcodes_enabled": False, "temp_cred_allow_zk_vaults": True,
        "temp_passcode_allow_custom": False, "temp_passcode_require_special": False,
        "temp_passcode_min_length": 16,
    })
    try:
        _login(page, fresh_admin["_username"], fresh_admin["_password"])
        _open_sftp_settings(page)

        # Card + controls render and reflect the API baseline (load path).
        enabled = page.locator("#setting-temp-passcodes-enabled")
        expect(enabled).to_be_visible()
        expect(enabled).not_to_be_checked()
        expect(page.locator("#setting-temp-cred-allow-zk-vaults")).to_be_checked()   # default ON
        expect(page.locator("#setting-temp-passcode-allow-custom")).not_to_be_checked()
        expect(page.locator("#setting-temp-passcode-require-special")).not_to_be_checked()
        expect(page.locator("#setting-temp-passcode-min-length")).to_have_value("16")
        # the rest of the controls exist
        for cid in ("setting-temp-passcode-one-time-default", "setting-temp-passcode-single-vault-only",
                    "setting-temp-passcode-require-uppercase", "setting-temp-passcode-require-lowercase",
                    "setting-temp-passcode-require-numbers", "setting-temp-passcode-max-lifetime"):
            expect(page.locator(f"#{cid}")).to_be_visible()

        # Toggle the policy and Save (save path), waiting for the PUT /settings to complete.
        enabled.check()
        page.locator("#setting-temp-passcode-allow-custom").check()
        page.locator("#setting-temp-passcode-require-special").check()
        page.fill("#setting-temp-passcode-min-length", "20")
        page.locator("#setting-temp-cred-allow-zk-vaults").uncheck()
        with page.expect_response(
            lambda r: r.url.rstrip("/").endswith("/settings") and r.request.method == "PUT"
        ) as resp_info:
            page.click("#save-all-settings-btn")
        assert resp_info.value.ok, f"PUT /settings failed: {resp_info.value.status}"

        # Authoritative check: the values persisted through PUT /settings.
        saved = admin.get("/settings").json()
        assert saved["temp_passcode_allow_custom"] is True
        assert saved["temp_passcode_require_special"] is True
        assert saved["temp_passcode_min_length"] == 20
        assert saved["temp_cred_allow_zk_vaults"] is False

        # Reload -> the card reflects the saved state (load path re-reads the overlay).
        page.reload()
        _open_sftp_settings(page)
        expect(page.locator("#setting-temp-passcodes-enabled")).to_be_checked()
        expect(page.locator("#setting-temp-passcode-allow-custom")).to_be_checked()
        expect(page.locator("#setting-temp-cred-allow-zk-vaults")).not_to_be_checked()
        expect(page.locator("#setting-temp-passcode-min-length")).to_have_value("20")
    finally:
        # leave the shared deployment back at defaults
        admin.put("/settings", json={
            "temp_passcodes_enabled": False, "temp_cred_allow_zk_vaults": True,
            "temp_passcode_allow_custom": False, "temp_passcode_require_special": False,
            "temp_passcode_min_length": 16,
        })
