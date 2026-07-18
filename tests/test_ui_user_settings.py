"""The self-service 'Your account' modal (replaces the coming-soon alert)."""
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


def _open_account_modal(page: Page):
    page.click("#profile-btn")          # open the profile dropdown
    page.click("#settings-btn")         # -> "Your account"
    expect(page.locator("#user-settings-modal")).to_be_visible(timeout=8000)


def test_account_modal_opens_and_shows_profile(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_account_modal(page)
    expect(page.locator("#us-username")).to_have_text(admin_creds["username"])
    expect(page.locator("#us-password-form")).to_be_visible()   # credential sections shown for a real user
    expect(page.locator("#us-temp-note")).to_be_hidden()


def test_account_password_change_via_modal(page: Page, admin):
    u = admin.create_user(role="user")
    try:
        _login(page, u["_username"], u["_password"])
        _open_account_modal(page)
        page.fill("#us-cur-pw", u["_password"])
        page.fill("#us-new-pw", "NewModalPass1!")
        page.fill("#us-new-pw2", "NewModalPass1!")
        page.click("#us-password-form button[type=submit]")
        page.wait_for_timeout(1500)
        # the new password now works
        fresh = admin.clone_anonymous()
        assert fresh.post("/auth/login", json={"username": u["_username"], "password": "NewModalPass1!"}).status_code == 200
    finally:
        admin.delete_user(u["id"])


def test_account_modal_hides_credentials_for_temp_credential(page: Page, admin):
    scope = {"v": 1, "pages": ["dashboard", "vaults"], "caps": [],
             "vault_caps_default": ["vault.see_info"], "temp": {}}
    body = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 60, "scope": scope, "vault_access_mode": "all", "selected_vaults": []}).json()
    _login(page, body["temp_username"], body["credential"])
    _open_account_modal(page)
    expect(page.locator("#us-temp-note")).to_be_visible()
    expect(page.locator("#us-password-form")).to_be_hidden()
