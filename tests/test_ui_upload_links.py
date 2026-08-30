"""UI — upload links (receivers): the Settings 'Upload Links' tab exposes the master toggle + per-user
cap + a receiver-tag editor (with MB->bytes size caps) + admin oversight, and the owner 'Upload links'
nav appears (with a working create modal) once the feature is enabled."""
import pytest
from playwright.sync_api import Page, expect

from conftest import unique

pytestmark = pytest.mark.ui

_MB = 1048576


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_uploadlinks_settings(page: Page):
    page.click('.sidebar-item[data-section="settings"]')
    page.click('#settings-section .tab-btn[data-tab="uploadlinks"]')
    expect(page.locator("#settings-tab-uploadlinks")).to_be_visible(timeout=10000)


@pytest.fixture
def restore_receivers(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ("public_receivers_enabled", "public_receiver_user_cap")}
    yield
    admin.put("/settings", json={k: v for k, v in snap.items() if v is not None})


def test_receivers_toggle_and_cap_persist(page: Page, admin, admin_creds, restore_receivers):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_uploadlinks_settings(page)
    expect(page.locator("#save-all-settings-btn")).to_be_enabled(timeout=10000)
    page.set_checked("#setting-public-receivers-enabled", True)
    page.fill("#setting-public-receiver-user-cap", "25")
    page.click("#save-all-settings-btn")
    page.wait_for_timeout(1500)
    s = admin.get("/settings").json()
    assert s["public_receivers_enabled"] is True
    assert s["public_receiver_user_cap"] == 25


def test_receiver_tag_editor_persists_with_mb_conversion(page: Page, admin, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_uploadlinks_settings(page)
    name = unique("RcTag")
    page.click("#rt-tag-add-btn")
    expect(page.locator("#rt-tag-editor")).to_be_visible()
    page.fill("#rt-tag-name", name)
    page.fill("#rt-tag-min-token-len", "12")
    page.select_option("#rt-tag-require-secret", "pin")
    page.select_option("#rt-tag-min-pin-len", "6")
    page.fill("#rt-tag-max-file-mb", "10")
    page.fill("#rt-tag-max-total-mb", "100")
    page.click("#rt-tag-save-btn")
    expect(page.locator("#rt-tags-list", has_text=name)).to_be_visible(timeout=10000)
    tag = next(t for t in admin.get("/receiver-tags").json() if t["name"] == name)
    assert tag["min_token_len"] == 12 and tag["require_secret"] == "pin" and tag["min_pin_len"] == 6
    # MB inputs are stored as bytes.
    assert tag["max_file_bytes_cap"] == 10 * _MB
    assert tag["max_total_bytes_cap"] == 100 * _MB


def test_admin_receivers_oversight_present(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_uploadlinks_settings(page)
    expect(page.locator("#rc-admin-links")).to_be_attached()
    expect(page.locator("#rc-admin-refresh")).to_be_visible()


def test_nav_and_create_modal_when_enabled(page: Page, admin, admin_creds):
    # Enable + ensure a receiver tag everyone can use, so the owner surface is live.
    admin.put("/settings", json={"public_receivers_enabled": True})
    tag_name = unique("Intake")
    admin.post("/receiver-tags", json={
        "name": tag_name, "min_token_len": 10, "max_total_bytes_cap": 100 * _MB,
        "auto_enroll_new_users": True, "is_active": True,
    })
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        # The nav item appears (revealed by refreshReceiverAvailability on login).
        nav = page.locator("#nav-uploadlinks")
        expect(nav).to_be_visible(timeout=10000)
        nav.click()
        expect(page.locator("#uploadlinks-section")).to_be_visible()
        # Open the create modal -> tag dropdown is populated + total-budget defaulted from the cap.
        page.click("#receiver-new-btn")
        expect(page.locator("#receiver-create-modal")).to_be_visible()
        # (<option>s are never "visible" to Playwright until the select is opened; assert on count.)
        assert page.locator("#rc-tag").evaluate("el => el.options.length") >= 1
        # The total-budget field is pre-filled from a tag's cap (each seeded/created tag caps it here).
        assert (page.locator("#rc-max-total-mb").input_value() or "").strip() != ""
    finally:
        admin.put("/settings", json={"public_receivers_enabled": False})
