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
        # Open the create modal -> a real tag reaches the dropdown, so Create is ENABLED (it is disabled
        # only in the no-usable-tag placeholder path). Selecting OUR tag defaults the budget to its cap.
        page.click("#receiver-new-btn")
        expect(page.locator("#receiver-create-modal")).to_be_visible()
        expect(page.locator("#rc-create")).to_be_enabled()
        expect(page.locator("#rc-tag option", has_text=tag_name)).to_have_count(1)
        page.select_option("#rc-tag", label=tag_name)
        expect(page.locator("#rc-max-total-mb")).to_have_value("100")  # from max_total_bytes_cap 100 MB
    finally:
        admin.put("/settings", json={"public_receivers_enabled": False})


def test_create_payload_converts_mb_to_bytes(page: Page, admin, admin_creds):
    # The most error-prone new logic: MB inputs -> bytes in the POST body. Intercept the POST so no real
    # receiver is created (there is NO DELETE /receivers to clean one up).
    import json as _json
    admin.put("/settings", json={"public_receivers_enabled": True})
    tag_name = unique("Payload")
    admin.post("/receiver-tags", json={"name": tag_name, "min_token_len": 10, "auto_enroll_new_users": True, "is_active": True})
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        expect(page.locator("#nav-uploadlinks")).to_be_visible(timeout=10000)
        page.locator("#nav-uploadlinks").click()
        expect(page.locator("#uploadlinks-section")).to_be_visible()

        captured = {}

        def _handle(route):
            req = route.request
            if req.method == "POST":
                captured["body"] = _json.loads(req.post_data or "{}")
                route.fulfill(status=200, content_type="application/json", body='{"token":"tk","url_path":"/u/tk"}')
            else:
                route.continue_()

        page.route("**/receivers", _handle)
        try:
            page.click("#receiver-new-btn")
            expect(page.locator("#receiver-create-modal")).to_be_visible()
            page.select_option("#rc-tag", label=tag_name)
            page.fill("#rc-max-file-mb", "10")
            page.fill("#rc-max-total-mb", "100")
            page.click("#rc-create")
            page.wait_for_timeout(1000)
            body = captured.get("body")
            assert body, "POST /receivers was never sent"
            assert body["max_total_bytes"] == 100 * _MB, body
            assert body["max_file_bytes"] == 10 * _MB, body
            assert body.get("tag_id")
        finally:
            page.unroute("**/receivers")
    finally:
        admin.put("/settings", json={"public_receivers_enabled": False})


def test_create_requires_total_budget(page: Page, admin, admin_creds):
    # Clearing the required total budget is refused client-side (no POST is sent).
    admin.put("/settings", json={"public_receivers_enabled": True})
    tag_name = unique("NoBudget")
    admin.post("/receiver-tags", json={"name": tag_name, "min_token_len": 10, "auto_enroll_new_users": True, "is_active": True})
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        expect(page.locator("#nav-uploadlinks")).to_be_visible(timeout=10000)
        page.locator("#nav-uploadlinks").click()
        expect(page.locator("#uploadlinks-section")).to_be_visible()
        page.click("#receiver-new-btn")
        expect(page.locator("#receiver-create-modal")).to_be_visible()
        page.select_option("#rc-tag", label=tag_name)
        page.fill("#rc-max-total-mb", "")  # clear the required budget
        page.click("#rc-create")
        err = page.locator("#rc-error")
        expect(err).to_be_visible()
        expect(err).to_contain_text("budget")
        # The form (not the "link ready" result) is still showing — nothing was created.
        expect(page.locator("#rc-result")).to_be_hidden()
    finally:
        admin.put("/settings", json={"public_receivers_enabled": False})
