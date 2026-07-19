"""UI — the Settings -> Sharing tab: the global enable switch + the Share Tags manager.

Verifies the tab renders, the master switch round-trips through PUT /settings, and the Tags manager
adds / edits / deactivates a tag through the /share-tags CRUD (authoritative check via the API).
Policy surface only — no share is created here.
"""
import pytest
from playwright.sync_api import Page, expect

from conftest import unique

pytestmark = pytest.mark.ui


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_sharing_settings(page: Page):
    page.click('.sidebar-item[data-section="settings"]')
    expect(page.locator("#settings-section")).to_be_visible()
    page.click('.tab-btn[data-tab="sharing"]')
    expect(page.locator("#settings-tab-sharing")).to_be_visible()


@pytest.fixture
def fresh_admin(admin):
    u = admin.create_user(role="admin")
    yield u
    admin.delete_user(u["id"])


def test_sharing_tab_renders_and_switch_round_trips(page: Page, admin, fresh_admin):
    admin.put("/settings", json={"sharing_enabled": False})
    try:
        _login(page, fresh_admin["_username"], fresh_admin["_password"])
        _open_sharing_settings(page)
        sw = page.locator("#setting-sharing-enabled")
        expect(sw).to_be_visible()
        expect(sw).not_to_be_checked()
        sw.check()
        with page.expect_response(
            lambda r: r.url.rstrip("/").endswith("/settings") and r.request.method == "PUT"
        ) as resp:
            page.click("#save-all-settings-btn")
        assert resp.value.ok, f"PUT /settings failed: {resp.value.status}"
        assert admin.get("/settings").json()["sharing_enabled"] is True
        # reload reflects it (load path re-reads the effective overlay)
        page.reload()
        _open_sharing_settings(page)
        expect(page.locator("#setting-sharing-enabled")).to_be_checked()
    finally:
        admin.put("/settings", json={"sharing_enabled": False})


def test_add_edit_deactivate_tag_via_ui(page: Page, admin, fresh_admin):
    name = unique("uiTag")
    # A department to exercise the create-allowlist picker (created before login so it loads into the picker).
    dept = admin.post("/groups", json={"name": unique("dept")}).json()
    try:
        _login(page, fresh_admin["_username"], fresh_admin["_password"])
        _open_sharing_settings(page)

        # --- Add a tag through the editor, including a department via the reused chip picker ---
        page.click("#share-tag-add-btn")
        expect(page.locator("#share-tag-editor")).to_be_visible()
        page.fill("#share-tag-name", name)
        page.fill("#share-tag-max-lifetime", "4320")
        page.fill("#share-tag-default-lifetime", "1440")
        page.fill("#share-tag-max-recipients-cap", "10")
        page.fill("#share-tag-max-recipients-default", "3")
        page.locator("#share-tag-aud-users").check()
        page.locator("#share-tag-aud-departments").check()
        page.locator("#share-tag-aud-anyone").uncheck()
        page.locator("#share-tag-auto-enroll").check()
        page.locator("#share-tag-dept-picker select.share-tag-dept-add").select_option(dept["id"])
        expect(page.locator("#share-tag-dept-picker .chip").first).to_be_visible()  # dept chip appears
        with page.expect_response(
            lambda r: r.url.rstrip("/").endswith("/share-tags") and r.request.method == "POST"
        ) as resp:
            page.click("#share-tag-save-btn")
        assert resp.value.ok, f"POST /share-tags failed: {resp.value.status}"

        # authoritative: the tag exists with the chosen policy AND the department allowlist persisted
        tag = next((t for t in admin.get("/share-tags").json() if t["name"] == name), None)
        assert tag is not None, "created tag not found via API"
        tid = tag["id"]
        assert tag["max_lifetime_minutes"] == 4320 and tag["max_recipients_cap"] == 10
        assert set(tag["allowed_audiences"]) == {"users", "departments"}
        assert tag["auto_enroll_new_users"] is True
        assert dept["id"] in tag["allowed_department_ids"], "department picker did not persist"
        expect(page.locator(f'#share-tags-list .share-tag-row[data-tag-id="{tid}"]')).to_be_visible()

        # --- Edit it: the editor repopulates the policy + the dept chip; change default recipients 3 -> 2 ---
        page.locator(f'.share-tag-row[data-tag-id="{tid}"]').get_by_role("button", name="Edit").click()
        expect(page.locator("#share-tag-editor")).to_be_visible()
        expect(page.locator("#share-tag-name")).to_have_value(name)
        expect(page.locator("#share-tag-max-lifetime")).to_have_value("4320")
        expect(page.locator("#share-tag-aud-users")).to_be_checked()
        expect(page.locator("#share-tag-aud-anyone")).not_to_be_checked()
        expect(page.locator("#share-tag-auto-enroll")).to_be_checked()
        expect(page.locator("#share-tag-dept-picker .chip").first).to_be_visible()  # dept chip restored on edit
        page.fill("#share-tag-max-recipients-default", "2")
        with page.expect_response(
            lambda r: f"/share-tags/{tid}" in r.url and r.request.method == "PATCH"
        ) as resp:
            page.click("#share-tag-save-btn")
        assert resp.value.ok, f"PATCH failed: {resp.value.status}"
        updated = next(t for t in admin.get("/share-tags").json() if t["id"] == tid)
        assert updated["max_recipients_default"] == 2
        assert dept["id"] in updated["allowed_department_ids"], "department allowlist lost on edit"

        # --- Deactivate (soft) then Reactivate (PATCH is_active) — both round-tripped ---
        with page.expect_response(
            lambda r: f"/share-tags/{tid}" in r.url and r.request.method == "DELETE"
        ) as resp:
            page.locator(f'.share-tag-row[data-tag-id="{tid}"]').get_by_role("button", name="Deactivate").click()
        assert resp.value.ok, f"DELETE failed: {resp.value.status}"
        assert next(t for t in admin.get("/share-tags").json() if t["id"] == tid)["is_active"] is False

        with page.expect_response(
            lambda r: f"/share-tags/{tid}" in r.url and r.request.method == "PATCH"
        ) as resp:
            page.locator(f'.share-tag-row[data-tag-id="{tid}"]').get_by_role("button", name="Reactivate").click()
        assert resp.value.ok, f"reactivate PATCH failed: {resp.value.status}"
        assert next(t for t in admin.get("/share-tags").json() if t["id"] == tid)["is_active"] is True
        expect(page.locator(f'.share-tag-row[data-tag-id="{tid}"]').get_by_role("button", name="Deactivate")).to_be_visible()
    finally:
        admin.delete(f"/groups/{dept['id']}")


def test_tag_validation_error_surfaced_in_ui(page: Page, admin, fresh_admin):
    # default recipients above the cap must be rejected by the backend and NOT create a tag
    name = unique("uiBad")
    _login(page, fresh_admin["_username"], fresh_admin["_password"])
    _open_sharing_settings(page)
    page.click("#share-tag-add-btn")
    page.fill("#share-tag-name", name)
    page.fill("#share-tag-max-recipients-cap", "2")
    page.fill("#share-tag-max-recipients-default", "9")
    with page.expect_response(
        lambda r: r.url.rstrip("/").endswith("/share-tags") and r.request.method == "POST"
    ) as resp:
        page.click("#share-tag-save-btn")
    assert resp.value.status == 400
    # the error is surfaced to the operator: the editor stays OPEN (not closed on failure) so they can fix it
    expect(page.locator("#share-tag-editor")).to_be_visible()
    # and no tag with that name was created
    assert not any(t["name"] == name for t in admin.get("/share-tags").json())
