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
    # initSettings deliberately keeps Save disabled while /settings, /groups, and the other
    # asynchronous form dependencies populate controls. Do not mutate a switch or open a picker
    # until that boundary is complete, or the late load can overwrite the test's interaction.
    save = page.locator("#save-all-settings-btn")
    expect(save).to_have_attribute("data-settings-ready", "true")
    expect(save).to_be_enabled()


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

    # The editor validates this combination itself, so the save never reaches the network. Assert
    # the request is NOT sent rather than waiting for a 400 that can no longer arrive — an earlier
    # version of this test expected the round-trip and hung for the full 30s response timeout.
    sent = []
    page.on("request", lambda r: sent.append(r) if (
        r.url.rstrip("/").endswith("/share-tags") and r.method == "POST") else None)
    page.click("#share-tag-save-btn")

    # the error is surfaced to the operator: the editor stays OPEN (not closed on failure) so they can fix it
    error = page.locator("#share-tag-editor-error")
    expect(error).to_be_visible()
    expect(error).to_contain_text("cannot exceed")
    expect(page.locator("#share-tag-editor")).to_be_visible()
    assert not sent, "an invalid default/cap pair was still POSTed to the server"
    # and no tag with that name was created
    assert not any(t["name"] == name for t in admin.get("/share-tags").json())

    # The client-side guard is a convenience, not the boundary: the same payload must still be
    # refused by the API for any caller that skips the browser.
    direct = admin.post("/share-tags", json={
        "name": name, "max_recipients_cap": 2, "max_recipients_default": 9,
    })
    assert direct.status_code == 400, direct.text
    assert not any(t["name"] == name for t in admin.get("/share-tags").json())


def test_user_allowlist_and_blocklist_pickers(page: Page, admin, fresh_admin):
    # two users to find through the /users/search-backed pickers
    u_allow = admin.create_user(role="user")
    u_block = admin.create_user(role="user")
    name = unique("uiUsers")
    try:
        _login(page, fresh_admin["_username"], fresh_admin["_password"])
        _open_sharing_settings(page)
        page.click("#share-tag-add-btn")
        expect(page.locator("#share-tag-editor")).to_be_visible()
        page.fill("#share-tag-name", name)

        # allowed users: search by username -> click the result -> a chip appears
        page.fill("#share-tag-allow-user-search", u_allow["_username"])
        allow_row = page.locator("#share-tag-allow-user-results").get_by_role("option", name=u_allow["_username"])
        expect(allow_row).to_be_visible(timeout=8000)
        allow_row.click()
        expect(page.locator("#share-tag-allow-user-chips .chip")).to_have_count(1)

        # blocked users: same flow, independent picker
        page.fill("#share-tag-block-user-search", u_block["_username"])
        block_row = page.locator("#share-tag-block-user-results").get_by_role("option", name=u_block["_username"])
        expect(block_row).to_be_visible(timeout=8000)
        block_row.click()
        expect(page.locator("#share-tag-block-user-chips .chip")).to_have_count(1)

        # mutual exclusion: adding the blocked user to the ALLOW picker MOVES it (removed from block)
        page.fill("#share-tag-allow-user-search", u_block["_username"])
        page.locator("#share-tag-allow-user-results").get_by_role("option", name=u_block["_username"]).click()
        expect(page.locator("#share-tag-block-user-chips .chip")).to_have_count(0)
        expect(page.locator("#share-tag-allow-user-chips .chip")).to_have_count(2)
        # move it back to blocked for the persistence assertions below
        page.fill("#share-tag-block-user-search", u_block["_username"])
        page.locator("#share-tag-block-user-results").get_by_role("option", name=u_block["_username"]).click()
        expect(page.locator("#share-tag-block-user-chips .chip")).to_have_count(1)
        expect(page.locator("#share-tag-allow-user-chips .chip")).to_have_count(1)

        with page.expect_response(
            lambda r: r.url.rstrip("/").endswith("/share-tags") and r.request.method == "POST"
        ) as resp:
            page.click("#share-tag-save-btn")
        assert resp.value.ok, f"POST failed: {resp.value.status}"

        tag = next((t for t in admin.get("/share-tags").json() if t["name"] == name), None)
        assert tag is not None
        tid = tag["id"]
        assert u_allow["id"] in tag["allowed_user_ids"], "allowed user not persisted"
        assert u_block["id"] in tag["blocked_user_ids"], "blocked user not persisted"

        # reopen (edit): the stored ids resolve to usernames in the chips, and PATCH preserves them
        page.locator(f'.share-tag-row[data-tag-id="{tid}"]').get_by_role("button", name="Edit").click()
        expect(page.locator("#share-tag-editor")).to_be_visible()
        expect(page.locator("#share-tag-allow-user-chips")).to_contain_text(u_allow["_username"])
        expect(page.locator("#share-tag-block-user-chips")).to_contain_text(u_block["_username"])
        with page.expect_response(
            lambda r: f"/share-tags/{tid}" in r.url and r.request.method == "PATCH"
        ) as resp:
            page.click("#share-tag-save-btn")
        assert resp.value.ok
        after = next(t for t in admin.get("/share-tags").json() if t["id"] == tid)
        assert u_allow["id"] in after["allowed_user_ids"] and u_block["id"] in after["blocked_user_ids"]
    finally:
        admin.delete_user(u_allow["id"])
        admin.delete_user(u_block["id"])
