"""UI — the Notes "Shared" tab (my public links, with revoke) and the admin "All public links"
oversight table in Settings -> Note Links (revoke any user's link)."""
import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.ui


@pytest.fixture
def links_on(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ("public_note_links_enabled", "public_note_link_user_cap")}
    admin.put("/settings", json={"public_note_links_enabled": True, "public_note_link_user_cap": 50})
    yield
    admin.put("/settings", json=snap)


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _client_for(user):
    c = ApiClient(BASE_URL); c.login(user["_username"], user["_password"])
    return c


def _mk_tag(admin, **over):
    payload = {"name": unique("nltag"), "min_token_len": 6, "auto_enroll_new_users": True}
    payload.update(over)
    r = admin.post("/note-link-tags", json=payload); r.raise_for_status()
    return r.json()


def test_shared_tab_lists_my_links_and_revokes(page: Page, admin, links_on):
    user = admin.create_user(role="user")
    c = _client_for(user)
    note_id = c.post("/notes", json={"title": unique("SharedNote"), "body": "b"}).json()["id"]
    tag = _mk_tag(admin)
    link = c.post("/note-links", json={"note_id": note_id, "tag_id": tag["id"]}).json()
    try:
        _login(page, user["_username"], user["_password"])
        page.click('.sidebar-item[data-section="notes"]')
        expect(page.locator("#notes-section")).to_be_visible(timeout=10000)
        page.click('.tab-btn[data-notes-tab="shared"]')
        card = page.locator("#notes-shared-list .note-link-card")
        expect(card).to_have_count(1)
        expect(card).to_contain_text(tag["name"])
        expect(card).to_contain_text("Active")
        # Revoke it (custom confirm dialog).
        card.get_by_role("button", name="Revoke", exact=True).click()
        page.click("#confirm-modal-confirm-btn")
        expect(page.locator("#notes-shared-list .note-link-card")).to_contain_text("Revoked", timeout=10000)
        # It really is dead: anonymous redeem 404s.
        assert admin.clone_anonymous().post(f"/note-links/{link['token']}/redeem", json={}).status_code == 404
    finally:
        admin.delete_user(user["id"])


def test_admin_all_links_table_revokes_any_users_link(page: Page, admin, admin_creds, links_on):
    owner = admin.create_user(role="user")
    oc = _client_for(owner)
    note_id = oc.post("/notes", json={"title": unique("AdminSeen"), "body": "b"}).json()["id"]
    tag = _mk_tag(admin)
    link = oc.post("/note-links", json={"note_id": note_id, "tag_id": tag["id"]}).json()
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        page.click('.sidebar-item[data-section="settings"]')
        page.click('#settings-section .tab-btn[data-tab="notelinks"]')
        expect(page.locator("#settings-tab-notelinks")).to_be_visible(timeout=10000)
        # The owner's link shows in the admin table, attributed to them.
        row = page.locator("#nl-admin-links tr", has_text=owner["_username"])
        expect(row).to_be_visible(timeout=10000)
        row.get_by_role("button", name="Revoke", exact=True).click()
        page.click("#confirm-modal-confirm-btn")
        # After revoke the link is dead.
        expect(page.locator("#nl-admin-summary")).to_be_visible(timeout=10000)
        assert admin.clone_anonymous().post(f"/note-links/{link['token']}/redeem", json={}).status_code == 404
    finally:
        admin.delete_user(owner["id"])
