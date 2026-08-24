"""UI — the note read modal: Open renders a note with a left rail to switch notes; a received note
can be Previewed before adopting."""
import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.ui


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_notes(page: Page):
    page.click('.sidebar-item[data-section="notes"]')
    expect(page.locator("#notes-section")).to_be_visible(timeout=10000)


def _client_for(user):
    c = ApiClient(BASE_URL)
    c.login(user["_username"], user["_password"])
    return c


def _share_tag(admin):
    r = admin.post("/share-tags", json={"name": unique("nvtag"), "auto_enroll_new_users": True,
                                        "allowed_audiences": ["users"], "max_recipients_cap": 10})
    r.raise_for_status()
    return r.json()


def test_open_renders_note_and_rail_switches(page: Page, admin):
    user = admin.create_user(role="user")
    c = _client_for(user)
    a = c.post("/notes", json={"title": unique("Alpha"), "body": "alpha body text"}).json()
    b = c.post("/notes", json={"title": unique("Beta"), "body": "beta body text"}).json()
    try:
        _login(page, user["_username"], user["_password"])
        _open_notes(page)
        # Open note A.
        page.locator("#notes-list .card", has_text=a["title"]).get_by_role("button", name="Open").click()
        expect(page.locator("#note-view-modal")).to_be_visible()
        expect(page.locator("#note-view-title")).to_have_text(a["title"])
        expect(page.locator("#note-view-content-body")).to_have_text("alpha body text")
        # Rail lists both notes; the current one is active.
        expect(page.locator("#note-view-rail .note-view-rail-item")).to_have_count(2)
        expect(page.locator("#note-view-rail .note-view-rail-item.active")).to_have_text(a["title"])
        # Switch to B via the rail — no close, body updates.
        page.locator("#note-view-rail .note-view-rail-item", has_text=b["title"]).click()
        expect(page.locator("#note-view-title")).to_have_text(b["title"])
        expect(page.locator("#note-view-content-body")).to_have_text("beta body text")
    finally:
        admin.delete_user(user["id"])


def test_preview_received_note_then_adopt(page: Page, admin):
    sharing_before = admin.get("/settings").json().get("sharing_enabled", False)
    admin.put("/settings", json={"sharing_enabled": True}).raise_for_status()
    recipient = admin.create_user(role="user")
    note = admin.post("/notes", json={"title": unique("Shared"), "body": "secret shared body"}).json()
    try:
        admin.post(f"/notes/{note['id']}/send",
                   json={"recipient_user_id": recipient["id"]}).raise_for_status()
        _login(page, recipient["_username"], recipient["_password"])
        _open_notes(page)
        page.click('.tab-btn[data-notes-tab="received"]')
        card = page.locator("#notes-received-list .card", has_text=note["title"])
        expect(card).to_be_visible(timeout=10000)
        # Preview shows the body BEFORE adopting.
        card.get_by_role("button", name="Preview").click()
        expect(page.locator("#note-view-modal")).to_be_visible()
        expect(page.locator("#note-view-content-body")).to_have_text("secret shared body")
        # Adopt from the modal.
        page.locator("#note-view-actions").get_by_role("button", name="Add to my notes").click()
        page.click('.tab-btn[data-notes-tab="mine"]')
        expect(page.locator("#notes-list .card", has_text=note["title"])).to_be_visible(timeout=10000)
    finally:
        admin.delete_user(recipient["id"])
        admin.put("/settings", json={"sharing_enabled": bool(sharing_before)})


def test_no_console_errors_opening_a_note(page: Page, admin):
    user = admin.create_user(role="user")
    c = _client_for(user)
    c.post("/notes", json={"title": unique("Solo"), "body": "solo"}).raise_for_status()
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    try:
        _login(page, user["_username"], user["_password"])
        _open_notes(page)
        page.locator("#notes-list .card").first.get_by_role("button", name="Open").click()
        expect(page.locator("#note-view-modal")).to_be_visible()
        page.wait_for_timeout(500)
        assert not errors, f"console errors opening a note: {errors}"
    finally:
        admin.delete_user(user["id"])
