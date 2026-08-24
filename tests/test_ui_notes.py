"""UI — the Notes page: create/favourite/edit, hide-text mask, send + receive, and temp exclusion."""
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


def _create_note(page: Page, title: str, body: str):
    page.click("#note-new-btn")
    expect(page.locator("#note-editor-modal")).to_be_visible()
    page.fill("#note-editor-title-input", title)
    page.fill("#note-editor-body-input", body)
    page.click("#note-editor-save")
    expect(page.locator("#notes-list", has_text=title)).to_be_visible(timeout=10000)


def test_create_favourite_and_edit_a_note(page: Page, admin, admin_creds):
    title = unique("uinote")
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_notes(page)
    _create_note(page, title, "first body")
    card = page.locator("#notes-list .card", has_text=title)
    # Favourite it.
    card.locator(".note-fav").click()
    expect(page.locator("#notes-list .card", has_text=title).locator(".note-fav.is-fav")).to_be_visible(timeout=10000)
    # Edit it.
    card.get_by_role("button", name="Edit", exact=True).click()
    expect(page.locator("#note-editor-modal")).to_be_visible()
    page.fill("#note-editor-body-input", "edited body")
    page.click("#note-editor-save")
    expect(page.locator("#notes-list .note-body", has_text="edited body")).to_be_visible(timeout=10000)


def test_hide_text_masks_the_body(page: Page, admin, admin_creds):
    title = unique("hidenote")
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_notes(page)
    _create_note(page, title, "secret content")
    card = page.locator("#notes-list .card", has_text=title)
    expect(card.locator(".note-body")).to_have_text("secret content")
    page.check("#notes-hide-toggle")
    # The body is masked; the literal text is gone and a "hidden" marker shows.
    expect(page.locator("#notes-list .note-body", has_text="secret content")).to_have_count(0)
    expect(card).to_contain_text("hidden")
    page.uncheck("#notes-hide-toggle")


def test_send_note_then_recipient_receives_and_adopts(page: Page, admin, admin_creds):
    recipient = admin.create_user(role="user")
    title = unique("sendnote")
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_notes(page)
    _create_note(page, title, "sent body")
    page.locator("#notes-list .card", has_text=title).get_by_role("button", name="Send", exact=True).click()
    expect(page.locator("#note-send-modal")).to_be_visible()
    page.fill("#note-send-search", recipient["_username"][:8])
    # Pick the recipient from the results, then send.
    page.locator("#note-send-results button", has_text=recipient["_username"]).first.click()
    expect(page.locator("#note-send-confirm")).to_be_enabled()
    page.click("#note-send-confirm")
    expect(page.locator("#note-send-modal")).to_be_hidden(timeout=10000)
    try:
        # Re-login as the recipient on the same tab; they see it under "Sent to me" and can adopt it.
        page.evaluate("() => { localStorage.clear(); sessionStorage.clear(); }")
        _login(page, recipient["_username"], recipient["_password"])
        _open_notes(page)
        page.click('.tab-btn[data-notes-tab="received"]')
        recv = page.locator("#notes-received-list .card", has_text=title)
        expect(recv).to_be_visible(timeout=10000)
        expect(recv).to_contain_text("Sent from")
        recv.get_by_role("button", name="Add to my notes").click()
        # It moves into "My notes".
        page.click('.tab-btn[data-notes-tab="mine"]')
        expect(page.locator("#notes-list .card", has_text=title)).to_be_visible(timeout=10000)
    finally:
        admin.delete_user(recipient["id"])


def test_temp_session_has_no_notes_nav(page: Page, admin):
    minted = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 30,
        "scope": {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": ["vault.see_info"], "temp": {}},
        "vault_access_mode": "all", "selected_vaults": []}).json()
    try:
        _login(page, minted["temp_username"], minted["credential"])
        nav = page.locator('.sidebar-item[data-section="notes"]')
        expect(nav).to_be_attached()
        expect(nav).to_be_hidden()
    finally:
        admin.post(f"/temp-creds/{minted['temp_username']}/delete")


def test_no_console_errors_on_notes(page: Page, admin, admin_creds):
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    _login(page, admin_creds["username"], admin_creds["password"])
    _open_notes(page)
    page.wait_for_timeout(800)
    assert not errors, f"console errors on the notes page: {errors}"
