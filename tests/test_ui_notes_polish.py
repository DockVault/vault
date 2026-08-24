"""UI — notes-card polish: the whole tile opens the note (no Open button), action buttons don't
trigger open, and long note text wraps inside the card instead of overflowing."""
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


def test_clicking_tile_body_opens_note_and_no_open_button(page: Page, admin):
    user = admin.create_user(role="user")
    c = _client_for(user)
    c.post("/notes", json={"title": unique("Tile"), "body": "clickable tile body"}).raise_for_status()
    try:
        _login(page, user["_username"], user["_password"])
        _open_notes(page)
        card = page.locator("#notes-list .card").first
        # There is no dedicated Open button any more.
        expect(card.get_by_role("button", name="Open")).to_have_count(0)
        # Clicking the body (not a button) opens the read modal.
        card.locator(".note-body").click()
        expect(page.locator("#note-view-modal")).to_be_visible()
        expect(page.locator("#note-view-content-body")).to_have_text("clickable tile body")
    finally:
        admin.delete_user(user["id"])


def test_action_button_does_not_open_the_view_modal(page: Page, admin):
    user = admin.create_user(role="user")
    c = _client_for(user)
    c.post("/notes", json={"title": unique("Memo"), "body": "body"}).raise_for_status()
    try:
        _login(page, user["_username"], user["_password"])
        _open_notes(page)
        card = page.locator("#notes-list .card").first
        # Clicking Edit must NOT open the read modal (it opens the editor instead).
        card.get_by_role("button", name="Edit", exact=True).click()
        expect(page.locator("#note-view-modal")).to_be_hidden()
    finally:
        admin.delete_user(user["id"])


def test_long_note_text_wraps_inside_the_card(page: Page, admin):
    user = admin.create_user(role="user")
    c = _client_for(user)
    # A long UNBROKEN string is the classic horizontal-overflow trigger.
    c.post("/notes", json={"title": unique("Long"), "body": "x" * 400}).raise_for_status()
    try:
        _login(page, user["_username"], user["_password"])
        _open_notes(page)
        card = page.locator("#notes-list .card").first
        expect(card).to_be_visible(timeout=10000)
        overflow = card.evaluate("el => el.scrollWidth - el.clientWidth")
        assert overflow <= 1, f"card overflows horizontally by {overflow}px (text not wrapping)"
    finally:
        admin.delete_user(user["id"])
