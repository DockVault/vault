"""UI — the note Share modal: a two-tile chooser (Send to a member / Public link), the public-link
creator enforcing the tag FLOOR (tighten-only), and a created link surfaced for copying."""
import re

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


def _open_notes(page: Page):
    page.click('.sidebar-item[data-section="notes"]')
    expect(page.locator("#notes-section")).to_be_visible(timeout=10000)


def _client_for(user):
    c = ApiClient(BASE_URL); c.login(user["_username"], user["_password"])
    return c


def test_share_button_opens_chooser_with_both_tiles(page: Page, admin, links_on):
    user = admin.create_user(role="user")
    c = _client_for(user)
    c.post("/notes", json={"title": unique("Share"), "body": "b"}).raise_for_status()
    try:
        _login(page, user["_username"], user["_password"])
        _open_notes(page)
        page.locator("#notes-list .card").first.get_by_role("button", name="Share", exact=True).click()
        expect(page.locator("#note-share-modal")).to_be_visible()
        expect(page.locator("#note-share-internal")).to_be_visible()
        expect(page.locator("#note-share-public")).to_be_visible()
        # Internal tile opens the send-a-copy flow.
        page.click("#note-share-internal")
        expect(page.locator("#note-send-modal")).to_be_visible()
        expect(page.locator("#note-share-modal")).to_be_hidden()
    finally:
        admin.delete_user(user["id"])


def test_public_tile_creates_a_link(page: Page, admin, links_on):
    user = admin.create_user(role="user")
    c = _client_for(user)
    c.post("/notes", json={"title": unique("Pub"), "body": "public snapshot body"}).raise_for_status()
    try:
        _login(page, user["_username"], user["_password"])
        _open_notes(page)
        page.locator("#notes-list .card").first.get_by_role("button", name="Share", exact=True).click()
        page.click("#note-share-public")
        expect(page.locator("#note-public-link-modal")).to_be_visible()
        # Pick the "Open" type (short, no secret) and create.
        page.select_option("#note-public-tag", label="Open")
        expect(page.locator("#note-public-tag-floor")).to_contain_text("at least")
        # Floor drives the min link length.
        assert page.locator("#note-public-token-len").get_attribute("min") == "6"
        page.click("#note-public-create")
        # The created link URL appears for copying and points at /l/.
        expect(page.locator("#note-public-result")).to_be_visible(timeout=10000)
        val = page.locator("#note-public-link-value").input_value()
        assert re.search(r"/l/[0-9A-Za-z]+$", val), val
    finally:
        admin.delete_user(user["id"])


def test_public_tile_enforces_secret_floor(page: Page, admin, links_on):
    # The "Confidential" seeded tag mandates a password; the Protect-with control must not offer a
    # weaker option (tighten-only).
    user = admin.create_user(role="user")
    c = _client_for(user)
    c.post("/notes", json={"title": unique("Conf"), "body": "b"}).raise_for_status()
    try:
        _login(page, user["_username"], user["_password"])
        _open_notes(page)
        page.locator("#notes-list .card").first.get_by_role("button", name="Share", exact=True).click()
        page.click("#note-share-public")
        expect(page.locator("#note-public-link-modal")).to_be_visible()
        page.select_option("#note-public-tag", label="Confidential")
        # Secret defaults to the floor (password) and weaker options are disabled.
        expect(page.locator("#note-public-secret")).to_have_value("password")
        assert page.locator('#note-public-secret option[value="none"]').is_disabled()
        assert page.locator('#note-public-secret option[value="pin"]').is_disabled()
        expect(page.locator("#note-public-password-group")).to_be_visible()
    finally:
        admin.delete_user(user["id"])


def test_public_tile_hidden_when_feature_off(page: Page, admin):
    before = admin.get("/settings").json().get("public_note_links_enabled")
    admin.put("/settings", json={"public_note_links_enabled": False})
    user = admin.create_user(role="user")
    c = _client_for(user)
    c.post("/notes", json={"title": unique("Off"), "body": "b"}).raise_for_status()
    try:
        _login(page, user["_username"], user["_password"])
        _open_notes(page)
        page.locator("#notes-list .card").first.get_by_role("button", name="Share", exact=True).click()
        expect(page.locator("#note-share-modal")).to_be_visible()
        # Public tile is disabled + the reason is shown; Internal still works.
        expect(page.locator("#note-share-public")).to_be_disabled()
        expect(page.locator("#note-share-public-disabled")).to_be_visible()
        expect(page.locator("#note-share-internal")).to_be_enabled()
    finally:
        admin.delete_user(user["id"])
        admin.put("/settings", json={"public_note_links_enabled": bool(before)})
