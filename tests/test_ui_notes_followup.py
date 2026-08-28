"""UI — follow-up fixes: a long note no longer hides the sidebar; My-notes count badge; tab persists
across reload; the public-link creator disables 'never expires' under a capped tag and shows a working
Done; the Shared tab can view a link's snapshot."""
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


def _login(page, username, password):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_notes(page):
    page.click('.sidebar-item[data-section="notes"]')
    expect(page.locator("#notes-section")).to_be_visible(timeout=10000)


def _client_for(user):
    c = ApiClient(BASE_URL); c.login(user["_username"], user["_password"])
    return c


def test_long_note_does_not_hide_the_sidebar(page: Page, admin):
    # THE reported bug: a large note (5800+ chars) made the notes grid's max-content huge, which
    # collapsed the sidebar rail to a sliver. The rail must stay its normal width.
    user = admin.create_user(role="user")
    c = _client_for(user)
    c.post("/notes", json={"title": unique("Big"),
                           "body": ("The quick brown fox jumps over the lazy dog. " * 140)[:5800]}).raise_for_status()
    c.post("/notes", json={"title": unique("Two"), "body": "short"}).raise_for_status()
    try:
        _login(page, user["_username"], user["_password"])
        _open_notes(page)
        expect(page.locator("#notes-list .note-card").first).to_be_visible(timeout=10000)
        width = page.locator(".sidebar").evaluate("el => Math.round(el.getBoundingClientRect().width)")
        assert width >= 180, f"sidebar collapsed to {width}px with a long note present"
    finally:
        admin.delete_user(user["id"])


def test_my_notes_count_badge(page: Page, admin):
    user = admin.create_user(role="user")
    c = _client_for(user)
    c.post("/notes", json={"title": unique("A"), "body": "a"}).raise_for_status()
    c.post("/notes", json={"title": unique("B"), "body": "b"}).raise_for_status()
    try:
        _login(page, user["_username"], user["_password"])
        _open_notes(page)
        badge = page.locator("#notes-mine-count")
        expect(badge).to_be_visible(timeout=10000)
        expect(badge).to_have_text("2")
    finally:
        admin.delete_user(user["id"])


def test_notes_tab_persists_across_reload(page: Page, admin):
    user = admin.create_user(role="user")
    _client_for(user).post("/notes", json={"title": unique("N"), "body": "n"}).raise_for_status()
    try:
        _login(page, user["_username"], user["_password"])
        _open_notes(page)
        page.click('.tab-btn[data-notes-tab="received"]')
        page.reload()
        _open_notes(page)  # land back on notes after the reload
        expect(page.locator('.tab-btn[data-notes-tab="received"]')).to_have_class(
            re.compile(r"\bactive\b"), timeout=10000)
        expect(page.locator("#notes-tab-received")).to_be_visible()
    finally:
        admin.delete_user(user["id"])


def test_confidential_disables_never_expires(page: Page, admin, links_on):
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
        # Never-expires is shown but disabled (the tag caps the lifetime).
        expect(page.locator("#note-public-never")).to_be_visible()
        expect(page.locator("#note-public-never")).to_be_disabled()
        # An uncapped tag re-enables it.
        page.select_option("#note-public-tag", label="Open")
        expect(page.locator("#note-public-never")).to_be_enabled()
    finally:
        admin.delete_user(user["id"])


def test_public_result_has_done_and_no_dead_back(page: Page, admin, links_on):
    user = admin.create_user(role="user")
    c = _client_for(user)
    c.post("/notes", json={"title": unique("Pub"), "body": "b"}).raise_for_status()
    try:
        _login(page, user["_username"], user["_password"])
        _open_notes(page)
        page.locator("#notes-list .card").first.get_by_role("button", name="Share", exact=True).click()
        page.click("#note-share-public")
        page.select_option("#note-public-tag", label="Open")
        page.click("#note-public-create")
        expect(page.locator("#note-public-result")).to_be_visible(timeout=10000)
        # No dead Back button; a working Done that closes.
        assert page.locator("#note-public-back").count() == 0
        expect(page.locator("#note-public-done")).to_be_visible()
        page.click("#note-public-done")
        expect(page.locator("#note-public-link-modal")).to_be_hidden()
    finally:
        admin.delete_user(user["id"])


def test_shared_tab_view_shows_snapshot(page: Page, admin, links_on):
    user = admin.create_user(role="user")
    c = _client_for(user)
    note_id = c.post("/notes", json={"title": unique("Snap"), "body": "the frozen snapshot text"}).json()["id"]
    tag = next(t for t in admin.get("/note-link-tags").json() if t["name"] == "Open")
    c.post("/note-links", json={"note_id": note_id, "tag_id": tag["id"]}).raise_for_status()
    try:
        _login(page, user["_username"], user["_password"])
        _open_notes(page)
        page.click('.tab-btn[data-notes-tab="shared"]')
        card = page.locator("#notes-shared-list .note-link-card").first
        expect(card).to_be_visible(timeout=10000)
        card.get_by_role("button", name="View", exact=True).click()
        expect(page.locator("#note-link-snapshot-modal")).to_be_visible()
        expect(page.locator("#note-link-snapshot-body")).to_have_text("the frozen snapshot text")
    finally:
        admin.delete_user(user["id"])
