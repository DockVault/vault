"""UI — a note sent to me appears LIVE (no page refresh) via the app-wide activity socket, and the
socket survives navigation (regression: it used to be closed on the first section change)."""
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


def test_sent_note_appears_live_after_navigation(page: Page, admin):
    recipient = admin.create_user(role="user")
    try:
        _login(page, recipient["_username"], recipient["_password"])
        # Navigate around FIRST — this is the regression guard: the activity socket used to be closed
        # on the first non-monitor navigation, which silently killed live notifications.
        page.click('.sidebar-item[data-section="vaults"]')
        page.wait_for_timeout(400)
        page.click('.sidebar-item[data-section="notes"]')
        expect(page.locator("#notes-section")).to_be_visible(timeout=10000)
        page.click('.tab-btn[data-notes-tab="received"]')
        # Nothing received yet.
        expect(page.locator("#notes-received-list .card")).to_have_count(0)

        # A note is sent to me from another account — I do NOT touch the browser.
        title = unique("LiveNote")
        note = admin.post("/notes", json={"title": title, "body": "live body"}).json()
        admin.post(f"/notes/{note['id']}/send",
                   json={"recipient_user_id": recipient["id"]}).raise_for_status()

        # It appears in my "Sent to me" list without any reload/navigation (WS push -> loadNotes).
        expect(page.locator("#notes-received-list .card", has_text=title)).to_be_visible(timeout=20000)
        # And the bell reflects it.
        expect(page.locator("#notif-badge")).to_be_visible(timeout=20000)
    finally:
        admin.delete_user(recipient["id"])
