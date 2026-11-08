"""Notes search: a box over the note titles narrows every tab's list as you type, in the browser; an empty match
says so; Escape clears it."""
import pytest
from playwright.sync_api import Page, expect

from conftest import unique

pytestmark = pytest.mark.ui


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def test_the_box_narrows_my_notes_by_title(page: Page, admin, admin_creds):
    stamp = unique("")[1:9]
    made = [admin.post("/notes", json={"title": t, "body": "x"}).json() for t in
            (f"Budget {stamp}", f"Budget review {stamp}", f"Holiday plan {stamp}")]
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        page.click('.sidebar-item[data-section="notes"]')
        cards = page.locator("#notes-list .note-card")
        expect(cards.filter(has_text=stamp)).to_have_count(3, timeout=15000)
        box = page.locator("#notes-search")
        expect(box).to_be_visible()
        box.fill("budget")
        expect(cards.filter(has_text=stamp)).to_have_count(2)
        titles = sorted(t.strip() for t in page.locator("#notes-list .note-open-title").filter(has_text=stamp).all_inner_texts())
        assert titles == [f"Budget {stamp}", f"Budget review {stamp}"], titles
        expect(cards.filter(has_text="Holiday")).to_have_count(0)
        box.fill("zzz-no-such-note")
        expect(page.locator("#notes-list .notes-search-empty")).to_contain_text("No note title holds")
        box.press("Escape")
        expect(box).to_have_value("")
        expect(cards.filter(has_text=stamp)).to_have_count(3)
        # The other tabs are narrowed by the same box.
        box.fill(f"holiday plan {stamp}")
        page.click('[data-notes-tab="received"]')
        expect(page.locator("#notes-received-list")).to_be_visible()
        page.click('[data-notes-tab="mine"]')
        expect(cards).to_have_count(1)
    finally:
        for n in made:
            admin.delete(f"/notes/{n['id']}")
