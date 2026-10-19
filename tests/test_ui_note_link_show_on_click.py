"""UI — a note link with no secret shows its note only on a "Show note" click, in a real browser.

Loading the page (with its script, as a link preview that runs pages would) must spend nothing, and so
must a fetch of the page with no script at all. The click spends one view and shows the note. A link
capped at one view then shows the next visitor the used-up notice. A link with a password prompts and
unlocks as it always has.
"""
import pytest
import requests
from playwright.sync_api import Page, expect

from conftest import unique

pytestmark = pytest.mark.ui

USED_UP = "This link is not available. It may have expired, been used up, or been revoked."


@pytest.fixture
def links_on(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ("public_note_links_enabled", "public_note_link_user_cap")}
    admin.put("/settings", json={"public_note_links_enabled": True, "public_note_link_user_cap": 50})
    yield
    admin.put("/settings", json=snap)


def _one_view_link(admin, body, password=None):
    note_id = admin.post("/notes", json={"title": "One look", "body": body}).json()["id"]
    tag = admin.post("/note-link-tags", json={
        "name": unique("onelook"), "min_token_len": 12, "auto_enroll_new_users": True,
        "require_secret": "password" if password else "none", "password_min_len": 8, "max_uses_cap": 1})
    assert tag.status_code in (200, 201), tag.text
    payload = {"note_id": note_id, "tag_id": tag.json()["id"], "max_uses": 1}
    if password:
        payload["password"] = password
    r = admin.post("/note-links", json=payload)
    assert r.status_code == 200, r.text
    return r.json()


def _views(admin, link_id):
    card = next(l for l in admin.get("/note-links").json()["links"] if l["id"] == link_id)
    return card["view_count"], card["use_count"], card["status"]


def test_loading_spends_nothing_and_the_click_spends_one_view(page: Page, admin, base_url, links_on, browser):
    link = _one_view_link(admin, "line one\nline two")
    # A fetch of the page with no script, as a preview service or a scanner makes.
    for agent in ("Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)", "facebookexternalhit/1.1"):
        assert requests.get(f"{base_url}/l/{link['token']}", headers={"User-Agent": agent}, timeout=30).status_code == 200
    # The page itself, script and all: it offers the button and waits.
    page.goto(f"/l/{link['token']}")
    expect(page.locator("#reveal-btn")).to_have_text("Show note", timeout=15000)
    expect(page.locator("#content")).to_be_hidden()
    page.wait_for_timeout(1500)
    assert _views(admin, link["id"]) == (0, 0, "active")
    # A reload is another visit, and spends nothing either.
    page.reload()
    expect(page.locator("#reveal-btn")).to_be_visible(timeout=15000)
    assert _views(admin, link["id"]) == (0, 0, "active")

    page.click("#reveal-btn")
    expect(page.locator("#content")).to_be_visible(timeout=15000)
    expect(page.locator("#note-title")).to_have_text("One look")
    expect(page.locator("#note-body")).to_have_text("line one\nline two")
    expect(page.locator("#reveal")).to_be_hidden()
    assert _views(admin, link["id"]) == (1, 1, "exhausted")

    # The next visitor, in a browser of their own, finds the link used up.
    other = browser.new_context(base_url=base_url)
    try:
        visitor = other.new_page()
        visitor.goto(f"/l/{link['token']}")
        expect(visitor.locator("#notice")).to_have_text(USED_UP, timeout=15000)
        expect(visitor.locator("#reveal")).to_be_hidden()
        expect(visitor.locator("#content")).to_be_hidden()
    finally:
        other.close()
    assert _views(admin, link["id"]) == (1, 1, "exhausted")


def test_a_password_link_prompts_and_unlocks_as_before(page: Page, admin, links_on):
    link = _one_view_link(admin, "the protected body", password="hunter2x9")
    page.goto(f"/l/{link['token']}")
    expect(page.locator("#secret-form")).to_be_visible(timeout=15000)
    expect(page.locator("#reveal")).to_be_hidden()
    assert _views(admin, link["id"]) == (0, 0, "active")
    page.fill("#secret-input", "hunter2x9")
    page.click("#secret-submit")
    expect(page.locator("#content")).to_be_visible(timeout=15000)
    expect(page.locator("#note-body")).to_have_text("the protected body")
    assert _views(admin, link["id"]) == (1, 1, "exhausted")
