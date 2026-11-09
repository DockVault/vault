"""The page of a file link or note link with a PIN shows the owner's message only after the right PIN.

Before the PIN, and after a wrong one, the page holds the prompt and nothing of the message; the right PIN
opens the link and the message with it.
"""
import pytest
from playwright.sync_api import Page, expect

from conftest import unique

pytestmark = pytest.mark.ui

MESSAGE = "Only for the one who has the code."


@pytest.fixture
def links(admin):
    before = admin.get("/settings").json()
    admin.put("/settings", json={"public_file_links_enabled": True, "public_note_links_enabled": True})
    v = admin.create_vault(name=unique("pinpage"))
    try:
        fid = admin.post(f"/vaults/{v['id']}/files", files=[("files", ("a.txt", b"x", "text/plain"))]).json()["files"][0]["id"]
        tag = admin.post("/note-link-tags", json={"name": unique("pp"), "auto_enroll_new_users": True,
                                                  "allowed_targets": ["file", "folder", "note"]})
        assert tag.status_code == 200, tag.text
        public = admin.post("/public-links", json={
            "vault_id": v["id"], "target_type": "file", "target_file_id": fid, "tag_id": tag.json()["id"],
            "secret_kind": "pin", "pin": "4821", "message": MESSAGE})
        assert public.status_code == 200, public.text
        note = admin.post("/notes", json={"title": unique("n"), "body": "hello"}).json()
        noted = admin.post("/note-links", json={"note_id": note["id"], "tag_id": tag.json()["id"],
                                                "secret_kind": "pin", "pin": "4821", "message": MESSAGE})
        assert noted.status_code in (200, 201), noted.text
        yield {"p": public.json()["token"], "l": noted.json()["token"]}
    finally:
        admin.delete_vault(v["id"])
        admin.put("/settings", json={"public_file_links_enabled": before.get("public_file_links_enabled"),
                                     "public_note_links_enabled": before.get("public_note_links_enabled")})


@pytest.mark.parametrize("prefix", ["p", "l"])
def test_the_page_shows_the_message_only_after_the_right_pin(page: Page, links, prefix):
    page.goto(f"/{prefix}/{links[prefix]}")
    expect(page.locator("#secret-form")).to_be_visible(timeout=15000)
    expect(page.locator("#owner-message")).to_be_hidden()
    assert MESSAGE not in page.content()
    page.fill("#secret-input", "0000")
    page.click("#secret-submit")
    expect(page.locator("#secret-error")).to_be_visible(timeout=10000)
    assert MESSAGE not in page.content()
    page.fill("#secret-input", "4821")
    page.click("#secret-submit")
    expect(page.locator("#owner-message")).to_have_text(MESSAGE, timeout=15000)
