"""UI — a password-protected public file link capped at one download delivers that download in a real
browser, and the page says it is used up afterwards.

The recipient opens the link, enters the password, sees the file and clicks Download, as anyone sent
such a link would. The saved file must be the exact bytes uploaded. A reload then shows the notice a
used-up link shows, and the owner's card counts one use and one completed download.
"""
import os
import time

import pytest
from playwright.sync_api import Page, expect

from conftest import unique

pytestmark = pytest.mark.ui

PASSWORD = "Recipient-Pass9"
USED_UP = "This link is not available. It may have expired, been used up, or been revoked."


@pytest.fixture
def files_enabled(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ("public_file_links_enabled", "public_note_link_user_cap")}
    r = admin.put("/settings", json={"public_file_links_enabled": True, "public_note_link_user_cap": 100})
    assert r.status_code == 200, r.text
    yield
    admin.put("/settings", json=snap)


def _one_download_password_link(admin, vault_id, content):
    r = admin.post(f"/vaults/{vault_id}/files",
                   files=[("files", ("contract.pdf", content, "application/pdf"))])
    assert r.status_code in (200, 201), r.text
    file_id = next(it["id"] for it in admin.get(f"/vaults/{vault_id}/files").json()["items"]
                   if it.get("name") == "contract.pdf")
    tag = admin.post("/note-link-tags", json={
        "name": unique("uicap"), "min_token_len": 20, "auto_enroll_new_users": True,
        "allowed_targets": ["note", "file", "folder"], "default_ttl_hours": 24, "max_ttl_hours": 24,
        "require_secret": "password", "password_min_len": 8, "password_require_alnum": True,
        "max_uses_cap": 1})
    assert tag.status_code in (200, 201), tag.text
    link = admin.post("/public-links", json={
        "vault_id": vault_id, "target_type": "file", "target_file_id": file_id,
        "tag_id": tag.json()["id"], "ttl_hours": 1, "max_uses": 1,
        "password": PASSWORD, "secret_kind": "password"})
    assert link.status_code == 200, link.text
    return link.json()


def _card(admin, link_id):
    deadline = time.monotonic() + 10
    while True:
        card = next(l for l in admin.get("/public-links").json()["links"] if l["id"] == link_id)
        if card["download_count"] >= 1 or time.monotonic() > deadline:
            return card
        time.sleep(0.2)


@pytest.mark.timeout(180)
def test_the_download_button_delivers_a_one_download_link_and_then_it_is_used_up(
        page: Page, admin, files_enabled, tmp_path):
    vault = admin.create_vault(name=unique("uicap"))
    try:
        content = os.urandom(200_000)
        link = _one_download_password_link(admin, vault["id"], content)

        page.goto(f"/p/{link['token']}")
        expect(page.locator("#secret-form")).to_be_visible(timeout=15000)
        page.fill("#secret-input", PASSWORD)
        page.click("#secret-submit")
        expect(page.locator("#content")).to_be_visible(timeout=15000)
        expect(page.locator("#title")).to_have_text("contract.pdf")

        with page.expect_download(timeout=30000) as download:
            page.click("#listing button")
        saved = tmp_path / "saved.pdf"
        download.value.save_as(saved)
        assert download.value.suggested_filename == "contract.pdf"
        assert saved.read_bytes() == content
        expect(page.locator("#dl-error")).to_be_hidden()

        card = _card(admin, link["id"])
        assert (card["use_count"], card["download_count"], card["status"]) == (1, 1, "exhausted"), card

        page.reload()
        expect(page.locator("#notice")).to_have_text(USED_UP, timeout=15000)
        expect(page.locator("#content")).to_be_hidden()
        expect(page.locator("#secret-form")).to_be_hidden()
    finally:
        admin.delete_vault(vault["id"])
