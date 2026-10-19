"""UI — the link cards say what each public file link delivered.

Four links, each brought to its state the way a recipient would: one never opened, one opened for a
download that never came (redeemed, and nothing downloaded), one downloaded, and one capped at three
that was downloaded twice and opened once more without a download. The owner's "My public links"
dialog and the administrators' oversight list must each word the four apart, a used link that
delivered nothing distinctly from one that delivered its file.
"""
import os

import pytest
import requests
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


@pytest.fixture
def files_enabled(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ("public_file_links_enabled", "public_note_link_user_cap")}
    r = admin.put("/settings", json={"public_file_links_enabled": True, "public_note_link_user_cap": 100})
    assert r.status_code == 200, r.text
    yield
    admin.put("/settings", json=snap)


def _link(admin, vault_id, file_id, cap, tag_name):
    tag = admin.post("/note-link-tags", json={
        "name": tag_name, "min_token_len": 20, "auto_enroll_new_users": True,
        "allowed_targets": ["note", "file", "folder"], "default_ttl_hours": 24, "max_ttl_hours": 24,
        "max_uses_cap": cap, "require_secret": "none"})
    assert tag.status_code in (200, 201), tag.text
    r = admin.post("/public-links", json={"vault_id": vault_id, "target_type": "file", "target_file_id": file_id,
                                          "tag_id": tag.json()["id"], "ttl_hours": 1, "max_uses": cap})
    assert r.status_code == 200, r.text
    return r.json()


def _use(base_url, link, file_id, download):
    redeemed = requests.post(f"{base_url}/public-links/{link['token']}/redeem", json={}, timeout=30)
    assert redeemed.status_code == 200, redeemed.text
    if download:
        got = requests.get(f"{base_url}/public-links/{link['token']}/download/{file_id}",
                           headers={"X-Download-Grant": redeemed.json()["grant"]}, timeout=60)
        assert got.status_code == 200


# tag-name suffix -> (cap, what happens to the link, the Uses cell's count, its wording)
CARDS = {
    "never": (1, [], "0/1", "Not used yet"),
    "nothing": (1, [False], "1/1", "Used, nothing downloaded"),
    "delivered": (1, [True], "1/1", "Downloaded"),
    "partly": (3, [True, True, False], "3/3", "Used 3 times, 2 downloaded"),
}


def _cells(table, tags):
    """The Uses cell of each row whose type cell names one of `tags`: {tag: (count, wording, state)}."""
    out = {}
    for tag in tags:
        # The tag's name is the cell's span (beside an optional colour dot), matched whole.
        row = table.locator("tbody tr", has=table.page.locator(f"td.nl-tag-cell > span:text-is('{tag}')"))
        expect(row).to_have_count(1, timeout=10000)
        cell = row.locator("td.pfl-uses")
        out[tag] = (cell.locator(".pfl-uses-count").inner_text(), cell.locator(".pfl-delivery").inner_text(),
                    cell.locator(".pfl-delivery").get_attribute("data-delivery"))
    return out


@pytest.mark.timeout(240)
def test_the_cards_word_each_link_by_what_it_delivered(page: Page, admin, admin_creds, base_url, files_enabled):
    vault = admin.create_vault(name=unique("cards"))
    try:
        content = os.urandom(20_000)
        up = admin.post(f"/vaults/{vault['id']}/files", files=[("files", ("card.bin", content, "application/octet-stream"))])
        assert up.status_code in (200, 201), up.text
        file_id = next(it["id"] for it in admin.get(f"/vaults/{vault['id']}/files").json()["items"]
                       if it.get("name") == "card.bin")
        prefix = unique("card")
        tags = {}
        for suffix, (cap, uses, _count, _text) in CARDS.items():
            tags[suffix] = f"{prefix}-{suffix}"
            link = _link(admin, vault["id"], file_id, cap, tags[suffix])
            for download in uses:
                _use(base_url, link, file_id, download)

        _login(page, admin_creds["username"], admin_creds["password"])
        # The owner's own list ("My public links").
        page.evaluate("openPublicLinksManage()")
        mine = page.locator("#pflm-list table")
        expect(mine).to_be_visible(timeout=15000)
        expect(mine.locator("thead th").nth(5)).to_have_text("Uses")
        owner = _cells(mine, tags.values())
        page.evaluate("closeModal()")
        # The administrators' oversight list (Settings, Public Links).
        page.click('.sidebar-item[data-section="settings"]')
        page.click('#settings-section .tab-btn[data-tab="notelinks"]')
        oversight_table = page.locator("#pfl-admin-links table")
        expect(oversight_table).to_be_visible(timeout=15000)
        oversight = _cells(oversight_table, tags.values())

        for suffix, (_cap, _uses, count, text) in CARDS.items():
            assert owner[tags[suffix]][:2] == (count, text), (suffix, owner[tags[suffix]])
            assert oversight[tags[suffix]][:2] == (count, text), (suffix, oversight[tags[suffix]])
        assert owner[tags["nothing"]][2] == "nothing" and owner[tags["delivered"]][2] == "downloaded"
    finally:
        admin.delete_vault(vault["id"])
