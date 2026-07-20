"""UI — the in-vault create-share modal (creator).

Opens the modal from the vault toolbar (whole-vault share) and from a file row, drives the
tag → audience flow, creates a share via POST /shares, and checks the show-once link appears +
a share row exists in the creator's list.
"""
import pytest
from playwright.sync_api import Page, expect

from conftest import ApiClient, unique

pytestmark = pytest.mark.ui


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


@pytest.fixture
def fresh_admin(admin):
    u = admin.create_user(role="admin")
    c = ApiClient()
    c.login(u["_username"], u["_password"])
    u["_client"] = c
    yield u
    admin.delete_user(u["id"])


def _make_tag(admin):
    name = unique("crtag")
    r = admin.post("/share-tags", json={
        "name": name, "auto_enroll_new_users": True,
        "allowed_audiences": ["anyone_internal", "users"],
        "allow_view_only": True, "allow_custom": True,
        "max_recipients_cap": 10, "max_downloads_cap": 100})
    assert r.status_code == 200, r.text
    return name


def _open_vault(page: Page, vault_id: str):
    page.click('.sidebar-item[data-section="vaults"]')
    card = page.locator(f'.vault-card[data-vault-id="{vault_id}"]')
    expect(card).to_be_visible(timeout=10000)
    card.locator(".open-vault-btn").click()
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)


def _create_in_modal(page: Page, tag_name: str, fc, vault_id: str):
    modal = page.locator("#create-share-modal")
    expect(modal).to_be_visible(timeout=10000)
    # wait for the tag options to load, then pick our tag + the link audience
    expect(page.locator(f'#share-tag-select option', has_text=tag_name)).to_have_count(1, timeout=10000)
    page.select_option("#share-tag-select", label=tag_name)
    page.select_option("#share-audience-select", "anyone_internal")
    with page.expect_response(
        lambda r: r.url.rstrip("/").endswith("/shares") and r.request.method == "POST"
    ) as resp:
        page.click("#share-create-submit")
    assert resp.value.ok, f"POST /shares failed: {resp.value.status}"
    expect(page.locator("#share-create-result")).to_be_visible(timeout=10000)
    link = page.locator("#share-link-value").inner_text().strip()
    assert len(link) > 10, f"show-once link looks wrong: {link!r}"
    assert any(s["vault_id"] == vault_id for s in fc.get("/shares").json())


def test_create_whole_vault_share_from_toolbar(page: Page, admin, fresh_admin):
    admin.put("/settings", json={"sharing_enabled": True})
    tag_name = _make_tag(admin)
    fc = fresh_admin["_client"]
    v = fc.create_vault(name=unique("crvault"))
    try:
        _login(page, fresh_admin["_username"], fresh_admin["_password"])
        _open_vault(page, v["id"])
        page.click("#share-vault-btn")
        _create_in_modal(page, tag_name, fc, v["id"])
    finally:
        fc.delete_vault(v["id"])


def test_create_file_share_from_row(page: Page, admin, fresh_admin):
    admin.put("/settings", json={"sharing_enabled": True})
    tag_name = _make_tag(admin)
    fc = fresh_admin["_client"]
    v = fc.create_vault(name=unique("crvf"))
    fc.post(f"/vaults/{v['id']}/files", files=[("files", ("shareme.txt", b"data", "text/plain"))])
    try:
        _login(page, fresh_admin["_username"], fresh_admin["_password"])
        _open_vault(page, v["id"])
        # switch to table view for a stable row, then click the file's Share action
        page.click("#files-view-table")
        expect(page.get_by_text("shareme.txt")).to_be_visible(timeout=10000)
        page.locator('button[data-action="share-file"]').first.click()
        _create_in_modal(page, tag_name, fc, v["id"])
    finally:
        fc.delete_vault(v["id"])
