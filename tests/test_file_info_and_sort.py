"""File Info panel + Show-hash + Last-modified-by + sortable list headers.

Three lanes:
  * unit — read the repo files: the modified_by column + its boot DDL, the /info route + the listing
           field, and the frontend wiring exist. No server.
  * api  — the /info endpoint over HTTP: its checksum IS the classic plaintext SHA-256, dates/size are
           right, and modified_by tracks the actual renamer (not just the uploader).
  * ui   — a real browser: the Info modal renders metadata + a copyable hash, the list headers sort,
           and the "Modified by" column shows the modifier.
"""
import hashlib
import re
import uuid
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

from conftest import ADMIN_USER, ApiClient, unique

ROOT = Path(__file__).resolve().parent.parent


def _upload(client, vault_id, name, content, folder_id=None, password=None):
    """Upload one file and return its id. The endpoint takes the `files` (plural) multipart field
    and answers {"files": [{"id": ...}]}."""
    files = [("files", (name, content, "application/octet-stream"))]
    params = {"folder_id": folder_id} if folder_id else None
    headers = {"X-Vault-Password": password} if password else None
    r = client.post(f"/vaults/{vault_id}/files", files=files, params=params, headers=headers)
    assert r.status_code in (200, 201), r.text
    return r.json()["files"][0]["id"]


# --------------------------------------------------------------------------- unit lane

@pytest.mark.unit
def test_modified_by_column_ddl_endpoint_and_wiring():
    models = (ROOT / "app" / "core" / "models.py").read_text(encoding="utf-8")
    api = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    app = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    idx = (ROOT / "static" / "index.html").read_text(encoding="utf-8")

    # schema: the model declares modified_by AND the boot DDL adds it to existing installs.
    assert re.search(r"^\s*modified_by = Column\(", models, re.M), "File.modified_by not declared"
    assert "ALTER TABLE files ADD COLUMN IF NOT EXISTS modified_by" in api, "no boot DDL for modified_by"

    # backend surfaces: a dedicated info route + the listing's modifier field.
    assert '/vaults/{vault_id}/files/{file_id}/info' in api
    assert "async def get_file_info(" in api
    assert "modified_by_name" in api

    # the modifier name is gated to GENUINE members in BOTH the listing and the info endpoint (a
    # scoped temp cred OR a share recipient must not learn org member identities).
    assert api.count("_member_grade_principal(current_user") >= 2, \
        "modifier-name exposure not gated on _member_grade_principal in both paths"

    # frontend wiring: sort comparator, header UI, info modal, and the "Modified by" column/header.
    assert "function sortFilesForRender(" in app
    assert "function applySortHeaderUI(" in app
    assert "function openFileInfo(" in app
    assert "is_zero_knowledge" in app  # the ZK hash-unavailable branch
    assert 'data-sort-key="modified_by"' in idx
    assert 'data-sort-key="size"' in idx
    assert 'id="file-info-modal"' in idx


# --------------------------------------------------------------------------- api lane

def test_info_checksum_is_the_classic_plaintext_sha256(admin, temp_vault):
    """The Show-hash value must be exactly what `sha256sum` of the file yields (Standard vault)."""
    vid = temp_vault["id"]
    content = b"the quick brown fox jumps over the lazy dog\n"
    fid = _upload(admin, vid, unique("hash") + ".txt", content)

    info = admin.get(f"/vaults/{vid}/files/{fid}/info")
    assert info.status_code == 200, info.text
    body = info.json()
    assert body["size"] == len(content)
    assert body["checksum_sha256"] == hashlib.sha256(content).hexdigest()
    assert body["checksum_algorithm"] == "SHA-256"
    assert body["is_zero_knowledge"] is False
    assert body["created_by"] == ADMIN_USER
    assert body["created_at"] and body["modified_at"]


def test_info_404_for_a_missing_file(admin, temp_vault):
    r = admin.get(f"/vaults/{temp_vault['id']}/files/{uuid.uuid4()}/info")
    assert r.status_code == 404


def test_listing_carries_modified_by_name(admin, temp_vault):
    vid = temp_vault["id"]
    fid = _upload(admin, vid, unique("mbn") + ".txt", b"x")
    items = admin.get(f"/vaults/{vid}/files").json()["items"]
    entry = next(i for i in items if i["id"] == fid)
    # never renamed -> last modifier is the uploader.
    assert entry["modified_by_name"] == ADMIN_USER


def test_modified_by_tracks_the_renamer_not_the_uploader(admin, temp_vault, temp_user):
    """The whole point of the column: created_by stays the uploader while modified_by becomes whoever
    renamed it last. Uploaded by admin, renamed by a second user."""
    vid = temp_vault["id"]
    fid = _upload(admin, vid, unique("mb") + ".txt", b"track me")

    uid = temp_user["id"]
    # FILE_DELETE (with its transitive FILE_VIEW) lets the user reach the rename endpoint; a vault
    # write grant lets the permission service authorize the rename itself.
    assert admin.post(f"/permissions/users/{uid}/grant",
                      json={"endpoint_group": "FILE_DELETE"}).status_code == 200
    assert admin.post(f"/vaults/{vid}/permissions",
                      json={"user_id": uid, "level": "write"}).status_code == 200

    other = ApiClient()
    other.login(temp_user["_username"], temp_user["_password"])
    rn = other.put(f"/vaults/{vid}/files/{fid}/rename", json={"new_name": unique("renamed") + ".txt"})
    assert rn.status_code == 200, rn.text

    body = admin.get(f"/vaults/{vid}/files/{fid}/info").json()
    assert body["created_by"] == ADMIN_USER
    assert body["modified_by"] == temp_user["_username"]
    assert body["modified_by"] != body["created_by"]


# --- share-recipient negative tests: names + hash must NOT leak to a share principal -----------

def _enable_sharing(admin, on=True):
    assert admin.put("/settings", json={"sharing_enabled": on}).status_code == 200


def _share_tag(admin, **over):
    body = {"name": unique("fitag"), "auto_enroll_new_users": True,
            "allowed_audiences": ["anyone_internal"], "max_recipients_cap": 10}
    body.update(over)
    r = admin.post("/share-tags", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def _make_share(admin, v, tag, **over):
    body = {"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault",
            "claim_audience": "anyone_internal"}
    body.update(over)
    r = admin.post("/shares", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def test_share_recipient_does_not_see_member_usernames(admin, temp_user_client):
    """A share recipient is a real account (not a temp session), so an is_scoped()-only gate leaked
    the uploader/modifier usernames to them. They must come back null on BOTH the listing and /info.
    A downloadable share still gets the hash (it can download the file)."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("mbshare"))
    try:
        content = b"shared-and-owned"
        fid = _upload(admin, v["id"], "shared.txt", content)
        share = _make_share(admin, v, _share_tag(admin))
        assert temp_user_client.post("/shares/claim", json={"token": share["link_token"]}).status_code == 200

        items = temp_user_client.get(f"/vaults/{v['id']}/files").json()["items"]
        entry = next(i for i in items if i["id"] == fid)
        assert entry.get("modified_by_name") is None, "listing leaked a username to a share recipient"

        info = temp_user_client.get(f"/vaults/{v['id']}/files/{fid}/info")
        assert info.status_code == 200, info.text
        body = info.json()
        assert body["created_by"] is None and body["modified_by"] is None, "info leaked usernames to a share recipient"
        # a downloadable (non-view-only) whole-vault share CAN download, so the hash is allowed.
        assert body["checksum_sha256"] == hashlib.sha256(content).hexdigest()
    finally:
        admin.delete_vault(v["id"])


def test_view_only_share_recipient_gets_no_hash(admin, temp_user_client):
    """A view-only share can list/preview but NOT download. The content hash is a fingerprint they
    could not compute themselves, so /info must withhold it (and the usernames)."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("vohash"))
    try:
        fid = _upload(admin, v["id"], "vo.txt", b"view only bytes")
        tag = _share_tag(admin, allow_view_only=True)
        share = _make_share(admin, v, tag, view_only=True)
        assert temp_user_client.post("/shares/claim", json={"token": share["link_token"]}).status_code == 200

        info = temp_user_client.get(f"/vaults/{v['id']}/files/{fid}/info")
        assert info.status_code == 200, info.text
        body = info.json()
        assert body["checksum_sha256"] is None, "view-only share recipient was given the content hash"
        assert body["created_by"] is None and body["modified_by"] is None
    finally:
        admin.delete_vault(v["id"])


# --------------------------------------------------------------------------- ui lane

def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_vault_table(page: Page, vault_id: str):
    page.click('.sidebar-item[data-section="vaults"]')
    page.click(f'.open-vault-btn[data-vault-id="{vault_id}"]')
    expect(page.locator("#vault-view-section")).to_be_visible(timeout=10000)
    page.click('[data-files-view="table"]')


@pytest.mark.ui
def test_info_modal_shows_metadata_hash_and_copy(page: Page, admin, admin_creds):
    v = admin.create_vault(name="info-modal")
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault_table(page, v["id"])
        page.set_input_files("#file-upload-input",
                             files=[{"name": "doc.txt", "mimeType": "text/plain", "buffer": b"hello info"}])
        row = page.locator("#vault-files-table-body tr").first
        expect(row).to_be_visible(timeout=15000)
        # Info lives in the right-click context menu now (not an inline row button).
        row.click(button="right")
        page.locator('#file-context-menu button[data-action="file-info"]').click()

        expect(page.locator("#file-info-modal")).to_be_visible(timeout=8000)
        expect(page.locator("#file-info-body .file-info-dl")).to_be_visible()
        hashval = page.locator("#file-info-body .file-info-hash-value")
        expect(hashval).to_be_visible()
        assert re.fullmatch(r"[0-9a-f]{64}", hashval.inner_text()), hashval.inner_text()
        assert hashval.inner_text() == hashlib.sha256(b"hello info").hexdigest()
        expect(page.locator("#file-info-body .file-info-hash-head button")).to_have_text("Copy")
    finally:
        admin.delete_vault(v["id"])


@pytest.mark.ui
def test_sortable_headers_reorder_the_list(page: Page, admin, admin_creds):
    v = admin.create_vault(name="sort")
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault_table(page, v["id"])
        # name order (aaa, zzz) and size order (zzz=10, aaa=200) disagree, so a size sort is visible.
        page.set_input_files("#file-upload-input", files=[
            {"name": "aaa.bin", "mimeType": "application/octet-stream", "buffer": b"a" * 200},
            {"name": "zzz.bin", "mimeType": "application/octet-stream", "buffer": b"z" * 10},
        ])
        expect(page.locator("#vault-files-table-body tr")).to_have_count(2, timeout=15000)
        first = page.locator("#vault-files-table-body tr").first.locator(".file-name")
        # default: name ascending -> aaa first
        expect(first).to_contain_text("aaa")

        size_th = page.locator('.files-table thead th[data-sort-key="size"]')
        size_th.click()  # size ascending -> zzz (10 bytes) first
        expect(size_th).to_have_attribute("aria-sort", "ascending")
        expect(page.locator("#vault-files-table-body tr").first.locator(".file-name")).to_contain_text("zzz")

        size_th.click()  # size descending -> aaa (200 bytes) first
        expect(size_th).to_have_attribute("aria-sort", "descending")
        expect(page.locator("#vault-files-table-body tr").first.locator(".file-name")).to_contain_text("aaa")
    finally:
        admin.delete_vault(v["id"])


@pytest.mark.ui
def test_modified_by_column_shows_the_modifier(page: Page, admin, admin_creds):
    v = admin.create_vault(name="modby")
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        _open_vault_table(page, v["id"])
        page.set_input_files("#file-upload-input",
                             files=[{"name": "who.txt", "mimeType": "text/plain", "buffer": b"y"}])
        row = page.locator("#vault-files-table-body tr").first
        expect(row).to_be_visible(timeout=15000)
        # admin uploaded it and it was never renamed -> last modifier is the admin.
        expect(row.locator(".file-modified-by")).to_have_text(admin_creds["username"])
    finally:
        admin.delete_vault(v["id"])
