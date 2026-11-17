"""A preview is recorded as a preview.

The web app's preview and text window read a file through the download route, so every preview was recorded
as "File download started" and "File download finished". The route now takes ``purpose=preview``, recorded as
a preview: the content was sent to the browser for a preview (file_previewed, then file_preview_completed; a ranged
read, which is how the text window reads the start of a large file, ends in a file_previewed row too). It is also
answered as the preview route answers (inline, never cached, the preview's headers and types), and a capped share
spends its recipient's preview allowance, counted apart from downloads. Every gate and the transfer slot are exactly
a download's, and a view-only share's recipient is still refused on this route: a preview discloses the content as
a download does, and the word from the client never opens what a download would not.
"""
import os
import subprocess

import pytest

from conftest import ApiClient, unique

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql):
    r = subprocess.run(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                       capture_output=True, text=True, timeout=20)
    return (r.stdout or "").strip()


def _actions(file_id):
    """The actions recorded against a file, oldest first, with their status."""
    out = _psql(f"SELECT action || ':' || status FROM audit_logs WHERE resource_id='{file_id}' "
                "AND resource_type='file' ORDER BY timestamp, id")
    return [line for line in out.splitlines() if line]


def _upload(client, vault_id, name, content):
    r = client.post(f"/vaults/{vault_id}/files", files=[("files", (name, content, "text/plain"))])
    assert r.status_code == 200, r.text
    files = client.get(f"/vaults/{vault_id}/files").json()["items"]
    return next(f["id"] for f in files if f["name"] == name)


@pytest.fixture
def a_file(admin, temp_vault):
    return temp_vault["id"], _upload(admin, temp_vault["id"], unique("note") + ".txt", b"a line of text\n" * 40)


def test_a_preview_writes_preview_rows_and_no_download_row(admin, a_file):
    vault_id, file_id = a_file
    before = _actions(file_id)
    r = admin.get(f"/vaults/{vault_id}/files/{file_id}/download", params={"purpose": "preview"})
    assert r.status_code == 200 and r.content.startswith(b"a line of text")
    new = _actions(file_id)[len(before):]
    assert new == ["file_previewed:authorized", "file_preview_completed:success"], new


def test_a_download_is_recorded_as_before(admin, a_file):
    vault_id, file_id = a_file
    before = _actions(file_id)
    assert admin.get(f"/vaults/{vault_id}/files/{file_id}/download").status_code == 200
    new = _actions(file_id)[len(before):]
    assert new == ["file_download:authorized", "file_download_completed:success"], new
    # Another word than "preview" is a download too: the label is read, never trusted for anything else.
    assert admin.get(f"/vaults/{vault_id}/files/{file_id}/download", params={"purpose": "whatever"}).status_code == 200
    assert _actions(file_id)[-2:] == ["file_download:authorized", "file_download_completed:success"]


def test_a_ranged_preview_writes_one_preview_row(admin, a_file):
    vault_id, file_id = a_file
    before = _actions(file_id)
    r = admin.get(f"/vaults/{vault_id}/files/{file_id}/download", params={"purpose": "preview"},
                  headers={"Range": "bytes=0-99"})
    assert r.status_code == 206 and len(r.content) == 100, (r.status_code, len(r.content))
    new = _actions(file_id)[len(before):]
    assert new == ["file_previewed:authorized", "file_previewed:success"], new
    assert _psql(f"SELECT details->>'range_end' FROM audit_logs WHERE resource_id='{file_id}' "
                 "AND action='file_previewed' ORDER BY timestamp DESC LIMIT 1") == "99"


def test_a_preview_keeps_every_gate(admin, a_file, temp_user_client):
    """Someone with no access to the vault gets the same refusal for a preview as for a download."""
    vault_id, file_id = a_file
    before = _actions(file_id)
    assert temp_user_client.get(f"/vaults/{vault_id}/files/{file_id}/download", params={"purpose": "preview"}).status_code == 403
    assert _actions(file_id) == before


def test_a_capped_shares_preview_is_counted_as_a_preview(admin, temp_user_client, temp_user):
    """A share recipient's preview through the download route (purpose=preview) is recorded as a shared file
    previewed and counted apart from downloads: the one download the share allows is still there after it."""
    sharing_before = admin.get("/settings").json().get("sharing_enabled")
    admin.put("/settings", json={"sharing_enabled": True})
    vault = admin.create_vault(name=unique("capped"))
    try:
        file_id = _upload(admin, vault["id"], unique("deck") + ".txt", b"the deck" * 10)
        tag = admin.post("/share-tags", json={"name": unique("once"), "allowed_audiences": ["anyone_internal"],
                                              "max_downloads_cap": 5, "max_recipients_cap": 10,
                                              "auto_enroll_new_users": True})
        assert tag.status_code == 200, tag.text
        share = admin.post("/shares", json={"vault_id": vault["id"], "tag_id": tag.json()["id"], "target_type": "vault",
                                            "claim_audience": "anyone_internal", "max_downloads": 1})
        assert share.status_code == 200, share.text
        assert temp_user_client.post("/shares/claim", json={"token": share.json()["link_token"]}).status_code == 200
        before = _actions(file_id)
        r = temp_user_client.get(f"/vaults/{vault['id']}/files/{file_id}/download", params={"purpose": "preview"})
        assert r.status_code == 200, r.text
        new = _actions(file_id)[len(before):]
        assert new == ["file_previewed:authorized", "share_previewed:success", "file_preview_completed:success"], new
        # The preview allowance is spent; the one download is not.
        again = temp_user_client.get(f"/vaults/{vault['id']}/files/{file_id}/download", params={"purpose": "preview"})
        assert again.status_code == 403 and "preview limit" in again.text, again.text
        assert temp_user_client.get(f"/vaults/{vault['id']}/files/{file_id}/download").status_code == 200
    finally:
        admin.delete_vault(vault["id"])
        admin.put("/settings", json={"sharing_enabled": sharing_before})
