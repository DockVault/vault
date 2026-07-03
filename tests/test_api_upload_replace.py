"""Same-name upload policy = REPLACE (web path).

Re-uploading a name overwrites the existing file (one row, new content), using
the safe insert-new-then-delete-old ordering. A scoped upload-only credential
(file.upload without file.delete) cannot replace and is rejected with 409.
"""
import uuid

from conftest import unique


def _upload(client, vault_id, name, content, folder_id=None):
    files = [("files", (name, content, "text/plain"))]
    params = {"folder_id": folder_id} if folder_id else None
    return client.post(f"/vaults/{vault_id}/files", files=files, params=params)


def _list(client, vault_id, folder_id=None):
    params = {"folder_id": folder_id} if folder_id else None
    return client.get(f"/vaults/{vault_id}/files", params=params).json()["items"]


def test_web_upload_same_name_replaces(admin, temp_vault):
    vid = temp_vault["id"]
    name = unique("dup") + ".txt"
    assert _upload(admin, vid, name, b"A-old").status_code == 200
    assert _upload(admin, vid, name, b"B-new").status_code == 200
    same = [it for it in _list(admin, vid) if it["type"] == "file" and it["name"] == name]
    assert len(same) == 1, f"expected exactly one row, got {len(same)}"
    r = admin.get(f"/vaults/{vid}/files/{same[0]['id']}/download")
    assert r.status_code == 200 and r.content == b"B-new"


def test_web_upload_same_name_replaces_in_folder(admin, temp_vault):
    vid = temp_vault["id"]
    fid = admin.post(f"/vaults/{vid}/folders", json={"name": unique("d")}).json()["folder"]["id"]
    name = unique("dup") + ".txt"
    assert _upload(admin, vid, name, b"A", folder_id=fid).status_code == 200
    assert _upload(admin, vid, name, b"B", folder_id=fid).status_code == 200
    same = [it for it in _list(admin, vid, folder_id=fid) if it["type"] == "file" and it["name"] == name]
    assert len(same) == 1


def test_scoped_upload_only_cred_cannot_replace(admin):
    va = admin.create_vault(name=unique("repl"))
    try:
        name = unique("keep") + ".txt"
        assert _upload(admin, va["id"], name, b"original").status_code == 200
        caps = ["vault.see_info", "vault.see_files", "file.upload"]  # no file.delete
        scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": caps,
                 "temp": {"view": False, "create": False, "invalidate": False, "clear": False, "delegate": False}}
        body = admin.post("/auth/temp-credentials", json={
            "validity_minutes": 60, "scope": scope, "vault_access_mode": "selected",
            "selected_vaults": [{"vault_id": va["id"], "caps": caps}]}).json()
        c = admin.clone_anonymous()
        c.login(body["temp_username"], body["credential"])
        # replacing the existing file is denied (no clobber without file.delete)
        assert _upload(c, va["id"], name, b"clobber").status_code == 409
        # creating a brand-new file is still allowed
        assert _upload(c, va["id"], unique("new") + ".txt", b"created").status_code == 200
        # the original is intact
        keep = [it for it in _list(admin, va["id"]) if it["name"] == name]
        assert len(keep) == 1
        assert admin.get(f"/vaults/{va['id']}/files/{keep[0]['id']}/download").content == b"original"
    finally:
        admin.delete_vault(va["id"])
