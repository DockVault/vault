"""Regression tests for file upload / download / storage.

recursive folder deletion requires DELETE permission (a read-only or
write-but-no-delete member must not destroy a subtree). control chars in a
filename are stripped and the file still downloads. an absurd total_chunks is
rejected at chunked-init. folder nesting depth is capped.
"""


def _mk_vault_folder(admin):
    v = admin.create_vault()
    r = admin.post(f"/vaults/{v['id']}/folders", json={"name": "secret-dir"})
    assert r.status_code == 200, r.text
    return v, r.json()["folder"]["id"]


def test_readonly_member_cannot_delete_folder(admin, temp_user, temp_user_client):
    v, fid = _mk_vault_folder(admin)
    try:
        admin.post(f"/vaults/{v['id']}/permissions", json={"user_id": temp_user["id"], "level": "read"})
        assert temp_user_client.get(f"/vaults/{v['id']}/files").status_code == 200  # read confirmed
        assert temp_user_client.post(f"/vaults/{v['id']}/folders/{fid}/delete").status_code == 403
        # the subtree must survive — the owner can still delete it
        assert admin.post(f"/vaults/{v['id']}/folders/{fid}/delete").status_code == 200
    finally:
        admin.delete_vault(v["id"])


def test_write_but_no_delete_member_cannot_delete_folder(admin, temp_user, temp_user_client):
    v, fid = _mk_vault_folder(admin)
    try:
        admin.post(f"/vaults/{v['id']}/permissions", json={"user_id": temp_user["id"], "level": "write"})
        assert temp_user_client.post(f"/vaults/{v['id']}/folders/{fid}/delete").status_code == 403
    finally:
        admin.delete_vault(v["id"])


def test_chunked_init_rejects_absurd_chunk_count(admin):
    v = admin.create_vault()
    try:
        r = admin.post(f"/vaults/{v['id']}/uploads",
                       json={"file_name": "x", "total_size": 1, "total_chunks": 2_000_000_000, "chunk_size": 1})
        assert r.status_code == 400
        r = admin.post(f"/vaults/{v['id']}/uploads",
                       json={"file_name": "ok.txt", "total_size": 10, "total_chunks": 2, "chunk_size": 5})
        assert r.status_code == 200
    finally:
        admin.delete_vault(v["id"])


def test_control_char_filename_sanitized_and_downloadable(admin):
    v = admin.create_vault()
    try:
        r = admin.post(f"/vaults/{v['id']}/uploads",
                       json={"file_name": "evil\r\nInjected.txt", "total_size": 5, "total_chunks": 1, "chunk_size": 5})
        assert r.status_code == 200, r.text
        sid = r.json().get("session_id") or r.json().get("id")
        assert admin.put(f"/vaults/{v['id']}/uploads/{sid}/chunks/0", data=b"hello").status_code in (200, 201)
        assert admin.post(f"/vaults/{v['id']}/uploads/{sid}/complete", json={}).status_code == 200
        items = admin.get(f"/vaults/{v['id']}/files").json()["items"]
        f = next(x for x in items if x.get("type") == "file" and "Injected" in x.get("name", ""))
        assert "\r" not in f["name"] and "\n" not in f["name"]  # sanitized at source
        assert admin.get(f"/vaults/{v['id']}/files/{f['id']}/download").status_code == 200  # header sink safe
    finally:
        admin.delete_vault(v["id"])


def test_rename_strips_control_chars(admin):
    v = admin.create_vault()
    try:
        r = admin.post(f"/vaults/{v['id']}/uploads",
                       json={"file_name": "orig.txt", "total_size": 5, "total_chunks": 1, "chunk_size": 5})
        sid = r.json().get("session_id") or r.json().get("id")
        admin.put(f"/vaults/{v['id']}/uploads/{sid}/chunks/0", data=b"hello")
        admin.post(f"/vaults/{v['id']}/uploads/{sid}/complete", json={})
        fid = next(x["id"] for x in admin.get(f"/vaults/{v['id']}/files").json()["items"] if x.get("type") == "file")
        r = admin.put(f"/vaults/{v['id']}/files/{fid}/rename", json={"new_name": "renamed\r\nInjected.txt"})
        assert r.status_code == 200, r.text
        name = next(x["name"] for x in admin.get(f"/vaults/{v['id']}/files").json()["items"] if x["id"] == fid)
        assert "\r" not in name and "\n" not in name  # control chars stripped at the rename sink
    finally:
        admin.delete_vault(v["id"])


def test_folder_nesting_depth_capped(admin):
    v = admin.create_vault()
    try:
        parent, rejected = None, False
        for i in range(70):
            body = {"name": f"lvl{i}"}
            if parent:
                body["parent_folder_id"] = parent
            r = admin.post(f"/vaults/{v['id']}/folders", json=body)
            if r.status_code == 200:
                parent = r.json()["folder"]["id"]
            else:
                rejected = True
                break
        assert rejected  # deep nesting is eventually rejected by the depth cap
    finally:
        admin.delete_vault(v["id"])
