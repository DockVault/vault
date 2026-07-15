"""Authorization denials on vault file ops must be 403, not 500.

A vault-level permission denial (PermissionDeniedError) used to be swallowed by a broad
`except Exception` in list / upload / download / delete-file / create-folder and re-wrapped
into a generic 500. These assert a clean 403 for both a write/delete denial (a read-only
member) and a read denial (a non-member).
"""


_OCTET = {"Content-Type": "application/octet-stream"}


def _upload(client, vid, name="f.txt", content=b"hello"):
    return client.post(f"/vaults/{vid}/files", files=[("files", (name, content, "text/plain"))])


def test_readonly_member_write_ops_are_403_not_500(admin, temp_user, temp_user_client):
    v = admin.create_vault()
    vid = v["id"]
    fid = _upload(admin, vid).json()["files"][0]["id"]
    admin.post(f"/vaults/{vid}/permissions", json={"user_id": temp_user["id"], "level": "read"})
    try:
        assert temp_user_client.get(f"/vaults/{vid}/files").status_code == 200  # read confirmed
        # WRITE/DELETE denials must be a clean 403 (were 500 before the fix). Use a distinct
        # filename so the write-permission check — not the same-name 409 — is what's exercised.
        assert _upload(temp_user_client, vid, name="member.txt").status_code == 403
        assert temp_user_client.post(f"/vaults/{vid}/folders", json={"name": "sub"}).status_code == 403
        assert temp_user_client.post(f"/vaults/{vid}/files/{fid}/delete").status_code == 403
    finally:
        admin.delete_vault(vid)


def test_non_member_read_ops_are_403_not_500(admin, temp_user, temp_user_client):
    v = admin.create_vault()
    vid = v["id"]
    fid = _upload(admin, vid).json()["files"][0]["id"]
    try:
        # temp_user is NOT a member of the vault -> READ denials must be a clean 403 (were 500)
        assert temp_user_client.get(f"/vaults/{vid}/files").status_code == 403
        assert temp_user_client.get(f"/vaults/{vid}/files/{fid}/download").status_code == 403
        # a non-member's write ops hit the outer get_vault READ guard — also 403, not 500
        assert _upload(temp_user_client, vid, name="intruder.txt").status_code == 403
        assert temp_user_client.post(f"/vaults/{vid}/folders", json={"name": "x"}).status_code == 403
        assert temp_user_client.post(f"/vaults/{vid}/files/{fid}/delete").status_code == 403
    finally:
        admin.delete_vault(vid)


def test_readonly_member_chunked_complete_is_403(admin, temp_user, temp_user_client):
    # A read-only member CAN init a chunked upload + push chunks (those only need READ);
    # the write-permission denial surfaces at /complete and must be 403, not 500.
    v = admin.create_vault()
    vid = v["id"]
    admin.post(f"/vaults/{vid}/permissions", json={"user_id": temp_user["id"], "level": "read"})
    data = b"x" * 100
    try:
        r = temp_user_client.post(f"/vaults/{vid}/uploads", json={
            "file_name": "member-chunked.bin", "total_size": len(data),
            "total_chunks": 1, "chunk_size": 1024 * 1024,
            "mime_type": "application/octet-stream",
        })
        assert r.status_code == 200, r.text
        sid = r.json()["session_id"]
        assert temp_user_client.put(
            f"/vaults/{vid}/uploads/{sid}/chunks/0", data=data, headers=_OCTET
        ).status_code == 200
        assert temp_user_client.post(f"/vaults/{vid}/uploads/{sid}/complete").status_code == 403
    finally:
        admin.delete_vault(vid)
