"""A share's claim-audience is re-checked at ACCESS, not only at claim time.

Removing a recipient from the targeted department cuts their live read/download access on their next
request (not only an explicit revoke/kick/expiry). A 'users' audience is snapshotted at create, so a
recipient's later group changes don't affect it — the re-check must not over-deny a legitimate claim.
"""
from conftest import ApiClient, unique


def _enable(admin):
    assert admin.put("/settings", json={"sharing_enabled": True}).status_code == 200


def _tag(admin):
    r = admin.post("/share-tags", json={"name": unique("revtag"), "auto_enroll_new_users": True,
                                        "allowed_audiences": ["users", "departments"],
                                        "max_recipients_cap": 10})
    assert r.status_code == 200, r.text
    return r.json()


def _upload(admin, vid):
    r = admin.post(f"/vaults/{vid}/files",
                   files=[("files", (unique("doc") + ".txt", b"secret-bytes\n", "text/plain"))])
    r.raise_for_status()
    return r.json()["files"][0]["id"]


def test_department_removal_cuts_live_share_access(admin):
    _enable(admin)
    v = admin.create_vault(name=unique("revvault"))
    g = admin.post("/groups", json={"name": unique("revdept")}).json()
    R = admin.create_user(role="user")
    admin.post(f"/groups/{g['id']}/members", json={"user_ids": [R["id"]]})
    rc = ApiClient(); rc.login(R["_username"], R["_password"])
    try:
        fid = _upload(admin, v["id"])
        share = admin.post("/shares", json={
            "vault_id": v["id"], "tag_id": _tag(admin)["id"],
            "target_type": "file", "target_file_id": fid,
            "claim_audience": "departments", "audience_department_ids": [g["id"]],
            "view_only": False}).json()
        assert rc.post(f"/shares/{share['id']}/claim").status_code == 200

        # In the targeted department -> can open the vault + download the shared file.
        assert rc.get(f"/vaults/{v['id']}").status_code == 200
        assert rc.get(f"/vaults/{v['id']}/files/{fid}/download").status_code == 200

        # Admin removes R from the targeted department.
        assert admin.delete(f"/groups/{g['id']}/members/{R['id']}").status_code in (200, 204)

        # Access is re-evaluated live -> now DENIED (the audience no longer covers R).
        assert rc.get(f"/vaults/{v['id']}/files/{fid}/download").status_code == 403
        assert rc.get(f"/vaults/{v['id']}").status_code == 403
    finally:
        admin.delete(f"/groups/{g['id']}")
        admin.delete_user(R["id"])
        admin.delete_vault(v["id"])


def test_users_audience_access_is_static(admin):
    """Control: a 'users' audience is snapshotted at create; a recipient's later group membership
    changes must not affect access, and the audience re-check must not over-deny a valid users claim."""
    _enable(admin)
    v = admin.create_vault(name=unique("revuvault"))
    R = admin.create_user(role="user")
    rc = ApiClient(); rc.login(R["_username"], R["_password"])
    g = admin.post("/groups", json={"name": unique("revgrp")}).json()
    try:
        fid = _upload(admin, v["id"])
        share = admin.post("/shares", json={
            "vault_id": v["id"], "tag_id": _tag(admin)["id"],
            "target_type": "file", "target_file_id": fid,
            "claim_audience": "users", "audience_user_ids": [R["id"]],
            "view_only": False}).json()
        assert rc.post(f"/shares/{share['id']}/claim").status_code == 200
        assert rc.get(f"/vaults/{v['id']}/files/{fid}/download").status_code == 200

        # Join then leave an unrelated group -> a users-audience claim is unaffected.
        admin.post(f"/groups/{g['id']}/members", json={"user_ids": [R["id"]]})
        admin.delete(f"/groups/{g['id']}/members/{R['id']}")
        assert rc.get(f"/vaults/{v['id']}/files/{fid}/download").status_code == 200
    finally:
        admin.delete(f"/groups/{g['id']}")
        admin.delete_user(R["id"])
        admin.delete_vault(v["id"])
