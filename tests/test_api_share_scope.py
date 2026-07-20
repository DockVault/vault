"""Share SUBTREE scoping (file/folder-target shares).

A recipient claiming a FOLDER or FILE share is confined to that subtree: they may list/download
inside it, but a sibling outside the subtree is neither listed (anti-enumeration) nor downloadable
(even by known id). A WHOLE-VAULT share stays unrestricted. The share scope is per-vault and does
not downgrade the recipient's own (real-account) vaults — a share recipient is never a temp session.
"""
import os

from conftest import unique

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _enable_sharing(admin, on=True):
    assert admin.put("/settings", json={"sharing_enabled": on}).status_code == 200


def _tag(admin, **over):
    body = {"name": unique("sctag"), "auto_enroll_new_users": True,
            "allowed_audiences": ["anyone_internal"], "max_recipients_cap": 10}
    body.update(over)
    r = admin.post("/share-tags", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def _make_share(admin, v, tag, **over):
    body = {"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault", "claim_audience": "anyone_internal"}
    body.update(over)
    r = admin.post("/shares", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def _mkfolder(admin, vid, name, parent=None):
    body = {"name": name}
    if parent:
        body["parent_folder_id"] = parent
    return admin.post(f"/vaults/{vid}/folders", json=body).json()["folder"]["id"]


def _upload(admin, vid, name, folder_id=None, content=b"data"):
    params = {"folder_id": folder_id} if folder_id else {}
    r = admin.post(f"/vaults/{vid}/files", files=[("files", (name, content, "text/plain"))], params=params)
    assert r.status_code in (200, 201), r.text


def _file_id(admin, vid, name, folder_id=None):
    params = {"folder_id": folder_id} if folder_id else {}
    for it in admin.get(f"/vaults/{vid}/files", params=params).json()["items"]:
        if it.get("name") == name and it.get("type") == "file":
            return it["id"]
    raise AssertionError(f"file {name} not found")


def _claim(client, share):
    r = client.post("/shares/claim", json={"token": share["link_token"]})
    assert r.status_code == 200, r.text


def _names(client, vid, folder_id=None):
    params = {"folder_id": folder_id} if folder_id else {}
    r = client.get(f"/vaults/{vid}/files", params=params)
    assert r.status_code == 200, r.text
    return {it["name"] for it in r.json()["items"]}


def test_folder_share_confines_recipient_to_subtree(admin, temp_user_client):
    """A folder share lets the recipient list+download inside the folder, but a sibling at the
    root is neither listed nor downloadable."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("scfld"))
    try:
        D = _mkfolder(admin, v["id"], "shared")
        _upload(admin, v["id"], "inside.txt", folder_id=D, content=b"in-subtree")
        _upload(admin, v["id"], "sibling.txt", content=b"outside")  # at root, NOT shared
        X = _file_id(admin, v["id"], "inside.txt", folder_id=D)
        Y = _file_id(admin, v["id"], "sibling.txt")

        share = _make_share(admin, v, _tag(admin), target_type="folder", target_folder_id=D)
        _claim(temp_user_client, share)

        # inside the shared folder: visible + downloadable
        assert "inside.txt" in _names(temp_user_client, v["id"], folder_id=D)
        r = temp_user_client.get(f"/vaults/{v['id']}/files/{X}/download")
        assert r.status_code == 200 and r.content == b"in-subtree", r.text

        # the sibling at root: NOT listed and NOT downloadable
        root = _names(temp_user_client, v["id"])
        assert "sibling.txt" not in root, "sibling outside the shared folder must not be enumerated"
        assert temp_user_client.get(f"/vaults/{v['id']}/files/{Y}/download").status_code == 403
    finally:
        admin.delete_vault(v["id"])


def test_file_share_confines_recipient_to_one_file(admin, temp_user_client):
    """A file share grants exactly that one file; a sibling file is hidden and undownloadable."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("scfile"))
    try:
        _upload(admin, v["id"], "a.txt", content=b"file-a")
        _upload(admin, v["id"], "b.txt", content=b"file-b")
        A = _file_id(admin, v["id"], "a.txt")
        B = _file_id(admin, v["id"], "b.txt")

        share = _make_share(admin, v, _tag(admin), target_type="file", target_file_id=A)
        _claim(temp_user_client, share)

        r = temp_user_client.get(f"/vaults/{v['id']}/files/{A}/download")
        assert r.status_code == 200 and r.content == b"file-a", r.text
        assert temp_user_client.get(f"/vaults/{v['id']}/files/{B}/download").status_code == 403

        root = _names(temp_user_client, v["id"])
        assert "a.txt" in root and "b.txt" not in root
    finally:
        admin.delete_vault(v["id"])


def test_whole_vault_share_stays_unrestricted(admin, temp_user_client):
    """Regression: the subtree stamping must NOT restrict a whole-vault recipient — they still see
    and download every file/folder."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("scwhole"))
    try:
        D = _mkfolder(admin, v["id"], "dir")
        _upload(admin, v["id"], "top.txt", content=b"top")
        _upload(admin, v["id"], "deep.txt", folder_id=D, content=b"deep")
        top = _file_id(admin, v["id"], "top.txt")

        share = _make_share(admin, v, _tag(admin))  # whole-vault
        _claim(temp_user_client, share)

        root = _names(temp_user_client, v["id"])
        assert "top.txt" in root and "dir" in root  # nothing filtered out
        assert temp_user_client.get(f"/vaults/{v['id']}/files/{top}/download").status_code == 200
    finally:
        admin.delete_vault(v["id"])


def test_share_scope_does_not_downgrade_recipients_own_vault(admin, temp_user, temp_user_client):
    """a share recipient is a REAL account, never a temp session. A folder scope on the
    SHARED vault must not bleed into the recipient's OWN vault — they see all of their own files."""
    _enable_sharing(admin, True)
    shared = admin.create_vault(name=unique("scshared"))
    own = temp_user_client.create_vault(name=unique("scown"))
    try:
        D = _mkfolder(admin, shared["id"], "d")
        _upload(admin, shared["id"], "s.txt", folder_id=D, content=b"s")
        _upload(temp_user_client, own["id"], "mine1.txt", content=b"m1")
        _upload(temp_user_client, own["id"], "mine2.txt", content=b"m2")

        share = _make_share(admin, shared, _tag(admin), target_type="folder", target_folder_id=D)
        _claim(temp_user_client, share)

        # scoped on the shared vault...
        assert "s.txt" in _names(temp_user_client, shared["id"], folder_id=D)
        # ...but the recipient's OWN vault is completely unrestricted
        own_names = _names(temp_user_client, own["id"])
        assert {"mine1.txt", "mine2.txt"} <= own_names
    finally:
        admin.delete_vault(shared["id"])
        temp_user_client.delete_vault(own["id"])


def test_revoked_folder_claim_loses_subtree(admin, temp_user, temp_user_client):
    """Revoking a folder claim removes the subtree grant LIVE (no lingering scoped access)."""
    import subprocess
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("screv"))
    try:
        D = _mkfolder(admin, v["id"], "d")
        _upload(admin, v["id"], "f.txt", folder_id=D, content=b"f")
        X = _file_id(admin, v["id"], "f.txt", folder_id=D)
        share = _make_share(admin, v, _tag(admin), target_type="folder", target_folder_id=D)
        _claim(temp_user_client, share)
        assert temp_user_client.get(f"/vaults/{v['id']}/files/{X}/download").status_code == 200
        subprocess.run(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc",
                        f"UPDATE share_claims SET revoked=true WHERE share_id='{share['id']}' AND user_id='{temp_user['id']}'"],
                       capture_output=True, text=True, timeout=20)
        assert temp_user_client.get(f"/vaults/{v['id']}").status_code == 403
        assert temp_user_client.get(f"/vaults/{v['id']}/files/{X}/download").status_code == 403
    finally:
        admin.delete_vault(v["id"])
