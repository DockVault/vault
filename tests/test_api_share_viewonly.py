"""View-only shares: see-but-not-download.

A view-only share grants the recipient VISIBILITY (open + list + preview) but denies download on the
download path. A normal (read+download) share still downloads. When a recipient holds BOTH a view-only
and a downloadable share on the same vault, download is resolved PER FILE (downloadable only where a
non-view-only claim covers it). Share downloads are audited as share_downloaded.
"""
import os
import subprocess

from conftest import unique

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql_out(sql):
    r = subprocess.run(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                       capture_output=True, text=True, timeout=20)
    return (r.stdout or "").strip()


def _enable_sharing(admin, on=True):
    assert admin.put("/settings", json={"sharing_enabled": on}).status_code == 200


def _tag(admin, **over):
    body = {"name": unique("votag"), "auto_enroll_new_users": True,
            "allowed_audiences": ["anyone_internal"], "max_recipients_cap": 10, "allow_view_only": True}
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
    assert client.post("/shares/claim", json={"token": share["link_token"]}).status_code == 200


def _names(client, vid, folder_id=None):
    params = {"folder_id": folder_id} if folder_id else {}
    return {it["name"] for it in client.get(f"/vaults/{vid}/files", params=params).json()["items"]}


def test_view_only_whole_vault_sees_all_but_no_download(admin, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("vowv"))
    try:
        _upload(admin, v["id"], "a.txt", content=b"aaa")
        _upload(admin, v["id"], "b.txt", content=b"bbb")
        a = _file_id(admin, v["id"], "a.txt")
        share = _make_share(admin, v, _tag(admin), view_only=True)
        _claim(temp_user_client, share)
        # sees the whole vault...
        assert {"a.txt", "b.txt"} <= _names(temp_user_client, v["id"])
        # ...but cannot download anything
        assert temp_user_client.get(f"/vaults/{v['id']}/files/{a}/download").status_code == 403
    finally:
        admin.delete_vault(v["id"])


def test_view_only_folder_sees_subtree_no_download(admin, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("vofld"))
    try:
        D = _mkfolder(admin, v["id"], "d")
        _upload(admin, v["id"], "in.txt", folder_id=D, content=b"in")
        x = _file_id(admin, v["id"], "in.txt", folder_id=D)
        share = _make_share(admin, v, _tag(admin), view_only=True, target_type="folder", target_folder_id=D)
        _claim(temp_user_client, share)
        assert "in.txt" in _names(temp_user_client, v["id"], folder_id=D)          # visible
        assert temp_user_client.get(f"/vaults/{v['id']}/files/{x}/download").status_code == 403  # no download
    finally:
        admin.delete_vault(v["id"])


def test_downloadable_share_still_downloads(admin, temp_user_client):
    """Regression: a normal (non-view-only) share is unaffected — download works."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("vodl"))
    try:
        _upload(admin, v["id"], "f.txt", content=b"downloadable")
        f = _file_id(admin, v["id"], "f.txt")
        share = _make_share(admin, v, _tag(admin))  # NOT view-only
        _claim(temp_user_client, share)
        r = temp_user_client.get(f"/vaults/{v['id']}/files/{f}/download")
        assert r.status_code == 200 and r.content == b"downloadable", r.text
    finally:
        admin.delete_vault(v["id"])


def test_mixed_view_only_and_downloadable_resolve_per_file(admin, temp_user_client):
    """A recipient holding a VIEW-ONLY folder share AND a DOWNLOADABLE folder share on the same vault
    can download from the downloadable subtree but not the view-only one; both are visible."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("vomix"))
    try:
        A = _mkfolder(admin, v["id"], "viewonly")
        B = _mkfolder(admin, v["id"], "downloadable")
        _upload(admin, v["id"], "va.txt", folder_id=A, content=b"va")
        _upload(admin, v["id"], "db.txt", folder_id=B, content=b"db")
        va = _file_id(admin, v["id"], "va.txt", folder_id=A)
        dbid = _file_id(admin, v["id"], "db.txt", folder_id=B)
        tag = _tag(admin)
        _claim(temp_user_client, _make_share(admin, v, tag, view_only=True, target_type="folder", target_folder_id=A))
        _claim(temp_user_client, _make_share(admin, v, tag, target_type="folder", target_folder_id=B))
        # both folders visible
        assert {"viewonly", "downloadable"} <= _names(temp_user_client, v["id"])
        # view-only subtree: no download; downloadable subtree: download ok
        assert temp_user_client.get(f"/vaults/{v['id']}/files/{va}/download").status_code == 403
        r = temp_user_client.get(f"/vaults/{v['id']}/files/{dbid}/download")
        assert r.status_code == 200 and r.content == b"db", r.text
    finally:
        admin.delete_vault(v["id"])


def test_share_download_is_audited(admin, temp_user, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("voaud"))
    try:
        _upload(admin, v["id"], "g.txt", content=b"g")
        g = _file_id(admin, v["id"], "g.txt")
        _claim(temp_user_client, _make_share(admin, v, _tag(admin)))
        assert temp_user_client.get(f"/vaults/{v['id']}/files/{g}/download").status_code == 200
        n = _psql_out(f"SELECT count(*) FROM audit_logs WHERE action='share_downloaded' "
                      f"AND user_id='{temp_user['id']}' AND resource_id='{g}'")
        assert int(n or "0") >= 1
    finally:
        admin.delete_vault(v["id"])
