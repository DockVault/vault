"""Per-recipient max_downloads on shares.

A share's max_downloads caps how many times EACH recipient may download (per-recipient): the
count is atomically consumed against the recipient's ShareClaim before the bytes are served, so a
recipient is cut off after N and one recipient's downloads never consume another's. An unlimited
share (no max_downloads) is never capped.
"""
import os
import subprocess

from conftest import ApiClient, unique

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql_out(sql):
    r = subprocess.run(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                       capture_output=True, text=True, timeout=20)
    return (r.stdout or "").strip()


def _enable_sharing(admin, on=True):
    assert admin.put("/settings", json={"sharing_enabled": on}).status_code == 200


def _tag(admin, **over):
    body = {"name": unique("dltag"), "auto_enroll_new_users": True,
            "allowed_audiences": ["anyone_internal"], "max_recipients_cap": 10, "max_downloads_cap": 100}
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


def _upload(admin, vid, name, content=b"data"):
    r = admin.post(f"/vaults/{vid}/files", files=[("files", (name, content, "text/plain"))])
    assert r.status_code in (200, 201), r.text


def _file_id(admin, vid, name):
    for it in admin.get(f"/vaults/{vid}/files").json()["items"]:
        if it.get("name") == name and it.get("type") == "file":
            return it["id"]
    raise AssertionError(f"file {name} not found")


def _claim(client, share):
    assert client.post("/shares/claim", json={"token": share["link_token"]}).status_code == 200


def _second_user(admin):
    u = admin.create_user(role="user")
    c = ApiClient()
    c.login(u["_username"], u["_password"])
    return u, c


def _dl(client, vid, fid):
    return client.get(f"/vaults/{vid}/files/{fid}/download").status_code


def test_max_downloads_enforced(admin, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("dle"))
    try:
        _upload(admin, v["id"], "f.txt", content=b"payload")
        f = _file_id(admin, v["id"], "f.txt")
        _claim(temp_user_client, _make_share(admin, v, _tag(admin), max_downloads=2))
        assert _dl(temp_user_client, v["id"], f) == 200   # 1
        assert _dl(temp_user_client, v["id"], f) == 200   # 2
        assert _dl(temp_user_client, v["id"], f) == 403    # over the cap
    finally:
        admin.delete_vault(v["id"])


def test_max_downloads_is_per_recipient(admin, temp_user_client):
    """Each recipient gets their own budget; one recipient's downloads never consume another's."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("dlpr"))
    u2, c2 = _second_user(admin)
    try:
        _upload(admin, v["id"], "g.txt", content=b"g")
        g = _file_id(admin, v["id"], "g.txt")
        share = _make_share(admin, v, _tag(admin), max_downloads=1)
        _claim(temp_user_client, share)
        _claim(c2, share)
        # each recipient gets exactly one
        assert _dl(temp_user_client, v["id"], g) == 200
        assert _dl(c2, v["id"], g) == 200
        # ...and each is then cut off independently
        assert _dl(temp_user_client, v["id"], g) == 403
        assert _dl(c2, v["id"], g) == 403
    finally:
        admin.delete_user(u2["id"])
        admin.delete_vault(v["id"])


def test_unlimited_share_is_never_capped(admin, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("dlu"))
    try:
        _upload(admin, v["id"], "u.txt", content=b"u")
        f = _file_id(admin, v["id"], "u.txt")
        _claim(temp_user_client, _make_share(admin, v, _tag(admin)))  # no max_downloads = unlimited
        for _ in range(4):
            assert _dl(temp_user_client, v["id"], f) == 200
    finally:
        admin.delete_vault(v["id"])


def test_download_count_increments_on_claim(admin, temp_user, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("dlc"))
    try:
        _upload(admin, v["id"], "c.txt", content=b"c")
        f = _file_id(admin, v["id"], "c.txt")
        share = _make_share(admin, v, _tag(admin), max_downloads=5)
        _claim(temp_user_client, share)
        assert _dl(temp_user_client, v["id"], f) == 200
        assert _dl(temp_user_client, v["id"], f) == 200
        cnt = _psql_out(f"SELECT download_count FROM share_claims "
                        f"WHERE share_id='{share['id']}' AND user_id='{temp_user['id']}'")
        assert cnt == "2", f"expected download_count 2, got {cnt!r}"
    finally:
        admin.delete_vault(v["id"])
