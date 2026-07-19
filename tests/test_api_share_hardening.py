"""Share hardening / edge cases: the download endpoint serves the full object (no partial/Range
responses), so a Range header cannot bypass max_downloads; and revoke/expiry take effect on the very
next request (live, no session to expire).
"""
from conftest import unique


def _enable_sharing(admin, on=True):
    assert admin.put("/settings", json={"sharing_enabled": on}).status_code == 200


def _tag(admin):
    r = admin.post("/share-tags", json={"name": unique("hdtag"), "auto_enroll_new_users": True,
                                        "allowed_audiences": ["anyone_internal"],
                                        "max_recipients_cap": 10, "max_downloads_cap": 100})
    assert r.status_code == 200, r.text
    return r.json()


def _make_share(admin, v, **over):
    body = {"vault_id": v["id"], "tag_id": _tag(admin)["id"], "target_type": "vault",
            "claim_audience": "anyone_internal"}
    body.update(over)
    r = admin.post("/shares", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def _upload(admin, vid, name, content=b"payload"):
    r = admin.post(f"/vaults/{vid}/files", files=[("files", (name, content, "text/plain"))])
    assert r.status_code in (200, 201), r.text
    return next(it["id"] for it in admin.get(f"/vaults/{vid}/files").json()["items"] if it["name"] == name)


def _claim(client, share):
    assert client.post("/shares/claim", json={"token": share["link_token"]}).status_code == 200


def test_range_request_does_not_bypass_max_downloads(admin, temp_user_client):
    """The endpoint serves the full object regardless of Range, so a Range GET consumes a download
    slot just like a normal GET — no free downloads by sending a Range header."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("hrng"))
    try:
        fid = _upload(admin, v["id"], "r.txt", b"x" * 500)
        share = _make_share(admin, v, max_downloads=1)
        _claim(temp_user_client, share)
        # a Range download counts as the single allowed download; the endpoint serves the FULL object
        # (status 200, all 500 bytes, no partial 206) — Range is ignored, so it can't be a cheap peek.
        r1 = temp_user_client.get(f"/vaults/{v['id']}/files/{fid}/download", headers={"Range": "bytes=0-10"})
        assert r1.status_code == 200 and len(r1.content) == 500, (r1.status_code, len(r1.content))
        # the cap is now spent — neither a Range nor a full GET gets more
        assert temp_user_client.get(f"/vaults/{v['id']}/files/{fid}/download",
                                    headers={"Range": "bytes=0-10"}).status_code == 403
        assert temp_user_client.get(f"/vaults/{v['id']}/files/{fid}/download").status_code == 403
    finally:
        admin.delete_vault(v["id"])


def test_revoke_denies_the_next_download_live(admin, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("hrev"))
    try:
        fid = _upload(admin, v["id"], "a.txt", b"data")
        share = _make_share(admin, v)  # unlimited downloads
        _claim(temp_user_client, share)
        assert temp_user_client.get(f"/vaults/{v['id']}/files/{fid}/download").status_code == 200
        # revoking is live: the very next request is denied
        assert admin.post(f"/shares/{share['id']}/revoke").status_code == 200
        assert temp_user_client.get(f"/vaults/{v['id']}/files/{fid}/download").status_code == 403
    finally:
        admin.delete_vault(v["id"])
