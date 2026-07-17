"""The admin 'Allowed File Types' + 'Max File Size' settings are enforced on upload."""


def _set(admin, **kw):
    r = admin.put("/settings", json=kw)
    assert r.status_code in (200, 204), r.text


def _reset(admin):
    _set(admin, allowed_file_types=[], max_file_size=0)  # allow everything, env cap


def _upload(client, vid, name, content):
    return client.post(f"/vaults/{vid}/files",
                       files=[("files", (name, content, "application/octet-stream"))])


def test_allowed_file_type_rejects_others(admin, temp_vault):
    vid = temp_vault["id"]
    _set(admin, allowed_file_types=["txt"])
    try:
        bad = _upload(admin, vid, "report.pdf", b"nope")
        assert bad.status_code == 400, bad.text
        assert "not permitted" in bad.text.lower()
        ok = _upload(admin, vid, "note.txt", b"fine")
        assert ok.status_code == 200, ok.text
    finally:
        _reset(admin)


def test_empty_allowlist_allows_all(admin, temp_vault):
    vid = temp_vault["id"]
    _set(admin, allowed_file_types=[])
    try:
        r = _upload(admin, vid, "anything.xyz", b"hi")
        assert r.status_code == 200, r.text
    finally:
        _reset(admin)


def test_max_file_size_setting_enforced(admin, temp_vault):
    vid = temp_vault["id"]
    _set(admin, max_file_size=1)  # 1 MB per-file cap
    try:
        big = _upload(admin, vid, "big.txt", b"x" * (2 * 1024 * 1024))  # 2 MB
        assert big.status_code == 413, big.text
        small = _upload(admin, vid, "small.txt", b"ok")
        assert small.status_code == 200, small.text
    finally:
        _reset(admin)


def test_rename_to_disallowed_type_rejected(admin, temp_vault):
    # the allowlist must survive rename — upload an allowed type then try to rename to a forbidden one
    vid = temp_vault["id"]
    _set(admin, allowed_file_types=["txt"])
    try:
        r = _upload(admin, vid, "ok.txt", b"data")
        assert r.status_code == 200, r.text
        fid = r.json()["files"][0]["id"]
        bad = admin.put(f"/vaults/{vid}/files/{fid}/rename", json={"new_name": "sneaky.exe"})
        assert bad.status_code == 400, bad.text
        ok = admin.put(f"/vaults/{vid}/files/{fid}/rename", json={"new_name": "renamed.txt"})
        assert ok.status_code == 200, ok.text
    finally:
        _reset(admin)


def test_settings_validation_rejects_bad_upload_policy(admin):
    try:
        assert admin.put("/settings", json={"allowed_file_types": "pdf"}).status_code == 400
        assert admin.put("/settings", json={"allowed_file_types": [1, 2]}).status_code == 400
        assert admin.put("/settings", json={"max_file_size": -5}).status_code == 400
        assert admin.put("/settings", json={"allowed_file_types": ["pdf", "png"]}).status_code in (200, 204)
    finally:
        _reset(admin)
