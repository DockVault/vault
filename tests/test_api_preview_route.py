"""The preview route: GET /vaults/{id}/files/{fid}/preview.

The file's bytes for the browser to show, not to save: served inline, never cached, recorded as a preview
(file_previewed, file_preview_completed; share_previewed for a share recipient). A view-only share's recipient,
who cannot download, may read through it. For a capped share, previews are counted apart from downloads against
the same per-recipient cap, so a preview spends no download and a download no preview. Everything else is the
download route's: a stranger is refused, a temporary credential without the download capability is refused, a
zero-knowledge vault's file is ciphertext either way.
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
    out = _psql(f"SELECT action || ':' || status FROM audit_logs WHERE resource_id='{file_id}' "
                "AND resource_type='file' ORDER BY timestamp, id")
    return [line for line in out.splitlines() if line]


def _upload(client, vault_id, name, content):
    r = client.post(f"/vaults/{vault_id}/files", files=[("files", (name, content, "text/plain"))])
    assert r.status_code == 200, r.text
    return next(f["id"] for f in client.get(f"/vaults/{vault_id}/files").json()["items"] if f["name"] == name)


@pytest.fixture
def sharing(admin):
    before = admin.get("/settings").json().get("sharing_enabled")
    admin.put("/settings", json={"sharing_enabled": True})
    yield
    admin.put("/settings", json={"sharing_enabled": before})


def _tag(admin, **over):
    body = {"name": unique("pvtag"), "auto_enroll_new_users": True, "allowed_audiences": ["anyone_internal"],
            "max_recipients_cap": 10, "max_downloads_cap": 5, "allow_view_only": True}
    body.update(over)
    r = admin.post("/share-tags", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def _share(admin, vault, tag, **over):
    body = {"vault_id": vault["id"], "tag_id": tag["id"], "target_type": "vault", "claim_audience": "anyone_internal"}
    body.update(over)
    r = admin.post("/shares", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def test_a_preview_is_inline_uncached_and_recorded_as_a_preview(admin, temp_vault):
    fid = _upload(admin, temp_vault["id"], unique("p") + ".txt", b"shown, not saved\n" * 20)
    before = _actions(fid)
    r = admin.get(f"/vaults/{temp_vault['id']}/files/{fid}/preview")
    assert r.status_code == 200 and r.content.startswith(b"shown, not saved")
    assert r.headers["Content-Disposition"].startswith("inline;") and "filename" in r.headers["Content-Disposition"]
    assert "no-store" in r.headers["Cache-Control"]
    assert _actions(fid)[len(before):] == ["file_previewed:authorized", "file_preview_completed:success"]
    # A download is still an attachment, recorded as a download.
    d = admin.get(f"/vaults/{temp_vault['id']}/files/{fid}/download")
    assert d.headers["Content-Disposition"].startswith("attachment;")
    assert _actions(fid)[-2:] == ["file_download:authorized", "file_download_completed:success"]


def test_a_stranger_and_a_credential_without_download_are_refused(admin, temp_vault, temp_user_client):
    fid = _upload(admin, temp_vault["id"], unique("p") + ".txt", b"x")
    assert temp_user_client.get(f"/vaults/{temp_vault['id']}/files/{fid}/preview").status_code == 403
    # A scoped temporary credential of the owner with every capability but the download.
    scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": ["vault.see_info", "vault.see_files"], "temp": {}}
    made = admin.post("/auth/temp-credentials", json={"validity_minutes": 30, "scope": scope,
                                                       "vault_access_mode": "all", "selected_vaults": []})
    assert made.status_code == 200, made.text
    cred = made.json()
    c = ApiClient()
    try:
        c.login(cred["temp_username"], cred["credential"])
        assert c.get(f"/vaults/{temp_vault['id']}/files/{fid}/preview").status_code == 403
        assert c.get(f"/vaults/{temp_vault['id']}/files/{fid}/download").status_code == 403
    finally:
        admin.post(f"/temp-creds/{cred['temp_username']}/delete")


def test_a_view_only_recipient_previews_and_never_downloads(admin, sharing, temp_user_client):
    vault = admin.create_vault(name=unique("vo"))
    try:
        fid = _upload(admin, vault["id"], "deck.txt", b"the deck")
        share = _share(admin, vault, _tag(admin), view_only=True)
        assert temp_user_client.post("/shares/claim", json={"token": share["link_token"]}).status_code == 200
        before = _actions(fid)
        p = temp_user_client.get(f"/vaults/{vault['id']}/files/{fid}/preview")
        assert p.status_code == 200 and p.content == b"the deck", p.text
        assert p.headers["Content-Disposition"].startswith("inline;")
        assert temp_user_client.get(f"/vaults/{vault['id']}/files/{fid}/download").status_code == 403
        new = _actions(fid)[len(before):]
        assert new == ["file_previewed:authorized", "share_previewed:success", "file_preview_completed:success"], new
        # The recipient's row counts the preview, not a download.
        claims = admin.get(f"/shares/{share['id'] if 'id' in share else share['share_id']}/claims").json()
        me = next(c for c in claims if c["username"] == temp_user_client.user["username"]) if hasattr(temp_user_client, "user") and temp_user_client.user else claims[0]
        assert me["preview_count"] == 1 and me["download_count"] == 0
    finally:
        admin.delete_vault(vault["id"])


def test_previews_and_downloads_have_separate_budgets_under_one_cap(admin, sharing, temp_user_client):
    vault = admin.create_vault(name=unique("cap"))
    try:
        fid = _upload(admin, vault["id"], "once.txt", b"once")
        share = _share(admin, vault, _tag(admin), max_downloads=1)
        assert temp_user_client.post("/shares/claim", json={"token": share["link_token"]}).status_code == 200
        base = f"/vaults/{vault['id']}/files/{fid}"
        assert temp_user_client.get(base + "/preview").status_code == 200
        # The preview spent no download: the one download is still there, and spends no preview.
        assert temp_user_client.get(base + "/download").status_code == 200
        again = temp_user_client.get(base + "/preview")
        assert again.status_code == 403 and "preview limit" in again.text, again.text
        again = temp_user_client.get(base + "/download")
        assert again.status_code == 403 and "download limit" in again.text, again.text
        sid = share["id"] if "id" in share else share["share_id"]
        me = admin.get(f"/shares/{sid}/claims").json()[0]
        assert (me["preview_count"], me["download_count"]) == (1, 1)
    finally:
        admin.delete_vault(vault["id"])


def test_an_unlimited_share_counts_nothing(admin, sharing, temp_user_client):
    vault = admin.create_vault(name=unique("free"))
    try:
        fid = _upload(admin, vault["id"], "free.txt", b"free")
        share = _share(admin, vault, _tag(admin, max_downloads_cap=None))  # no cap from the tag either
        assert share["max_downloads"] is None, share
        assert temp_user_client.post("/shares/claim", json={"token": share["link_token"]}).status_code == 200
        for _ in range(3):
            assert temp_user_client.get(f"/vaults/{vault['id']}/files/{fid}/preview").status_code == 200
        sid = share["id"] if "id" in share else share["share_id"]
        me = admin.get(f"/shares/{sid}/claims").json()[0]
        assert (me["preview_count"], me["download_count"]) == (0, 0)
    finally:
        admin.delete_vault(vault["id"])


def test_a_preview_of_svg_or_html_is_plain_text_under_a_sandbox_and_a_download_is_not(admin):
    v = admin.create_vault(name=unique("pvsafe"))
    try:
        svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
        html = b"<html><body><script>alert(2)</script></body></html>"
        for name, content, mime in (("x.svg", svg, "image/svg+xml"), ("x.html", html, "text/html")):
            r = admin.post(f"/vaults/{v['id']}/files", files=[("files", (name, content, mime))])
            assert r.status_code == 200, r.text
            fid = next(f["id"] for f in admin.get(f"/vaults/{v['id']}/files").json()["items"] if f["name"] == name)
            p = admin.get(f"/vaults/{v['id']}/files/{fid}/preview")
            assert p.status_code == 200, p.text
            assert p.headers["content-type"].startswith("text/plain"), (name, p.headers["content-type"])
            assert p.headers["content-security-policy"] == "default-src 'none'; sandbox"
            assert p.headers["x-content-type-options"] == "nosniff"
            assert p.content == content
            # A ranged preview is answered the same way.
            rp = admin.get(f"/vaults/{v['id']}/files/{fid}/preview", headers={"Range": "bytes=0-9"})
            if rp.status_code == 206:
                assert rp.headers["content-type"].startswith("text/plain")
                assert rp.headers["content-security-policy"] == "default-src 'none'; sandbox"
            # A download keeps the stored type and saves the file.
            d = admin.get(f"/vaults/{v['id']}/files/{fid}/download")
            assert d.status_code == 200 and "attachment" in d.headers.get("content-disposition", "")
            assert d.headers["content-type"].startswith(mime)
    finally:
        admin.delete_vault(v["id"])
