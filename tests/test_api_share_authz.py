"""Whole-vault share AUTHORIZATION (the read+download access grant).

A recipient who holds an active claim on a whole-vault share may OPEN the vault, LIST its
contents, and DOWNLOAD its files — read-only — over the web endpoints. Everything else is
fail-closed: no claim, a revoked claim, a revoked/expired share, a vault that gained a
password or became zero-knowledge, and any write/delete op are all denied. A view-only share
grants open/list but denies download (see test_api_share_viewonly.py). The SFTP fail-closed
guarantee is proven in test_sftp_share_denied.py.
"""
import os
import subprocess

from conftest import unique

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql):
    subprocess.run(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                   capture_output=True, text=True, timeout=20)


def _psql_out(sql):
    r = subprocess.run(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                       capture_output=True, text=True, timeout=20)
    return (r.stdout or "").strip()


def _enable_sharing(admin, on=True):
    assert admin.put("/settings", json={"sharing_enabled": on}).status_code == 200


def _tag(admin, **over):
    body = {"name": unique("aztag"), "auto_enroll_new_users": True,
            "allowed_audiences": ["users", "departments", "anyone_internal"], "max_recipients_cap": 10}
    body.update(over)
    r = admin.post("/share-tags", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def _make_share(admin, v, tag, **over):
    body = {"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault", "claim_audience": "anyone_internal"}
    body.update(over)
    r = admin.post("/shares", json=body)
    assert r.status_code == 200, r.text
    return r.json()  # includes the show-once link_token


def _upload(admin, vault_id, name, content):
    r = admin.post(f"/vaults/{vault_id}/files",
                   files=[("files", (name, content, "application/octet-stream"))])
    assert r.status_code in (200, 201), r.text
    return r.json()["files"][0]["id"]


def _claim(client, share):
    r = client.post("/shares/claim", json={"token": share["link_token"]})
    assert r.status_code == 200, r.text
    return r.json()


def test_recipient_with_claim_can_open_list_download(admin, temp_user_client):
    """The grant works end to end: open (my_permission=read), list (sees the file), download
    (byte-identical) — read-only access via an active whole-vault claim."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("azok"))
    try:
        content = b"shared-whole-vault-bytes-" * 8
        fid = _upload(admin, v["id"], "hello.txt", content)
        share = _make_share(admin, v, _tag(admin))
        _claim(temp_user_client, share)

        r = temp_user_client.get(f"/vaults/{v['id']}")
        assert r.status_code == 200, r.text
        assert r.json()["my_permission"] == "read"

        r = temp_user_client.get(f"/vaults/{v['id']}/files")
        assert r.status_code == 200, r.text
        assert "hello.txt" in [it["name"] for it in r.json()["items"]]

        r = temp_user_client.get(f"/vaults/{v['id']}/files/{fid}/download")
        assert r.status_code == 200, r.text
        assert r.content == content
    finally:
        admin.delete_vault(v["id"])


def test_non_claimant_denied_everywhere(admin, temp_user_client):
    """A user who never claimed the share gets nothing, even though a share exists."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("aznc"))
    try:
        fid = _upload(admin, v["id"], "secret.txt", b"nope")
        _make_share(admin, v, _tag(admin))  # exists, but this user never claims it
        assert temp_user_client.get(f"/vaults/{v['id']}").status_code == 403
        assert temp_user_client.get(f"/vaults/{v['id']}/files").status_code == 403
        assert temp_user_client.get(f"/vaults/{v['id']}/files/{fid}/download").status_code == 403
    finally:
        admin.delete_vault(v["id"])


def test_revoked_claim_denied_access(admin, temp_user, temp_user_client):
    """A single-recipient kick (claim.revoked=true) revokes access LIVE."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("azrc"))
    try:
        share = _make_share(admin, v, _tag(admin))
        _claim(temp_user_client, share)
        assert temp_user_client.get(f"/vaults/{v['id']}").status_code == 200
        _psql(f"UPDATE share_claims SET revoked=true WHERE share_id='{share['id']}' AND user_id='{temp_user['id']}'")
        assert temp_user_client.get(f"/vaults/{v['id']}").status_code == 403
        assert temp_user_client.get(f"/vaults/{v['id']}/files").status_code == 403
    finally:
        admin.delete_vault(v["id"])


def test_revoked_share_denies_access(admin, temp_user_client):
    """Revoking the whole share (status='revoked') denies every claimant LIVE."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("azrs"))
    try:
        share = _make_share(admin, v, _tag(admin))
        _claim(temp_user_client, share)
        assert temp_user_client.get(f"/vaults/{v['id']}").status_code == 200
        _psql(f"UPDATE shares SET status='revoked' WHERE id='{share['id']}'")
        assert temp_user_client.get(f"/vaults/{v['id']}").status_code == 403
    finally:
        admin.delete_vault(v["id"])


def test_expired_share_denies_access(admin, temp_user_client):
    """A share past its expiry denies access even to an existing claimant."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("azex"))
    try:
        share = _make_share(admin, v, _tag(admin))
        _claim(temp_user_client, share)
        assert temp_user_client.get(f"/vaults/{v['id']}").status_code == 200
        _psql(f"UPDATE shares SET expires_at = now() - interval '1 hour' WHERE id='{share['id']}'")
        assert temp_user_client.get(f"/vaults/{v['id']}").status_code == 403
        assert temp_user_client.get(f"/vaults/{v['id']}/files").status_code == 403
    finally:
        admin.delete_vault(v["id"])


def test_password_added_after_claim_denies_access(admin, temp_user_client):
    """A vault password added AFTER the claim must close the share grant."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("azpw"))
    try:
        share = _make_share(admin, v, _tag(admin))
        _claim(temp_user_client, share)
        assert temp_user_client.get(f"/vaults/{v['id']}").status_code == 200
        _psql(f"UPDATE vaults SET password_hash='x' WHERE id='{v['id']}'")
        assert temp_user_client.get(f"/vaults/{v['id']}").status_code == 403
        assert temp_user_client.get(f"/vaults/{v['id']}/files").status_code == 403
        _psql(f"UPDATE vaults SET password_hash=NULL WHERE id='{v['id']}'")  # restore for teardown
    finally:
        admin.delete_vault(v["id"])


def test_zk_vault_denies_share_access(admin, temp_user_client):
    """A vault flipped to zero-knowledge must not be opened by a share claim."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("azzk"))
    try:
        share = _make_share(admin, v, _tag(admin))
        _claim(temp_user_client, share)
        assert temp_user_client.get(f"/vaults/{v['id']}").status_code == 200
        _psql(f"UPDATE vaults SET type='zero_knowledge' WHERE id='{v['id']}'")
        assert temp_user_client.get(f"/vaults/{v['id']}").status_code == 403
        _psql(f"UPDATE vaults SET type='standard' WHERE id='{v['id']}'")  # restore for teardown
    finally:
        admin.delete_vault(v["id"])


def test_view_only_share_allows_open_but_not_download(admin, temp_user_client):
    """A view-only whole-vault share lets the recipient OPEN the vault (see-only); download is
    denied on the download path (thorough view-only coverage is in test_api_share_viewonly.py)."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("azvo"))
    try:
        fid = _upload(admin, v["id"], "vo.txt", b"view-only-bytes")
        share = _make_share(admin, v, _tag(admin), view_only=True)
        _claim(temp_user_client, share)
        assert temp_user_client.get(f"/vaults/{v['id']}").status_code == 200          # can open
        assert temp_user_client.get(f"/vaults/{v['id']}/files/{fid}/download").status_code == 403  # no download
    finally:
        admin.delete_vault(v["id"])


def test_recipient_cannot_write(admin, temp_user_client):
    """The grant is read-only: a claimant cannot upload to (write) the shared vault."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("azwr"))
    try:
        share = _make_share(admin, v, _tag(admin))
        _claim(temp_user_client, share)
        assert temp_user_client.get(f"/vaults/{v['id']}").status_code == 200  # read ok
        r = temp_user_client.post(f"/vaults/{v['id']}/files",
                                  files=[("files", ("x.txt", b"x", "application/octet-stream"))])
        assert r.status_code == 403, r.text  # write denied
    finally:
        admin.delete_vault(v["id"])


def test_disabling_sharing_org_wide_cuts_existing_access(admin, temp_user_client):
    """The deployment-wide sharing switch is a LIVE kill-switch: disabling it denies an existing
    claimant immediately, and re-enabling restores access."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("azks"))
    try:
        share = _make_share(admin, v, _tag(admin))
        _claim(temp_user_client, share)
        assert temp_user_client.get(f"/vaults/{v['id']}").status_code == 200
        _enable_sharing(admin, False)
        assert temp_user_client.get(f"/vaults/{v['id']}").status_code == 403
        assert temp_user_client.get(f"/vaults/{v['id']}/files").status_code == 403
        _enable_sharing(admin, True)
        assert temp_user_client.get(f"/vaults/{v['id']}").status_code == 200
    finally:
        _enable_sharing(admin, True)
        admin.delete_vault(v["id"])


def test_share_open_is_audited(admin, temp_user, temp_user_client):
    """Opening a vault via a share claim writes a 'share_opened' audit row for the claimant."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("azau"))
    try:
        share = _make_share(admin, v, _tag(admin))
        _claim(temp_user_client, share)
        assert temp_user_client.get(f"/vaults/{v['id']}").status_code == 200
        n = _psql_out(f"SELECT count(*) FROM audit_logs WHERE action='share_opened' "
                      f"AND user_id='{temp_user['id']}'")
        assert int(n or "0") >= 1
    finally:
        admin.delete_vault(v["id"])
