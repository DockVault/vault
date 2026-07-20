"""GET /shares/shared-with-me — the recipient's claimed-shares list (backs the "Shared" tab)."""
import os
import subprocess

from conftest import ApiClient, unique

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql):
    subprocess.run(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                   capture_output=True, text=True, timeout=20)


def _enable_sharing(admin, on=True):
    assert admin.put("/settings", json={"sharing_enabled": on}).status_code == 200


def _tag(admin, **over):
    body = {"name": unique("swtag"), "auto_enroll_new_users": True,
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


def _claim(client, share):
    assert client.post("/shares/claim", json={"token": share["link_token"]}).status_code == 200


def test_shared_with_me_lists_claim_with_metadata(admin, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("swv"))
    try:
        share = _make_share(admin, v, _tag(admin))
        _claim(temp_user_client, share)
        rows = temp_user_client.get("/shares/shared-with-me").json()
        row = next(r for r in rows if r["share_id"] == share["id"])
        assert row["vault_id"] == v["id"]
        assert row["vault_name"] == v["name"]
        assert row["target_type"] == "vault"
        assert row["status"] == "active"
        assert "token" not in row and "link_token" not in row
    finally:
        admin.delete_vault(v["id"])


def test_shared_with_me_shows_revoked_and_expired_status(admin, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("swrs"))
    try:
        s1 = _make_share(admin, v, _tag(admin))
        _claim(temp_user_client, s1)
        assert admin.post(f"/shares/{s1['id']}/revoke").status_code == 200
        s2 = _make_share(admin, v, _tag(admin))
        _claim(temp_user_client, s2)
        _psql(f"UPDATE shares SET expires_at = now() - interval '1 hour' WHERE id='{s2['id']}'")
        rows = {r["share_id"]: r for r in temp_user_client.get("/shares/shared-with-me").json()}
        assert rows[s1["id"]]["status"] == "revoked"
        assert rows[s2["id"]]["status"] == "expired"
    finally:
        admin.delete_vault(v["id"])


def test_shared_with_me_empty_for_temp_session(admin):
    _enable_sharing(admin, True)
    creds = admin.post("/auth/temp-credentials", json={"validity_minutes": 30}).json()
    temp = ApiClient()
    temp.login(creds["temp_username"], creds["credential"])
    assert temp.get("/shares/shared-with-me").json() == []
