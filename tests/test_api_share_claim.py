"""Claim a share by token (POST /shares/claim). No access grant yet — this creates the ShareClaim.

Covers the fail-closed claim path (bad token, expired/revoked share, wrong audience, recipient limit,
temp session, sharing off, a vault that gained a password) and the happy path (idempotent re-open,
claim reflected in the creator's claim_count) for each audience.
"""
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
    body = {"name": unique("cltag"), "auto_enroll_new_users": True,
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


def test_claim_anyone_internal_idempotent_and_counted(admin, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("clv"))
    try:
        share = _make_share(admin, v, _tag(admin))
        r = temp_user_client.post("/shares/claim", json={"token": share["link_token"]})
        assert r.status_code == 200, r.text
        claim = r.json()
        assert claim["share_id"] == share["id"] and claim["vault_id"] == v["id"] and "token" not in claim
        # idempotent re-open -> same claim id, no duplicate
        r2 = temp_user_client.post("/shares/claim", json={"token": share["link_token"]})
        assert r2.status_code == 200 and r2.json()["claim_id"] == claim["claim_id"]
        # the creator's list now shows one claim
        row = next(s for s in admin.get("/shares").json() if s["id"] == share["id"])
        assert row["claim_count"] == 1
    finally:
        admin.delete_vault(v["id"])


def test_claim_bad_token_404(admin, temp_user_client):
    _enable_sharing(admin, True)
    assert temp_user_client.post("/shares/claim", json={"token": "not-a-real-token-xyz"}).status_code == 404


def test_claim_users_audience_enforced(admin, temp_user, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("clu"))
    tag = _tag(admin)
    other = admin.create_user(role="user")
    try:
        # share addressed to ANOTHER user -> temp_user is not in the audience
        s1 = _make_share(admin, v, tag, claim_audience="users", audience_user_ids=[other["id"]])
        assert temp_user_client.post("/shares/claim", json={"token": s1["link_token"]}).status_code == 403
        # share whose audience INCLUDES temp_user -> claim ok
        s2 = _make_share(admin, v, tag, claim_audience="users", audience_user_ids=[temp_user["id"]])
        assert temp_user_client.post("/shares/claim", json={"token": s2["link_token"]}).status_code == 200
    finally:
        admin.delete_user(other["id"])
        admin.delete_vault(v["id"])


def test_claim_departments_audience_enforced(admin, temp_user, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("cld"))
    g = admin.post("/groups", json={"name": unique("cldept")}).json()
    assert admin.post(f"/groups/{g['id']}/members", json={"user_ids": [temp_user["id"]]}).status_code in (200, 201)
    u2 = admin.create_user(role="user")
    try:
        share = _make_share(admin, v, _tag(admin), claim_audience="departments", audience_department_ids=[g["id"]])
        assert temp_user_client.post("/shares/claim", json={"token": share["link_token"]}).status_code == 200
        c2 = ApiClient()
        c2.login(u2["_username"], u2["_password"])  # not in the department
        assert c2.post("/shares/claim", json={"token": share["link_token"]}).status_code == 403
    finally:
        admin.delete_user(u2["id"])
        admin.delete_vault(v["id"])
        admin.delete(f"/groups/{g['id']}")


def test_claim_max_recipients_enforced(admin, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("clm"))
    u2 = admin.create_user(role="user")
    try:
        share = _make_share(admin, v, _tag(admin), max_recipients=1)
        assert temp_user_client.post("/shares/claim", json={"token": share["link_token"]}).status_code == 200
        c2 = ApiClient()
        c2.login(u2["_username"], u2["_password"])
        assert c2.post("/shares/claim", json={"token": share["link_token"]}).status_code == 409
        # an EXISTING claimant may still re-open even at a full cap (idempotency is checked BEFORE the limit)
        assert temp_user_client.post("/shares/claim", json={"token": share["link_token"]}).status_code == 200
    finally:
        admin.delete_user(u2["id"])
        admin.delete_vault(v["id"])


def test_revoked_claim_is_not_reopened(admin, temp_user, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("clrv"))
    try:
        share = _make_share(admin, v, _tag(admin))
        assert temp_user_client.post("/shares/claim", json={"token": share["link_token"]}).status_code == 200
        # the creator kicks this recipient (single-recipient revoke); re-claiming must NOT reactivate it
        _psql(f"UPDATE share_claims SET revoked=true WHERE share_id='{share['id']}' AND user_id='{temp_user['id']}'")
        assert temp_user_client.post("/shares/claim", json={"token": share["link_token"]}).status_code == 403
        # and no active claim was resurrected
        row = next(s for s in admin.get("/shares").json() if s["id"] == share["id"])
        assert row["claim_count"] == 0
    finally:
        admin.delete_vault(v["id"])


def test_claim_refused_if_vault_becomes_zk(admin, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("clzk"))
    try:
        share = _make_share(admin, v, _tag(admin))
        _psql(f"UPDATE vaults SET type='zero_knowledge' WHERE id='{v['id']}'")
        assert temp_user_client.post("/shares/claim", json={"token": share["link_token"]}).status_code == 403
        _psql(f"UPDATE vaults SET type='standard' WHERE id='{v['id']}'")  # restore so teardown works
    finally:
        admin.delete_vault(v["id"])


def test_claim_expired_and_revoked_share_gone(admin, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("cle"))
    try:
        s1 = _make_share(admin, v, _tag(admin))
        _psql(f"UPDATE shares SET expires_at = now() - interval '1 hour' WHERE id='{s1['id']}'")
        assert temp_user_client.post("/shares/claim", json={"token": s1["link_token"]}).status_code == 410
        s2 = _make_share(admin, v, _tag(admin))
        _psql(f"UPDATE shares SET status='revoked' WHERE id='{s2['id']}'")
        assert temp_user_client.post("/shares/claim", json={"token": s2["link_token"]}).status_code == 410
    finally:
        admin.delete_vault(v["id"])


def test_claim_refused_for_temp_session_and_sharing_off(admin, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("clt"))
    try:
        share = _make_share(admin, v, _tag(admin))
        creds = admin.post("/auth/temp-credentials", json={"validity_minutes": 30}).json()
        temp = ApiClient()
        temp.login(creds["temp_username"], creds["credential"])
        assert temp.post("/shares/claim", json={"token": share["link_token"]}).status_code == 403
        _enable_sharing(admin, False)
        assert temp_user_client.post("/shares/claim", json={"token": share["link_token"]}).status_code == 403
    finally:
        _enable_sharing(admin, True)
        admin.delete_vault(v["id"])


def test_claim_refused_if_vault_gains_password(admin, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("clpw"))
    try:
        share = _make_share(admin, v, _tag(admin))
        # a vault password added AFTER the share was created must not be opened by a claim (defense-in-depth)
        _psql(f"UPDATE vaults SET password_hash='x' WHERE id='{v['id']}'")
        assert temp_user_client.post("/shares/claim", json={"token": share["link_token"]}).status_code == 403
        _psql(f"UPDATE vaults SET password_hash=NULL WHERE id='{v['id']}'")
    finally:
        admin.delete_vault(v["id"])
