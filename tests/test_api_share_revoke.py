"""Share revoke + per-recipient kick (POST /shares/{id}/revoke, POST /shares/{id}/claims/{uid}/revoke).

Revoking a share, or kicking one recipient, is a creator-or-admin action whose effect is LIVE — the
claimant loses access at the vault chokepoint on the next request (no session to expire). A kick is
isolated (other claimants keep access). Non-creators can't revoke; a temp session can't manage shares.
"""
from conftest import ApiClient, unique


def _enable_sharing(admin, on=True):
    assert admin.put("/settings", json={"sharing_enabled": on}).status_code == 200


def _tag(admin, **over):
    body = {"name": unique("rvtag"), "auto_enroll_new_users": True,
            "allowed_audiences": ["anyone_internal"], "max_recipients_cap": 10}
    body.update(over)
    r = admin.post("/share-tags", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def _make_share(client, v, tag, **over):
    body = {"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault", "claim_audience": "anyone_internal"}
    body.update(over)
    r = client.post("/shares", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def _claim(client, share):
    assert client.post("/shares/claim", json={"token": share["link_token"]}).status_code == 200


def _second_user(admin):
    u = admin.create_user(role="user")
    c = ApiClient()
    c.login(u["_username"], u["_password"])
    return u, c


def test_creator_revoke_denies_claimant_live(admin, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("rvc"))
    try:
        share = _make_share(admin, v, _tag(admin))
        _claim(temp_user_client, share)
        assert temp_user_client.get(f"/vaults/{v['id']}").status_code == 200
        r = admin.post(f"/shares/{share['id']}/revoke")
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "revoked"
        # access is denied LIVE on the next request
        assert temp_user_client.get(f"/vaults/{v['id']}").status_code == 403
        # and the creator's list reflects it
        row = next(s for s in admin.get("/shares").json() if s["id"] == share["id"])
        assert row["status"] == "revoked"
    finally:
        admin.delete_vault(v["id"])


def test_recipient_cannot_revoke(admin, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("rvnc"))
    try:
        share = _make_share(admin, v, _tag(admin))
        _claim(temp_user_client, share)
        # the recipient is neither creator nor admin -> cannot revoke
        assert temp_user_client.post(f"/shares/{share['id']}/revoke").status_code == 403
        # ...and still has access (the failed revoke changed nothing)
        assert temp_user_client.get(f"/vaults/{v['id']}").status_code == 200
    finally:
        admin.delete_vault(v["id"])


def test_admin_can_revoke_another_users_share(admin, temp_user_client):
    """A non-admin creates a share on their own vault; an admin can still revoke it."""
    _enable_sharing(admin, True)
    own = temp_user_client.create_vault(name=unique("rvown"))
    u2, c2 = _second_user(admin)
    try:
        share = _make_share(temp_user_client, own, _tag(admin))  # created by the non-admin owner
        _claim(c2, share)
        assert c2.get(f"/vaults/{own['id']}").status_code == 200
        assert admin.post(f"/shares/{share['id']}/revoke").status_code == 200
        assert c2.get(f"/vaults/{own['id']}").status_code == 403
    finally:
        admin.delete_user(u2["id"])
        temp_user_client.delete_vault(own["id"])


def test_per_recipient_kick_is_isolated(admin, temp_user, temp_user_client):
    """Kicking R1 denies only R1; R2 keeps access; the share itself stays active."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("rvk"))
    u2, c2 = _second_user(admin)
    try:
        share = _make_share(admin, v, _tag(admin))
        _claim(temp_user_client, share)   # R1 = temp_user
        _claim(c2, share)                 # R2 = u2
        assert temp_user_client.get(f"/vaults/{v['id']}").status_code == 200
        assert c2.get(f"/vaults/{v['id']}").status_code == 200
        # kick R1
        r = admin.post(f"/shares/{share['id']}/claims/{temp_user['id']}/revoke")
        assert r.status_code == 200 and r.json()["revoked"] is True
        assert temp_user_client.get(f"/vaults/{v['id']}").status_code == 403  # R1 out
        assert c2.get(f"/vaults/{v['id']}").status_code == 200                # R2 unaffected
        # the share is still active for the creator (only one claim was kicked)
        row = next(s for s in admin.get("/shares").json() if s["id"] == share["id"])
        assert row["status"] == "active" and row["claim_count"] == 1
    finally:
        admin.delete_user(u2["id"])
        admin.delete_vault(v["id"])


def test_kick_of_unclaimed_user_is_404(admin, temp_user):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("rvk404"))
    try:
        share = _make_share(admin, v, _tag(admin))  # nobody claims
        assert admin.post(f"/shares/{share['id']}/claims/{temp_user['id']}/revoke").status_code == 404
    finally:
        admin.delete_vault(v["id"])


def test_revoke_idempotent_and_temp_session_denied(admin, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("rvi"))
    try:
        share = _make_share(admin, v, _tag(admin))
        assert admin.post(f"/shares/{share['id']}/revoke").status_code == 200
        assert admin.post(f"/shares/{share['id']}/revoke").status_code == 200  # idempotent
        # a temp-credential session cannot manage shares
        creds = admin.post("/auth/temp-credentials", json={"validity_minutes": 30}).json()
        temp = ApiClient()
        temp.login(creds["temp_username"], creds["credential"])
        assert temp.post(f"/shares/{share['id']}/revoke").status_code == 403
    finally:
        admin.delete_vault(v["id"])
