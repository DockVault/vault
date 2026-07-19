"""GET /shares/{id}/claims — the creator/admin list of a share's recipients (backs the kick UI),
plus the tag_name/target_name fields on GET /shares (management cards)."""
from conftest import ApiClient, unique


def _enable_sharing(admin, on=True):
    assert admin.put("/settings", json={"sharing_enabled": on}).status_code == 200


def _tag(admin):
    name = unique("cltag")
    r = admin.post("/share-tags", json={"name": name, "auto_enroll_new_users": True,
                                        "allowed_audiences": ["anyone_internal"], "max_recipients_cap": 10})
    assert r.status_code == 200, r.text
    t = r.json(); t["_name"] = name
    return t


def _make_share(admin, v, tag, **over):
    body = {"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault", "claim_audience": "anyone_internal"}
    body.update(over)
    r = admin.post("/shares", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def test_claims_list_shows_recipients_and_download_usage(admin, temp_user, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("clv"))
    try:
        share = _make_share(admin, v, _tag(admin))
        assert temp_user_client.post("/shares/claim", json={"token": share["link_token"]}).status_code == 200
        claims = admin.get(f"/shares/{share['id']}/claims").json()
        row = next(c for c in claims if c["user_id"] == temp_user["id"])
        assert row["username"] == temp_user["_username"]
        assert row["revoked"] is False and row["download_count"] == 0
        assert "token" not in row
    finally:
        admin.delete_vault(v["id"])


def test_claims_list_creator_or_admin_only(admin, temp_user_client):
    _enable_sharing(admin, True)
    own = temp_user_client.create_vault(name=unique("clown"))
    u2, c2 = None, None
    try:
        # a non-admin creates a share on their own vault; a THIRD user can't list its claims
        tag = _tag(admin)
        share = _make_share(temp_user_client, own, tag)
        u2 = admin.create_user(role="user")
        c2 = ApiClient(); c2.login(u2["_username"], u2["_password"])
        assert c2.get(f"/shares/{share['id']}/claims").status_code == 403   # not creator/admin
        assert admin.get(f"/shares/{share['id']}/claims").status_code == 200  # admin can
        assert temp_user_client.get(f"/shares/{share['id']}/claims").status_code == 200  # creator can
    finally:
        if u2:
            admin.delete_user(u2["id"])
        temp_user_client.delete_vault(own["id"])


def test_shares_list_exposes_tag_and_target_names(admin):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("cltn"))
    try:
        g = admin.post(f"/vaults/{v['id']}/folders", json={"name": "reports"}).json()["folder"]["id"]
        tag = _tag(admin)
        share = _make_share(admin, v, tag, target_type="folder", target_folder_id=g)
        row = next(s for s in admin.get("/shares").json() if s["id"] == share["id"])
        assert row["tag_name"] == tag["_name"]
        assert row["target_name"] == "reports"
        assert row["vault_name"] == v["name"]
    finally:
        admin.delete_vault(v["id"])
