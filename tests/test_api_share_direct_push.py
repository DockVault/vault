"""Direct push: a share addressed to named users/departments auto-appears as an 'available' card in
the recipient's shared-with-me list and can be claimed BY ID (no link token), audience-gated.
"""
from conftest import ApiClient, unique


def _enable_sharing(admin, on=True):
    assert admin.put("/settings", json={"sharing_enabled": on}).status_code == 200


def _tag(admin):
    r = admin.post("/share-tags", json={"name": unique("dptag"), "auto_enroll_new_users": True,
                                        "allowed_audiences": ["users", "departments", "anyone_internal"],
                                        "max_recipients_cap": 10})
    assert r.status_code == 200, r.text
    return r.json()


def _make_share(admin, v, tag, **over):
    body = {"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault"}
    body.update(over)
    r = admin.post("/shares", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def _swm(client):
    return {s["share_id"]: s for s in client.get("/shares/shared-with-me").json()}


def test_pushed_user_sees_available_and_claims_by_id(admin, temp_user, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("dpv"))
    try:
        share = _make_share(admin, v, _tag(admin), claim_audience="users", audience_user_ids=[temp_user["id"]])
        # the pushed user sees it as 'available' without claiming
        row = _swm(temp_user_client).get(share["id"])
        assert row is not None and row["status"] == "available"
        # claim by id (no token) -> becomes an active claimed card
        assert temp_user_client.post(f"/shares/{share['id']}/claim").status_code == 200
        row = _swm(temp_user_client).get(share["id"])
        assert row is not None and row["status"] == "active"
    finally:
        admin.delete_vault(v["id"])


def test_claim_by_id_denied_for_non_audience_user(admin, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("dpna"))
    other = admin.create_user(role="user")
    try:
        # addressed to ANOTHER user
        share = _make_share(admin, v, _tag(admin), claim_audience="users", audience_user_ids=[other["id"]])
        # temp_user is not in the audience -> not available, and claim-by-id is 403
        assert share["id"] not in _swm(temp_user_client)
        assert temp_user_client.post(f"/shares/{share['id']}/claim").status_code == 403
    finally:
        admin.delete_user(other["id"])
        admin.delete_vault(v["id"])


def test_anyone_internal_share_is_link_only(admin, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("dpai"))
    try:
        share = _make_share(admin, v, _tag(admin), claim_audience="anyone_internal")
        # an anyone_internal share is NOT a direct push -> not surfaced as available...
        assert share["id"] not in _swm(temp_user_client)
        # ...and cannot be claimed by id (must use the link token)
        assert temp_user_client.post(f"/shares/{share['id']}/claim").status_code == 403
        # the link path still works
        assert temp_user_client.post("/shares/claim", json={"token": share["link_token"]}).status_code == 200
    finally:
        admin.delete_vault(v["id"])


def test_department_push_available_to_member(admin, temp_user, temp_user_client):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("dpd"))
    g = admin.post("/groups", json={"name": unique("dpdept")}).json()
    assert admin.post(f"/groups/{g['id']}/members", json={"user_ids": [temp_user["id"]]}).status_code in (200, 201)
    try:
        share = _make_share(admin, v, _tag(admin), claim_audience="departments", audience_department_ids=[g["id"]])
        row = _swm(temp_user_client).get(share["id"])
        assert row is not None and row["status"] == "available"
        assert temp_user_client.post(f"/shares/{share['id']}/claim").status_code == 200
    finally:
        admin.delete_vault(v["id"])
        admin.delete(f"/groups/{g['id']}")


def test_cap_full_push_not_surfaced_as_available(admin, temp_user, temp_user_client):
    """A capped share that is already full is not offered as an 'available' dead-end to the remaining
    audience members (its claim would only 409)."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("dpcap"))
    other = admin.create_user(role="user")
    oc = ApiClient()
    oc.login(other["_username"], other["_password"])
    try:
        share = _make_share(admin, v, _tag(admin), claim_audience="users",
                            audience_user_ids=[temp_user["id"], other["id"]], max_recipients=1)
        assert oc.post(f"/shares/{share['id']}/claim").status_code == 200  # fills the single slot
        assert share["id"] not in _swm(temp_user_client)                   # no dead-end 'available' card
        assert temp_user_client.post(f"/shares/{share['id']}/claim").status_code == 409  # backend still refuses
    finally:
        admin.delete_user(other["id"])
        admin.delete_vault(v["id"])


def test_claim_by_id_temp_session_denied(admin, temp_user):
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("dpt"))
    try:
        share = _make_share(admin, v, _tag(admin), claim_audience="users", audience_user_ids=[temp_user["id"]])
        creds = admin.post("/auth/temp-credentials", json={"validity_minutes": 30}).json()
        temp = ApiClient()
        temp.login(creds["temp_username"], creds["credential"])
        assert temp.post(f"/shares/{share['id']}/claim").status_code == 403
    finally:
        admin.delete_vault(v["id"])
