"""The 'shared with me' available-card scan filters server-side (JSONB @> containment): a user sees a
pushed share iff they are in its audience — a named user, or a member of a targeted department — and a
bystander sees none. Exercises both the users and departments containment branches plus the exclusion.
"""
from conftest import ApiClient, unique


def _enable(admin):
    assert admin.put("/settings", json={"sharing_enabled": True}).status_code == 200


def _tag(admin):
    r = admin.post("/share-tags", json={"name": unique("swmtag"), "auto_enroll_new_users": True,
                                        "allowed_audiences": ["users", "departments"],
                                        "max_recipients_cap": 20})
    assert r.status_code == 200, r.text
    return r.json()


def _swm_ids(client):
    return {s["share_id"] for s in client.get("/shares/shared-with-me").json()}


def test_available_scan_scoped_by_audience(admin):
    _enable(admin)
    tag = _tag(admin)
    v = admin.create_vault(name=unique("swmv"))
    named = admin.create_user(role="user")      # pushed by user id
    member = admin.create_user(role="user")     # in a pushed department
    bystander = admin.create_user(role="user")  # neither
    g = admin.post("/groups", json={"name": unique("swmdept")}).json()
    admin.post(f"/groups/{g['id']}/members", json={"user_ids": [member["id"]]})
    nc = ApiClient(); nc.login(named["_username"], named["_password"])
    mc = ApiClient(); mc.login(member["_username"], member["_password"])
    bc = ApiClient(); bc.login(bystander["_username"], bystander["_password"])
    try:
        us = admin.post("/shares", json={"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault",
                                         "claim_audience": "users", "audience_user_ids": [named["id"]]}).json()
        ds = admin.post("/shares", json={"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault",
                                         "claim_audience": "departments",
                                         "audience_department_ids": [g["id"]]}).json()
        # named user sees ONLY the users-push; dept member sees ONLY the dept-push; bystander sees neither.
        assert us["id"] in _swm_ids(nc) and ds["id"] not in _swm_ids(nc)
        assert ds["id"] in _swm_ids(mc) and us["id"] not in _swm_ids(mc)
        assert _swm_ids(bc).isdisjoint({us["id"], ds["id"]})
    finally:
        admin.delete(f"/groups/{g['id']}")
        for u in (named, member, bystander):
            admin.delete_user(u["id"])
        admin.delete_vault(v["id"])
