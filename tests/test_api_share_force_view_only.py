"""force_view_only: a tag can MANDATE view-only on every share it mints, independent of allow_custom or
the creator's request. A share created under such a tag is view-only (download denied) even when the
creator explicitly asks for a downloadable one; and the contradictory force+disallow combo is rejected.
"""
from conftest import ApiClient, unique


def _enable(admin):
    assert admin.put("/settings", json={"sharing_enabled": True}).status_code == 200


def _force_tag(admin, **over):
    body = {"name": unique("fvotag"), "auto_enroll_new_users": True,
            "allowed_audiences": ["users", "anyone_internal"],
            "allow_view_only": True, "allow_custom": True, "force_view_only": True}
    body.update(over)
    return admin.post("/share-tags", json=body)


def _upload(admin, vid):
    r = admin.post(f"/vaults/{vid}/files",
                   files=[("files", (unique("d") + ".txt", b"secret\n", "text/plain"))])
    r.raise_for_status()
    return r.json()["files"][0]["id"]


def test_force_view_only_persisted_and_listed(admin):
    r = _force_tag(admin)
    assert r.status_code == 200, r.text
    assert r.json()["force_view_only"] is True
    tag = next(t for t in admin.get("/share-tags").json() if t["id"] == r.json()["id"])
    assert tag["force_view_only"] is True
    # The non-admin create surface (/share-policy, which feeds the create modal) also exposes it, so
    # the modal can force+lock the view-only toggle for a mandatory-view-only tag.
    pol = admin.get("/share-policy").json()
    pt = next((x for x in pol.get("tags", []) if x["id"] == r.json()["id"]), None)
    assert pt is not None and pt.get("force_view_only") is True


def test_force_view_only_requires_allow_view_only(admin):
    # create: force + not-allowed is contradictory -> 400
    assert _force_tag(admin, allow_view_only=False).status_code == 400
    # patch: same rejection on update of an existing plain tag
    tid = _force_tag(admin, force_view_only=False).json()["id"]
    assert admin.patch(f"/share-tags/{tid}",
                       json={"force_view_only": True, "allow_view_only": False}).status_code == 400


def test_force_view_only_overrides_creator_request(admin):
    _enable(admin)
    v = admin.create_vault(name=unique("fvov"))
    tag = _force_tag(admin).json()  # force_view_only + allow_custom=True (creator may customize other limits)
    try:
        # The creator explicitly asks for a DOWNLOADABLE share; the tag forces view-only anyway.
        r = admin.post("/shares", json={"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault",
                                        "claim_audience": "anyone_internal", "view_only": False})
        assert r.status_code == 200, r.text
        assert r.json()["view_only"] is True
    finally:
        admin.delete_vault(v["id"])


def test_force_view_only_recipient_cannot_download(admin):
    _enable(admin)
    v = admin.create_vault(name=unique("fvod"))
    R = admin.create_user(role="user")
    rc = ApiClient(); rc.login(R["_username"], R["_password"])
    tag = _force_tag(admin).json()
    try:
        fid = _upload(admin, v["id"])
        share = admin.post("/shares", json={
            "vault_id": v["id"], "tag_id": tag["id"], "target_type": "file", "target_file_id": fid,
            "claim_audience": "users", "audience_user_ids": [R["id"]], "view_only": False}).json()
        assert share["view_only"] is True  # forced despite the creator's request
        assert rc.post(f"/shares/{share['id']}/claim").status_code == 200
        # The recipient can open + see the item but must NOT be able to download it.
        assert rc.get(f"/vaults/{v['id']}").status_code == 200
        assert rc.get(f"/vaults/{v['id']}/files/{fid}/download").status_code == 403
    finally:
        admin.delete_user(R["id"])
        admin.delete_vault(v["id"])


def test_default_view_only_still_overridable_when_not_forced(admin):
    """Control: with force_view_only OFF and allow_custom ON, a creator can still turn a
    default-view-only tag's share into a downloadable one (the force flag is what removes that ability)."""
    _enable(admin)
    v = admin.create_vault(name=unique("fvctl"))
    tag = _force_tag(admin, force_view_only=False, default_view_only=True).json()
    try:
        r = admin.post("/shares", json={"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault",
                                        "claim_audience": "anyone_internal", "view_only": False})
        assert r.status_code == 200, r.text
        assert r.json()["view_only"] is False  # creator overrode the default (allowed, since not forced)
    finally:
        admin.delete_vault(v["id"])
