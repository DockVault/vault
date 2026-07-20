"""Input-hardening + non-disclosure checks for the sharing surface:

- oversized integer limits are a clean 4xx, never an uncaught 500 (int4 column ceiling);
- an unknown audience id is reported by COUNT only, never echoed back (no existence oracle);
- an id-scoped (file/folder) share recipient does not receive the owner-authored vault description;
- the claim path denies an out-of-audience caller uniformly, without leaking the share's lifecycle
  state (active vs revoked) through distinct status codes.
"""
from conftest import ApiClient, unique


def _enable(admin):
    assert admin.put("/settings", json={"sharing_enabled": True}).status_code == 200


def _tag(admin, audiences):
    r = admin.post("/share-tags", json={"name": unique("hardtag"), "auto_enroll_new_users": True,
                                        "allowed_audiences": audiences})
    assert r.status_code == 200, r.text
    return r.json()


def test_share_tag_int_overflow_is_clean_4xx_not_500(admin):
    # A value above the 32-bit column ceiling is rejected at the boundary, never an uncaught DataError.
    for field in ("max_lifetime_minutes", "max_downloads_cap", "max_recipients_cap"):
        r = admin.post("/share-tags", json={"name": unique("ovf"), field: 9999999999})
        assert r.status_code in (400, 422), f"{field}: {r.status_code} {r.text}"
        assert r.status_code != 500


def test_share_create_limit_overflow_is_clean_4xx_not_500(admin):
    _enable(admin)
    v = admin.create_vault(name=unique("ovfv"))
    tag = _tag(admin, ["anyone_internal"])  # null caps => the overflow reaches the create path
    try:
        r = admin.post("/shares", json={"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault",
                                        "claim_audience": "anyone_internal", "max_downloads": 9999999999})
        assert r.status_code in (400, 422), r.text
        assert r.status_code != 500
    finally:
        admin.delete_vault(v["id"])


def test_unknown_audience_id_is_not_echoed(admin):
    _enable(admin)
    v = admin.create_vault(name=unique("enumv"))
    tag = _tag(admin, ["users"])
    bogus = "00000000-0000-0000-0000-0000000000ff"
    try:
        r = admin.post("/shares", json={"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault",
                                        "claim_audience": "users", "audience_user_ids": [bogus]})
        assert r.status_code == 400, r.text
        assert bogus not in r.text  # count only — the submitted id is never reflected back
    finally:
        admin.delete_vault(v["id"])


def test_id_scoped_recipient_does_not_see_vault_description(admin):
    _enable(admin)
    secret = "internal-only description " + unique("s")
    v = admin.create_vault(name=unique("descv"), description=secret)
    R = admin.create_user(role="user")
    rc = ApiClient(); rc.login(R["_username"], R["_password"])
    tag = _tag(admin, ["users"])
    try:
        up = admin.post(f"/vaults/{v['id']}/files",
                        files=[("files", ("d.txt", b"x\n", "text/plain"))]).json()
        fid = up["files"][0]["id"]
        share = admin.post("/shares", json={
            "vault_id": v["id"], "tag_id": tag["id"], "target_type": "file", "target_file_id": fid,
            "claim_audience": "users", "audience_user_ids": [R["id"]]}).json()
        assert rc.post(f"/shares/{share['id']}/claim").status_code == 200
        # The file-scoped recipient can open the vault but must not receive the owner's description.
        assert rc.get(f"/vaults/{v['id']}").json().get("description") is None
        # Control: the owner still sees it.
        assert admin.get(f"/vaults/{v['id']}").json().get("description") == secret
    finally:
        admin.delete_user(R["id"])
        admin.delete_vault(v["id"])


def test_out_of_audience_claim_does_not_leak_lifecycle_state(admin):
    """A caller who holds the link token but is NOT in the audience is denied uniformly whether the
    share is active or revoked — the audience check runs before any status/expiry check, so the error
    code can't fingerprint the share's lifecycle state."""
    _enable(admin)
    v = admin.create_vault(name=unique("orav"))
    tag = _tag(admin, ["users"])
    target = admin.create_user(role="user")     # the sole intended recipient
    outsider = admin.create_user(role="user")   # not in the audience, but holds the link
    oc = ApiClient(); oc.login(outsider["_username"], outsider["_password"])
    try:
        share = admin.post("/shares", json={
            "vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault",
            "claim_audience": "users", "audience_user_ids": [target["id"]]}).json()
        token = share["link_token"]
        active_code = oc.post("/shares/claim", json={"token": token}).status_code
        assert active_code == 403  # audience denies first
        admin.post(f"/shares/{share['id']}/revoke")
        revoked_code = oc.post("/shares/claim", json={"token": token}).status_code
        # Same code for active and revoked -> no state oracle (was 403 vs 410 before the reorder).
        assert revoked_code == active_code == 403
    finally:
        admin.delete_user(target["id"])
        admin.delete_user(outsider["id"])
        admin.delete_vault(v["id"])
