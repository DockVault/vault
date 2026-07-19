"""GET /share-policy — the non-admin effective reader that shapes the (future) share modal.

Proves the fail-closed create-allowlist: a user sees ONLY the active tags they may create shares with,
the create-allowlist internals are never exposed, and the whole surface is empty when sharing is off.
Also checks the department-allowlist path and the admin (no-bypass) behavior.
"""
from conftest import ApiClient, unique


def _enable_sharing(admin, on=True):
    assert admin.put("/settings", json={"sharing_enabled": on}).status_code == 200


def _policy(client):
    r = client.get("/share-policy")
    assert r.status_code == 200, r.text
    return r.json()


def test_share_policy_empty_when_sharing_off(admin):
    _enable_sharing(admin, False)
    body = _policy(admin)
    assert body["sharing_enabled"] is False
    assert body["tags"] == []
    _enable_sharing(admin, True)  # restore for the rest of the file


def test_share_policy_shows_only_creatable_tags_and_hides_allowlist(admin, temp_user, temp_user_client):
    _enable_sharing(admin, True)
    uid = temp_user["id"]
    # A: user explicitly allowed -> visible
    a = admin.post("/share-tags", json={
        "name": unique("A"), "allowed_user_ids": [uid], "max_recipients_cap": 4, "max_recipients_default": 2,
        "allowed_audiences": ["users", "departments", "anyone_internal"],
    }).json()
    # B: nobody enrolled (fail-closed) -> hidden
    b = admin.post("/share-tags", json={"name": unique("B")}).json()
    # C: auto-enroll ON but this user BLOCKED -> hidden (blocklist wins)
    c = admin.post("/share-tags", json={
        "name": unique("C"), "auto_enroll_new_users": True, "blocked_user_ids": [uid],
    }).json()
    # D: auto-enroll ON, not blocked -> visible
    d = admin.post("/share-tags", json={"name": unique("D"), "auto_enroll_new_users": True}).json()

    body = _policy(temp_user_client)
    assert body["sharing_enabled"] is True
    visible_ids = {t["id"] for t in body["tags"]}
    assert a["id"] in visible_ids            # allowed user
    assert d["id"] in visible_ids            # auto-enrolled
    assert b["id"] not in visible_ids        # fail-closed: nobody enrolled
    assert c["id"] not in visible_ids        # blocklist wins

    # The effective tag entry carries the modal-shaping fields but NEVER the allowlist internals.
    entry = next(t for t in body["tags"] if t["id"] == a["id"])
    assert entry["name"] and "allowed_audiences" in entry
    assert entry["max_recipients_cap"] == 4 and entry["max_recipients_default"] == 2
    for leaked in ("allowed_user_ids", "blocked_user_ids", "allowed_department_ids",
                   "auto_enroll_new_users", "description"):
        assert leaked not in entry, f"/share-policy must not expose {leaked}"


def test_share_policy_department_allowlist(admin, temp_user, temp_user_client):
    _enable_sharing(admin, True)
    uid = temp_user["id"]
    # a group the user belongs to
    g = admin.post("/groups", json={"name": unique("dept")}).json()
    assert admin.post(f"/groups/{g['id']}/members", json={"user_ids": [uid]}).status_code in (200, 201)
    tag = admin.post("/share-tags", json={
        "name": unique("deptTag"), "allowed_department_ids": [g["id"]],
    }).json()
    body = _policy(temp_user_client)
    assert tag["id"] in {t["id"] for t in body["tags"]}
    # a user NOT in the department does not see it: the admin (not in this group, no bypass) shouldn't
    assert tag["id"] not in {t["id"] for t in _policy(admin)["tags"]}


def test_share_policy_deactivated_tag_disappears(admin, temp_user, temp_user_client):
    _enable_sharing(admin, True)
    uid = temp_user["id"]
    tag = admin.post("/share-tags", json={"name": unique("E"), "allowed_user_ids": [uid]}).json()
    assert tag["id"] in {t["id"] for t in _policy(temp_user_client)["tags"]}
    assert admin.delete(f"/share-tags/{tag['id']}").status_code == 200  # soft-deactivate
    assert tag["id"] not in {t["id"] for t in _policy(temp_user_client)["tags"]}


def test_share_policy_requires_auth(anon):
    assert anon.get("/share-policy").status_code in (401, 403)


def test_temp_session_never_creatable_and_denied_tag_crud(admin):
    """A temporary-credential session can NEVER create a share (fail-closed) and cannot manage tags,
    even when minted from an admin and even when a tag would otherwise auto-enroll its account."""
    _enable_sharing(admin, True)
    tag = admin.post("/share-tags", json={"name": unique("tmp"), "auto_enroll_new_users": True}).json()
    creds = admin.post("/auth/temp-credentials", json={"validity_minutes": 30}).json()
    temp = ApiClient()
    temp.login(creds["temp_username"], creds["credential"])
    # (a) the temp session sees NO creatable tags, though the underlying admin account is auto-enrolled
    body = temp.get("/share-policy").json()
    assert body["sharing_enabled"] is True
    assert body["tags"] == [], "a temp session must not be offered any tag to create a share with"
    # (b) an admin-minted temp session is not an interactive admin -> tag CRUD is denied
    assert temp.post("/share-tags", json={"name": unique("z")}).status_code == 403
    assert temp.patch(f"/share-tags/{tag['id']}", json={"description": "x"}).status_code == 403
    assert temp.delete(f"/share-tags/{tag['id']}").status_code == 403
