"""Direct-push 'users' audience is limited to recipients the creator could reach via the picker.

create_share validates audience_user_ids the same way GET /users/search does: active, non-EXTERNAL
accounts, and — when the org sets directory_search_scope='same_department' — accounts sharing a
department with the creator. A crafted POST /shares can't push a share to a user the picker would never
surface. An interactive admin is not department-scoped (they have the unrestricted /users directory).
"""
from conftest import ApiClient, unique


def _enable(admin):
    assert admin.put("/settings", json={"sharing_enabled": True}).status_code == 200


def _set_scope(admin, scope):
    assert admin.put("/settings", json={"directory_search_scope": scope}).status_code == 200


def _tag(admin):
    r = admin.post("/share-tags", json={"name": unique("pushtag"), "auto_enroll_new_users": True,
                                        "allowed_audiences": ["users"], "max_recipients_cap": 10})
    assert r.status_code == 200, r.text
    return r.json()


def test_push_to_out_of_department_user_rejected_under_same_department(admin):
    _enable(admin)
    tag = _tag(admin)
    # Creator U in dept A (owns a vault); target X in dept B (disjoint).
    U = admin.create_user(role="user")
    X = admin.create_user(role="user")
    gA = admin.post("/groups", json={"name": unique("deptA")}).json()
    gB = admin.post("/groups", json={"name": unique("deptB")}).json()
    admin.post(f"/groups/{gA['id']}/members", json={"user_ids": [U["id"]]})
    admin.post(f"/groups/{gB['id']}/members", json={"user_ids": [X["id"]]})
    uc = ApiClient(); uc.login(U["_username"], U["_password"])
    uv = uc.create_vault(name=unique("pushvault"))
    peer = None
    try:
        _set_scope(admin, "same_department")
        # U's own recipient picker cannot surface X (out of U's department scope).
        found = [r["id"] for r in uc.get(f"/users/search?q={X['_username'][:8]}").json()]
        assert X["id"] not in found

        # A crafted push to the out-of-scope X is rejected (the picker would never offer X).
        r = uc.post("/shares", json={"vault_id": uv["id"], "tag_id": tag["id"], "target_type": "vault",
                                     "claim_audience": "users", "audience_user_ids": [X["id"]]})
        assert r.status_code == 400, r.text

        # Control: pushing to a same-department peer U CAN see is allowed.
        peer = admin.create_user(role="user")
        admin.post(f"/groups/{gA['id']}/members", json={"user_ids": [peer["id"]]})
        ok = uc.post("/shares", json={"vault_id": uv["id"], "tag_id": tag["id"], "target_type": "vault",
                                      "claim_audience": "users", "audience_user_ids": [peer["id"]]})
        assert ok.status_code == 200, ok.text
    finally:
        _set_scope(admin, "deployment")
        uc.delete_vault(uv["id"])
        if peer:
            admin.delete_user(peer["id"])
        admin.delete(f"/groups/{gA['id']}")
        admin.delete(f"/groups/{gB['id']}")
        admin.delete_user(U["id"])
        admin.delete_user(X["id"])


def test_push_to_external_user_rejected(admin):
    """EXTERNAL accounts are never eligible share recipients (parity with /users/search), regardless of
    department scope or that the creator is an admin."""
    _enable(admin)
    v = admin.create_vault(name=unique("extvault"))
    ext = admin.create_user(role="external")
    try:
        _set_scope(admin, "deployment")  # isolate the EXTERNAL check from the department check
        r = admin.post("/shares", json={"vault_id": v["id"], "tag_id": _tag(admin)["id"],
                                        "target_type": "vault", "claim_audience": "users",
                                        "audience_user_ids": [ext["id"]]})
        assert r.status_code == 400, r.text
    finally:
        admin.delete_user(ext["id"])
        admin.delete_vault(v["id"])


def test_admin_creator_not_department_scoped(admin):
    """An interactive admin has the unrestricted /users directory, so a push is not department-scoped
    for an admin creator (still bounded to active, non-EXTERNAL accounts)."""
    _enable(admin)
    v = admin.create_vault(name=unique("admvault"))
    X = admin.create_user(role="user")  # admin shares no group with X
    try:
        _set_scope(admin, "same_department")
        r = admin.post("/shares", json={"vault_id": v["id"], "tag_id": _tag(admin)["id"],
                                        "target_type": "vault", "claim_audience": "users",
                                        "audience_user_ids": [X["id"]]})
        assert r.status_code == 200, r.text
    finally:
        _set_scope(admin, "deployment")
        admin.delete_user(X["id"])
        admin.delete_vault(v["id"])
