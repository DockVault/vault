"""GET /users/search — minimal scoped user lookup that feeds the share/grant picker.

It must let a vault owner/manager (not just admins) find a recipient, while NOT being a
directory-enumeration oracle for users who can't share anything.
"""
import uuid


def _logged_in(admin, role="user"):
    u = admin.create_user(role=role)
    c = admin.clone_anonymous()
    c.login(u["_username"], u["_password"])
    return u, c


def _sharer(admin):
    """A non-admin user made a Manager of a fresh vault -> a legitimate sharer."""
    u, c = _logged_in(admin)
    v = admin.create_vault()
    admin.post(f"/vaults/{v['id']}/permissions", json={"user_id": u["id"], "level": "manage"})
    return u, c, v


def test_search_denied_to_non_sharer(admin):
    u, c = _logged_in(admin)  # owns/manages no vault
    try:
        assert c.get("/users/search?q=ad").status_code == 403
    finally:
        admin.delete_user(u["id"])


def test_manager_can_search_and_gets_id_username_only(admin):
    u, c, v = _sharer(admin)
    target = admin.create_user(username="findme-recipient")
    try:
        r = c.get("/users/search?q=findme")
        assert r.status_code == 200, r.text
        results = r.json()
        assert any(x["username"] == "findme-recipient" for x in results)
        for x in results:
            assert set(x) == {"id", "username"}  # no email / role / directory leak
    finally:
        admin.delete_user(target["id"])
        admin.delete_vault(v["id"])
        admin.delete_user(u["id"])


def test_search_requires_min_prefix(admin):
    u, c, v = _sharer(admin)
    try:
        assert c.get("/users/search?q=a").json() == []   # 1 char -> empty (no 1-char enumeration)
        assert c.get("/users/search?q=").json() == []    # empty -> empty
    finally:
        admin.delete_vault(v["id"])
        admin.delete_user(u["id"])


def test_search_escapes_like_wildcards(admin):
    u, c, v = _sharer(admin)
    try:
        # a '%' must be treated literally, not sweep the whole directory
        r = c.get("/users/search?q=%25%25")  # url-encoded "%%"
        assert r.status_code == 200
        assert r.json() == []  # no username literally starts with "%%"
    finally:
        admin.delete_vault(v["id"])
        admin.delete_user(u["id"])


def test_directory_search_scope_validation(admin):
    """The policy only accepts the two known values; anything else is rejected (fail-safe)."""
    try:
        assert admin.put("/settings", json={"directory_search_scope": "bogus"}).status_code == 400
        assert admin.put("/settings", json={"directory_search_scope": "same_department"}).status_code == 200
        assert admin.get("/settings").json()["directory_search_scope"] == "same_department"
    finally:
        admin.put("/settings", json={"directory_search_scope": "deployment"})


def test_same_department_scope_filters_search(admin):
    """With directory_search_scope=same_department, a sharer finds only accounts sharing a department
    with them; group_id narrows to one of the caller's own departments (a foreign group id -> empty)."""
    u, c, v = _sharer(admin)  # the caller — a manager, so allowed to search
    G = admin.post("/groups", json={"name": "dss_" + uuid.uuid4().hex[:8]}).json()["id"]
    H = admin.post("/groups", json={"name": "dss_" + uuid.uuid4().hex[:8]}).json()["id"]
    pfx = "dss" + uuid.uuid4().hex[:6]
    mate = admin.create_user(username=pfx + "-mate")    # same department as the caller
    other = admin.create_user(username=pfx + "-other")  # a different department
    try:
        assert admin.post(f"/groups/{G}/members", json={"user_ids": [u["id"], mate["id"]]}).status_code == 200
        assert admin.post(f"/groups/{H}/members", json={"user_ids": [other["id"]]}).status_code == 200

        # deployment (default): both are findable
        admin.put("/settings", json={"directory_search_scope": "deployment"})
        names = {x["username"] for x in c.get(f"/users/search?q={pfx}").json()}
        assert (pfx + "-mate") in names and (pfx + "-other") in names

        # same_department: only the same-department account is findable
        admin.put("/settings", json={"directory_search_scope": "same_department"})
        names = {x["username"] for x in c.get(f"/users/search?q={pfx}").json()}
        assert (pfx + "-mate") in names
        assert (pfx + "-other") not in names

        # group_id narrows to the caller's own department G; a foreign department H yields nothing
        names = {x["username"] for x in c.get(f"/users/search?q={pfx}&group_id={G}").json()}
        assert (pfx + "-mate") in names and (pfx + "-other") not in names
        assert c.get(f"/users/search?q={pfx}&group_id={H}").json() == []  # caller not in H
        assert c.get(f"/users/search?q={pfx}&group_id=not-a-uuid").json() == []  # unparseable -> empty
    finally:
        admin.put("/settings", json={"directory_search_scope": "deployment"})  # restore the shared policy
        admin.delete_user(mate["id"])
        admin.delete_user(other["id"])
        admin.delete_vault(v["id"])
        admin.delete_user(u["id"])
        admin.delete(f"/groups/{G}")
        admin.delete(f"/groups/{H}")
