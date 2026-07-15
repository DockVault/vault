"""GET /users/search — minimal scoped user lookup that feeds the share/grant picker.

It must let a vault owner/manager (not just admins) find a recipient, while NOT being a
directory-enumeration oracle for users who can't share anything.
"""


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
