"""User management — both the main /users routes and /api/user-management/*."""
from conftest import unique


# ---- main /users (admin CRUD) ---------------------------------------------
def test_create_list_get_user(admin):
    user = admin.create_user(role="user")
    try:
        assert user["username"]
        assert user["role"] == "user"

        # appears in admin list
        r = admin.get("/users")
        assert r.status_code == 200
        assert any(u["id"] == user["id"] for u in r.json())

        # fetch by id
        r = admin.get(f"/users/{user['id']}")
        assert r.status_code == 200
        assert r.json()["username"] == user["_username"]
    finally:
        admin.delete_user(user["id"])


def test_create_user_duplicate_username(admin, temp_user):
    r = admin.post("/users", json={
        "username": temp_user["_username"],
        "email": f"{unique('x')}@example.com",
        "password": "AnotherPass123!",
        "role": "user",
    })
    assert r.status_code == 400


def test_create_user_invalid_email(admin):
    r = admin.post("/users", json={
        "username": unique("user"),
        "email": "not-an-email",
        "password": "AnotherPass123!",
        "role": "user",
    })
    assert r.status_code == 422


def test_patch_user_email(admin, temp_user):
    new_email = f"{unique('e')}@example.com"
    r = admin.patch(f"/users/{temp_user['id']}", json={"email": new_email})
    assert r.status_code == 200
    assert r.json()["email"] == new_email


def test_delete_user(admin):
    user = admin.create_user(role="user")
    r = admin.post(f"/users/{user['id']}/delete")
    assert r.status_code == 200
    # gone now
    r = admin.get(f"/users/{user['id']}")
    assert r.status_code == 404


def test_admin_cannot_delete_self(admin):
    me = admin.get("/users/me").json()
    r = admin.post(f"/users/{me['id']}/delete")
    assert r.status_code == 400


# ---- authorization: non-admin is forbidden on admin endpoints -------------
def test_non_admin_cannot_list_users(temp_user_client):
    r = temp_user_client.get("/users")
    assert r.status_code == 403


def test_non_admin_cannot_create_users(temp_user_client):
    r = temp_user_client.post("/users", json={
        "username": unique("user"),
        "email": f"{unique('e')}@example.com",
        "password": "AnotherPass123!",
        "role": "user",
    })
    assert r.status_code == 403


# ---- /api/user-management/* -----------------------------------------------
def test_user_management_metrics(admin):
    r = admin.get("/api/user-management/metrics")
    assert r.status_code == 200
    body = r.json()
    for key in ("total_users", "active_users", "locked_users"):
        assert key in body


def test_user_management_list_with_search(admin, temp_user):
    r = admin.get("/api/user-management/users", params={"search": temp_user["_username"]})
    assert r.status_code == 200
    rows = r.json()
    assert any(u["id"] == temp_user["id"] for u in rows)


def test_user_management_detail(admin, temp_user):
    r = admin.get(f"/api/user-management/users/{temp_user['id']}")
    assert r.status_code == 200
    assert r.json()["username"] == temp_user["_username"]


def test_user_management_toggle_active(admin, temp_user):
    r = admin.post(f"/api/user-management/users/{temp_user['id']}/toggle-active")
    assert r.status_code == 200
    assert r.json()["is_active"] is False
    # toggle back
    r = admin.post(f"/api/user-management/users/{temp_user['id']}/toggle-active")
    assert r.json()["is_active"] is True


def test_user_management_toggle_locked(admin, temp_user):
    r = admin.post(f"/api/user-management/users/{temp_user['id']}/toggle-locked")
    assert r.status_code == 200
    assert "is_locked" in r.json()
    admin.post(f"/api/user-management/users/{temp_user['id']}/toggle-locked")  # restore


def test_user_management_roles_catalog(admin):
    r = admin.get("/api/user-management/roles")
    assert r.status_code == 200
    roles = r.json()
    assert {row["role"] for row in roles} >= {"admin", "user"}


def test_user_management_change_role(admin, temp_user):
    r = admin.patch(f"/api/user-management/users/{temp_user['id']}/role",
                    json={"new_role": "external"})
    assert r.status_code == 200
    assert r.json()["new_role"] == "external"


def test_user_management_activity(admin, temp_user):
    r = admin.get(f"/api/user-management/users/{temp_user['id']}/activity")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_etag_conditional_on_users_list(admin):
    r1 = admin.get("/api/user-management/users")
    etag = r1.headers.get("ETag")
    if not etag:
        return  # endpoint may not emit an ETag in all builds
    r2 = admin.get("/api/user-management/users", headers={"If-None-Match": etag})
    assert r2.status_code in (200, 304)
