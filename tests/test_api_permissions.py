"""Endpoint-permission groups and per-user grants/revokes."""


def test_list_permission_groups(admin):
    r = admin.get("/permissions/groups")
    assert r.status_code == 200
    groups = r.json()
    assert isinstance(groups, list) and groups
    names = {g["name"] for g in groups}
    # a couple of well-known groups should exist
    assert names & {"VAULT_MANAGE", "TEMP_CREDS_MANAGE", "USER_MANAGE"}


def test_non_admin_cannot_list_groups(temp_user_client):
    r = temp_user_client.get("/permissions/groups")
    assert r.status_code == 403


def test_get_user_permissions(admin, temp_user):
    r = admin.get(f"/permissions/users/{temp_user['id']}")
    assert r.status_code == 200
    body = r.json()
    assert body["user_id"] == temp_user["id"]
    assert "granted_groups" in body
    assert "permissions" in body


def test_grant_and_revoke_group(admin, temp_user):
    uid = temp_user["id"]
    group = "VAULT_VIEW"

    r = admin.post(f"/permissions/users/{uid}/grant", json={"endpoint_group": group})
    assert r.status_code == 200

    r = admin.get(f"/permissions/users/{uid}")
    assert group in r.json()["granted_groups"]

    r = admin.delete(f"/permissions/users/{uid}/revoke/{group}")
    assert r.status_code == 200
    r = admin.get(f"/permissions/users/{uid}")
    assert group not in r.json()["granted_groups"]


def test_grant_invalid_group(admin, temp_user):
    r = admin.post(f"/permissions/users/{temp_user['id']}/grant",
                   json={"endpoint_group": "NOT_A_REAL_GROUP"})
    assert r.status_code in (400, 404)


def test_non_admin_cannot_grant(temp_user_client, temp_user):
    r = temp_user_client.post(f"/permissions/users/{temp_user['id']}/grant",
                              json={"endpoint_group": "VAULT_VIEW"})
    assert r.status_code == 403


def test_user_can_view_own_permissions(temp_user_client, temp_user):
    r = temp_user_client.get(f"/permissions/users/{temp_user['id']}")
    assert r.status_code == 200
